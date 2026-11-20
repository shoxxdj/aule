"""Reconstruction de l'historique d'un `.git` : un instantané complet par commit (avec git-extractor-rs : et tous les objets, même inaccessibles).

Deux exécutables, reconnus d'après leur nom (`options.flavor` : auto | rust | sh pour forcer) :

  rust  `git-extractor-rs` (https://github.com/shoxxdj/git-tools-rs), PAR DÉFAUT. Réécriture en Rust de l'Extractor de GitTools :
        extracted/{blobs,commits,trees,tags}/<empreinte> (TOUS les objets, même inaccessibles : charges utiles Git brutes) et un instantané
        par commit, extracted/snapshots/<AAAAMMJJ-HHMM>_<empreinte>/<chemins d'origine>. Nécessite `git` dans le PATH.
  sh    `extractor.sh` de GitTools (internetwache) : extracted/<n>-<empreinte>/ + commit-meta.txt. À désigner par `tools.gittools.path`.

Outil optionnel (désactivé par défaut). Il alimente la liste des commits (entités `commit`, onglet « Historique ») et le mode `history` de
gitleaks, qui scanne les instantanés (le rapport du plugin dit à gitleaks OÙ scanner et à quel commit correspond chaque dossier).
Attention : un arbre complet est écrit par commit, l'espace disque peut être important.

Lu dans le code de git-extractor-rs (et non deviné) : `metadata/snapshots.json` est un tableau de
`{commit, directory, date, timestamp, tz_offset, files}` ; on s'en sert pour la correspondance commit -> dossier et le nombre de fichiers, avec repli
sur les noms de dossiers (`snapshots/<AAAAMMJJ-HHMM>_<hash>`) s'il est absent ou illisible. Les commits viennent des objets bruts `commits/<hash>`.
`metadata/objects.json` et le `report.json` de l'outil ne sont pas utilisés ; le `report.json` de CE plugin est le nôtre.

Limites propres à git-extractor-rs, à connaître :
  - il s'ARRÊTE au premier commit dont l'arbre ou un fichier manque (`git archive` échoue) : sur un `.git` incomplet (récupéré d'un serveur),
    utilisez l'extractor.sh de GitTools pour ce projet ;
  - `git archive` applique `.gitattributes` : un fichier marqué `export-ignore` n'est PAS dans les instantanés (donc pas scanné par `history`) ;
  - il n'écrit que les fichiers réguliers (liens symboliques ignorés).
"""
from __future__ import annotations

import heapq
import json
import re
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..models import ParsedEntity, Project
from .base import RunContext, Tool, register

_DIR_RE = re.compile(r"^(\d+)-([0-9a-fA-F]{6,40})$")        # extractor.sh
_SNAP_RE = re.compile(r"^(\d{8}-\d{4})_([0-9a-f]{40})$")     # git-extractor-rs (00000000-0000 si la date est illisible)
_HASH_RE = re.compile(r"^[0-9a-f]{40}$")
_IDENT_RE = re.compile(r"^(.*?) <(.*?)> (\d+) ([+-])(\d{2})(\d{2})$")
_STAMP_RE = re.compile(r"^(?:committer|author) .*> (\d+) [+-]\d{4}$", re.M)
_VERSION_RE = re.compile(r"\d+\.\d+")
_ARCHIVE_FAIL = "git archive failed"
SNAPSHOT_DATES = ("committer", "author")


def _iso(ts: str, sign: str, hh: str, mm: str) -> str:
    offset = timedelta(hours=int(hh), minutes=int(mm)) * (-1 if sign == "-" else 1)
    return datetime.fromtimestamp(int(ts), tz=timezone(offset)).isoformat()


def parse_commit_meta(text: str) -> dict:
    """Lit un commit au format `git cat-file -p <commit>` — c'est aussi la charge utile brute d'un objet commit (tolérant)."""
    head, _, message = text.partition("\n\n")
    meta: dict = {"parents": [], "message": message.strip()[:500]}
    for line in head.splitlines():
        key, _, value = line.partition(" ")
        if key == "tree":
            meta["tree"] = value
        elif key == "parent":
            meta["parents"].append(value)
        elif key in ("author", "committer"):
            m = _IDENT_RE.match(value)
            if m:
                meta[key], meta[f"{key}_email"] = m[1], m[2]
                meta[f"{key}_date"] = _iso(m[3], m[4], m[5], m[6])
            else:
                meta[key] = value
    meta["date"] = meta.get("author_date") or meta.get("committer_date")
    if "author" not in meta:  # format inattendu : on garde le brut plutôt que de perdre l'info
        meta["raw_meta"] = text[:1000]
    return meta


def flavor_of(options: dict, exe: list[str]) -> str:
    """`rust` (git-extractor-rs) ou `sh` (extractor.sh), d'après l'exécutable résolu, sauf `options.flavor` explicite."""
    wanted = str(options.get("flavor", "auto")).lower()
    if wanted in ("rust", "sh"):
        return wanted
    if wanted != "auto":
        raise ValueError(f"tools.gittools.options.flavor : auto, rust ou sh (reçu : {wanted!r})")
    return "sh" if any(str(part).endswith(".sh") for part in exe) else "rust"


def rust_options(options: dict) -> tuple[int, str]:
    """(threads, snapshot_date) validés ; ValueError avec un message à destination de l'auditeur."""
    threads = options.get("threads", 4)
    if isinstance(threads, bool) or not isinstance(threads, int) or not 1 <= threads <= 64:
        raise ValueError(f"tools.gittools.options.threads : entier de 1 à 64 attendu (reçu : {threads!r})")
    date = str(options.get("snapshot_date", "committer"))
    if date not in SNAPSHOT_DATES:
        raise ValueError(f"tools.gittools.options.snapshot_date : committer ou author (reçu : {date!r})")
    return threads, date


def chronological(items: list[tuple[str, int, list[str]]]) -> list[str]:
    """Empreintes en ordre chronologique qui RESPECTE la filiation (un parent précède ses enfants).
    Le préfixe de date des instantanés n'a qu'une précision à la minute : deux commits d'une même minute ne se départagent pas par leur nom."""
    nodes = {h: (ts, parents) for h, ts, parents in items}
    waiting = {h: {p for p in parents if p in nodes and p != h} for h, (_, parents) in nodes.items()}
    children: dict[str, list[str]] = defaultdict(list)
    for h, pending in waiting.items():
        for p in pending:
            children[p].append(h)
    heap = [(nodes[h][0], h) for h, pending in waiting.items() if not pending]
    heapq.heapify(heap)
    out: list[str] = []
    while heap:
        _, h = heapq.heappop(heap)
        out.append(h)
        for child in children.get(h, ()):
            waiting[child].discard(h)
            if not waiting[child]:
                heapq.heappush(heap, (nodes[child][0], child))
    if len(out) < len(nodes):  # impossible dans un dépôt valide : on ne perd rien pour autant
        done = set(out)
        out += sorted(h for h in nodes if h not in done)
    return out


@register
class GitTools(Tool):
    name = "gittools"
    binary = "git-extractor-rs"
    alt_binaries = ("git-extractor",)  # nom sous lequel l'outil peut être installé (cargo install d'une autre version, binaire renommé)
    version_args = ("--version",)
    modes = ("extract",)
    default_enabled = False

    # --- variante, version, prérequis ---------------------------------------------------------
    def version_command(self, exe: list[str]) -> list[str] | None:
        return None if flavor_of({}, exe) == "sh" else [*exe, "--version"]  # extractor.sh n'a pas de --version : il la lirait comme un dépôt

    def failure_hint(self, message: str) -> str | None:
        if _ARCHIVE_FAIL in message:
            return ("dépôt incomplet : git-extractor-rs s'arrête au premier commit dont l'arbre ou un fichier manque. "
                    "Pour ce projet, utilisez l'extractor.sh de GitTools (tools.gittools.path) ; `gitleaks git` reste disponible")
        return None

    def parse_version(self, out: str, exit_code: int) -> str | None:
        """`--version` existe (clap) ; on valide quand même la sortie : une erreur d'usage (autre version de l'outil) ne doit pas passer pour une version."""
        first = out.splitlines()[0] if out else ""
        return first if exit_code == 0 and _VERSION_RE.search(first) else None

    def prerequisites(self, cfg, data_dir: Path) -> str | None:
        exe = self.resolve(cfg)
        if exe is None:
            return None  # « introuvable » est déjà signalé par l'orchestrateur
        try:
            flavor = flavor_of(cfg.options, exe)
            if flavor == "rust":
                rust_options(cfg.options)
        except ValueError as exc:
            return str(exc)
        if flavor == "rust" and not shutil.which("git"):
            return "git introuvable dans le PATH (requis par git-extractor-rs)"
        return None

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return (project.path / ".git").exists()

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        out = str(report_path.parent / "extracted")  # créé par l'outil lui-même
        if flavor_of(ctx.cfg.options, ctx.exe) == "sh":
            return [*ctx.exe, str(project.path), out]  # extractor.sh <dépôt contenant .git> <dossier de sortie>
        threads, date = rust_options(ctx.cfg.options)
        # forme documentée avec option : la forme positionnelle de la sortie ne se combine pas avec -o
        return [*ctx.exe, str(project.path), "-o", out, "--threads", str(threads), "--snapshot-date", date]

    # --- lecture des sorties ------------------------------------------------------------------
    @staticmethod
    def _reachable(repo: Path) -> set[str] | None:
        """Commits atteints par au moins une référence (branches, étiquettes, remises, suivi distant). None si git ne sait pas répondre
        (dépôt endommagé) : « inconnu » n'est pas « inaccessible »."""
        try:
            p = subprocess.run(["git", "-C", str(repo), "rev-list", "--all"], capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return {l.strip() for l in p.stdout.splitlines() if _HASH_RE.match(l.strip())} if p.returncode == 0 else None

    @staticmethod
    def _collect_sh(out: Path, reachable: set[str] | None = None) -> list[dict]:
        commits = []
        for d in out.iterdir() if out.is_dir() else []:
            m = _DIR_RE.match(d.name)
            if not (d.is_dir() and m):
                continue
            meta_file = d / "commit-meta.txt"
            meta = parse_commit_meta(meta_file.read_text(encoding="utf-8", errors="replace")) if meta_file.exists() else {}
            commits.append({"index": int(m[1]), "hash": m[2], "dir": d.name, **meta,
                            "reachable": None if reachable is None else (m[2] in reachable if len(m[2]) == 40 else any(h.startswith(m[2]) for h in reachable))})
        commits.sort(key=lambda c: c["index"])
        return commits

    @staticmethod
    def _snapshot_index(out: Path) -> dict[str, dict]:
        """`metadata/snapshots.json` de git-extractor-rs : tableau de {commit, directory, date, timestamp, tz_offset, files}. Tolérant : vide si illisible."""
        try:
            data = json.loads((out / "metadata" / "snapshots.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {i["commit"]: i for i in data if isinstance(data, list) and isinstance(i, dict) and isinstance(i.get("commit"), str)
                and _HASH_RE.match(i["commit"]) and isinstance(i.get("directory"), str)}

    @classmethod
    def _collect_rust(cls, out: Path, reachable: set[str] | None = None) -> list[dict]:
        index, root = cls._snapshot_index(out), out / "snapshots"
        snapshots: dict[str, str] = {}
        for h, item in index.items():  # l'index fait foi, à condition que le dossier existe et porte le nom documenté
            if _SNAP_RE.match(item["directory"]) and (root / item["directory"]).is_dir():
                snapshots[h] = item["directory"]
        for d in root.iterdir() if root.is_dir() else []:  # repli : index absent ou incomplet
            m = _SNAP_RE.match(d.name)
            if d.is_dir() and m:
                snapshots.setdefault(m[2], d.name)
        payloads: dict[str, str] = {}
        for f in (out / "commits").iterdir() if (out / "commits").is_dir() else []:
            if f.is_file() and _HASH_RE.match(f.name):
                payloads[f.name] = f.read_text(encoding="utf-8", errors="replace")
        metas = {h: parse_commit_meta(payloads[h]) if h in payloads else {} for h in set(snapshots) | set(payloads)}

        def stamp(h: str) -> int:
            if m := _STAMP_RE.search(payloads.get(h, "").partition("\n\n")[0]):
                return int(m[1])
            ts = index.get(h, {}).get("timestamp")
            return ts if isinstance(ts, int) and not isinstance(ts, bool) else 0
        order = chronological([(h, stamp(h), metas[h].get("parents", [])) for h in metas])
        entries = []
        for i, h in enumerate(order):
            files = index.get(h, {}).get("files")
            entries.append({"index": i, "hash": h, "dir": snapshots.get(h), **metas[h], "reachable": None if reachable is None else h in reachable,
                            "files": files if isinstance(files, int) and not isinstance(files, bool) and files >= 0 else None})
        return entries

    def post_run(self, project: Project, mode: str, raw_dir: Path, report_path: Path, ctx: RunContext) -> None:
        flavor = flavor_of(ctx.cfg.options, ctx.exe)
        out = raw_dir / "extracted"
        reachable = self._reachable(project.path)
        commits = self._collect_rust(out, reachable) if flavor == "rust" else self._collect_sh(out, reachable)
        if not commits:
            raise RuntimeError("aucun commit extrait (.git vide ou incomplet)")
        report_path.write_text(json.dumps(
            {"flavor": flavor, "extracted_dir": "extracted", "scan_root": "extracted/snapshots" if flavor == "rust" else "extracted", "commits": commits},
            indent=2, ensure_ascii=False), encoding="utf-8")

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return [ParsedEntity("commit", f"{project.name}:commit:{c['hash']}", c) for c in data["commits"]]
