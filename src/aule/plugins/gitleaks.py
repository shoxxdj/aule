from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter
from functools import lru_cache
from pathlib import Path

from ..config import ToolConfig
from ..models import ParsedEntity, Project, sha256_text as _sha
from ..rulesets import RuleSetError, expand, merge_gitleaks, wants_default
from .base import RunContext, Tool, register

_HISTORY_FILE_RE = re.compile(r"^(\d+)-([0-9a-fA-F]{6,40})/(.+)$")


def mask(secret: str) -> str:
    """Masque un secret en gardant juste de quoi le reconnaître."""
    if len(secret) <= 8:
        return "••••••"
    return f"{secret[:2]}••••••{secret[-2:]}"


def _relative(base: Path, file: str) -> str:
    """Chemin du fichier relatif au projet. gitleaks rapporte les chemins TELS QU'ON LES LUI DONNE : absolus avec une cible absolue, relatifs (`src/x`) avec `.`."""
    if not os.path.isabs(file) and not re.match(r"^[A-Za-z]:[\\/]", file):
        return re.sub(r"^(\./)+", "", file.replace("\\", "/"))
    try:
        return Path(file).resolve().relative_to(base.resolve()).as_posix()
    except (ValueError, OSError):
        return file.replace("\\", "/")


MIN_EXTEND_VERSION = (8, 9, 0)  # `[extend] useDefault = true` : ajouter des règles sans remplacer celles par défaut


@lru_cache(maxsize=16)
def _gitleaks_version(exe: tuple[str, ...], env: tuple[tuple[str, str], ...]) -> tuple[int, int, int] | None:
    """(8, 18, 4)… ou None si la version n'est pas lisible (on suppose alors une version récente ; `aule doctor` le vérifie)."""
    try:
        out = subprocess.run([*exe, "version"], capture_output=True, text=True, timeout=15, env={**os.environ, **dict(env)} if env else None)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", (out.stdout or "") + (out.stderr or ""))
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


@register
class Gitleaks(Tool):
    """Trois modes :
    - dir     : état courant des fichiers
    - git     : historique git (secrets supprimés mais toujours présents dans les commits)
    - history : `gitleaks dir` sur les commits reconstruits par gittools (utile quand le .git est
                incomplet/non exploitable par `gitleaks git`) ; actif seulement si gittools a réussi.
    """

    name = "gitleaks"
    binary = "gitleaks"
    version_args = ("version",)
    modes = ("dir", "git", "history")
    ok_exit_codes = frozenset({0, 1})  # 1 = fuites trouvées
    mode_requires = {"history": "gittools"}
    secrets_source = True

    def clear_values(self, report_path: Path) -> dict[int, tuple[str, str]] | None:
        text = report_path.read_text(encoding="utf-8").strip() if report_path.exists() else ""
        return {i: (f.get("Secret") or "", f.get("Match") or "") for i, f in enumerate((json.loads(text) if text else None) or [])}

    def phase(self, mode: str) -> int:
        return 1 if mode == "history" else 0

    def _gittools_report(self, project: Project, ctx: RunContext) -> dict:
        try:
            return json.loads((ctx.raw_dir(project.name, "gittools", "extract") / "report.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _extracted_dir(self, project: Project, ctx: RunContext) -> Path:
        """Dossier à scanner pour le mode history : le `scan_root` du rapport de gittools (extracted/snapshots avec git-extractor-rs, où `blobs/`,
        `commits/`... ne doivent PAS être scannés), sinon `extracted/` (extractor.sh, anciens rapports)."""
        raw = ctx.raw_dir(project.name, "gittools", "extract")
        root = (raw / (self._gittools_report(project, ctx).get("scan_root") or "extracted")).resolve()
        return root if root.is_relative_to(raw.resolve()) else raw / "extracted"

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        if mode == "git":
            return project.is_git
        if mode == "history":
            return (ctx.raw_dir(project.name, "gittools", "extract") / "report.json").exists()
        return True

    # --- vos règles (tools.gitleaks.rules) : Aulë n'en ajoute AUCUNE de lui-même ---------------------------------------
    @staticmethod
    def _own_config(cfg: ToolConfig) -> bool:
        """L'utilisateur donne SA configuration à gitleaks (extra_args) : `--config` remplace alors tout, nous n'y touchons pas."""
        return any(a in ("--config", "-c") or a.startswith(("--config=", "-c=")) for a in cfg.extra_args)

    supports_rules = True

    @staticmethod
    def default_rules_mode(cfg: ToolConfig):
        return cfg.options.get("default_rules", "auto")

    def _use_default(self, cfg: ToolConfig, user_files: list[Path]) -> bool:
        """Étendre les règles PAR DÉFAUT de gitleaks ? `true`/`false` : décidé ; `auto` : comme gitleaks, un fichier de règles les REMPLACE sauf s'il contient
        `[extend] useDefault = true`."""
        mode = self.default_rules_mode(cfg)
        if mode is True or mode is False:
            return mode
        if cfg.default_pass:
            return False  # la configuration par défaut a déjà tourné dans sa propre passe : la vôtre est AUTONOME (comme `gitleaks -c`), sauf `default_rules: true`
        return wants_default(user_files)

    def _rules_args(self, cfg: ToolConfig, exe: list[str], raw_dir: Path) -> list[str]:
        """gitleaks n'accepte qu'UN `--config` : les règles de TOUS les fichiers de `rules` sont FUSIONNÉES dans `rules.toml` de la sortie brute. Sans `rules`, aucun `--config` :
        gitleaks tourne avec SA configuration par défaut. `--config` avec `useDefault` sur une version trop ancienne REMPLACERAIT les règles par défaut (pas de `useDefault` avant 8.9.0) :
        on ne l'ajoute alors pas (`check_rules` refuse ce cas)."""
        if self._own_config(cfg) or not cfg.rules:
            return []
        user = expand(cfg.rules, {".toml"})
        use_default = self._use_default(cfg, user)
        version = _gitleaks_version(tuple(exe), tuple(sorted(cfg.env.items())))
        if use_default and version is not None and version < MIN_EXTEND_VERSION:
            return []
        raw_dir.mkdir(parents=True, exist_ok=True)
        merged = raw_dir / "rules.toml"
        merged.write_text(merge_gitleaks(user, use_default), encoding="utf-8")
        return ["--config", str(merged.resolve())]  # absolu : le dossier de travail change (voir cwd)

    def check_rules(self, cfg: ToolConfig, exe: list[str]) -> str | None:
        if self._own_config(cfg):
            return "tools.gitleaks.rules et un --config dans extra_args ne peuvent pas être combinés (gitleaks n'accepte qu'UN fichier de configuration) : retirez l'un des deux"
        try:
            user = expand(cfg.rules, {".toml"})
            use_default = self._use_default(cfg, user)
            merge_gitleaks(user, use_default)  # valide tout avant de lancer quoi que ce soit
        except RuleSetError as exc:
            return f"tools.gitleaks.rules : {exc}"
        version = _gitleaks_version(tuple(exe), tuple(sorted(cfg.env.items())))
        if use_default and version is not None and version < MIN_EXTEND_VERSION:
            return (f"tools.gitleaks.rules : gitleaks {'.'.join(map(str, version))} < {'.'.join(map(str, MIN_EXTEND_VERSION))} : ses règles par défaut seraient REMPLACÉES "
                    "par les vôtres (pas de `useDefault`) ; mettez gitleaks à jour, ou `default_rules: false` pour ne pas les étendre")
        return None

    def prerequisites(self, cfg: ToolConfig, data_dir: Path) -> str | None:
        if "credential_rules" in cfg.options:
            return ("tools.gitleaks.options.credential_rules n'existe plus : Aulë n'ajoute plus AUCUNE règle à gitleaks. Définissez les vôtres dans `tools.gitleaks.rules` "
                    "(un exemple à copier et adapter : examples/gitleaks-credentials.example.toml)")
        mode = self.default_rules_mode(cfg)
        if not (mode is True or mode is False or mode == "auto"):  # `is` : 0 == False et 1 == True en Python, `default_rules: 0` n'est pas un booléen
            return "tools.gitleaks.options.default_rules : true, false ou auto"
        if not isinstance(cfg.options.get("relative_paths", True), bool):
            return "tools.gitleaks.options.relative_paths : true ou false (sans guillemets)"
        if "default_pass" in cfg.options:
            return "tools.gitleaks.options.default_pass est devenu une clé de l'outil (comme `rules`) : écrivez `default_pass: true` sous `gitleaks:`, pas sous `options:`"
        if cfg.default_pass and self._own_config(cfg):
            return "tools.gitleaks.default_pass ne se combine pas avec un --config dans extra_args (la passe « par défaut » n'en serait plus une) : retirez l'un des deux"
        return None

    def warnings(self, cfg: ToolConfig, exe: list[str]) -> list[str]:
        if not cfg.rules or cfg.default_pass:  # avec default_pass, la configuration par défaut a sa propre passe : rien n'est « remplacé »
            return []
        try:
            user = expand(cfg.rules, {".toml"})
        except RuleSetError:
            return []  # check_rules l'a déjà refusé, avec le nom du fichier
        if self._use_default(cfg, user):
            return []
        return ["règles PAR DÉFAUT de gitleaks NON chargées : vos fichiers de règles les remplacent, comme `gitleaks -c fichier.toml` (ajoutez `[extend] useDefault = true` "
                "à votre fichier, ou `default_rules: true`, pour les conserver)"]

    @staticmethod
    def relative_paths(cfg: ToolConfig) -> bool:
        return cfg.options.get("relative_paths", True) is not False

    def _scan_root(self, project: Project, mode: str, ctx: RunContext) -> Path:
        return self._extracted_dir(project, ctx) if mode == "history" else project.path

    def cwd(self, project: Project, mode: str, ctx: RunContext) -> Path | None:
        """`gitleaks dir` rapporte (et teste contre les `path` des règles et des exclusions) les chemins TELS QU'ON LES LUI DONNE : avec une cible absolue, une règle
        `path = '^src/'` ne se déclenche JAMAIS. On l'exécute donc DANS le dossier scanné avec la cible `.`, comme `gitleaks -c fichier.toml` lancé à la main."""
        if mode == "git" or not self.relative_paths(ctx.cfg):
            return None
        return self._scan_root(project, mode, ctx)

    @staticmethod
    def _anchored(args: list[str]) -> list[str]:
        """Le dossier de travail change : un chemin RELATIF de `extra_args` garde son sens (relatif au dossier de l'auditeur) en devenant absolu."""
        out = []
        for arg in args:
            name, eq, value = arg.partition("=") if arg.startswith("-") else ("", "", arg)
            candidate = value if eq else arg
            if candidate and not candidate.startswith("-") and not os.path.isabs(candidate) and Path(candidate).exists():
                resolved = str(Path(candidate).resolve())
                arg = f"{name}={resolved}" if eq else resolved
            out.append(arg)
        return out

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        relative = mode != "git" and self.relative_paths(ctx.cfg)
        extra = self._anchored(ctx.cfg.extra_args) if relative else ctx.cfg.extra_args
        common = ["--report-format", "json", "--report-path", str(report_path.resolve()), "--no-banner", *self._rules_args(ctx.cfg, ctx.exe, report_path.parent), *extra]
        if mode == "git":
            return [*ctx.exe, "git", *common, "--log-opts=--all", str(project.path)]  # toutes branches/tags
        return [*ctx.exe, "dir", *common, "." if relative else str(self._scan_root(project, mode, ctx))]

    # ------------------------------------------------------------------ parsing
    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        text = report_path.read_text(encoding="utf-8").strip() if report_path.exists() else ""
        findings = json.loads(text) if text else []
        if mode == "history":
            return self._parse_history(project, findings or [], ctx)
        return self._parse_flat(project, mode, findings or [])

    @staticmethod
    def _common(f: dict, secret: str, index: int) -> dict:
        masked = mask(secret)
        return {
            "tool": "gitleaks",
            "rule_id": f.get("RuleID"),
            "description": f.get("Description"),
            "start_line": f.get("StartLine"),
            "end_line": f.get("EndLine"),
            "entropy": f.get("Entropy"),
            "tags": f.get("Tags") or [],
            # Le secret en clair reste uniquement dans le rapport brut.
            "secret_masked": masked,
            "secret_sha256": _sha(secret),
            "match_masked": (f.get("Match") or "").replace(secret, masked) if secret else f.get("Match"),
            "raw_index": index,
        }

    def _parse_flat(self, project: Project, mode: str, findings: list[dict]) -> list[ParsedEntity]:
        occurrences: Counter[str] = Counter()
        entities: list[ParsedEntity] = []
        for index, f in enumerate(findings):
            secret = f.get("Secret") or ""
            file = _relative(project.path, f.get("File", ""))
            # Pas de numéro de ligne dans l'empreinte : le triage survit aux décalages de code.
            base = _sha("|".join([project.name, mode, f.get("RuleID", ""), file, f.get("Commit", ""), _sha(secret)]))[:24]
            occurrences[base] += 1
            n = occurrences[base]
            entities.append(ParsedEntity("secret", base if n == 1 else f"{base}#{n}", {
                **self._common(f, secret, index),
                "mode": mode, "file": file,
                "commit": f.get("Commit") or None,
                "author": f.get("Author") or None,
                "email": f.get("Email") or None,
                "date": f.get("Date") or None,
                "commit_message": (f.get("Message") or "")[:200] or None,
            }))
        return entities

    def _parse_history(self, project: Project, findings: list[dict], ctx: RunContext) -> list[ParsedEntity]:
        """Un même secret présent dans 200 commits ressort 200 fois : on regroupe par
        (règle, fichier, secret) et on garde les commits concernés."""
        extracted = self._extracted_dir(project, ctx)
        commit_meta = self._commit_meta(project, ctx)
        by_dir = {c["dir"]: c for c in self._gittools_report(project, ctx).get("commits", []) if c.get("dir")}  # dossier d'instantané -> commit
        groups: dict[str, dict] = {}
        for index, f in enumerate(findings):
            secret = f.get("Secret") or ""
            rel = _relative(extracted, f.get("File", ""))
            first, _, rest = rel.partition("/")
            if first in by_dir and rest:
                commit_idx, commit, file = by_dir[first].get("index", 0), by_dir[first]["hash"], rest
            elif m := _HISTORY_FILE_RE.match(rel):  # repli : rapport sans correspondance de dossiers
                commit_idx, commit, file = int(m[1]), m[2], m[3]
            else:
                commit_idx, commit, file = None, None, rel
            key = _sha("|".join([project.name, "history", f.get("RuleID", ""), file, _sha(secret)]))[:24]
            g = groups.setdefault(key, {"first": f, "secret": secret, "index": index, "file": file, "commits": {}})
            if commit:
                g["commits"][commit] = commit_idx

        entities = []
        for key, g in groups.items():
            def sort_key(item):
                h, i = item
                return (commit_meta.get(h, {}).get("date") or "", i)
            ordered = sorted(g["commits"].items(), key=sort_key)
            first = ordered[0][0] if ordered else None
            last = ordered[-1][0] if ordered else None
            flags = [commit_meta.get(h, {}).get("reachable") for h, _ in ordered]
            unreachable_only = bool(flags) and all(f is False for f in flags)  # que des commits sur lesquels aucune référence ne mène
            meta = commit_meta.get(first, {}) if first else {}
            entities.append(ParsedEntity("secret", key, {
                **self._common(g["first"], g["secret"], g["index"]),
                "mode": "history", "file": g["file"],
                "commit": first, "first_commit": first, "last_commit": last,
                "commits": [h for h, _ in ordered], "commits_count": len(ordered), "unreachable_only": unreachable_only,
                "author": meta.get("author"), "email": meta.get("author_email"),
                "date": meta.get("date"), "commit_message": (meta.get("message") or "")[:200] or None,
            }))
        return entities

    def _commit_meta(self, project: Project, ctx: RunContext) -> dict[str, dict]:
        return {c["hash"]: c for c in self._gittools_report(project, ctx).get("commits", []) if "hash" in c}
