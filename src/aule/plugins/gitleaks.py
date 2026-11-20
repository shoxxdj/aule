from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from ..models import ParsedEntity, Project, sha256_text as _sha
from .base import RunContext, Tool, register

_HISTORY_FILE_RE = re.compile(r"^(\d+)-([0-9a-fA-F]{6,40})/(.+)$")


def mask(secret: str) -> str:
    """Masque un secret en gardant juste de quoi le reconnaître."""
    if len(secret) <= 8:
        return "••••••"
    return f"{secret[:2]}••••••{secret[-2:]}"


def _relative(base: Path, file: str) -> str:
    try:
        return Path(file).resolve().relative_to(base.resolve()).as_posix()
    except (ValueError, OSError):
        return file.replace("\\", "/")


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

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        common = ["--report-format", "json", "--report-path", str(report_path), "--no-banner", *ctx.cfg.extra_args]
        if mode == "git":
            return [*ctx.exe, "git", *common, "--log-opts=--all", str(project.path)]  # toutes branches/tags
        target = self._extracted_dir(project, ctx) if mode == "history" else project.path
        return [*ctx.exe, "dir", *common, str(target)]

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
