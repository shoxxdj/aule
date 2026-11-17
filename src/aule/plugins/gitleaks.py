from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from ..models import ParsedEntity, Project
from .base import RunContext, Tool, register

_HISTORY_FILE_RE = re.compile(r"^(\d+)-([0-9a-fA-F]{6,40})/(.+)$")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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

    def _extracted_dir(self, project: Project, ctx: RunContext) -> Path:
        return ctx.raw_dir(project.name, "gittools", "extract") / "extracted"

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
        groups: dict[str, dict] = {}
        for index, f in enumerate(findings):
            secret = f.get("Secret") or ""
            rel = _relative(extracted, f.get("File", ""))
            m = _HISTORY_FILE_RE.match(rel)
            commit_idx, commit, file = (int(m[1]), m[2], m[3]) if m else (None, None, rel)
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
            meta = commit_meta.get(first, {}) if first else {}
            entities.append(ParsedEntity("secret", key, {
                **self._common(g["first"], g["secret"], g["index"]),
                "mode": "history", "file": g["file"],
                "commit": first, "first_commit": first, "last_commit": last,
                "commits": [h for h, _ in ordered], "commits_count": len(ordered),
                "author": meta.get("author"), "email": meta.get("author_email"),
                "date": meta.get("date"), "commit_message": (meta.get("message") or "")[:200] or None,
            }))
        return entities

    def _commit_meta(self, project: Project, ctx: RunContext) -> dict[str, dict]:
        report = ctx.raw_dir(project.name, "gittools", "extract") / "report.json"
        try:
            return {c["hash"]: c for c in json.loads(report.read_text(encoding="utf-8"))["commits"]}
        except (OSError, ValueError, KeyError):
            return {}
