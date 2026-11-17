from __future__ import annotations

import json
from pathlib import Path

from ..models import ParsedEntity, Project
from .base import RunContext, Tool, register

DEFAULT_EXCLUDED_DIRS = ["node_modules", ".venv", "venv", "__pycache__"]


@register
class Cloc(Tool):
    """Options aule.yaml : `exclude_dirs` (liste de noms de dossiers)."""

    name = "cloc"
    binary = "cloc"
    report_optional = True  # cloc n'écrit rien si le dossier ne contient aucun code

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        excluded = ctx.cfg.options.get("exclude_dirs", DEFAULT_EXCLUDED_DIRS)
        cmd = [*ctx.exe, "--json", "--quiet", f"--report-file={report_path}"]
        if excluded:
            cmd.append(f"--exclude-dir={','.join(excluded)}")
        return [*cmd, *ctx.cfg.extra_args, str(project.path)]

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        if not report_path.exists() or not report_path.read_text(encoding="utf-8").strip():
            return []
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return [
            ParsedEntity(
                kind="technology",
                fingerprint=f"{project.name}:technology:{lang}",
                data={
                    "language": lang,
                    "files": stats.get("nFiles", 0),
                    "blank": stats.get("blank", 0),
                    "comment": stats.get("comment", 0),
                    "code": stats.get("code", 0),
                },
            )
            for lang, stats in data.items()
            if lang not in ("header", "SUM")
        ]
