"""Checkov (Prisma Cloud / Bridgecrew) : mauvaises configurations d'infrastructure as code.

Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, GitHub Actions... Lancé seulement si un fichier d'IaC
est détecté (*.tf, Dockerfile*, docker-compose.y*ml, chart.yaml...). Résultats dans l'onglet Code (SAST),
catégorie `iac`. Sans clé d'API Prisma, Checkov ne fournit pas de sévérité : `options.default_severity`
(défaut `medium`) s'applique.

Options aule.yaml (tools.checkov.options) : default_severity.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..models import ParsedEntity, Project
from ..techmap import detect_ecosystems
from ..vulns import normalize_severity
from .base import RunContext, Tool, register


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@register
class Checkov(Tool):
    name = "checkov"
    binary = "checkov"
    modes = ("scan",)
    default_enabled = False
    report_filename = "results_json.json"  # nom imposé par checkov dans --output-file-path
    ok_exit_codes = frozenset({0, 1})  # 1 = contrôles en échec

    def phase(self, mode: str) -> int:
        return 1

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return "iac" in detect_ecosystems(ctx.languages(project.name), project.path)

    def reason(self, project: Project, mode: str, ctx: RunContext) -> str:
        return "aucun fichier d'infrastructure as code détecté (Terraform, Dockerfile, Compose, Helm...)"

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        return [*ctx.exe, "-d", str(project.path), "-o", "json", "--output-file-path", str(report_path.parent),
                "--quiet", "--compact", *ctx.cfg.extra_args]

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        text = report_path.read_text(encoding="utf-8").strip() if report_path.exists() else ""
        if not text:
            return []
        doc = json.loads(text)
        default = str(ctx.cfg.options.get("default_severity", "medium"))
        entities: list[ParsedEntity] = []
        seen: dict[str, int] = {}
        for framework in doc if isinstance(doc, list) else [doc]:  # un objet par framework si plusieurs
            for f in ((framework.get("results") or {}).get("failed_checks")) or []:
                lines = f.get("file_line_range") or [None, None]
                file = (f.get("file_path") or "").lstrip("/").replace("\\", "/")
                fp = _sha("|".join([project.name, self.name, str(f.get("check_id")), file, str(f.get("resource"))]))[:24]
                seen[fp] = seen.get(fp, 0) + 1
                code = "".join(str(c[1]) for c in f.get("code_block") or [] if len(c) > 1)
                entities.append(ParsedEntity("sast_finding", fp if seen[fp] == 1 else f"{fp}#{seen[fp]}", {
                    "tool": self.name, "rule_id": f.get("check_id") or "unknown", "rule_name": f.get("check_name"),
                    "severity": normalize_severity(f.get("severity") or default),
                    "level": None, "security_severity": None,
                    "message": f"{f.get('check_name')} — ressource {f.get('resource')}"[:1000], "file": file,
                    "start_line": lines[0], "end_line": lines[1], "start_col": None, "end_col": None,
                    "snippet": code[:2000] or None, "cwe": [], "owasp": [],
                    "tags": [t for t in [framework.get("check_type"), "iac"] if t], "confidence": None,
                    "help_uri": f.get("guideline"), "flow": [], "category": "iac"}))
        return entities
