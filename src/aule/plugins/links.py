"""Références inter-projets : dépôt d'origine, paquets publiés/requis, chemins locaux, hôtes.

Outil interne (pas de binaire) : lance `python -m aule.linkscan`. Il est activé par défaut car il est
léger et alimente le calcul des liens entre projets (voir links.py), fait une fois tous les outils passés.

Options aule.yaml (tools.links.options) : ignore_hosts — hôtes à ne pas relier (en plus des hôtes publics
courants : github.com, registres de paquets, w3.org...). Un suffixe de domaine suffit (« corp.example »).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..config import ToolConfig
from ..models import ParsedEntity, Project
from .base import RunContext, Tool, register


@register
class Links(Tool):
    name = "links"
    binary = "python"
    modes = ("scan",)
    version_args = None
    default_enabled = True

    def resolve(self, cfg: ToolConfig) -> list[str] | None:
        return [sys.executable, "-m", "aule.linkscan"]  # toujours disponible

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        return [*ctx.exe, str(project.path), str(report_path)]

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        refs = json.loads(report_path.read_text(encoding="utf-8")).get("references") or []
        return [ParsedEntity("reference", f"{project.name}:ref:{r['type']}:{r['value']}", r) for r in refs]
