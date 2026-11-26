"""Opengrep + jeu de règles https://github.com/opengrep/opengrep-rules

Ciblage par technologie : après cloc, seuls les dossiers de règles correspondant aux langages détectés
du projet sont passés à opengrep (`--config <règles>/<langage>`). Sans technologie reconnue, le projet est
ignoré (raison indiquée dans le rapport). Si cloc n'a pas tourné, tous les dossiers de règles sont utilisés.

Préparation : `aule update opengrep` clone / met à jour les règles (réseau, git).

Options aule.yaml (tools.opengrep.options) :
  rules_path      dossier du clone (défaut : <data>/rules/opengrep-rules)
  rules_repo      dépôt des règles (défaut : https://github.com/opengrep/opengrep-rules)
  rule_dirs       force la liste des dossiers de règles (désactive le ciblage par technologie)
  always_include  dossiers toujours ajoutés (ex. [generic])
  exclude_rule_dirs  dossiers jamais utilisés
  language_map    correspondances supplémentaires {langage cloc: dossier de règles}
  exclude         chemins exclus du scan (défaut : node_modules, .venv, venv)
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from ..config import ToolConfig
from ..models import ParsedEntity, Project
from ..sarif import parse_sarif
from ..techmap import OPENGREP_RULE_DIRS
from .base import RunContext, Tool, ToolError, register

DEFAULT_REPO = "https://github.com/opengrep/opengrep-rules"
DEFAULT_EXCLUDE = ["node_modules", ".venv", "venv"]


def _git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=900)


@register
class Opengrep(Tool):
    name = "opengrep"
    binary = "opengrep"
    modes = ("scan",)
    default_enabled = False
    supports_rules = True  # tools.opengrep.rules : chaque dossier/fichier devient un `--config`, en plus du jeu communautaire
    updatable = True
    report_filename = "report.sarif"
    capture_stdout = True  # `opengrep scan --sarif` écrit le SARIF sur stdout, les journaux sur stderr
    ok_exit_codes = frozenset({0, 1})

    def phase(self, mode: str) -> int:
        return 1  # a besoin des technologies détectées par cloc (phase 0)

    # --- règles ------------------------------------------------------------
    def rules_path(self, cfg: ToolConfig, data_dir: Path) -> Path:
        return Path(cfg.options.get("rules_path") or data_dir / "rules" / "opengrep-rules")

    def prerequisites(self, cfg: ToolConfig, data_dir: Path) -> str | None:
        rules = self.rules_path(cfg, data_dir)
        if (not rules.is_dir() or not self._available_dirs(rules)) and not cfg.rules:  # vos règles suffisent sans le jeu communautaire
            return (f"jeu de règles introuvable ou vide : {rules} — lancez `aule update opengrep` "
                    "ou renseignez tools.opengrep.options.rules_path")
        return None

    def version_info(self, cfg: ToolConfig, data_dir: Path) -> str | None:
        rules = self.rules_path(cfg, data_dir)
        try:
            out = _git(["-C", str(rules), "rev-parse", "--short=8", "HEAD"])
        except (OSError, subprocess.TimeoutExpired):
            return f"règles {rules.name}"
        return f"règles {rules.name}@{out.stdout.strip()}" if out.returncode == 0 and out.stdout.strip() else f"règles {rules.name}"

    @staticmethod
    def _available_dirs(rules: Path) -> set[str]:
        return {d.name for d in rules.iterdir() if d.is_dir() and not d.name.startswith(".")}

    def _rule_dirs(self, project: Project, ctx: RunContext) -> list[Path]:
        rules = self.rules_path(ctx.cfg, ctx.data_dir)
        if not rules.is_dir():
            return []
        opts, available = ctx.cfg.options, self._available_dirs(rules)
        if opts.get("rule_dirs"):
            names = set(opts["rule_dirs"])
        else:
            languages = ctx.languages(project.name)
            if languages is None:  # cloc absent : pas d'information, on prend tout
                names = set(available)
            else:
                mapping = {**OPENGREP_RULE_DIRS, **(opts.get("language_map") or {})}
                names = {mapping[lang] for lang in languages if lang in mapping}
            names |= set(opts.get("always_include") or [])
        names -= set(opts.get("exclude_rule_dirs") or [])
        return [rules / n for n in sorted(names & available)]

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return bool(self._rule_dirs(project, ctx)) or bool(ctx.cfg.rules)  # vos règles déclarent leurs langages : elles s'appliquent même sans technologie reconnue

    def reason(self, project: Project, mode: str, ctx: RunContext) -> str:
        languages = ctx.languages(project.name)
        if languages:
            return "aucune règle pour les technologies détectées : " + ", ".join(sorted(languages))
        return "aucune technologie détectée par cloc" if languages == {} else "aucun dossier de règles applicable"

    # --- exécution ---------------------------------------------------------
    def cwd(self, project: Project, mode: str, ctx: RunContext) -> Path | None:
        return project.path  # chemins du rapport relatifs au projet

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        cmd = [*ctx.exe, "scan", "--sarif"]
        for d in self._rule_dirs(project, ctx):
            cmd += ["--config", str(d)]
        for custom in ctx.cfg.rules:
            cmd += ["--config", custom]
        for pattern in ctx.cfg.options.get("exclude", DEFAULT_EXCLUDE):
            cmd += ["--exclude", pattern]
        return [*cmd, *ctx.cfg.extra_args, "."]

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        return parse_sarif(report_path, project.name, project.path)

    # --- mise à jour -------------------------------------------------------
    def update(self, cfg: ToolConfig, exe: list[str] | None, data_dir: Path, log: Callable[[str], None]) -> None:
        rules = self.rules_path(cfg, data_dir)
        repo = cfg.options.get("rules_repo") or DEFAULT_REPO
        try:
            if (rules / ".git").exists():
                log(f"Mise à jour des règles : {rules}")
                out = _git(["-C", str(rules), "pull", "--ff-only"])
            else:
                if rules.exists() and any(rules.iterdir()):
                    raise ToolError(f"{rules} existe et n'est pas un clone git ; supprimez-le ou changez rules_path")
                log(f"Clonage de {repo} -> {rules}")
                rules.parent.mkdir(parents=True, exist_ok=True)
                out = _git(["clone", "--depth", "1", repo, str(rules)])
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolError(f"git indisponible ou délai dépassé : {exc}") from exc
        if out.returncode != 0:
            raise ToolError(f"git a échoué : {(out.stderr or out.stdout).strip().splitlines()[-1:]}")
        log(f"Règles à jour : {self.version_info(cfg, data_dir)}")
