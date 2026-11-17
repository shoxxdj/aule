"""Contrat de plugin : un outil = une sous-classe de `Tool` décorée par `@register`."""
from __future__ import annotations

import json
import os
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ClassVar

from ..config import ToolConfig
from ..models import ParsedEntity, Project


class ToolError(Exception):
    """Erreur lisible par l'auditeur (préparation, mise à jour...)."""


_REGISTRY: dict[str, "Tool"] = {}
#: mode des lignes « ignoré / indisponible » d'un outil `quiet_skip` (une seule ligne par projet)
PLACEHOLDER_MODE = "-"


@dataclass
class RunContext:
    """Ce qu'un plugin a le droit de connaître de l'exécution en cours."""

    data_dir: Path
    run_id: str
    cfg: ToolConfig
    exe: list[str]  # launcher + binaire résolu, prêt à être placé en tête de commande
    timeout: int = 1800  # délai (s) applicable aux étapes lancées par le plugin lui-même (post_run)

    def raw_dir(self, project: str, tool: str, mode: str) -> Path:
        """Dossier de sortie brute d'une autre exécution (ex. résultat de cloc ou de gittools)."""
        return self.data_dir / "runs" / self.run_id / project / tool / mode

    def languages(self, project: str) -> dict[str, int] | None:
        """Technologies détectées par cloc pour ce projet : {langage: lignes de code}.
        None = inconnu (cloc non lancé ou en échec) ; {} = cloc a réussi mais n'a rien trouvé."""
        raw = self.raw_dir(project, "cloc", "default")
        report = raw / "report.json"
        try:
            if report.exists():
                data = json.loads(report.read_text(encoding="utf-8") or "{}")
                return {k: int(v.get("code", 0)) for k, v in data.items() if k not in ("header", "SUM")}
            if json.loads((raw / "meta.json").read_text(encoding="utf-8")).get("status") == "ok":
                return {}  # cloc réussi, rapport absent : rien à compter
        except (OSError, ValueError):
            pass
        return None


class Tool(ABC):
    name: ClassVar[str]
    binary: ClassVar[str]
    alt_binaries: ClassVar[tuple[str, ...]] = ()  # autres noms cherchés dans le PATH
    version_args: ClassVar[tuple[str, ...] | None] = ("--version",)  # None = pas de version
    modes: ClassVar[tuple[str, ...]] = ("default",)
    default_enabled: ClassVar[bool] = True  # False = option (active via aule.yaml, --tools ou --with)
    #: mode -> outil dont il dépend ; si cet outil n'est pas activé, le mode est ignoré silencieusement
    mode_requires: ClassVar[dict[str, str]] = {}
    #: nombre max d'exécutions simultanées de cet outil (ex. base de données partagée) ; None = illimité.
    #: Surchargeable par `max_parallel:` dans aule.yaml.
    max_parallel: ClassVar[int | None] = None
    #: délai par défaut (s) de l'outil quand ni aule.yaml ni --timeout n'en fixent un ; None = global (1800)
    default_timeout: ClassVar[int | None] = None
    #: True pour un outil à nombreux modes dont seuls certains concernent un projet (un mode par langage) :
    #: les modes non applicables ne laissent aucune trace ; si aucun ne s'applique, UNE ligne (mode « - »)
    #: explique pourquoi.
    quiet_skip: ClassVar[bool] = False
    #: True si l'outil produit des entités `secret` dont la valeur en clair se relit via `clear_values`
    secrets_source: ClassVar[bool] = False
    #: True si l'outil a un `update()` (règles, base de vulnérabilités...) : commande `aule update`
    updatable: ClassVar[bool] = False
    #: codes retour considérés comme un succès (gitleaks renvoie 1 s'il trouve des fuites)
    ok_exit_codes: ClassVar[frozenset[int]] = frozenset({0})
    report_filename: ClassVar[str] = "report.json"
    #: True si l'outil écrit son rapport sur stdout (ex. opengrep --sarif)
    capture_stdout: ClassVar[bool] = False
    #: True si l'absence de rapport avec un code retour OK est normale (rien à analyser)
    report_optional: ClassVar[bool] = False

    def resolve(self, cfg: ToolConfig) -> list[str] | None:
        """Commande de base (launcher + exécutable) ou None si introuvable."""
        target = cfg.path or self.binary
        launcher = list(cfg.launcher)
        explicit = bool(cfg.path) and (os.sep in target or "/" in target)
        if explicit:
            p = Path(target)
            if not p.is_file():
                return None
            if not launcher and not os.access(p, os.X_OK):
                if p.suffix != ".sh":
                    return None
                launcher = ["bash"]  # script .sh non exécutable : on le lance avec bash
            found = str(p)
        else:
            names = [target] if cfg.path else [target, *self.alt_binaries]
            found = next((w for n in names if (w := shutil.which(n))), None)
        return [*launcher, found] if found else None

    def phase(self, mode: str) -> int:
        """Les phases s'exécutent dans l'ordre ; une phase dépend des résultats des précédentes."""
        return 0

    def prerequisites(self, cfg: ToolConfig, data_dir: Path) -> str | None:
        """Message d'erreur si l'outil ne peut pas tourner (règles absentes...), sinon None.
        Évalué une fois par run ; les exécutions sont alors marquées `unavailable`."""
        return None

    def version_info(self, cfg: ToolConfig, data_dir: Path) -> str | None:
        """Complément de version tracé dans le rapport (ex. révision du jeu de règles)."""
        return None

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        """L'outil/mode s'applique-t-il à ce projet ? (évalué juste avant sa phase)"""
        return True

    def reason(self, project: Project, mode: str, ctx: RunContext) -> str:
        """Pourquoi `applicable` est faux (affiché dans le rapport)."""
        return "non applicable"

    def cwd(self, project: Project, mode: str, ctx: RunContext) -> Path | None:
        """Dossier de travail de la commande (None = celui de l'auditeur)."""
        return None

    def notice(self, cfg: ToolConfig) -> str | None:
        """Avertissement affiché au lancement (ex. données envoyées à un service tiers)."""
        return None

    def clear_values(self, report_path: Path) -> dict[int, tuple[str, str]] | None:
        """{raw_index: (secret en clair, ligne)} relu dans la sortie brute (outils `secrets_source`)."""
        return None

    def sensitive_values(self, ctx: RunContext) -> list[str]:
        """Valeurs à masquer (« *** ») dans cmd.txt, meta.json, la base et les journaux."""
        return []

    @abstractmethod
    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        """Ligne de commande à exécuter ; le rapport doit être écrit dans `report_path`."""

    def check_result(self, exit_code: int | None, report_path: Path) -> str | None:
        """Cohérence code retour / rapport (après capture). Message = échec. Utile quand un code « succès »
        ambigu (ex. 1 = résultats trouvés) pourrait aussi masquer une erreur."""
        return None

    def post_run(self, project: Project, mode: str, raw_dir: Path, report_path: Path, ctx: RunContext) -> None:
        """Appelé après un succès (ex. fabriquer report.json depuis des fichiers produits).
        Lever une exception marque l'exécution en échec."""

    @abstractmethod
    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        """Transforme le rapport brut en entités normalisées. Doit être rejouable."""

    def update(self, cfg: ToolConfig, exe: list[str] | None, data_dir: Path, log: Callable[[str], None]) -> None:
        """Met à jour règles / base de données (réseau). Lever ToolError en cas d'échec."""
        raise ToolError(f"{self.name} n'a rien à mettre à jour")


def register(cls: type[Tool]) -> type[Tool]:
    _REGISTRY[cls.name] = cls()
    return cls
