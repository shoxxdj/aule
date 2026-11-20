from __future__ import annotations

import hashlib

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Project:
    """Une unité à analyser : un sous-dossier du dossier audité, ou une archive décompressée.

    parent : nom du projet d'origine (archives décompressées) ; origin : chemin de l'archive.
    """

    name: str
    path: Path
    is_git: bool
    head_commit: str | None = None
    parent: str | None = None
    origin: str | None = None


@dataclass
class ParsedEntity:
    """Objet normalisé produit par le parseur d'un outil.

    kind         : 'technology', 'secret', 'commit', 'sast_finding', 'dependency', ...
    fingerprint  : identifiant stable entre deux runs (sert au triage)
    data         : payload libre, stocké en JSON
    """

    kind: str
    fingerprint: str
    data: dict[str, Any] = field(default_factory=dict)


# --- constantes et aides partagées (étaient recopiées dans plusieurs modules) ---------------------------------------
SEVERITIES = ("critical", "high", "medium", "low", "info")            # du plus grave au moins grave
SEV_RANK = {s: len(SEVERITIES) - 1 - i for i, s in enumerate(SEVERITIES)}   # critical 4 … info 0
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", ".gradle", ".idea", ".tox"}   # jamais parcourus (recherche, liens, navigation)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
