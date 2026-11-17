from __future__ import annotations

import subprocess
from pathlib import Path

from .models import Project


def _head_commit(path: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (out.stdout.strip() or None) if out.returncode == 0 else None


def build_project(name: str, path: Path, parent: str | None = None, origin: str | None = None) -> Project:
    is_git = (path / ".git").exists()  # dossier, ou fichier pour worktree/submodule
    return Project(name, path, is_git, _head_commit(path) if is_git else None, parent, origin)


def discover_projects(root: Path, exclude: tuple[Path | str, ...] = ()) -> list[Project]:
    """Chaque sous-dossier direct de `root` est un projet.

    Les dossiers cachés, les liens symboliques et les chemins/noms de `exclude`
    (typiquement le dossier de données) sont ignorés.
    """
    root = root.resolve()
    excluded_paths = {Path(e).resolve() for e in exclude}
    excluded_names = {str(e) for e in exclude}
    projects: list[Project] = []
    for child in sorted(root.iterdir()):
        if child.name.startswith(".") or child.is_symlink() or not child.is_dir():
            continue
        if child.resolve() in excluded_paths or child.name in excluded_names:
            continue
        projects.append(build_project(child.name, child))
    return projects
