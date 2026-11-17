"""Décompression (optionnelle) des archives trouvées dans les projets.

Chaque archive décompressée devient un projet dérivé `<projet>@<chemin_archive>` analysé comme les
autres : si elle contient un `.git`, l'historique devient analysable (gitleaks git, gittools...).

Sécurité : les archives viennent du client, donc potentiellement hostiles. On refuse les chemins qui
sortent du dossier cible (zip-slip), on ignore liens symboliques et fichiers spéciaux, et on borne
la taille décompressée et le nombre de fichiers (bombes de décompression).
"""
from __future__ import annotations

import os
import shutil
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import UnpackConfig
from .discovery import build_project
from .models import Project

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}


class ArchiveError(Exception):
    pass


@dataclass
class UnpackEvent:
    project: str     # projet dans lequel l'archive a été trouvée
    archive: str     # chemin relatif de l'archive
    status: str      # ok | failed
    error: str | None = None
    files: int = 0
    skipped: int = 0  # liens symboliques, fichiers spéciaux, chemins dangereux


def find_archives(root: Path, extensions: tuple[str, ...]) -> list[Path]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        found += [Path(dirpath) / f for f in sorted(filenames) if f.lower().endswith(extensions)]
    return found


def _safe_target(dest: Path, name: str) -> Path | None:
    name = name.replace("\\", "/")
    if not name or name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    target = (dest / name).resolve()
    return target if target.is_relative_to(dest.resolve()) else None


def _copy_limited(src, out, budget: list[int]) -> None:
    """Copie en comptant les octets réellement écrits (la taille déclarée peut mentir)."""
    while chunk := src.read(1 << 20):
        budget[0] -= len(chunk)
        if budget[0] < 0:
            raise ArchiveError("taille décompressée supérieure à la limite (bombe de décompression ?)")
        out.write(chunk)


def _extract_zip(archive: Path, dest: Path, cfg: UnpackConfig) -> tuple[int, int]:
    files = skipped = 0
    budget = [cfg.max_total_mb * 1024 * 1024]
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > cfg.max_files:
            raise ArchiveError(f"{len(infos)} entrées (limite {cfg.max_files})")
        for info in infos:
            if info.flag_bits & 0x1:
                raise ArchiveError("archive chiffrée (mot de passe requis)")
            target = _safe_target(dest, info.filename)
            is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
            if target is None or is_symlink:
                skipped += 1
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                _copy_limited(src, out, budget)
            files += 1
    return files, skipped


def _extract_tar(archive: Path, dest: Path, cfg: UnpackConfig) -> tuple[int, int]:
    skipped = total = 0
    safe: list[tarfile.TarInfo] = []
    with tarfile.open(archive) as tf:
        for m in tf:
            if not (m.isfile() or m.isdir()) or _safe_target(dest, m.name) is None:
                skipped += 1
                continue
            total += m.size
            safe.append(m)
            if len(safe) > cfg.max_files:
                raise ArchiveError(f"plus de {cfg.max_files} entrées")
            if total > cfg.max_total_mb * 1024 * 1024:
                raise ArchiveError("taille décompressée supérieure à la limite (bombe de décompression ?)")
        try:
            tf.extractall(dest, members=safe, filter="data")
        except TypeError:  # Python < 3.11.4 : pas de filtre, mais les membres sont déjà filtrés
            tf.extractall(dest, members=safe)
    return sum(1 for m in safe if m.isfile()), skipped


def extract_archive(archive: Path, dest: Path, cfg: UnpackConfig) -> tuple[int, int]:
    """Retourne (fichiers extraits, éléments ignorés). Lève ArchiveError."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        if zipfile.is_zipfile(archive):
            return _extract_zip(archive, dest, cfg)
        if tarfile.is_tarfile(archive):
            return _extract_tar(archive, dest, cfg)
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, RuntimeError) as exc:
        raise ArchiveError(f"archive illisible : {exc}") from exc
    raise ArchiveError("format non reconnu (zip, tar, tar.gz, tar.bz2, tar.xz gérés)")


def unpack_projects(projects: list[Project], work_dir: Path, cfg: UnpackConfig
                    ) -> tuple[list[Project], list[UnpackEvent]]:
    """Décompresse les archives de chaque projet et renvoie les projets dérivés."""
    derived: list[Project] = []
    events: list[UnpackEvent] = []
    frontier = [(p, 1) for p in projects]
    while frontier:
        project, depth = frontier.pop(0)
        for archive in find_archives(project.path, cfg.extensions):
            rel = archive.relative_to(project.path).as_posix()
            name = f"{project.name}@{rel.replace('/', '__')}"
            dest, marker = work_dir / name, work_dir / f"{name}.done"
            try:
                if marker.exists() and dest.is_dir():  # reprise : déjà décompressée
                    files = skipped = 0
                else:
                    shutil.rmtree(dest, ignore_errors=True)
                    files, skipped = extract_archive(archive, dest, cfg)
                    marker.write_text("ok")
            except ArchiveError as exc:
                shutil.rmtree(dest, ignore_errors=True)
                events.append(UnpackEvent(project.name, rel, "failed", str(exc)))
                continue
            entries = list(dest.iterdir())
            # Archive à dossier unique (site/, repo-main/...) : la racine du projet est ce dossier.
            root = entries[0] if len(entries) == 1 and entries[0].is_dir() and entries[0].name != ".git" else dest
            child = build_project(name, root, parent=project.name, origin=rel)
            derived.append(child)
            events.append(UnpackEvent(project.name, rel, "ok", files=files, skipped=skipped))
            if depth < cfg.max_depth:
                frontier.append((child, depth + 1))
    return derived, events
