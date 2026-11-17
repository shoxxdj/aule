"""Rétention : supprime des runs entiers ou seulement leurs données volumineuses.

`data/` grossit vite : arbres complets de GitTools (un par commit), bases CodeQL, archives décompressées.
Le triage, les constats et les notes sont GLOBAUX et ne sont jamais supprimés.
Par défaut rien n'est effacé (plan seul) ; `apply=True` exécute.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import Database

_RUN_ID = re.compile(r"^\d{8}-\d{6}(-\d+)?$")


@dataclass
class Item:
    path: Path
    size: int
    run: str
    kind: str   # run | work | extracted | report | export


def dir_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file() and not f.is_symlink())


def human(n: int) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} o"


def _safe(data_dir: Path, path: Path) -> bool:
    return path.resolve().is_relative_to(data_dir.resolve()) and path.resolve() != data_dir.resolve()


def select_runs(db: Database, runs: list[str] | None, older_than_days: int | None, keep: int | None) -> list[str]:
    audits = db.list_audits()  # du plus récent au plus ancien
    ids = [a["id"] for a in audits]
    chosen: set[str] = set()
    for r in runs or []:
        if r not in ids:
            raise ValueError(f"run inconnu : {r}")
        chosen.add(r)
    if older_than_days is not None:
        limit = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        for a in audits:
            started = datetime.fromisoformat(a["started_at"])
            if (started if started.tzinfo else started.replace(tzinfo=timezone.utc)) < limit:
                chosen.add(a["id"])
    if keep is not None:
        chosen.update(ids[max(0, keep):])
    return [i for i in ids if i in chosen]


def plan_purge(db: Database, data_dir: Path, *, runs: list[str] | None = None, older_than_days: int | None = None,
               keep: int | None = None, heavy: bool = False) -> tuple[list[str], list[Item]]:
    doomed = select_runs(db, runs, older_than_days, keep)
    items: list[Item] = []

    def add(path: Path, run: str, kind: str) -> None:
        if _RUN_ID.match(run) and path.exists() and _safe(data_dir, path):
            items.append(Item(path, dir_size(path), run, kind))

    for run in doomed:
        add(data_dir / "runs" / run, run, "run")
        add(data_dir / "work" / run, run, "work")
        # noms EXACTS : un motif `report-<run>*` capterait aussi `<run>-2`, `<run>-3` (runs de la même seconde)
        own = re.compile(rf"^(report|export)-{re.escape(run)}(-masque)?\.\w+$")
        for f in sorted(data_dir.iterdir()) if data_dir.is_dir() else []:
            if f.is_file() and (m := own.match(f.name)):
                add(f, run, "report" if m.group(1) == "report" else "export")
    if heavy:
        for a in db.list_audits():
            if a["id"] in doomed:
                continue
            add(data_dir / "work" / a["id"], a["id"], "work")  # archives décompressées, bases CodeQL
            for extracted in sorted((data_dir / "runs" / a["id"]).glob("*/gittools/extract/extracted")):
                add(extracted, a["id"], "extracted")  # arbres complets par commit (report.json conservé)
    return doomed, items


def apply_purge(db: Database, data_dir: Path, doomed: list[str], items: list[Item]) -> int:
    freed = 0
    for it in items:
        if not _safe(data_dir, it.path):
            continue
        freed += it.size
        shutil.rmtree(it.path, ignore_errors=True) if it.path.is_dir() else it.path.unlink(missing_ok=True)
    for run in doomed:
        db.delete_audit(run)
    if doomed:
        db.conn.execute("VACUUM")
    return freed
