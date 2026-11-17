"""GitTools « Extractor » (internetwache/GitTools) : reconstruit chaque commit d'un `.git`
(même incomplet ou récupéré d'un serveur/archive) dans un dossier `<n>-<hash>/`.

Outil optionnel : désactivé par défaut. Il alimente :
  - la liste des commits (entités `commit`, onglet « Historique ») ;
  - le mode `history` de gitleaks, qui scanne tous les commits extraits.
Attention : un arbre complet est écrit par commit, l'espace disque peut être important.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..models import ParsedEntity, Project
from .base import RunContext, Tool, register

_DIR_RE = re.compile(r"^(\d+)-([0-9a-fA-F]{6,40})$")
_IDENT_RE = re.compile(r"^(.*?) <(.*?)> (\d+) ([+-])(\d{2})(\d{2})$")


def _iso(ts: str, sign: str, hh: str, mm: str) -> str:
    offset = timedelta(hours=int(hh), minutes=int(mm)) * (-1 if sign == "-" else 1)
    return datetime.fromtimestamp(int(ts), tz=timezone(offset)).isoformat()


def parse_commit_meta(text: str) -> dict:
    """Lit un `commit-meta.txt` au format `git cat-file -p <commit>` (tolérant)."""
    head, _, message = text.partition("\n\n")
    meta: dict = {"parents": [], "message": message.strip()[:500]}
    for line in head.splitlines():
        key, _, value = line.partition(" ")
        if key == "tree":
            meta["tree"] = value
        elif key == "parent":
            meta["parents"].append(value)
        elif key in ("author", "committer"):
            m = _IDENT_RE.match(value)
            if m:
                meta[key], meta[f"{key}_email"] = m[1], m[2]
                meta[f"{key}_date"] = _iso(m[3], m[4], m[5], m[6])
            else:
                meta[key] = value
    meta["date"] = meta.get("author_date") or meta.get("committer_date")
    if "author" not in meta:  # format inattendu : on garde le brut plutôt que de perdre l'info
        meta["raw_meta"] = text[:1000]
    return meta


@register
class GitTools(Tool):
    name = "gittools"
    binary = "extractor.sh"
    version_args = None
    modes = ("extract",)
    default_enabled = False

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return (project.path / ".git").exists()

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        # extractor.sh <dépôt contenant .git> <dossier de sortie (créé par le script)>
        return [*ctx.exe, str(project.path), str(report_path.parent / "extracted")]

    def post_run(self, project: Project, mode: str, raw_dir: Path, report_path: Path, ctx: RunContext) -> None:
        out = raw_dir / "extracted"
        commits = []
        for d in out.iterdir() if out.is_dir() else []:
            m = _DIR_RE.match(d.name)
            if not (d.is_dir() and m):
                continue
            meta_file = d / "commit-meta.txt"
            meta = parse_commit_meta(meta_file.read_text(encoding="utf-8", errors="replace")) if meta_file.exists() else {}
            commits.append({"index": int(m[1]), "hash": m[2], "dir": d.name, **meta})
        if not commits:
            raise RuntimeError("aucun commit extrait (.git vide ou incomplet)")
        commits.sort(key=lambda c: c["index"])
        report_path.write_text(json.dumps({"extracted_dir": "extracted", "commits": commits},
                                          indent=2, ensure_ascii=False), encoding="utf-8")

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return [ParsedEntity("commit", f"{project.name}:commit:{c['hash']}", c) for c in data["commits"]]
