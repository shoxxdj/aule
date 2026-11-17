"""Navigation dans le code des projets audités (interface locale) : arborescence, lecture par fenêtres de lignes, recherche.

Tout est confiné à la racine du projet (traversée, liens symboliques sortants et `.git` refusés), borné (taille, nombre
d'entrées, longueur des lignes) et lu à la demande. En mode `--mask`, les secrets connus du projet et les jetons évidents sont
masqués dans ce qui est servi, et les fichiers sensibles (`.env`, clés privées…) refusés : le code reste consultable sans
que les secrets quittent le serveur.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .critiq import Redactor, _glob_re

MAX_FILE = 5 * 1024 * 1024
MAX_WINDOW = 2000
MAX_LINE = 2000
MAX_ENTRIES = 3000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", ".gradle", ".idea"}
LANG = {".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript", ".java": "java", ".kt": "kotlin", ".go": "go",
        ".rb": "ruby", ".php": "php", ".cs": "csharp", ".c": "c", ".h": "c", ".cpp": "cpp", ".rs": "rust", ".sh": "shell", ".yml": "yaml", ".yaml": "yaml",
        ".json": "json", ".xml": "xml", ".tf": "terraform", ".html": "html", ".css": "css", ".sql": "sql", ".md": "markdown", ".toml": "toml"}


class CodeError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


@dataclass
class Source:
    root: Path
    is_git: bool = False
    mask: bool = False                  # mode --mask : expurgation + fichiers sensibles refusés
    redact: Redactor = field(default_factory=Redactor)
    deny: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self._deny = [_glob_re(g) for g in self.deny]
        self.root = self.root.resolve()

    def clean(self, rel: str) -> str:
        rel = (rel or "").replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        rel = rel.strip("/")
        parts = rel.split("/") if rel else []
        if "\0" in rel or ".." in parts or (len(rel) > 1 and rel[1] == ":"):
            raise CodeError(400, "chemin invalide")
        if parts and parts[0] == ".git":
            raise CodeError(403, "le dossier .git n'est pas navigable (utilisez « voir à ce commit »)")
        return rel

    def denied(self, rel: str) -> bool:
        return self.mask and any(rx.match(rel) for rx in self._deny)

    def path(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if p != self.root and not p.is_relative_to(self.root):
            raise CodeError(403, "hors du projet")  # lien symbolique sortant, ou traversée
        return p


def _guess_lang(rel: str) -> str | None:
    return LANG.get(Path(rel).suffix.lower())


def list_dir(src: Source, rel: str = "") -> dict[str, Any]:
    rel = src.clean(rel)
    d = src.path(rel)
    if not d.is_dir():
        raise CodeError(404, "dossier introuvable")
    entries, truncated = [], False
    try:
        children = sorted(os.scandir(d), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.casefold()))
    except OSError as exc:
        raise CodeError(403, f"dossier illisible : {exc.strerror}") from exc
    for e in children:
        if e.name == ".git":
            continue
        child = f"{rel}/{e.name}" if rel else e.name
        if src.denied(child):
            continue
        if len(entries) >= MAX_ENTRIES:
            truncated = True
            break
        if e.is_symlink():
            entries.append({"name": e.name, "type": "link", "size": None})
        elif e.is_dir():
            entries.append({"name": e.name, "type": "dir", "size": None})
        else:
            try:
                entries.append({"name": e.name, "type": "file", "size": e.stat().st_size})
            except OSError:
                continue
    return {"path": rel, "entries": entries, "truncated": truncated}


def _read_text(src: Source, rel: str, ref: str | None) -> str:
    if ref:
        if not (src.is_git and re.fullmatch(r"[0-9a-fA-F]{7,40}|HEAD", ref)):
            raise CodeError(400, "révision invalide (identifiant de commit attendu)")
        try:
            out = subprocess.run(["git", "-C", str(src.root), "show", f"{ref}:{rel}"], capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CodeError(500, "git indisponible") from exc
        if out.returncode != 0:
            raise CodeError(404, f"fichier absent du commit {ref[:8]}")
        raw = out.stdout
        if len(raw) > MAX_FILE:
            raise CodeError(413, "fichier trop volumineux")
    else:
        p = src.path(rel)
        if not p.is_file():
            raise CodeError(404, "fichier introuvable")
        if p.stat().st_size > MAX_FILE:
            raise CodeError(413, f"fichier trop volumineux (> {MAX_FILE // 1024 // 1024} Mo) : ouvrez-le depuis le disque")
        raw = p.read_bytes()
    if b"\0" in raw[:8192]:
        raise CodeError(415, "fichier binaire")
    text = raw.decode("utf-8", "replace")
    return src.redact(text) if src.mask else text


def read_lines(src: Source, rel: str, *, start: int | None = None, end: int | None = None, around: int | None = None,
               window: int = 400, ref: str | None = None) -> dict[str, Any]:
    rel = src.clean(rel)
    if not rel:
        raise CodeError(400, "chemin de fichier requis")
    if src.denied(rel):
        raise CodeError(403, "fichier sensible : non affiché en mode --mask")
    lines = _read_text(src, rel, ref).splitlines()
    total, window = len(lines), max(1, min(window, MAX_WINDOW))
    if around is not None:
        start = max(1, around - window // 2)
    start = max(1, start or 1)
    end = min(total, end if end else start + window - 1, start + MAX_WINDOW - 1)
    if total and start > total:
        start, end = max(1, total - window + 1), total
    shown, cut = [], 0
    for line in lines[start - 1:end]:
        if len(line) > MAX_LINE:
            line, cut = line[:MAX_LINE] + " …", cut + 1
        shown.append(line)
    return {"path": rel, "ref": ref, "total": total, "start": start, "end": start + len(shown) - 1 if shown else start - 1, "lines": shown,
            "language": _guess_lang(rel), "long_lines_cut": cut, "redacted": src.mask}


def find_in_file(src: Source, rel: str, needle: str, *, case: bool = False, ref: str | None = None) -> dict[str, Any]:
    rel = src.clean(rel)
    if not (1 <= len(needle) <= 200):
        raise CodeError(400, "recherche : 1 à 200 caractères")
    if src.denied(rel):
        raise CodeError(403, "fichier sensible : non affiché en mode --mask")
    key = needle if case else needle.casefold()
    hits = [n for n, line in enumerate(_read_text(src, rel, ref).splitlines(), 1) if key in (line if case else line.casefold())]
    return {"path": rel, "matches": hits[:1000], "total": len(hits), "capped": len(hits) > 1000}


def _walk(src: Source):
    for dirpath, dirnames, filenames in os.walk(src.root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (Path(dirpath) / d).is_symlink())
        base = Path(dirpath).relative_to(src.root).as_posix()
        for name in sorted(filenames):
            rel = name if base == "." else f"{base}/{name}"
            if not src.denied(rel):
                yield rel, Path(dirpath) / name


def search_project(src: Source, needle: str, *, case: bool = False, limit: int = 200) -> dict[str, Any]:
    if not (3 <= len(needle) <= 200):
        raise CodeError(400, "recherche : 3 à 200 caractères")
    key = needle if case else needle.casefold()
    results, scanned, capped = [], 0, False
    for rel, path in _walk(src):
        scanned += 1
        if scanned > 8000:
            capped = True
            break
        try:
            if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue
        text = raw.decode("utf-8", "replace")
        if src.mask:
            text = src.redact(text)
        for n, line in enumerate(text.splitlines(), 1):
            if key in (line if case else line.casefold()):
                results.append({"file": rel, "line": n, "text": line.strip()[:200]})
                if len(results) >= limit:
                    return {"results": results, "scanned": scanned, "capped": True}
    return {"results": results, "scanned": scanned, "capped": capped}


def list_files(src: Source, query: str, limit: int = 50) -> dict[str, Any]:
    """« Aller au fichier » : chemins contenant `query` (sans casse), les plus courts d'abord."""
    q, found, scanned = query.casefold(), [], 0
    for rel, _ in _walk(src):
        scanned += 1
        if scanned > 30000:
            break
        if q in rel.casefold():
            found.append(rel)
    found.sort(key=lambda r: (len(r), r))
    return {"files": found[:limit], "total": len(found), "capped": scanned > 30000}
