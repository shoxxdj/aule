"""Extrait d'un projet les références qui peuvent le relier à d'autres projets.

Lancé comme sous-processus (`python -m aule.linkscan <projet> <rapport.json>`) par le plugin `links`.
Types de références :
  git_remote  dépôt d'origine, normalisé `hôte/org/dépôt` (identifiants retirés)
  provides    paquet publié par ce projet            `npm:@corp/lib`, `maven:g:a`, `pypi:nom`, `image:nom`...
  requires    paquet dont ce projet dépend
  local_path  chemin local vers un autre dossier (file:../x, ProjectReference, build Compose, replace =>...)
  endpoint    hôte référencé par une URL ou une chaîne de connexion (identifiants retirés)
Tout est lu en texte, avec des bornes de taille et de nombre : un projet hostile ne peut pas bloquer l'analyse.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import yaml

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build", ".tox", ".gradle", ".idea"}
MAX_FILES, MAX_URL_FILES, MAX_HOSTS = 20_000, 3_000, 500
MAX_TEXT, MAX_MANIFEST = 512 * 1024, 2 * 1024 * 1024
TEXT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs", ".yml",
            ".yaml", ".json", ".xml", ".properties", ".toml", ".ini", ".cfg", ".conf", ".sh", ".gradle", ".tf", ".tfvars", ".env"}
XMLNS_RE = re.compile(r"""\b(?:xmlns(?::\w+)?|xsi:schemaLocation)\s*=\s*(?:"[^"]*"|'[^']*')""")  # espaces de noms XML : pas des points d'accès
URL_RE = re.compile(r"""(?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|kafka|ldaps?|s?ftp|smtp|jdbc:[a-z0-9]+)://[^\s'"<>)\]}\\,;`]+""", re.I)


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def normalize_remote(url: str) -> str | None:
    """`git@h:o/r.git`, `https://user:tok@H/o/r/`, `ssh://git@h/o/r` -> `h/o/r` (jamais d'identifiants)."""
    url = url.strip()
    if not url:
        return None
    scp = re.match(r"^[\w.-]+@([\w.-]+):(?!//)(.+)$", url)
    if scp:
        host, path = scp.group(1), scp.group(2)
    else:
        parsed = urlparse(url)
        if not parsed.hostname:  # chemin local : conservé tel quel (deux clones du même chemin se rejoignent)
            return "path:" + url.removesuffix("/").removesuffix(".git")
        host, path = parsed.hostname, parsed.path
    return f"{host}/{path.strip('/')}".removesuffix(".git").lower()


def image_name(ref: str) -> str:
    ref = ref.split("@")[0]
    last = ref.rsplit("/", 1)[-1]
    return (ref.rsplit(":", 1)[0] if ":" in last else ref).lower()


class Collector:
    def __init__(self, root: Path):
        self.root = root
        self.refs: dict[tuple[str, str], dict] = {}

    def add(self, rtype: str, value: str | None, file: str) -> None:
        if not value:
            return
        r = self.refs.setdefault((rtype, value), {"type": rtype, "value": value, "files": [], "count": 0})
        r["count"] += 1
        if file not in r["files"] and len(r["files"]) < 5:
            r["files"].append(file)

    def local(self, base: Path, rel: str, file: str) -> None:
        rel = rel.strip().replace("\\", "/")
        if rel and not re.match(r"^[a-z][a-z0-9+.-]*://", rel):
            self.add("local_path", str((base / rel).resolve()), file)


def _read(path: Path, limit: int = MAX_MANIFEST) -> str:
    return path.read_bytes()[:limit].decode("utf-8", "replace")


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: ET.Element, name: str) -> str:
    for ch in el:
        if _local_tag(ch.tag) == name:
            return (ch.text or "").strip()
    return ""


# ---- manifestes ------------------------------------------------------------------------------------
def _package_json(p: Path, rel: str, c: Collector) -> None:
    d = json.loads(_read(p))
    if d.get("name"):
        c.add("provides", f"npm:{d['name']}", rel)
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for dep, spec in (d.get(key) or {}).items():
            c.add("requires", f"npm:{dep}", rel)
            if isinstance(spec, str) and spec.startswith(("file:", "link:")):
                c.local(p.parent, spec.split(":", 1)[1], rel)


def _pyproject(p: Path, rel: str, c: Collector) -> None:
    d = tomllib.loads(_read(p))
    proj, poetry = d.get("project") or {}, (d.get("tool") or {}).get("poetry") or {}
    if name := proj.get("name") or poetry.get("name"):
        c.add("provides", f"pypi:{norm_py(name)}", rel)
    specs = list(proj.get("dependencies") or []) + [s for v in (proj.get("optional-dependencies") or {}).values() for s in v]
    for spec in specs:
        if m := re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec):
            c.add("requires", f"pypi:{norm_py(m.group(1))}", rel)
    for dep, v in (poetry.get("dependencies") or {}).items():
        if dep.lower() != "python":
            c.add("requires", f"pypi:{norm_py(dep)}", rel)
            if isinstance(v, dict) and v.get("path"):
                c.local(p.parent, v["path"], rel)


def _requirements(p: Path, rel: str, c: Collector) -> None:
    for line in _read(p).splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        if line.startswith(("-e ", "--editable ")):
            c.local(p.parent, line.split(None, 1)[1].split("#egg")[0], rel)
        elif line.startswith("file:"):
            c.local(p.parent, line[5:], rel)
        elif not line.startswith("-") and (m := re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)):
            c.add("requires", f"pypi:{norm_py(m.group(1))}", rel)


def _pom(p: Path, rel: str, c: Collector) -> None:
    root = ET.fromstring(_read(p))
    parent = next((ch for ch in root if _local_tag(ch.tag) == "parent"), None)
    gid = _child(root, "groupId") or (_child(parent, "groupId") if parent is not None else "")
    aid = _child(root, "artifactId")
    if gid and aid and "${" not in gid + aid:
        c.add("provides", f"maven:{gid}:{aid}", rel)
    if parent is not None and (rp := _child(parent, "relativePath")):
        c.local(p.parent, rp.removesuffix("pom.xml"), rel)
    for dep in root.iter():
        if _local_tag(dep.tag) == "dependency":
            g, a = _child(dep, "groupId"), _child(dep, "artifactId")
            if g and a and "${" not in g + a:
                c.add("requires", f"maven:{g}:{a}", rel)


def _gradle(p: Path, rel: str, c: Collector) -> None:
    text = _read(p)
    if m := re.search(r"^\s*group\s*=\s*['\"]([\w.-]+)['\"]", text, re.M):
        name = re.search(r"rootProject\.name\s*=\s*['\"]([\w.-]+)['\"]", text)
        if name:
            c.add("provides", f"maven:{m.group(1)}:{name.group(1)}", rel)
    for g, a in re.findall(r"['\"]([\w.-]+):([\w.-]+):[^'\"]+['\"]", text):
        c.add("requires", f"maven:{g}:{a}", rel)


def _gomod(p: Path, rel: str, c: Collector) -> None:
    text = _read(p)
    if m := re.search(r"^module\s+(\S+)", text, re.M):
        c.add("provides", f"go:{m.group(1)}", rel)
    for mod in re.findall(r"^\s*(?:require\s+)?([\w.-]+\.[\w.-]+/[^\s]+)\s+v[\w.+-]+", text, re.M):
        c.add("requires", f"go:{mod}", rel)
    for target in re.findall(r"=>\s*(\.{1,2}/\S+)", text):
        c.local(p.parent, target, rel)


def _composer(p: Path, rel: str, c: Collector) -> None:
    d = json.loads(_read(p))
    if d.get("name"):
        c.add("provides", f"composer:{d['name']}", rel)
    for key in ("require", "require-dev"):
        for dep in (d.get(key) or {}):
            if dep != "php" and not dep.startswith("ext-"):
                c.add("requires", f"composer:{dep}", rel)


def _csproj(p: Path, rel: str, c: Collector) -> None:
    root = ET.fromstring(_read(p))
    for el in root.iter():
        tag = _local_tag(el.tag)
        if tag == "PackageReference" and el.get("Include"):
            c.add("requires", f"nuget:{el.get('Include')}", rel)
        elif tag == "ProjectReference" and el.get("Include"):
            c.local(p.parent, el.get("Include", ""), rel)
        elif tag in ("AssemblyName", "PackageId") and (el.text or "").strip():
            c.add("provides", f"nuget:{el.text.strip()}", rel)


def _cargo(p: Path, rel: str, c: Collector) -> None:
    d = tomllib.loads(_read(p))
    if name := (d.get("package") or {}).get("name"):
        c.add("provides", f"cargo:{name}", rel)
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        for dep, v in (d.get(key) or {}).items():
            c.add("requires", f"cargo:{dep}", rel)
            if isinstance(v, dict) and v.get("path"):
                c.local(p.parent, v["path"], rel)


def _gemfile(p: Path, rel: str, c: Collector) -> None:
    for line in _read(p).splitlines():
        if m := re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"](.*)$", line):
            c.add("requires", f"gem:{m.group(1)}", rel)
            if path := re.search(r"path:\s*['\"]([^'\"]+)['\"]", m.group(2)):
                c.local(p.parent, path.group(1), rel)


def _gemspec(p: Path, rel: str, c: Collector) -> None:
    if m := re.search(r"\.name\s*=\s*['\"]([^'\"]+)['\"]", _read(p)):
        c.add("provides", f"gem:{m.group(1)}", rel)


def _compose(p: Path, rel: str, c: Collector) -> None:
    services = (yaml.safe_load(_read(p)) or {}).get("services") or {}
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        build, image = svc.get("build"), svc.get("image")
        context = build if isinstance(build, str) else (build or {}).get("context") if isinstance(build, dict) else None
        if context:
            c.local(p.parent, str(context), rel)
        if image:
            c.add("provides" if build else "requires", f"image:{image_name(str(image))}", rel)


def _dockerfile(p: Path, rel: str, c: Collector) -> None:
    stages: set[str] = set()
    for line in _read(p).splitlines():
        if m := re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I):
            base = m.group(1)
            if base.lower() != "scratch" and base.lower() not in stages and "$" not in base:
                c.add("requires", f"image:{image_name(base)}", rel)
            if m.group(2):
                stages.add(m.group(2).lower())


PARSERS = {"package.json": _package_json, "pyproject.toml": _pyproject, "pom.xml": _pom, "build.gradle": _gradle,
           "build.gradle.kts": _gradle, "go.mod": _gomod, "composer.json": _composer, "cargo.toml": _cargo,
           "gemfile": _gemfile}
SUFFIX_PARSERS = {".csproj": _csproj, ".vbproj": _csproj, ".fsproj": _csproj, ".gemspec": _gemspec}


def _parser_for(name: str):
    low = name.lower()
    if low in PARSERS:
        return PARSERS[low]
    if re.match(r"^requirements.*\.txt$", low):
        return _requirements
    if re.match(r"^(docker-)?compose.*\.ya?ml$", low):
        return _compose
    if low.startswith("dockerfile"):
        return _dockerfile
    return SUFFIX_PARSERS.get(os.path.splitext(low)[1])


def _git_remotes(root: Path, c: Collector) -> None:
    config = root / ".git" / "config"
    if not config.is_file():
        return
    in_remote = False
    for line in _read(config, 64 * 1024).splitlines():
        line = line.strip()
        if line.startswith("["):
            in_remote = line.startswith("[remote ")
        elif in_remote and (m := re.match(r"^url\s*=\s*(.+)$", line)):
            c.add("git_remote", normalize_remote(m.group(1)), ".git/config")


def _is_text_candidate(name: str) -> bool:
    low = name.lower()
    if low.endswith((".lock", "-lock.json", ".min.js", ".map")) or low in ("package-lock.json", "pnpm-lock.yaml"):
        return False
    return os.path.splitext(low)[1] in TEXT_EXT or low == ".env" or low.startswith(".env.")


def scan_project(root: Path) -> list[dict]:
    c = Collector(root.resolve())
    _git_remotes(c.root, c)
    seen = url_files = 0
    hosts: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(c.root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            seen += 1
            if seen > MAX_FILES:
                break
            path = Path(dirpath) / name
            rel = path.relative_to(c.root).as_posix()
            if (parser := _parser_for(name)) is not None:
                try:
                    parser(path, rel, c)
                except Exception:  # manifeste invalide ou hostile : on l'ignore, le reste continue
                    pass
            if url_files < MAX_URL_FILES and _is_text_candidate(name):
                try:
                    if path.stat().st_size > MAX_TEXT:
                        continue
                    url_files += 1
                    for url in URL_RE.findall(XMLNS_RE.sub("", path.read_text(encoding="utf-8", errors="replace"))):
                        host = urlparse(url.removeprefix("jdbc:") if url.lower().startswith("jdbc:") else url).hostname
                        if host and len(hosts) < MAX_HOSTS:
                            hosts.add(host.lower())
                            c.add("endpoint", host.lower(), rel)
                        elif host and host.lower() in hosts:
                            c.add("endpoint", host.lower(), rel)
                except (OSError, ValueError):
                    continue
        if seen > MAX_FILES:
            break
    return sorted(c.refs.values(), key=lambda r: (r["type"], r["value"]))


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        print("usage : python -m aule.linkscan <projet> <rapport.json>", file=sys.stderr)
        return 2
    Path(args[1]).write_text(json.dumps({"version": 1, "references": scan_project(Path(args[0]))}, ensure_ascii=False, indent=1),
                             encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
