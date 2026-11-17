"""`aule doctor` : lance chaque outil sur un mini-projet embarqué et vérifie qu'il fait ce qu'on attend.

Détecte, avant de partir chez le client : binaire introuvable, version aux arguments incompatibles, règles ou
bases absentes, format de rapport inattendu. Données de test synthétiques (aucune donnée client) ; tout est
écrit dans un dossier temporaire, sauf la lecture des règles / bases déjà installées dans `data/`.
Verdicts : PASS (ok et résultat attendu) · WARN (ok mais rien trouvé / non applicable) · FAIL (échec) · SKIP.
"""
from __future__ import annotations

import copy
import platform
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .db import Database
from .orchestrator import run_audit
from .plugins import load_plugins


@dataclass
class Check:
    name: str
    status: str            # PASS | WARN | FAIL | SKIP
    detail: str = ""
    hint: str = ""
    seconds: float = 0.0


def _secrets() -> tuple[str, str, str]:
    """Jetons d'allure réaliste (entropie suffisante pour les règles de gitleaks), stables d'un lancement à l'autre."""
    rng = random.Random(20260101)
    alnum = string.ascii_letters + string.digits
    gh = "ghp_" + "".join(rng.choice(alnum) for _ in range(36))
    gh2 = "ghp_" + "".join(rng.choice(alnum) for _ in range(36))
    aws = "AKIA" + "".join(rng.choice(string.ascii_uppercase + "234567") for _ in range(16))
    return gh, gh2, aws


def make_corpus(root: Path) -> Path:
    """Crée `root/sample` : un petit projet git (2 commits) avec de quoi déclencher chaque famille d'outils."""
    project = root / "sample"
    project.mkdir(parents=True)
    gh, gh2, aws = _secrets()
    files = {
        "app.py": ("import sqlite3\nfrom flask import request\n\n\ndef find():\n    uid = request.args.get('id')\n"
                   "    cur = sqlite3.connect('x.db').cursor()\n    cur.execute('SELECT * FROM users WHERE id=' + uid)\n"
                   "    return eval(request.args.get('expr'))\n"),
        "config.py": f'GITHUB_TOKEN = "{gh}"\nAWS_ACCESS_KEY_ID = "{aws}"\n',
        "settings.py": f'DEPLOY_TOKEN = "{gh2}"\n',
        "requirements.txt": "django==2.2.0\npyyaml==5.3\n",
        "package.json": '{"name": "sample", "dependencies": {"lodash": "4.17.4"}}\n',
        "Dockerfile": "FROM ubuntu:22.04\nUSER root\nRUN apt-get update\n",
        "main.tf": 'resource "aws_s3_bucket" "data" {\n  bucket = "sample-data"\n  acl    = "public-read"\n}\n',
        "README.md": "# sample\n\nJeu de test de `aule doctor` : données synthétiques.\n",
    }
    for name, text in files.items():
        (project / name).write_text(text, encoding="utf-8")

    def git(*args: str) -> None:
        subprocess.run(["git", "-c", "user.name=doctor", "-c", "user.email=doctor@example.invalid", "-c", "commit.gpgsign=false",
                        *args], cwd=project, check=True, capture_output=True)
    git("init", "-q")
    git("add", ".")
    git("commit", "-qm", "import initial")
    (project / "config.py").write_text("import os\nGITHUB_TOKEN = os.environ['GITHUB_TOKEN']\n", encoding="utf-8")
    git("commit", "-qam", "retire les secrets du code")  # ils restent dans l'historique
    return project


# (type d'entité, filtre optionnel sur les données, minimum attendu, libellé)
EXPECT: dict[str, list[tuple[str, dict, int, str]]] = {
    "cloc": [("technology", {}, 1, "technologie(s)")],
    "gitleaks": [("secret", {"mode": "dir"}, 1, "secret(s) dans les fichiers"), ("secret", {"mode": "git"}, 1, "secret(s) dans l'historique")],
    "trufflehog": [("secret", {}, 1, "secret(s)")],
    "gittools": [("commit", {}, 2, "commit(s) reconstruit(s)")],
    "opengrep": [("sast_finding", {}, 1, "faille(s) de code")],
    "codeql": [("sast_finding", {}, 1, "faille(s) de code")],
    "checkov": [("sast_finding", {}, 1, "mauvaise(s) configuration(s)")],
    "trivy": [("vulnerability", {}, 1, "vulnérabilité(s)")],
    "osv-scanner": [("vulnerability", {}, 1, "vulnérabilité(s)")],
    "dependency-check": [("vulnerability", {}, 1, "vulnérabilité(s)")],
    "links": [("reference", {}, 1, "référence(s)")],
}


def _hint(tool: str, text: str) -> str:
    low = text.lower()
    if re.search(r"unknown flag|unrecognized|no such option|unknown command|invalid option|usage:", low):
        return f"version incompatible ? comparez cmd.txt avec `{tool} --help`"
    if tool == "codeql" and re.search(r"resolve|pack|quer", low):
        return "paquets de requêtes absents : aule update codeql (ou CodeQL bundle)"
    if re.search(r"could not resolve host|connection|network|dial tcp|timed out|unreachable", low):
        return "réseau requis (base de vulnérabilités, API) : voir la documentation de l'outil pour le mode hors ligne"
    if "délai" in low:
        return f"augmentez tools.{tool}.timeout dans aule.yaml"
    return "voir stderr.txt et cmd.txt dans le dossier de sortie brute (--keep pour le conserver)"


def _ready(tool, cfg, data_dir: Path, full: bool) -> str | None:
    """Outils lourds sans base locale : on n'amorce pas un téléchargement de plusieurs minutes/heures sans --full."""
    if full:
        return None
    if tool.name == "dependency-check":
        db = Path(cfg.options.get("data_path") or data_dir / "depcheck-db")
        if not (db.is_dir() and any(db.iterdir())):
            return f"base NVD absente ({db}) : aule update dependency-check, ou --full pour la télécharger"
    if tool.name == "trivy":
        cache = Path(cfg.options.get("cache_dir") or Path.home() / ".cache" / "trivy")
        if not cache.is_dir():
            return f"base Trivy absente ({cache}) : lancez trivy une fois en ligne, ou --full"
    return None


def environment() -> list[Check]:
    checks = [Check("python", "PASS" if sys.version_info >= (3, 11) else "FAIL", platform.python_version(),
                    "" if sys.version_info >= (3, 11) else "Python ≥ 3.11 requis")]
    git = shutil.which("git")
    checks.append(Check("git", "PASS", subprocess.run(["git", "--version"], capture_output=True, text=True).stdout.strip(), "")
                  if git else Check("git", "FAIL", "introuvable", "git est requis (historique, clones de règles)"))
    if sys.platform.startswith("win"):
        checks.append(Check("système", "WARN", "Windows : non testé par les auteurs",
                            "WSL2 est recommandé ; chiffrement de data/ (seal) indisponible, utilisez BitLocker/VeraCrypt"))
    return checks


def run_doctor(config: Config, data_dir: Path, *, only: list[str] | None = None, full: bool = False,
               timeout: int = 900, keep: bool = False, log=print) -> tuple[list[Check], Path | None]:
    registry = load_plugins()
    names = only or list(registry)
    unknown = [n for n in names if n not in registry]
    if unknown:
        raise ValueError(f"outil(s) inconnu(s) : {', '.join(unknown)} (disponibles : {', '.join(registry)})")
    checks = environment()
    if any(c.status == "FAIL" for c in checks):
        return checks, None
    work = Path(tempfile.mkdtemp(prefix="audit-doctor-"))
    kept = work if keep else None
    try:
        corpus = make_corpus(work / "corpus").parent
        db = Database(work / "data" / "audit.db")
        for name in names:
            tool = registry[name]
            cfg = copy.deepcopy(config)
            tc = cfg.tools.setdefault(name, copy.deepcopy(config.tool(name)))
            tc.timeout = min(tc.timeout or timeout, timeout)
            tc.enabled = True
            if name == "opengrep":
                tc.options.setdefault("rules_path", str(data_dir / "rules" / "opengrep-rules"))
            if name == "dependency-check":
                tc.options.setdefault("data_path", str(data_dir / "depcheck-db"))
            if tool.resolve(tc) is None:
                checks.append(Check(name, "SKIP", f"introuvable : '{tc.path or tool.binary}'", f"renseignez tools.{name}.path dans aule.yaml"))
                continue
            if (why := _ready(tool, tc, data_dir, full)):
                checks.append(Check(name, "SKIP", why))
                continue
            log(f"  … {name}")
            run_id = run_audit(db, work / "data", corpus, config=cfg, tool_names=sorted({"cloc", name}), jobs=1,
                               timeout=timeout, log=lambda *_: None)
            checks.append(_evaluate(db, work / "data", run_id, tool, name))
        db.close()
    finally:
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
    return checks, kept


def _evaluate(db: Database, data_dir: Path, run_id: str, tool, name: str) -> Check:
    runs = [r for r in db.list_tool_runs(run_id) if r["tool"] == name]
    seconds = round(sum(r["duration_s"] or 0 for r in runs), 1)
    if not runs:
        return Check(name, "WARN", "aucune exécution (outil non applicable ?)", seconds=seconds)
    bad = [r for r in runs if r["status"] in ("failed", "timeout", "parse_error")]
    if bad:
        r = bad[0]
        detail = f"{r['mode']} : {r['error']}"
        stderr = data_dir / (r["raw_dir"] or "") / "stderr.txt"
        tail = stderr.read_text(errors="replace").strip().splitlines()[-1:] if r["raw_dir"] and stderr.exists() else []
        return Check(name, "FAIL", detail + (f" | {tail[0][:200]}" if tail and tail[0] not in detail else ""), _hint(name, detail + " " + " ".join(tail)), seconds)
    blocked = [r for r in runs if r["status"] == "unavailable"]
    if blocked and len(blocked) == len(runs):
        return Check(name, "SKIP", blocked[0]["error"] or "indisponible", "", seconds)
    ok = [r for r in runs if r["status"] == "ok"]
    if not ok:
        return Check(name, "WARN", "non applicable sur le jeu de test : " + (runs[0]["error"] or ""), "technologie non détectée par cloc ?", seconds)
    version = next((r["tool_version"] for r in ok if r["tool_version"]), None)
    found, missing = [], []
    for kind, where, minimum, label in EXPECT.get(name, []):
        n = sum(1 for e in db.entities(run_id, kind) if all(e["data"].get(k) == v for k, v in where.items()))
        (found if n >= minimum else missing).append(f"{n} {label}")
    if missing:
        return Check(name, "WARN", "s'exécute mais " + " ; ".join(missing) + " (attendu ≥ 1 sur le jeu de test)",
                     "règles / bases à jour ? l'outil a pu changer de format ou de comportement", seconds)
    return Check(name, "PASS", " ; ".join(found) + (f" · {version}" if version else ""), "", seconds)


def summarize(checks: list[Check]) -> dict[str, int]:
    return {s: sum(1 for c in checks if c.status == s) for s in ("PASS", "WARN", "FAIL", "SKIP")}
