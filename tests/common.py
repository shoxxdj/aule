from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fakes
from aule.config import Config
from aule.db import Database
from aule.orchestrator import run_audit


def git(*args: str, cwd: Path) -> str:
    out = subprocess.run(["git", "-c", "user.name=Alice", "-c", "user.email=alice@example.org", *args],
                         cwd=cwd, check=True, capture_output=True, text=True)
    return out.stdout.strip()


def make_repo(path: Path) -> list[str]:
    """Commit 1 : config.py contient SECRET_A, settings.py contient SECRET_B.
    Commit 2 : SECRET_A est supprimé (reste visible dans l'historique). Retourne [c1, c2]."""
    path.mkdir(parents=True)
    git("init", "-q", cwd=path)
    (path / "app.py").write_text("print('hello')\n")
    (path / "config.py").write_text(f'AWS_KEY = "{fakes.SECRET_A}"\n')
    (path / "settings.py").write_text(f'TOKEN = "{fakes.SECRET_B}"\n')
    git("add", ".", cwd=path)
    git("commit", "-qm", "initial import", cwd=path)
    (path / "config.py").write_text('import os\nAWS_KEY = os.environ["AWS_KEY"]\n')
    git("commit", "-qam", "remove hardcoded key </script><script>alert(1)</script>", cwd=path)
    return git("rev-list", "--reverse", "HEAD", cwd=path).split()


class AuditCase(unittest.TestCase):
    """Environnement : faux cloc/gitleaks/extractor.sh dans le PATH, dossier à auditer et base."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        fakes.install(self.bin)
        self.log = self.tmp / "calls.log"
        patcher = mock.patch.dict(os.environ, {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "FAKE_LOG": str(self.log)})
        patcher.start()
        self.addCleanup(patcher.stop)

        self.root = self.tmp / "audited"
        self.commits = make_repo(self.root / "repo-git")
        (self.root / "plain").mkdir()
        (self.root / "plain" / "keys.py").write_text(f'KEY = "{fakes.SECRET_A}"\n')
        (self.root / ".hidden").mkdir()
        (self.root / "file.txt").write_text("ignored\n")

        self.data = self.tmp / "data"
        self.db = Database(self.data / "audit.db")
        self.addCleanup(self.db.close)

    def run_audit(self, config: Config | None = None, **kw) -> str:
        return run_audit(self.db, self.data, self.root, config=config, log=lambda *_: None, **kw)

    def statuses(self, run_id: str) -> dict[tuple[str, str, str], str]:
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        return {(names[r["project_id"]], r["tool"], r["mode"]): r["status"] for r in self.db.list_tool_runs(run_id)}

    def calls(self) -> list[str]:
        return self.log.read_text().split() if self.log.exists() else []

    def secrets(self, run_id: str, project: str | None = None, mode: str | None = None) -> list[dict]:
        pid = {p["name"]: p["id"] for p in self.db.list_projects(run_id)}.get(project) if project else None
        return [s for s in self.db.entities(run_id, "secret", pid) if mode is None or s["data"]["mode"] == mode]
