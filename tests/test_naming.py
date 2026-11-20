"""Le nom : Aulë (commande `aule`). Compatibilité avec l'ancien nom (`audit`) et absence de restes des noms précédents."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aule import cli
from aule.config import load_config
from common import AuditCase

ROOT = Path(__file__).parent.parent


class PackagingTest(unittest.TestCase):
    def test_entry_points_and_metadata(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(data["project"]["name"], "aule-audit")
        self.assertEqual(data["project"]["scripts"], {"aule": "aule.cli:main", "audit": "aule.cli:main"})       # `audit` : alias de l'ancien nom
        self.assertEqual(data["tool"]["uv"]["build-backend"]["module-name"], "aule")
        self.assertIn("Aulë", data["project"]["description"])
        self.assertTrue((ROOT / "src" / "aule" / "__main__.py").is_file())
        self.assertFalse((ROOT / "src" / "auditor").exists() or (ROOT / "src" / "ariane").exists())

    def test_the_module_runs_and_presents_itself(self):
        proc = subprocess.run([sys.executable, "-m", "aule", "--help"], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("usage: aule", proc.stdout)
        self.assertIn("Aulë", proc.stdout)

    def test_no_trace_of_the_previous_names(self):
        """Ni `auditor`, ni `ariane`, ni l'ancienne commande `audit <sous-commande>` ne doivent subsister dans le code, les tests et la documentation."""
        sub = "run|runs|tools|show|report|update|triage|diff|links|finding|note|export|doctor|purge|seal|unseal|serve|critiq|mission|label|reparse|correlate|sarif"
        offenders = []
        for path in [*ROOT.glob("src/aule/**/*.py"), ROOT / "src/aule/templates/report.html", *ROOT.glob("tests/*.py"), *ROOT.glob("tests/*.js"), ROOT / "README.md",
                     ROOT / "pyproject.toml", ROOT / "aule.example.yaml", *ROOT.glob("docker/*")]:
            if path == Path(__file__):
                continue
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if re.search(r"\bauditor\b|\bariane\b|\bAriane\b|ARIANE_", line) or re.search(r"(?<![\w'’-])audit (" + sub + r")\b", line):
                    offenders.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:90]}")
        self.assertEqual(offenders, [])


class CompatibilityTest(AuditCase):
    def test_config_file_names(self):
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.tmp)
        self.assertEqual(load_config(None).critiq.enabled, False)                              # aucun fichier : valeurs par défaut
        (self.tmp / "audit.yaml").write_text("critiq:\n  max_rounds: 2\n")
        self.assertEqual(load_config(None).critiq.max_rounds, 2)                             # l'ancien nom est toujours reconnu
        (self.tmp / "aule.yaml").write_text("critiq:\n  max_rounds: 5\n")
        self.assertEqual(load_config(None).critiq.max_rounds, 5)                            # le nouveau l'emporte
        self.assertEqual(load_config(self.tmp / "audit.yaml").critiq.max_rounds, 2)          # --config explicite : on obéit

    def test_passphrase_variables(self):
        args = SimpleNamespace(passphrase_file=None)
        with mock.patch.dict(os.environ, {"AUDIT_PASSPHRASE": "ancienne"}, clear=False):
            os.environ.pop("AULE_PASSPHRASE", None)
            self.assertEqual(cli._passphrase(args, confirm=False), "ancienne")                 # ancien nom accepté
            os.environ["AULE_PASSPHRASE"] = "nouvelle"
            self.assertEqual(cli._passphrase(args, confirm=False), "nouvelle")                 # nouveau nom prioritaire


if __name__ == "__main__":
    unittest.main()
