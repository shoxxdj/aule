"""Onglet Sources : navigation dans le code, de bout en bout (vrai serveur, faux DOM)."""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest
import urllib.request
from pathlib import Path

import fakes
from test_rawview import rich_sarif
from test_rawview_api import RawServerCase

HERE = Path(__file__).parent


@unittest.skipUnless(shutil.which("node"), "node requis")
class SourcesUiTest(RawServerCase):
    def setUp(self):
        super().setUp()
        (self.root / "repo-git" / "pkg").mkdir()
        (self.root / "repo-git" / "pkg" / "util.py").write_text("needle_here = 1\n")

    def play(self, mode: str, extra: str | None = None) -> dict:
        page = self.tmp / f"live-{mode}.html"
        page.write_bytes(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/").read())
        rich = self.tmp / "rich.sarif"
        rich.write_text(json.dumps(rich_sarif()))
        proc = subprocess.run(["node", str(HERE / "code_scenario.js"), str(page), f"http://127.0.0.1:{self.port}", mode, extra or str(rich)], capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_from_a_finding_to_the_code_and_around(self):
        out = self.play("main")
        # ouverture depuis un constat : fichier, ligne ciblée, marge, plage, chemin de données
        self.assertIn("db.py", out["open"])
        self.assertIn("cur.execute('SELECT * FROM t WHERE id=' + uid)", out["open"])
        self.assertTrue(out["target"].strip().startswith("5"), out["target"])
        self.assertEqual(out["markers"], 1)                                       # un marqueur dans la marge, sur la ligne du constat
        self.assertEqual(out["rangeLines"], 1)
        self.assertEqual(out["stepBadges"], ["1", "2"])                           # les deux étapes sont repérées dans le code
        for expected in ("Constat sélectionné", "py/sql-injection", "Constats de ce fichier (1)", "Chemin de données", "user-provided value", "sink reached here", "2 étape(s)"):
            self.assertIn(expected, out["open"], expected)
        # chemin de données : étape par étape
        self.assertIn("étape 1/2", out["step1"]["text"])
        self.assertTrue(out["step1"]["target"].strip().startswith("4"), out["step1"]["target"])      # source : ligne 4
        self.assertIn("étape 2/2", out["step2"]["text"])
        self.assertTrue(out["step2"]["target"].strip().startswith("5"), out["step2"]["target"])      # puits : ligne 5
        self.assertTrue(out["back"])
        # aller à une ligne, chercher dans le fichier
        self.assertTrue(out["goto"].strip().startswith("2"), out["goto"])
        self.assertIn("1/1", out["find"])
        self.assertTrue(out["findTarget"].strip().startswith("5"), out["findTarget"])
        # aller au fichier, recherche dans le projet, arborescence, fichiers à constats, changement de projet
        self.assertIn("eval('1+1')", out["quick"])
        self.assertEqual(out["quickMarkers"], 1)                                  # service.py : le constat opengrep apparaît dans la marge
        self.assertIn("pkg/util.py:1", out["searchResults"])
        self.assertIn("needle_here = 1", out["search"])
        for expected in ("Fichiers à constats", "db.py", "service.py", "settings.py"):
            self.assertIn(expected, out["hot"], expected)
        self.assertIn("▾ pkg/", " ".join(out["treeAuto"]))                        # le fichier ouvert est situé dans l'arbre : dossier déplié tout seul
        self.assertIn("util.py", " ".join(out["treeAuto"]))
        self.assertIn("▸ pkg/", " ".join(out["treeClosed"]))
        self.assertNotIn("util.py", " ".join(out["treeClosed"]))                  # replié : le fichier disparaît de l'arbre
        self.assertIn("util.py", " ".join(out["treeReopened"]))
        self.assertTrue(any("keys.py" in n for n in out["plain"]))                # autre projet : son propre arbre

    def test_changing_run_resets_the_raw_tree_and_the_open_file(self):
        first = self.run_id
        config = __import__("aule.config", fromlist=["parse_config"]).parse_config({}, self.tmp)
        self.run_audit(config, tool_names=["cloc", "gitleaks", "opengrep", "codeql"])                  # run plus récent, sans rich.sarif
        out = self.play("runswitch", extra=first)
        self.assertNotIn("rich.sarif", out["latestTree"])
        self.assertTrue(out["opened"])
        self.assertNotIn("cur.execute", out["sourcesAfter"])                                            # le code ouvert n'est pas resté affiché
        self.assertIn("Choisissez un fichier", out["sourcesAfter"])
        self.assertIn("rich.sarif", out["firstTree"])                                                   # arborescence rechargée pour le run choisi

    def test_warns_when_the_code_changed_since_the_scan(self):
        self.assertNotIn("diffère", self.play("drift")["text"])
        db = self.root / "repo-git" / "db.py"
        db.write_text(db.read_text().replace("cur.execute('SELECT * FROM t WHERE id=' + uid)", "cur.execute('SELECT 1')"))
        self.assertIn("la ligne actuelle diffère de celle qui a été analysée", self.play("drift")["text"])

    def test_secret_from_history_opens_at_its_commit(self):
        out = self.play("history")
        self.assertIn("état au commit", out["atCommit"])
        self.assertIn(fakes.SECRET_A, out["atCommit"])                            # au commit concerné : le secret supprimé depuis
        self.assertNotIn("état au commit", out["now"])
        self.assertNotIn(fakes.SECRET_A, out["now"])                              # état actuel : il n'y est plus

    def test_from_the_sarif_explorer_per_file_view_and_import(self):
        out = self.play("sarif")
        self.assertGreaterEqual(out["codeButtons"], 5)                            # emplacements, emplacements liés et étapes
        self.assertIn("db.py", out["c1"]["text"])
        self.assertTrue(out["c1"]["target"].strip().startswith("5"), out["c1"]["target"])
        self.assertIn("introuvable", out["c2"])                                   # web.py n'existe pas : message clair, pas de plantage
        for expected in ("3 fichier(s) touché(s)", "db.py", "other.py", "service.py"):
            self.assertIn(expected, out["files"], expected)
        self.assertIn("#0", out["filtered"])
        self.assertNotIn("#2", out["filtered"])                                   # filtre par fichier
        self.assertIn("Résultats (3)", out["imported"])                           # SARIF importé : ouvert directement
        self.assertIn("(importés)", out["imported"])


if __name__ == "__main__":
    unittest.main()
