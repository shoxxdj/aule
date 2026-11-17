"""Interface : une ligne par constat, triage du groupe entier, retour aux détections brutes, marge du code, rapport statique."""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest
import urllib.request
from pathlib import Path

from aule.correlate import correlate_run
from aule.report import render_report
from test_export import Inject
from test_rawview_api import RawServerCase

HERE = Path(__file__).parent


@unittest.skipUnless(shutil.which("node"), "node requis")
class GroupUiTest(Inject, RawServerCase):
    def setUp(self):
        super().setUp()
        # opengrep voit la même injection que CodeQL (db.py:5, CWE-89) : même vulnérabilité, deux outils
        self.inject("sast_finding", "repo-git", "9" * 24, tool="opengrep", rule_id="python.lang.security.sqli", severity="high", file="db.py", start_line=5,
                    end_line=5, cwe=["CWE-89"], message="SQL injection", snippet="cur.execute(...)", flow=[])
        correlate_run(self.db, self.data, self.run_id)
        self.sqli_pair = sorted(next(c for c in self.db.list_clusters(self.run_id) if "9" * 24 in c["members"])["members"])

    def play(self, mode: str) -> dict:
        page = self.tmp / f"live-{mode}.html"
        page.write_bytes(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/").read())
        proc = subprocess.run(["node", str(HERE / "group_scenario.js"), str(page), f"http://127.0.0.1:{self.port}", mode], capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_one_line_per_finding_and_triage_of_the_whole_group(self):
        out = self.play("main")
        # secrets : 4 détections gitleaks -> 3 constats ; le doublon montre les deux modes et « ×2 »
        self.assertIn("4 détections recoupées", out["synthese"])                         # la Synthèse dit ce que le recoupement a fait (secrets : 4 -> 3)
        self.assertIn("3 détections recoupées", out["synthese"])                         # SAST : 3 détections -> 2 constats
        self.assertEqual(out["rows"], 3)
        self.assertRegex(out["badge"], r"Secrets\s*3\b")
        for expected in ("dir", "git", "×2"):
            self.assertIn(expected, out["settingsRow"])
        self.assertIn("3 constat(s) affiché(s) (4 détection(s)) sur 3 constat(s) · 4 détection(s)", out["counts"])
        for expected in ("2 détections regroupées", "même valeur de secret dans le même fichier", "Le triage s'applique à toutes"):
            self.assertIn(expected, out["detail"])
        # triage depuis la ligne = les deux détections
        settings = [e for e in self.db.entities(self.run_id, "secret") if e["data"]["file"] == "settings.py"]
        self.assertEqual(len(settings), 2)
        self.assertEqual({self.db.list_triage()[e["fingerprint"]]["status"] for e in settings}, {"false_positive"})
        self.assertEqual(len(self.db.list_triage()), 2)                                  # et rien d'autre
        # retour aux détections brutes
        self.assertEqual(out["ungroupedRows"], 4)
        self.assertRegex(out["ungroupedBadge"], r"Secrets\s*4\b")
        self.assertEqual(out["regroupedRows"], 3)
        # SAST : CodeQL + opengrep sur la même ligne = une ligne, deux outils
        self.assertEqual(out["sastRows"], 2)                                             # sqli (×2) + eval
        self.assertRegex(out["sastBadge"], r"Code \(SAST\)\s*2\b")                         # le badge compte des constats (3 détections), pas des détections
        for expected in ("CodeQL", "opengrep", "×2"):
            self.assertIn(expected, out["sqli"])
        self.assertIn("même CWE, lignes qui se recouvrent", out["sastDetail"])
        self.assertEqual(out["markers"], 1)                                              # un seul marqueur dans la marge du code, pas deux
        self.assertIn("Constats de ce fichier (1)", out["fileList"])

    def test_divergent_decisions_are_made_visible(self):
        self.db.set_triage(self.sqli_pair[0], "confirmed")
        self.db.set_triage(self.sqli_pair[1], "false_positive")
        out = self.play("conflict")
        self.assertIn("⚠ triages divergents", out["sqli"])
        self.assertIn("triages divergents : choisir un triage ci-dessus les aligne toutes", out["detail"])

    def test_bulk_triage_covers_every_detection_of_every_group(self):
        self.play("bulk")
        secrets = [e["fingerprint"] for e in self.db.entities(self.run_id, "secret")]
        self.assertEqual(len(secrets), 4)
        self.assertEqual({self.db.list_triage()[fp]["status"] for fp in secrets}, {"to_review"})     # 3 lignes affichées -> 4 détections marquées

    def test_static_report_is_grouped_too(self):
        page = self.tmp / "static.html"
        page.write_text(render_report(self.db, self.run_id, self.data, reveal=True), encoding="utf-8")
        out = json.loads(subprocess.run(["node", str(HERE / "dom_smoke.js"), str(page)], capture_output=True, text=True, timeout=120).stdout)
        secrets = next(v for k, v in out["tabs"].items() if k.startswith("Secrets"))
        self.assertIn("×2", secrets)
        self.assertTrue(any(k.startswith("Secrets") and k.rstrip().endswith("3") for k in out["tabs"]), list(out["tabs"]))
        self.assertIn("3 constat(s) affiché(s) (4 détection(s))", secrets)


if __name__ == "__main__":
    unittest.main()
