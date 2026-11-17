"""Export HTML de partage : résultats SARIF complets embarqués (bornés), faux positifs retirés, secrets masqués."""
from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import fakes
import aule.report as report_mod
from aule.cli import main
from aule.report import build_report_data, render_report
from test_export import Inject
from test_rawview_api import RawServerCase

HERE = Path(__file__).parent


class ShareCase(Inject, RawServerCase):
    def data_with(self, **kw):
        return build_report_data(self.db, self.run_id, self.data, **kw)

    def sast(self, d, rule=None):
        return [f for f in d["sast"] if rule is None or f["rule_id"] == rule]


class RawDetailsTest(ShareCase):
    def test_full_sarif_result_is_embedded_for_each_finding(self):
        d = self.data_with(reveal=True, raw_details=True)
        self.assertEqual(d["options"]["raw_details"]["embedded"], len(d["sast"]))
        self.assertFalse(d["options"]["raw_details"]["truncated"])
        f = self.sast(d, "py/sql-injection")[0]
        det = f["raw_detail"]
        self.assertEqual((det["index"], det["ruleId"], det["rule"]["properties"]["precision"]), (f["raw_index"], "py/sql-injection", "high"))
        self.assertEqual([s["location"]["message"] for s in det["codeFlows"][0]["threadFlows"][0]["steps"]], ["user-provided value", "sink reached here"])
        og = self.sast(d, "python.lang.security.audit.eval-detected")[0]["raw_detail"]
        self.assertEqual((og["ruleId"], og["effectiveLevel"]), ("python.lang.security.audit.eval-detected", "error"))
        self.assertIn("eval", og["rule"]["helpUri"] + og["ruleId"])
        self.assertIsNone(self.data_with(reveal=True)["options"]["raw_details"])      # désactivé par défaut : rien n'est embarqué
        self.assertFalse(any("raw_detail" in f for f in self.data_with(reveal=True)["sast"]))

    def test_results_are_found_by_rule_file_and_line_on_runs_that_predate_raw_index(self):
        self.db.conn.execute("UPDATE entity SET data = json_remove(json_remove(data, '$.raw_index'), '$.sarif_run') WHERE kind = 'sast_finding'")
        self.db.conn.commit()
        d = self.data_with(reveal=True, raw_details=True)
        self.assertTrue(all("raw_index" not in f for f in d["sast"]))
        f = self.sast(d, "py/sql-injection")[0]
        self.assertEqual((f["raw_detail"]["ruleId"], f["raw_detail"]["locations"][0]["uri"]), ("py/sql-injection", "db.py"))

    def test_size_budget_is_enforced_and_reported(self):
        with mock.patch.object(report_mod, "RAW_DETAIL_BUDGET", 1500):
            d = self.data_with(reveal=True, raw_details=True)
        info = d["options"]["raw_details"]
        self.assertTrue(info["truncated"])
        self.assertLess(info["embedded"], len(d["sast"]))
        self.assertLessEqual(info["bytes"], 1500)
        self.assertEqual(sum(1 for f in d["sast"] if "raw_detail" in f), info["embedded"])

    def test_masked_reports_skip_secret_like_rules(self):
        pid = next(p["id"] for p in self.db.list_projects(self.run_id) if p["name"] == "repo-git")
        trid = next(r["id"] for r in self.db.list_tool_runs(self.run_id) if r["tool"] == "codeql" and r["mode"] == "python" and r["project_id"] == pid)
        self.db.conn.execute("INSERT INTO entity(audit_id, project_id, tool_run_id, kind, fingerprint, data) VALUES (?,?,?,?,?,?)",
                             (self.run_id, pid, trid, "sast_finding", "h" * 24, json.dumps(
                                 {"tool": "CodeQL", "rule_id": "py/hardcoded-password", "severity": "high", "file": "db.py", "start_line": 5, "cwe": [], "flow": [],
                                  "raw_index": 0, "sarif_run": 0, "snippet": "password = 'x'"})))
        self.db.conn.commit()
        masked = self.data_with(reveal=False, raw_details=True)
        item = self.sast(masked, "py/hardcoded-password")[0]
        self.assertNotIn("raw_detail", item)
        self.assertIsNone(item["snippet"])
        self.assertEqual(masked["options"]["raw_details"]["skipped_masked"], 1)
        self.assertIn("raw_detail", self.sast(self.data_with(reveal=True, raw_details=True), "py/hardcoded-password")[0])


class HideFalsePositivesTest(ShareCase):
    def test_false_positives_are_removed_from_every_list(self):
        d = self.data_with(reveal=True)
        sast_fp, secret_fp = d["sast"][0]["fingerprint"], d["secrets"][0]["fingerprint"]
        self.db.set_triage(sast_fp, "false_positive")
        self.db.set_triage(secret_fp, "false_positive")
        shown = self.data_with(reveal=True, hide_false_positives=True)
        self.assertNotIn(sast_fp, {f["fingerprint"] for f in shown["sast"]})
        self.assertNotIn(secret_fp, {f["fingerprint"] for f in shown["secrets"]})
        self.assertEqual((len(shown["sast"]), len(shown["secrets"])), (len(d["sast"]) - 1, len(d["secrets"]) - 1))
        self.assertTrue(shown["options"]["hide_false_positives"])
        kept = self.data_with(reveal=True)
        self.assertEqual((len(kept["sast"]), len(kept["secrets"])), (len(d["sast"]), len(d["secrets"])))


class ShareReportTest(ShareCase):
    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--data", str(self.data)])
        return code, out.getvalue(), err.getvalue()

    def payload(self, path: Path) -> dict:
        m = re.search(r'<script id="audit-data" type="application/json">(.*?)</script>', path.read_text(encoding="utf-8"), re.S)
        return json.loads(m.group(1))

    def test_share_preset(self):
        self.db.set_mission("Acme 2026", client="Acme SA")
        self.db.set_audit_label(self.run_id, "contre-audit")
        fp = next(f["fingerprint"] for f in build_report_data(self.db, self.run_id, self.data)["sast"] if "eval" in f["rule_id"])
        self.db.set_triage(fp, "false_positive")
        code, out, _ = self.cli("report", "--share")
        self.assertEqual(code, 0)
        path = self.data / f"report-{self.run_id}-partage.html"
        self.assertTrue(path.exists())
        html = path.read_text(encoding="utf-8")
        for secret in (fakes.SECRET_A, fakes.SECRET_B):
            self.assertNotIn(secret, html)                                     # secrets masqués
            for i in range(len(secret) - 6):                                   # ... et aucun fragment de 7 caractères (masquage d'un outil tiers incomplet)
                self.assertNotIn(secret[i:i + 7], html, f"fragment de secret exposé : {secret[i:i + 7]!r}")
        self.assertNotIn("EN CLAIR", out)
        d = self.payload(path)
        self.assertFalse(d["options"]["reveal"])
        self.assertTrue(d["options"]["hide_false_positives"])
        self.assertNotIn(fp, {f["fingerprint"] for f in d["sast"]})            # faux positif retiré
        self.assertTrue(d["sast"] and all("raw_detail" in f for f in d["sast"]))
        self.assertIn("<title>Audit Acme 2026 — contre-audit</title>", html)
        self.assertEqual(html.count("</script>"), 2)

    def test_options_are_independent(self):
        code, out, _ = self.cli("report", "--raw-details", "-o", str(self.tmp / "a.html"))
        d = self.payload(self.tmp / "a.html")
        self.assertTrue(d["options"]["reveal"])                                # seul --raw-details : secrets toujours en clair (défaut)
        self.assertTrue(any("secret" in s for s in d["secrets"]))
        self.assertTrue(all("raw_detail" in f for f in d["sast"]))
        self.assertIn("EN CLAIR", out)

    def test_nothing_is_embedded_by_default(self):
        self.cli("report", "-o", str(self.tmp / "b.html"))
        d = self.payload(self.tmp / "b.html")
        self.assertFalse(any("raw_detail" in f for f in d["sast"]))

    @unittest.skipUnless(shutil.which("node"), "node requis")
    def test_static_page_shows_the_complete_result_without_live_controls(self):
        self.cli("report", "--raw-details", "-o", str(self.tmp / "c.html"))
        out = json.loads(subprocess.run(["node", str(HERE / "dom_smoke.js"), str(self.tmp / "c.html")], capture_output=True, text=True, timeout=120).stdout)
        sast = next(v for k, v in out["tabsOpen"].items() if k.startswith("Code (SAST)"))
        for expected in ("Résultat complet (sortie brute)", "Chemins de données (1)", "sink reached here", "Description de la règle"):
            self.assertIn(expected, sast)
        self.assertNotIn("Voir la sortie brute complète", sast)                # lecture seule : pas de lien vers l'explorateur
        self.assertFalse(any(k.startswith("Sorties brutes") for k in out["tabs"]))


if __name__ == "__main__":
    unittest.main()
