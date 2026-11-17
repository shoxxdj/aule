"""Mission nommée et passages nommés : libellé libre choisi par l'auditeur, identifiant horodaté immuable."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sqlite3
import subprocess
import unittest
import urllib.parse
from pathlib import Path

from aule.cli import main
from aule.db import SCHEMA_VERSION, Database
from aule.runs import RunRefError, resolve_run, validate_label
from common import AuditCase
from test_server import ServerCase

HERE = Path(__file__).parent


class LabelRulesTest(unittest.TestCase):
    EXISTING = [{"id": "20260101-100000", "label": "Initial"}, {"id": "20260102-100000", "label": None}]

    def test_free_text_is_accepted_and_normalized(self):
        self.assertEqual(validate_label("  contre-audit   n°1 — après correctifs ", self.EXISTING), "contre-audit n°1 — après correctifs")
        self.assertEqual(validate_label("é" * 80, self.EXISTING), "é" * 80)

    def test_refusals_are_explained(self):
        for bad, msg in (("", "vide"), ("   ", "vide"), ("x" * 81, "trop long"), ("a\x07b", "contrôle"), ("@dernier", "@"), ("20260101-100000", "identifiant"),
                         ("20260101-100000-2", "identifiant"), ("INITIAL", "désigne déjà")):
            with self.assertRaisesRegex(ValueError, msg, msg=bad):
                validate_label(bad, self.EXISTING)
        self.assertEqual(validate_label("initial", self.EXISTING, exclude="20260101-100000"), "initial")   # se renommer soi-même : permis


class DatabaseTest(AuditCase):
    def test_labels_and_mission_persist(self):
        self.db.create_audit("20260101-100000", self.root, "Initial")
        self.db.create_audit("20260102-100000", self.root)
        self.assertEqual({a["id"]: a["label"] for a in self.db.list_audits()}, {"20260101-100000": "Initial", "20260102-100000": None})
        with self.assertRaisesRegex(ValueError, "désigne déjà"):
            self.db.create_audit("20260103-100000", self.root, "initial")
        self.assertIsNone(self.db.get_audit("20260103-100000"))                 # rien n'a été créé
        self.assertEqual(self.db.set_audit_label("20260102-100000", "  contre-audit "), "contre-audit")
        self.assertIsNone(self.db.set_audit_label("20260102-100000", ""))       # vide : retire le libellé
        self.assertIsNone(self.db.get_audit("20260102-100000")["label"])
        with self.assertRaisesRegex(ValueError, "run inconnu"):
            self.db.set_audit_label("nope", "x")

    def test_mission(self):
        self.assertIsNone(self.db.get_mission())
        m = self.db.set_mission("  Acme   2026 ", client="Acme SA", scope="SI de paie")
        self.assertEqual((m["name"], m["client"], m["scope"]), ("Acme 2026", "Acme SA", "SI de paie"))
        m2 = self.db.set_mission("Acme — mission paie")                        # renommer : client et périmètre conservés
        self.assertEqual((m2["name"], m2["client"], m2["scope"], m2["created_at"]), ("Acme — mission paie", "Acme SA", "SI de paie", m["created_at"]))
        for bad in ("", "  ", "x" * 121, "a\x00b"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.db.set_mission(bad)

    def test_v4_database_is_upgraded_in_place_keeping_everything(self):
        old = self.tmp / "v4" / "audit.db"
        old.parent.mkdir()
        con = sqlite3.connect(old)
        con.executescript("""
            CREATE TABLE audit (id TEXT PRIMARY KEY, root TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL);
            INSERT INTO audit VALUES ('20250101-100000', '/old', '2025-01-01T10:00:00', NULL, 'complete');
            CREATE TABLE triage (fingerprint TEXT PRIMARY KEY, status TEXT NOT NULL, comment TEXT, updated_at TEXT NOT NULL);
            INSERT INTO triage VALUES ('f' , 'confirmed', 'ancien', '2025-01-01');
            PRAGMA user_version = 4;""")
        con.commit()
        con.close()
        db = Database(old)
        self.addCleanup(db.close)
        self.assertEqual(db.conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        self.assertEqual([(a["id"], a["label"]) for a in db.list_audits()], [("20250101-100000", None)])    # historique conservé, sans libellé
        self.assertEqual(db.list_triage()["f"]["comment"], "ancien")
        db.set_audit_label("20250101-100000", "Reprise")
        self.assertEqual(resolve_run(db, "reprise"), "20250101-100000")


class ResolveTest(AuditCase):
    def setUp(self):
        super().setUp()
        for rid, label in (("20260101-100000", "Initial"), ("20260102-100000", None), ("20260103-100000", "Contre-audit")):
            self.db.create_audit(rid, self.root, label)

    def test_every_way_to_designate_a_run(self):
        self.assertEqual(resolve_run(self.db), "20260103-100000")
        for ref, want in (("@dernier", "20260103-100000"), ("@last", "20260103-100000"), ("@précédent", "20260102-100000"), ("@previous", "20260102-100000"),
                          ("initial", "20260101-100000"), ("CONTRE-AUDIT", "20260103-100000"), ("20260102-100000", "20260102-100000")):
            self.assertEqual(resolve_run(self.db, ref), want, ref)

    def test_unknown_reference_lists_what_exists(self):
        with self.assertRaisesRegex(RunRefError, r"'nope'.*Contre-audit \(20260103-100000\).*20260102-100000.*Initial \(20260101-100000\)"):
            resolve_run(self.db, "nope")

    def test_edge_cases(self):
        empty = Database(self.tmp / "e" / "audit.db")
        self.addCleanup(empty.close)
        self.assertIsNone(resolve_run(empty))                                   # aucun audit : les commandes gardent leur message « Aucun audit »
        with self.assertRaisesRegex(RunRefError, "aucun audit"):
            resolve_run(empty, "@dernier")
        self.db.conn.execute("DELETE FROM audit WHERE id != '20260101-100000'")
        self.db.conn.commit()
        with self.assertRaisesRegex(RunRefError, "pas de run précédent"):
            resolve_run(self.db, "@précédent")


class CliTest(AuditCase):
    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--data", str(self.data)])
        return code, out.getvalue(), err.getvalue()

    def run_named(self, name, *extra):
        return self.cli("run", str(self.root), "--tools", "cloc,gitleaks", "--name", name, *extra)

    def test_named_passes_work_everywhere_an_id_does(self):
        self.cli("mission", "init", "Acme 2026", "--client", "Acme SA", "--scope", "SI de paie")
        self.assertEqual(self.run_named("initial")[0], 0)
        (self.root / "plain" / "keys.py").write_text("KEY = None\n")
        self.assertEqual(self.run_named("contre-audit")[0], 0)
        ids = {a["label"]: a["id"] for a in self.db.list_audits()}
        self.assertEqual(set(ids), {"initial", "contre-audit"})
        code, out, _ = self.cli("runs")
        self.assertIn("Mission : Acme 2026  (client : Acme SA)", out)
        self.assertRegex(out, rf"{ids['initial']}\s+complete\s+initial\s")
        code, out, _ = self.cli("diff", "initial", "contre-audit", "--kind", "secret")
        self.assertEqual(code, 0)
        self.assertIn(f"A = {ids['initial']}  →  B = {ids['contre-audit']}", out)
        self.assertIn("1 corrigé", out)
        self.assertEqual(self.cli("diff", "@précédent", "@dernier", "--kind", "secret")[1].count("corrigé"), out.count("corrigé"))
        code, out, _ = self.cli("show", "initial")
        self.assertIn(f"Mission « Acme 2026 » — Audit initial ({ids['initial']})", out)
        self.assertEqual(self.cli("report", "initial", "-o", str(self.tmp / "r.html"), "--compare", "contre-audit")[0], 0)
        self.assertEqual(self.cli("export", "contre-audit", "--format", "json", "-o", str(self.tmp / "e.json"))[0], 0)
        self.assertEqual(json.loads((self.tmp / "e.json").read_text())["audit"]["id"], ids["contre-audit"])
        self.assertEqual(self.cli("triage", "list", "--run", "initial")[0], 0)
        self.assertEqual(self.cli("links", "initial")[0], 0)

    def test_invalid_or_duplicate_name_is_refused_before_any_tool_runs(self):
        self.assertEqual(self.run_named("initial")[0], 0)
        before = len(self.db.list_audits())
        for bad, msg in (("initial", "désigne déjà"), ("@x", "@"), ("20260101-100000", "identifiant")):
            code, _, err = self.run_named(bad)
            self.assertEqual(code, 2, bad)
            self.assertIn(msg, err)
        self.assertEqual(len(self.db.list_audits()), before)                   # aucun audit à moitié créé

    def test_label_command_and_unknown_reference(self):
        self.run_named("initial")
        code, out, _ = self.cli("label", "@dernier", "Premier passage")
        self.assertIn("libellé « Premier passage »", out)
        self.assertEqual(self.db.list_audits()[0]["label"], "Premier passage")
        self.assertIn("libellé retiré", self.cli("label", "premier passage", "")[1])
        self.assertIsNone(self.db.list_audits()[0]["label"])
        code, _, err = self.cli("show", "introuvable")
        self.assertEqual(code, 2)
        self.assertIn("run inconnu : 'introuvable'", err)
        self.assertEqual(self.cli("label", "@dernier", "@mauvais")[0], 2)

    def test_resume_by_label(self):
        self.run_named("initial")
        self.assertEqual(self.cli("run", str(self.root), "--tools", "cloc,gitleaks", "--resume", "initial")[0], 0)
        self.assertEqual(len(self.db.list_audits()), 1)                        # reprise du même run, pas un nouveau

    def test_mission_commands(self):
        self.assertIn("Aucune mission nommée", self.cli("mission", "show")[1])
        self.assertIn("créée", self.cli("mission", "init", "Mission A")[1])
        self.cli("mission", "set", "Mission A", "--client", "ACME")
        self.cli("mission", "rename", "Mission B")
        out = self.cli("mission", "show")[1]
        self.assertIn("Mission : Mission B", out)
        self.assertIn("Client  : ACME", out)
        self.assertEqual(self.cli("mission", "init", "")[0], 2)

    def test_purge_accepts_labels(self):
        self.run_named("initial")
        self.run_named("second")
        code, out, _ = self.cli("purge", "--run", "initial", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual([a["label"] for a in self.db.list_audits()], ["second"])


class ServerAndReportTest(ServerCase):
    def setUp(self):
        AuditCase.setUp(self)
        self.db.set_mission("Acme 2026", client="Acme SA")
        self.run1 = self.run_audit(tool_names=self.TOOLS, label="initial")
        (self.root / "plain" / "keys.py").write_text("KEY = None\n")
        self.run2 = self.run_audit(tool_names=self.TOOLS, label="contre-audit")
        self.run_id = self.run2
        self.start_server(True)

    def test_labels_work_in_api_parameters_and_payload(self):
        d = self.call("GET", "/api/data?run=initial")[1]
        self.assertEqual((d["audit"]["id"], d["audit"]["label"], d["mission"]["name"]), (self.run1, "initial", "Acme 2026"))
        self.assertEqual([(a["label"], a["id"]) for a in d["options"]["audits"]], [("contre-audit", self.run2), ("initial", self.run1)])
        status, diff, _ = self.call("GET", "/api/diff?a=initial&b=contre-audit")
        self.assertEqual((status, diff["a"], diff["b"]), (200, self.run1, self.run2))
        self.assertEqual(self.call("GET", "/api/diff?a=" + urllib.parse.quote("@précédent"))[1]["a"], self.run1)
        status, body, _ = self.call("GET", "/api/data?run=nope")
        self.assertEqual((status, "contre-audit" in body["error"]), (404, True))        # le message liste les passages existants

    def test_job_name_is_validated_immediately(self):
        for bad, msg in (("initial", "désigne déjà"), ("@x", "@")):
            status, body, _ = self.call("POST", "/api/jobs", {"root": str(self.root), "tools": ["cloc"], "name": bad})
            self.assertEqual((status, msg in body["error"]), (400, True), bad)
        self.assertEqual(self.call("GET", "/api/jobs/current")[1]["state"], "idle")      # aucun job lancé
        self.assertEqual(self.call("POST", "/api/jobs", {"root": str(self.root), "tools": ["cloc"], "name": "  3e passage "})[0], 202)
        import time
        for _ in range(300):
            if self.call("GET", "/api/jobs/current")[1]["state"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(self.db.list_audits()[0]["label"], "3e passage")

    def test_report_title_carries_mission_and_label_and_is_escaped(self):
        from aule.report import render_report
        self.db.set_audit_label(self.run2, "<b>x</b> & y")
        html = render_report(self.db, self.run2, self.data)
        self.assertIn("<title>Audit Acme 2026 — &lt;b&gt;x&lt;/b&gt; &amp; y</title>", html)
        self.assertEqual(html.count("</script>"), 2)

    def test_headers_in_the_page(self):
        if not shutil.which("node"):
            self.skipTest("node requis")
        from aule.report import render_report
        page = self.tmp / "r.html"
        page.write_text(render_report(self.db, self.run2, self.data), encoding="utf-8")
        out = json.loads(subprocess.run(["node", str(HERE / "dom_smoke.js"), str(page)], capture_output=True, text=True, timeout=120).stdout)
        self.assertEqual(out["title"], "Acme 2026 — Audit contre-audit")


if __name__ == "__main__":
    unittest.main()
