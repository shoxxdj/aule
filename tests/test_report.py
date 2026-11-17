"""Rapport HTML : contenu, sécurité (aucun secret en clair, pas d'injection), exécution du JS."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import unittest
from pathlib import Path

import fakes
from aule.cli import main
from aule.config import parse_config
from aule.db import Database
from aule.report import build_report_data, render_report
from common import AuditCase

HERE = Path(__file__).parent


class ReportTest(AuditCase):
    def setUp(self):
        super().setUp()
        from test_unpack import zip_dir
        zip_dir(self.root / "repo-git", self.root / "plain" / "site.zip", wrapper="repo-main")
        self.run_id = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"], unpack=True)
        self.db.set_triage(self.secrets(self.run_id, "repo-git", "dir")[0]["fingerprint"], "false_positive", "test")
        self.html = render_report(self.db, self.run_id)

    def test_data_content(self):
        d = build_report_data(self.db, self.run_id)
        self.assertEqual({p["name"] for p in d["projects"]}, {"repo-git", "plain", "plain@site.zip"})
        self.assertEqual({s["mode"] for s in d["secrets"]}, {"dir", "git", "history"})
        self.assertEqual(len(d["commits"]), 4)  # 2 commits x (repo-git + archive)
        self.assertTrue(any(r["tool"] == "unpack" for r in d["runs"]))
        self.assertEqual([r["type"] for r in d["relations"]].count("extracted_from"), 1)
        self.assertIn("false_positive", {s["triage"] for s in d["secrets"]})

    def test_no_clear_secret_in_report(self):
        for secret in (fakes.SECRET_A, fakes.SECRET_B):
            self.assertNotIn(secret, self.html)

    def test_untrusted_content_cannot_break_out_of_script_tag(self):
        # un message de commit contient </script><script>alert(1)</script>
        self.assertIn("alert(1)", self.html)               # la donnée est bien là (échappée)
        self.assertEqual(self.html.count("</script>"), 2)  # uniquement les 2 vraies balises du gabarit
        self.assertNotIn("<script>alert", self.html)

    def test_cli_report_command(self):
        out = self.tmp / "out" / "r.html"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["report", "--data", str(self.data), "-o", str(out)])
        self.assertEqual(code, 0)
        self.assertTrue(out.read_text(encoding="utf-8").startswith("<!doctype html>"))
        self.assertIn(str(out), buf.getvalue())

    @unittest.skipUnless(shutil.which("node"), "node requis pour exécuter le JS du rapport")
    def test_javascript_runs_and_renders_every_tab(self):
        page = self.tmp / "report.html"
        page.write_text(self.html, encoding="utf-8")
        proc = subprocess.run(["node", str(HERE / "dom_smoke.js"), str(page)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertGreater(out["clicks"], 30)  # tris, ouvertures de lignes, filtres : tout a été sollicité
        self.assertEqual(out["title"], f"Audit {self.run_id}")
        tabs = out["tabs"]
        self.assertIn("plain@site.zip", tabs["Synthèse 3"])
        self.assertIn("Python", next(v for k, v in tabs.items() if k.startswith("Technologies")))
        secrets = next(v for k, v in tabs.items() if k.startswith("Secrets"))
        for expected in ("aws-access-token", "github-pat", "AK••••••LE"):
            self.assertIn(expected, secrets)
        self.assertIn("Commits reconstruits", next(v for k, v in tabs.items() if k.startswith("Historique")))
        self.assertIn("unpack / site.zip", next(v for k, v in tabs.items() if k.startswith("Exécutions")))
        self.assertNotIn("repo-git", out["afterSearch"])   # la recherche sans correspondance vide la vue
        self.assertIn("Rien à afficher", out["afterSearch"])

    @unittest.skipUnless(shutil.which("node"), "node requis")
    def test_deep_link_to_tab_and_project(self):
        page = self.tmp / "r2.html"
        page.write_text(self.html, encoding="utf-8")
        proc = subprocess.run(["node", str(HERE / "dom_smoke.js"), str(page), "#tab=secrets&project=repo-git"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


class MigrationTest(AuditCase):
    def test_v1_database_is_upgraded_in_place(self):
        old = self.tmp / "old" / "audit.db"
        old.parent.mkdir()
        con = sqlite3.connect(old)
        con.executescript("""
            CREATE TABLE audit (id TEXT PRIMARY KEY, root TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL);
            CREATE TABLE project (id INTEGER PRIMARY KEY, audit_id TEXT NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL,
                                  is_git INTEGER NOT NULL, head_commit TEXT, UNIQUE (audit_id, name));
            INSERT INTO audit VALUES ('r1', '/x', '2025-01-01', NULL, 'complete');
            INSERT INTO project VALUES (1, 'r1', 'legacy', '/x/legacy', 0, NULL);
            PRAGMA user_version = 1;
        """)
        con.commit()
        con.close()
        db = Database(old)
        self.addCleanup(db.close)
        p = db.list_projects("r1")[0]
        self.assertEqual((p["name"], p["parent"], p["origin"]), ("legacy", None, None))
        from aule.db import SCHEMA_VERSION
        self.assertEqual(db.conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        db.add_finding("legacy", "Constat posé après migration")  # tables v3 créées sur une base v1
        self.assertEqual(len(db.list_findings("legacy")), 1)


if __name__ == "__main__":
    unittest.main()


def run_smoke(page: Path, hash_: str = "") -> dict:
    proc = subprocess.run(["node", str(HERE / "dom_smoke.js"), str(page), hash_], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


class RevealTest(AuditCase):
    """Secrets en clair dans le rapport : relus depuis les sorties brutes, jamais écrits dans la base."""

    def setUp(self):
        super().setUp()
        self.run_id = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"])

    def data_reveal(self):
        return build_report_data(self.db, self.run_id, self.data, reveal=True)

    def test_each_secret_is_paired_with_its_own_value(self):
        secrets = self.data_reveal()["secrets"]
        self.assertEqual({s["mode"] for s in secrets}, {"dir", "git", "history"})
        for s in secrets:
            expected = {"aws-access-token": fakes.SECRET_A, "github-pat": fakes.SECRET_B}[s["rule_id"]]
            self.assertEqual(s["secret"], expected, f"{s['mode']} {s['file']}")   # bon index pour chaque mode
            self.assertIn(expected, s["match"])
        self.assertTrue(all("secret" in s for s in secrets))

    def test_masked_by_default_and_requires_data_dir(self):
        masked = build_report_data(self.db, self.run_id)
        self.assertFalse(any("secret" in s or "match" in s for s in masked["secrets"]))
        with self.assertRaises(ValueError):
            build_report_data(self.db, self.run_id, None, reveal=True)
        for secret in (fakes.SECRET_A, fakes.SECRET_B):
            self.assertNotIn(secret, render_report(self.db, self.run_id, self.data, reveal=False))

    def test_clear_html_and_db_stays_clean(self):
        html = render_report(self.db, self.run_id, self.data, reveal=True)
        self.assertIn(fakes.SECRET_A, html)
        self.assertIn(fakes.SECRET_B, html)
        self.assertEqual(html.count("</script>"), 2)  # l'échappement protège aussi les valeurs en clair
        dump = "\n".join(self.db.conn.iterdump())
        self.assertNotIn(fakes.SECRET_A, dump)
        self.assertNotIn(fakes.SECRET_B, dump)

    def test_tampered_raw_report_is_detected(self):
        raw = self.data / "runs" / self.run_id / "repo-git" / "gitleaks" / "dir" / "report.json"
        raw.write_text(raw.read_text() + "\n ")  # le contenu change, donc l'empreinte aussi
        d = self.data_reveal()
        self.assertEqual(len(d["warnings"]), 1)
        self.assertIn("repo-git · gitleaks/dir", d["warnings"][0])
        by = {(s["project"], s["mode"]): s for s in d["secrets"]}
        self.assertNotIn("secret", by[("repo-git", "dir")])    # pas de valeur non vérifiée
        self.assertIn("secret", by[("repo-git", "git")])       # les autres rapports restent valides

    def test_missing_raw_report_degrades_gracefully(self):
        (self.data / "runs" / self.run_id / "plain" / "gitleaks" / "dir" / "report.json").unlink()
        d = self.data_reveal()
        self.assertTrue(any("plain" in w for w in d["warnings"]))
        self.assertTrue(any("secret" in s for s in d["secrets"]))

    def test_secretish_sast_snippets_are_dropped_only_when_masking(self):
        pid = self.db.list_projects(self.run_id)[0]["id"]
        rid = self.db.list_tool_runs(self.run_id)[0]["id"]
        for rule in ("python.hardcoded-password", "python.eval-detected"):
            self.db.conn.execute("INSERT INTO entity(audit_id, project_id, tool_run_id, kind, fingerprint, data) VALUES (?,?,?,?,?,?)",
                                 (self.run_id, pid, rid, "sast_finding", rule, json.dumps(
                                     {"rule_id": rule, "severity": "high", "file": "a.py", "snippet": "pwd = 'hunter2'"})))
        self.db.conn.commit()
        snip = lambda reveal: {f["rule_id"]: f["snippet"] for f in build_report_data(self.db, self.run_id, self.data, reveal)["sast"]}  # noqa: E731
        self.assertEqual(snip(False), {"python.hardcoded-password": None, "python.eval-detected": "pwd = 'hunter2'"})
        self.assertEqual(snip(True)["python.hardcoded-password"], "pwd = 'hunter2'")

    def test_cli_defaults_to_clear_with_restricted_permissions(self):
        out = self.tmp / "clear.html"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["report", "--data", str(self.data), "-o", str(out)]), 0)
        self.assertIn(fakes.SECRET_B, out.read_text(encoding="utf-8"))
        self.assertIn("EN CLAIR", buf.getvalue())
        if os.name == "posix":
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_cli_mask_option(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["report", "--data", str(self.data), "--mask"]), 0)
        out = self.data / f"report-{self.run_id}-masque.html"
        self.assertTrue(out.exists())
        for secret in (fakes.SECRET_A, fakes.SECRET_B):
            self.assertNotIn(secret, out.read_text(encoding="utf-8"))
        self.assertNotIn("EN CLAIR", buf.getvalue())

    @unittest.skipUnless(shutil.which("node"), "node requis")
    def test_page_shows_clear_values_and_danger_banner(self):
        page = self.tmp / "clear.html"
        page.write_text(render_report(self.db, self.run_id, self.data, reveal=True), encoding="utf-8")
        out = run_smoke(page)
        self.assertIn("CONFIDENTIEL", out["notices"])
        secrets_tab = next(v for k, v in out["tabs"].items() if k.startswith("Secrets"))
        self.assertIn(fakes.SECRET_B, secrets_tab)
        self.assertIn("Valeur (en clair)", secrets_tab)

        masked = self.tmp / "masked.html"
        masked.write_text(render_report(self.db, self.run_id, self.data, reveal=False), encoding="utf-8")
        out = run_smoke(masked)
        self.assertNotIn("CONFIDENTIEL", out["notices"])
        self.assertIn("masquées", out["notices"])
        self.assertNotIn(fakes.SECRET_B, next(v for k, v in out["tabs"].items() if k.startswith("Secrets")))

    @unittest.skipUnless(shutil.which("node"), "node requis")
    def test_page_shows_integrity_warning(self):
        (self.data / "runs" / self.run_id / "plain" / "gitleaks" / "dir" / "report.json").write_text("[]")
        page = self.tmp / "w.html"
        page.write_text(render_report(self.db, self.run_id, self.data, reveal=True), encoding="utf-8")
        self.assertIn("modifiée", run_smoke(page)["notices"])


class SastDepsReportTest(AuditCase):
    def setUp(self):
        super().setUp()
        from test_sast_deps import make_rules
        (self.root / "repo-git" / "service.py").write_text("x = eval('1')\n")
        (self.root / "repo-git" / "requirements.txt").write_text("django==2.2.0\nrequests==2.31.0\n")
        cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(make_rules(self.tmp))}}}}, self.tmp)
        self.run_id = self.run_audit(cfg, tool_names=["cloc", "opengrep", "dependency-check"])

    def test_data(self):
        d = build_report_data(self.db, self.run_id)
        self.assertEqual({f["rule_id"] for f in d["sast"]}, {"python.lang.security.audit.eval-detected"})
        self.assertEqual({v["id"] for v in d["vulns"]}, {"CVE-2019-19844"})
        self.assertEqual({x["name"] for x in d["deps"] if x["project"] == "repo-git"}, {"django", "requests"})

    @unittest.skipUnless(shutil.which("node"), "node requis")
    def test_new_tabs_render(self):
        page = self.tmp / "r.html"
        page.write_text(render_report(self.db, self.run_id, self.data, reveal=True), encoding="utf-8")
        out = run_smoke(page)
        tabs = out["tabs"]
        self.assertIn("python.lang.security.audit.eval-detected", next(v for k, v in tabs.items() if k.startswith("Code (SAST)")))
        deps = next(v for k, v in tabs.items() if k.startswith("Dépendances"))
        self.assertIn("CVE-2019-19844", deps)
        self.assertIn("django", deps)
        syn = next(v for k, v in tabs.items() if k.startswith("Synthèse"))
        self.assertIn("Failles de code (SAST)", syn)
        self.assertIn("Dépendances vulnérables", syn)
        self.assertGreater(out["clicks"], 60)

    @unittest.skipUnless(shutil.which("node"), "node requis")
    def test_empty_states_explain_how_to_enable(self):
        run_id = self.run_audit(tool_names=["cloc", "gitleaks"])  # ni opengrep ni dependency-check
        page = self.tmp / "e.html"
        page.write_text(render_report(self.db, run_id, self.data), encoding="utf-8")
        tabs = run_smoke(page)["tabs"]
        self.assertIn("--with opengrep", next(v for k, v in tabs.items() if k.startswith("Code (SAST)")))
        self.assertIn("--with dependency-check", next(v for k, v in tabs.items() if k.startswith("Dépendances")))
