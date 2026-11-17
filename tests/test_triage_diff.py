"""Triage (CLI, base) et comparaison de runs."""
from __future__ import annotations

import contextlib
import io
import json
import os
from unittest import mock

import fakes
from aule.cli import main
from aule.db import TRIAGE_STATUSES
from aule.diff import diff_runs
from aule.triage import find_entities
from common import AuditCase


class TriageTest(AuditCase):
    def setUp(self):
        super().setUp()
        self.run_id = self.run_audit(tool_names=["cloc", "gitleaks"])

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main([*argv, "--data", str(self.data)])
            except SystemExit as exc:  # argparse
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def status_of(self, fp):
        return (self.db.list_triage().get(fp) or {}).get("status")

    def test_set_by_prefix_with_comment_then_list_then_clear(self):
        e = find_entities(self.db, self.run_id, kind="secret", project="plain")[0]
        code, out, _ = self.cli("triage", "set", "false_positive", e["fingerprint"][:8], "-c", "clé de démonstration")
        self.assertEqual(code, 0)
        self.assertIn("1 élément(s) marqué(s) « false_positive »", out)
        self.assertEqual(self.db.list_triage()[e["fingerprint"]]["comment"], "clé de démonstration")
        code, out, _ = self.cli("triage", "list")
        self.assertIn("false_positive", out)
        self.assertIn("clé de démonstration", out)
        self.assertEqual(self.cli("triage", "clear", e["fingerprint"][:8])[0], 0)
        self.assertIsNone(self.status_of(e["fingerprint"]))

    def test_all_statuses_valid_and_invalid_rejected(self):
        fp = find_entities(self.db, self.run_id)[0]["fingerprint"]
        for status in TRIAGE_STATUSES:
            self.db.set_triage(fp, status)
            self.assertEqual(self.status_of(fp), status)
        with self.assertRaises(ValueError):
            self.db.set_triage(fp, "banana")
        self.assertEqual(self.cli("triage", "set", "banana", fp[:8])[0], 2)  # refusé par argparse

    def test_comment_is_kept_when_status_changes_without_comment(self):
        fp = find_entities(self.db, self.run_id)[0]["fingerprint"]
        self.db.set_triage(fp, "to_review", "à creuser")
        self.db.set_triage(fp, "confirmed")
        self.assertEqual(self.db.list_triage()[fp]["comment"], "à creuser")

    def test_bulk_by_filter_needs_confirmation(self):
        code, out, _ = self.cli("triage", "set", "to_review", "--kind", "secret", "--project", "repo-git")
        self.assertEqual(code, 0)
        self.assertIn("Ajoutez --yes", out)
        self.assertEqual(self.db.list_triage(), {})          # rien n'a été modifié
        code, out, _ = self.cli("triage", "set", "to_review", "--kind", "secret", "--project", "repo-git", "--yes")
        self.assertIn("3 élément(s)", out)                    # dir + 2 en historique git
        self.assertEqual(len(self.db.list_triage()), 3)
        # --untriaged : seul le projet restant
        self.cli("triage", "set", "confirmed", "--kind", "secret", "--untriaged", "--yes")
        self.assertEqual(sorted(v["status"] for v in self.db.list_triage().values()), ["confirmed", "to_review", "to_review", "to_review"])

    def test_filters_mode_rule_file_and_severity(self):
        self.assertEqual({e["data"]["mode"] for e in find_entities(self.db, self.run_id, kind="secret", mode="git")}, {"git"})
        self.assertEqual(len(find_entities(self.db, self.run_id, kind="secret", rule="aws-access-token")), 2)
        self.assertEqual(len(find_entities(self.db, self.run_id, kind="secret", file_glob="config.*")), 1)
        self.assertEqual(len(find_entities(self.db, self.run_id, kind="secret", severity="high")), 4)
        self.assertEqual(find_entities(self.db, self.run_id, kind="secret", severity="critical"), [])

    def test_errors_are_explained(self):
        self.assertIn("préfixe trop court", self.cli("triage", "set", "confirmed", "abc")[2])
        self.assertIn("aucun résultat ne correspond", self.cli("triage", "set", "confirmed", "zzzzzzzz")[2])
        self.assertIn("indiquez des empreintes ou au moins un filtre", self.cli("triage", "set", "confirmed")[2])
        self.assertEqual(self.cli("triage", "set", "confirmed", "--project", "nope", "--yes")[0], 1)

    def test_ambiguous_prefix_is_refused(self):
        fps = sorted(e["fingerprint"] for e in find_entities(self.db, self.run_id))
        with mock.patch("aule.triage.find_entities", wraps=find_entities):
            from aule.triage import resolve_prefixes
            common = os.path.commonprefix(fps)
            if len(common) >= 6:  # (improbable avec des hash) ; sinon on fabrique l'ambiguïté
                with self.assertRaisesRegex(ValueError, "ambigu"):
                    resolve_prefixes(self.db, self.run_id, [common])
        self.db.conn.execute("UPDATE entity SET fingerprint = 'aaaaaa111111' WHERE id IN (SELECT id FROM entity WHERE kind='secret' LIMIT 1)")
        self.db.conn.execute("UPDATE entity SET fingerprint = 'aaaaaa222222' WHERE id IN (SELECT id FROM entity WHERE kind='secret' ORDER BY id DESC LIMIT 1)")
        self.db.conn.commit()
        from aule.triage import resolve_prefixes
        with self.assertRaisesRegex(ValueError, "ambigu"):
            resolve_prefixes(self.db, self.run_id, ["aaaaaa"])


class DiffTest(AuditCase):
    def mutate(self):
        """Entre deux runs : un secret corrigé (plain), un nouveau (webapp), le reste inchangé."""
        (self.root / "plain" / "keys.py").write_text("KEY = os.environ['KEY']\n")
        (self.root / "webapp").mkdir()
        (self.root / "webapp" / "token.js").write_text(f'const t = "{fakes.SECRET_B}";\n')

    def labels(self, d, section, kind="secret"):
        return sorted((r["project"], r["location"]) for r in d["kinds"][kind][section])

    def test_new_fixed_persistent(self):
        r1 = self.run_audit(tool_names=["cloc", "gitleaks"])
        fp_persistent = next(e["fingerprint"] for e in find_entities(self.db, r1, kind="secret", project="repo-git", mode="dir"))
        self.db.set_triage(fp_persistent, "accepted_risk", "connu")
        self.mutate()
        r2 = self.run_audit(tool_names=["cloc", "gitleaks"])
        d = diff_runs(self.db, r1, r2, ("secret",))
        self.assertEqual(self.labels(d, "new"), [("webapp", "token.js:1")])
        self.assertEqual(self.labels(d, "fixed"), [("plain", "keys.py:1")])
        self.assertEqual(self.labels(d, "persistent"), [("repo-git", "config.py:1"), ("repo-git", "settings.py:1"), ("repo-git", "settings.py:1")])
        self.assertEqual(d["kinds"]["secret"]["counts"], {"new": 1, "fixed": 1, "persistent": 3})
        self.assertIn("webapp", d["projects_added"])
        self.assertEqual(next(r for r in d["kinds"]["secret"]["persistent"] if r["fingerprint"] == fp_persistent)["triage"], "accepted_risk")

    def test_removed_project_is_not_reported_as_fixed(self):
        r1 = self.run_audit(tool_names=["cloc", "gitleaks"])
        import shutil
        shutil.rmtree(self.root / "plain")
        r2 = self.run_audit(tool_names=["cloc", "gitleaks"])
        d = diff_runs(self.db, r1, r2, ("secret",))
        self.assertEqual(d["projects_removed"], ["plain"])
        self.assertEqual(d["kinds"]["secret"]["counts"], {"new": 0, "fixed": 0, "persistent": 3})  # plain : ni corrigé ni persistant

    def test_a_tool_missing_from_one_run_is_not_reported_as_new(self):
        r1 = self.run_audit(tool_names=["cloc", "gitleaks"])
        from test_sast_deps import make_rules
        from aule.config import parse_config
        (self.root / "repo-git" / "x.py").write_text("eval(1)\n")
        cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(make_rules(self.tmp))}}}}, self.tmp)
        r2 = self.run_audit(cfg, tool_names=["cloc", "gitleaks", "opengrep"])
        self.assertTrue(self.db.entities(r2, "sast_finding"))
        d = diff_runs(self.db, r1, r2)
        self.assertEqual(d["kinds"]["sast_finding"]["counts"], {"new": 0, "fixed": 0, "persistent": 0})  # non comparable
        self.assertTrue(any("opengrep" in x and "seulement dans B" in x for x in d["not_comparable"]))
        self.assertEqual(d["counts"]["fixed"], 0)

    def test_a_failed_tool_does_not_fake_fixes(self):
        r1 = self.run_audit(tool_names=["cloc", "gitleaks"])
        with mock.patch.dict(os.environ, {"FAKE_GITLEAKS_FAIL": "1"}):
            r2 = self.run_audit(tool_names=["cloc", "gitleaks"])
        d = diff_runs(self.db, r1, r2, ("secret",))
        self.assertEqual(d["kinds"]["secret"]["counts"], {"new": 0, "fixed": 0, "persistent": 0})  # ce n'est pas « tout corrigé »
        self.assertTrue(any("gitleaks" in x for x in d["not_comparable"]))

    def test_cli_defaults_to_last_two_runs_and_json(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main(["diff", "--data", str(self.data)]), 2)
        self.assertIn("au moins deux audits", err.getvalue())
        r1 = self.run_audit(tool_names=["cloc", "gitleaks"])
        self.mutate()
        r2 = self.run_audit(tool_names=["cloc", "gitleaks"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["diff", "--data", str(self.data), "--kind", "secret"]), 0)
        text = out.getvalue()
        self.assertIn(f"A = {r1}  →  B = {r2}", text)
        self.assertIn("+ ", text)
        self.assertIn("webapp", text)
        self.assertNotIn("  = ", text)  # persistants masqués par défaut
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["diff", r1, r2, "--data", str(self.data), "--kind", "secret", "--json"])
        self.assertEqual(json.loads(out.getvalue())["counts"]["new"], 1)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main(["diff", "nope", r2, "--data", str(self.data)]), 2)
        self.assertIn("run inconnu", err.getvalue())


if __name__ == "__main__":
    import unittest
    unittest.main()
