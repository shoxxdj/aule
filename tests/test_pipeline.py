"""Pipeline de base : découverte, exécution, sorties brutes, reprise, erreurs."""
from __future__ import annotations

import json
import os
from unittest import mock

import fakes
from aule.discovery import discover_projects
from aule.orchestrator import reparse
from common import AuditCase


class PipelineTest(AuditCase):
    def test_discovery(self):
        projects = {p.name: p for p in discover_projects(self.root)}
        self.assertEqual(set(projects), {"repo-git", "plain"})  # ni caché ni fichier
        self.assertTrue(projects["repo-git"].is_git)
        self.assertEqual(len(projects["repo-git"].head_commit or ""), 40)
        self.assertFalse(projects["plain"].is_git)

    def test_data_dir_inside_root_is_excluded(self):
        inside = self.root / "data"
        inside.mkdir()
        self.assertNotIn("data", {p.name for p in discover_projects(self.root, exclude=(inside,))})

    def test_full_run(self):
        run_id = self.run_audit()
        st = self.statuses(run_id)
        self.assertEqual(st[("repo-git", "cloc", "default")], "ok")
        self.assertEqual(st[("repo-git", "gitleaks", "dir")], "ok")   # code retour 1 accepté
        self.assertEqual(st[("repo-git", "gitleaks", "git")], "ok")
        self.assertEqual(st[("plain", "gitleaks", "git")], "skipped")  # pas un dépôt git
        self.assertEqual(self.db.get_audit(run_id)["status"], "complete")

        techs = self.db.entities(run_id, "technology", {p["name"]: p["id"] for p in self.db.list_projects(run_id)}["repo-git"])
        self.assertEqual({t["data"]["language"] for t in techs}, {"Python"})
        # dir : seule la clé encore présente. git : les 2 clés du 1er commit (dont celle supprimée ensuite).
        self.assertEqual([s["data"]["file"] for s in self.secrets(run_id, "repo-git", "dir")], ["settings.py"])
        self.assertEqual(sorted(s["data"]["file"] for s in self.secrets(run_id, "repo-git", "git")), ["config.py", "settings.py"])
        self.assertEqual(len(self.secrets(run_id, "plain", "dir")), 1)

    def test_history_is_opt_in(self):
        st = self.statuses(self.run_audit())
        self.assertFalse([k for k in st if k[1] == "gittools" or k[2] == "history"])

    def test_secret_never_stored_in_clear_in_db_but_kept_raw(self):
        run_id = self.run_audit()
        dump = "\n".join(self.db.conn.iterdump())
        self.assertNotIn(fakes.SECRET_A, dump)
        self.assertNotIn(fakes.SECRET_B, dump)
        raw = self.data / "runs" / run_id / "repo-git" / "gitleaks" / "dir"
        self.assertIn(fakes.SECRET_B, (raw / "report.json").read_text())

    def test_raw_outputs_and_meta(self):
        run_id = self.run_audit()
        raw = self.data / "runs" / run_id / "repo-git" / "gitleaks" / "git"
        for f in ("cmd.txt", "stdout.txt", "stderr.txt", "report.json", "meta.json"):
            self.assertTrue((raw / f).exists(), f)
        meta = json.loads((raw / "meta.json").read_text())
        self.assertEqual(meta["tool_version"], "8.30.0")
        self.assertEqual(meta["exit_code"], 1)
        self.assertEqual(len(meta["git_commit"]), 40)
        self.assertEqual(len(meta["report_sha256"]), 64)
        self.assertIn("--log-opts=--all", (raw / "cmd.txt").read_text())

    def test_resume_skips_completed_work(self):
        run_id = self.run_audit()
        first = len(self.calls())
        self.run_audit(resume=run_id)
        self.assertEqual(len(self.calls()), first)

    def test_resume_reruns_failures_only(self):
        with mock.patch.dict(os.environ, {"FAKE_GITLEAKS_FAIL": "1"}):
            run_id = self.run_audit()
        st = self.statuses(run_id)
        self.assertEqual(st[("repo-git", "gitleaks", "dir")], "failed")
        self.assertEqual(st[("repo-git", "cloc", "default")], "ok")  # les autres continuent
        self.assertEqual(self.db.get_audit(run_id)["status"], "partial")
        self.assertIn("boom", next(r["error"] for r in self.db.list_tool_runs(run_id) if r["status"] == "failed"))

        before = self.calls().count("cloc")
        self.run_audit(resume=run_id)
        self.assertEqual(self.calls().count("cloc"), before)
        self.assertEqual(self.statuses(run_id)[("repo-git", "gitleaks", "dir")], "ok")
        self.assertEqual(self.db.get_audit(run_id)["status"], "complete")

    def test_missing_binary_is_recorded_not_fatal(self):
        (self.bin / "gitleaks").unlink()
        st = self.statuses(self.run_audit())
        self.assertEqual(st[("repo-git", "gitleaks", "dir")], "unavailable")
        self.assertEqual(st[("repo-git", "cloc", "default")], "ok")

    def test_reparse_rebuilds_entities_from_raw(self):
        run_id = self.run_audit()
        self.db.conn.execute("DELETE FROM entity")
        self.db.conn.commit()
        reparse(self.db, self.data, run_id, log=lambda *_: None)
        self.assertEqual(len(self.db.entities(run_id, "secret")), 4)  # repo-git : 1 dir + 2 git ; plain : 1 dir

    def test_triage_survives_new_run(self):
        run1 = self.run_audit()
        fp = self.db.entities(run1, "secret")[0]["fingerprint"]
        self.db.set_triage(fp, "false_positive", "clé d'exemple")
        run2 = self.run_audit()
        self.assertNotEqual(run1, run2)
        match = [e for e in self.db.entities(run2, "secret") if e["fingerprint"] == fp]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0]["triage_status"], "false_positive")


if __name__ == "__main__":
    import unittest
    unittest.main()
