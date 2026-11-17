"""gittools (Extractor) + gitleaks mode history."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from aule.plugins.gittools import parse_commit_meta
from common import AuditCase

TOOLS = ["cloc", "gitleaks", "gittools"]


class CommitMetaTest(unittest.TestCase):
    def test_parse_cat_file_output(self):
        meta = parse_commit_meta(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"
            "parent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "author Alice Martin <alice@example.org> 1700000000 +0100\n"
            "committer Bob <bob@example.org> 1700003600 -0530\n\n"
            "Fix the thing\n\nLonger body\n")
        self.assertEqual(meta["parents"], ["a" * 40])
        self.assertEqual((meta["author"], meta["author_email"]), ("Alice Martin", "alice@example.org"))
        self.assertEqual(meta["author_date"], "2023-11-14T23:13:20+01:00")
        self.assertTrue(meta["committer_date"].endswith("-05:30"))
        self.assertEqual(meta["date"], meta["author_date"])
        self.assertTrue(meta["message"].startswith("Fix the thing"))

    def test_unexpected_format_keeps_raw_text(self):
        meta = parse_commit_meta("something else entirely")
        self.assertIn("something else", meta["raw_meta"])


class HistoryTest(AuditCase):
    def test_extract_then_scan_history(self):
        run_id = self.run_audit(tool_names=TOOLS)
        st = self.statuses(run_id)
        self.assertEqual(st[("repo-git", "gittools", "extract")], "ok")
        self.assertEqual(st[("plain", "gittools", "extract")], "skipped")      # pas de .git
        self.assertEqual(st[("repo-git", "gitleaks", "history")], "ok")
        self.assertEqual(st[("plain", "gitleaks", "history")], "skipped")      # pas d'extraction

        commits = self.db.entities(run_id, "commit")
        self.assertEqual([c["data"]["hash"] for c in sorted(commits, key=lambda c: c["data"]["index"])], self.commits)
        self.assertTrue(all(c["data"]["author"] == "Alice" and c["data"]["date"] for c in commits))
        self.assertIn("remove hardcoded key", next(c for c in commits if c["data"]["hash"] == self.commits[1])["data"]["message"])

        hist = {s["data"]["file"]: s["data"] for s in self.secrets(run_id, "repo-git", "history")}
        self.assertEqual(set(hist), {"config.py", "settings.py"})
        # la clé supprimée au commit 2 n'existe que dans le commit 1 ; l'autre persiste dans les deux
        self.assertEqual((hist["config.py"]["commits_count"], hist["config.py"]["first_commit"]), (1, self.commits[0]))
        self.assertEqual(hist["settings.py"]["commits_count"], 2)
        self.assertEqual((hist["settings.py"]["first_commit"], hist["settings.py"]["last_commit"]), (self.commits[0], self.commits[1]))
        self.assertTrue(hist["config.py"]["date"] and hist["config.py"]["author"] == "Alice")
        self.assertNotIn("0-", hist["config.py"]["file"])  # préfixe <n>-<hash>/ retiré

    def test_history_fingerprints_are_stable_across_runs(self):
        a = {s["fingerprint"] for s in self.secrets(self.run_audit(tool_names=TOOLS), mode="history")}
        b = {s["fingerprint"] for s in self.secrets(self.run_audit(tool_names=TOOLS), mode="history")}
        self.assertEqual(a, b)
        self.assertEqual(len(a), 2)

    def test_phase_order_gittools_before_history(self):
        self.run_audit(tool_names=TOOLS)
        calls = self.calls()
        self.assertLess(calls.index("extractor"), calls.index("gitleaks-history") if "gitleaks-history" in calls else len(calls))

    def test_extractor_failure_is_recorded_and_history_skipped(self):
        with mock.patch.dict(os.environ, {"FAKE_EXTRACTOR_FAIL": "1"}):
            run_id = self.run_audit(tool_names=TOOLS)
        st = self.statuses(run_id)
        self.assertEqual(st[("repo-git", "gittools", "extract")], "failed")
        self.assertEqual(st[("repo-git", "gitleaks", "history")], "skipped")
        self.assertEqual(st[("repo-git", "gitleaks", "dir")], "ok")  # le reste n'est pas affecté
        err = next(r["error"] for r in self.db.list_tool_runs(run_id) if r["tool"] == "gittools" and r["status"] == "failed")
        self.assertIn("broken repository", err)

    def test_history_mode_dropped_when_gittools_not_selected(self):
        st = self.statuses(self.run_audit(tool_names=["gitleaks"]))
        self.assertFalse([k for k in st if k[2] == "history"])

    def test_reparse_history_from_raw(self):
        from aule.orchestrator import reparse
        run_id = self.run_audit(tool_names=TOOLS)
        before = sorted(e["fingerprint"] for e in self.db.entities(run_id))
        self.db.conn.execute("DELETE FROM entity")
        self.db.conn.commit()
        reparse(self.db, self.data, run_id, log=lambda *_: None)
        self.assertEqual(sorted(e["fingerprint"] for e in self.db.entities(run_id)), before)


if __name__ == "__main__":
    unittest.main()
