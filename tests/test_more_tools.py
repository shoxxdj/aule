"""trufflehog, osv-scanner, trivy, checkov."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fakes
from aule.cli import main
from aule.config import parse_config
from aule.orchestrator import run_audit
from aule.plugins.trufflehog import TruffleHog
from aule.report import build_report_data
from common import AuditCase


class MoreToolsCase(AuditCase):
    """repo-git : Python + requirements (django vulnérable) + Dockerfile root + Terraform public ; webapp : lodash."""

    def setUp(self):
        super().setUp()
        repo = self.root / "repo-git"
        (repo / "requirements.txt").write_text("django==2.2.0\nrequests==2.31.0\n")
        (repo / "Dockerfile").write_text("FROM ubuntu:22.04\nUSER root\n")
        (repo / "main.tf").write_text('resource "aws_s3_bucket" "data" {\n  acl = "public-read"\n}\n')
        (self.root / "webapp").mkdir()
        (self.root / "webapp" / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.4"}}))
        (self.root / "webapp" / "app.js").write_text("console.log(1)\n")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "README.md").write_text("# docs\n")

    def go(self, tools, cfg=None, **kw) -> str:
        return self.run_audit(cfg, tool_names=list(tools), **kw)

    def ents(self, run_id, kind, project=None, tool=None):
        pid = {p["name"]: p["id"] for p in self.db.list_projects(run_id)}.get(project) if project else None
        return [e for e in self.db.entities(run_id, kind, pid) if tool is None or e["data"].get("tool") == tool]

    def rows(self, run_id, tool):
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        return {(names[r["project_id"]], r["mode"]): r for r in self.db.list_tool_runs(run_id) if r["tool"] == tool}


class TruffleHogTest(MoreToolsCase):
    def test_disabled_by_default(self):
        self.assertFalse([k for k in self.statuses(self.run_audit()) if k[1] == "trufflehog"])

    def test_modes_and_entities(self):
        run_id = self.go(["trufflehog"])
        st = {k: r["status"] for k, r in self.rows(run_id, "trufflehog").items()}
        self.assertEqual(st, {("repo-git", "dir"): "ok", ("repo-git", "git"): "ok", ("plain", "dir"): "ok",
                              ("plain", "git"): "skipped", ("webapp", "dir"): "ok", ("docs", "dir"): "ok", ("docs", "git"): "skipped", ("webapp", "git"): "skipped"})
        dir_hits = self.ents(run_id, "secret", "repo-git")
        by_mode = {m: sorted((e["data"]["rule_id"], e["data"]["file"]) for e in dir_hits if e["data"]["mode"] == m) for m in ("dir", "git")}
        self.assertEqual(by_mode["dir"], [("Github", "settings.py")])
        self.assertEqual(by_mode["git"], [("AWS", "config.py"), ("Github", "settings.py")])
        d = dir_hits[0]["data"]
        self.assertEqual((d["tool"], d["verified"], d["secret_masked"], d["start_line"]), ("trufflehog", False, "gh••••••R8", 1))
        self.assertIsNone(d["match_masked"])                                  # la chaîne « Redacted » de l'outil n'est jamais reprise
        git = next(e["data"] for e in dir_hits if e["data"]["mode"] == "git")
        self.assertEqual(git["commit"], self.commits[0])

    def test_verification_is_off_by_default_and_warned_when_on(self):
        self.go(["trufflehog"])
        self.assertIn("trufflehog:dir:verify=no", self.calls())
        self.assertNotIn("trufflehog:dir:verify=yes", self.calls())
        cfg = parse_config({"tools": {"trufflehog": {"options": {"verify": True}}}}, self.tmp)
        lines: list[str] = []
        run_audit(self.db, self.data, self.root, config=cfg, log=lines.append, tool_names=["trufflehog"])
        self.assertIn("trufflehog:dir:verify=yes", self.calls())
        self.assertTrue(any("vérification ACTIVE" in ln for ln in lines))
        lines2: list[str] = []
        run_audit(self.db, self.data, self.root, log=lines2.append, tool_names=["trufflehog"])
        self.assertFalse(any("vérification" in ln for ln in lines2))

    def test_same_secret_has_same_hash_across_tools_but_distinct_fingerprints(self):
        run_id = self.go(["gitleaks", "trufflehog"])
        secrets = [e for e in self.db.entities(run_id, "secret") if e["data"]["file"] == "settings.py" and e["data"]["mode"] == "dir"]
        self.assertEqual({e["data"]["tool"] for e in secrets}, {"gitleaks", "trufflehog"})
        self.assertEqual(len({e["data"]["secret_sha256"] for e in secrets}), 1)   # même secret : permet le regroupement
        self.assertEqual(len({e["fingerprint"] for e in secrets}), 2)             # triage indépendant par outil

    def test_gitleaks_entities_now_carry_their_tool(self):
        run_id = self.go(["gitleaks"])
        self.assertEqual({e["data"]["tool"] for e in self.db.entities(run_id, "secret")}, {"gitleaks"})

    def test_clear_values_are_paired_and_verified(self):
        run_id = self.go(["gitleaks", "trufflehog"])
        d = build_report_data(self.db, run_id, self.data, reveal=True)
        want = {"AWS": fakes.SECRET_A, "aws-access-token": fakes.SECRET_A, "Github": fakes.SECRET_B, "github-pat": fakes.SECRET_B}
        for s in d["secrets"]:
            self.assertEqual(s["secret"], want[s["rule_id"]], (s["tool"], s["mode"], s["file"]))
        tr = next(s for s in d["secrets"] if s["tool"] == "trufflehog")
        self.assertTrue(tr["raw_report"].endswith("trufflehog/dir/report.jsonl") or tr["raw_report"].endswith("trufflehog/git/report.jsonl"))
        raw = self.data / "runs" / run_id / "repo-git" / "trufflehog" / "dir" / "report.jsonl"
        raw.write_text(raw.read_text() + "\n")
        d = build_report_data(self.db, run_id, self.data, reveal=True)
        self.assertTrue(any("repo-git · trufflehog/dir" in w for w in d["warnings"]))
        self.assertFalse(any("secret" in s for s in d["secrets"] if s["tool"] == "trufflehog" and s["project"] == "repo-git" and s["mode"] == "dir"))

    def test_ndjson_noise_is_tolerated(self):
        f = Path(tempfile.mkdtemp()) / "r.jsonl"
        f.write_text('2025-01-01 INFO starting\n{"DetectorName": "AWS", "Raw": "AKIAXXXXXXXXXXXXXXXX"}\n\n{broken\n{"DetectorName": "Github", "Raw": "ghp_x"}\n')
        self.assertEqual([r["DetectorName"] for r in TruffleHog._results(f)], ["AWS", "Github"])
        self.assertEqual(TruffleHog().clear_values(f), {0: ("AKIAXXXXXXXXXXXXXXXX", ""), 1: ("ghp_x", "")})


class OsvTest(MoreToolsCase):
    def test_scoped_and_entities(self):
        run_id = self.go(["cloc", "osv-scanner"])
        rows = self.rows(run_id, "osv-scanner")
        self.assertEqual({k: r["status"] for k, r in rows.items()},
                         {("repo-git", "scan"): "ok", ("webapp", "scan"): "ok", ("plain", "scan"): "ok", ("docs", "scan"): "skipped"})
        self.assertIn("fichier de dépendances", rows[("docs", "scan")]["error"])
        self.assertEqual(self.ents(run_id, "vulnerability", "plain"), [])        # code 128 : rien à analyser, pas une erreur
        (v,) = self.ents(run_id, "vulnerability", "repo-git")
        d = v["data"]
        self.assertEqual((d["id"], d["tool"], d["severity"], d["cvss_score"]), ("CVE-2019-19844", "osv-scanner", "critical", 9.8))
        self.assertEqual((d["cwes"], d["fixed_version"], d["aliases"]), (["CWE-640"], "3.0.1", ["GHSA-h5jv-4p7w-64jg"]))
        self.assertEqual((d["dependency"]["purl"], d["dependency"]["file"]), ("pkg:pypi/django@2.2.0", "requirements.txt"))
        (dep,) = self.ents(run_id, "dependency", "repo-git")
        self.assertEqual((dep["data"]["name"], dep["data"]["vulnerability_count"]), ("django", 1))
        (w,) = self.ents(run_id, "vulnerability", "webapp")
        self.assertEqual((w["data"]["id"], w["data"]["severity"], w["data"]["dependency"]["purl"]), ("CVE-2018-16487", "high", "pkg:npm/lodash@4.17.4"))

    def test_privacy_notice_and_offline_option(self):
        lines: list[str] = []
        run_audit(self.db, self.data, self.root, log=lines.append, tool_names=["cloc", "osv-scanner"])
        self.assertTrue(any("api.osv.dev" in ln and "quittent la machine" in ln for ln in lines))
        self.assertIn("osv:offline=no", self.calls())
        cfg = parse_config({"tools": {"osv-scanner": {"options": {"offline": True}}}}, self.tmp)
        lines2: list[str] = []
        run_audit(self.db, self.data, self.root, config=cfg, log=lines2.append, tool_names=["cloc", "osv-scanner"])
        self.assertIn("osv:offline=yes", self.calls())
        self.assertFalse(any("api.osv.dev" in ln for ln in lines2))

    def test_command_option_for_older_versions(self):
        cfg = parse_config({"tools": {"osv-scanner": {"options": {"command": ["scan"]}}}}, self.tmp)
        run_id = self.go(["cloc", "osv-scanner"], cfg)
        raw = self.data / "runs" / run_id / "repo-git" / "osv-scanner" / "scan"
        self.assertIn("osv-scanner scan --format json", (raw / "cmd.txt").read_text())
        row = self.rows(run_id, "osv-scanner")[("repo-git", "scan")]
        self.assertEqual(row["status"], "failed")  # code 1 SANS rapport : une erreur, pas « aucune vulnérabilité »
        self.assertIn("aucun rapport", row["error"])
        self.assertEqual(self.ents(run_id, "vulnerability", "repo-git"), [])


class TrivyTest(MoreToolsCase):
    def test_vulnerabilities_and_iac_misconfigurations(self):
        run_id = self.go(["cloc", "trivy"])
        rows = self.rows(run_id, "trivy")
        self.assertEqual(rows[("repo-git", "fs")]["status"], "ok")
        self.assertEqual(rows[("docs", "fs")]["status"], "skipped")
        (v,) = self.ents(run_id, "vulnerability", "repo-git")
        d = v["data"]
        self.assertEqual((d["id"], d["tool"], d["severity"], d["cvss_score"], d["fixed_version"], d["cwes"]),
                         ("CVE-2019-19844", "trivy", "critical", 9.8, "3.0.1", ["CWE-640"]))   # max des V3Score
        self.assertEqual((d["dependency"]["purl"], d["dependency"]["file"]), ("pkg:pypi/django@2.2.0", "requirements.txt"))
        (m,) = self.ents(run_id, "sast_finding", "repo-git", tool="trivy")          # le contrôle PASS est ignoré
        md = m["data"]
        self.assertEqual((md["rule_id"], md["severity"], md["file"], md["start_line"], md["category"]),
                         ("AVD-DS-0002", "high", "Dockerfile", 2, "iac"))
        self.assertEqual(md["snippet"], "USER root")
        self.assertIn("non-root", md["message"])

    def test_options(self):
        cfg = parse_config({"tools": {"trivy": {"options": {"scanners": ["vuln"], "skip_db_update": True, "offline": True,
                                                          "cache_dir": str(self.tmp / "cache")}}}}, self.tmp)
        run_id = self.go(["cloc", "trivy"], cfg)
        self.assertEqual(self.ents(run_id, "sast_finding", "repo-git", tool="trivy"), [])  # misconfig non demandé
        cmd = (self.data / "runs" / run_id / "repo-git" / "trivy" / "fs" / "cmd.txt").read_text()
        for flag in ("--scanners vuln", "--skip-db-update", "--offline-scan", f"--cache-dir {self.tmp / 'cache'}"):
            self.assertIn(flag, cmd)
        self.assertIn("trivy:vuln:offline", self.calls())

    def test_runs_are_serialized(self):
        with mock.patch.dict(os.environ, {"FAKE_TRIVY_DELAY": "0.25"}):
            self.go(["cloc", "trivy"], jobs=4)
        ev = [c for c in self.calls() if c in ("trivy-start", "trivy-end")]
        self.assertGreaterEqual(ev.count("trivy-start"), 2)
        self.assertEqual(ev, ["trivy-start", "trivy-end"] * (len(ev) // 2))


class CheckovTest(MoreToolsCase):
    def test_gated_on_iac_files_with_reason(self):
        run_id = self.go(["cloc", "checkov"])
        rows = self.rows(run_id, "checkov")
        self.assertEqual(rows[("repo-git", "scan")]["status"], "ok")
        self.assertEqual(rows[("webapp", "scan")]["status"], "skipped")
        self.assertIn("infrastructure as code", rows[("webapp", "scan")]["error"])
        self.assertEqual(self.db.get_audit(run_id)["status"], "complete")      # code retour 1 (contrôles en échec) accepté

    def test_findings(self):
        run_id = self.go(["cloc", "checkov"], parse_config({"tools": {"checkov": {"options": {"default_severity": "high"}}}}, self.tmp))
        (f,) = self.ents(run_id, "sast_finding", "repo-git")
        d = f["data"]
        self.assertEqual((d["tool"], d["rule_id"], d["file"], d["start_line"], d["end_line"], d["severity"], d["category"]),
                         ("checkov", "CKV_AWS_20", "main.tf", 1, 4, "high", "iac"))
        self.assertEqual(d["tags"], ["terraform", "iac"])
        self.assertIn('acl = "public-read"', d["snippet"])
        self.assertTrue(d["help_uri"].startswith("https://docs.prismacloud.io"))
        self.assertIn("aws_s3_bucket.data", d["message"])

    def test_single_framework_dict_output_is_parsed_too(self):
        from aule.models import Project
        from aule.plugins.base import RunContext
        from aule.config import ToolConfig
        from aule.plugins.checkov import Checkov
        f = Path(tempfile.mkdtemp()) / "results_json.json"
        f.write_text(json.dumps({"check_type": "dockerfile", "results": {"failed_checks": [
            {"check_id": "CKV_DOCKER_3", "check_name": "no user", "file_path": "/Dockerfile", "file_line_range": [1, 2],
             "resource": "/Dockerfile.", "severity": "LOW", "code_block": [[1, "FROM x\n"]]}]}}))
        (e,) = Checkov().parse(Project("p", Path("/p"), False), "scan", f, RunContext(Path("."), "r", ToolConfig(), []))
        self.assertEqual((e.data["rule_id"], e.data["severity"], e.data["file"]), ("CKV_DOCKER_3", "low", "Dockerfile"))


class CrossToolTest(MoreToolsCase):
    def test_with_flag_and_phases(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["run", str(self.root), "--data", str(self.data), "--with", "trufflehog,osv-scanner,trivy,checkov"])
        self.assertEqual(code, 0)
        self.assertIn("outils : cloc, gitleaks, links, trufflehog, osv-scanner, trivy, checkov", buf.getvalue())
        calls = self.calls()
        first = lambda c: calls.index(c)  # noqa: E731
        self.assertLess(first("cloc"), first("checkov"))                     # checkov : phase 2 (après cloc)
        self.assertLess(first("checkov"), first("trivy-start"))              # trivy : phase 3

    def test_report_data_normalizes_tool_everywhere(self):
        run_id = self.go(["cloc", "gitleaks", "trufflehog", "osv-scanner", "trivy", "checkov"])
        d = build_report_data(self.db, run_id)
        self.assertEqual({v["tool"] for v in d["vulns"]}, {"osv-scanner", "trivy"})
        self.assertEqual({f["tool"] for f in d["sast"]}, {"trivy", "checkov"})
        self.assertEqual({s["tool"] for s in d["secrets"]}, {"gitleaks", "trufflehog"})
        self.assertTrue(all(v["raw_report"] for v in d["vulns"]))
        self.assertTrue(all((self.data / f["raw_report"]).exists() for f in d["sast"]))


if __name__ == "__main__":
    unittest.main()
