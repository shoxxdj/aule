"""opengrep (ciblage par technologie, règles) et OWASP dependency-check, SARIF générique, techmap."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import fakes
from aule.cli import main
from aule.config import load_config, parse_config
from aule.orchestrator import run_audit
from aule.plugins.depcheck import DependencyCheck
from aule.sarif import parse_sarif, relative_uri, severity_from
from aule.techmap import detect_ecosystems
from common import AuditCase, git

TOOLS = ["cloc", "opengrep", "dependency-check"]


def make_rules(root: Path) -> Path:
    """Faux clone d'opengrep-rules : un dossier par langage, repo git pour tracer la révision."""
    rules = root / "opengrep-rules"
    for d in ("python", "javascript", "java", "yaml", "generic"):
        (rules / d).mkdir(parents=True)
        (rules / d / "rule.yaml").write_text("rules: []\n")
    git("init", "-q", cwd=rules)
    git("add", ".", cwd=rules)
    git("commit", "-qm", "rules", cwd=rules)
    return rules


class SarifTest(unittest.TestCase):
    SARIF = {"runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [
        {"id": "py/sql-injection", "name": "SqlInjection", "shortDescription": {"text": "SQL injection"},
         "defaultConfiguration": {"level": "warning"},
         "properties": {"security-severity": "9.8", "tags": ["security", "external/cwe/cwe-089", "CWE-89", "OWASP-A03:2021 - Injection"], "precision": "high"}},
        {"id": "py/unused", "properties": {}}]}},
        "results": [
            {"ruleId": "py/sql-injection", "ruleIndex": 0, "message": {"text": "Query built from user input."},
             "partialFingerprints": {"primaryLocationLineHash": "abc123:1"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///work/proj/src/db.py"},
                                                 "region": {"startLine": 10, "endLine": 12, "snippet": {"text": "cursor.execute(q)"}}}}]},
            {"ruleId": "py/unused", "level": "note", "message": {"text": "Unused."},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "./lib/x.py"}, "region": {"startLine": 3}}}]}]}]}

    def test_codeql_like_document(self):
        import tempfile
        f = Path(tempfile.mkdtemp()) / "r.sarif"
        f.write_text(json.dumps(self.SARIF))
        a, b = parse_sarif(f, "proj", Path("/work/proj"))
        self.assertEqual((a.kind, a.data["severity"], a.data["security_severity"]), ("sast_finding", "critical", 9.8))  # score > level
        self.assertEqual(a.data["file"], "src/db.py")           # file:///abs -> relatif au projet
        self.assertEqual(a.data["cwe"], ["CWE-89"])
        self.assertEqual(a.data["owasp"], ["OWASP-A03:2021 - Injection"])
        self.assertEqual((a.data["start_line"], a.data["end_line"], a.data["snippet"]), (10, 12, "cursor.execute(q)"))
        self.assertEqual((b.data["severity"], b.data["file"], b.data["level"]), ("low", "lib/x.py", "note"))
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_fingerprint_ignores_line_numbers(self):
        import copy, tempfile
        moved = copy.deepcopy(self.SARIF)
        moved["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"]["startLine"] = 99
        d = Path(tempfile.mkdtemp())
        (d / "a.sarif").write_text(json.dumps(self.SARIF)); (d / "b.sarif").write_text(json.dumps(moved))
        fa = [e.fingerprint for e in parse_sarif(d / "a.sarif", "p", Path("/work/proj"))]
        fb = [e.fingerprint for e in parse_sarif(d / "b.sarif", "p", Path("/work/proj"))]
        self.assertEqual(fa, fb)

    def test_helpers(self):
        self.assertEqual([severity_from("error", None), severity_from("warning", None), severity_from("note", None),
                          severity_from(None, 7.0), severity_from("error", 3.9), severity_from("error", 0)],
                         ["high", "medium", "low", "high", "low", "info"])
        self.assertEqual(relative_uri("file:///a/b/c.py", Path("/a/b")), "c.py")
        self.assertEqual(relative_uri("src/x.py", Path("/a")), "src/x.py")
        self.assertEqual(relative_uri("/elsewhere/y.py", Path("/a")), "/elsewhere/y.py")

    def test_empty_or_missing_report(self):
        self.assertEqual(parse_sarif(Path("/nonexistent.sarif"), "p", Path("/x")), [])


class TechmapTest(AuditCase):
    def test_languages_and_manifests_and_binaries(self):
        d = self.tmp / "p"
        (d / "node_modules" / "x").mkdir(parents=True)
        (d / "node_modules" / "x" / "package.json").write_text("{}")  # ignoré
        (d / "lib").mkdir()
        (d / "lib" / "Foo.JAR").write_bytes(b"PK")
        self.assertEqual(detect_ecosystems(None, d), {"java"})                 # .jar : invisible pour cloc
        self.assertEqual(detect_ecosystems({"Python": 10, "Markdown": 5}, d), {"python", "java"})
        self.assertEqual(detect_ecosystems({}, self.tmp / "empty-nonexistent"), set())


class OpengrepTest(AuditCase):
    def setUp(self):
        super().setUp()
        (self.root / "repo-git" / "service.py").write_text("x = eval('1+1')\n")
        (self.root / "webapp").mkdir()
        (self.root / "webapp" / "app.js").write_text("const y = eval(input);\n")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "README.md").write_text("# docs\n\ntext\n")
        self.rules = make_rules(self.tmp)
        self.cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(self.rules)}}}}, self.tmp)

    def findings(self, run_id, project):
        pid = {p["name"]: p["id"] for p in self.db.list_projects(run_id)}[project]
        return self.db.entities(run_id, "sast_finding", pid)

    def test_disabled_by_default(self):
        st = self.statuses(self.run_audit())
        self.assertFalse([k for k in st if k[1] == "opengrep"])

    def test_rule_dirs_follow_detected_technologies(self):
        run_id = self.run_audit(self.cfg, tool_names=["cloc", "opengrep"])
        st = self.statuses(run_id)
        self.assertEqual([st[(p, "opengrep", "scan")] for p in ("repo-git", "plain", "webapp")], ["ok"] * 3)
        self.assertEqual(st[("docs", "opengrep", "scan")], "skipped")
        reason = next(r["error"] for r in self.db.list_tool_runs(run_id) if r["tool"] == "opengrep" and r["status"] == "skipped")
        self.assertIn("Markdown", reason)
        calls = [c for c in self.calls() if c.startswith("opengrep:")]
        self.assertEqual(sorted(calls), ["opengrep:javascript", "opengrep:python", "opengrep:python"])  # pas de java/yaml/generic
        self.assertEqual(sorted(c for c in self.calls() if c.startswith("opengrep-cwd:")),
                         ["opengrep-cwd:plain", "opengrep-cwd:repo-git", "opengrep-cwd:webapp"])  # cwd = projet

    def test_findings_normalized(self):
        run_id = self.run_audit(self.cfg, tool_names=["cloc", "opengrep"])
        (f,) = self.findings(run_id, "repo-git")
        d = f["data"]
        self.assertEqual((d["file"], d["start_line"], d["severity"]), ("service.py", 1, "high"))
        self.assertEqual(d["rule_id"], "python.lang.security.audit.eval-detected")
        self.assertEqual(d["cwe"], ["CWE-95"])
        self.assertEqual(d["owasp"], ["OWASP-A03:2021 - Injection"])
        self.assertIn("eval(", d["snippet"])
        self.assertEqual(d["confidence"], "high")
        (w,) = self.findings(run_id, "webapp")
        self.assertEqual(w["data"]["file"], "app.js")

    def test_fingerprints_stable_and_triage_carries_over(self):
        r1 = self.run_audit(self.cfg, tool_names=["cloc", "opengrep"])
        fp = self.findings(r1, "repo-git")[0]["fingerprint"]
        self.db.set_triage(fp, "false_positive")
        (service := self.root / "repo-git" / "service.py").write_text("\n\n# shifted\nx = eval('1+1')\n")
        r2 = self.run_audit(self.cfg, tool_names=["cloc", "opengrep"])
        (f2,) = self.findings(r2, "repo-git")
        self.assertEqual((f2["fingerprint"], f2["data"]["start_line"], f2["triage_status"]), (fp, 4, "false_positive"))

    def test_rules_revision_is_traced(self):
        run_id = self.run_audit(self.cfg, tool_names=["cloc", "opengrep"])
        version = next(r["tool_version"] for r in self.db.list_tool_runs(run_id) if r["tool"] == "opengrep" and r["status"] == "ok")
        head = git("rev-parse", "--short=8", "HEAD", cwd=self.rules)
        self.assertEqual(version, f"1.8.0 · règles opengrep-rules@{head}")

    def test_missing_rules_gives_actionable_error(self):
        cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(self.tmp / "nope")}}}}, self.tmp)
        run_id = self.run_audit(cfg, tool_names=["cloc", "opengrep"])
        errs = {r["error"] for r in self.db.list_tool_runs(run_id) if r["tool"] == "opengrep"}
        self.assertEqual(len(errs), 1)
        self.assertIn("aule update opengrep", errs.pop())
        self.assertEqual(self.statuses(run_id)[("repo-git", "cloc", "default")], "ok")  # le reste continue

    def test_without_cloc_all_rule_dirs_are_used(self):
        self.run_audit(self.cfg, tool_names=["opengrep"])
        self.assertTrue(all(c == "opengrep:generic,java,javascript,python,yaml" for c in self.calls() if c.startswith("opengrep:")))

    def test_explicit_rule_dirs_and_always_include(self):
        cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(self.rules), "rule_dirs": ["python", "nonexistent"]}}}}, self.tmp)
        self.run_audit(cfg, tool_names=["cloc", "opengrep"])
        self.assertTrue(all(c == "opengrep:python" for c in self.calls() if c.startswith("opengrep:")))
        cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(self.rules), "always_include": ["generic"]}}}}, self.tmp)
        self.log.unlink()
        self.run_audit(cfg, tool_names=["cloc", "opengrep"])
        self.assertIn("opengrep:generic,javascript", self.calls())
        # `docs` (Markdown seul) est désormais analysé grâce à always_include
        self.assertIn("opengrep:generic", self.calls())

    def test_failure_is_recorded(self):
        with mock.patch.dict(os.environ, {"FAKE_OPENGREP_FAIL": "1"}):
            run_id = self.run_audit(self.cfg, tool_names=["cloc", "opengrep"])
        self.assertEqual(self.statuses(run_id)[("repo-git", "opengrep", "scan")], "failed")
        self.assertIn("invalid rule", next(r["error"] for r in self.db.list_tool_runs(run_id) if r["status"] == "failed"))

    def test_update_clones_then_pulls(self):
        remote = self.tmp / "remote-rules"
        (remote / "python").mkdir(parents=True)
        (remote / "python" / "r.yaml").write_text("rules: []\n")
        git("init", "-q", cwd=remote); git("add", ".", cwd=remote); git("commit", "-qm", "v1", cwd=remote)
        yaml_path = self.tmp / "aule.yaml"
        yaml_path.write_text(f"tools:\n  opengrep:\n    options:\n      rules_repo: {remote.as_uri()}\n")
        argv = ["update", "opengrep", "--config", str(yaml_path), "--data", str(self.data)]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(argv), 0)
        clone = self.data / "rules" / "opengrep-rules"
        self.assertTrue((clone / "python" / "r.yaml").exists())
        (remote / "javascript").mkdir()
        (remote / "javascript" / "r.yaml").write_text("rules: []\n")
        git("add", ".", cwd=remote); git("commit", "-qm", "v2", cwd=remote)
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(argv), 0)
        self.assertTrue((clone / "javascript" / "r.yaml").exists())
        self.assertIn("Règles à jour", buf.getvalue())

    def test_update_refuses_to_overwrite_a_non_git_directory(self):
        target = self.data / "rules" / "opengrep-rules"
        target.mkdir(parents=True)
        (target / "precious.txt").write_text("mine")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["update", "opengrep", "--data", str(self.data)])
        self.assertEqual(code, 2)
        self.assertIn("pas un clone git", err.getvalue())
        self.assertTrue((target / "precious.txt").exists())


class DependencyCheckTest(AuditCase):
    def setUp(self):
        super().setUp()
        (self.root / "repo-git" / "requirements.txt").write_text("django==2.2.0\npyyaml==5.3\nrequests==2.31.0\n")
        (self.root / "webapp").mkdir()
        (self.root / "webapp" / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.4"}}))
        (self.root / "webapp" / "app.js").write_text("x\n")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "README.md").write_text("# docs\n")

    def ents(self, run_id, kind, project):
        pid = {p["name"]: p["id"] for p in self.db.list_projects(run_id)}[project]
        return self.db.entities(run_id, kind, pid)

    def test_disabled_by_default(self):
        self.assertFalse([k for k in self.statuses(self.run_audit()) if k[1] == "dependency-check"])

    def test_scoped_by_ecosystem_with_reasons(self):
        run_id = self.run_audit(tool_names=TOOLS[:1] + ["dependency-check"])
        st = self.statuses(run_id)
        self.assertEqual(st[("repo-git", "dependency-check", "scan")], "ok")
        self.assertEqual(st[("webapp", "dependency-check", "scan")], "ok")
        self.assertEqual(st[("docs", "dependency-check", "scan")], "skipped")
        reason = next(r["error"] for r in self.db.list_tool_runs(run_id) if r["status"] == "skipped" and r["tool"] == "dependency-check")
        self.assertIn("Markdown", reason)

    def test_entities(self):
        run_id = self.run_audit(tool_names=["cloc", "dependency-check"])
        deps = {d["data"]["name"]: d["data"] for d in self.ents(run_id, "dependency", "repo-git")}
        self.assertEqual(set(deps), {"django", "pyyaml", "requests"})
        self.assertEqual((deps["django"]["version"], deps["django"]["type"], deps["django"]["file"]), ("2.2.0", "pypi", "requirements.txt"))
        self.assertEqual((deps["django"]["vulnerability_count"], deps["requests"]["vulnerability_count"]), (1, 0))
        vulns = {v["data"]["id"]: v["data"] for v in self.ents(run_id, "vulnerability", "repo-git")}
        self.assertEqual(set(vulns), {"CVE-2019-19844", "CVE-2020-14343"})
        v = vulns["CVE-2019-19844"]
        self.assertEqual((v["severity"], v["cvss_score"], v["cwes"], v["dependency"]["name"]),
                         ("critical", 9.8, ["CWE-640"], "django"))
        (lodash,) = self.ents(run_id, "vulnerability", "webapp")
        self.assertEqual((lodash["data"]["severity"], lodash["data"]["dependency"]["purl"]), ("high", "pkg:npm/lodash@4.17.4"))

    def test_api_key_is_redacted_everywhere_but_passed_to_the_tool(self):
        key = "SUPER-SECRET-NVD-KEY-123"
        cfg = parse_config({"tools": {"dependency-check": {"options": {"nvd_api_key": key}}}}, self.tmp)           # la clé est dans la configuration
        run_id = self.run_audit(cfg, tool_names=["cloc", "dependency-check"])
        self.assertIn("depcheck-key:yes", self.calls())  # l'outil l'a bien reçue
        raw = self.data / "runs" / run_id / "repo-git" / "dependency-check" / "scan"
        for name in ("cmd.txt", "meta.json", "stdout.txt", "stderr.txt"):
            self.assertNotIn(key, (raw / name).read_text(), name)
        self.assertIn("--nvdApiKey ***", (raw / "cmd.txt").read_text())
        self.assertNotIn(key, "\n".join(self.db.conn.iterdump()))
        for path in self.data.rglob("*"):                                                                       # ... et nulle part dans les données conservées
            if path.is_file() and path.stat().st_size < 5_000_000:
                self.assertNotIn(key.encode(), path.read_bytes(), str(path))

    def test_options_noupdate_formats_and_data_path(self):
        cfg = parse_config({"tools": {"dependency-check": {"options": {
            "update": False, "formats": ["HTML"], "data_path": str(self.tmp / "nvd")}}}}, self.tmp)
        run_id = self.run_audit(cfg, tool_names=["cloc", "dependency-check"])
        self.assertIn("depcheck-noupdate:yes", self.calls())
        raw = self.data / "runs" / run_id / "repo-git" / "dependency-check" / "scan"
        self.assertTrue((raw / "dependency-check-report.html").exists())  # HTML conservé en sortie brute
        self.assertIn(str(self.tmp / "nvd"), (raw / "cmd.txt").read_text())
        self.assertTrue((self.tmp / "nvd").is_dir())

    def test_runs_are_serialized(self):
        (self.root / "plain" / "requirements.txt").write_text("django==2.2.0\n")
        with mock.patch.dict(os.environ, {"FAKE_DEPCHECK_DELAY": "0.25"}):
            self.run_audit(tool_names=["cloc", "dependency-check"], jobs=4)
        events = [c for c in self.calls() if c in ("depcheck-start", "depcheck-end")]
        self.assertGreaterEqual(events.count("depcheck-start"), 3)
        self.assertEqual(events, ["depcheck-start", "depcheck-end"] * (len(events) // 2))  # jamais deux en même temps

    def test_update_command_uses_key_without_printing_it(self):
        key = "ANOTHER-KEY-456"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["update", "dependency-check", "--data", str(self.data), "--config", str(self.config_file(f"nvd_api_key: {key}"))])
        self.assertEqual(code, 0)
        self.assertIn("depcheck-update:key=yes", self.calls())
        self.assertNotIn(key, buf.getvalue())
        self.assertTrue((self.data / "depcheck-db").is_dir())

    def config_file(self, option_lines: str = "", mode: int = 0o600) -> Path:
        """Un aule.yaml réel (la clé NVD y est une option de l'outil), avec les droits voulus."""
        path = self.tmp / "aule.yaml"
        path.write_text("tools:\n  dependency-check:\n    options:\n" + "".join(f"      {line}\n" for line in option_lines.splitlines()) if option_lines else "tools: {}\n")
        path.chmod(mode)
        return path

    def test_the_environment_is_never_consulted(self):
        with mock.patch.dict(os.environ, {"NVD_API_KEY": "ENV-KEY-NE-DOIT-PAS-SERVIR", "NVD_KEY": "ENV-KEY-2"}):
            self.run_audit(tool_names=["cloc", "dependency-check"])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                main(["update", "dependency-check", "--data", str(self.data)])
        self.assertIn("depcheck-key:no", self.calls())                                                          # la variable de l'ancienne version n'est plus lue
        self.assertIn("depcheck-update:key=no", self.calls())
        self.assertIn("`nvd_api_key` dans aule.yaml", buf.getvalue())                                           # et le message dit où la mettre

    def test_the_old_env_option_is_refused_with_the_way_out(self):
        cfg = parse_config({"tools": {"dependency-check": {"options": {"nvd_api_key_env": "MA_VAR"}}}}, self.tmp)
        lines: list[str] = []
        run_id = run_audit(self.db, self.data, self.root, config=cfg, tool_names=["cloc", "dependency-check"], log=lines.append)
        self.assertTrue(any("nvd_api_key_env n'existe plus" in ln and "`nvd_api_key`" in ln for ln in lines), lines)
        self.assertNotIn("depcheck-key:yes", self.calls())                                                      # rien n'a été lancé avec une configuration ambiguë
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(io.StringIO()):
            code = main(["update", "dependency-check", "--data", str(self.data), "--config", str(self.config_file("nvd_api_key_env: MA_VAR"))])
        self.assertEqual(code, 2)
        self.assertIn("nvd_api_key_env n'existe plus", buf.getvalue())

    def test_an_invalid_key_is_refused_without_being_echoed(self):
        for bad in ("avec espace", 123456789, ["liste"], "ligne1\nligne2", ""):
            cfg = parse_config({"tools": {"dependency-check": {"options": {"nvd_api_key": bad}}}}, self.tmp)
            problem = DependencyCheck.check_options(cfg.tool("dependency-check"))
            if bad == "":
                self.assertIsNone(problem)                                                                      # vide : comme absent (pas de clé)
                continue
            self.assertIn("nvd_api_key", problem, bad)
            for leak in ("avec espace", "123456789", "ligne2"):
                self.assertNotIn(leak, problem)

    def test_a_loose_config_file_is_flagged_only_when_it_holds_a_key(self):
        def warnings(**kw):
            path = self.config_file(**kw)
            lines: list[str] = []
            run_audit(self.db, self.data, self.root, config=load_config(path), tool_names=["cloc", "dependency-check"], log=lines.append)
            return [ln for ln in lines if "lisible par d'autres utilisateurs" in ln]
        self.assertEqual(len(warnings(option_lines="nvd_api_key: CLE-0123456789", mode=0o644)), 1)
        self.assertIn("chmod 600", warnings(option_lines="nvd_api_key: CLE-0123456789", mode=0o644)[0])
        self.assertEqual(warnings(option_lines="nvd_api_key: CLE-0123456789", mode=0o600), [])                  # droits stricts : rien à dire
        self.assertEqual(warnings(option_lines="update: true", mode=0o644), [])                                 # un fichier ouvert SANS clé n'est pas un problème
        self.assertEqual(warnings(mode=0o644), [])
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
            main(["update", "dependency-check", "--data", str(self.data), "--config", str(self.config_file("nvd_api_key: CLE-0123456789", mode=0o644))])
        self.assertIn("chmod 600", buf.getvalue())                                                              # `aule update` avertit aussi
        self.assertNotIn("CLE-0123456789", buf.getvalue())


class PhaseOrderTest(AuditCase):
    def test_cloc_then_opengrep_then_dependency_check(self):
        (self.root / "repo-git" / "requirements.txt").write_text("django==2.2.0\n")
        rules = make_rules(self.tmp)
        cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(rules)}}}}, self.tmp)
        self.run_audit(cfg, tool_names=TOOLS)
        calls = self.calls()
        first = lambda prefix: next(i for i, c in enumerate(calls) if c.startswith(prefix))  # noqa: E731
        self.assertLess(first("cloc"), first("opengrep:"))
        self.assertLess(first("opengrep:"), first("depcheck-start"))

    def test_with_flag_adds_optional_tools_to_defaults(self):
        rules = make_rules(self.tmp)
        yaml_path = self.tmp / "aule.yaml"
        yaml_path.write_text(f"tools:\n  opengrep:\n    options:\n      rules_path: {rules}\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["run", str(self.root), "--config", str(yaml_path), "--data", str(self.data), "--with", "opengrep"])
        self.assertEqual(code, 0)
        self.assertIn("outils : cloc, gitleaks, links, opengrep", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
