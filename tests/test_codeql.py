"""CodeQL : un mode par langage, phase 4, base + analyse, chemins de données, options, mise à jour."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import fakes
from aule.cli import main
from aule.config import ToolConfig, parse_config
from aule.orchestrator import resolve_timeout, run_audit
from aule.plugins import load_plugins
from aule.report import build_report_data, render_report
from aule.sarif import parse_sarif
from common import AuditCase

HERE = Path(__file__).parent
SQLI = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'


class CodeqlCase(AuditCase):
    """repo-git (Python, SQLi), webapp (JS, XSS), legacy (Java), docs (Markdown seul), plain (Python propre)."""

    def setUp(self):
        super().setUp()
        (self.root / "repo-git" / "db.py").write_text("import sqlite3\n" + SQLI)
        (self.root / "webapp").mkdir()
        (self.root / "webapp" / "ui.js").write_text("el.innerHTML = input;\n")
        (self.root / "legacy").mkdir()
        (self.root / "legacy" / "Run.java").write_text("class Run { void f(String c) { Runtime.getRuntime().exec(c); } }\n")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "README.md").write_text("# docs\n")

    def cfg(self, **options) -> object:
        return parse_config({"tools": {"codeql": {"options": options}}}, self.tmp)

    def go(self, cfg=None, tools=("cloc", "codeql"), **kw) -> str:
        return self.run_audit(cfg or self.cfg(), tool_names=list(tools), **kw)

    def rows(self, run_id, project=None):
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        return [(names[r["project_id"]], r["mode"], r["status"], r["error"]) for r in self.db.list_tool_runs(run_id)
                if r["tool"] == "codeql" and (project is None or names[r["project_id"]] == project)]

    def findings(self, run_id, project):
        pid = {p["name"]: p["id"] for p in self.db.list_projects(run_id)}[project]
        return self.db.entities(run_id, "sast_finding", pid)

    def raw(self, run_id, project, lang) -> Path:
        return self.data / "runs" / run_id / project / "codeql" / lang


class SelectionTest(CodeqlCase):
    def test_disabled_by_default(self):
        self.assertFalse([k for k in self.statuses(self.run_audit()) if k[1] == "codeql"])

    def test_one_task_per_project_and_detected_language(self):
        run_id = self.go()
        ok = sorted((p, m) for p, m, st, _ in self.rows(run_id) if st == "ok")
        self.assertEqual(ok, [("legacy", "java-kotlin"), ("plain", "python"), ("repo-git", "python"),
                              ("webapp", "javascript-typescript")])
        # aucun bruit pour les 5 autres langages : pas de ligne « ignoré » par langage absent
        self.assertEqual(len(self.rows(run_id)), 5)

    def test_project_without_supported_language_gets_one_explained_row(self):
        (row,) = self.rows(self.go(), "docs")
        self.assertEqual(row[1:3], ("-", "skipped"))
        self.assertIn("Markdown", row[3])

    def test_without_cloc_one_explained_row_per_project_and_nothing_runs(self):
        run_id = self.go(tools=("codeql",))
        self.assertTrue(all(m == "-" and st == "skipped" and "cloc" in err for _, m, st, err in self.rows(run_id)))
        self.assertFalse([c for c in self.calls() if c.startswith("codeql-")])

    def test_modes_restriction_from_yaml(self):
        cfg = parse_config({"tools": {"codeql": {"modes": ["python"]}}}, self.tmp)
        run_id = self.go(cfg)
        self.assertEqual({m for _, m, st, _ in self.rows(run_id) if st == "ok"}, {"python"})
        self.assertEqual([m for p, m, *_ in self.rows(run_id) if p == "legacy"], ["-"])  # Java exclu par la config

    def test_language_map_and_min_lines(self):
        (self.root / "native").mkdir()
        (self.root / "native" / "tiny.c").write_text("int main(){return 0;}\n")
        self.assertIn(("native", "c-cpp"), {(p, m) for p, m, st, _ in self.rows(self.go()) if st == "ok"})
        run_id = self.go(self.cfg(min_code_lines=5))
        self.assertEqual({(p, st) for p, m, st, _ in self.rows(run_id) if m == "-"} >= {("native", "skipped")}, True)


class ExecutionTest(CodeqlCase):
    def test_build_modes_and_default_query_suites(self):
        self.go()
        calls = self.calls()
        self.assertIn("codeql-create:java-kotlin:none", calls)           # Java/Kotlin : sans build
        self.assertIn("codeql-create:python:default", calls)             # interprété : aucun flag de build
        self.assertIn("codeql-analyze:python:codeql/python-queries:codeql-suites/python-security-extended.qls", calls)
        self.assertIn("codeql-analyze:java-kotlin:codeql/java-queries:codeql-suites/java-security-extended.qls", calls)
        self.assertIn("codeql-analyze:javascript-typescript:codeql/javascript-queries:codeql-suites/javascript-security-extended.qls", calls)

    def test_findings_are_normalized_with_data_flow(self):
        run_id = self.go()
        (f,) = self.findings(run_id, "repo-git")
        d = f["data"]
        self.assertEqual((d["tool"], d["language"], d["rule_id"], d["file"], d["start_line"]),
                         ("CodeQL", "python", "py/sql-injection", "db.py", 2))
        self.assertEqual((d["severity"], d["security_severity"], d["cwe"]), ("high", 8.8, ["CWE-89"]))  # cwe-089 -> CWE-89
        self.assertIn("execute(", d["snippet"])
        self.assertEqual([(s["file"], s["line"], s["message"]) for s in d["flow"]],
                         [("db.py", 1, "user-provided value"), ("db.py", 2, "sink reached here")])
        (j,) = self.findings(run_id, "legacy")
        self.assertEqual((j["data"]["severity"], j["data"]["language"]), ("critical", "java-kotlin"))
        (w,) = self.findings(run_id, "webapp")
        self.assertEqual((w["data"]["severity"], w["data"]["cwe"]), ("medium", ["CWE-79"]))
        self.assertEqual(self.findings(run_id, "plain"), [])  # analysé, rien trouvé

    def test_fingerprint_survives_line_shift_and_triage_carries_over(self):
        r1 = self.go()
        fp = self.findings(r1, "repo-git")[0]["fingerprint"]
        self.db.set_triage(fp, "false_positive")
        (self.root / "repo-git" / "db.py").write_text("import sqlite3\n\n\n# moved\n" + SQLI)
        r2 = self.go()
        (f,) = self.findings(r2, "repo-git")
        self.assertEqual((f["fingerprint"], f["data"]["start_line"], f["triage_status"]), (fp, 5, "false_positive"))

    def test_raw_outputs_for_both_steps(self):
        run_id = self.go()
        raw = self.raw(run_id, "legacy", "java-kotlin")
        for name in ("cmd.txt", "analyze.cmd.txt", "analyze.stdout.txt", "analyze.stderr.txt", "report.sarif", "meta.json"):
            self.assertTrue((raw / name).exists(), name)
        create, analyze = (raw / "cmd.txt").read_text(), (raw / "analyze.cmd.txt").read_text()
        self.assertIn("database create", create)
        self.assertIn("--build-mode=none", create)
        self.assertIn("--language=java-kotlin", create)
        for flag in ("database analyze", "--format=sarif-latest", "--sarif-add-snippets", "--output="):
            self.assertIn(flag, analyze)
        meta = json.loads((raw / "meta.json").read_text())
        self.assertEqual((meta["status"], len(meta["report_sha256"])), ("ok", 64))
        self.assertEqual(json.loads((raw / "report.sarif").read_text())["runs"][0]["tool"]["driver"]["name"], "CodeQL")

    def test_database_is_removed_unless_kept(self):
        run_id = self.go()
        self.assertFalse((self.data / "work" / run_id / "codeql" / "repo-git" / "python").exists())
        run_id = self.go(self.cfg(keep_database=True))
        db = self.data / "work" / run_id / "codeql" / "repo-git" / "python"
        self.assertTrue((db / "codeql-database.yml").exists())
        self.assertEqual((self.raw(run_id, "repo-git", "python") / "database.txt").read_text().strip(), str(db))

    def test_reparse_from_raw_sarif(self):
        from aule.orchestrator import reparse
        run_id = self.go()
        before = sorted(e["fingerprint"] for e in self.db.entities(run_id, "sast_finding"))
        self.db.conn.execute("DELETE FROM entity"); self.db.conn.commit()
        reparse(self.db, self.data, run_id, log=lambda *_: None)
        self.assertEqual(sorted(e["fingerprint"] for e in self.db.entities(run_id, "sast_finding")), before)
        self.assertEqual({e["data"]["language"] for e in self.db.entities(run_id, "sast_finding")},
                         {"python", "javascript-typescript", "java-kotlin"})


class OptionsTest(CodeqlCase):
    def test_suite_pack_version_and_query_override(self):
        self.go(self.cfg(suite="security-and-quality", pack_versions={"python": "1.2.3"},
                         queries={"java-kotlin": "/my/queries/custom.qls"}))
        calls = self.calls()
        self.assertIn("codeql-analyze:python:codeql/python-queries@1.2.3:codeql-suites/python-security-and-quality.qls", calls)
        self.assertIn("codeql-analyze:java-kotlin:/my/queries/custom.qls", calls)
        self.assertIn("codeql-analyze:javascript-typescript:codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls", calls)

    def test_explicit_build_command_and_build_mode_override(self):
        (self.root / "native").mkdir()
        (self.root / "native" / "main.c").write_text("void f(char*s){char b[4]; strcpy(b, s);}\n")
        run_id = self.go(self.cfg(build_commands={"c-cpp": "make -j2"}, build_modes={"java-kotlin": "autobuild"}))
        self.assertIn("codeql-create:c-cpp:cmd", self.calls())
        self.assertIn("--command=make -j2", (self.raw(run_id, "native", "c-cpp") / "cmd.txt").read_text())
        self.assertIn("codeql-create:java-kotlin:default", self.calls())  # autobuild : pas de --build-mode
        self.assertEqual(self.findings(run_id, "native")[0]["data"]["rule_id"], "cpp/unbounded-write")

    def test_invalid_suite_is_rejected_before_any_expensive_step(self):
        run_id = self.go(self.cfg(suite="security-ultra"))
        rows = self.rows(run_id)
        self.assertTrue(rows and all(m == "-" and st == "unavailable" and "security-ultra" in err for _, m, st, err in rows))
        self.assertFalse([c for c in self.calls() if c.startswith("codeql-create")])
        self.assertEqual(self.statuses(run_id)[("repo-git", "cloc", "default")], "ok")

    def test_analyze_args_search_path_download_ram(self):
        run_id = self.go(self.cfg(analyze_args=["--rerun"], search_path="/opt/codeql-repo", download=True, ram=4096, threads=2))
        analyze = (self.raw(run_id, "repo-git", "python") / "analyze.cmd.txt").read_text()
        for expected in ("--rerun", "--search-path=/opt/codeql-repo", "--download", "--ram=4096", "--threads=2"):
            self.assertIn(expected, analyze)
        self.assertIn("--threads=2", (self.raw(run_id, "repo-git", "python") / "cmd.txt").read_text())

    def test_extra_args_apply_to_database_create_only(self):
        cfg = parse_config({"tools": {"codeql": {"extra_args": ["--no-run-unnecessary-builds"]}}}, self.tmp)
        run_id = self.go(cfg)
        self.assertIn("--no-run-unnecessary-builds", (self.raw(run_id, "repo-git", "python") / "cmd.txt").read_text())
        self.assertNotIn("--no-run-unnecessary-builds", (self.raw(run_id, "repo-git", "python") / "analyze.cmd.txt").read_text())

    def test_suite_is_traced_in_version(self):
        run_id = self.go()
        version = next(r["tool_version"] for r in self.db.list_tool_runs(run_id) if r["tool"] == "codeql" and r["status"] == "ok")
        self.assertEqual(version, "CodeQL command-line toolchain release 2.20.1. · suite security-extended")


class FailureTest(CodeqlCase):
    def test_create_failure_is_isolated_to_its_language(self):
        with mock.patch.dict(os.environ, {"FAKE_CODEQL_FAIL_CREATE": "python"}):
            run_id = self.go()
        st = {(p, m): s for p, m, s, _ in self.rows(run_id)}
        self.assertEqual((st[("repo-git", "python")], st[("webapp", "javascript-typescript")], st[("legacy", "java-kotlin")]),
                         ("failed", "ok", "ok"))
        err = next(e for p, m, s, e in self.rows(run_id) if p == "repo-git" and s == "failed")
        self.assertIn("Could not auto-detect a suitable build method", err)
        self.assertEqual(self.db.get_audit(run_id)["status"], "partial")

    def test_analyze_failure_keeps_database_and_explains(self):
        with mock.patch.dict(os.environ, {"FAKE_CODEQL_FAIL_ANALYZE": "python"}):
            run_id = self.go()
        err = next(e for p, m, s, e in self.rows(run_id) if p == "repo-git" and s == "failed")
        self.assertIn("post-traitement : codeql database analyze : code 2", err)
        self.assertIn("Could not resolve queries", err)
        db = self.data / "work" / run_id / "codeql" / "repo-git" / "python"
        self.assertIn(f"base conservée : {db}", err)
        self.assertTrue(db.exists())  # pour diagnostiquer
        self.assertIn("Could not resolve queries", (self.raw(run_id, "repo-git", "python") / "analyze.stderr.txt").read_text())

    def test_resume_reruns_only_the_failed_language(self):
        with mock.patch.dict(os.environ, {"FAKE_CODEQL_FAIL_CREATE": "python"}):
            run_id = self.go()
        js_before = self.calls().count("codeql-create:javascript-typescript:default")
        self.go(resume=run_id)
        self.assertEqual(self.calls().count("codeql-create:javascript-typescript:default"), js_before)
        self.assertEqual(len(self.findings(run_id, "repo-git")), 1)
        self.assertEqual(self.db.get_audit(run_id)["status"], "complete")

    def test_missing_binary_leaves_one_row_per_project_and_resume_cleans_it(self):
        (self.bin / "codeql").unlink()
        run_id = self.go()
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        rows = [r for r in self.db.list_tool_runs(run_id) if r["tool"] == "codeql"]
        self.assertEqual(sorted((names[r["project_id"]], r["mode"], r["status"]) for r in rows),
                         sorted((p, "-", "unavailable") for p in ("docs", "legacy", "plain", "repo-git", "webapp")))
        fakes.install(self.bin, cloc=None, gitleaks=None, extractor=None, opengrep=None, depcheck=None)
        self.go(resume=run_id)
        self.assertFalse([r for r in self.db.list_tool_runs(run_id) if r["tool"] == "codeql" and r["mode"] == "-" and r["status"] == "unavailable"])
        self.assertEqual(len(self.findings(run_id, "repo-git")), 1)
        self.assertEqual(self.db.get_audit(run_id)["status"], "complete")


class ResourcesAndPhaseTest(CodeqlCase):
    def events(self):
        return [c for c in self.calls() if c in ("codeql-start", "codeql-end")]

    def test_runs_are_serialized_by_default(self):
        with mock.patch.dict(os.environ, {"FAKE_CODEQL_DELAY": "0.25"}):
            self.go(jobs=4)
        ev = self.events()
        self.assertGreaterEqual(ev.count("codeql-start"), 4)
        self.assertEqual(ev, ["codeql-start", "codeql-end"] * (len(ev) // 2))

    def test_max_parallel_is_configurable(self):
        cfg = parse_config({"tools": {"codeql": {"max_parallel": 4}}}, self.tmp)
        with mock.patch.dict(os.environ, {"FAKE_CODEQL_DELAY": "0.3"}):
            self.go(cfg, jobs=4)
        ev = self.events()
        self.assertIn(["codeql-start", "codeql-start"], [ev[i:i + 2] for i in range(len(ev) - 1)])  # chevauchement
        self.assertEqual(ev.count("codeql-start"), ev.count("codeql-end"))

    def test_timeout_precedence(self):
        tool = load_plugins()["codeql"]
        self.assertEqual(tool.default_timeout, 7200)
        self.assertEqual(resolve_timeout(tool, ToolConfig(), None), 7200)                  # défaut de l'outil
        self.assertEqual(resolve_timeout(tool, ToolConfig(), 600), 600)                    # --timeout / YAML global
        self.assertEqual(resolve_timeout(tool, ToolConfig(timeout=99), 600), 99)           # YAML de l'outil
        self.assertEqual(resolve_timeout(load_plugins()["cloc"], ToolConfig(), None), 1800)

    def test_codeql_is_the_fourth_phase_after_all_other_tools(self):
        from test_sast_deps import make_rules
        (self.root / "repo-git" / "requirements.txt").write_text("django==2.2.0\n")
        cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(make_rules(self.tmp))}}}}, self.tmp)
        lines: list[str] = []
        run_audit(self.db, self.data, self.root, config=cfg, log=lines.append,
                  tool_names=["cloc", "gitleaks", "gittools", "opengrep", "dependency-check", "codeql"])
        phases = [ln.split(" :")[0] for ln in lines if ln.startswith("Phase ")]
        self.assertEqual(phases, ["Phase 1", "Phase 2", "Phase 3", "Phase 4"])   # numérotées à partir de 1
        calls = self.calls()
        first = lambda prefix: next(i for i, c in enumerate(calls) if c.startswith(prefix))  # noqa: E731
        self.assertLess(first("cloc"), first("opengrep:"))
        self.assertLess(first("opengrep:"), first("depcheck-start"))
        self.assertLess(first("depcheck-end"), first("codeql-start"))
        self.assertEqual(sum(1 for ln in lines if ln.startswith("Phase 4 :")), 1)


class UpdateTest(CodeqlCase):
    def run_update(self, *argv, **env):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["update", "codeql", "--data", str(self.data), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_downloads_default_language_packs(self):
        code, out, _ = self.run_update()
        self.assertEqual(code, 0)
        expected = ",".join(f"codeql/{p}-queries" for p in ("python", "javascript", "java", "csharp", "go", "cpp", "ruby"))
        # (ordre alphabétique des identifiants : c-cpp, csharp, go, java-kotlin, javascript-typescript, python, ruby)
        pack_call = next(c for c in self.calls() if c.startswith("codeql-packs:"))
        self.assertEqual(sorted(pack_call.removeprefix("codeql-packs:").split(",")), sorted(expected.split(",")))
        self.assertIn("Paquets de requêtes à jour", out)

    def test_follows_modes_and_pinned_versions(self):
        yaml_path = self.tmp / "aule.yaml"
        yaml_path.write_text("tools:\n  codeql:\n    modes: [python, java-kotlin]\n    options:\n      pack_versions: {python: '1.2.3'}\n")
        code, *_ = self.run_update("--config", str(yaml_path))
        self.assertEqual(code, 0)
        self.assertIn("codeql-packs:codeql/python-queries@1.2.3,codeql/java-queries", self.calls())

    def test_failure_is_reported(self):
        code, _, err = self.run_update(FAKE_CODEQL_FAIL_PACKS="1")
        self.assertEqual(code, 2)
        self.assertIn("unauthorized", err)

    def test_missing_binary_is_actionable(self):
        (self.bin / "codeql").unlink()
        code, _, err = self.run_update()
        self.assertEqual(code, 2)
        self.assertIn("tools.codeql.path", err)


class SarifFlowTest(unittest.TestCase):
    def test_code_flow_extraction(self):
        import tempfile
        loc = lambda uri, line, msg: {"location": {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}, "message": {"text": msg}}}  # noqa: E731
        doc = {"runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "r"}]}}, "results": [
            {"ruleId": "r", "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 9}}}],
             "codeFlows": [{"threadFlows": [{"locations": [loc("file:///p/src/a.py", 3, "source"), loc("b.py", 5, "step"), loc("a.py", 9, "sink")]}]},
                           {"threadFlows": [{"locations": [loc("x.py", 1, "other path")]}]}]},
            {"ruleId": "r", "message": {"text": "no flow"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "c.py"}, "region": {"startLine": 1}}}]}]}]}
        f = Path(tempfile.mkdtemp()) / "r.sarif"
        f.write_text(json.dumps(doc))
        a, b = parse_sarif(f, "p", Path("/p"))
        self.assertEqual([(s["file"], s["line"], s["message"]) for s in a.data["flow"]],
                         [("src/a.py", 3, "source"), ("b.py", 5, "step"), ("a.py", 9, "sink")])  # 1er chemin seulement
        self.assertEqual(b.data["flow"], [])


class ReportTest(CodeqlCase):
    def setUp(self):
        super().setUp()
        from test_sast_deps import make_rules
        (self.root / "repo-git" / "service.py").write_text("x = eval('1')\n")
        cfg = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(make_rules(self.tmp))}}}}, self.tmp)
        self.run_id = self.run_audit(cfg, tool_names=["cloc", "opengrep", "codeql"])

    def test_data_has_both_tools_and_raw_report_links(self):
        d = build_report_data(self.db, self.run_id)
        self.assertEqual({f["tool"] for f in d["sast"]}, {"Opengrep OSS", "CodeQL"})
        cq = next(f for f in d["sast"] if f["tool"] == "CodeQL" and f["project"] == "repo-git")
        self.assertTrue(cq["raw_report"].endswith("repo-git/codeql/python/report.sarif"))
        self.assertEqual(cq["language"], "python")
        og = next(f for f in d["sast"] if f["tool"] == "Opengrep OSS")
        self.assertTrue(og["raw_report"].endswith("/opengrep/scan/report.sarif"))
        self.assertTrue((self.data / cq["raw_report"]).exists())  # le lien pointe un vrai fichier

    @unittest.skipUnless(shutil.which("node"), "node requis")
    def test_sast_tab_shows_tool_filter_and_data_flow(self):
        page = self.tmp / "r.html"
        page.write_text(render_report(self.db, self.run_id, self.data), encoding="utf-8")
        proc = subprocess.run(["node", str(HERE / "dom_smoke.js"), str(page)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        sast = next(v for k, v in out["tabs"].items() if k.startswith("Code (SAST)"))
        for expected in ("py/sql-injection", "js/xss", "java/command-line-injection", "CodeQL", "Opengrep OSS"):
            self.assertIn(expected, sast)
        opened = next(v for k, v in out["tabsOpen"].items() if k.startswith("Code (SAST)"))
        for expected in ("Chemin de données", "user-provided value", "sink reached here", "codeql/python/report.sarif"):
            self.assertIn(expected, opened)

    def test_sast_count_in_summary_includes_codeql(self):
        d = build_report_data(self.db, self.run_id)
        self.assertGreaterEqual(len([f for f in d["sast"] if f["tool"] == "CodeQL"]), 3)


class MixedProjectTest(CodeqlCase):
    def test_polyglot_project_gets_one_run_per_language(self):
        (self.root / "repo-git" / "front.js").write_text("a.innerHTML = b;\n")
        run_id = self.go()
        modes = sorted(m for p, m, st, _ in self.rows(run_id, "repo-git") if st == "ok")
        self.assertEqual(modes, ["javascript-typescript", "python"])
        self.assertEqual({f["data"]["language"] for f in self.findings(run_id, "repo-git")}, {"python", "javascript-typescript"})
        self.assertTrue(self.raw(run_id, "repo-git", "python").is_dir() and self.raw(run_id, "repo-git", "javascript-typescript").is_dir())

    def test_with_flag_adds_codeql(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["run", str(self.root), "--data", str(self.data), "--with", "codeql"])
        self.assertEqual(code, 0)
        self.assertIn("outils : cloc, gitleaks, links, codeql", buf.getvalue())
        self.assertIn("Phase 4 :", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
