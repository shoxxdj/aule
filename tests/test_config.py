"""aule.yaml : chemins d'outils hors PATH, options, validation."""
from __future__ import annotations

import contextlib
import io
import os
import unittest
from pathlib import Path

import fakes
from aule.cli import main
from aule.config import Config, ConfigError, load_config, parse_config
from aule.plugins import load_plugins, select_tools
from common import AuditCase


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


class ConfigParsingTest(unittest.TestCase):
    def test_full_config_and_relative_paths(self):
        base = Path("/etc/audit")
        cfg = parse_config({
            "jobs": 2, "timeout": 60, "data_dir": "./d",
            "unpack": {"enabled": True, "max_depth": 2, "max_total_mb": 5, "extensions": [".ZIP"]},
            "tools": {"gitleaks": {"path": "bin/gl", "launcher": ["bash"], "extra_args": ["--x", 1],
                                   "env": {"A": 1}, "timeout": 9, "modes": ["dir"], "enabled": False,
                                   "options": {"k": "v"}},
                      "cloc": {"path": "cloc"}},
        }, base)
        self.assertEqual((cfg.jobs, cfg.timeout, cfg.data_dir), (2, 60, Path("/etc/audit/d")))
        self.assertTrue(cfg.unpack.enabled)
        self.assertEqual((cfg.unpack.max_depth, cfg.unpack.max_total_mb, cfg.unpack.extensions), (2, 5, (".zip",)))
        g = cfg.tool("gitleaks")
        self.assertEqual(g.path, "/etc/audit/bin/gl")        # relatif au fichier de config
        self.assertEqual((g.launcher, g.extra_args, g.env), (["bash"], ["--x", "1"], {"A": "1"}))
        self.assertEqual((g.timeout, g.modes, g.enabled, g.options), (9, ["dir"], False, {"k": "v"}))
        self.assertEqual(cfg.tool("cloc").path, "cloc")      # nom nu : cherché dans le PATH
        self.assertEqual(cfg.tool("unknown").path, None)

    def test_typos_are_errors(self):
        with self.assertRaisesRegex(ConfigError, "inconnue"):
            parse_config({"tool": {}}, Path("."))
        with self.assertRaisesRegex(ConfigError, "tools.cloc"):
            parse_config({"tools": {"cloc": {"pth": "x"}}}, Path("."))
        with self.assertRaisesRegex(ConfigError, "type attendu"):
            parse_config({"tools": {"cloc": {"extra_args": "--oops"}}}, Path("."))

    def test_unknown_tool_in_yaml_is_reported_at_selection(self):
        with self.assertRaisesRegex(ValueError, "inconnu"):
            select_tools(parse_config({"tools": {"clock": {"enabled": True}}}, Path(".")))

    def test_load_config_errors_and_default(self):
        with self.assertRaisesRegex(ConfigError, "introuvable"):
            load_config(Path("/nonexistent/aule.yaml"))
        self.assertIsNone(Config().source)


class ConfigBehaviourTest(AuditCase):
    def test_tool_outside_path_via_yaml(self):
        (self.bin / "gitleaks").unlink()
        fakes.install(self.tmp / "opt", gitleaks="gl-custom", cloc=None, extractor=None)
        cfg = parse_config({"tools": {"gitleaks": {"path": str(self.tmp / "opt" / "gl-custom")}}}, self.tmp)
        self.assertEqual(self.statuses(self.run_audit(cfg))[("repo-git", "gitleaks", "dir")], "ok")

    def test_wrong_path_gives_actionable_message(self):
        cfg = parse_config({"tools": {"gitleaks": {"path": str(self.tmp / "nope")}}}, self.tmp)
        run_id = self.run_audit(cfg)
        err = next(r["error"] for r in self.db.list_tool_runs(run_id) if r["tool"] == "gitleaks")
        self.assertIn("nope", err)

    def test_enabled_false_and_cli_override(self):
        cfg = parse_config({"tools": {"cloc": {"enabled": False}}}, self.tmp)
        self.assertEqual([t.name for t in select_tools(cfg)], ["gitleaks", "links"])
        self.assertEqual([t.name for t in select_tools(cfg, ["cloc"])], ["cloc"])  # --tools explicite gagne
        self.assertEqual([t.name for t in select_tools(parse_config({"tools": {"gittools": {"enabled": True}}}, self.tmp))],
                         ["cloc", "gitleaks", "gittools", "links"])

    def test_modes_extra_args_and_options_reach_the_command(self):
        cfg = parse_config({"tools": {
            "gitleaks": {"modes": ["dir"], "extra_args": ["--config", "x.toml"]},
            "cloc": {"options": {"exclude_dirs": ["vendor"]}}}}, self.tmp)
        run_id = self.run_audit(cfg)
        st = self.statuses(run_id)
        self.assertNotIn(("repo-git", "gitleaks", "git"), st)  # mode restreint
        raw = self.data / "runs" / run_id / "repo-git"
        self.assertIn("--config x.toml", (raw / "gitleaks" / "dir" / "cmd.txt").read_text())
        self.assertIn("--exclude-dir=vendor", (raw / "cloc" / "default" / "cmd.txt").read_text())

    def test_sh_script_without_exec_bit_gets_bash_launcher(self):
        script = self.tmp / "extractor.sh"
        script.write_text("#!/bin/bash\necho hi\n")
        script.chmod(0o644)
        cfg = parse_config({"tools": {"gittools": {"path": str(script)}}}, self.tmp)
        self.assertEqual(load_plugins()["gittools"].resolve(cfg.tool("gittools")), ["bash", str(script)])

    def test_cli_tools_lists_resolved_paths_and_missing_hints(self):
        yaml_path = write(self.tmp / "aule.yaml", "tools:\n  gitleaks:\n    path: ./does-not-exist\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["tools", "--config", str(yaml_path)])
        out = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("INTROUVABLE", out)
        self.assertIn("tools.gitleaks.path", out)
        self.assertIn("désactivé (option)", out)  # gittools

    def test_cli_rejects_bad_config(self):
        bad = write(self.tmp / "bad.yaml", "tolls: {}\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(main(["tools", "--config", str(bad)]), 2)
        self.assertIn("tolls", err.getvalue())


if __name__ == "__main__":
    unittest.main()
