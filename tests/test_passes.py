"""`default_pass` générique : n'importe quel outil qui accepte `rules` peut tourner d'abord avec sa configuration par défaut SEULE, puis avec la vôtre, dans la même exécution.
Preuve avec un FAUX OUTIL qui ne connaît rien aux passes : seul son `build_command` regarde `ctx.cfg.rules` (c'est ce que fera tout futur outil)."""
from __future__ import annotations

import json
import os
import stat
import unittest
from pathlib import Path
from unittest import mock

from aule.config import ConfigError, ToolConfig, parse_config
from aule.models import ParsedEntity, sha256_text
from aule.orchestrator import reparse, run_audit
from aule.plugins.base import _REGISTRY, Tool
from aule.correlate import compute_clusters
from aule.report import build_report_data, load_clear_secrets, reveal_one
from aule.runner import clear_values_of, parse_task, pass_reports, raw_ref, report_digest
from common import AuditCase

TOY_SCRIPT = '''#!/usr/bin/env python3
import json, os, sys, time
a = sys.argv[1:]
time.sleep(float(os.environ.get("TOY_SLEEP", "0")))
log = os.environ.get("TOY_LOG")
if log:
    open(log, "a").write(json.dumps(a) + "\\n")
rules = [a[i + 1] for i, x in enumerate(a) if x == "--rules"]
if os.environ.get("TOY_FAIL_DEFAULT") and not rules:
    sys.stderr.write("toy: configuration par défaut cassée\\n")
    sys.exit(4)
if os.environ.get("TOY_FAIL_RULES") and rules:
    sys.stderr.write("toy: règles refusées\\n")
    sys.exit(3)
out = os.path.join(a[a.index("--outdir") + 1], "results.jsonl") if "--outdir" in a else a[a.index("--out") + 1]
findings = [{"id": "D1", "file": "a.txt", "line": 1, "secret": "S-DEFAULT"}, {"id": "D2", "file": "b.txt", "line": 2, "secret": "S-SHARED"}]
for r in rules:  # un outil ADDITIF : la configuration par défaut + vos règles
    findings.append({"id": "R-" + os.path.basename(r), "file": "c.txt", "line": 3, "secret": "S-" + os.path.basename(r).upper()})
open(out, "w").write("".join(json.dumps(f) + "\\n" for f in findings))
'''


class ToyTool(Tool):
    """Tout ce qu'un nouvel outil a à écrire : rien sur les passes."""

    name = "toy"
    binary = "toy-scan"
    modes = ("dir",)
    default_enabled = False
    version_args = None
    report_filename = "toy.jsonl"
    secrets_source = True
    supports_rules = True

    def build_command(self, project, mode, report_path, ctx):
        return [*ctx.exe, "--src", str(project.path), "--out", str(report_path), *[a for r in ctx.cfg.rules for a in ("--rules", r)]]

    def parse(self, project, mode, report_path, ctx):
        out = []
        for i, line in enumerate(report_path.read_text().splitlines()):
            f = json.loads(line)
            out.append(ParsedEntity("secret", f"{f['id']}:{f['file']}", {"tool": self.name, "mode": mode, "rule_id": f["id"], "file": f["file"], "start_line": f["line"],
                                                                        "raw_index": i, "secret_sha256": sha256_text(f["secret"]), "secret_masked": "***"}))
        return out

    def clear_values(self, report_path):
        return {i: (json.loads(line)["secret"], "") for i, line in enumerate(report_path.read_text().splitlines())}


class ToyFileTool(ToyTool):
    """Comme checkov : le NOM du rapport est imposé par l'outil dans le dossier de sortie (`--outdir`)."""

    name = "toyfile"
    binary = "toy-scan"
    report_filename = "results.jsonl"

    def build_command(self, project, mode, report_path, ctx):
        return [*ctx.exe, "--outdir", str(report_path.parent), *[a for r in ctx.cfg.rules for a in ("--rules", r)]]


class ToyNoRules(ToyTool):
    name = "toynorules"
    supports_rules = False


class PassesCase(AuditCase):
    def setUp(self):
        super().setUp()
        script = self.bin / "toy-scan"
        script.write_text(TOY_SCRIPT)
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        for tool in (ToyTool, ToyFileTool, ToyNoRules):
            _REGISTRY[tool.name] = tool()
            self.addCleanup(_REGISTRY.pop, tool.name, None)                                                     # le faux outil ne pollue pas les autres tests
        self.toy_log = self.tmp / "toy.log"
        env = mock.patch.dict(os.environ, {"TOY_LOG": str(self.toy_log)})
        env.start()
        self.addCleanup(env.stop)
        self.rules_a, self.rules_b = self.tmp / "A", self.tmp / "B"
        self.rules_a.mkdir()
        self.rules_b.mkdir()

    def cfg(self, tool: str = "toy", **keys):
        return parse_config({"tools": {tool: {"enabled": True, **keys}}}, self.tmp)

    def audit(self, config, tool: str = "toy") -> str:
        lines: list[str] = []
        run_id = run_audit(self.db, self.data, self.root, config=config, tool_names=[tool], log=lines.append)
        self.lines = lines
        self.run_id = run_id
        return run_id

    def raw(self, tool: str = "toy", project: str = "plain") -> Path:
        return self.data / "runs" / self.run_id / project / tool / "dir"

    def entities(self, project: str = "plain") -> dict[str, dict]:
        pid = {p["name"]: p["id"] for p in self.db.list_projects(self.run_id)}[project]
        return {e["data"]["rule_id"]: e["data"] for e in self.db.entities(self.run_id, "secret", pid)}

    def invocations(self) -> list[list[str]]:
        return [json.loads(line) for line in self.toy_log.read_text().splitlines()] if self.toy_log.exists() else []


class SinglePassTest(PassesCase):
    def test_without_default_pass_nothing_changes(self):
        self.audit(self.cfg(rules=[str(self.rules_a)]))
        data = self.entities()
        self.assertEqual(sorted(data), ["D1", "D2", "R-A"])
        self.assertFalse(any("config_pass" in d or "report" in d for d in data.values()))                       # pas d'étiquette, pas de rapport annexe
        self.assertNotIn("passes", json.loads((self.raw() / "meta.json").read_text()))
        self.assertEqual([p.name for p in self.raw().iterdir() if p.is_dir()], [])                              # aucun sous-dossier de passe
        self.assertEqual(len([a for a in self.invocations() if "--src" in a and str(self.root / "plain") in a]), 1)


class TwoPassTest(PassesCase):
    def setUp(self):
        super().setUp()
        self.audit(self.cfg(rules=[str(self.rules_a), str(self.rules_b)], default_pass=True))

    def test_the_tool_runs_twice_first_with_its_default_configuration_alone(self):
        calls = [a for a in self.invocations() if str(self.root / "plain") in a]
        self.assertEqual(len(calls), 2)
        self.assertNotIn("--rules", calls[0])                                                                   # passe 1 : la configuration par défaut SEULE
        self.assertEqual([calls[1][i + 1] for i, x in enumerate(calls[1]) if x == "--rules"], [str(self.rules_a), str(self.rules_b)])   # passe 2 : toutes vos règles
        self.assertEqual([json.loads(l)["id"] for l in (self.raw() / "toy.jsonl").read_text().splitlines()], ["D1", "D2"])
        self.assertEqual([json.loads(l)["id"] for l in (self.raw() / "rules" / "toy.jsonl").read_text().splitlines()], ["D1", "D2", "R-A", "R-B"])

    def test_findings_are_merged_once_and_tagged(self):
        data = self.entities()
        self.assertEqual(sorted(data), ["D1", "D2", "R-A", "R-B"])                                              # chaque constat UNE fois
        self.assertEqual({k: v["config_pass"] for k, v in data.items()}, {"D1": "default+rules", "D2": "default+rules", "R-A": "rules", "R-B": "rules"})
        self.assertNotIn("report", data["D1"])                                                                  # trouvé par la passe 1 : se relit dans le rapport principal
        self.assertEqual(data["R-A"]["report"], "rules/toy.jsonl")                                              # seulement par la passe 2 : dit où se relire

    def test_each_pass_keeps_its_own_raw_outputs(self):
        for name in ("cmd.txt", "stdout.txt", "stderr.txt", "toy.jsonl"):
            self.assertTrue((self.raw() / name).is_file(), name)
            self.assertTrue((self.raw() / "rules" / name).is_file(), f"rules/{name}")
        self.assertNotIn("--rules", (self.raw() / "cmd.txt").read_text())
        self.assertIn("--rules", (self.raw() / "rules" / "cmd.txt").read_text())                                 # de quoi rejouer chaque passe à la main

    def test_meta_lists_the_passes(self):
        meta = json.loads((self.raw() / "meta.json").read_text())
        self.assertEqual([(p["name"], p["report"], p["status"]) for p in meta["passes"]], [("default", "toy.jsonl", "ok"), ("rules", "rules/toy.jsonl", "ok")])
        self.assertNotIn("--rules", meta["command"])                                                            # `command` : celle de la passe 1
        row = next(r for r in self.db.list_tool_runs(self.run_id) if r["tool"] == "toy" and r["raw_dir"].endswith("plain/toy/dir"))
        self.assertNotIn("--rules", row["command"])                                                             # idem dans la base
        self.assertAlmostEqual(row["duration_s"], sum(p["duration_s"] for p in meta["passes"]), places=1)       # la durée est celle de TOUTES les passes
        self.assertEqual([(n, p.relative_to(self.raw()).as_posix()) for n, p in pass_reports(self.raw(), _REGISTRY["toy"])], [("default", "toy.jsonl"), ("rules", "rules/toy.jsonl")])

    def test_the_digest_covers_every_report_of_the_task(self):
        tool, run = _REGISTRY["toy"], next(r for r in self.db.list_tool_runs(self.run_id) if r["tool"] == "toy")
        self.assertEqual(report_digest(self.raw(), tool), run["report_sha256"])
        _, warnings = load_clear_secrets(self.db, self.run_id, self.data)
        self.assertEqual(warnings, [])
        extra = self.raw() / "rules" / "toy.jsonl"
        original = extra.read_text()
        extra.write_text(original.replace("S-A", "S-X"))                                                        # un rapport de la PASSE 2 est modifié après l'audit
        clear, warnings = load_clear_secrets(self.db, self.run_id, self.data)
        self.assertTrue(any("sortie brute modifiée depuis l'audit" in w for w in warnings), warnings)           # l'empreinte le voit
        self.assertNotIn(("plain", "toy", "dir"), clear)
        fingerprint = next(e["fingerprint"] for e in self.db.entities(self.run_id, "secret") if e["data"]["rule_id"] == "R-A")
        with self.assertRaisesRegex(ValueError, "sortie brute modifiée depuis l'audit"):
            reveal_one(self.db, self.run_id, self.data, fingerprint)                                            # la valeur d'un secret n'est jamais donnée d'un rapport altéré
        extra.write_text(original)
        self.assertEqual(load_clear_secrets(self.db, self.run_id, self.data)[1], [])
        meta_path = self.raw() / "meta.json"
        meta = json.loads(meta_path.read_text())
        meta["passes"][1]["name"] = "autre"                                                                     # falsifier meta.json (ce qui décide des rapports lus)
        meta_path.write_text(json.dumps(meta))
        self.assertTrue(any("sortie brute modifiée" in w for w in load_clear_secrets(self.db, self.run_id, self.data)[1]))

    def test_clear_values_and_reveal_work_for_every_pass(self):
        clear, _ = load_clear_secrets(self.db, self.run_id, self.data)
        values = clear[("plain", "toy", "dir")]
        data = self.entities()
        self.assertEqual({k: values[raw_ref(v)][0] for k, v in data.items()}, {"D1": "S-DEFAULT", "D2": "S-SHARED", "R-A": "S-A", "R-B": "S-B"})   # le bon secret pour CHAQUE constat
        for e in self.db.entities(self.run_id, "secret", {p["name"]: p["id"] for p in self.db.list_projects(self.run_id)}["plain"]):
            revealed = reveal_one(self.db, self.run_id, self.data, e["fingerprint"])
            self.assertEqual(sha256_text(revealed["secret"]), e["data"]["secret_sha256"], e["data"]["rule_id"])   # reveal_one aussi, par passe
        self.assertEqual(raw_ref({"raw_index": 3}), 3)
        self.assertEqual(raw_ref({"raw_index": 3, "report": "rules/toy.jsonl"}), "rules/toy.jsonl:3")
        self.assertIsNone(raw_ref({}))

    def test_the_report_reads_each_finding_in_its_own_raw_report_and_reveals_the_right_secret(self):
        data = build_report_data(self.db, self.run_id, self.data, reveal=True)
        mine = {s["rule_id"]: s for s in data["secrets"] if s["project"] == "plain" and s["tool"] == "toy"}
        self.assertEqual({k: v["secret"] for k, v in mine.items()}, {"D1": "S-DEFAULT", "D2": "S-SHARED", "R-A": "S-A", "R-B": "S-B"})
        self.assertTrue(mine["D1"]["raw_report"].endswith("/dir/toy.jsonl") and not mine["D1"]["raw_report"].endswith("rules/toy.jsonl"))
        self.assertTrue(mine["R-A"]["raw_report"].endswith("/dir/rules/toy.jsonl"))                             # le rapport brut de la passe qui l'a trouvé
        masked = build_report_data(self.db, self.run_id, self.data, reveal=False)
        self.assertFalse(any("secret" in s for s in masked["secrets"] if s["tool"] == "toy"))                   # mode masqué : jamais de valeur en clair

    def test_the_correlation_that_reads_clear_values_works_with_two_passes(self):
        groups = compute_clusters(self.db, self.data, self.run_id, nested=True)
        self.assertTrue(groups)                                                                                  # les valeurs en clair de TOUTES les passes sont relues sans erreur

    def test_reparse_rebuilds_the_same_entities_from_the_raw_outputs(self):
        before = {k: dict(v) for k, v in self.entities().items()}
        reparse(self.db, self.data, self.run_id, parse_config({}, self.tmp), log=lambda *_: None)
        self.assertEqual(self.entities(), before)                                                               # sans relancer l'outil

    def test_the_cost_is_announced_for_any_tool(self):
        self.assertTrue(any(ln.startswith("  ! toy : default_pass : DEUX passes") and "deux fois plus longtemps" in ln for ln in self.lines), self.lines)


class FailureAndRefusalTest(PassesCase):
    def test_a_failing_pass_fails_the_task_and_names_the_pass(self):
        with mock.patch.dict(os.environ, {"TOY_FAIL_RULES": "1"}):
            self.audit(self.cfg(rules=[str(self.rules_a)], default_pass=True))
        row = next(r for r in self.db.list_tool_runs(self.run_id) if r["tool"] == "toy")
        self.assertEqual(row["status"], "failed")
        self.assertRegex(row["error"], r"^passe « rules » : code retour 3 : toy: règles refusées")
        self.assertIn("règles refusées", (self.raw() / "rules" / "stderr.txt").read_text())
        self.assertEqual(self.entities(), {})                                                                   # rien présenté comme complet

    def test_when_the_first_pass_fails_the_second_does_not_run(self):
        with mock.patch.dict(os.environ, {"TOY_FAIL_DEFAULT": "1"}):
            self.audit(self.cfg(rules=[str(self.rules_a)], default_pass=True))
        row = next(r for r in self.db.list_tool_runs(self.run_id) if r["tool"] == "toy")
        self.assertRegex(row["error"], r"^passe « default » : code retour 4 : toy: configuration par défaut cassée")
        self.assertEqual(len([a for a in self.invocations() if str(self.root / "plain") in a]), 1)              # la passe « rules » n'a pas tourné : son résultat n'aurait servi à rien
        self.assertFalse((self.raw() / "rules").exists())

    def test_an_imposed_report_name_does_not_collide_between_passes(self):
        self.audit(self.cfg("toyfile", rules=[str(self.rules_a)], default_pass=True), "toyfile")
        first = (self.raw("toyfile") / "results.jsonl").read_text()
        second = (self.raw("toyfile") / "rules" / "results.jsonl").read_text()
        self.assertEqual(first.count("\n"), 2)
        self.assertEqual(second.count("\n"), 3)                                                                 # chaque passe a SON rapport, malgré le nom imposé par l'outil
        self.assertEqual(sorted(self.entities()), ["D1", "D2", "R-A"])

    def test_a_tool_without_custom_rules_refuses_default_pass_naming_the_tools_that_have_some(self):
        for tool in ("toynorules", "cloc"):
            self.audit(self.cfg(tool, default_pass=True), tool)
            message = next((ln for ln in self.lines if f"tools.{tool}.default_pass" in ln), "")
            self.assertIn(f"{tool} n'a pas de règles personnalisables", message, tool)
            self.assertRegex(message, r"outils qui en ont : .*gitleaks.*toy")
        self.assertEqual(self.invocations(), [])                                                                # jamais lancé

    def test_default_pass_without_rules_is_one_pass_and_says_so(self):
        self.audit(self.cfg(default_pass=True))
        self.assertTrue(any("toy : default_pass sans `rules`" in ln for ln in self.lines), self.lines)
        self.assertEqual(len([a for a in self.invocations() if str(self.root / "plain") in a]), 1)
        self.assertFalse((self.raw() / "rules").exists())
        self.assertNotIn("config_pass", self.entities()["D1"])

    def test_default_pass_is_a_strict_boolean_key_of_the_tool(self):
        for bad in ("oui", 1, None, "true"):
            with self.assertRaisesRegex(ConfigError, r"tools\.toy\.default_pass : true ou false"):
                parse_config({"tools": {"toy": {"default_pass": bad}}}, self.tmp)
        self.assertIs(parse_config({"tools": {"toy": {"default_pass": True}}}, self.tmp).tool("toy").default_pass, True)
        self.assertIs(parse_config({}, self.tmp).tool("toy").default_pass, False)


class TimingTest(PassesCase):
    def test_the_duration_of_a_task_is_the_sum_of_its_passes(self):
        with mock.patch.dict(os.environ, {"TOY_SLEEP": "0.25"}):
            self.audit(self.cfg(rules=[str(self.rules_a)], default_pass=True))
        row = next(r for r in self.db.list_tool_runs(self.run_id) if r["tool"] == "toy" and r["raw_dir"].endswith("plain/toy/dir"))
        self.assertGreaterEqual(row["duration_s"], 0.49)                                                        # deux passes de 0,25 s : la durée de la tâche est celle des DEUX


class BaseClassTest(unittest.TestCase):
    def test_passes_of_the_tool_base_class(self):
        tool, plain = ToyTool(), ToyNoRules()
        cfg = ToolConfig(rules=["/r"], default_pass=True)
        names = [(n, c.rules) for n, c in tool.passes(cfg)]
        self.assertEqual(names, [("default", []), ("rules", ["/r"])])                                           # défaut SEUL, puis la vôtre
        self.assertEqual([n for n, _ in tool.passes(ToolConfig(rules=["/r"]))], ["main"])
        self.assertEqual([n for n, _ in tool.passes(ToolConfig(default_pass=True))], ["main"])                  # sans règles : une passe
        self.assertEqual([n for n, _ in plain.passes(cfg)], ["main"])                                           # sans règles personnalisables : une passe

    def test_parse_task_keeps_one_entity_per_fingerprint(self):
        import tempfile
        raw = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, raw, True)
        (raw / "rules").mkdir()
        (raw / "toy.jsonl").write_text(json.dumps({"id": "A", "file": "x", "line": 1, "secret": "s1"}) + "\n")
        (raw / "rules" / "toy.jsonl").write_text("".join(json.dumps({"id": i, "file": "x", "line": 1, "secret": "s"}) + "\n" for i in ("A", "B", "C", "C")))   # « C » deux fois dans la même passe
        (raw / "meta.json").write_text(json.dumps({"passes": [{"name": "default", "report": "toy.jsonl"}, {"name": "rules", "report": "rules/toy.jsonl"}]}))
        from aule.models import Project
        got = parse_task(ToyTool(), Project("p", raw, False, None, None, None), "dir", raw, None)
        self.assertEqual([(e.data["rule_id"], e.data["config_pass"]) for e in got], [("A", "default+rules"), ("B", "rules"), ("C", "rules")])                    # un seul « C » : l'unicité des empreintes est préservée
        self.assertEqual(clear_values_of(ToyTool(), raw), {0: ("s1", ""), "rules/toy.jsonl:0": ("s", ""), "rules/toy.jsonl:1": ("s", ""), "rules/toy.jsonl:2": ("s", ""), "rules/toy.jsonl:3": ("s", "")})


if __name__ == "__main__":
    unittest.main()
