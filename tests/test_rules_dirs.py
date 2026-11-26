"""`tools.<outil>.rules` : plusieurs dossiers ou fichiers de règles par outil, l'outil est lancé avec TOUS (opengrep, gitleaks, trufflehog, checkov, trivy, codeql)."""
from __future__ import annotations

import json
import os
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import yaml

from aule.config import ConfigError, parse_config
from aule.orchestrator import run_audit
from aule.plugins.gitleaks import _gitleaks_version
from aule.rulesets import RuleSetError, expand, merge_gitleaks, merge_trufflehog, toml_dumps
from common import AuditCase
from test_sast_deps import make_rules

EXAMPLE = Path(__file__).parent.parent / "examples" / "gitleaks-credentials.example.toml"   # un EXEMPLE : Aulë ne le charge jamais
UNSUPPORTED = ["cloc", "links", "gittools", "osv-scanner", "dependency-check"]
SUPPORTED = ["checkov", "codeql", "gitleaks", "opengrep", "trivy", "trufflehog"]


def rule_toml(rid: str, regex: str = "ZZZ[0-9]{4}", **extra) -> str:
    lines = [f'[[rules]]\nid = "{rid}"\ndescription = "règle {rid}"\nregex = \'\'\'{regex}\'\'\'\nkeywords = ["zzz"]']
    return "\n".join(lines + [f"{k} = {json.dumps(v)}" for k, v in extra.items()]) + "\n"


class RulesCase(AuditCase):
    def setUp(self):
        super().setUp()
        self.argv_dir = self.tmp / "argv"
        self.argv_dir.mkdir()
        env = mock.patch.dict(os.environ, {"FAKE_ARGV_DIR": str(self.argv_dir), "FAKE_GITLEAKS_HONOR_CONFIG": "1"})
        env.start()
        self.addCleanup(env.stop)
        _gitleaks_version.cache_clear()
        self.addCleanup(_gitleaks_version.cache_clear)
        make_rules(self.data / "rules")                                                                         # jeu communautaire d'opengrep (faux)
        repo = self.root / "repo-git"
        (repo / "ui.js").write_text("console.log(1)\n")
        (repo / "main.tf").write_text('resource "aws_s3_bucket" "data" {\n  acl = "public-read"\n}\n')
        (repo / "Dockerfile").write_text("FROM ubuntu:22.04\nUSER root\n")

    def folder(self, name: str, files: dict[str, str]) -> Path:
        root = self.tmp / name
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        root.mkdir(exist_ok=True)
        return root

    def argvs(self, tool: str) -> list[list[str]]:
        path = self.argv_dir / f"{tool}.argv"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def values(self, tool: str, flag: str, command: str | None = None) -> list[str]:
        """Valeurs de `flag` dans les arguments de la (dernière) commande qui le porte."""
        for args in reversed(self.argvs(tool)):
            if (command is None or command in args) and flag in args:
                return [args[i + 1] for i, a in enumerate(args) if a == flag]
        return []

    def audit(self, tool: str, rules, tools: list[str] | None = None, **tool_cfg):
        cfg = parse_config({"tools": {tool: {"rules": rules, **tool_cfg}}}, self.tmp)
        lines: list[str] = []
        run_id = run_audit(self.db, self.data, self.root, config=cfg, tool_names=tools or ["cloc", tool], log=lines.append)
        self.lines = lines
        return run_id

    def blocked(self, tool: str) -> str | None:
        return next((ln for ln in self.lines if ln.startswith(f"  ! {tool} : ") and "tools." in ln), None)

    def raw(self, run_id: str, tool: str, mode: str, project: str = "repo-git") -> Path:
        return self.data / "runs" / run_id / project / tool / mode


class ConfigTest(unittest.TestCase):
    def rules(self, value, base="/etc/aule"):
        return parse_config({"tools": {"gitleaks": {"rules": value}}}, Path(base)).tool("gitleaks").rules

    def test_one_path_or_a_list_always_relative_to_the_config_file(self):
        self.assertEqual(self.rules("regles"), ["/etc/aule/regles"])                                            # même un nom nu : relatif au fichier YAML
        self.assertEqual(self.rules(["a", "/abs/b", "sous/c"]), ["/etc/aule/a", "/abs/b", "/etc/aule/sous/c"])
        self.assertEqual(self.rules(["a", "a", "/etc/aule/a"]), ["/etc/aule/a"])                                # sans doublon, ordre conservé
        self.assertTrue(self.rules("~/regles")[0].endswith("/regles") and not self.rules("~/regles")[0].startswith("~"))

    def test_invalid_values_are_refused(self):
        for bad in (123, {"a": 1}, [1, 2], ["ok", ""], "  "):
            with self.assertRaises(ConfigError, msg=repr(bad)):
                self.rules(bad)

    def test_default_is_no_rules_and_the_key_is_accepted_for_any_tool(self):
        self.assertEqual(parse_config({}, Path(".")).tool("gitleaks").rules, [])
        for tool in UNSUPPORTED + SUPPORTED:
            self.assertEqual(len(parse_config({"tools": {tool: {"rules": ["x"]}}}, Path(".")).tool(tool).rules), 1)      # le refus se fait à l'exécution, avec un message qui nomme les outils


class ExampleConfigTest(unittest.TestCase):
    def test_the_example_puts_rules_inside_each_tool_block_and_it_parses_there(self):
        """L'exemple montre `rules` DANS le bloc de chaque outil : décommentées, ces lignes sont acceptées exactement à cet endroit."""
        import re
        text = (Path(__file__).parent.parent / "aule.example.yaml").read_text(encoding="utf-8")
        active = re.sub(r"(?m)^(    )# (rules: \[)", r"\1\2", text)
        self.assertEqual(len(re.findall(r"(?m)^    # rules: ", text)), len(SUPPORTED))                            # une ligne par outil qui en a
        cfg = parse_config(yaml.safe_load(active), Path("/etc/aule"))
        for tool in SUPPORTED:
            self.assertTrue(cfg.tool(tool).rules, tool)
            self.assertTrue(all(r.startswith("/etc/aule/regles/") for r in cfg.tool(tool).rules), (tool, cfg.tool(tool).rules))
        self.assertEqual(len(re.findall(r"\brules:", text)), len(SUPPORTED))                                      # `rules:` n'apparaît QUE dans les blocs d'outils : pas de bloc séparé en bas
        self.assertFalse([t for t in UNSUPPORTED if cfg.tool(t).rules], "aucun outil sans règles ne reçoit la clé")


class RuleSetsTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def write(self, name: str, text: str) -> Path:
        p = self.tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def test_toml_writer_round_trips_the_structures_of_a_gitleaks_config(self):
        data = {"title": 'a "b" \\ é', "extend": {"useDefault": True}, "allowlist": {"regexes": ["a\\.b", "(?i)^x$"], "n": 3, "f": 1.5},
                "rules": [{"id": "r1", "regex": "x\\d+", "keywords": ["k"], "entropy": 3.5, "allowlists": [{"regexes": ["z"], "condition": "OR"}], "required": [{"id": "r2", "withinLines": 5}]},
                          {"id": "r2", "path": "p", "tags": []}]}
        self.assertEqual(tomllib.loads(toml_dumps(data)), data)
        self.assertEqual(tomllib.loads(toml_dumps({"é-clé": "x", "k": "\x7f"})), {"é-clé": "x", "k": "\x7f"})
        real = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(tomllib.loads(toml_dumps(real)), real)                                                 # le fichier d'Aulë lui-même

    def test_expand_files_and_directories(self):
        a = self.write("a/one.toml", "")
        self.write("a/sub/two.toml", "")
        self.write("a/.hidden/skip.toml", "")
        self.write("a/notes.md", "")
        b = self.write("b/three.toml", "")
        found = expand([str(self.tmp / "a"), str(b), str(a)], {".toml"})
        self.assertEqual([f.name for f in found], ["one.toml", "two.toml", "three.toml"])                       # récursif, ordre stable, caché ignoré, sans doublon
        with self.assertRaisesRegex(RuleSetError, "introuvable"):
            expand([str(self.tmp / "nope")], {".toml"})
        with self.assertRaisesRegex(RuleSetError, "aucun fichier de règles"):
            expand([str(self.tmp / "a" / ".hidden")], {".yaml"})

    def test_gitleaks_merge_keeps_every_rule_and_extends_the_defaults(self):
        a = self.write("a.toml", 'title = "A"\n[extend]\nuseDefault = true\n' + rule_toml("r-a") + '[allowlist]\nregexes = ["^x$"]\npaths = ["vendor/"]\n')
        b = self.write("b.toml", rule_toml("r-b") + rule_toml("r-c", path="\\.js$") + '[allowlist]\nregexes = ["^x$", "^y$"]\n[[allowlists]]\ndescription = "d"\nregexes = ["z"]\n')
        merged = tomllib.loads(merge_gitleaks([a, b]))
        self.assertEqual([r["id"] for r in merged["rules"]], ["r-a", "r-b", "r-c"])
        self.assertIs(merged["extend"]["useDefault"], True)
        self.assertEqual(merged["allowlist"], {"regexes": ["^x$", "^y$"], "paths": ["vendor/"]})                # réunies, sans doublon
        self.assertEqual(merged["allowlists"], [{"description": "d", "regexes": ["z"]}])
        self.assertEqual(merged["rules"][2]["path"], "\\.js$")                                                  # les champs de chaque règle sont conservés

    def test_gitleaks_merge_refuses_what_it_cannot_combine_safely(self):
        a, b = self.write("a.toml", rule_toml("dup")), self.write("b.toml", rule_toml("dup"))
        with self.assertRaisesRegex(RuleSetError, r"« dup » définie deux fois.*a\.toml.*b\.toml"):
            merge_gitleaks([a, b])
        with self.assertRaisesRegex(RuleSetError, r"bad\.toml : TOML invalide"):
            merge_gitleaks([self.write("bad.toml", "rules = = =")])
        with self.assertRaisesRegex(RuleSetError, r"extend\.toml.*`\[extend\] path`"):
            merge_gitleaks([self.write("extend.toml", '[extend]\npath = "base.toml"\n')])
        with self.assertRaisesRegex(RuleSetError, r"clé\(s\) inconnue\(s\)"):
            merge_gitleaks([self.write("odd.toml", "mystery = 1\n")])
        with self.assertRaisesRegex(RuleSetError, r"règle sans `id`"):
            merge_gitleaks([self.write("noid.toml", '[[rules]]\nregex = "x"\n')])
        with self.assertRaisesRegex(RuleSetError, "diffère"):
            merge_gitleaks([self.write("t1.toml", '[allowlist]\nregexTarget = "line"\n'), self.write("t2.toml", '[allowlist]\nregexTarget = "match"\n')])

    def test_trufflehog_merge(self):
        a = self.write("a.yaml", "detectors:\n  - name: det-a\n    keywords: [k]\n    regex: {x: 'A[0-9]+'}\n")
        b = self.write("b.yml", "detectors:\n  - name: det-b\n    keywords: [k]\n    regex: {y: 'B[0-9]+'}\ncustomVerifiers:\n  - url: https://v.example\n")
        merged = yaml.safe_load(merge_trufflehog([a, b]))
        self.assertEqual([d["name"] for d in merged["detectors"]], ["det-a", "det-b"])
        self.assertEqual(merged["customVerifiers"], [{"url": "https://v.example"}])
        with self.assertRaisesRegex(RuleSetError, "« det-a » défini deux fois"):
            merge_trufflehog([a, self.write("c.yaml", "detectors:\n  - name: det-a\n")])
        with self.assertRaisesRegex(RuleSetError, "sans `name`"):
            merge_trufflehog([self.write("d.yaml", "detectors:\n  - keywords: [k]\n")])
        with self.assertRaisesRegex(RuleSetError, r"`sources` ne concerne que `multi-scan`"):
            merge_trufflehog([self.write("e.yaml", "sources:\n  - x\n")])
        with self.assertRaisesRegex(RuleSetError, "YAML invalide"):
            merge_trufflehog([self.write("f.yaml", "a: [unclosed\n")])


class CentralCheckTest(RulesCase):
    def test_a_tool_without_custom_rules_is_refused_and_not_run(self):
        folder = self.folder("r", {"x.txt": ""})
        for tool in UNSUPPORTED:
            self.argv_dir.joinpath(f"{tool}.argv").unlink(missing_ok=True)
            self.audit(tool, [str(folder)], tools=["cloc", tool])
            message = self.blocked(tool)
            self.assertIsNotNone(message, tool)
            self.assertIn(f"{tool} n'a pas de règles personnalisables", message)
            self.assertIn("checkov, codeql, gitleaks, opengrep, trivy, trufflehog", message)                    # dit lesquels en ont
            if tool != "cloc":
                self.assertEqual(self.argvs(tool), [], tool)                                                    # jamais lancé avec une configuration qu'il ignorerait

    def test_a_missing_path_is_refused_naming_it(self):
        good = self.folder("good", {"r.toml": rule_toml("r1")})
        for tool in SUPPORTED:
            self.audit(tool, [str(good), str(self.tmp / "absent")])
            self.assertRegex(self.blocked(tool) or "", rf"tools\.{tool}\.rules : introuvable : .*absent", tool)

    def test_without_rules_nothing_changes(self):
        run_id = self.audit("opengrep", [], tools=["cloc", "opengrep"])
        self.assertFalse(self.blocked("opengrep"))
        self.assertTrue([r for r in self.db.list_tool_runs(run_id) if r["tool"] == "opengrep" and r["status"] == "ok"])


class GitleaksRulesTest(RulesCase):
    def test_all_files_and_folders_are_merged(self):
        a = self.folder("a", {"first.toml": "[extend]\nuseDefault = true\n" + rule_toml("team-a", "AAA[0-9]{4}"), "sub/second.toml": rule_toml("team-a2", "AA2[0-9]{4}")})   # un fichier demande les règles par défaut
        b = self.folder("b", {"third.toml": rule_toml("team-b", "BBB[0-9]{4}")})
        single = self.folder("c", {"only.toml": rule_toml("single")}) / "only.toml"
        run_id = self.audit("gitleaks", [str(a), str(b), str(single)])
        for mode in ("dir", "git"):
            merged = tomllib.loads((self.raw(run_id, "gitleaks", mode) / "rules.toml").read_text())
            self.assertEqual([r["id"] for r in merged["rules"]], ["team-a", "team-a2", "team-b", "single"], mode)   # TOUTES les vôtres, dans l'ordre, et rien d'autre : Aulë n'ajoute aucune règle
            self.assertIs(merged["extend"]["useDefault"], True)
            self.assertEqual(self.values("gitleaks", "--config", mode), [str(self.raw(run_id, "gitleaks", mode) / "rules.toml")], mode)   # UN seul --config : le fichier fusionné

    def test_your_rule_yields_findings_next_to_the_default_rules(self):
        (self.root / "repo-git" / "keys.txt").write_text("token ZZZ1234 et AKIA" + "ABCDEFGHIJKLMNOP\n")
        run_id = self.audit("gitleaks", [str(self.folder("mine", {"r.toml": "[extend]\nuseDefault = true\n" + rule_toml("internal-zzz")}))])   # [extend] useDefault = true : on AJOUTE aux règles par défaut
        got = {(e["data"]["rule_id"], e["data"]["file"]) for e in self.db.entities(run_id, "secret") if e["data"]["mode"] == "dir"}
        self.assertIn(("internal-zzz", "keys.txt"), got)                                                        # votre règle
        self.assertIn(("aws-access-token", "keys.txt"), got)                                                    # la règle PAR DÉFAUT survit

    def test_without_rules_gitleaks_gets_no_config_at_all(self):
        """Aulë n'ajoute AUCUNE règle : sans `rules`, gitleaks tourne avec sa configuration par défaut, sans --config."""
        run_id = self.audit("gitleaks", [])
        self.assertEqual(self.values("gitleaks", "--config", "dir"), [])
        self.assertEqual(self.values("gitleaks", "--config", "git"), [])
        self.assertFalse((self.raw(run_id, "gitleaks", "dir") / "rules.toml").exists())
        self.audit("gitleaks", [str(self.folder("mine", {"r.toml": rule_toml("mine")}))])                         # avec `rules` : le fichier fusionné, et lui seul
        self.assertTrue(self.values("gitleaks", "--config", "dir"))

    def test_what_cannot_be_combined_is_refused_before_any_run(self):
        mine = str(self.folder("mine", {"r.toml": rule_toml("mine")}))
        self.argv_dir.joinpath("gitleaks.argv").unlink(missing_ok=True)
        self.audit("gitleaks", [mine], extra_args=["--config", str(self.tmp / "own.toml")])
        self.assertIn("ne peuvent pas être combinés", self.blocked("gitleaks"))
        self.audit("gitleaks", [str(self.folder("dup", {"a.toml": rule_toml("same"), "b.toml": rule_toml("same")}))])
        self.assertRegex(self.blocked("gitleaks"), r"« same » définie deux fois.*a\.toml.*b\.toml")
        self.audit("gitleaks", [str(self.folder("bad", {"broken.toml": "rules = = ="}))])
        self.assertRegex(self.blocked("gitleaks"), r"broken\.toml : TOML invalide")
        self.assertEqual([a for a in self.argvs("gitleaks") if a[0] in ("dir", "git")], [])                    # aucune exécution avec une configuration douteuse

    def test_an_old_gitleaks_would_lose_the_default_rules_so_it_is_refused(self):
        mine = str(self.folder("mine", {"r.toml": "[extend]\nuseDefault = true\n" + rule_toml("mine")}))
        with mock.patch.dict(os.environ, {"FAKE_GITLEAKS_VERSION": "8.8.5"}):
            self.audit("gitleaks", [mine])
            self.assertRegex(self.blocked("gitleaks"), r"8\.8\.5 < 8\.9\.0.*REMPLACÉES.*mettez gitleaks à jour")
            self.audit("gitleaks", [str(self.folder("plain", {"r.toml": rule_toml("plain")}))])
            self.assertIsNone(self.blocked("gitleaks"))                                                         # sans règles par défaut à étendre, une vieille version convient : le fichier est autonome
            self.audit("gitleaks", [mine], options={"default_rules": False})
            self.assertIsNone(self.blocked("gitleaks"))                                                         # et `default_rules: false` le permet explicitement


class OtherToolsRulesTest(RulesCase):
    def test_opengrep_gets_every_entry_after_the_community_rules(self):
        a, b = self.folder("a", {"r.yaml": "rules: []\n"}), self.folder("b", {"r.yaml": "rules: []\n"})
        single = self.folder("c", {"one.yaml": "rules: []\n"}) / "one.yaml"
        self.audit("opengrep", [str(a), str(b), str(single)])
        configs = self.values("opengrep", "--config")
        self.assertEqual(configs[-3:], [str(a), str(b), str(single)])                                           # TOUTES, dans l'ordre
        self.assertTrue(any(c.endswith("opengrep-rules/python") for c in configs[:-3]))                         # et le jeu communautaire est toujours là

    def test_opengrep_runs_with_only_your_rules_and_on_projects_without_a_detected_technology(self):
        mine = self.folder("mine", {"r.yaml": "rules: []\n"})
        run_id = self.audit("opengrep", [str(mine)], options={"rules_path": str(self.tmp / "no-community-pack")})
        self.assertFalse(self.blocked("opengrep"))
        projects = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        ran = {projects[r["project_id"]] for r in self.db.list_tool_runs(run_id) if r["tool"] == "opengrep" and r["status"] == "ok"}
        self.assertIn("repo-git", ran)
        self.audit("opengrep", [], options={"rules_path": str(self.tmp / "no-community-pack")})
        self.assertIn("jeu de règles introuvable", self.blocked("opengrep") or "")                              # sans vos règles : l'exigence d'avant demeure

    def test_trufflehog_detectors_are_merged_into_one_config(self):
        a = self.folder("a", {"a.yaml": "detectors:\n  - name: det-a\n    keywords: [k]\n    regex: {x: 'A[0-9]+'}\n"})
        b = self.folder("b", {"b.yml": "detectors:\n  - name: det-b\n    keywords: [k]\n    regex: {y: 'B[0-9]+'}\n"})
        run_id = self.audit("trufflehog", [str(a), str(b)])
        merged = yaml.safe_load((self.raw(run_id, "trufflehog", "dir") / "detectors.yaml").read_text())
        self.assertEqual([d["name"] for d in merged["detectors"]], ["det-a", "det-b"])
        for mode in ("dir", "git"):
            self.assertEqual(self.values("trufflehog", "--config", "git" if mode == "git" else "filesystem"), [str(self.raw(run_id, "trufflehog", mode) / "detectors.yaml")])
        self.audit("trufflehog", [str(a)], extra_args=["--config=x.yaml"])
        self.assertIn("ne peuvent pas être combinés", self.blocked("trufflehog"))
        self.audit("trufflehog", [str(self.folder("dup", {"1.yaml": "detectors:\n  - name: same\n", "2.yaml": "detectors:\n  - name: same\n"}))])
        self.assertIn("« same » défini deux fois", self.blocked("trufflehog"))

    def test_checkov_gets_one_external_checks_dir_per_entry(self):
        a, b = self.folder("a", {"CKV_A.yaml": "x: 1\n"}), self.folder("b", {"check.py": "x = 1\n"})
        self.audit("checkov", [str(a), str(b)])
        self.assertEqual(self.values("checkov", "--external-checks-dir"), [str(a), str(b)])
        self.audit("checkov", [str(a / "CKV_A.yaml")])
        self.assertIn("des DOSSIERS sont attendus", self.blocked("checkov"))

    def test_trivy_gets_every_check_and_the_namespaces(self):
        a, b = self.folder("a", {"x.rego": "package user.a\n"}), self.folder("b", {"y.rego": "package user.b\n"})
        self.audit("trivy", [str(a), str(b)])
        self.assertEqual(self.values("trivy", "--config-check"), [str(a), str(b)])
        self.assertEqual(self.values("trivy", "--check-namespaces"), ["user"])                                  # sans espace de noms, les règles ne seraient pas évaluées
        self.audit("trivy", [str(a)], options={"check_namespaces": ["user", "main"]})
        self.assertEqual(self.values("trivy", "--check-namespaces"), ["user", "main"])
        self.audit("trivy", [str(a)], options={"scanners": ["vuln"]})
        self.assertIn("scanner `misconfig`", self.blocked("trivy"))
        self.audit("trivy", [str(a)], options={"check_namespaces": []})
        self.assertIn("check_namespaces", self.blocked("trivy"))

    def test_codeql_adds_the_language_folder_of_each_entry(self):
        a = self.folder("a", {"python/qlpack.yml": "name: a\n", "javascript-typescript/qlpack.yml": "name: a-js\n"})
        b = self.folder("b", {"python/qlpack.yml": "name: b\n"})
        run_id = self.audit("codeql", [str(a), str(b)])
        analyzes = [args for args in self.argvs("codeql") if args[:2] == ["database", "analyze"]]
        by_lang = {("python" if "python" in args[2] else "javascript-typescript"): args for args in analyzes}
        self.assertEqual(sorted(by_lang), ["javascript-typescript", "python"], run_id)
        self.assertEqual([x for x in by_lang["python"] if x.startswith(str(self.tmp))][-2:], [str(a / "python"), str(b / "python")])      # chaque dossier, pour CE langage
        js_specs = [x for x in by_lang["javascript-typescript"] if x.startswith(str(self.tmp / "a")) or x.startswith(str(self.tmp / "b"))]
        self.assertEqual(js_specs, [str(a / "javascript-typescript")])                                          # b n'a pas de dossier JS : rien d'ajouté pour lui

    def test_codeql_warns_about_a_folder_that_would_apply_to_no_language(self):
        flat = self.folder("flat", {"query.ql": "select 1\n"})
        self.audit("codeql", [str(flat)])
        self.assertTrue(any("n'a aucun sous-dossier de langage" in ln and str(flat) in ln for ln in self.lines), self.lines)
        self.audit("codeql", [str(flat / "query.ql")])
        self.assertIn("des DOSSIERS sont attendus", self.blocked("codeql"))


class EveryToolTest(RulesCase):
    def test_each_tool_is_launched_with_all_its_entries(self):
        """L'exigence : « si plusieurs clés existent, l'outil se lance avec toutes », pour chaque outil qui a des règles, dans UNE configuration."""
        def two(tool: str, files: dict[str, str]):
            return [str(self.folder(f"{side}/{tool}", files)) for side in ("A", "B")]
        distinct = lambda side, name: {f"{name}-{side}.toml": rule_toml(f"{name}-{side}")}  # noqa: E731
        cfg = parse_config({"tools": {
            "gitleaks": {"rules": [str(self.folder(f"{s}/gitleaks", distinct(s, "g"))) for s in "AB"]},
            "opengrep": {"rules": two("opengrep", {"r.yaml": "rules: []\n"})},
            "trufflehog": {"rules": [str(self.folder(f"{s}/trufflehog", {"d.yaml": f"detectors:\n  - name: det-{s}\n"})) for s in "AB"]},
            "checkov": {"rules": two("checkov", {"c.yaml": "x: 1\n"})},
            "trivy": {"rules": two("trivy", {"c.rego": "package user.x\n"})},
            "codeql": {"rules": two("codeql", {"python/qlpack.yml": "name: q\n"})}}}, self.tmp)
        lines: list[str] = []
        run_id = run_audit(self.db, self.data, self.root, config=cfg, tool_names=["cloc", *SUPPORTED], log=lines.append)
        self.assertFalse([ln for ln in lines if "tools." in ln and "rules" in ln], lines)                       # aucun refus
        A, B = self.tmp / "A", self.tmp / "B"
        self.assertEqual(self.values("opengrep", "--config")[-2:], [str(A / "opengrep"), str(B / "opengrep")])
        self.assertEqual(self.values("checkov", "--external-checks-dir"), [str(A / "checkov"), str(B / "checkov")])
        self.assertEqual(self.values("trivy", "--config-check"), [str(A / "trivy"), str(B / "trivy")])
        analyze = next(a for a in reversed(self.argvs("codeql")) if a[:2] == ["database", "analyze"] and "python" in a[2])
        self.assertEqual([x for x in analyze if x.startswith((str(A), str(B)))], [str(A / "codeql" / "python"), str(B / "codeql" / "python")])
        self.assertEqual([r["id"] for r in tomllib.loads((self.raw(run_id, "gitleaks", "dir") / "rules.toml").read_text())["rules"]][-2:], ["g-A", "g-B"])
        self.assertEqual([d["name"] for d in yaml.safe_load((self.raw(run_id, "trufflehog", "dir") / "detectors.yaml").read_text())["detectors"]], ["det-A", "det-B"])
        for tool in SUPPORTED:
            self.assertTrue([r for r in self.db.list_tool_runs(run_id) if r["tool"] == tool and r["status"] == "ok"], tool)    # et chacun a bien tourné


if __name__ == "__main__":
    unittest.main()
