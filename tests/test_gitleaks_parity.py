"""`tools.gitleaks.rules: [conf.toml]` doit donner les mêmes résultats que `gitleaks -c conf.toml` lancé à la main depuis le dossier du projet.

Deux causes d'écart ont été corrigées : (1) `gitleaks dir` teste les `path` des règles et des exclusions contre les chemins TELS QU'ON LES LUI DONNE (absolus avec une cible absolue :
`^src/` ne correspondait jamais) ; (2) Aulë imposait `[extend] useDefault = true`, ce qui ajoutait à vos règles l'exclusion globale par défaut de gitleaks (vendor/, node_modules/…)."""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from aule.models import sha256_text
from aule.config import ConfigError
from aule.plugins.gitleaks import Gitleaks, _relative
from aule.runner import clear_values_of, raw_ref
from aule.rulesets import merge_gitleaks, wants_default
from test_rules_dirs import RulesCase, rule_toml

CONF = """
[[rules]]
id = "team-token"
description = "jeton d'équipe, seulement sous src/"
regex = '''TEAM-[0-9]{6}'''
keywords = ["team-"]
path = '''^src/'''

[[rules]]
id = "any-token"
description = "jeton, partout"
regex = '''ANY-[0-9]{6}'''
keywords = ["any-"]

[allowlist]
paths = ['''^docs/''']
"""
RULES_REPORT = "rules/report.json"  # la passe « rules » (default_pass) a son sous-dossier
EXTEND = "[extend]\nuseDefault = true\n"
EXPECTED_DIRECT = {("team-token", "src/app.js"), ("any-token", "src/app.js"), ("any-token", "node_modules/lib/x.js")}


class ParityCase(RulesCase):
    def setUp(self):
        super().setUp()
        self.app = self.root / "app"
        for rel, text in {"src/app.js": 'const a = "TEAM-123456"; const b = "ANY-111111";\n', "node_modules/lib/x.js": 'const c = "ANY-222222";\n', "docs/readme.txt": "ANY-333333\n"}.items():
            (self.app / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.app / rel).write_text(text)
        self.conf = self.tmp / "conf.toml"
        self.conf.write_text(CONF)

    def direct(self, config: Path | None = None) -> set[tuple[str, str]]:
        """`gitleaks dir . -c conf.toml`, lancé à la main depuis le dossier du projet."""
        out = self.tmp / "direct.json"
        out.unlink(missing_ok=True)
        assert subprocess.run([shutil.which("gitleaks"), "dir", "--report-format", "json", "--report-path", str(out), "--no-banner", "--config", str(config or self.conf), "."], cwd=self.app).returncode in (0, 1)  # gitleaks sort avec 1 quand il trouve des fuites
        return {(f["RuleID"], f["File"]) for f in json.loads(out.read_text())}

    def aule(self, rules=None, default_pass: bool = False, **options) -> set[tuple[str, str]]:
        run_id = self.audit("gitleaks", [str(self.conf)] if rules is None else rules, default_pass=default_pass, options=options)
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        self.run_id = run_id
        return {(e["data"]["rule_id"], e["data"]["file"]) for e in self.db.entities(run_id, "secret") if names.get(e["project_id"]) == "app" and e["data"]["mode"] == "dir"}


class ParityTest(ParityCase):
    def test_aule_finds_exactly_what_gitleaks_dash_c_finds(self):
        self.assertEqual(self.direct(), EXPECTED_DIRECT)                                                        # la référence : docs/ exclu, node_modules/ PAS exclu (pas de règles par défaut)
        self.assertEqual(self.aule(), EXPECTED_DIRECT)

    def test_the_old_absolute_target_diverged_in_both_directions(self):
        got = self.aule(relative_paths=False)
        self.assertNotIn(("team-token", "src/app.js"), got)                                                     # `path = '^src/'` ne correspondait jamais : un secret MANQUÉ
        self.assertIn(("any-token", "docs/readme.txt"), got)                                                    # `paths = ['^docs/']` n'excluait jamais : un faux positif de plus
        self.assertEqual(got, {("any-token", "src/app.js"), ("any-token", "node_modules/lib/x.js"), ("any-token", "docs/readme.txt")})

    def test_extending_the_defaults_brings_their_global_exclusions(self):
        got = self.aule(default_rules=True)
        self.assertNotIn(("any-token", "node_modules/lib/x.js"), got)                                           # l'exclusion par défaut s'applique alors à VOS règles aussi
        self.assertEqual(got, {("team-token", "src/app.js"), ("any-token", "src/app.js")})
        self.conf.write_text(EXTEND + CONF)                                                                    # le même effet, demandé par le fichier lui-même (`auto`)
        self.assertEqual(self.aule(), got)
        self.assertEqual(self.direct(), got)                                                                    # et c'est aussi ce que fait gitleaks seul

    def test_replaying_the_recorded_command_by_hand_gives_the_same_findings(self):
        """La recette de diagnostic : cmd.txt + le dossier de travail de meta.json + rules.toml rejouent exactement l'exécution d'Aulë."""
        got = self.aule()
        raw = self.raw(self.run_id, "gitleaks", "dir", "app")
        meta = json.loads((raw / "meta.json").read_text())
        self.assertEqual(meta["cwd"], str(self.app))
        command = shlex.split((raw / "cmd.txt").read_text())
        self.assertEqual(command[-1], ".")                                                                      # la cible est `.`, comme à la main
        replay = subprocess.run(command, cwd=meta["cwd"])
        self.assertIn(replay.returncode, (0, 1))                                                                # 1 : des fuites trouvées (code normal de gitleaks)
        replayed = {(f["RuleID"], f["File"]) for f in json.loads((raw / "report.json").read_text())}
        self.assertEqual(replayed, got)
        self.assertEqual(self.direct(raw / "rules.toml"), got)                                                  # gitleaks seul avec le fichier fusionné d'Aulë : même résultat

    def test_the_report_files_are_project_relative_and_triage_keys_do_not_change(self):
        self.aule()
        files = {f for _, f in self.aule()}
        self.assertEqual(files, {"src/app.js", "node_modules/lib/x.js"})                                        # ni `./src/…`, ni chemin absolu
        git_meta = json.loads((self.raw(self.run_id, "gitleaks", "git", "repo-git") / "meta.json").read_text())
        self.assertIsNone(git_meta["cwd"])                                                                      # `git` : chemins déjà relatifs au dépôt, rien à changer


class CommandLineParityTest(ParityCase):
    def test_dir_runs_inside_the_scanned_folder_with_absolute_report_and_config(self):
        self.aule()
        dir_calls = [a for a in self.argvs("gitleaks") if a[0] == "dir"]
        self.assertTrue(dir_calls)
        for args in dir_calls:
            self.assertEqual(args[-1], ".")
            self.assertTrue(os.path.isabs(args[args.index("--report-path") + 1]))                              # le dossier de travail change : tout le reste est absolu
            self.assertTrue(os.path.isabs(args[args.index("--config") + 1]))
        git_calls = [a for a in self.argvs("gitleaks") if a[0] == "git"]
        self.assertTrue(all(os.path.isabs(a[-1]) for a in git_calls))                                           # `git` garde le chemin absolu du dépôt

    def test_relative_paths_false_restores_the_absolute_target(self):
        self.aule(relative_paths=False)
        dir_call = next(a for a in self.argvs("gitleaks") if a[0] == "dir" and str(self.app) in a[-1])
        self.assertEqual(dir_call[-1], str(self.app))
        meta = json.loads((self.raw(self.run_id, "gitleaks", "dir", "app") / "meta.json").read_text())
        self.assertIsNone(meta["cwd"])

    def test_relative_extra_args_keep_their_meaning_when_the_working_directory_changes(self):
        before = os.getcwd()
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        (work / "base.json").write_text("[]")
        (work / "conf2.toml").write_text("")
        os.chdir(work)
        try:
            got = Gitleaks._anchored(["--baseline-path", "base.json", "--config=conf2.toml", "--log-level=debug", "--max-decode-depth", "2", "absent.json", "/déjà/absolu", "-v"])
        finally:
            os.chdir(before)
        real = str(work.resolve())
        self.assertEqual(got, ["--baseline-path", f"{real}/base.json", f"--config={real}/conf2.toml", "--log-level=debug", "--max-decode-depth", "2", "absent.json", "/déjà/absolu", "-v"])

    def test_the_option_must_be_a_boolean(self):
        self.audit("gitleaks", [str(self.conf)], options={"relative_paths": "non"})
        self.assertIn("relative_paths : true ou false", self.blocked("gitleaks") or "")


class RelativeDataDirTest(unittest.TestCase):
    def test_a_relative_data_directory_still_reaches_the_report_after_the_working_directory_changes(self):
        """`aule run --data ./data` : le rapport et la configuration fusionnée doivent être ABSOLUS, car gitleaks s'exécute désormais dans le dossier du projet."""
        from aule.config import parse_config
        from aule.models import Project
        from aule.plugins.base import RunContext
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        (work / "project").mkdir()
        (work / "mine.toml").write_text(rule_toml("mine"))
        cfg = parse_config({"tools": {"gitleaks": {"rules": [str(work / "mine.toml")]}}}, work).tool("gitleaks")
        before = os.getcwd()
        os.chdir(work)
        try:
            tool = Gitleaks()
            ctx = RunContext(data_dir=Path("data"), run_id="r1", cfg=cfg, exe=["/usr/bin/gitleaks"])
            project = Project(name="p", path=(work / "project").resolve(), is_git=False)
            command = tool.build_command(project, "dir", Path("data/runs/r1/p/gitleaks/dir/report.json"), ctx)
            cwd = tool.cwd(project, "dir", ctx)
        finally:
            os.chdir(before)
        report = command[command.index("--report-path") + 1]
        merged = command[command.index("--config") + 1]
        self.assertEqual(report, str(work.resolve() / "data/runs/r1/p/gitleaks/dir/report.json"))               # résolu AVANT le changement de dossier
        self.assertTrue(os.path.isabs(merged) and Path(merged).is_file(), merged)
        self.assertEqual((command[-1], cwd), (".", (work / "project").resolve()))


class DefaultPassTest(ParityCase):
    """`default_pass: true` : gitleaks tourne avec SA configuration par défaut PUIS avec la vôtre, dans la même exécution d'Aulë (pas besoin de relancer)."""

    def setUp(self):
        super().setUp()
        (self.app / "src" / "keys.txt").write_text("AKIA" + "ABCDEFGHIJKLMNOP\n")                             # une règle PAR DÉFAUT du faux gitleaks

    def entities(self, run_id: str) -> dict[tuple[str, str], dict]:
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        return {(e["data"]["rule_id"], e["data"]["file"]): e["data"] for e in self.db.entities(run_id, "secret") if names.get(e["project_id"]) == "app" and e["data"]["mode"] == "dir"}

    def raw_app(self, name: str, mode: str = "dir") -> Path:
        return self.raw(self.run_id, "gitleaks", mode, "app") / name

    def test_both_configurations_run_and_their_findings_are_combined(self):
        got = self.aule(default_pass=True)
        self.assertEqual(got, {("aws-access-token", "src/keys.txt"), ("team-token", "src/app.js"), ("any-token", "src/app.js"), ("any-token", "node_modules/lib/x.js")})
        main = {f["RuleID"] for f in json.loads(self.raw_app("report.json").read_text())}
        rules = {f["RuleID"] for f in json.loads(self.raw_app(RULES_REPORT).read_text())}
        self.assertEqual(main, {"aws-access-token"})                                                            # passe 1 : la configuration par défaut seule
        self.assertEqual(rules, {"team-token", "any-token"})                                                    # passe 2 : la vôtre seule
        calls = [a for a in self.argvs("gitleaks") if a[0] == "dir"]
        self.assertEqual(sum("--config" in a for a in calls) * 2, len(calls))                                   # autant de commandes avec --config que sans
        self.assertTrue(all(a[a.index("--config") + 1].endswith("rules.toml") for a in calls if "--config" in a))
        self.assertIn("--config", self.raw_app("rules/cmd.txt").read_text())                                    # la commande de la 2e passe est conservée (rejeu à la main)
        self.assertNotIn("--config", (self.raw_app("meta.json")).read_text().split('"command"')[1].split('"cwd"')[0])   # celle de la 1re (meta.json) n'en a pas

    def test_your_configuration_is_standalone_so_the_default_exclusions_do_not_hide_your_findings(self):
        self.assertIn(("any-token", "node_modules/lib/x.js"), self.aule(default_pass=True))                    # sans `default_pass`, l'ancien comportement (étendre) n'était pas celui-là :
        self.assertEqual(self.aule(default_pass=True, default_rules=True) - {("aws-access-token", "src/keys.txt")}, {("team-token", "src/app.js"), ("any-token", "src/app.js")})   # `default_rules: true` étend, donc l'exclusion par défaut revient

    def test_a_file_that_asks_for_the_defaults_is_still_standalone_in_the_second_pass(self):
        """Les règles par défaut ont déjà tourné en passe 1 : demander `useDefault = true` dans votre fichier n'y change rien (sinon leur exclusion globale reviendrait vous cacher des constats)."""
        self.conf.write_text(EXTEND + CONF)
        got = self.aule(default_pass=True)
        merged = tomllib.loads(self.raw_app("rules/rules.toml").read_text())
        self.assertNotIn("extend", merged)
        self.assertIn(("any-token", "node_modules/lib/x.js"), got)                                              # l'exclusion par défaut ne vous cache rien
        self.assertEqual(self.entities(self.run_id)[("aws-access-token", "src/keys.txt")]["config_pass"], "default")   # et la règle AWS n'a tourné qu'en passe 1

    def test_each_finding_says_which_configuration_found_it(self):
        self.aule(default_pass=True)
        data = self.entities(self.run_id)
        self.assertEqual(data[("aws-access-token", "src/keys.txt")]["config_pass"], "default")
        self.assertEqual(data[("team-token", "src/app.js")]["config_pass"], "rules")

    def test_a_finding_seen_by_both_passes_is_counted_once(self):
        self.conf.write_text(EXTEND + CONF)                                                                    # votre fichier étend les règles par défaut : la règle AWS tourne aussi en passe 2
        self.aule(default_pass=True, default_rules=True)
        aws = [e for e in self.db.entities(self.run_id, "secret") if e["data"]["rule_id"] == "aws-access-token" and e["data"]["mode"] == "dir" and e["data"]["file"] == "src/keys.txt"]
        self.assertEqual(len(aws), 1)                                                                           # un seul constat, pas deux
        self.assertEqual(aws[0]["data"]["config_pass"], "default+rules")

    def test_the_clear_values_follow_the_same_merged_list_as_the_parsing(self):
        """`raw_index` doit désigner le même secret dans parse et dans clear_values : sinon l'interface afficherait la valeur d'un AUTRE secret."""
        self.aule(default_pass=True)
        clear = clear_values_of(Gitleaks(), self.raw_app("report.json").parent)
        entities = [e["data"] for e in self.db.entities(self.run_id, "secret") if e["data"]["mode"] == "dir" and e["data"]["file"] in ("src/keys.txt", "src/app.js", "node_modules/lib/x.js")]
        self.assertGreaterEqual(len(entities), 4)
        for data in entities:
            self.assertEqual(sha256_text(clear[raw_ref(data)][0]), data["secret_sha256"], data["rule_id"])   # le secret relu EST celui du constat, quel que soit le rapport

    def test_without_default_pass_nothing_changes(self):
        got = self.aule()
        self.assertFalse(self.raw_app(RULES_REPORT).exists())
        self.assertFalse(any("config_pass" in d for d in self.entities(self.run_id).values()))
        self.assertEqual(got, EXPECTED_DIRECT)
        self.assertFalse([a for a in self.argvs("gitleaks") if a[0] == "dir" and "--config" not in a])         # une seule commande, avec --config

    def test_both_passes_also_run_in_git_mode(self):
        self.aule(default_pass=True)
        git_calls = [a for a in self.argvs("gitleaks") if a[0] == "git"]
        self.assertEqual(sum("--config" in a for a in git_calls) * 2, len(git_calls))
        self.assertTrue((self.raw(self.run_id, "gitleaks", "git", "repo-git") / RULES_REPORT).is_file())

    def test_invalid_combinations_are_refused_and_the_cost_is_announced(self):
        for bad in ("oui", 1, None):
            with self.assertRaisesRegex(ConfigError, "default_pass : true ou false"):
                self.audit("gitleaks", [str(self.conf)], default_pass=bad)                                      # une clé de l'outil, strictement booléenne
        self.audit("gitleaks", [str(self.conf)], options={"default_pass": True})
        self.assertRegex(self.blocked("gitleaks") or "", r"options\.default_pass est devenu une clé de l'outil.*sous `gitleaks:`")   # l'ancienne place : refusée avec la marche à suivre
        self.audit("gitleaks", [], default_pass=True, extra_args=["--config", str(self.conf)])
        self.assertIn("default_pass ne se combine pas avec un --config", self.blocked("gitleaks") or "")          # sans `rules` : le refus propre à default_pass
        self.audit("gitleaks", [str(self.conf)], default_pass=True, extra_args=["--config", str(self.conf)])
        self.assertIn("ne peuvent pas être combinés", self.blocked("gitleaks") or "")                           # avec `rules` : le refus général, qui passe en premier
        self.audit("gitleaks", [str(self.conf)], default_pass=True)
        self.assertTrue(any("DEUX passes" in ln and "deux fois plus longtemps" in ln for ln in self.lines), self.lines)
        run_id = self.audit("gitleaks", [], default_pass=True)                                                 # sans `rules` : rien à ajouter
        self.assertTrue(any("default_pass sans `rules`" in ln for ln in self.lines), self.lines)
        self.assertFalse((self.raw(run_id, "gitleaks", "dir", "app") / RULES_REPORT).exists())

    def test_a_second_pass_that_writes_no_report_fails_the_run(self):
        with mock.patch.dict(os.environ, {"FAKE_GL_NO_REPORT_CONFIG": "1"}):
            run_id = self.audit("gitleaks", [str(self.conf)], default_pass=True)
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        row = next(r for r in self.db.list_tool_runs(run_id) if r["tool"] == "gitleaks" and r["mode"] == "dir" and names[r["project_id"]] == "app")
        self.assertEqual((row["status"], row["error"].split(" — ")[0]), ("failed", "passe « rules » : rapport absent"))

    def test_a_failing_second_pass_fails_the_run_instead_of_showing_a_partial_result(self):
        with mock.patch.dict(os.environ, {"FAKE_GL_FAIL_CONFIG": "1"}):
            run_id = self.audit("gitleaks", [str(self.conf)], default_pass=True)
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        row = next(r for r in self.db.list_tool_runs(run_id) if r["tool"] == "gitleaks" and r["mode"] == "dir" and names[r["project_id"]] == "app")
        self.assertEqual(row["status"], "failed")
        self.assertRegex(row["error"], r"passe « rules » : code retour 2 : boom")
        self.assertTrue(self.raw(run_id, "gitleaks", "dir", "app").joinpath("rules", "stderr.txt").read_text().startswith("boom"))   # la sortie de la passe est conservée
        self.assertEqual(self.entities(run_id), {})                                                             # rien présenté comme complet


class DefaultRulesTest(ParityCase):
    def merged(self, rules=None, **options) -> dict:
        self.aule(rules, **options)
        return tomllib.loads((self.raw(self.run_id, "gitleaks", "dir", "app") / "rules.toml").read_text())

    def test_auto_follows_the_files_like_gitleaks_does(self):
        self.assertNotIn("extend", self.merged())                                                               # un fichier sans [extend] REMPLACE les règles par défaut
        self.assertTrue(any("règles PAR DÉFAUT de gitleaks NON chargées" in ln and "useDefault" in ln for ln in self.lines), self.lines)   # et on le dit
        self.conf.write_text(EXTEND + CONF)
        self.assertEqual(self.merged()["extend"], {"useDefault": True})
        self.assertFalse(any("NON chargées" in ln for ln in self.lines))

    def test_true_and_false_override_the_files(self):
        self.assertEqual(self.merged(default_rules=True)["extend"], {"useDefault": True})
        self.assertFalse(any("NON chargées" in ln for ln in self.lines))
        self.conf.write_text(EXTEND + CONF)
        self.assertNotIn("extend", self.merged(default_rules=False))                                           # explicite : jamais les règles par défaut, même si le fichier les demande
        self.assertTrue(any("NON chargées" in ln for ln in self.lines))

    def test_an_invalid_value_is_refused(self):
        for bad in ("oui", "false", 0, None):
            self.audit("gitleaks", [str(self.conf)], options={"default_rules": bad})
            self.assertIn("default_rules : true, false ou auto", self.blocked("gitleaks") or "", bad)

    def test_without_your_rules_gitleaks_keeps_its_own_configuration(self):
        self.audit("gitleaks", [], options={})                                                                   # Aulë n'ajoute aucune règle : pas de --config du tout
        self.assertEqual(self.values("gitleaks", "--config", "dir"), [])
        self.audit("gitleaks", [], options={"default_rules": False})                                             # `default_rules` ne concerne que VOS fichiers
        self.assertEqual(self.values("gitleaks", "--config", "dir"), [])


class RuleSetsParityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.write_text(text)
        return path

    def test_wants_default_only_when_a_file_asks_for_it(self):
        self.assertFalse(wants_default([self.write("a.toml", rule_toml("a"))]))
        self.assertFalse(wants_default([self.write("b.toml", "[extend]\nuseDefault = false\n" + rule_toml("b"))]))
        self.assertTrue(wants_default([self.write("c.toml", rule_toml("c")), self.write("d.toml", EXTEND + rule_toml("d"))]))
        self.assertFalse(wants_default([self.write("bad.toml", "= = =")]))                                     # le fichier invalide est signalé par merge_gitleaks, pas ici

    def test_merge_extends_only_when_asked(self):
        a = self.write("a.toml", rule_toml("a"))
        self.assertNotIn("extend", tomllib.loads(merge_gitleaks([a], use_default=False)))
        self.assertEqual(tomllib.loads(merge_gitleaks([a], use_default=True))["extend"], {"useDefault": True})
        self.assertEqual(tomllib.loads(merge_gitleaks([a]))["extend"], {"useDefault": True})                   # défaut de la fonction : inchangé pour ses appelants


class RelativePathTest(unittest.TestCase):
    def test_relative_inputs_are_normalised_and_absolute_ones_made_project_relative(self):
        base = Path("/work/project")
        self.assertEqual(_relative(base, "src/app.js"), "src/app.js")
        self.assertEqual(_relative(base, "./src/app.js"), "src/app.js")
        self.assertEqual(_relative(base, "././src/app.js"), "src/app.js")
        self.assertEqual(_relative(base, "src\\app.js"), "src/app.js")
        self.assertEqual(_relative(base, "/work/project/src/app.js"), "src/app.js")
        self.assertEqual(_relative(base, "/ailleurs/x.js"), "/ailleurs/x.js")
        self.assertEqual(_relative(base, "C:\\w\\x.js"), "C:/w/x.js")                                          # chemin Windows : jamais pris pour un chemin relatif au projet
        self.assertEqual(_relative(base, ".env"), ".env")                                                       # un fichier caché reste lui-même


if __name__ == "__main__":
    unittest.main()
