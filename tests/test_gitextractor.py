"""gittools avec git-extractor-rs (défaut) ou extractor.sh : variante, ligne de commande, lecture des sorties, ordre des commits, history, alias."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fakes
from aule.config import ConfigError, parse_config
from aule.plugins import load_plugins, select_tools
from aule.plugins.gittools import GitTools, chronological, flavor_of, parse_commit_meta, rust_options
from aule.runner import tool_version
from common import AuditCase

TOOL = GitTools()
SNAP = re.compile(r"^\d{8}-\d{4}_[0-9a-f]{40}$")
H = lambda n: f"{n:040x}"  # noqa: E731


def commit_payload(parents=(), ts=1700000000, tz="+0000", msg="msg") -> str:
    lines = ["tree " + "4b825dc642cb6eb9a060e54bf8d69288fbee4904", *[f"parent {p}" for p in parents],
             f"author Alice <a@x.org> {ts} {tz}", f"committer Alice <a@x.org> {ts} {tz}", "", msg]
    return "\n".join(lines) + "\n"


class FlavorAndOptionsTest(unittest.TestCase):
    def test_flavor_is_read_from_the_executable_unless_forced(self):
        self.assertEqual(flavor_of({}, ["/opt/bin/git-extractor-rs"]), "rust")
        self.assertEqual(flavor_of({}, ["/opt/GitTools/Extractor/extractor.sh"]), "sh")
        self.assertEqual(flavor_of({}, ["bash", "/opt/extractor.sh"]), "sh")                             # script lancé par un launcher
        self.assertEqual(flavor_of({"flavor": "sh"}, ["/opt/mon-script"]), "sh")                          # forcé
        self.assertEqual(flavor_of({"flavor": "RUST"}, ["/opt/x.sh"]), "rust")
        with self.assertRaisesRegex(ValueError, "auto, rust ou sh"):
            flavor_of({"flavor": "perl"}, ["x"])

    def test_option_validation(self):
        self.assertEqual(rust_options({}), (4, "committer"))
        self.assertEqual(rust_options({"threads": 16, "snapshot_date": "author"}), (16, "author"))
        for bad, msg in (({"threads": 0}, "threads"), ({"threads": 65}, "threads"), ({"threads": "4"}, "threads"), ({"threads": True}, "threads"),
                         ({"snapshot_date": "both"}, "snapshot_date")):
            with self.assertRaisesRegex(ValueError, msg):
                rust_options(bad)

    def test_git_extractor_rs_is_the_default_binary(self):
        self.assertEqual(TOOL.binary, "git-extractor-rs")
        self.assertIs(load_plugins()["gittools"].__class__, GitTools)


class CommandLineTest(AuditCase):
    def argv_of_last_run(self):
        calls = [json.loads(l) for l in (self.tmp / "argv.log").read_text().splitlines()]
        return [c for c in calls if c != ["--version"]]                                                  # hors sonde de version de l'orchestrateur

    def run_gittools(self, options=None, **tool):
        config = parse_config({"tools": {"gittools": {"options": options or {}, **tool}}}, self.tmp)
        with mock.patch.dict(os.environ, {"FAKE_ARGV": str(self.tmp / "argv.log")}):
            return self.run_audit(config, tool_names=["gittools"])

    def test_the_documented_option_form_is_used(self):
        run_id = self.run_gittools()
        (args,) = self.argv_of_last_run()
        out = str(self.data / "runs" / run_id / "repo-git" / "gittools" / "extract" / "extracted")
        self.assertEqual(args, [str(self.root / "repo-git"), "-o", out, "--threads", "4", "--snapshot-date", "committer"])
        self.assertEqual(sum(1 for a in args if not a.startswith("-") and a != out and "repo-git" not in a and not a.isdigit() and a != "committer"), 0)

    def test_options_are_passed_through(self):
        self.run_gittools({"threads": 8, "snapshot_date": "author"})
        (args,) = self.argv_of_last_run()
        self.assertEqual(args[3:], ["--threads", "8", "--snapshot-date", "author"])

    def test_the_legacy_script_keeps_its_own_command_line(self):
        fakes.install(self.tmp / "legacy", extractor=None, legacy_extractor="extractor.sh", cloc=None, gitleaks=None)
        run_id = self.run_gittools(path=str(self.tmp / "legacy" / "extractor.sh"))
        report = json.loads(next((self.data / "runs" / run_id).glob("repo-git/gittools/extract/report.json")).read_text())
        self.assertEqual((report["flavor"], report["scan_root"]), ("sh", "extracted"))
        self.assertEqual(len(report["commits"]), 2)
        self.assertTrue(all(re.fullmatch(r"\d+-[0-9a-f]{40}", c["dir"]) for c in report["commits"]))

    def test_invalid_options_block_the_tool_with_a_clear_message(self):
        lines: list[str] = []
        config = parse_config({"tools": {"gittools": {"options": {"threads": 0}}}}, self.tmp)
        from aule.orchestrator import run_audit
        run_id = run_audit(self.db, self.data, self.root, config=config, tool_names=["gittools"], log=lines.append)
        self.assertTrue(any("gittools : tools.gittools.options.threads" in l for l in lines), lines)
        st = {(r["tool"], r["mode"]): r["status"] for r in self.db.list_tool_runs(run_id)}
        self.assertNotIn("ok", {v for k, v in st.items() if k[0] == "gittools"})

    def test_git_is_required_by_the_rust_flavor_only(self):
        cfg = parse_config({}, self.tmp).tool("gittools")
        import shutil as _shutil
        real_which = _shutil.which
        without_git = lambda name, *a, **k: None if name == "git" else real_which(name, *a, **k)  # noqa: E731 — masque seulement git
        with mock.patch("shutil.which", side_effect=without_git):
            self.assertIn("git introuvable", TOOL.prerequisites(cfg, self.data))
            sh_cfg = parse_config({"tools": {"gittools": {"options": {"flavor": "sh"}}}}, self.tmp).tool("gittools")
            self.assertIsNone(TOOL.prerequisites(sh_cfg, self.data))
        self.assertIsNone(TOOL.prerequisites(cfg, self.data))


class OutputsTest(AuditCase):
    def setUp(self):
        super().setUp()
        self.run_id = self.run_audit(tool_names=["gittools"])
        self.raw = self.data / "runs" / self.run_id / "repo-git" / "gittools" / "extract"

    def test_report_and_layout(self):
        report = json.loads((self.raw / "report.json").read_text())
        self.assertEqual((report["flavor"], report["extracted_dir"], report["scan_root"]), ("rust", "extracted", "extracted/snapshots"))
        self.assertEqual([c["hash"] for c in report["commits"]], self.commits)                       # ordre chronologique, parent d'abord
        self.assertEqual([c["index"] for c in report["commits"]], [0, 1])
        self.assertTrue(all(SNAP.match(c["dir"]) and (self.raw / "extracted" / "snapshots" / c["dir"]).is_dir() for c in report["commits"]))
        self.assertTrue(all(c["author"] == "Alice" and c["date"] and c["parents"] is not None for c in report["commits"]))
        self.assertIn("remove hardcoded key", report["commits"][1]["message"])
        for d in ("blobs", "commits", "trees"):
            self.assertTrue(any((self.raw / "extracted" / d).iterdir()), d)                          # tous les objets sont conservés (raw)
        self.assertTrue((self.raw / "extracted" / "report.json").exists())                           # le rapport de l'OUTIL...
        self.assertNotEqual((self.raw / "extracted" / "report.json").read_text(), (self.raw / "report.json").read_text())   # ...n'est pas le nôtre

    def test_entities_and_stable_identity(self):
        commits = self.db.entities(self.run_id, "commit")
        self.assertEqual(sorted(c["data"]["hash"] for c in commits), sorted(self.commits))
        self.assertTrue(all(c["fingerprint"] for c in commits))

    def test_purge_heavy_removes_the_extracted_tree_but_keeps_our_report(self):
        from aule.purge import apply_purge, plan_purge
        doomed, items = plan_purge(self.db, self.data, heavy=True)
        self.assertTrue(any(i.kind == "extracted" and i.path == self.raw / "extracted" for i in items))
        apply_purge(self.db, self.data, doomed, items)
        self.assertFalse((self.raw / "extracted").exists())
        self.assertTrue((self.raw / "report.json").exists())


class OrderTest(unittest.TestCase):
    def test_parents_come_first_even_when_timestamps_tie_or_lie(self):
        self.assertEqual(chronological([("b", 100, ["a"]), ("a", 100, []), ("c", 100, ["b"])]), ["a", "b", "c"])        # même seconde : la filiation tranche
        self.assertEqual(chronological([("b", 50, ["a"]), ("a", 100, [])]), ["a", "b"])                                  # horloge fausse : un parent précède quand même
        self.assertEqual(chronological([("y", 200, []), ("x", 100, [])]), ["x", "y"])                                    # deux racines : par date
        self.assertEqual(chronological([("m", 300, ["a", "b"]), ("a", 100, []), ("b", 200, [])]), ["a", "b", "m"])       # fusion
        self.assertEqual(chronological([("a", 1, ["inconnu"])]), ["a"])                                                  # parent absent (dépôt incomplet)
        self.assertEqual(sorted(chronological([("a", 1, ["b"]), ("b", 1, ["a"])])), ["a", "b"])                          # cycle impossible : rien n'est perdu
        self.assertEqual(chronological([("a", 1, ["a"])]), ["a"])

    def test_directory_names_are_not_trusted_for_the_order(self):
        """Même minute pour deux commits : le nom de dossier se termine par l'empreinte, donc l'ordre alphabétique est celui des empreintes."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "extracted"
            parent, child = H(0xFFFF), H(0x0001)                                                        # le PARENT a l'empreinte la plus « grande »
            for h, payload in ((parent, commit_payload()), (child, commit_payload([parent]))):
                (out / "commits").mkdir(parents=True, exist_ok=True)
                (out / "commits" / h).write_text(payload)
                (out / "snapshots" / f"20261117-1633_{h}").mkdir(parents=True)
            names = sorted(p.name for p in (out / "snapshots").iterdir())
            self.assertTrue(names[0].endswith(child))                                                   # l'ordre des noms est INVERSE de la chronologie
            commits = GitTools._collect_rust(out)
            self.assertEqual([c["hash"] for c in commits], [parent, child])                             # ... et l'ordre retenu est le bon

    def test_epoch_not_wall_clock_decides(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "x"
            early, late = H(2), H(1)
            (out / "commits").mkdir(parents=True)
            (out / "commits" / early).write_text(commit_payload(ts=1700000000, tz="+0100"))              # 2023-11-14 23:13 heure locale
            (out / "commits" / late).write_text(commit_payload(ts=1700000100, tz="-0800"))               # 14:15 heure locale : « avant » à l'horloge, après en réalité
            self.assertEqual([c["hash"] for c in GitTools._collect_rust(out)], [early, late])


class RobustnessTest(unittest.TestCase):
    def collect(self, build) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "extracted"
            out.mkdir()
            build(out)
            return GitTools._collect_rust(out)

    def test_snapshots_without_payloads_and_payloads_without_snapshots(self):
        def build(out):
            (out / "snapshots" / f"00000000-0000_{H(1)}").mkdir(parents=True)                           # date illisible : préfixe documenté
            (out / "commits").mkdir()
            (out / "commits" / H(2)).write_text(commit_payload())
        commits = {c["hash"]: c for c in self.collect(build)}
        self.assertEqual(commits[H(1)]["dir"], f"00000000-0000_{H(1)}")
        self.assertNotIn("author", commits[H(1)])                                                       # pas de métadonnées : on garde le commit quand même
        self.assertIsNone(commits[H(2)]["dir"])                                                         # commit connu mais sans instantané
        self.assertEqual(commits[H(2)]["author"], "Alice")

    def test_noise_is_ignored_and_binary_payloads_survive(self):
        def build(out):
            (out / "commits").mkdir()
            (out / "commits" / "pas-une-empreinte").write_text("x")
            (out / "commits" / H(3)).write_bytes(b"tree " + b"a" * 40 + b"\nauthor \xff\xfe <a@x> 1 +0000\n\nmessage \xe9\n")
            (out / "snapshots" / "dossier-quelconque").mkdir(parents=True)
            (out / "snapshots" / "20261117-1633_zz").mkdir()
            (out / "snapshots" / f"20261117-1633_{H(0xabc).upper()}").mkdir()                          # empreinte en majuscules : pas le format documenté
        self.assertEqual([c["hash"] for c in self.collect(build)], [H(3)])

    def test_nothing_extracted_is_an_error_not_an_empty_success(self):
        self.assertEqual(self.collect(lambda out: None), [])
        raw = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, raw, True)
        (raw / "extracted").mkdir()
        ctx = mock.Mock(cfg=mock.Mock(options={}), exe=["git-extractor-rs"])
        with self.assertRaisesRegex(RuntimeError, "aucun commit extrait"):
            TOOL.post_run(mock.Mock(), "extract", raw, raw / "report.json", ctx)


class HistoryTest(AuditCase):
    def dangling_commit(self) -> str:
        """Un commit que plus aucune référence n'atteint (branche supprimée, historique réécrit) et qui contient une clé."""
        repo = self.root / "repo-git"
        env = {**os.environ, "GIT_AUTHOR_NAME": "Mallory", "GIT_AUTHOR_EMAIL": "m@x.org", "GIT_COMMITTER_NAME": "Mallory", "GIT_COMMITTER_EMAIL": "m@x.org"}
        run = lambda *a, **k: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True, env=env, **k).stdout.strip()  # noqa: E731
        blob = run("hash-object", "-w", "--stdin", input=f'AWS_KEY = "{fakes.SECRET_A}"\n')
        tree = run("mktree", input=f"100644 blob {blob}\tvault.py\n")
        return run("commit-tree", tree, "-m", "ajout d'un coffre (branche supprimée depuis)")

    def test_a_secret_in_an_unreachable_commit_is_found_by_history_only(self):
        ghost = self.dangling_commit()
        run_id = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"])
        commits = {c["data"]["hash"] for c in self.db.entities(run_id, "commit")}
        self.assertIn(ghost, commits)                                                                    # l'historique inclut les commits inaccessibles
        found = {(s["data"]["mode"], s["data"]["file"]) for s in self.db.entities(run_id, "secret")}
        self.assertIn(("history", "vault.py"), found)
        self.assertNotIn(("git", "vault.py"), found)                                                     # `gitleaks git` ne voit que l'historique accessible
        entity = next(s["data"] for s in self.db.entities(run_id, "secret") if s["data"]["mode"] == "history" and s["data"]["file"] == "vault.py")
        self.assertEqual((entity["first_commit"], entity["commit_message"].startswith("ajout d'un coffre")), (ghost, True))
        self.assertEqual(entity["author"], "Mallory")

    def test_history_scans_the_snapshots_not_the_raw_objects(self):
        run_id = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"])
        files = {s["data"]["file"] for s in self.db.entities(run_id, "secret") if s["data"]["mode"] == "history"}
        self.assertEqual(files, {"config.py", "settings.py"})                                            # jamais « blobs/<hash> », « commits/<hash> »...
        raw = self.data / "runs" / run_id / "repo-git" / "gittools" / "extract" / "extracted"
        secret_blobs = [b for b in (raw / "blobs").iterdir() if fakes.SECRET_B.encode() in b.read_bytes() or fakes.SECRET_A.encode() in b.read_bytes()]
        self.assertTrue(secret_blobs)                                                                    # les blobs contiennent bien les secrets : l'absence ci-dessus est un choix

    def test_both_flavors_agree_on_what_history_finds(self):
        def summary(run_id):
            return sorted((s["data"]["file"], s["data"]["commits_count"], s["data"]["first_commit"], s["data"]["last_commit"])
                          for s in self.db.entities(run_id, "secret") if s["data"]["mode"] == "history")
        rust = summary(self.run_audit(tool_names=["cloc", "gitleaks", "gittools"]))
        fakes.install(self.tmp / "legacy", extractor=None, legacy_extractor="extractor.sh", cloc=None, gitleaks=None)
        config = parse_config({"tools": {"gittools": {"path": str(self.tmp / "legacy" / "extractor.sh")}}}, self.tmp)
        sh = summary(self.run_audit(config, tool_names=["cloc", "gitleaks", "gittools"]))
        self.assertEqual(rust, sh)
        self.assertEqual(len(rust), 2)

    def test_reports_written_before_this_change_still_work(self):
        """Un rapport gittools sans `flavor` ni `scan_root` (runs antérieurs) : on retombe sur extracted/ et sur la correspondance par nom <n>-<hash>."""
        fakes.install(self.tmp / "legacy", extractor=None, legacy_extractor="extractor.sh", cloc=None, gitleaks=None)
        config = parse_config({"tools": {"gittools": {"path": str(self.tmp / "legacy" / "extractor.sh")}}}, self.tmp)
        run_id = self.run_audit(config, tool_names=["cloc", "gitleaks", "gittools"])
        before = sorted(e["fingerprint"] for e in self.db.entities(run_id, "secret"))
        report = self.data / "runs" / run_id / "repo-git" / "gittools" / "extract" / "report.json"
        old = json.loads(report.read_text())
        for key in ("flavor", "scan_root"):
            old.pop(key)
        for c in old["commits"]:
            c.pop("dir")                                                                                # et même sans la correspondance de dossiers
        report.write_text(json.dumps(old))
        from aule.orchestrator import reparse
        reparse(self.db, self.data, run_id, config, log=lambda *_: None)
        self.assertEqual(sorted(e["fingerprint"] for e in self.db.entities(run_id, "secret")), before)


class VersionTest(AuditCase):
    def exe(self):
        return TOOL.resolve(parse_config({}, self.tmp).tool("gittools"))

    def test_the_real_tool_answers_version_and_it_is_shown(self):
        self.assertEqual(tool_version(TOOL, self.exe()), "git-extractor-rs 0.1.0")                       # clap `version` : « <nom> <version> » (lu dans le code)

    def test_a_build_without_the_flag_is_never_shown_as_a_version(self):
        with mock.patch.dict(os.environ, {"FAKE_EXTRACTOR_NO_VERSION": "1"}):
            self.assertIsNone(tool_version(TOOL, self.exe()))                                            # erreur d'usage (code 2) : pas une version

    def test_the_legacy_script_is_never_asked_for_a_version(self):
        fakes.install(self.tmp / "legacy", extractor=None, legacy_extractor="extractor.sh", cloc=None, gitleaks=None)
        exe = TOOL.resolve(parse_config({"tools": {"gittools": {"path": str(self.tmp / "legacy" / "extractor.sh")}}}, self.tmp).tool("gittools"))
        argv = self.tmp / "legacy-argv.log"
        with mock.patch.dict(os.environ, {"FAKE_ARGV": str(argv)}):
            self.assertIsNone(tool_version(TOOL, exe))
        self.assertFalse(argv.exists(), argv.read_text() if argv.exists() else "")                       # le script n'a pas été lancé (il lirait « --version » comme un dépôt)

    def test_other_tools_keep_their_first_line_behavior(self):
        self.assertEqual(load_plugins()["cloc"].parse_version("2.00\nautre", 0), "2.00")
        self.assertIsNone(load_plugins()["cloc"].parse_version("", 0))


class AliasTest(unittest.TestCase):
    def test_gitdump_and_friends_designate_gittools(self):
        for name in ("gitdump", "git-extractor", "git-extractor-rs", "git-tools-rs", "extractor", "gittools"):
            self.assertEqual([t.name for t in select_tools(parse_config({}, Path(".")), [name])], ["gittools"], name)
        cfg = parse_config({"tools": {"gitdump": {"enabled": True, "options": {"threads": 2}}}}, Path("."))
        self.assertEqual(cfg.tool("gittools").options, {"threads": 2})                                  # le YAML sous un alias est la config de gittools
        self.assertEqual([t.name for t in select_tools(cfg)], ["cloc", "gitleaks", "gittools", "links"])

    def test_naming_it_twice_is_refused(self):
        with self.assertRaisesRegex(ConfigError, "configuré deux fois"):
            parse_config({"tools": {"gittools": {"enabled": True}, "gitdump": {"enabled": False}}}, Path("."))

    def test_unknown_names_still_fail_and_list_the_real_one(self):
        with self.assertRaisesRegex(ValueError, r"inconnu.*gitdumper.*disponibles.*gittools"):
            select_tools(parse_config({}, Path(".")), ["gitdumper"])


class RealSchemaTest(AuditCase):
    """Les schémas de sortie viennent du CODE de git-extractor-rs (src/main.rs) : le faux doit les respecter, sinon nos tests ne prouvent rien."""

    def setUp(self):
        super().setUp()
        self.run_id = self.run_audit(tool_names=["gittools"])
        self.out = self.data / "runs" / self.run_id / "repo-git" / "gittools" / "extract" / "extracted"

    def test_the_fake_writes_the_documented_json(self):
        snaps = json.loads((self.out / "metadata" / "snapshots.json").read_text())
        self.assertEqual(set(snaps[0]), {"commit", "directory", "date", "timestamp", "tz_offset", "files"})
        self.assertEqual([x["directory"] for x in snaps], sorted(x["directory"] for x in snaps))               # trié par dossier, comme l'outil
        objects = json.loads((self.out / "metadata" / "objects.json").read_text())
        self.assertEqual(set(objects[0]), {"hash", "object_type", "size", "path"})
        report = json.loads((self.out / "report.json").read_text())
        self.assertEqual(set(report), {"repository", "total_objects", "counts", "includes_unreachable_objects"})
        self.assertEqual(report["total_objects"], len(objects))

    def test_files_come_from_the_snapshot_index_and_match_the_disk(self):
        report = json.loads((self.data / "runs" / self.run_id / "repo-git" / "gittools" / "extract" / "report.json").read_text())
        for c in report["commits"]:
            on_disk = sum(1 for f in (self.out / "snapshots" / c["dir"]).rglob("*") if f.is_file())
            self.assertEqual((c["files"], c["files"] > 0), (on_disk, True), c["dir"])

    def test_the_index_is_optional_and_never_trusted_blindly(self):
        good = GitTools._collect_rust(self.out)
        idx = self.out / "metadata" / "snapshots.json"
        original = idx.read_text()
        for broken in ("{pas du json", "[]", '{"commit": "x"}', '[{"commit": 1}, "texte", null]'):
            idx.write_text(broken)
            degraded = GitTools._collect_rust(self.out)
            self.assertEqual([(c["hash"], c["dir"]) for c in degraded], [(c["hash"], c["dir"]) for c in good], broken)    # repli : mêmes dossiers via les noms
            self.assertTrue(all(c["files"] is None for c in degraded))                                       # mais plus de comptage
        idx.unlink()
        self.assertEqual([c["dir"] for c in GitTools._collect_rust(self.out)], [c["dir"] for c in good])
        evil = json.loads(original)
        evil[0].update(directory="../../../etc", files=True)
        evil[1].update(directory="n-importe-quoi", files=-1)
        idx.write_text(json.dumps(evil))
        result = GitTools._collect_rust(self.out)
        self.assertEqual([c["dir"] for c in result], [c["dir"] for c in good])                              # un nom invalide ou hors dossier n'est jamais retenu
        counts = [c["files"] for c in result]
        self.assertNotIn(-1, counts)                                                                         # un nombre négatif n'a pas de sens
        self.assertNotIn(True, counts)                                                                       # et un booléen n'est pas un nombre de fichiers

    def test_the_index_timestamp_orders_commits_whose_payload_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "x"
            late, early = H(1), H(2)
            for h in (late, early):
                (out / "snapshots" / f"20261117-1633_{h}").mkdir(parents=True)
            (out / "metadata").mkdir()
            (out / "metadata" / "snapshots.json").write_text(json.dumps([
                {"commit": late, "directory": f"20261117-1633_{late}", "date": "20261117-1633", "timestamp": 1700000500, "tz_offset": "+0000", "files": 2},
                {"commit": early, "directory": f"20261117-1633_{early}", "date": "20261117-1633", "timestamp": 1700000100, "tz_offset": "+0000", "files": 1}]))
            self.assertEqual([c["hash"] for c in GitTools._collect_rust(Path(out))], [early, late])


class GhostCase(AuditCase):
    def ghost(self, files: dict[str, str]) -> str:
        """Commit orphelin : aucune référence n'y mène (branche supprimée, historique réécrit)."""
        repo = self.root / "repo-git"
        env = {**os.environ, "GIT_AUTHOR_NAME": "Mallory", "GIT_AUTHOR_EMAIL": "m@x.org", "GIT_COMMITTER_NAME": "Mallory", "GIT_COMMITTER_EMAIL": "m@x.org"}
        run = lambda *a, **k: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True, env=env, **k).stdout.strip()  # noqa: E731
        entries = "".join(f"100644 blob {run('hash-object', '-w', '--stdin', input=body)}\t{name}\n" for name, body in files.items())
        return run("commit-tree", run("mktree", input=entries), "-m", "commit orphelin")

    def history(self, run_id):
        return {s["data"]["file"]: s["data"] for s in self.db.entities(run_id, "secret") if s["data"]["mode"] == "history"}


class ReachabilityTest(GhostCase):
    def test_commits_know_whether_a_reference_still_reaches_them(self):
        ghost = self.ghost({"vault.py": f'KEY = "{fakes.SECRET_A}"\n'})
        run_id = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"])
        reach = {c["data"]["hash"]: c["data"]["reachable"] for c in self.db.entities(run_id, "commit")}
        self.assertEqual({h: reach[h] for h in self.commits}, {self.commits[0]: True, self.commits[1]: True})
        self.assertIs(reach[ghost], False)

    def test_a_secret_only_in_unreachable_commits_is_flagged_and_a_mixed_one_is_not(self):
        self.ghost({"vault.py": f'KEY = "{fakes.SECRET_A}"\n', "settings.py": f'TOKEN = "{fakes.SECRET_B}"\n'})
        hist = self.history(self.run_audit(tool_names=["cloc", "gitleaks", "gittools"]))
        self.assertIs(hist["vault.py"]["unreachable_only"], True)                                           # n'existe que dans un commit orphelin
        self.assertIs(hist["settings.py"]["unreachable_only"], False)                                       # aussi dans l'historique visible : pas « cachée »
        self.assertIs(hist["config.py"]["unreachable_only"], False)
        self.assertEqual(hist["settings.py"]["commits_count"], 3)                                           # 2 commits visibles + l'orphelin

    def test_unknown_is_not_unreachable(self):
        self.assertIsNone(GitTools._reachable(self.tmp / "pas-un-depot"))                                    # git ne sait pas répondre : « inconnu »
        commits = GitTools._collect_rust(Path(tempfile.mkdtemp()), None)
        self.assertEqual(commits, [])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "x"
            (out / "commits").mkdir(parents=True)
            (out / "commits" / H(7)).write_text(commit_payload())
            self.assertIsNone(GitTools._collect_rust(out, None)[0]["reachable"])
            self.assertIs(GitTools._collect_rust(out, set())[0]["reachable"], False)                         # références connues, aucune n'y mène
            self.assertIs(GitTools._collect_rust(out, {H(7)})[0]["reachable"], True)

    def test_the_legacy_flavor_reports_reachability_too(self):
        fakes.install(self.tmp / "legacy", extractor=None, legacy_extractor="extractor.sh", cloc=None, gitleaks=None)
        config = parse_config({"tools": {"gittools": {"path": str(self.tmp / "legacy" / "extractor.sh")}}}, self.tmp)
        run_id = self.run_audit(config, tool_names=["gittools"])
        self.assertEqual({c["data"]["reachable"] for c in self.db.entities(run_id, "commit")}, {True})


@unittest.skipUnless(__import__("shutil").which("node"), "node requis")
class UnreachableUiTest(GhostCase):
    def page(self):
        from aule.report import render_report
        self.ghost({"vault.py": f'KEY = "{fakes.SECRET_A}"\n', "settings.py": f'TOKEN = "{fakes.SECRET_B}"\n'})
        run_id = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"])
        path = self.tmp / "r.html"
        path.write_text(render_report(self.db, run_id, self.data, reveal=True), encoding="utf-8")
        out = json.loads(subprocess.run(["node", str(Path(__file__).parent / "dom_smoke.js"), str(path)], capture_output=True, text=True, timeout=120).stdout)
        return {k.split(" ")[0]: v for k, v in out["tabs"].items()}, {k.split(" ")[0]: v for k, v in out["tabsOpen"].items()}

    def test_the_interface_makes_hidden_history_visible(self):
        tabs, opened = self.page()
        self.assertIn("inaccessible", tabs["Secrets"])                                                       # le secret du commit orphelin porte la pastille...
        self.assertEqual(tabs["Secrets"].count("inaccessible"), 1)                                           # ... et lui seul : settings.py existe aussi dans l'historique visible
        self.assertIn("invisible dans `git log`", opened["Secrets"])
        for expected in ("inaccessibles seulement (1)", "Accès", "inaccessible"):
            self.assertIn(expected, tabs["Historique"])
        self.assertIn("Aucune référence (branche, étiquette, remise) n'atteint ce commit", opened["Historique"])
        self.assertIn("Fichiers de l'instantané", opened["Historique"])


class IncompleteRepositoryTest(AuditCase):
    """git-extractor-rs s'arrête au premier `git archive` en échec (code source) : un .git incomplet n'est pas exploitable avec lui."""

    def test_the_first_failing_archive_stops_everything_with_an_actionable_message(self):
        with mock.patch.dict(os.environ, {"FAKE_EXTRACTOR_ARCHIVE_FAIL": "1"}):
            run_id = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"])
        st = {(r["project_id"], r["tool"], r["mode"]): r for r in self.db.list_tool_runs(run_id)}
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        run = next(r for (pid, tool, mode), r in st.items() if tool == "gittools" and names[pid] == "repo-git")
        self.assertEqual(run["status"], "failed")
        self.assertIn("git archive failed for", run["error"])
        self.assertIn("dépôt incomplet", run["error"])
        self.assertIn("extractor.sh", run["error"])                                                          # la piste : l'autre extracteur, toléré par GitTools
        self.assertEqual(self.db.entities(run_id, "commit"), [])
        by_mode = {(names[pid], mode): r["status"] for (pid, tool, mode), r in st.items() if tool == "gitleaks"}
        self.assertEqual(by_mode[("repo-git", "history")], "skipped")                                       # pas d'instantanés : pas de history...
        self.assertEqual((by_mode[("repo-git", "dir")], by_mode[("repo-git", "git")]), ("ok", "ok"))        # ... mais le reste de l'audit est intact

    def test_an_empty_repository_is_an_error_not_an_empty_success(self):
        empty = self.root / "empty-git"
        empty.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=empty, check=True)
        run_id = self.run_audit(tool_names=["gittools"])
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        run = next(r for r in self.db.list_tool_runs(run_id) if names[r["project_id"]] == "empty-git" and r["tool"] == "gittools")
        self.assertEqual(run["status"], "failed")                                                            # l'outil sort en code 0 sans rien écrire (code source)
        self.assertIn("aucun commit extrait", run["error"])
        ok = next(r for r in self.db.list_tool_runs(run_id) if names[r["project_id"]] == "repo-git" and r["tool"] == "gittools")
        self.assertEqual(ok["status"], "ok")

    def test_the_hint_only_applies_to_that_failure(self):
        self.assertIn("dépôt incomplet", TOOL.failure_hint("code retour 1 : Error: git archive failed for abc: fatal: unable to read tree"))
        self.assertIsNone(TOOL.failure_hint("code retour 1 : Error: not a Git repository: fatal"))
        self.assertIsNone(load_plugins()["gitleaks"].failure_hint("code retour 1 : Error: git archive failed"))   # propre à gittools


class InstalledUnderAnotherNameTest(AuditCase):
    """Cas réel : l'outil est installé sous le nom `git-extractor` (et non `git-extractor-rs`) ; il était déclaré « introuvable »."""

    def setUp(self):
        super().setUp()
        for f in self.bin.glob("git-extractor*"):
            f.unlink()                                                                                   # aucun des deux noms n'est installé...
        fakes.install(self.bin, extractor="git-extractor", cloc=None, gitleaks=None)                       # ... sauf `git-extractor`

    def test_the_tool_is_found_under_its_other_name_and_works(self):
        cfg = parse_config({}, self.tmp).tool("gittools")
        exe = TOOL.resolve(cfg)
        self.assertEqual(Path(exe[-1]).name, "git-extractor")
        run_id = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"])
        self.assertEqual({c["data"]["hash"] for c in self.db.entities(run_id, "commit")}, set(self.commits))
        self.assertTrue(self.db.entities(run_id, "secret"))
        self.assertEqual(flavor_of({}, exe), "rust")                                                       # pas de .sh : c'est bien la variante Rust

    def test_the_primary_name_wins_when_both_exist(self):
        fakes.install(self.bin, extractor="git-extractor-rs", cloc=None, gitleaks=None)
        self.assertEqual(Path(TOOL.resolve(parse_config({}, self.tmp).tool("gittools"))[-1]).name, "git-extractor-rs")

    def test_a_bare_name_in_the_config_is_resolved_through_the_path(self):
        cfg = parse_config({"tools": {"gittools": {"path": "git-extractor"}}}, self.tmp).tool("gittools")
        self.assertEqual(Path(TOOL.resolve(cfg)[-1]).name, "git-extractor")

    def test_when_neither_is_installed_the_message_names_both(self):
        for f in self.bin.glob("git-extractor*"):
            f.unlink()
        cfg = parse_config({}, self.tmp).tool("gittools")
        self.assertIsNone(TOOL.resolve(cfg))
        self.assertEqual(TOOL.wanted(cfg), "git-extractor-rs ou git-extractor")
        lines: list[str] = []
        from aule.orchestrator import run_audit
        run_audit(self.db, self.data, self.root, config=parse_config({}, self.tmp), tool_names=["gittools"], log=lines.append)
        self.assertTrue(any("'git-extractor-rs ou git-extractor' introuvable" in l for l in lines), lines)
        self.assertEqual(TOOL.wanted(parse_config({"tools": {"gittools": {"path": "/opt/x"}}}, self.tmp).tool("gittools")), "/opt/x")      # un chemin configuré : celui-là
        self.assertEqual(load_plugins()["gitleaks"].wanted(cfg), "gitleaks")                                  # les autres outils : inchangé

    def run_tools_command(self, *argv, columns="100"):
        import contextlib, io
        from aule.cli import main
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": columns, "PATH": str(self.bin)}), contextlib.redirect_stdout(out):
            main(["tools", "--data", str(self.data), *argv])
        return out.getvalue()

    def test_the_tools_screen_keeps_the_action_readable_on_a_narrow_terminal(self):
        from aule.ui import strip_ansi
        config = self.tmp / "aule.yaml"
        config.write_text("tools:\n  gittools:\n    enabled: true\n")
        for f in self.bin.glob("git-extractor*"):
            f.unlink()
        for width in ("80", "100"):
            text = strip_ansi(self.run_tools_command("--config", str(config), "--color", "always", columns=width))
            row = next(l for l in text.splitlines() if l.lstrip().startswith("gittools"))
            self.assertIn("introuvable", row)                                                            # la ligne du tableau peut être coupée par une colonne souple...
            self.assertIn("gittools : cherché : git-extractor-rs ou git-extractor", text)                 # ... pas la piste d'action, entière et sur ses propres lignes
            self.assertIn("ajoutez-le au PATH ou renseignez tools.gittools.path dans aule.yaml", text)
            self.assertTrue(all(len(l) <= int(width) for l in text.splitlines()), width)

    def test_legacy_text_output_names_both_too(self):
        for f in self.bin.glob("git-extractor*"):
            f.unlink()
        self.assertIn("INTROUVABLE : 'git-extractor-rs ou git-extractor'", self.run_tools_command("--color", "never"))


class DoctorHintTest(unittest.TestCase):
    def test_the_hint_names_the_real_command_not_the_plugin(self):
        from aule.doctor import _hint
        text = "error: unexpected argument '--threads' found\nUsage: git-extractor-rs <REPO>"
        self.assertEqual(_hint("gittools", text), "version incompatible ? comparez cmd.txt avec `git-extractor-rs --help`")
        self.assertIn("`gitleaks --help`", _hint("gitleaks", text))                                      # inchangé quand le plugin et la commande portent le même nom
        self.assertIn("`aucun-plugin --help`", _hint("aucun-plugin", text))                              # nom inconnu : on garde ce qu'on a


class PackagingTest(unittest.TestCase):
    """Le Dockerfile ne peut pas être construit ici : on vérifie au moins ce qui peut l'être statiquement."""

    def test_image_builds_git_extractor_rs_at_a_pinned_revision(self):
        root = Path(__file__).parent.parent
        dockerfile = (root / "docker" / "Dockerfile").read_text()
        for expected in ("github.com/shoxxdj/git-tools-rs", "--rev \"${GIT_TOOLS_RS_REF}\"", "--locked", "ARG GIT_TOOLS_RS_REF",
                         "COPY --from=gitrs /out/git-extractor-rs /usr/local/bin/git-extractor-rs", "for n in git-extractor-rs git-extractor"):
            self.assertIn(expected, dockerfile, expected)
        self.assertNotIn("internetwache", dockerfile)                                                    # plus de clone de GitTools
        self.assertNotIn("GITTOOLS_COMMIT", dockerfile)
        self.assertNotIn("git-dumper", [l for l in dockerfile.splitlines() if l.startswith("COPY")][0])  # le téléchargeur n'entre pas dans l'image
        self.assertNotIn("extractor.sh", (root / "docker" / "aule.yaml").read_text())
        import yaml
        docker_cfg = yaml.safe_load((root / "docker" / "aule.yaml").read_text())["tools"]["gittools"]
        self.assertEqual(docker_cfg, {"enabled": True})                                                  # activé, SANS chemin : l'exécutable est cherché dans le PATH de l'image

    def test_example_config_documents_the_new_default(self):
        import yaml
        text = (Path(__file__).parent.parent / "aule.example.yaml").read_text()
        cfg = parse_config(yaml.safe_load(text), Path("."))                                                # le modèle reste accepté par le parseur réel
        self.assertEqual(cfg.tool("gittools").options, {})
        for expected in ("git-extractor-rs", "snapshot_date", "threads", "gitdump"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
