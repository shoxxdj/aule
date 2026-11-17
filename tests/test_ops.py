"""Exploitation : doctor, purge, seal/unseal, progression."""
from __future__ import annotations

import contextlib
import io
import math
import os
import re
import shutil
import stat
import subprocess
import types
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

import fakes
from aule import seal as seal_mod
from aule.cli import main
from aule.config import Config
from aule.db import Database
from aule.doctor import make_corpus, run_doctor, summarize
from aule.orchestrator import run_audit
from aule.purge import apply_purge, human, plan_purge
from aule.seal import SealError, seal, unseal, verify
from common import AuditCase, git
from test_sast_deps import make_rules


def entropy(s: str) -> float:
    return -sum(n / len(s) * math.log2(n / len(s)) for n in Counter(s).values())


class DoctorCorpusTest(unittest.TestCase):
    def test_corpus_has_history_and_realistic_secrets(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        project = make_corpus(root)
        log = subprocess.run(["git", "-C", str(project), "log", "--format=%s"], capture_output=True, text=True).stdout.split("\n")
        self.assertEqual([m for m in log if m], ["retire les secrets du code", "import initial"])
        head = (project / "config.py").read_text()
        first = subprocess.run(["git", "-C", str(project), "show", "HEAD~1:config.py"], capture_output=True, text=True).stdout
        tokens = re.findall(r"ghp_[A-Za-z0-9]{36}", first) + re.findall(r"AKIA[A-Z2-7]{16}", first)
        self.assertEqual(len(tokens), 2)
        self.assertTrue(all(t not in head for t in tokens))                    # présents seulement dans l'historique
        self.assertTrue(all(entropy(t[4:]) > 3.3 for t in tokens))             # assez « aléatoires » pour gitleaks
        self.assertRegex((project / "settings.py").read_text(), r"ghp_[A-Za-z0-9]{36}")  # persistant (mode dir)
        self.assertNotIn("EXAMPLE", first)                                     # sinon liste d'exclusion de gitleaks
        root2 = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root2, True)
        self.assertEqual((make_corpus(root2) / "settings.py").read_text(), (project / "settings.py").read_text())  # déterministe


class DoctorTest(AuditCase):
    def setUp(self):
        super().setUp()
        make_rules(self.data / "rules")                                       # data/rules/opengrep-rules

    def doctor(self, **kw):
        checks, kept = run_doctor(Config(), self.data, log=lambda *_: None, **kw)
        return {c.name: c for c in checks}, kept

    def test_everything_installed_passes_and_heavy_tools_are_skipped_without_local_base(self):
        c, _ = self.doctor()
        for name in ("python", "git", "cloc", "gitleaks", "gittools", "links", "trufflehog", "opengrep", "codeql", "checkov", "osv-scanner"):
            self.assertEqual(c[name].status, "PASS", (name, c[name].detail))
        self.assertEqual((c["dependency-check"].status, c["trivy"].status), ("SKIP", "SKIP"))
        self.assertIn("aule update dependency-check", c["dependency-check"].detail)
        self.assertIn("secret(s) dans l'historique", c["gitleaks"].detail)
        self.assertIn("2 commit(s)", c["gittools"].detail)
        self.assertEqual(summarize(list(c.values()))["FAIL"], 0)

    def test_full_runs_the_heavy_tools_too(self):
        c, _ = self.doctor(only=["dependency-check", "trivy"], full=True)
        self.assertEqual((c["dependency-check"].status, c["trivy"].status), ("PASS", "PASS"))

    def test_trivy_runs_when_its_local_base_exists(self):
        home = self.tmp / "home"
        with mock.patch("pathlib.Path.home", return_value=home):
            self.assertEqual(self.doctor(only=["trivy"])[0]["trivy"].status, "SKIP")
            (home / ".cache" / "trivy").mkdir(parents=True)
            self.assertEqual(self.doctor(only=["trivy"])[0]["trivy"].status, "PASS")

    def test_missing_binary_is_skip_with_actionable_hint(self):
        (self.bin / "codeql").unlink()
        c, _ = self.doctor(only=["codeql"])
        self.assertEqual(c["codeql"].status, "SKIP")
        self.assertIn("tools.codeql.path", c["codeql"].hint)

    def test_failure_is_fail_with_stderr_and_hint(self):
        with mock.patch.dict(os.environ, {"FAKE_GITLEAKS_FAIL": "1"}):
            c, _ = self.doctor(only=["gitleaks"])
        self.assertEqual(c["gitleaks"].status, "FAIL")
        self.assertIn("boom", c["gitleaks"].detail)
        with mock.patch.dict(os.environ, {"FAKE_CODEQL_FAIL_ANALYZE": "python"}):
            c, _ = self.doctor(only=["codeql"])
        self.assertEqual(c["codeql"].status, "FAIL")
        self.assertIn("aule update codeql", c["codeql"].hint)                  # indice adapté à l'erreur

    def test_ran_but_found_nothing_is_a_warning_not_a_pass(self):
        shutil.rmtree(self.data / "rules")
        make_rules(self.data / "rules")
        for d in ("python", "javascript", "yaml", "generic"):                   # plus aucune règle pour le jeu de test
            shutil.rmtree(self.data / "rules" / "opengrep-rules" / d)
        c, _ = self.doctor(only=["opengrep"])
        self.assertEqual(c["opengrep"].status, "WARN")
        self.assertIn("non applicable", c["opengrep"].detail)

    def test_missing_rules_are_reported_as_skip_with_the_fix(self):
        shutil.rmtree(self.data / "rules")
        c, _ = self.doctor(only=["opengrep"])
        self.assertEqual(c["opengrep"].status, "SKIP")
        self.assertIn("aule update opengrep", c["opengrep"].detail)

    def test_keep_and_cleanup(self):
        _, kept = self.doctor(only=["cloc"], keep=True)
        self.assertTrue((kept / "corpus" / "sample" / "app.py").exists())
        self.addCleanup(shutil.rmtree, kept, True)
        self.assertIsNone(self.doctor(only=["cloc"])[1])

    def test_unknown_tool(self):
        with self.assertRaisesRegex(ValueError, "inconnu"):
            run_doctor(Config(), self.data, only=["nope"])

    def test_user_config_paths_are_honoured_without_touching_user_data(self):
        from aule.config import parse_config
        (self.bin / "gitleaks").rename(self.tmp / "gl-elsewhere")
        cfg = parse_config({"tools": {"gitleaks": {"path": str(self.tmp / "gl-elsewhere")}}}, self.tmp)
        checks, _ = run_doctor(cfg, self.data, only=["gitleaks"], log=lambda *_: None)
        self.assertEqual({c.name: c.status for c in checks}["gitleaks"], "PASS")
        self.assertFalse((self.data / "audit.db").stat().st_size > 100_000)       # base de l'auditeur non polluée
        self.assertFalse(list((self.data / "runs").glob("*"))) if (self.data / "runs").exists() else None

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--data", str(self.data)])
        return code, out.getvalue(), err.getvalue()

    def test_cli_exit_codes_and_output(self):
        code, out, _ = self.cli("doctor", "--tool", "cloc", "--tool", "gitleaks")
        self.assertEqual(code, 0)
        self.assertIn("✓ cloc", out)
        self.assertIn("Bilan : ", out)
        with mock.patch.dict(os.environ, {"FAKE_GITLEAKS_FAIL": "1"}):
            code, out, _ = self.cli("doctor", "--tool", "gitleaks")
        self.assertEqual(code, 1)
        self.assertIn("✗ gitleaks", out)
        self.assertIn("→", out)
        shutil.rmtree(self.data / "rules" / "opengrep-rules" / "python")
        shutil.rmtree(self.data / "rules" / "opengrep-rules" / "yaml")
        shutil.rmtree(self.data / "rules" / "opengrep-rules" / "javascript")
        shutil.rmtree(self.data / "rules" / "opengrep-rules" / "generic")
        self.assertEqual(self.cli("doctor", "--tool", "opengrep")[0], 0)           # WARN : non bloquant...
        self.assertEqual(self.cli("doctor", "--tool", "opengrep", "--strict")[0], 1)  # ... sauf --strict
        self.assertEqual(self.cli("doctor", "--tool", "nope")[0], 2)


class PurgeTest(AuditCase):
    def setUp(self):
        super().setUp()
        self.runs = [self.run_audit(tool_names=["cloc", "gitleaks"]) for _ in range(3)]  # du plus ancien au plus récent
        self.db.set_triage(self.db.entities(self.runs[2], "secret")[0]["fingerprint"], "confirmed", "à garder")
        self.db.add_finding("plain", "Constat à garder")
        for r in self.runs:
            (self.data / f"report-{r}.html").write_text("<html>")
            (self.data / f"export-{r}-masque.md").write_text("md")

    def paths(self, run):
        return [self.data / "runs" / run, self.data / f"report-{run}.html", self.data / f"export-{run}-masque.md"]

    def test_dry_run_changes_nothing_then_apply_keeps_triage_and_findings(self):
        doomed, items = plan_purge(self.db, self.data, keep=1)
        self.assertEqual(sorted(doomed), sorted(self.runs[:2]))
        self.assertGreaterEqual(len(items), 6)
        self.assertTrue(all(p.exists() for r in self.runs for p in self.paths(r)))      # plan seulement
        self.assertEqual(len(self.db.list_audits()), 3)
        freed = apply_purge(self.db, self.data, doomed, items)
        self.assertGreater(freed, 0)
        self.assertEqual([a["id"] for a in self.db.list_audits()], [self.runs[2]])
        for r in self.runs[:2]:
            self.assertFalse(any(p.exists() for p in self.paths(r)))
        self.assertTrue(all(p.exists() for p in self.paths(self.runs[2])))
        self.assertEqual(self.db.entities(self.runs[2], "secret")[0]["triage_status"], "confirmed")
        self.assertEqual([f["title"] for f in self.db.list_findings()], ["Constat à garder"])
        self.assertEqual(self.db.conn.execute("SELECT COUNT(*) FROM entity WHERE audit_id=?", (self.runs[0],)).fetchone()[0], 0)  # cascade

    def test_selection_by_run_and_age(self):
        self.assertEqual(plan_purge(self.db, self.data, runs=[self.runs[1]])[0], [self.runs[1]])
        with self.assertRaisesRegex(ValueError, "run inconnu"):
            plan_purge(self.db, self.data, runs=["nope"])
        self.db.conn.execute("UPDATE audit SET started_at='2020-01-01T00:00:00+00:00' WHERE id=?", (self.runs[0],))
        self.db.conn.commit()
        self.assertEqual(plan_purge(self.db, self.data, older_than_days=30)[0], [self.runs[0]])
        self.assertEqual(plan_purge(self.db, self.data, older_than_days=30, keep=2)[0], [self.runs[0]])   # union des critères

    def test_never_touches_paths_outside_data_dir(self):
        outside = self.tmp / "evil"
        outside.mkdir()
        (outside / "precious").write_text("x")
        self.db.conn.execute("INSERT INTO audit(id, root, started_at, status) VALUES ('../evil', '/x', '2020-01-01T00:00:00+00:00', 'complete')")
        self.db.conn.commit()
        doomed, items = plan_purge(self.db, self.data, runs=["../evil"])
        self.assertEqual(items, [])                                  # identifiant non conforme : aucun chemin construit
        apply_purge(self.db, self.data, doomed, items)
        self.assertTrue((outside / "precious").exists())

    def test_heavy_removes_bulk_but_keeps_reports_and_runs_usable(self):
        from test_unpack import zip_dir
        zip_dir(self.root / "repo-git", self.root / "plain" / "site.zip", wrapper="repo-main")
        run = self.run_audit(tool_names=["cloc", "gitleaks", "gittools"], unpack=True)
        extracted = list((self.data / "runs" / run).glob("*/gittools/extract/extracted"))
        self.assertTrue(extracted and (self.data / "work" / run).exists())
        doomed, items = plan_purge(self.db, self.data, heavy=True)
        self.assertEqual(doomed, [])
        self.assertEqual({i.kind for i in items} - {"work"}, {"extracted"})
        apply_purge(self.db, self.data, doomed, items)
        self.assertFalse(any(e.exists() for e in extracted))
        self.assertFalse((self.data / "work" / run).exists())
        self.assertTrue(list((self.data / "runs" / run).glob("*/gittools/extract/report.json")))   # rapports bruts conservés
        from aule.report import build_report_data
        d = build_report_data(self.db, run, self.data, reveal=True)                                  # le rapport marche encore
        self.assertTrue(d["secrets"] and not d["warnings"])
        self.assertEqual(len(self.db.list_audits()), 4)

    def test_human_sizes(self):
        self.assertEqual([human(0), human(1023), human(1536), human(5 * 1024 ** 2), human(3 * 1024 ** 3)], ["0 o", "1023 o", "1.5 Ko", "5.0 Mo", "3.0 Go"])

    def test_cli(self):
        def cli(*argv):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                return main([*argv, "--data", str(self.data)]), out.getvalue(), err.getvalue()
        self.assertEqual(cli("purge")[0], 2)
        code, out, _ = cli("purge", "--keep", "1")
        self.assertEqual(code, 0)
        self.assertIn("Plan seulement", out)
        self.assertEqual(len(self.db.list_audits()), 3)
        code, out, _ = cli("purge", "--keep", "1", "--yes")
        self.assertIn("Libéré", out)
        self.assertEqual(len(Database(self.data / "audit.db").list_audits()), 1)
        self.assertEqual(cli("purge", "--run", "nope")[0], 2)


@unittest.skipUnless(shutil.which("gpg") and os.name == "posix", "gpg (POSIX) requis")
class SealTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        home = self.tmp / "gnupg"
        home.mkdir(mode=0o700)
        patcher = mock.patch.dict(os.environ, {"GNUPGHOME": str(home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.data = self.tmp / "data"
        (self.data / "runs" / "r1").mkdir(parents=True)
        (self.data / "runs" / "r1" / "report.json").write_text(f'[{{"Secret": "{fakes.SECRET_A}"}}]')
        (self.data / "audit.db").write_bytes(os.urandom(5000))

    def test_roundtrip(self):
        out = seal(self.data, self.tmp / "data.gpg", "correct horse")
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        raw = out.read_bytes()
        self.assertNotIn(fakes.SECRET_A.encode(), raw)                          # rien en clair
        self.assertNotIn(b"report.json", raw)                                   # même les noms de fichiers
        self.assertEqual(verify(out, "correct horse"), 2)
        dest = unseal(out, self.tmp / "restored", "correct horse")
        self.assertEqual((dest / "data" / "audit.db").read_bytes(), (self.data / "audit.db").read_bytes())
        self.assertIn(fakes.SECRET_A, (dest / "data" / "runs" / "r1" / "report.json").read_text())

    def test_wrong_passphrase_extracts_nothing(self):
        out = seal(self.data, self.tmp / "data.gpg", "good")
        with self.assertRaisesRegex(SealError, "incorrecte ou archive corrompue"):
            unseal(out, self.tmp / "restored", "bad")
        self.assertFalse((self.tmp / "restored" / "data").exists())
        with self.assertRaises(SealError):
            verify(out, "bad")

    def test_tampered_archive_is_detected(self):
        out = seal(self.data, self.tmp / "data.gpg", "pw")
        blob = bytearray(out.read_bytes())
        blob[len(blob) // 2] ^= 0xFF
        out.write_bytes(bytes(blob))
        with self.assertRaises(SealError):
            verify(out, "pw")

    def test_refuses_to_overwrite_and_other_guard_rails(self):
        out = seal(self.data, self.tmp / "data.gpg", "pw")
        with self.assertRaisesRegex(SealError, "existe déjà"):
            seal(self.data, out, "pw")
        unseal(out, self.tmp / "restored", "pw")
        with self.assertRaisesRegex(SealError, "existe déjà"):
            unseal(out, self.tmp / "restored", "pw")                            # n'écrase jamais un data/ existant
        with self.assertRaisesRegex(SealError, "vide"):
            seal(self.data, self.tmp / "x.gpg", "")
        with self.assertRaisesRegex(SealError, "dans le dossier chiffré"):
            seal(self.data, self.data / "inside.gpg", "pw")
        with self.assertRaisesRegex(SealError, "n'est pas un dossier"):
            seal(self.tmp / "nope", self.tmp / "y.gpg", "pw")
        with self.assertRaisesRegex(SealError, "introuvable"):
            unseal(self.tmp / "nope.gpg", self.tmp / "r2", "pw")

    def test_missing_gpg_and_windows_messages(self):
        with mock.patch("aule.seal.shutil.which", return_value=None), self.assertRaisesRegex(SealError, "gpg introuvable"):
            seal(self.data, self.tmp / "z.gpg", "pw")
        with mock.patch.object(seal_mod, "os", types.SimpleNamespace(name="nt")), self.assertRaisesRegex(SealError, "Windows"):
            seal_mod._gpg()

    def test_cli_seal_remove_and_unseal(self):
        def cli(*argv, env=None):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, env or {}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                return main(list(argv)), out.getvalue(), err.getvalue()
        code, out, _ = cli("seal", "--data", str(self.data), "--remove", env={"AULE_PASSPHRASE": "s3cret"})
        self.assertEqual(code, 0)
        self.assertIn("2 fichier(s) vérifié(s)", out)
        self.assertIn("Effacement non sécurisé", out)
        self.assertFalse(self.data.exists())                                    # supprimé APRÈS vérification
        archive = self.tmp / "data.tar.gz.gpg"
        self.assertTrue(archive.exists())
        pw = self.tmp / "pw.txt"
        pw.write_text("s3cret\n")
        code, out, _ = cli("unseal", str(archive), "--to", str(self.tmp / "back"), "--passphrase-file", str(pw))
        self.assertEqual(code, 0)
        self.assertTrue((self.tmp / "back" / "data" / "audit.db").exists())
        code, _, err = cli("unseal", str(archive), "--to", str(self.tmp / "back2"), env={"AULE_PASSPHRASE": "wrong"})
        self.assertEqual(code, 2)
        self.assertIn("incorrecte", err)


    def test_no_passphrase_and_no_terminal_gives_a_clean_error_not_a_traceback(self):
        env = {k: v for k, v in os.environ.items() if k != "AULE_PASSPHRASE"}
        for argv in (["seal", "--data", str(self.data)], ["unseal", str(self.tmp / "x.gpg")]):
            err = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), mock.patch("getpass.getpass", side_effect=EOFError), \
                    contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(argv), 2)
            self.assertIn("phrase secrète requise", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())


class ProgressTest(AuditCase):
    def test_callback_and_counters(self):
        events, lines = [], []
        run_audit(self.db, self.data, self.root, log=lines.append, progress=lambda d, t, p: events.append((d, t, p)),
                  tool_names=["cloc", "gitleaks"])
        by_phase = {}
        for done, total, phase in events:
            by_phase.setdefault(phase, []).append((done, total))
        self.assertEqual(sorted(by_phase), [1])
        seq = by_phase[1]
        self.assertEqual((seq[0][0], seq[-1][0]), (0, seq[-1][1]))                 # de 0 à total
        self.assertEqual([d for d, _ in seq], list(range(len(seq))))                # strictement croissant
        counted = [ln for ln in lines if re.match(r"\s+\(\d+/\d+\) \[", ln)]
        self.assertEqual(len(counted), seq[-1][1])
        self.assertTrue(any("(1/" in ln for ln in counted))

    def test_phases_are_numbered_from_one_in_progress_too(self):
        events = []
        run_audit(self.db, self.data, self.root, log=lambda *_: None, progress=lambda d, t, p: events.append(p),
                  tool_names=["cloc", "gittools", "gitleaks"])
        self.assertEqual(sorted(set(events)), [1, 2])                               # phase 2 = gitleaks history


if __name__ == "__main__":
    unittest.main()
