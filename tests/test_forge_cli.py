"""Le CLI de la forge : mode forge (terminal / --color always) ET texte historique (redirigé / --color never)."""
from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from aule.cli import main
from aule.config import parse_config
from aule.cli_pretty import RunPrinter
from aule.doctor import Check
from aule.orchestrator import run_audit
from aule.ui import Ui, cell_width, strip_ansi
from common import AuditCase
from test_sast_deps import make_rules
import aule.cli_pretty as pretty

SRC = str(Path(__file__).parent.parent / "src")


def forbidden_in_ascii(ch: str) -> bool:
    o = ord(ch)
    return o >= 0x1F000 or 0x2500 <= o <= 0x27BF or o == 0xFE0F or 0x2800 <= o <= 0x28FF


class ForgeCase(AuditCase):
    COLUMNS = "100"

    def cli(self, *argv, color="always", columns=None, extra_env=None):
        out, err = io.StringIO(), io.StringIO()
        env = {"COLUMNS": columns or self.COLUMNS}
        env.update(extra_env or {})
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--data", str(self.data), "--color", color])
        return code, out.getvalue(), err.getvalue()

    def plain(self, text: str) -> str:
        return strip_ansi(text)

    def assert_fits(self, text: str, width: int):
        for line in text.split("\n"):
            self.assertLessEqual(cell_width(line), width, f"ligne trop large ({cell_width(line)} > {width}) : {strip_ansi(line)!r}")


class RunScreenTest(ForgeCase):
    def test_a_pass_tells_the_story_of_the_forge(self):
        self.cli("mission", "init", "Acme 2026 — paie", "--client", "Acme SA")
        code, out, _ = self.cli("run", str(self.root), "--tools", "cloc,gitleaks", "--name", "initial")
        self.assertEqual(code, 0)
        text = self.plain(out)
        for expected in ("⚒️ Aulë · le forgeron de l’audit", "mission « Acme 2026 — paie »", "passage « initial »", "⛏️ Prospection  inventaire et premiers sondages",
                         "✔", "cloc/default", "gitleaks/git", "▕", "⚗️ Alliage", "💎 Terminé — le fruit de la forge", "🗝️ Secrets", "constats", "détections recoupées",
                         "aule serve --open", "aule report --share"):
            self.assertIn(expected, text, expected)
        self.assertLess(text.index("Prospection"), text.index("Alliage"))
        self.assertLess(text.index("Alliage"), text.index("le fruit de la forge"))
        self.assertNotIn("Phase 1 :", text)                                           # le journal brut est mis en scène, pas affiché tel quel
        self.assertIn("\x1b[", out)                                                   # couleurs
        self.assertNotIn("\r", out)                                                   # pas d'animation sans vrai terminal
        self.assertNotIn("\x1b[?25", out)
        self.assert_fits(text, 100)

    def test_every_line_of_a_complete_pass_is_recognized(self):
        """La mise en scène lit le journal texte : un message modifié doit faire échouer CE test, pas dégrader l'écran en silence."""
        config = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(make_rules(self.tmp))}}}}, self.tmp)
        ui = Ui().configure(out=io.StringIO(), err=io.StringIO(), mode="always", env={"COLUMNS": "100"})
        with RunPrinter(ui, self.db, self.root, animate=False) as printer:
            run_id = run_audit(self.db, self.data, self.root, config=config, tool_names=["cloc", "gitleaks", "opengrep", "codeql", "links"],
                               log=printer.log, progress=printer.progress)
        self.assertEqual(printer.unmatched, [], "lignes du journal non reconnues par la mise en scène")
        self.assertEqual((printer.status, printer.run_id), ("complete", run_id))
        text = self.plain(ui.out.getvalue())
        for phase in ("Prospection", "Fonte", "Grande forge"):                         # phases 1, 2 et 4 (opengrep, CodeQL)
            self.assertIn(phase, text)
        self.assertIn("Liens entre projets", text)
        self.assertRegex(text, r"▕█+▏ \d+/\d+")                                       # barre de progression terminée par phase
        self.assertEqual(text.count("▕"), len(re.findall(r"▕", text)))

    def test_errors_and_warnings_in_a_pass_stay_readable(self):
        config = parse_config({"tools": {"gitleaks": {"path": "/nope/gitleaks"}}}, self.tmp)
        ui = Ui().configure(out=io.StringIO(), err=io.StringIO(), mode="always", env={"COLUMNS": "100"})
        with RunPrinter(ui, self.db, self.root, animate=False) as printer:
            run_audit(self.db, self.data, self.root, config=config, tool_names=["cloc", "gitleaks"], log=printer.log, progress=printer.progress)
        text = self.plain(ui.out.getvalue())
        self.assertIn("▲", text)                                                      # outil introuvable : avertissement
        self.assertIn("gitleaks", text)
        self.assertIn("introuvable", text)
        self.assertEqual(printer.unmatched, [])

    def test_the_text_mode_is_the_historical_one(self):
        code, out, _ = self.cli("run", str(self.root), "--tools", "cloc", color="never")
        self.assertEqual(code, 0)
        for expected in ("Run ", "Phase 1 : ", "Terminé : complete"):
            self.assertIn(expected, out)
        self.assertNotIn("\x1b", out)
        self.assertFalse(any(ord(ch) >= 0x2190 and ch not in "→—«»’…×·" for ch in out if ord(ch) > 0x2000), "emoji ou bordure en mode texte")

    def test_ascii_mode_has_no_emoji_and_no_border_characters(self):
        for argv in (["run", str(self.root), "--tools", "cloc,gitleaks"], ["runs"], ["show"], ["tools"]):
            code, out, err = self.cli(*argv, "--ascii")
            text = self.plain(out + err)
            self.assertFalse([ch for ch in text if forbidden_in_ascii(ch)], f"{argv[0]} : {sorted({ch for ch in text if forbidden_in_ascii(ch)})}")
            self.assertIn("\x1b[", out)                                               # toujours en couleur : seuls emoji et bordures sont remplacés


class OtherScreensTest(ForgeCase):
    def setUp(self):
        super().setUp()
        self.cli("mission", "init", "Acme", "--client", "Acme SA")
        self.cli("run", str(self.root), "--tools", "cloc,gitleaks", "--name", "initial", color="never")
        (self.root / "plain" / "keys.py").write_text("KEY = None\n")
        self.cli("run", str(self.root), "--tools", "cloc,gitleaks", "--name", "contre-audit", color="never")

    def test_runs(self):
        text = self.plain(self.cli("runs")[1])
        for expected in ("📜 Passages", "mission « Acme »", "client Acme SA", "Passage", "Identifiant", "Statut", "initial", "contre-audit", "✔ complete"):
            self.assertIn(expected, text)
        self.assert_fits(text, 100)

    def test_show_and_its_detail(self):
        text = self.plain(self.cli("show", "initial")[1])
        for expected in ("Passage initial", "⛰️ repo-git", "🗝️ Secrets", "constat", "🔧 Exécutions", "✔"):
            self.assertIn(expected, text)
        detail = self.plain(self.cli("show", "initial", "--project", "repo-git")[1])
        self.assertIn("[dir]", detail)
        self.assertIn("github-pat", detail)
        self.assert_fits(text + detail, 100)

    def test_tools(self):
        text = self.plain(self.cli("tools", extra_env={"PATH": "/usr/bin:/bin"})[1])
        for expected in ("🧰 Atelier", "Outil", "État", "Modes", "gitleaks", "introuvable", "option"):
            self.assertIn(expected, text)
        self.assert_fits(text, 100)

    def test_diff(self):
        text = self.plain(self.cli("diff", "initial", "contre-audit", "--kind", "secret")[1])
        for expected in ("⚖️ Comparaison", "nouveau(x)", "corrigé(s)", "persistant(s)", "🗝️"):
            self.assertIn(expected, text)
        self.assertRegex(text, r"\n  [-+=] [0-9a-f]{10}")
        self.assert_fits(text, 100)

    def test_triage_list_and_set(self):
        fp = next(e["fingerprint"] for e in self.db.entities(self.db.latest_audit_id(), "secret"))
        out = self.plain(self.cli("triage", "set", "false_positive", fp[:10], "--comment", "fixture")[1])
        self.assertRegex(out, r"✔ \d+ élément\(s\) marqué\(s\) « false_positive »")
        text = self.plain(self.cli("triage", "list")[1])
        for expected in ("🔨 Trempe", "Empreinte", "Triage", "false_positive", "fixture"):
            self.assertIn(expected, text)
        self.assert_fits(text, 100)

    def test_correlate(self):
        text = self.plain(self.cli("correlate", "--show", "5")[1])
        for expected in ("⚗️ Alliage", "secrets", "Vu par", "×2", "same_secret", "groupe de plusieurs détections"):
            self.assertIn(expected, text)
        self.assert_fits(text, 100)

    def test_report_and_errors(self):
        code, out, _ = self.cli("report", "-o", str(self.tmp / "r.html"))
        self.assertIn("✔ Rapport :", self.plain(out))
        self.assertIn("▲ Ce rapport contient des secrets EN CLAIR", self.plain(out))
        code, out, err = self.cli("show", "introuvable")
        self.assertEqual(code, 2)
        self.assertTrue(self.plain(err).startswith("✖ Erreur : run inconnu : 'introuvable'"), err)
        code, out, err = self.cli("show", "introuvable", color="never")
        self.assertTrue(err.startswith("Erreur : run inconnu : 'introuvable'"), err)                   # texte historique, inchangé
        self.assertNotIn("\x1b", err)

    def test_narrow_terminals(self):
        for width in ("60", "80"):
            for argv in (["runs"], ["show", "initial"], ["tools"], ["triage", "list"], ["correlate", "--show", "5"], ["diff", "initial", "contre-audit"]):
                code, out, err = self.cli(*argv, columns=width)
                self.assert_fits(self.plain(out + err), int(width))

    def test_a_whole_pass_and_its_summary_fit_a_narrow_terminal(self):
        for width in ("60", "80"):
            code, out, err = self.cli("run", str(self.root), "--tools", "cloc,gitleaks", "--name", f"etroit-{width}", columns=width)
            self.assertEqual(code, 0)
            text = self.plain(out + err)
            self.assertIn("le fruit de la forge", text)
            self.assert_fits(text, int(width))
            self.assertEqual(len({cell_width(l) for l in text.split("\n") if l.startswith(("╭", "│", "╰"))}), 1)       # le bilan reste un rectangle fermé

    def test_a_very_long_tool_error_is_clipped_to_the_terminal(self):
        run = self.db.latest_audit_id()
        long_error = "jeu de règles introuvable ou vide : " + "/très/long/chemin/" * 12 + "\nsur plusieurs lignes"
        self.db.conn.execute("UPDATE tool_run SET status='error', error=? WHERE id=(SELECT MIN(id) FROM tool_run WHERE audit_id=? AND tool='gitleaks')", (long_error, run))
        self.db.conn.commit()
        for width in ("60", "100"):
            text = self.plain(self.cli("show", columns=width)[1])
            self.assertIn("jeu de règles introuvable", text)
            self.assertIn("…", text)
            self.assert_fits(text, int(width))

    def test_doctor_screen(self):
        checks = [Check("cloc", "PASS", "version 2.00", seconds=0.1), Check("gitleaks", "WARN", "version ancienne", hint="mettez à jour gitleaks", seconds=0.4),
                  Check("codeql", "FAIL", "binaire introuvable " + "x" * 120, hint="renseignez tools.codeql.path"), Check("trivy", "SKIP", "option non activée")]
        ui = Ui().configure(out=io.StringIO(), err=io.StringIO(), mode="always", env={"COLUMNS": "80"})
        pretty.doctor(ui, checks, "/tmp/kept", strict=False)
        text = self.plain(ui.out.getvalue())
        for expected in ("cloc", "PASS", "WARN", "FAIL", "SKIP", "→ gitleaks : mettez à jour gitleaks", "→ codeql : renseignez tools.codeql.path", "Banc d'essai",
                         "1 ok", "1 avertissement(s)", "1 échec(s)", "1 ignoré(s)", "Données de test conservées : /tmp/kept"):
            self.assertIn(expected, text, expected)
        self.assert_fits(text, 80)
        self.assertEqual(len({cell_width(l) for l in text.split("\n") if l.startswith(("╭", "│", "╰"))}), 1)       # le panneau est un rectangle fermé


class GlobalOptionsTest(ForgeCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "100"}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_options_work_before_and_after_the_command(self):
        self.run_audit(tool_names=["cloc"])
        for argv in (["runs", "--data", str(self.data), "--color", "never"], ["--data", str(self.data), "--color", "never", "runs"],
                     ["--color", "never", "runs", "--data", str(self.data)]):
            code, out, _ = self.run_cli(*argv)
            self.assertEqual(code, 0, argv)
            self.assertIn("complete", out)
            self.assertNotIn("\x1b", out)
        other = self.tmp / "autre"
        code, out, _ = self.run_cli("--data", str(self.data), "runs", "--data", str(other))        # le plus proche de la commande l'emporte
        self.assertNotIn("complete", out)
        code, out, _ = self.run_cli("--data", str(self.data), "--color", "always", "runs", "--color", "never")
        self.assertNotIn("\x1b", out)

    def test_defaults_are_unchanged_when_nothing_is_given(self):
        self.addCleanup(os.chdir, os.getcwd())                                         # ne laisse jamais le processus dans un dossier supprimé
        os.chdir(self.tmp)
        code, out, _ = self.run_cli("tools")
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out)                                               # sortie non terminale : texte historique par défaut


class WebBrandTest(ForgeCase):
    def test_the_web_page_carries_the_forge_identity(self):
        from aule.report import render_report
        run = self.run_audit(tool_names=["cloc"])
        html = render_report(self.db, run, self.data)
        self.assertIn('<div class="brand">⚒️ Aulë <span>· le forgeron de l’audit</span></div>', html)
        self.assertIn('rel="icon" href="data:image/svg+xml', html)               # icône intégrée : la CSP n'autorise que data: pour les images
        self.assertNotIn("http://", html.split("<title>")[1].split("</head>")[0].replace("http://www.w3.org/2000/svg", ""))   # aucune ressource externe en en-tête
        self.assertEqual(html.count("</script>"), 2)


@unittest.skipUnless(sys.platform.startswith("linux"), "pseudo-terminal : Linux")
class RealTerminalTest(ForgeCase):
    def spawn(self, *argv, tty: bool, env=None):
        import pty
        full_env = {"PATH": os.environ["PATH"], "PYTHONPATH": SRC, "HOME": str(self.tmp), "COLUMNS": "100", "TERM": "xterm-256color", **(env or {})}
        cmd = [sys.executable, "-m", "aule", *argv, "--data", str(self.data)]
        if not tty:
            proc = subprocess.run(cmd, capture_output=True, text=True, env=full_env, timeout=120)
            return proc.returncode, proc.stdout
        master, slave = pty.openpty()
        proc = subprocess.Popen(cmd, stdout=slave, stderr=slave, stdin=subprocess.DEVNULL, env=full_env)
        os.close(slave)
        chunks = b""
        while True:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            chunks += data
        os.close(master)
        return proc.wait(timeout=60), chunks.decode("utf-8", "replace")

    def test_detection_follows_the_terminal(self):
        self.spawn("run", str(self.root), "--tools", "cloc,gitleaks", "--name", "initial", tty=False)
        code, piped = self.spawn("runs", tty=False)
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", piped)                                               # redirigé : texte historique
        self.assertIn("initial", piped)
        self.assertNotIn("Passages", piped)
        code, tty = self.spawn("runs", tty=True)
        self.assertIn("\x1b[", tty)                                                   # terminal : la forge
        self.assertIn("Passages", tty)
        for env in ({"NO_COLOR": "1"}, {"TERM": "dumb"}):
            code, out = self.spawn("runs", tty=True, env=env)
            self.assertNotIn("\x1b", out, env)                                        # NO_COLOR / TERM=dumb : texte simple, même sur un terminal

    def test_live_progress_on_a_real_terminal(self):
        code, out = self.spawn("run", str(self.root), "--tools", "cloc,gitleaks", tty=True)
        self.assertEqual(code, 0)
        self.assertIn("\x1b[?25l", out)                                               # curseur masqué pendant la progression
        self.assertGreater(out.index("\x1b[?25h"), out.index("\x1b[?25l"))              # ... et rendu, avant le bilan final
        self.assertLess(out.index("\x1b[?25h"), out.index("le fruit de la forge"))
        self.assertIn("\x1b[2K", out)                                                 # ligne de progression redessinée sur place
        text = self.plain(out.replace("\r", "\n"))
        for expected in ("Prospection", "le fruit de la forge"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
