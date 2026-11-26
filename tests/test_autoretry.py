"""critiq.auto_retry : une panne passagère du moteur (504, 503, 429, délai dépassé…) est retentée SANS LIMITE ; une erreur permanente n'est jamais attendue pour rien."""
from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import shutil
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import test_critiq as tc
from aule.cli import build_parser, main
from aule.config import ConfigError, parse_config
from aule.critiq import _patiently, critique_unit, run_critique
from aule.llm import LLMError, OllamaProvider, Provider, TRANSIENT_STATUSES, make_provider
from fake_librechat import make_certs
from fake_ollama import verdict
from fake_openai import KEY, FakeOpenAI
from test_custom_llm import conf, oa_responder

# le corps EXACT que renvoyait votre passerelle
GATEWAY_504 = b"<html><body><h1>504 Gateway Time-out</h1>\nThe server didn't respond in time.\n</body></html>\n"
CLEAN_504 = "504 Gateway Time-out The server didn't respond in time."
SCHEMA = {"type": "object"}
MSGS = [{"role": "user", "content": "Q"}]


def plan_responder(first: int, status: int = 504, body=GATEWAY_504):
    """Les `first` premiers appels échouent (comme une longue panne de la passerelle), les suivants répondent normalement."""
    return lambda payload, n: ("http", status, body) if n < first else oa_responder(payload, n)


class ClassificationTest(unittest.TestCase):
    def serve(self, **kw) -> FakeOpenAI:
        fake = FakeOpenAI(**kw).start()
        self.addCleanup(fake.stop)
        return fake

    def error_of(self, fake: FakeOpenAI, **q) -> LLMError:
        with self.assertRaises(LLMError) as ctx:
            make_provider(conf(url=fake.url, retries=0, **q)).chat(MSGS, SCHEMA)
        return ctx.exception

    def test_which_http_statuses_are_passing_failures(self):
        for code in sorted(TRANSIENT_STATUSES):
            fake = self.serve(responder=lambda p, n, c=code: ("http", c, {"error": {"message": "x"}}))
            self.assertTrue(self.error_of(fake).transient, code)
        for code in (400, 401, 403, 404, 422, 500):                                                             # clé refusée, adresse fausse, requête invalide... et le 500 (souvent déterministe)
            fake = self.serve(responder=lambda p, n, c=code: ("http", c, {"error": {"message": "x"}}))
            self.assertFalse(self.error_of(fake).transient, code)
        self.assertEqual(sorted(TRANSIENT_STATUSES), [408, 425, 429, 502, 503, 504, 520, 521, 522, 523, 524])

    def test_your_gateway_error_is_readable_and_passing(self):
        err = self.error_of(self.serve(responder=lambda p, n: ("http", 504, GATEWAY_504)))
        self.assertEqual(str(err), f"le service a répondu 504 — {CLEAN_504}")                                  # une ligne, sans balises (avant : la page HTML entière)
        self.assertTrue(err.transient)

    def test_json_error_details_are_collapsed_to_one_line(self):
        err = self.error_of(self.serve(responder=lambda p, n: ("http", 503, {"error": {"message": "ligne 1\n\n   ligne 2\t fin"}})))
        self.assertEqual(str(err), "le service a répondu 503 — ligne 1 ligne 2 fin")

    def test_network_failures(self):
        self.assertTrue(self.error_of(self.serve(responder=lambda p, n: ("sleep", 3)), timeout=1).transient)    # délai dépassé : passager
        with self.assertRaises(LLMError) as ctx:
            make_provider(conf(url="http://127.0.0.1:1/x", retries=0)).chat(MSGS, SCHEMA)
        self.assertTrue(ctx.exception.transient)                                                                # connexion refusée : le service redémarre peut-être
        with self.assertRaises(LLMError) as ctx:
            make_provider(conf(url="http://hote-qui-n-existe-pas.invalid:81/x", retries=0, allow_remote=True, insecure_http=True)).chat(MSGS, SCHEMA)
        self.assertFalse(ctx.exception.transient)                                                               # nom de domaine inconnu : une faute de frappe, jamais retentée

    @unittest.skipUnless(shutil.which("openssl"), "openssl requis")
    def test_an_unknown_certificate_is_never_retried(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        fake = self.serve(tls=make_certs(tmp))
        self.assertFalse(self.error_of(fake).transient)

    def test_the_transient_rule_on_raw_network_errors(self):
        """Les cas que le réseau réel produit selon la version de Python (une lecture SSL expirée n'est pas toujours un TimeoutError)."""
        import socket
        import ssl
        import urllib.error
        from aule.llm import _HttpBase
        for exc, expected in ((urllib.error.URLError(ConnectionRefusedError()), True), (ConnectionResetError(), True), (socket.timeout("timed out"), True), (TimeoutError(), True),
                              (urllib.error.URLError(ssl.SSLError("The read operation timed out")), True),                  # lecture SSL expirée : passager
                              (urllib.error.URLError(ssl.SSLError("handshake failure")), False), (urllib.error.URLError(ssl.SSLCertVerificationError("CERTIFICATE_VERIFY_FAILED")), False),
                              (urllib.error.URLError(socket.gaierror(-2, "Name or service not known")), False)):
            self.assertEqual(_HttpBase._net_transient(exc), expected, repr(exc))

    def test_answers_that_would_not_change_are_permanent(self):
        garbage = self.serve(responder=lambda p, n: ("http", 200, b"pas du json"))
        self.assertFalse(self.error_of(garbage).transient)
        cut = self.serve(responder=lambda p, n: ("raw", {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}))
        self.assertFalse(self.error_of(cut).transient)                                                          # réponse coupée par max_tokens : le même prompt redonnerait la même coupure
        tool = self.serve(responder=lambda p, n: ("raw", {"choices": [{"message": {"content": None, "tool_calls": [{"type": "function"}]}}]}))
        self.assertFalse(self.error_of(tool).transient)

    def test_ollama_errors_are_classified_too(self):
        for status, expected in ((503, True), (504, True), (404, False), (401, False)):
            fake = self.serve(key="", path="/api/chat", responder=lambda p, n, s=status: ("http", s, {"error": "x"}))
            with self.assertRaises(LLMError) as ctx:
                OllamaProvider(fake.url.rsplit("/api/chat", 1)[0], "m", timeout=5).chat(MSGS, SCHEMA)
            self.assertEqual(ctx.exception.transient, expected, status)
        with self.assertRaises(LLMError) as ctx:
            OllamaProvider("http://127.0.0.1:1", "m", timeout=5).chat(MSGS, SCHEMA)
        self.assertTrue(ctx.exception.transient)

    def test_a_plain_llm_error_is_permanent_by_default(self):
        self.assertFalse(LLMError("x").transient)
        self.assertTrue(LLMError("x", transient=True).transient)


class PatientlyTest(unittest.TestCase):
    cfg = dataclasses.replace(tc.CritiqConfig(), auto_retry=True)

    def failing(self, times: int, transient: bool = True):
        state = {"n": 0}

        def call():
            state["n"] += 1
            if state["n"] <= times:
                raise LLMError("504", transient=transient)
            return "ok"
        return call, state

    def test_the_pauses_grow_then_stay_at_the_cap(self):
        sleeps: list[float] = []
        call, _ = self.failing(9)
        self.assertEqual(_patiently(call, self.cfg, None, sleeps.append), "ok")
        self.assertEqual(sleeps, [5, 10, 20, 40, 80, 160, 300, 300, 300])                                       # 5 s doublé à chaque fois, plafonné à 300 s
        sleeps.clear()
        call, _ = self.failing(6)
        _patiently(call, dataclasses.replace(self.cfg, retry_max_wait=60), None, sleeps.append)
        self.assertEqual(sleeps, [5, 10, 20, 40, 60, 60])                                                       # le plafond est réglable

    def test_there_is_no_limit(self):
        sleeps: list[float] = []
        call, state = self.failing(500)
        self.assertEqual(_patiently(call, self.cfg, None, sleeps.append), "ok")
        self.assertEqual((state["n"], len(sleeps), max(sleeps)), (501, 500, 300))                               # 500 pannes de suite : toujours pas d'abandon

    def test_a_permanent_error_is_raised_at_once_without_waiting(self):
        sleeps: list[float] = []
        call, state = self.failing(5, transient=False)
        with self.assertRaises(LLMError):
            _patiently(call, self.cfg, None, sleeps.append)
        self.assertEqual((state["n"], sleeps), (1, []))

    def test_without_the_option_nothing_changes(self):
        sleeps: list[float] = []
        call, state = self.failing(5)
        with self.assertRaises(LLMError):
            _patiently(call, dataclasses.replace(self.cfg, auto_retry=False), None, sleeps.append)
        self.assertEqual((state["n"], sleeps), (1, []))

    def test_the_callback_sees_each_attempt_and_other_exceptions_pass_through(self):
        seen = []
        call, _ = self.failing(3)
        _patiently(call, self.cfg, lambda a, p, e: seen.append((a, p, str(e))), lambda s: None)
        self.assertEqual(seen, [(1, 5, "504"), (2, 10, "504"), (3, 20, "504")])
        with self.assertRaises(ValueError):
            _patiently(lambda: (_ for _ in ()).throw(ValueError("bug")), self.cfg, None, lambda s: None)
        def stop(_):
            raise KeyboardInterrupt
        call, _ = self.failing(2)
        with self.assertRaises(KeyboardInterrupt):
            _patiently(call, self.cfg, None, stop)                                                              # Ctrl-C pendant l'attente : on sort


class RetryCase(tc.CritiqCase):
    unit_for = tc.CritiqueUnitTest.unit_for

    def setUp(self):
        super().setUp()
        self.oa = FakeOpenAI(responder=oa_responder).start()
        self.addCleanup(self.oa.stop)
        self.engine = conf(url=self.oa.url, retries=0)                                                          # pas de reprises du transport : on teste la patience de la critique
        self.sleeps: list[float] = []

    def auto(self, **kw):
        return dataclasses.replace(self.cfg, auto_retry=True, **kw)

    def run_crit(self, cfg=None, llm=None, sleep=None, **kw):
        lines: list[str] = []
        summary = run_critique(self.db, self.data, self.run_id, cfg or self.cfg, llm=llm or self.engine, log=lines.append, sleep=sleep or self.sleeps.append, **kw)
        self.lines = lines
        return summary


class RunTest(RetryCase):
    def test_without_the_option_three_failures_abort_the_run_as_before(self):
        self.oa.responder = plan_responder(99)
        s = self.run_crit()
        self.assertEqual((s["critiqued"], s["errors"], s["retries"], self.sleeps), (0, 3, 0, []))      # trois constats en erreur, aucun avis
        self.assertEqual(s["aborted"], f"3 erreurs consécutives, arrêt : le service a répondu 504 — {CLEAN_504}")   # lisible : une ligne, sans HTML
        self.assertNotIn("<html>", s["aborted"] + "".join(self.lines))

    def test_with_the_option_a_long_outage_is_waited_out(self):
        self.oa.responder = plan_responder(7)
        s = self.run_crit(self.auto())
        self.assertEqual((s["units"], s["critiqued"], s["errors"], s["retries"], s.get("aborted")), (5, 5, 0, 7, None))
        self.assertEqual(s["verdicts"], {"true_positive": 1, "false_positive": 1, "uncertain": 3})              # les mêmes avis que sans panne
        self.assertEqual(self.sleeps, [5, 10, 20, 40, 80, 160, 300])
        retries = [ln for ln in self.lines if "nouvelle tentative" in ln]
        self.assertEqual(len(retries), 7)
        self.assertIn("n°1 dans 5 s", retries[0])
        self.assertIn("n°7 dans 300 s", retries[-1])
        for expected in (CLEAN_504, "auto_retry", "Ctrl-C pour arrêter", " · "):
            self.assertIn(expected, retries[0])                                                                 # la cause, comment l'arrêter, et le constat concerné

    def test_failures_spread_over_the_run_never_stop_it(self):
        self.oa.responder = lambda p, n: ("http", 503, {"error": {"message": "occupé"}}) if n % 2 == 0 else oa_responder(p, n)
        s = self.run_crit(self.auto())
        self.assertEqual((s["critiqued"], s["errors"], s["verdicts"]), (5, 0, {"true_positive": 1, "false_positive": 1, "uncertain": 3}))
        self.assertGreaterEqual(s["retries"], 5)

    def test_a_permanent_error_still_stops_after_three_and_never_waits(self):
        self.oa.responder = lambda p, n: ("http", 401, {"error": {"message": "clé invalide"}})
        s = self.run_crit(self.auto())
        self.assertEqual((s["critiqued"], s["errors"], s["retries"], self.sleeps), (0, 3, 0, []))              # pas de boucle infinie sur une clé fausse
        self.assertIn("3 erreurs consécutives", s["aborted"])
        self.assertIn("clé d'API refusée (401)", s["aborted"])

    def test_waiting_then_a_permanent_error(self):
        self.oa.responder = lambda p, n: ("http", 504, GATEWAY_504) if n < 2 else ("http", 404, {"error": {"message": "x"}})
        s = self.run_crit(self.auto())
        self.assertEqual((s["retries"], s["errors"], self.sleeps), (2, 3, [5, 10]))                              # deux attentes, puis l'erreur permanente compte comme avant
        self.assertIn("3 erreurs consécutives", s["aborted"])

    def test_the_cap_is_configurable_from_the_run(self):
        self.oa.responder = plan_responder(6)
        self.run_crit(self.auto(retry_max_wait=30))
        self.assertEqual(self.sleeps, [5, 10, 20, 30, 30, 30])

    def test_ctrl_c_keeps_what_was_done_and_the_next_run_resumes(self):
        self.oa.responder = lambda p, n: oa_responder(p, n) if n < 2 else ("http", 504, GATEWAY_504)

        def interrupt(_):
            raise KeyboardInterrupt
        s = self.run_crit(self.auto(), sleep=interrupt)
        self.assertEqual((s["critiqued"], s["errors"]), (2, 0))                                                 # deux avis déjà enregistrés
        self.assertRegex(s["aborted"], r"interrompu \(Ctrl-C\).*conservés")
        self.assertTrue(any("interrompu (Ctrl-C)" in ln for ln in self.lines))
        self.oa.responder = oa_responder                                                                         # le service est rétabli
        s = self.run_crit(self.auto())
        self.assertEqual((s["cached"], s["critiqued"], s.get("aborted")), (2, 3, None))                         # reprise : rien n'est refait

    def test_the_engine_check_at_the_start_is_patient_too(self):
        engine = conf(url=self.oa.url, retries=0, check_url=self.oa.models_url)
        self.oa.models_override = ("http", 504, GATEWAY_504)

        def sleeper(seconds):
            self.sleeps.append(seconds)
            if len(self.sleeps) == 2:
                self.oa.models_override = None                                                                   # le service revient après deux attentes
        s = self.run_crit(self.auto(), llm=engine, sleep=sleeper)
        self.assertEqual((self.sleeps, s["critiqued"], s["retries"]), ([5, 10], 5, 2))
        self.assertTrue(any(ln.startswith("  ! moteur : ") for ln in self.lines))
        self.oa.models_override = ("http", 504, GATEWAY_504)
        with self.assertRaisesRegex(LLMError, "504"):
            self.run_crit(self.cfg, llm=engine)                                                                  # sans l'option : l'erreur remonte comme avant

    def test_dry_run_never_waits(self):
        self.oa.responder = plan_responder(99)
        s = self.run_crit(self.auto(), dry_run=True, show=1)
        self.assertEqual((self.oa.requests, self.sleeps, s["retries"]), ([], [], 0))


class UnitTest(RetryCase):
    def test_only_the_failed_call_is_retried_not_the_rounds_already_obtained(self):
        class Flaky(Provider):
            name, model = "flaky", "m"

            def __init__(self, plan):
                self.plan, self.calls = list(plan), []

            def check(self):
                return []

            def chat(self, messages, schema):
                self.calls.append(json.dumps(messages))
                step = self.plan.pop(0)
                if isinstance(step, Exception):
                    raise step
                return step
        ask = json.dumps(verdict("uncertain", 0.3, "il me faut plus", need=[{"search": "cursor"}]))
        done = json.dumps(verdict("true_positive", 0.9, "ok"))
        u, acc, red = self.unit_for("py/sql-injection")
        p = Flaky([ask, LLMError("504", transient=True), LLMError("504", transient=True), done])
        out = critique_unit(p, u, acc, self.auto(), red, None, sleep=self.sleeps.append)
        self.assertEqual((out.verdict, out.rounds, len(p.calls), self.sleeps), ("true_positive", 2, 4, [5, 10]))
        self.assertEqual(p.calls[1], p.calls[2])
        self.assertEqual(p.calls[2], p.calls[3])                                                                 # le tour 2 est rejoué À L'IDENTIQUE : le tour 1 n'est pas redemandé


class ConfigAndCliTest(RetryCase):
    def test_config(self):
        c = parse_config({}, Path(".")).critiq
        self.assertEqual((c.auto_retry, c.retry_max_wait), (False, 300))
        c = parse_config({"critiq": {"auto_retry": True, "retry_max_wait": 120}}, Path(".")).critiq
        self.assertEqual((c.auto_retry, c.retry_max_wait), (True, 120))
        self.assertEqual(parse_config({"critiq": {"retry_max_wait": 1}}, Path(".")).critiq.retry_max_wait, 5)          # bornes saines
        self.assertEqual(parse_config({"critiq": {"retry_max_wait": 10**9}}, Path(".")).critiq.retry_max_wait, 3600)
        for bad in ("true", "oui", 1, None):
            with self.assertRaisesRegex(ConfigError, "critiq.auto_retry : true ou false"):
                parse_config({"critiq": {"auto_retry": bad}}, Path("."))                                         # « false » en texte serait lu comme vrai

    def test_flags_exist_and_default_to_off(self):
        parser = build_parser()
        self.assertFalse(parser.parse_args(["critiq", "run"]).auto_retry)
        self.assertTrue(parser.parse_args(["critiq", "run", "--auto-retry"]).auto_retry)
        self.assertFalse(parser.parse_args(["run", "x"]).auto_retry)
        self.assertTrue(parser.parse_args(["run", "x", "--critiq", "--auto-retry"]).auto_retry)

    def cli(self, *argv):
        (self.tmp / "aule.yaml").write_text("critiq: {}\n")
        (self.tmp / "llm.yaml").write_text(f"provider: custom\nurl: {self.oa.url}\nmodel: triton\napi_key: {KEY}\napi_key_header: x-ai-api-key\nretries: 0\ntimeout: 20\n")
        (self.tmp / "llm.yaml").chmod(0o600)
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "130"}), mock.patch("aule.critiq.time", types.SimpleNamespace(sleep=self.sleeps.append)), contextlib.redirect_stdout(out):   # seulement le `time` de critiq : pas le sleep global
            code = main(["critiq", "run", *argv, "--data", str(self.data), "--config", str(self.tmp / "aule.yaml"), "--color", "never"])
        return code, out.getvalue()

    def test_the_command_line_option_end_to_end(self):
        self.oa.responder = plan_responder(2)
        code, out = self.cli("--auto-retry")
        self.assertEqual(code, 0)
        self.assertIn("nouvelle tentative n°1 dans 5 s", out)
        self.assertIn("2 relance(s) après panne passagère.", out)
        self.assertEqual(self.sleeps, [5, 10])
        self.assertNotIn("erreurs consécutives", out)                                                           # plus d'abandon
        self.sleeps.clear()
        self.oa.chats = 0
        self.oa.responder = plan_responder(99)
        code, out = self.cli("--force")
        self.assertIn("3 erreurs consécutives, arrêt", out)                                                     # sans l'option : le comportement d'avant
        self.assertEqual(self.sleeps, [])

    def test_the_option_from_the_config_file(self):
        self.oa.responder = plan_responder(1)
        (self.tmp / "aule.yaml").write_text("critiq:\n  auto_retry: true\n  retry_max_wait: 7\n")
        (self.tmp / "llm.yaml").write_text(f"provider: custom\nurl: {self.oa.url}\nmodel: triton\napi_key: {KEY}\napi_key_header: x-ai-api-key\nretries: 0\n")
        (self.tmp / "llm.yaml").chmod(0o600)
        out = io.StringIO()
        with mock.patch("aule.critiq.time", types.SimpleNamespace(sleep=self.sleeps.append)), contextlib.redirect_stdout(out):
            main(["critiq", "run", "--data", str(self.data), "--config", str(self.tmp / "aule.yaml"), "--color", "never"])
        self.assertEqual(self.sleeps, [5])
        self.assertIn("1 relance(s)", out.getvalue())

    def test_ctrl_c_gives_a_clean_exit(self):
        err = io.StringIO()
        with mock.patch("aule.cli.cmd_tools", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["tools", "--data", str(self.tmp), "--color", "never"])
        self.assertEqual(code, 130)
        self.assertIn("interrompu (Ctrl-C)", err.getvalue())

    def test_the_retry_line_is_understood_by_the_forge_screen(self):
        from aule.cli_pretty import RunPrinter
        from aule.ui import Ui, strip_ansi
        ui = Ui().configure(out=io.StringIO(), err=io.StringIO(), mode="always", env={"COLUMNS": "100"})
        with RunPrinter(ui, self.db, None, animate=False) as printer:
            printer.log("Phase 5 : critique IA des résultats")
            printer.log(f"  ! repo-git · py/sql-injection : {CLEAN_504} — nouvelle tentative n°1 dans 5 s (auto_retry ; Ctrl-C pour arrêter)")
        self.assertEqual(printer.unmatched, [])
        self.assertIn("nouvelle tentative n°1 dans 5 s", strip_ansi(ui.out.getvalue()))


if __name__ == "__main__":
    unittest.main()
