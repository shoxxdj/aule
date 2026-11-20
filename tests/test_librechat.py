"""LibreChat (API Agents) comme moteur de critique : jeton, sûreté du transport, protocole, résilience, intégration, CLI."""
from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fakes
import aule.llm as llm_mod
from aule.cli import main
from aule.config import ConfigError
from aule.llmconf import LLMConfig, parse_llm
from aule.critiq import run_critique
from aule.llm import LLMError, LibreChatProvider, agents_url, extract_text, fold_messages, make_provider, scrub
from aule.orchestrator import run_audit
from aule.ui import strip_ansi
from fake_librechat import TOKEN, FakeLibreChat, make_certs, verdict_json
from fake_ollama import user_text, verdict
from test_critiq import CritiqCase, default_responder

AGENT = "agent_abc123"
SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}


def lc_responder(payload, n):
    messages = payload.get("messages") or payload.get("input") or []          # Chat Completions : messages ; Open Responses : input
    return json.dumps(default_responder({"messages": messages}, n))


def cfg_for(fake: FakeLibreChat, **kw) -> LLMConfig:
    return LLMConfig(provider="librechat", url=fake.url, model=AGENT, api_key=TOKEN, timeout=20, **kw)


class FakeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = FakeLibreChat().start()
        self.addCleanup(self.fake.stop)

    def provider(self, **kw) -> LibreChatProvider:
        kw.setdefault("timeout", 10)
        return LibreChatProvider(self.fake.url, kw.pop("agent", AGENT), kw.pop("token", TOKEN), **kw)


class ConfigTest(unittest.TestCase):
    def test_a_librechat_file(self):
        base = Path("/etc/aule")
        q = parse_llm({"provider": "librechat", "url": "https://chat.exemple.fr/", "model": AGENT, "api_key": TOKEN, "allow_remote": True, "endpoint": "responses",
                       "ca_file": "pki/ca.pem", "proxy": "env"}, base, base / "llm.yaml")
        self.assertEqual((q.provider, q.url, q.model, q.api_key, q.endpoint, q.proxy, q.allow_remote), ("librechat", "https://chat.exemple.fr", AGENT, TOKEN, "responses", "env", True))
        self.assertEqual((q.ca_file, q.source), ("/etc/aule/pki/ca.pem", "/etc/aule/llm.yaml"))                   # chemins relatifs à llm.yaml
        d = parse_llm({"provider": "librechat", "url": "https://x"}, base)
        self.assertEqual((d.endpoint, d.api_key, d.proxy, d.retries, d.insecure_http), ("chat_completions", None, None, 2, False))

    def test_the_key_lives_in_the_file_and_is_never_shown(self):
        q = parse_llm({"provider": "librechat", "url": "https://x", "api_key": TOKEN}, Path("."))                  # LibreChat accepte désormais la clé dans le fichier
        self.assertNotIn(TOKEN, repr(q))
        for bad in (f"{TOKEN} suite", f"{TOKEN}\nX-Injected: 1", "jeton-é", ""):
            with self.assertRaises(ConfigError) as ctx:
                parse_llm({"provider": "librechat", "url": "https://x", "api_key": bad}, Path("."))
            self.assertIn("api_key", str(ctx.exception))
            self.assertNotIn("lc-9f8e", str(ctx.exception))                                                      # le message ne recopie jamais la clé

    def test_other_mistakes(self):
        for bad, msg in (({"provider": "librechat"}, "url : requise"), ({"provider": "openai"}, "ollama.*librechat"), ({"provider": "librechat", "url": "https://x", "endpoint": "ws"}, "endpoint"),
                         ({"provider": "librechat", "url": "ftp://x"}, "URL http"), ({"provider": "librechat", "url": "https://u:p@x"}, "pas d'identifiants"),
                         ({"provider": "librechat", "url": "https://x", "proxy": "pas-un-proxy"}, "proxy"), ({"provider": "librechat", "url": "https://x", "retries": 9}, "retries")):
            with self.assertRaisesRegex(ConfigError, msg):
                parse_llm(bad, Path("."))


class KeyTest(unittest.TestCase):
    """La clé vient de llm.yaml : jamais de l'environnement, jamais d'un fichier annexe."""

    def test_a_missing_key_points_to_the_file(self):
        engine = LLMConfig(provider="librechat", url="http://127.0.0.1:3080", model=AGENT)
        with self.assertRaises(LLMError) as ctx:
            make_provider(engine)
        self.assertRegex(str(ctx.exception), r"clé d'API LibreChat absente.*`api_key`.*llm\.yaml.*Clés d'API d'agents")

    def test_the_environment_is_never_consulted(self):
        engine = LLMConfig(provider="librechat", url="http://127.0.0.1:3080", model=AGENT)
        with mock.patch.dict(os.environ, {"LIBRECHAT_API_KEY": TOKEN, "AULE_API_KEY": TOKEN}):
            with self.assertRaisesRegex(LLMError, "clé d'API LibreChat absente"):
                make_provider(engine)                                                                            # la variable de l'ancienne version n'est plus lue
            self.assertEqual(make_provider(dataclasses.replace(engine, api_key=TOKEN))._token, TOKEN)

    def test_a_loose_file_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "llm.yaml"
            f.write_text("x: 1\n")
            engine = LLMConfig(provider="librechat", url="http://127.0.0.1:3080", model=AGENT, api_key=TOKEN, source=str(f))
            f.chmod(0o644)
            self.assertIn("lisible par d'autres utilisateurs", make_provider(engine).warnings[0])
            self.assertIn("chmod 600", make_provider(engine).warnings[0])
            f.chmod(0o600)
            self.assertEqual(make_provider(engine).warnings, [])


class UrlSafetyTest(unittest.TestCase):
    def test_url_normalization(self):
        for given in ("https://chat.exemple.fr", "https://chat.exemple.fr/", "https://chat.exemple.fr/api/agents/v1", "https://chat.exemple.fr/api/agents/v1/chat/completions",
                      "https://chat.exemple.fr/api/agents/v1/models"):
            self.assertEqual(agents_url(given), "https://chat.exemple.fr/api/agents/v1", given)
        self.assertEqual(agents_url("http://localhost:3080"), "http://localhost:3080/api/agents/v1")
        self.assertEqual(agents_url("https://h/prefixe"), "https://h/prefixe/api/agents/v1")                  # LibreChat derrière un préfixe

    def test_a_remote_server_needs_explicit_consent_and_https(self):
        remote = LLMConfig(provider="librechat", url="https://chat.exemple.invalid", model=AGENT, api_key=TOKEN)
        with self.assertRaisesRegex(LLMError, "n'est pas un endpoint local.*allow_remote"):
            make_provider(remote)
        ok = dataclasses.replace(remote, allow_remote=True)
        self.assertIsInstance(make_provider(ok), LibreChatProvider)
        plain_http = dataclasses.replace(ok, url="http://chat.exemple.invalid")
        with self.assertRaisesRegex(LLMError, "NON chiffrés"):
            make_provider(plain_http)                                                                           # la clé ne circule jamais en clair par accident
        self.assertIsInstance(make_provider(dataclasses.replace(plain_http, insecure_http=True)), LibreChatProvider)
        self.assertIsInstance(make_provider(LLMConfig(provider="librechat", url="http://localhost:3080", model=AGENT, api_key=TOKEN)), LibreChatProvider)

    def test_the_key_is_checked_only_after_the_safety_checks(self):
        remote = LLMConfig(provider="librechat", url="https://chat.exemple.invalid", model=AGENT)
        with self.assertRaisesRegex(LLMError, "endpoint local"):
            make_provider(remote)                                                                               # refus d'abord, clé manquante ensuite


class ProtocolTest(FakeCase):
    def test_request_shape_and_headers(self):
        p = self.provider()
        self.assertEqual(p.check(), ["agent_abc123", "agent_autre"])
        p.chat([{"role": "system", "content": "SYSTEME"}, {"role": "user", "content": "QUESTION"}], SCHEMA)
        get, post = self.fake.requests
        self.assertEqual((get["method"], get["path"]), ("GET", "/api/agents/v1/models"))
        self.assertEqual((post["method"], post["path"]), ("POST", "/api/agents/v1/chat/completions"))
        for req in (get, post):
            self.assertEqual(req["headers"]["authorization"], f"Bearer {TOKEN}")
        self.assertEqual(post["headers"]["content-type"], "application/json")
        body = post["json"]
        self.assertEqual(set(body), {"model", "messages", "stream"})                                        # pas de response_format, temperature ni outils
        self.assertEqual((body["model"], body["stream"]), (AGENT, False))

    def test_system_message_and_schema_are_folded_into_the_first_user_message(self):
        msgs = [{"role": "system", "content": "SYSTEME"}, {"role": "user", "content": "Q1"}, {"role": "assistant", "content": "R1"}, {"role": "user", "content": "Q2"}]
        out = fold_messages(msgs, SCHEMA)
        self.assertEqual([m["role"] for m in out], ["user", "assistant", "user"])                           # plus de rôle « system » : l'agent a ses propres instructions
        self.assertTrue(out[0]["content"].startswith("<instructions>\nSYSTEME"))
        self.assertIn("ONE JSON object", out[0]["content"])
        self.assertIn(json.dumps(SCHEMA), out[0]["content"])
        self.assertTrue(out[0]["content"].endswith("Q1"))
        self.assertEqual((out[1]["content"], out[2]["content"]), ("R1", "Q2"))

    def test_open_responses_interface(self):
        p = self.provider(endpoint="responses")
        text = p.chat([{"role": "system", "content": "S"}, {"role": "user", "content": "Q"}], SCHEMA)
        self.assertEqual(json.loads(text)["verdict"], "uncertain")                                          # l'élément « reasoning » est ignoré
        post = self.fake.requests[-1]
        self.assertEqual(post["path"], "/api/agents/v1/responses")
        self.assertEqual(set(post["json"]), {"model", "input", "stream"})
        self.assertEqual(post["json"]["input"][0]["role"], "user")

    def test_usage_is_counted_for_billing(self):
        p = self.provider()
        for _ in range(3):
            p.chat([{"role": "user", "content": "Q"}], SCHEMA)
        self.assertEqual(p.tokens, 360)
        r = self.provider(endpoint="responses")
        r.chat([{"role": "user", "content": "Q"}], SCHEMA)
        self.assertEqual(r.tokens, 120)

    def test_response_shapes(self):
        parts = {"choices": [{"message": {"role": "assistant", "content": [{"type": "text", "text": '{"a":'}, {"type": "text", "text": " 1}"}]}}]}
        self.assertEqual(extract_text(parts, "chat_completions"), '{"a": 1}')
        self.assertEqual(extract_text({"output_text": "directe"}, "responses"), "directe")
        for bad, endpoint, msg in (([], "chat_completions", "objet JSON"), ({"choices": []}, "chat_completions", "sans choix"),
                                   ({"choices": [{"message": {"content": "  "}}]}, "chat_completions", "vide"),
                                   ({"error": {"message": "quota épuisé"}}, "chat_completions", "quota épuisé"),
                                   ({"status": "failed", "output": []}, "responses", "failed")):
            with self.assertRaisesRegex(LLMError, msg):
                extract_text(bad, endpoint)

    def test_an_agent_that_calls_a_tool_is_refused(self):
        for endpoint, raw in (("chat_completions", {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "web_search"}}]}}]}),
                              ("chat_completions", {"choices": [{"message": {"content": "ok", "function_call": {"name": "x"}}}]}),
                              ("responses", {"output": [{"type": "web_search_call", "status": "completed"}, {"type": "message", "content": [{"type": "output_text", "text": "{}"}]}]}),
                              ("responses", {"output": [{"type": "function_call", "name": "run_code", "call_id": "c"}]})):
            with self.assertRaisesRegex(LLMError, r"tenté d'utiliser un outil.*sans aucun outil"):
                extract_text(raw, endpoint, AGENT)

    def test_check_diagnostics(self):
        with self.assertRaisesRegex(LLMError, r"aucun agent configuré.*agent_abc123, agent_autre"):
            self.provider(agent="").check()
        with self.assertRaisesRegex(LLMError, r"agent « agent_absent » introuvable.*agent_abc123, agent_autre"):
            self.provider(agent="agent_absent").check()
        with self.assertRaises(LLMError) as ctx:
            self.provider(token="mauvais-jeton-0123456789").check()
        self.assertIn("jeton refusé (401)", str(ctx.exception))
        self.assertNotIn("mauvais-jeton", str(ctx.exception))
        self.fake.models_override = ("http", 403, {"error": {"message": "Remote agents disabled"}})
        with self.assertRaisesRegex(LLMError, r"accès refusé \(403\).*Remote Agents.*Remote agents disabled"):
            self.provider().check()
        self.fake.models_override = ("http", 404, {"error": {"message": "Not Found"}})
        with self.assertRaisesRegex(LLMError, r"API Agents introuvable.*sans API Agents"):
            self.provider().check()
        with self.assertRaisesRegex(LLMError, r"agent « agent_absent » introuvable ou non accessible avec ce jeton \(404\)"):
            self.provider(agent="agent_absent").chat([{"role": "user", "content": "Q"}], SCHEMA)

    def test_the_provider_never_shows_its_token(self):
        p = self.provider(origin="llm.yaml")
        shown = repr(p) + str(p) + "\n".join(p.describe())
        self.assertNotIn(TOKEN, shown)
        self.assertIn("token=***", repr(p))
        self.assertIn("jeton : lu dans llm.yaml (35 caractères, jamais affiché)", p.describe())


class ResilienceTest(FakeCase):
    def test_rate_limit_is_retried_politely(self):
        self.fake.responder = lambda payload, n: ("http", 429, {"error": {"message": "slow down"}}, {"Retry-After": "0"}) if n < 2 else verdict_json("false_positive", 0.9)
        out = self.provider().chat([{"role": "user", "content": "Q"}], SCHEMA)
        self.assertEqual(json.loads(out)["verdict"], "false_positive")
        self.assertEqual(self.fake.chats, 3)
        self.fake.chats = 0
        self.fake.responder = lambda payload, n: ("http", 503, {"error": {"message": "busy"}}, {"Retry-After": "0"})
        with self.assertRaisesRegex(LLMError, "503|indisponible|busy"):
            self.provider().chat([{"role": "user", "content": "Q"}], SCHEMA)
        self.assertEqual(self.fake.chats, 3)                                                                # trois essais, pas plus
        self.fake.chats = 0
        self.fake.responder = lambda payload, n: ("http", 429, {"error": {"message": "quota"}}, {"Retry-After": "0"})
        with self.assertRaisesRegex(LLMError, r"limite de débit.*429.*quota"):
            self.provider().chat([{"role": "user", "content": "Q"}], SCHEMA)

    def test_server_errors_are_not_retried_and_other_failures_are_clear(self):
        self.fake.responder = lambda payload, n: ("http", 500, {"error": {"message": "model crashed"}})
        with self.assertRaisesRegex(LLMError, r"répondu 500 — model crashed"):
            self.provider().chat([{"role": "user", "content": "Q"}], SCHEMA)
        self.assertEqual(self.fake.chats, 1)
        self.fake.responder = lambda payload, n: ("sleep", 3)
        with self.assertRaisesRegex(LLMError, "délai de 1s dépassé"):
            self.provider(timeout=1).chat([{"role": "user", "content": "Q"}], SCHEMA)
        self.fake.responder = lambda payload, n: ("http", 200, b"pas du json")
        with self.assertRaisesRegex(LLMError, "illisible"):
            self.provider().chat([{"role": "user", "content": "Q"}], SCHEMA)
        with self.assertRaisesRegex(LLMError, "injoignable"):
            LibreChatProvider("http://127.0.0.1:1", AGENT, TOKEN, timeout=3).check()

    def test_a_redirect_never_carries_the_token_elsewhere(self):
        thief = FakeLibreChat().start()
        self.addCleanup(thief.stop)
        self.fake.responder = lambda payload, n: ("http", 302, b"", {"Location": f"{thief.url}/steal"})
        with self.assertRaises(LLMError) as ctx:
            self.provider().chat([{"role": "user", "content": "Q"}], SCHEMA)
        self.assertRegex(str(ctx.exception), r"redirection \(302\).*jamais envoyé à une autre adresse")
        self.assertEqual(thief.requests, [])                                                                # rien n'est arrivé chez l'autre : pas de suivi
        self.assertNotIn(TOKEN, str(ctx.exception))

    def test_the_token_is_scrubbed_from_errors_even_when_the_server_echoes_it(self):
        echo = FakeLibreChat(echo_credentials=True).start()
        self.addCleanup(echo.stop)
        wrong = "mauvais-jeton-0123456789abcdef"
        with self.assertRaises(LLMError) as ctx:
            LibreChatProvider(echo.url, AGENT, wrong, timeout=5).check()
        self.assertNotIn(wrong, str(ctx.exception))                                                         # le serveur recopie l'en-tête dans son erreur : on le retire
        self.fake.responder = lambda payload, n: ("http", 500, {"error": {"message": f"boom Bearer {TOKEN} et {TOKEN}"}})
        with self.assertRaises(LLMError) as ctx2:
            self.provider().chat([{"role": "user", "content": "Q"}], SCHEMA)
        self.assertNotIn(TOKEN, str(ctx2.exception))
        self.assertIn("***", str(ctx2.exception))
        self.assertEqual(scrub(f"x Bearer {TOKEN} y {TOKEN}", TOKEN), "x Bearer *** y ***")


@unittest.skipUnless(shutil.which("openssl"), "openssl requis")
class TlsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.certs = make_certs(self.tmp)
        self.fake = FakeLibreChat(tls=self.certs).start()
        self.addCleanup(self.fake.stop)

    def test_a_private_ca_works_with_ca_file_and_fails_without(self):
        self.assertEqual(LibreChatProvider(self.fake.url, AGENT, TOKEN, ca_file=str(self.certs["ca"]), timeout=10).check(), ["agent_abc123", "agent_autre"])
        with self.assertRaisesRegex(LLMError, r"certificat TLS non reconnu.*ca_file"):
            LibreChatProvider(self.fake.url, AGENT, TOKEN, timeout=10).check()
        self.assertEqual(self.fake.requests[-1]["headers"]["authorization"], f"Bearer {TOKEN}")
        other = self.tmp / "autre"
        other.mkdir()
        wrong_ca = make_certs(other)["ca"]
        with self.assertRaisesRegex(LLMError, "certificat TLS non reconnu"):
            LibreChatProvider(self.fake.url, AGENT, TOKEN, ca_file=str(wrong_ca), timeout=10).check()        # une autre autorité ne valide pas ce serveur

    def test_a_failed_handshake_sends_no_token(self):
        before = len(self.fake.requests)
        with self.assertRaises(LLMError):
            LibreChatProvider(self.fake.url, AGENT, TOKEN, timeout=10).check()
        self.assertEqual(len(self.fake.requests), before)                                                   # la requête n'est même pas partie

    def test_tls_verification_cannot_be_disabled(self):
        source = Path(llm_mod.__file__).read_text()
        for forbidden in ("CERT_NONE", "check_hostname = False", "_create_unverified_context", "verify=False"):
            self.assertNotIn(forbidden, source)


class LibreCase(CritiqCase):
    """Corpus et passage réels (comme pour Ollama), critique par un faux LibreChat."""

    def setUp(self):
        super().setUp()
        self.lc = FakeLibreChat(responder=lc_responder).start()
        self.addCleanup(self.lc.stop)
        self.lcfg = cfg_for(self.lc)

    def crit_lc(self, llm=None, **kw):
        lines: list[str] = []
        summary = run_critique(self.db, self.data, self.run_id, self.cfg, llm=llm or self.lcfg, log=lines.append, **kw)
        self.lines = lines
        return summary


class IntegrationTest(LibreCase):
    def test_a_full_critique_through_librechat(self):
        s = self.crit_lc()
        self.assertEqual((s["units"], s["critiqued"], s["errors"]), (5, 5, 0))
        self.assertEqual(s["verdicts"], {"true_positive": 1, "false_positive": 1, "uncertain": 3})
        sq, _ = self.verdict_of("py/sql-injection", AGENT)
        self.assertEqual((sq["verdict"], sq["confidence"], sq["model"]), ("true_positive", 0.95, AGENT))
        self.assertEqual(s["tokens"], 5 * 120)                                                              # consommation rapportée
        self.assertTrue(all(r["path"] == "/api/agents/v1/chat/completions" for r in self.lc.requests if r["method"] == "POST"))
        self.assertEqual(self.lc.requests[0]["path"], "/api/agents/v1/models")                              # `check` avant tout envoi

    def test_the_audit_safeguards_still_hold(self):
        self.crit_lc()
        sent = self.lc.sent_text()
        for secret in (fakes.SECRET_A, fakes.SECRET_B, "do-not-send-me"):
            self.assertNotIn(secret, sent)                                                                  # jamais de valeur de secret, ni de fichier .env
        self.assertIn("<SECRET>", sent)
        self.assertIn("THE SECRET VALUE IS WITHHELD", sent)

    def test_the_token_leaks_nowhere(self):
        self.crit_lc()
        raw = "\n".join(f.read_text() for f in (self.data / "runs" / self.run_id / "critiq").rglob("*.json"))
        self.assertNotIn(TOKEN, raw)                                                                        # conversations conservées
        self.assertNotIn(TOKEN, "\n".join(self.db.conn.iterdump()))                                         # base de données
        self.assertNotIn(TOKEN, "\n".join(self.lines))                                                      # journal
        self.assertNotIn(TOKEN, self.lc.sent_text())                                                        # corps des requêtes : le jeton n'est que dans l'en-tête
        for path in self.data.rglob("*"):
            if path.is_file() and path.suffix in (".json", ".txt", ".html", ".md", ".yaml", ".sarif") and path.stat().st_size < 5_000_000:
                self.assertNotIn(TOKEN, path.read_text(errors="replace"), str(path))

    def test_dry_run_needs_no_token_and_sends_nothing(self):
        s = self.crit_lc(dataclasses.replace(self.lcfg, api_key=None), dry_run=True, show=1)
        self.assertEqual((self.lc.requests, s["units"], len(s["prompts"])), ([], 5, 1))                    # on relit ce qui partirait, sans accès configuré

    def test_remote_and_billing_notices(self):
        with mock.patch("aule.critiq.is_local_url", return_value=False):
            self.crit_lc(max_findings=1)
        text = "\n".join(self.lines)
        self.assertIn("⚠ moteur distant : des extraits du code audité sont envoyés à 127.0.0.1", text)
        self.assertIn("consomme le solde de jetons du compte LibreChat", text)

    def test_authentication_failure_stops_before_any_code_is_sent(self):
        with self.assertRaisesRegex(LLMError, r"jeton refusé \(401\)"):
            self.crit_lc(dataclasses.replace(self.lcfg, api_key="jeton-revoque-0123456789"))
        self.assertEqual([r for r in self.lc.requests if r["method"] == "POST"], [])

    def test_an_agent_with_tools_is_detected_unit_by_unit(self):
        self.lc.responder = lambda payload, n: ("raw", {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{"type": "function", "function": {"name": "web_search"}}]}}]})
        s = self.crit_lc()
        self.assertEqual((s["verdicts"], s["errors"]), ({}, 3))
        self.assertIn("3 erreurs consécutives", s["aborted"])
        row = next(iter(self.db.critiques(AGENT).values()))
        self.assertEqual(row["verdict"], "error")
        self.assertIn("sans aucun outil", row["reasoning"])

    def test_the_responses_interface_gives_the_same_verdicts(self):
        s = self.crit_lc(dataclasses.replace(self.lcfg, endpoint="responses"))
        self.assertEqual(s["verdicts"], {"true_positive": 1, "false_positive": 1, "uncertain": 3})
        self.assertTrue(all(r["path"] == "/api/agents/v1/responses" for r in self.lc.requests if r["method"] == "POST"))

    def test_the_forge_screen_keeps_the_progress_bar_of_the_critique_phase(self):
        from aule.cli_pretty import RunPrinter
        from aule.ui import Ui
        ui = Ui().configure(out=io.StringIO(), err=io.StringIO(), mode="always", env={"COLUMNS": "100"})
        config = dataclasses.replace(self.config, critiq=dataclasses.replace(self.cfg, enabled=True), llm=self.lcfg)
        with RunPrinter(ui, self.db, self.root, animate=False) as printer:
            run_audit(self.db, self.data, self.root, config=config, tool_names=["cloc", "gitleaks"], critiq=True, log=printer.log, progress=printer.progress)
        text = strip_ansi(ui.out.getvalue())
        self.assertEqual(printer.unmatched, [])                                                             # tout le journal de la critique est reconnu
        self.assertEqual(text.count("Orfèvrerie  avis du modèle"), 1)                                       # un seul en-tête de phase...
        self.assertRegex(text, r"Orfèvrerie  avis du modèle[^\n]*\n(?:.*\n)*?  ✔ ▕█+▏ \d+/\d+")               # ... suivi de sa barre de progression terminée
        self.assertIn("chaque appel consomme le solde", text)
        self.assertNotIn(TOKEN, text)

    def test_audit_phase_five_survives_a_missing_token(self):
        config = dataclasses.replace(self.config, critiq=dataclasses.replace(self.cfg, enabled=True), llm=dataclasses.replace(self.lcfg, api_key=None))
        lines: list[str] = []
        run = run_audit(self.db, self.data, self.root, config=config, tool_names=["cloc", "gitleaks"], critiq=True, log=lines.append)
        self.assertEqual(self.db.get_audit(run)["status"], "complete")                                      # la critique n'abîme jamais l'audit
        self.assertTrue(any("critique IA impossible" in ln and "clé d'API LibreChat absente" in ln for ln in lines))
        self.assertEqual([r for r in self.lc.requests if r["method"] == "POST"], [])


class CliTest(LibreCase):
    def cli(self, *argv, color="never", api_key=TOKEN):
        yaml = self.tmp / "aule.yaml"
        yaml.write_text("critiq: {}\n")                                                                          # aule.yaml : aucun secret
        (self.tmp / "llm.yaml").write_text(f"provider: librechat\nurl: {self.lc.url}\nmodel: {AGENT}\ntimeout: 20\n" + (f"api_key: {api_key}\n" if api_key else ""))
        (self.tmp / "llm.yaml").chmod(0o600)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "100"}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--data", str(self.data), "--config", str(yaml), "--color", color])
        return code, out.getvalue(), err.getvalue()

    def test_check_text_output(self):
        code, out, err = self.cli("critiq", "check")
        self.assertEqual(code, 0, err)
        for expected in (f"moteur : librechat — {self.lc.url}/api/agents/v1", f"agent : {AGENT}", "interface : chat_completions",
                         "jeton : lu dans llm.yaml (35 caractères, jamais affiché)", "Connexion établie : agent « agent_abc123 » disponible (2 agent(s) visible(s) avec ce jeton)"):
            self.assertIn(expected, out)
        self.assertNotIn(TOKEN, out + err)
        self.assertEqual([r["method"] for r in self.lc.requests], ["GET"])                                  # aucun code envoyé

    def test_check_forge_output_and_failures(self):
        code, out, _ = self.cli("critiq", "check", color="always")
        text = strip_ansi(out)
        self.assertIn("🔍 Moteur IA", text)
        self.assertIn("✔ Connexion établie", text)
        self.assertIn("Aucun code n'a été envoyé", text)
        self.assertNotIn(TOKEN, out)
        code, out, err = self.cli("critiq", "check", "--model", "agent_absent")
        self.assertEqual(code, 2)
        self.assertIn("agent « agent_absent » introuvable", err)
        self.assertIn("agent_abc123, agent_autre", err)
        code, _, err = self.cli("critiq", "check", api_key=None)
        self.assertEqual(code, 2)
        self.assertIn("clé d'API LibreChat absente", err)
        self.assertIn("llm.yaml", err)
        code, _, err = self.cli("critiq", "check", api_key="jeton-revoque-0123456789")
        self.assertIn("jeton refusé (401)", err)
        self.assertNotIn("jeton-revoque", err)

    def test_run_reports_tokens(self):
        code, out, err = self.cli("critiq", "run", "--max", "2")
        self.assertEqual(code, 0, err)
        self.assertIn("Jetons consommés : 240.", out)
        self.assertNotIn(TOKEN, out + err)


if __name__ == "__main__":
    unittest.main()
