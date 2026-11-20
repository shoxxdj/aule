"""Fournisseur `custom` : point d'accès HTTP compatible Chat Completions, entièrement paramétrable (URL, clé dans le YAML, en-tête, corps, TLS…)."""
from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import re
import shutil
import ssl
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
from aule.llm import CustomProvider, LLMError, LibreChatProvider, _dig, make_provider, public_url
from aule.ui import strip_ansi
from fake_librechat import make_certs
from fake_openai import KEY, FakeOpenAI, verdict_json
from fake_ollama import verdict
from test_critiq import CritiqCase, default_responder

SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}
HELLO = "Say hello in one short sentence."


def conf(path: Path | None = None, **q) -> LLMConfig:
    """Le contenu de llm.yaml passé par le VRAI analyseur."""
    base = {"provider": "custom", "model": "triton", "api_key": KEY, "api_key_header": "x-ai-api-key", "timeout": 20}
    return parse_llm({**base, **q}, Path("."), path)


def oa_responder(payload, n):
    return json.dumps(default_responder({"messages": payload["messages"]}, n))


class FakeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = FakeOpenAI().start()
        self.addCleanup(self.fake.stop)

    def cfg(self, **q) -> LLMConfig:
        return conf(url=self.fake.url, **q)

    def provider(self, **q) -> CustomProvider:
        return make_provider(self.cfg(**q))


class ConfigTest(unittest.TestCase):
    def test_your_exact_setup(self):
        c = conf(url="https://domain.com/v1/chat/completions", max_tokens=50, verify_tls=False, allow_remote=True)
        self.assertEqual((c.provider, c.url, c.model, c.api_key, c.api_key_header, c.max_tokens, c.verify_tls), ("custom", "https://domain.com/v1/chat/completions", "triton", KEY, "x-ai-api-key", 50, False))

    def test_defaults(self):
        c = parse_llm({"provider": "custom", "url": "https://h/v1/chat/completions"}, Path("."))
        self.assertEqual((c.api_key, c.api_key_header, c.api_key_prefix, c.headers, c.body, c.max_tokens, c.verify_tls, c.response_path, c.json_mode, c.fold_system, c.check_url, c.retries, c.proxy),
                         (None, None, None, {}, {}, 2048, True, "choices.0.message.content", "prompt", False, None, 2, None))
        self.assertEqual(parse_llm({}, Path(".")).url, "http://127.0.0.1:11434")                                  # Ollama local : aucune clé à écrire

    def test_the_key_never_appears_in_a_representation(self):
        c = conf(url="https://h/x", headers={"X-Tenant": "secret-tenant-value"})
        self.assertNotIn(KEY, repr(c))
        self.assertNotIn("secret-tenant-value", repr(c))

    def test_full_section_and_relative_paths(self):
        c = parse_llm({"provider": "custom", "url": "https://h/x", "check_url": "https://h/v1/models", "api_key_prefix": "Token ", "headers": {"X-Tenant": "acme"},
                       "body": {"temperature": 0, "top_p": 0.9}, "json_mode": "json_schema", "response_path": "output.text", "fold_system": True, "retries": 0,
                       "proxy": "http://proxy:3128", "client_cert": "pki/c.pem", "client_key": "pki/c.key", "ca_file": "pki/ca.pem", "max_tokens": None}, Path("/etc/aule"))
        self.assertEqual((c.api_key_prefix, c.headers, c.body, c.json_mode, c.response_path, c.fold_system, c.retries, c.proxy, c.max_tokens),
                         ("Token ", {"X-Tenant": "acme"}, {"temperature": 0, "top_p": 0.9}, "json_schema", "output.text", True, 0, "http://proxy:3128", None))
        self.assertEqual((c.client_cert, c.client_key, c.ca_file), ("/etc/aule/pki/c.pem", "/etc/aule/pki/c.key", "/etc/aule/pki/ca.pem"))     # relatifs à llm.yaml

    def test_validation(self):
        good = {"provider": "custom", "url": "https://h/x"}
        for bad, msg in (({"url": None}, "url : requise"), ({"url": "llm.exemple.fr/v1/chat/completions"}, "URL http"), ({"url": "ftp://h/x"}, "URL http"),
                         ({"url": "https://user:pw@h/x"}, "pas d'identifiants"), ({"check_url": "pas-une-url"}, "check_url"),
                         ({"api_key": "avec espace"}, "api_key"), ({"api_key": "ligne1\nligne2"}, "api_key"), ({"api_key": "é-accent"}, "api_key"),
                         ({"api_key_header": "Mauvais Nom"}, "api_key_header"), ({"api_key_header": "Host"}, "api_key_header"), ({"api_key_prefix": "a\nb"}, "api_key_prefix"),
                         ({"headers": {"Bon": "a\nb"}}, "headers.Bon"), ({"headers": {"Content-Length": "1"}}, "invalide ou interdit"), ({"headers": ["x"]}, "headers"),
                         ({"body": {"messages": []}}, "body.messages"), ({"body": {"model": "x"}}, "body.model"), ({"body": {"stream": True}}, "stream"),
                         ({"max_tokens": 0}, "max_tokens"), ({"max_tokens": "50"}, "max_tokens"), ({"verify_tls": "non"}, "verify_tls : true ou false"),
                         ({"response_path": "a..b"}, "response_path"), ({"response_path": "a b"}, "response_path"), ({"json_mode": "xml"}, "json_mode"),
                         ({"retries": 6}, "retries"), ({"retries": True}, "retries"), ({"timeout": 0}, "timeout"), ({"allow_remote": "false"}, "allow_remote : true ou false"),
                         ({"proxy": "pas-un-proxy"}, "proxy"), ({"client_key": "k.pem"}, "client_cert"), ({"provider": "openai"}, "provider")):
            with self.subTest(bad=bad), self.assertRaisesRegex(ConfigError, msg):
                parse_llm({**good, **bad}, Path("."))

    def test_errors_never_echo_a_secret(self):
        for q in ({"api_key": "avec espace"}, {"api_key": "ligne1\nligne2"}, {"headers": {"X-Secret": "valeur\nsecrète"}}, {"url": "https://user:motdepasse@h/x"}):
            with self.assertRaises(ConfigError) as ctx:
                parse_llm({"provider": "custom", "url": "https://h/x", **q}, Path("."))
            for leak in ("avec espace", "ligne2", "secrète", "motdepasse"):
                self.assertNotIn(leak, str(ctx.exception))

    def test_one_table_decides_which_key_fits_which_engine(self):
        parse_llm({"provider": "librechat", "url": "https://x", "api_key": KEY}, Path("."))                       # LibreChat : la clé se donne dans le fichier, comme pour custom
        for key, value in (("api_key", KEY), ("retries", 1), ("proxy", "env"), ("ca_file", "ca.pem"), ("client_cert", "c.pem")):
            with self.assertRaisesRegex(ConfigError, f"{key} : sans objet avec provider: ollama"):               # ollama n'envoie pas de clé : l'accepter serait la perdre en silence
                parse_llm({"provider": "ollama", key: value}, Path("."))
        for key, value in (("headers", {"A": "b"}), ("body", {"a": 1}), ("verify_tls", False), ("json_mode", "json_object"), ("max_tokens", 5), ("response_path", "a.b"),
                           ("check_url", "https://x/m"), ("api_key_header", "X"), ("fold_system", True)):
            with self.assertRaisesRegex(ConfigError, f"{key} : sans objet avec provider: librechat \\(réservé à provider: custom\\)"):   # LibreChat reste strict : jamais de TLS désactivé
                parse_llm({"provider": "librechat", "url": "https://x", key: value}, Path("."))
        for provider in ("librechat", "custom"):
            for key, value in (("num_ctx", 4096), ("temperature", 0.5)):
                with self.assertRaisesRegex(ConfigError, f"{key} : sans objet avec provider: {provider}"):
                    parse_llm({"provider": provider, "url": "https://x/y", key: value}, Path("."))
        with self.assertRaisesRegex(ConfigError, "endpoint : sans objet avec provider: custom"):
            parse_llm({"provider": "custom", "url": "https://x/y", "endpoint": "responses"}, Path("."))
        with self.assertRaisesRegex(ConfigError, "inventee : clé inconnue"):
            parse_llm({"provider": "custom", "url": "https://x/y", "inventee": 1}, Path("."))

    def test_the_old_names_are_refused_with_the_way_out(self):
        for key, value, hint in (("base_url", "https://h", "utilisez `url`"), ("api_key_env", "MA_CLE", "aucun secret en variable d'environnement"),
                                 ("api_key_file", "k.txt", "aucun secret dans un fichier à part"), ("use_env_proxy", True, "utilisez `proxy: env`")):
            with self.assertRaisesRegex(ConfigError, f"{key} : .*{re.escape(hint)}"):
                parse_llm({"provider": "custom", "url": "https://h/x", key: value}, Path("."))

    def test_the_documented_examples_stay_valid(self):
        """llm.example.yaml : chaque bloc (ollama, librechat, custom) est commenté ; on le décommente et le vrai analyseur doit l'accepter."""
        import yaml
        text = (Path(__file__).parent.parent / "llm.example.yaml").read_text()
        self.assertEqual(parse_llm(yaml.safe_load(text), Path(".")).provider, "ollama")                           # copié tel quel : Ollama local, valide
        blocks = re.split(r"^# === (\w+) ===\n", text, flags=re.M)[1:]
        self.assertEqual(blocks[0::2], ["ollama", "librechat", "custom"])
        for name, body in zip(blocks[0::2], blocks[1::2]):
            lines = [ln[2:] for ln in body.splitlines() if ln.startswith("# ") and re.match(r"# [a-z_]+:", ln)]
            c = parse_llm(yaml.safe_load("\n".join(lines)), Path("."))
            self.assertEqual(c.provider, name)
        self.assertEqual((c.api_key_header, c.json_mode, c.response_path, c.retries), ("x-ai-api-key", "prompt", "choices.0.message.content", 2))   # le dernier : custom


class MakeProviderTest(unittest.TestCase):
    def test_a_remote_server_needs_consent_and_https(self):
        remote = conf(url="https://llm.exemple.invalid/v1/chat/completions")
        with self.assertRaisesRegex(LLMError, "n'est pas un endpoint local.*allow_remote.*llm.yaml"):
            make_provider(remote)
        self.assertIsInstance(make_provider(dataclasses.replace(remote, allow_remote=True)), CustomProvider)
        plain = dataclasses.replace(remote, url="http://llm.exemple.invalid/v1/chat/completions", allow_remote=True)
        with self.assertRaisesRegex(LLMError, "NON chiffrés.*insecure_http"):
            make_provider(plain)
        self.assertIsInstance(make_provider(dataclasses.replace(plain, insecure_http=True)), CustomProvider)
        self.assertIsInstance(make_provider(conf(url="http://localhost:8000/v1/chat/completions")), CustomProvider)

    def test_the_url_is_never_displayed_with_credentials_or_query(self):
        c = conf(url="https://llm.exemple.fr:8443/v1/chat/completions?api-key=SECRETQUERY&x=1", allow_remote=True)
        p = make_provider(c)
        shown = repr(p) + "\n".join(p.describe()) + p.base_url + public_url(c.url)
        self.assertNotIn("SECRETQUERY", shown)
        self.assertEqual(p.base_url, "https://llm.exemple.fr:8443/v1/chat/completions")
        self.assertEqual(public_url("http://[::1]:8080/v1/x?k=1"), "http://[::1]:8080/v1/x")

    def test_no_secret_is_ever_read_from_the_environment(self):
        local = conf(url="http://127.0.0.1:1/x")
        with mock.patch.dict(os.environ, {"LIBRECHAT_API_KEY": "env-secret-0123456789", "MA_CLE": "env-secret-4567890123", "AULE_API_KEY": "env-secret-aaaaaaaaaa"}):
            self.assertEqual(make_provider(local)._key, KEY)                                                     # la clé du fichier, quoi que dise l'environnement
            self.assertEqual(make_provider(dataclasses.replace(local, api_key=None))._key, "")                   # sans clé dans le fichier : requête sans authentification
        source = (Path(llm_mod.__file__)).read_text()
        for forbidden in ("os.environ", "getenv", "api_key_env"):
            self.assertNotIn(forbidden, source)                                                                  # llm.py ne sait même pas lire l'environnement

    def test_proxy_semantics(self):
        def proxies(**q):
            """Les proxys réellement utilisés : un ProxyHandler vide n'est même pas enregistré par urllib (c'est ce qui désactive ceux de l'environnement)."""
            handlers = make_provider(conf(url="http://127.0.0.1:1/x", **q))._opener.handlers
            return next((h.proxies for h in handlers if isinstance(h, __import__("urllib.request", fromlist=["x"]).ProxyHandler)), {})
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://envproxy:3128", "HTTP_PROXY": "http://envproxy:3128"}):
            self.assertEqual(proxies(), {})                                                                      # par défaut : jamais de proxy d'environnement (le code audité n'y passe pas par accident)
            self.assertEqual(proxies(proxy="env")["https"], "http://envproxy:3128")                              # proxy: env : on les suit
            self.assertEqual(proxies(proxy="http://explicite:8080"), {"http": "http://explicite:8080", "https": "http://explicite:8080"})

    def test_warnings_tls_and_loose_file(self):
        self.assertTrue(any("vérification TLS désactivée" in w for w in make_provider(conf(url="http://127.0.0.1:1/x", verify_tls=False)).warnings))
        self.assertEqual(make_provider(conf(url="http://127.0.0.1:1/x")).warnings, [])
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "llm.yaml"
            f.write_text("x: 1\n")
            f.chmod(0o644)
            self.assertTrue(any("lisible par d'autres utilisateurs" in w and "chmod 600" in w for w in make_provider(conf(f, url="http://127.0.0.1:1/x")).warnings))
            f.chmod(0o600)
            self.assertEqual(make_provider(conf(f, url="http://127.0.0.1:1/x")).warnings, [])
            f.chmod(0o644)
            self.assertEqual(make_provider(conf(f, url="http://127.0.0.1:1/x", api_key=None)).warnings, [])           # sans clé dans le fichier : rien à protéger

    def test_description_shows_everything_except_secrets(self):
        c = conf(url="http://127.0.0.1:1/x", headers={"X-Tenant": "valeur-secrete-9"}, body={"temperature": 0}, max_tokens=None)
        p = make_provider(c)
        text = "\n".join(p.describe()) + repr(p) + str(p)
        for secret in (KEY, "valeur-secrete-9"):
            self.assertNotIn(secret, text)
        for expected in ("moteur : custom", "modèle : triton", "en-tête x-ai-api-key", "jamais affichée", "vérification activée", "max_tokens : non envoyé", "en-têtes supplémentaires : X-Tenant", "corps supplémentaire : temperature"):
            self.assertIn(expected, text)


class ProtocolTest(FakeCase):
    def last(self):
        return self.fake.requests[-1]

    def test_your_exact_request(self):
        p = self.provider(max_tokens=50)
        self.assertEqual(json.loads(p.probe())["verdict"], "uncertain")
        r = self.last()
        self.assertEqual((r["method"], r["path"]), ("POST", "/v1/chat/completions"))
        self.assertEqual(r["headers"]["x-ai-api-key"], KEY)
        self.assertNotIn("authorization", r["headers"])                                                       # pas de « Bearer » : l'en-tête de VOTRE passerelle
        self.assertEqual(r["headers"]["content-type"], "application/json")
        self.assertEqual(r["json"], {"model": "triton", "messages": [{"role": "user", "content": HELLO}], "max_tokens": 50})   # identique à votre exemple

    def test_header_styles(self):
        for q, header, value in (({"api_key_header": None}, "authorization", f"Bearer {KEY}"), ({"api_key_header": "Authorization", "api_key_prefix": ""}, "authorization", KEY),
                                 ({"api_key_header": "Authorization", "api_key_prefix": "Token "}, "authorization", f"Token {KEY}"), ({"api_key_header": "X-Api-Key", "api_key_prefix": "k="}, "x-api-key", f"k={KEY}")):
            with self.subTest(q=q):
                fake = FakeOpenAI(auth_header=header, prefix=value[:-len(KEY)]).start()
                self.addCleanup(fake.stop)
                make_provider(conf(url=fake.url, **q)).probe()                                                # api_key_header: None = non précisé -> Authorization
                self.assertEqual(fake.requests[-1]["headers"][header], value)

    def test_extra_headers_are_sent_and_may_override(self):
        self.provider(headers={"X-Tenant": "acme", "Accept": "application/vnd.x+json"}).probe()
        h = self.last()["headers"]
        self.assertEqual((h["x-tenant"], h["accept"]), ("acme", "application/vnd.x+json"))

    def test_payload_defaults_and_overrides(self):
        self.provider().probe()
        self.assertEqual(self.last()["json"]["max_tokens"], 2048)                                              # plafond serveur évité (certains serveurs : 16)
        self.provider(max_tokens=None).probe()
        self.assertNotIn("max_tokens", self.last()["json"])
        self.provider(max_tokens=100, body={"temperature": 0, "top_p": 0.9, "max_tokens": 7, "stop": ["###"]}).probe()
        sent = self.last()["json"]
        self.assertEqual((sent["temperature"], sent["top_p"], sent["stop"], sent["max_tokens"]), (0, 0.9, ["###"], 7))   # le corps configuré l'emporte
        self.assertEqual((sent["model"], sent["messages"][0]["content"]), ("triton", HELLO))
        self.assertNotIn("stream", sent)

    def test_json_modes_and_system_message(self):
        msgs = [{"role": "system", "content": "SYSTEME"}, {"role": "user", "content": "Q"}]
        shapes = {}
        for mode in ("prompt", "json_object", "json_schema"):
            self.provider(json_mode=mode).chat(msgs, SCHEMA)
            shapes[mode] = self.last()["json"]
        for sent in shapes.values():
            self.assertEqual([m["role"] for m in sent["messages"]], ["system", "user"])
            self.assertTrue(sent["messages"][0]["content"].startswith("SYSTEME\n\nOutput format: reply with ONE JSON object"))     # la consigne de format rejoint le système
            self.assertIn(json.dumps(SCHEMA), sent["messages"][0]["content"])
        self.assertNotIn("response_format", shapes["prompt"])
        self.assertEqual(shapes["json_object"]["response_format"], {"type": "json_object"})
        self.assertEqual(shapes["json_schema"]["response_format"], {"type": "json_schema", "json_schema": {"name": "critique", "schema": SCHEMA, "strict": False}})
        self.provider(fold_system=True).chat(msgs, SCHEMA)
        folded = self.last()["json"]["messages"]
        self.assertEqual([m["role"] for m in folded], ["user"])
        self.assertTrue(folded[0]["content"].startswith("<instructions>\nSYSTEME"))
        self.provider().chat([{"role": "user", "content": "Q"}], SCHEMA)                                       # sans message système : un système est ajouté
        self.assertEqual([m["role"] for m in self.last()["json"]["messages"]], ["system", "user"])

    def test_response_paths(self):
        for shape, path in (("custom", "output.text"), ("openai", "choices.0.message.content")):
            fake = FakeOpenAI(shape=shape).start()
            self.addCleanup(fake.stop)
            self.assertEqual(json.loads(make_provider(conf(url=fake.url, response_path=path)).probe())["verdict"], "uncertain")
        fake = FakeOpenAI(responder=lambda p, n: ("raw", {"data": [{"parts": [{"type": "text", "text": '{"a":'}, {"type": "text", "text": " 1}"}]}]})).start()
        self.addCleanup(fake.stop)
        self.assertEqual(make_provider(conf(url=fake.url, response_path="data.0.parts")).probe(), '{"a": 1}')    # liste de morceaux de texte
        self.assertEqual(_dig({"a": [{"b": 5}]}, "a.0.b"), 5)
        self.assertIsNone(_dig({"a": []}, "a.0"))
        self.assertIsNone(_dig({"a": 1}, "a.b"))

    def test_a_wrong_response_path_is_explained(self):
        with self.assertRaisesRegex(LLMError, r"rien à lire au chemin « output\.text ».*clés présentes : id, object, model, choices, usage"):
            self.provider(response_path="output.text").probe()
        fake = FakeOpenAI(responder=lambda p, n: ("raw", {"output": {"text": "  "}})).start()
        self.addCleanup(fake.stop)
        with self.assertRaisesRegex(LLMError, "rien à lire"):
            make_provider(conf(url=fake.url, response_path="output.text")).probe()

    def test_a_tool_call_is_refused_and_usage_is_counted(self):
        fake = FakeOpenAI(responder=lambda p, n: ("raw", {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{"type": "function"}]}}]})).start()
        self.addCleanup(fake.stop)
        with self.assertRaisesRegex(LLMError, "tenté d'utiliser un outil"):
            make_provider(conf(url=fake.url)).probe()
        p = self.provider()
        p.probe(); p.probe()
        self.assertEqual(p.tokens, 240)
        other = FakeOpenAI(shape="custom").start()
        self.addCleanup(other.stop)
        q = make_provider(conf(url=other.url, response_path="output.text"))
        q.probe()
        self.assertEqual(q.tokens, 15)                                                                         # input_tokens + output_tokens

    def test_check_url(self):
        p = self.provider()
        self.assertEqual((p.check(), self.fake.requests), ([], []))                                            # sans check_url : aucune requête
        p = self.provider(check_url=self.fake.models_url)
        self.assertEqual(p.check(), ["triton", "autre"])
        get = self.last()
        self.assertEqual((get["method"], get["headers"]["x-ai-api-key"]), ("GET", KEY))
        with self.assertRaisesRegex(LLMError, r"modèle « absent » absent de .*/v1/models ; disponibles : triton, autre"):
            self.provider(check_url=self.fake.models_url, model="absent").check()
        with self.assertRaisesRegex(LLMError, "aucun modèle configuré"):
            make_provider(dataclasses.replace(self.cfg(), model=None)).check()
        with self.assertRaisesRegex(LLMError, r"clé d'API refusée \(401\)"):
            self.provider(check_url=self.fake.models_url, api_key="mauvaise-cle-0123456789").check()


class ResilienceTest(FakeCase):
    def probe_error(self, **q) -> str:
        with self.assertRaises(LLMError) as ctx:
            self.provider(**q).probe()
        return str(ctx.exception)

    def test_status_messages_never_leak_the_key(self):
        msg = self.probe_error(api_key="mauvaise-cle-0123456789")
        self.assertIn("clé d'API refusée (401)", msg)
        self.assertNotIn("mauvaise-cle", msg)
        for status, expected in ((403, "accès refusé (403)"), (404, "adresse introuvable (404) : vérifiez `url` dans llm.yaml"), (500, "le service a répondu 500")):
            self.fake.responder = lambda p, n, s=status: ("http", s, {"error": {"message": "détail serveur"}})
            self.assertIn(expected + " — détail serveur", self.probe_error())

    def test_retries_are_configurable(self):
        slow = lambda p, n: ("http", 429, {"error": {"message": "lent"}}, {"Retry-After": "0"})
        for retries, attempts in ((0, 1), (1, 2), (2, 3)):
            self.fake.chats, self.fake.responder = 0, slow
            self.assertIn("limite de débit atteinte (429)", self.probe_error(retries=retries))
            self.assertEqual(self.fake.chats, attempts, retries)
        self.fake.chats = 0
        self.fake.responder = lambda p, n: ("http", 503, {"error": {"message": "occupé"}}, {"Retry-After": "0"}) if n < 1 else verdict_json("false_positive")
        self.assertEqual(json.loads(self.provider(retries=1).probe())["verdict"], "false_positive")             # une panne passagère est absorbée

    def test_timeout_garbage_and_unreachable(self):
        self.fake.responder = lambda p, n: ("sleep", 3)
        self.assertIn("délai de 1s dépassé", self.probe_error(timeout=1))
        self.fake.responder = lambda p, n: ("http", 200, b"pas du json")
        self.assertIn("réponse illisible", self.probe_error())
        with self.assertRaisesRegex(LLMError, r"injoignable à http://127\.0\.0\.1:1/v1/chat/completions"):
            make_provider(conf(url="http://127.0.0.1:1/v1/chat/completions", timeout=3)).probe()

    def test_a_redirect_never_carries_the_key_elsewhere(self):
        thief = FakeOpenAI().start()
        self.addCleanup(thief.stop)
        self.fake.responder = lambda p, n: ("http", 302, b"", {"Location": f"{thief.url}?steal=1"})
        msg = self.probe_error()
        self.assertRegex(msg, r"redirection \(302\).*la clé d'API n'est jamais envoyée à une autre adresse")
        self.assertEqual(thief.requests, [])
        self.assertNotIn(KEY, msg)

    def test_every_configured_secret_is_scrubbed_even_when_echoed(self):
        extra = "second-secret-abcdef123456"
        self.fake.responder = lambda p, n: ("http", 500, {"error": {"message": f"boom Bearer {KEY} puis {KEY} et {extra}"}})
        msg = self.probe_error(headers={"X-Second": extra})
        for secret in (KEY, extra):
            self.assertNotIn(secret, msg)
        echo = FakeOpenAI(echo=True).start()
        self.addCleanup(echo.stop)
        with self.assertRaises(LLMError) as ctx:
            make_provider(conf(url=echo.url, api_key="mauvaise-cle-0123456789")).probe()                        # le serveur recopie l'en-tête reçu dans son erreur
        self.assertNotIn("mauvaise-cle", str(ctx.exception))


@unittest.skipUnless(shutil.which("openssl"), "openssl requis")
class TlsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.certs = make_certs(self.tmp)
        self.fake = FakeOpenAI(tls=self.certs).start()
        self.addCleanup(self.fake.stop)

    def test_default_verifies_and_explains_both_ways_out(self):
        before = len(self.fake.requests)
        with self.assertRaisesRegex(LLMError, r"certificat TLS non reconnu.*ca_file.*verify_tls: false"):
            make_provider(conf(url=self.fake.url)).probe()
        self.assertEqual(len(self.fake.requests), before)                                                      # la poignée de main échoue : la clé n'est même pas partie

    def test_ca_file_validates_the_private_authority(self):
        p = make_provider(conf(url=self.fake.url, ca_file=str(self.certs["ca"])))
        self.assertEqual(json.loads(p.probe())["verdict"], "uncertain")
        self.assertEqual(p.warnings, [])
        other = self.tmp / "autre"
        other.mkdir()
        with self.assertRaisesRegex(LLMError, "certificat TLS non reconnu"):
            make_provider(conf(url=self.fake.url, ca_file=str(make_certs(other)["ca"]))).probe()               # une autre autorité ne valide pas ce serveur

    def test_verify_tls_false_is_curl_insecure_and_loud(self):
        p = make_provider(conf(url=self.fake.url, verify_tls=False))
        self.assertEqual(json.loads(p.probe())["verdict"], "uncertain")                                       # fonctionne avec un certificat inconnu
        self.assertEqual(self.fake.requests[-1]["headers"]["x-ai-api-key"], KEY)
        self.assertTrue(any("vérification TLS désactivée" in w for w in p.warnings))
        self.assertIn("⚠ vérification DÉSACTIVÉE", "\n".join(p.describe()))

    def test_the_bypass_lives_in_one_module_only(self):
        root = Path(llm_mod.__file__).parent
        source = (root / "llm.py").read_text()
        for forbidden in ("CERT_NONE", "check_hostname = False", "_create_unverified_context", "verify=False"):
            self.assertNotIn(forbidden, source)                                                                # llm.py reste sans contournement
        self.assertEqual(source.count("insecure_tls"), 1)                                                      # un seul point d'appel, derrière `verify_tls=False`
        self.assertIn("CERT_NONE", (root / "insecure_tls.py").read_text())
        self.assertNotIn("verify_tls", LibreChatProvider.__init__.__code__.co_varnames)                        # LibreChat ne peut pas être rendu non vérifié
        users = [f.name for f in root.rglob("*.py") if "insecure_tls" in f.read_text() and f.name != "insecure_tls.py"]
        self.assertEqual(users, ["llm.py"])

    def test_client_certificate_for_mutual_tls(self):
        seen = {}
        with mock.patch.object(ssl.SSLContext, "load_cert_chain", lambda self, cert, key=None, password=None: seen.update(cert=cert, key=key)):
            make_provider(conf(url=self.fake.url, ca_file=str(self.certs["ca"]), client_cert="/pki/c.pem", client_key="/pki/c.key"))
        self.assertEqual(seen, {"cert": "/pki/c.pem", "key": "/pki/c.key"})
        with self.assertRaisesRegex(LLMError, "certificat illisible"):
            make_provider(conf(url=self.fake.url, client_cert="/n/existe/pas.pem"))
        with self.assertRaisesRegex(LLMError, "certificat illisible"):
            make_provider(conf(url=self.fake.url, ca_file="/n/existe/pas.pem"))


YOUR_RESPONSE = {"model": "llm_medium", "usage": {"prompt_tokens": 59, "completion_tokens": 28, "total_tokens": 87, "reasoning_tokens": 17},
                 "choices": [{"message": {"content": "Hello, it's great to meet you!", "role": "assistant", "reasoning_content": "The user wants me to say hello in one short sentence. Simple request.\n",
                                          "tool_calls": None, "function_call": None}, "finish_reason": "stop", "index": 0, "logprobs": None}],
                 "id": "cmpl-b9ff02a8-e382-11f1-809a-19c05545d488", "created": 1795028603, "system_fingerprint": None, "object": "chat.completion"}


def truncated(content="", reasoning="Je réfléchis longuement… "):
    """La même réponse, coupée par la limite de longueur : le raisonnement a consommé le budget avant la réponse."""
    choice = {**YOUR_RESPONSE["choices"][0], "finish_reason": "length", "message": {**YOUR_RESPONSE["choices"][0]["message"], "content": content, "reasoning_content": reasoning}}
    return {**YOUR_RESPONSE, "choices": [choice]}


class YourRealResponseTest(FakeCase):
    """La réponse réelle de votre passerelle (modèle à raisonnement) : texte dans `content`, `tool_calls: null`, `reasoning_content` à part."""

    def serve(self, response, **q):
        fake = FakeOpenAI(responder=lambda p, n: ("raw", response)).start()
        self.addCleanup(fake.stop)
        return make_provider(conf(url=fake.url, **q))

    def test_the_default_path_reads_your_response(self):
        p = self.serve(YOUR_RESPONSE)
        self.assertEqual(p.probe(), "Hello, it's great to meet you!")                                        # sans aucun réglage de response_path
        self.assertEqual(p.tokens, 87)                                                                         # usage.total_tokens

    def test_null_tool_calls_are_not_a_tool_call(self):
        self.assertEqual(self.serve(YOUR_RESPONSE).probe(), "Hello, it's great to meet you!")                  # `tool_calls: null` et `function_call: null` ne déclenchent pas le refus
        called = {**YOUR_RESPONSE, "choices": [{**YOUR_RESPONSE["choices"][0], "message": {**YOUR_RESPONSE["choices"][0]["message"], "tool_calls": [{"type": "function"}]}}]}
        with self.assertRaisesRegex(LLMError, "tenté d'utiliser un outil"):
            self.serve(called).probe()                                                                         # ... mais un vrai appel d'outil reste refusé

    def test_the_reasoning_is_ignored_unless_you_ask_for_it(self):
        self.assertNotIn("Simple request", self.serve(YOUR_RESPONSE).probe())
        self.assertEqual(self.serve(YOUR_RESPONSE, response_path="choices.0.message.reasoning_content").probe().strip(), "The user wants me to say hello in one short sentence. Simple request.")

    def test_a_reply_cut_by_the_length_limit_is_explained(self):
        p = self.serve(truncated())
        with self.assertRaises(LLMError) as ctx:
            p.probe()
        msg = str(ctx.exception)
        self.assertIn("finish_reason: length", msg)
        self.assertIn("`max_tokens` dans llm.yaml", msg)                                                                # ce qu'il faut régler
        self.assertIn("17 jeton(s) consommés par le raisonnement", msg)                                        # pourquoi : le budget est parti dans le raisonnement
        self.assertEqual(p.tokens, 87)                                                                         # la consommation est comptée malgré l'échec
        with self.assertRaisesRegex(LLMError, "finish_reason: length"):
            self.serve(truncated(content='{"verdict": "true_posi')).probe()                                    # un JSON coupé n'est jamais accepté
        cut = truncated(); cut["usage"] = {"total_tokens": 5}
        with self.assertRaises(LLMError) as ctx2:
            self.serve(cut).probe()
        self.assertNotIn("raisonnement", str(ctx2.exception))                                                  # sans reasoning_tokens : pas de fausse explication

    def test_other_finish_reasons_and_shapes_are_untouched(self):
        for reason in ("stop", None, "end_turn"):
            ok = {**YOUR_RESPONSE, "choices": [{**YOUR_RESPONSE["choices"][0], "finish_reason": reason}]}
            self.assertEqual(self.serve(ok).probe(), "Hello, it's great to meet you!")
        fake = FakeOpenAI(shape="custom").start()                                                              # une autre forme de réponse n'a pas de finish_reason
        self.addCleanup(fake.stop)
        self.assertEqual(json.loads(make_provider(conf(url=fake.url, response_path="output.text")).probe())["verdict"], "uncertain")


class CustomCase(CritiqCase):
    """Corpus et passage réels (comme pour Ollama et LibreChat), critique par un faux point d'accès à en-tête de clé."""

    def setUp(self):
        super().setUp()
        self.oa = FakeOpenAI(responder=oa_responder).start()
        self.addCleanup(self.oa.stop)
        self.ccfg = conf(url=self.oa.url, check_url=self.oa.models_url)

    def crit(self, llm=None, **kw):
        lines: list[str] = []
        summary = run_critique(self.db, self.data, self.run_id, self.cfg, llm=llm or self.ccfg, log=lines.append, **kw)
        self.lines = lines
        return summary


class IntegrationTest(CustomCase):
    def test_a_full_critique_through_the_custom_endpoint(self):
        s = self.crit()
        self.assertEqual((s["units"], s["critiqued"], s["errors"]), (5, 5, 0))
        self.assertEqual(s["verdicts"], {"true_positive": 1, "false_positive": 1, "uncertain": 3})
        sq, _ = self.verdict_of("py/sql-injection", "triton")
        self.assertEqual((sq["verdict"], sq["model"]), ("true_positive", "triton"))
        self.assertEqual(s["tokens"], 5 * 120)
        posts = [r for r in self.oa.requests if r["method"] == "POST"]
        self.assertTrue(all(r["headers"]["x-ai-api-key"] == KEY and "authorization" not in r["headers"] for r in posts))
        self.assertEqual(self.oa.requests[0]["path"], "/v1/models")                                            # check_url avant tout envoi

    def test_audit_safeguards_still_hold(self):
        self.crit()
        sent = self.oa.sent_text()
        for secret in (fakes.SECRET_A, fakes.SECRET_B, "do-not-send-me"):
            self.assertNotIn(secret, sent)
        self.assertIn("<SECRET>", sent)

    def test_the_key_leaks_nowhere(self):
        self.crit()
        raw = "\n".join(f.read_text() for f in (self.data / "runs" / self.run_id / "critiq").rglob("*.json"))
        self.assertNotIn(KEY, raw)
        self.assertNotIn(KEY, "\n".join(self.db.conn.iterdump()))
        self.assertNotIn(KEY, "\n".join(self.lines))
        self.assertNotIn(KEY, self.oa.sent_text())                                                             # jamais dans le corps : seulement dans l'en-tête
        for path in self.data.rglob("*"):
            if path.is_file() and path.suffix in (".json", ".txt", ".html", ".md", ".yaml", ".sarif") and path.stat().st_size < 5_000_000:
                self.assertNotIn(KEY, path.read_text(errors="replace"), str(path))

    def test_dry_run_needs_no_key_and_sends_nothing(self):
        s = self.crit(dataclasses.replace(self.ccfg, api_key=None), dry_run=True, show=1)
        self.assertEqual((self.oa.requests, s["units"], len(s["prompts"])), ([], 5, 1))

    def test_warnings_reach_the_run_log(self):
        self.crit(dataclasses.replace(self.ccfg, verify_tls=False), max_findings=1)
        self.assertIn("⚠ vérification TLS désactivée", "\n".join(self.lines))
        with mock.patch("aule.critiq.is_local_url", return_value=False):
            self.crit(max_findings=1)
        self.assertIn("⚠ moteur distant : des extraits du code audité sont envoyés à 127.0.0.1", "\n".join(self.lines))

    def test_a_refused_key_stops_before_any_code_is_sent(self):
        with self.assertRaisesRegex(LLMError, r"clé d'API refusée \(401\)"):
            self.crit(dataclasses.replace(self.ccfg, api_key="mauvaise-cle-0123456789"))
        self.assertEqual([r for r in self.oa.requests if r["method"] == "POST"], [])


class YourShapeIntegrationTest(CustomCase):
    def test_a_critique_with_a_reasoning_model_stores_the_answer_only(self):
        thought = "PENSEE-PRIVEE-NE-DOIT-PAS-ETRE-CONSERVEE"
        def reply(payload, n):
            choice = {**YOUR_RESPONSE["choices"][0], "message": {**YOUR_RESPONSE["choices"][0]["message"], "content": oa_responder(payload, n), "reasoning_content": thought}}
            return ("raw", {**YOUR_RESPONSE, "choices": [choice]})
        self.oa.responder = reply
        s = self.crit()
        self.assertEqual((s["units"], s["critiqued"], s["errors"]), (5, 5, 0))
        self.assertEqual(s["verdicts"], {"true_positive": 1, "false_positive": 1, "uncertain": 3})
        self.assertEqual(s["tokens"], 5 * 87)
        stored = "\n".join(f.read_text() for f in (self.data / "runs" / self.run_id / "critiq").rglob("*.json")) + "\n".join(self.db.conn.iterdump())
        self.assertNotIn(thought, stored)                                                                      # le raisonnement du modèle n'est ni lu ni conservé
        self.assertNotIn(thought, "\n".join(self.lines))

    def test_a_too_small_max_tokens_is_diagnosed_on_every_unit(self):
        self.oa.responder = lambda p, n: ("raw", truncated())
        s = self.crit(dataclasses.replace(self.ccfg, max_tokens=20))
        self.assertEqual(s["verdicts"], {})
        self.assertIn("finish_reason: length", " ".join(self.lines))
        self.assertIn("max_tokens", " ".join(self.lines))


class CliTest(CustomCase):
    def cli(self, *argv, color="never", api_key=KEY, extra=""):
        yaml = self.tmp / "aule.yaml"
        yaml.write_text("critiq: {}\n")                                                                          # aule.yaml : le comportement, aucun secret
        (self.tmp / "llm.yaml").write_text(f"provider: custom\nurl: {self.oa.url}\nmodel: triton\napi_key: {api_key}\napi_key_header: x-ai-api-key\ntimeout: 20\n{extra}")
        (self.tmp / "llm.yaml").chmod(0o600)                                                                     # llm.yaml : le moteur, clé comprise
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "110"}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--data", str(self.data), "--config", str(yaml), "--color", color])
        return code, out.getvalue(), err.getvalue()

    def test_check_without_check_url_sends_nothing(self):
        code, out, err = self.cli("critiq", "check")
        self.assertEqual(code, 0, err)
        for expected in ("moteur : custom", "modèle : triton", "en-tête x-ai-api-key", "Configuration valide (aucune requête envoyée : check_url absent de llm.yaml)", "check --probe"):
            self.assertIn(expected, out)
        self.assertNotIn(KEY, out + err)
        self.assertEqual(self.oa.requests, [])

    def test_probe_reproduces_the_hello_request(self):
        code, out, err = self.cli("critiq", "check", "--probe", extra="max_tokens: 50\n")
        self.assertEqual(code, 0, err)
        self.assertIn(f"Réponse du modèle à « {HELLO} »", out)
        self.assertIn("(120 jeton(s))", out)
        self.assertEqual(self.oa.requests[-1]["json"], {"model": "triton", "messages": [{"role": "user", "content": HELLO}], "max_tokens": 50})
        self.assertNotIn(KEY, out + err)

    def test_probe_failures_are_explained(self):
        code, _, err = self.cli("critiq", "check", "--probe", api_key="mauvaise-cle-0123456789")
        self.assertEqual(code, 2)
        self.assertIn("essai en échec : clé d'API refusée (401)", err)
        self.assertNotIn("mauvaise-cle", err)
        self.oa.responder = lambda p, n: ("raw", {"pas": "de choix"})
        code, _, err = self.cli("critiq", "check", "--probe")
        self.assertEqual(code, 2)
        self.assertIn("essai en échec", err)

    def test_check_url_and_forge_output(self):
        code, out, _ = self.cli("critiq", "check", color="always", extra=f"check_url: {self.oa.models_url}\n")
        text = strip_ansi(out)
        self.assertEqual(code, 0)
        self.assertIn("🔍 Moteur IA", text)
        self.assertIn("✔ Connexion établie : modèle « triton » disponible (2 modèle(s) visible(s)", text)
        self.assertNotIn(KEY, out)

    def test_probe_is_refused_for_engines_without_it(self):
        yaml = self.tmp / "ollama.yaml"
        yaml.write_text("critiq: {}\n")
        (self.tmp / "llm.yaml").write_text("provider: ollama\nmodel: m\n")
        err = io.StringIO()
        with mock.patch.object(__import__("aule.llm", fromlist=["x"]).OllamaProvider, "check", lambda self: ["m"]), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["critiq", "check", "--probe", "--data", str(self.data), "--config", str(yaml), "--color", "never"])
        self.assertEqual(code, 2)
        self.assertIn("--probe : disponible avec provider: custom seulement", err.getvalue())

    def test_critique_run_reports_tokens(self):
        code, out, err = self.cli("critiq", "run", "--max", "2")
        self.assertEqual(code, 0, err)
        self.assertIn("Jetons consommés : 240.", out)
        self.assertNotIn(KEY, out + err)


if __name__ == "__main__":
    unittest.main()
