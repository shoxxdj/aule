"""llm.yaml : le moteur d'IA dans un fichier à part, secrets compris, sans variable d'environnement ; refus de l'ancien format ; `aule llm migrate`."""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from aule.cli import main
from aule.config import ConfigError, load_config, parse_config
from aule.llmconf import LEGACY_KEYS, load_llm, migrate, parse_llm

KEY = "lc-9f8e7d6c5b4a3210fedcba9876543210"


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name: str, text: str, mode: int | None = None) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if mode is not None:
            path.chmod(mode)
        return path


class LoadTest(Tmp):
    LLM = "provider: custom\nurl: https://llm.exemple.fr/v1/chat/completions\nmodel: triton\napi_key: " + KEY + "\nca_file: pki/ca.pem\n"

    def test_llm_yaml_beside_aule_yaml_is_loaded(self):
        cfg = load_config(self.write("aule.yaml", "critiq:\n  enabled: true\n  max_rounds: 4\n"))
        self.assertIsNone(cfg.llm)                                                                               # pas de llm.yaml : pas de moteur (et aucune erreur)
        self.write("llm.yaml", self.LLM)
        cfg = load_config(self.tmp / "aule.yaml")
        self.assertEqual((cfg.llm.provider, cfg.llm.model, cfg.llm.api_key, cfg.critiq.enabled, cfg.critiq.max_rounds), ("custom", "triton", KEY, True, 4))
        self.assertEqual((cfg.llm.ca_file, cfg.llm.source), (str((self.tmp / "pki/ca.pem").resolve()), str((self.tmp / "llm.yaml").resolve())))   # relatif à llm.yaml

    def test_llm_file_points_elsewhere(self):
        self.write("secrets/mon-llm.yaml", self.LLM)
        cfg = load_config(self.write("aule.yaml", "llm_file: secrets/mon-llm.yaml\n"))
        self.assertEqual(cfg.llm.model, "triton")
        self.assertEqual(Path(cfg.llm.ca_file), (self.tmp / "secrets/pki/ca.pem").resolve())                    # les chemins se rapportent au fichier du moteur, pas à aule.yaml
        with self.assertRaisesRegex(ConfigError, "llm_file : fichier introuvable"):
            load_config(self.write("autre.yaml", "llm_file: absent.yaml\n"))                                    # un fichier EXPLICITEMENT nommé doit exister
        with mock.patch.dict(os.environ, {"HOME": str(self.tmp)}):
            self.write("home-llm.yaml", self.LLM)
            self.assertEqual(load_config(self.write("home.yaml", "llm_file: ~/home-llm.yaml\n")).llm.model, "triton")

    def test_without_aule_yaml_the_llm_yaml_of_the_current_directory_is_read(self):
        self.write("llm.yaml", "provider: ollama\nmodel: m\n")
        old = Path.cwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, old)
        cfg = load_config(None)
        self.assertEqual((cfg.llm.model, cfg.source), ("m", None))

    def test_a_dictionary_never_reads_a_file(self):
        self.write("llm.yaml", self.LLM)
        old = Path.cwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, old)
        self.assertIsNone(parse_config({}, self.tmp).llm)                                                        # configuration en mémoire : aucun fichier ramassé par hasard

    def test_errors_name_the_file(self):
        self.write("llm.yaml", "provider: custom\nurl: https://x/y\napi_key_env: MA_CLE\n")
        with self.assertRaisesRegex(ConfigError, r"llm\.yaml.*api_key_env : aucun secret en variable d'environnement"):
            load_config(self.write("aule.yaml", "critiq: {}\n"))
        self.write("llm.yaml", "provider: [\n")
        with self.assertRaisesRegex(ConfigError, r"llm\.yaml : YAML invalide"):
            load_config(self.tmp / "aule.yaml")

    def test_the_old_format_is_refused_and_no_secret_is_echoed(self):
        legacy = "critiq:\n  enabled: true\n  provider: custom\n  url: https://x/y\n  model: m\n  api_key: " + KEY + "\n  base_url: https://x\n  use_env_proxy: true\n"
        with self.assertRaises(ConfigError) as ctx:
            load_config(self.write("aule.yaml", legacy))
        message = str(ctx.exception)
        for expected in ("critiq.provider", "critiq.url", "critiq.api_key", "critiq.base_url", "critiq.use_env_proxy", "déménagé dans llm.yaml", "aule llm migrate"):
            self.assertIn(expected, message)
        self.assertNotIn(KEY, message)                                                                           # le message liste les NOMS des clés, jamais une valeur
        for key in sorted(LEGACY_KEYS):                                                                          # chaque clé du moteur est détectée, même seule
            with self.subTest(key=key), self.assertRaisesRegex(ConfigError, f"critiq.{key}"):
                parse_config({"critiq": {key: "x"}}, Path("."))

    def test_behaviour_keys_stay_in_aule_yaml(self):
        cfg = parse_config({"critiq": {"enabled": True, "kinds": ["secret"], "allow_more_code": True, "extended_rounds": 5, "deny_globs": ["x/**"]}}, Path("."))
        self.assertEqual((cfg.critiq.enabled, cfg.critiq.allow_more_code, cfg.critiq.extended_rounds), (True, True, 5))
        for flag in ("enabled", "skip_triaged", "send_secret_values", "allow_more_code"):
            with self.assertRaisesRegex(ConfigError, f"critiq.{flag} : true ou false"):
                parse_config({"critiq": {flag: "false"}}, Path("."))                                            # « false » en texte serait lu comme vrai : refusé


class MigrateTest(Tmp):
    def migrate(self, legacy: str, env: dict | None = None, **kw):
        config = self.write("aule.yaml", legacy)
        notes, keys = migrate(config, self.tmp / "llm.yaml", env=env or {}, **kw)
        return notes, keys, load_llm(self.tmp / "llm.yaml")

    def test_a_custom_setup_is_carried_over_and_aule_yaml_is_not_touched(self):
        legacy = ("# mon aule.yaml\ncritiq:\n  enabled: true\n  provider: custom\n  url: https://llm.exemple.fr/v1/chat/completions\n  model: triton\n  api_key: " + KEY + "\n"
                  "  api_key_header: x-ai-api-key\n  allow_remote: true\n  verify_tls: false\n  headers: {X-Tenant: acme}\n  max_tokens: 50\n  timeout: 60\n  max_rounds: 4\n")
        before = (self.tmp / "aule.yaml").read_text() if (self.tmp / "aule.yaml").exists() else legacy
        notes, keys, llm = self.migrate(legacy)
        self.assertEqual((llm.provider, llm.url, llm.model, llm.api_key, llm.api_key_header, llm.allow_remote, llm.verify_tls, llm.headers, llm.max_tokens, llm.timeout),
                         ("custom", "https://llm.exemple.fr/v1/chat/completions", "triton", KEY, "x-ai-api-key", True, False, {"X-Tenant": "acme"}, 50, 60))
        self.assertEqual(keys, sorted(["provider", "url", "model", "api_key", "api_key_header", "allow_remote", "verify_tls", "headers", "max_tokens", "timeout"]))   # `enabled` et `max_rounds` restent
        self.assertEqual((self.tmp / "aule.yaml").read_text(), legacy)                                           # aule.yaml n'est pas modifié (ses commentaires survivent)
        self.assertEqual(notes, [])

    def test_the_file_is_private(self):
        self.migrate("critiq:\n  provider: custom\n  url: https://x/y\n  api_key: " + KEY + "\n")
        self.assertEqual(stat.S_IMODE((self.tmp / "llm.yaml").stat().st_mode), 0o600)
        old = self.write("llm.yaml", "ancien\n", 0o644)                                                         # un fichier écrasé garde ses anciens droits : on les force
        migrate(self.tmp / "aule.yaml", old, force=True, env={})
        self.assertEqual(stat.S_IMODE(old.stat().st_mode), 0o600)

    def test_secrets_from_the_environment_or_a_file_are_written_into_the_file(self):
        notes, _, llm = self.migrate("critiq:\n  provider: librechat\n  base_url: https://chat.exemple.fr\n  model: agent_abc\n  api_key_env: MON_JETON\n  use_env_proxy: true\n", env={"MON_JETON": KEY})
        self.assertEqual((llm.api_key, llm.url, llm.proxy), (KEY, "https://chat.exemple.fr", "env"))            # base_url -> url, use_env_proxy -> proxy: env
        self.assertIn("lue dans $MON_JETON et inscrite dans llm.yaml", notes[0])
        self.assertNotIn(KEY, "\n".join(notes))
        (self.tmp / "llm.yaml").unlink()
        _, _, llm = self.migrate("critiq:\n  provider: librechat\n  base_url: https://chat.exemple.fr\n  model: agent_abc\n", env={"LIBRECHAT_API_KEY": KEY})
        self.assertEqual(llm.api_key, KEY)                                                                       # la variable par défaut de l'ancienne version
        (self.tmp / "llm.yaml").unlink()
        self.write("secrets/jeton.txt", KEY + "\n")
        notes, _, llm = self.migrate("critiq:\n  provider: librechat\n  base_url: https://chat.exemple.fr\n  model: a\n  api_key_file: secrets/jeton.txt\n")
        self.assertEqual(llm.api_key, KEY)
        self.assertIn("lue dans secrets/jeton.txt", notes[0])
        (self.tmp / "llm.yaml").unlink()
        notes, _, llm = self.migrate("critiq:\n  provider: librechat\n  base_url: https://chat.exemple.fr\n  model: a\n  api_key_env: PERSONNE\n")
        self.assertIsNone(llm.api_key)
        self.assertIn("AUCUNE clé d'API trouvée", notes[0])                                                      # on le dit, on n'invente rien

    def test_ollama_needs_no_key(self):
        notes, keys, llm = self.migrate("critiq:\n  base_url: http://127.0.0.1:11434\n  model: qwen\n  num_ctx: 16384\n  temperature: 0.2\n")
        self.assertEqual((llm.provider, llm.url, llm.model, llm.num_ctx, llm.temperature, notes), ("ollama", "http://127.0.0.1:11434", "qwen", 16384, 0.2, []))
        self.assertEqual(keys, ["base_url", "model", "num_ctx", "temperature"])

    def test_refusals(self):
        with self.assertRaisesRegex(ConfigError, "rien à migrer"):
            self.migrate("critiq:\n  enabled: true\n")
        self.write("aule.yaml", "critiq:\n  provider: custom\n  url: https://x/y\n")
        self.write("llm.yaml", "existant\n")
        with self.assertRaisesRegex(ConfigError, r"existe déjà \(--force"):
            migrate(self.tmp / "aule.yaml", self.tmp / "llm.yaml", env={})
        self.assertEqual((self.tmp / "llm.yaml").read_text(), "existant\n")                                      # rien d'écrasé sans --force
        (self.tmp / "llm.yaml").unlink()
        self.write("aule.yaml", "critiq:\n  provider: custom\n  model: m\n")                                    # custom sans url : la migration serait invalide
        with self.assertRaisesRegex(ConfigError, "la configuration migrée serait invalide : url : requise"):
            migrate(self.tmp / "aule.yaml", self.tmp / "llm.yaml", env={})
        self.assertFalse((self.tmp / "llm.yaml").exists())                                                       # ... et rien n'est écrit

    def test_relative_paths_follow_the_file_when_it_moves(self):
        self.write("aule.yaml", "critiq:\n  provider: custom\n  url: https://x/y\n  ca_file: pki/ca.pem\n  client_cert: pki/c.pem\n")
        out = self.tmp / "ailleurs" / "llm.yaml"
        out.parent.mkdir()
        migrate(self.tmp / "aule.yaml", out, env={})
        llm = load_llm(out)
        self.assertEqual((Path(llm.ca_file), Path(llm.client_cert)), ((self.tmp / "pki/ca.pem").resolve(), (self.tmp / "pki/c.pem").resolve()))

    def test_the_whole_cycle(self):
        """Ancienne configuration -> refusée -> migrée -> clés retirées -> chargée."""
        legacy = "critiq:\n  enabled: true\n  provider: custom\n  url: https://x/y\n  model: m\n  api_key: " + KEY + "\n  max_rounds: 5\n"
        self.write("aule.yaml", legacy)
        with self.assertRaisesRegex(ConfigError, "déménagé"):
            load_config(self.tmp / "aule.yaml")
        _, keys = migrate(self.tmp / "aule.yaml", self.tmp / "llm.yaml", env={})
        self.write("aule.yaml", "critiq:\n  enabled: true\n  max_rounds: 5\n")                                  # l'utilisateur retire les clés listées
        cfg = load_config(self.tmp / "aule.yaml")
        self.assertEqual((cfg.llm.api_key, cfg.llm.model, cfg.critiq.max_rounds, keys), (KEY, "m", 5, ["api_key", "model", "provider", "url"]))


class CliTest(Tmp):
    def run_cli(self, *argv, cwd=None):
        out, err = io.StringIO(), io.StringIO()
        old = Path.cwd()
        os.chdir(cwd or self.tmp)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main([*argv, "--color", "never"])
        finally:
            os.chdir(old)
        return code, out.getvalue(), err.getvalue()

    def test_migrate_runs_even_though_the_old_format_is_refused_everywhere_else(self):
        config = self.write("aule.yaml", "critiq:\n  provider: custom\n  url: https://x/y\n  model: m\n  api_key: " + KEY + "\n")
        code, _, err = self.run_cli("tools", "--config", str(config))
        self.assertEqual(code, 2)                                                                                # le chargement refuse l'ancien format...
        self.assertIn("aule llm migrate", err)
        code, out, err = self.run_cli("llm", "migrate", "--config", str(config))                                # ... mais la migration passe avant le chargement
        self.assertEqual(code, 0, err)
        for expected in ("llm.yaml créé (droits 600)", "supprimez de la section critiq", "api_key, model, provider, url", "ne le versionnez pas"):
            self.assertIn(expected, out)
        self.assertNotIn(KEY, out + err)                                                                         # la commande n'affiche jamais la clé
        self.assertEqual(stat.S_IMODE((self.tmp / "llm.yaml").stat().st_mode), 0o600)
        code, _, err = self.run_cli("llm", "migrate", "--config", str(config))
        self.assertEqual(code, 2)
        self.assertIn("existe déjà", err)

    def test_migrate_finds_aule_yaml_in_the_current_directory_and_reports_a_missing_one(self):
        code, _, err = self.run_cli("llm", "migrate")
        self.assertEqual(code, 2)
        self.assertIn("aucun aule.yaml à migrer", err)
        self.write("aule.yaml", "critiq:\n  base_url: http://127.0.0.1:11434\n  model: m\n")
        code, out, _ = self.run_cli("llm", "migrate", "--out", str(self.tmp / "mon-llm.yaml"))
        self.assertEqual(code, 0)
        self.assertTrue((self.tmp / "mon-llm.yaml").exists())

    def test_without_llm_yaml_the_check_explains_what_to_do(self):
        config = self.write("aule.yaml", "critiq: {}\n")
        code, _, err = self.run_cli("critiq", "check", "--config", str(config))
        self.assertEqual(code, 2)
        for expected in ("aucun moteur configuré", "llm.yaml", "llm.example.yaml", "aule llm migrate"):
            self.assertIn(expected, err)


class RepositoryHygieneTest(unittest.TestCase):
    def test_llm_yaml_is_never_versioned_and_the_example_is_complete(self):
        root = Path(__file__).parent.parent
        self.assertIn("llm.yaml", (root / ".gitignore").read_text().splitlines())                               # le fichier qui porte les secrets est ignoré par git
        example = (root / "llm.example.yaml").read_text()
        for key in sorted(LEGACY_KEYS - {"base_url", "api_key_env", "api_key_file", "use_env_proxy"}):          # chaque clé valide du moteur est documentée
            self.assertIn(f"# {key}:", example, key)
        for removed in ("base_url", "api_key_env", "api_key_file", "use_env_proxy"):
            self.assertNotRegex(example, rf"^# {removed}:", removed)                                             # et aucun ancien nom n'y traîne
        self.assertNotIn("critiq:", (root / "aule.example.yaml").read_text().split("# Comportement de la critique IA")[0])

    def test_the_docker_image_has_no_ai_and_never_copies_llm_yaml(self):
        """L'image Docker d'Aulë est volontairement SANS IA : pas de llm.yaml dans l'image (ni sa clé d'API), critique désactivée."""
        dockerfile = (Path(__file__).parent.parent / "docker" / "Dockerfile").read_text()
        self.assertNotRegex(dockerfile, r"(?m)^(COPY|ADD)[^\n]*llm\.yaml")                                      # la clé d'API ne va jamais dans l'image
        self.assertIn("SANS IA", dockerfile)
        self.assertNotIn("llm_file", (Path(__file__).parent.parent / "docker" / "aule.yaml").read_text())

    def test_no_secret_key_is_left_in_aule_example_yaml(self):
        text = (Path(__file__).parent.parent / "aule.example.yaml").read_text()
        for key in ("api_key", "api_key_env", "api_key_file", "base_url", "use_env_proxy"):
            self.assertNotRegex(text, rf"(?m)^\s*#?\s*{key}:", key)                                              # les CLÉS du moteur (et non toute chaîne qui y ressemble, comme nvd_api_key_env)


if __name__ == "__main__":
    unittest.main()
