"""Exemple de règles gitleaks (examples/gitleaks-credentials.example.toml) et contrat : Aulë n'EMBARQUE et n'AJOUTE aucune règle. Les règles viennent de `tools.gitleaks.rules`,
c'est-à-dire de VOS fichiers ; l'exemple est à copier et à adapter dans votre propre dossier."""
from __future__ import annotations

import os
import re
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import aule.doctor as doctor
import aule.plugins.gitleaks as gitleaks_plugin
from aule.config import Config, parse_config
from aule.plugins.gitleaks import _gitleaks_version
from aule.orchestrator import run_audit
from common import AuditCase, git

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "examples" / "gitleaks-credentials.example.toml"
CONF = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
RULES = {r["id"]: r for r in CONF["rules"]}
ALLOW = [re.compile(x) for x in CONF["allowlist"]["regexes"]]
IDS = ["aule-credential-quoted", "aule-credential-unquoted", "aule-credential-in-url", "aule-credential-xml-element"]
NODEMAILER = 'const t = nodemailer.createTransport({ auth: { user: "bob@exemple.fr", pass: "Tr0ub4dor&3xyz" } });\n'
SW_JS = """

var transporter     = nodemailer.createTransport(
      {
        host    : 'ip',
        port    : 25,
        secure  : false, // use / not use TLS
        auth    : {
          user: 'user',
          pass: 'password' // mail in commentaire passowrd in commentaire    newmail in coment / new pass in comment
        },
        tls     : {
          rejectUnauthorized: false
        }
        // ... et/ou nodemailer-smtp-transport
        // https://stackoverflow.com/questions/32447210/node-js-nodemailer-gmail-error
      }
);
"""


def hits(filename: str, text: str) -> list[tuple[str, str]]:
    """(règle, secret) que gitleaks signalerait : filtre de chemin, mots-clés (pré-filtre), expression, puis exclusion globale. Mêmes étapes que le vrai outil."""
    out = []
    for rid, r in RULES.items():
        if r.get("path") and not re.search(r["path"], filename):
            continue
        if not any(k in text.lower() for k in r["keywords"]):  # gitleaks ne lance même pas l'expression sans un de ces mots dans le texte
            continue
        for m in re.finditer(r["regex"], text):
            secret = m.group(r["secretGroup"])
            if not any(a.search(secret) for a in ALLOW):
                out.append((rid, secret))
    return out


POS = [
    ("a.js", "var transporter = { nodemailer.createTransport({host: '', auth :{user: 'user',pass:'password'}})", "aule-credential-quoted", "password"),     # votre extrait, tel quel
    ("mail.js", 'auth: { user: "bob@exemple.fr", pass: "Tr0ub4dor&3xyz" },', "aule-credential-quoted", "Tr0ub4dor&3xyz"),
    ("index.html", "<script>var t = nodemailer.createTransport({auth:{user:'u',pass:'MotDePasse1'}})</script>", "aule-credential-quoted", "MotDePasse1"),     # le même code dans du HTML
    ("x.ts", "smtpPass: 'abcd1234'", "aule-credential-quoted", "abcd1234"), ("x.py", 'DB_PASSWORD = "hunter2x"', "aule-credential-quoted", "hunter2x"),
    ("c.json", '"password": "s3cr3t!"', "aule-credential-quoted", "s3cr3t!"), ("a.php", "'password' => 'azerty12'", "aule-credential-quoted", "azerty12"),
    ("a.js", "const apiKey = 'abc123def';", "aule-credential-quoted", "abc123def"), ("s.py", "SECRET_KEY = 'django-insecure-1234'", "aule-credential-quoted", "django-insecure-1234"),
    ("a.js", "pass = 'abcd'", "aule-credential-quoted", "abcd"), ("a.js", "if (password == 'letmein1')", "aule-credential-quoted", "letmein1"),
    ("app.yml", "password: hunter22", "aule-credential-unquoted", "hunter22"), ("app.properties", "db.password=abc12345", "aule-credential-unquoted", "abc12345"),
    (".env", "SMTP_PASS=Tr0ub4dor", "aule-credential-unquoted", "Tr0ub4dor"), ("x.sh", "export SMTP_PASS=Tr0ub4dor", "aule-credential-unquoted", "Tr0ub4dor"),
    ("app.yaml", "  - password: azerty123 # prod", "aule-credential-unquoted", "azerty123"), ("app.yml", "# password: oldsecret1", "aule-credential-unquoted", "oldsecret1"),
    ("Dockerfile", "ENV DB_PASS=abc12345", "aule-credential-unquoted", "abc12345"), ("Dockerfile.prod", "ARG SMTP_PASSWORD=Tr0ub4dor", "aule-credential-unquoted", "Tr0ub4dor"),
    ("config/.env.production", "API_KEY=abcd1234efgh", "aule-credential-unquoted", "abcd1234efgh"),
    ("a.go", "postgres://admin:s3cret@db:5432/app", "aule-credential-in-url", "s3cret"), ("a.js", "smtp://user:pass@smtp.exemple.fr:587", "aule-credential-in-url", "pass"),
    ("a.py", "mongodb+srv://u:p4ssw0rd@cluster0.x.mongodb.net/db", "aule-credential-in-url", "p4ssw0rd"),
    ("settings.xml", "<password>Abc12345</password>", "aule-credential-xml-element", "Abc12345"), ("server.xml", '<Resource name="jdbc" password="tomcat12" />', "aule-credential-quoted", "tomcat12"),
]
NEG = [
    ("a.js", "pass: process.env.SMTP_PASS"), ("a.js", "password: config.password"), ("a.js", "password: req.body.pass"), ("a.js", 'password: ""'), ("a.js", 'password: "${DB_PASSWORD}"'),
    ("a.js", "password: '{{ password }}'"), ("a.js", 'password: "<password>"'), ("a.js", "password: null"), ("a.js", "password: true"), ("a.js", 'bypass: "true"'), ("a.js", 'compass: "north"'),
    ("a.js", 'passenger: "abcdef"'), ("a.js", 'password: "Mot de passe"'), ("a.yml", "secretName: my-secret"), ("a.yml", "password_required: true"), ("a.env", "PASSWORD_MIN_LENGTH = 8"),
    ("a.js", "pass: x"), ("a.js", "const password = req.body.password;"), ("a.yml", "password: !vault abc"), ("a.yml", "password: ${DB_PASS}"), (".env", "SMTP_PASS="), ("a.yml", "password: %PASSWORD%"),
    ("a.js", 'pass: "@pass@"'), ("a.js", 'password: "***"'), ("a.js", "https://example.com/path"), ("a.js", "https://user@example.com/x"), ("a.js", "postgres://admin:${PASS}@db/app"),
    ("a.js", "url = 'http://host:8080/a'"), ("pom.xml", "<password>${env.DB_PASS}</password>"), ("pom.xml", "<passwordField>abcdef</passwordField>"), ("a.yml", "password: [a, b, c]"),
    ("a.py", "password: str = None"), ("a.js", "password: password"),
    # limites ASSUMÉES (les changer doit être volontaire) : documentation, valeurs courtes, phrases
    ("README.md", "password: hunter22"), ("a.js", "password: 'ab'"), ("a.js", "password: 'two words here'"),
]


class ExampleFileTest(unittest.TestCase):
    def test_it_is_an_example_that_aule_never_loads(self):
        first_lines = " ".join(EXAMPLE.read_text(encoding="utf-8").splitlines()[:2])
        self.assertIn("EXEMPLE", first_lines)
        self.assertIn("JAMAIS", first_lines)
        self.assertFalse((ROOT / "src" / "aule" / "rules").exists())                                            # plus de dossier de règles dans le paquet
        self.assertEqual(list((ROOT / "src" / "aule").rglob("*.toml")), [])                                     # ni aucun autre fichier de règles

    def test_the_example_extends_the_default_rules_instead_of_replacing_them(self):
        self.assertIs(CONF["extend"]["useDefault"], True)
        self.assertNotIn("path", CONF["extend"])                                                                # `useDefault` et `path` ne peuvent pas être utilisés ensemble
        self.assertEqual(sorted(RULES), sorted(IDS))

    def test_each_rule_is_complete_and_consistent(self):
        for rid, r in RULES.items():
            self.assertTrue(r["description"] and r["tags"], rid)
            self.assertEqual(r["keywords"], [k.lower() for k in r["keywords"]], rid)                           # le pré-filtre compare en minuscules
            self.assertGreaterEqual(re.compile(r["regex"]).groups, r["secretGroup"], rid)                       # le groupe du secret existe

    def test_only_the_version_stable_allowlist_form_is_used(self):
        for rid, r in RULES.items():
            self.assertNotIn("allowlist", r, rid)                                                               # [rules.allowlist] est devenu [[rules.allowlists]] en 8.21 : on l'évite
            self.assertNotIn("allowlists", r, rid)
        self.assertTrue(CONF["allowlist"]["regexes"])

    def test_expressions_stay_within_the_go_regexp_syntax(self):
        """gitleaks est écrit en Go (RE2) : ni anticipation, ni rétroréférence, ni groupe atomique, ni quantificateur possessif."""
        patterns = [r["regex"] for r in RULES.values()] + [r["path"] for r in RULES.values() if r.get("path")] + CONF["allowlist"]["regexes"]
        for pat in patterns:
            re.compile(pat)
            for forbidden, why in ((r"\(\?[=!]", "anticipation"), (r"\(\?<[=!]", "rétro-anticipation"), (r"\(\?>", "groupe atomique"), (r"\\[1-9]", "rétroréférence"), (r"[*+?}]\+", "quantificateur possessif")):
                self.assertIsNone(re.search(forbidden, pat), f"{why} interdite dans {pat[:60]}")

    def test_positive_corpus(self):
        for filename, text, rule, secret in POS:
            self.assertIn((rule, secret), hits(filename, text), f"{filename} : {text}")

    def test_negative_corpus(self):
        for filename, text in NEG:
            self.assertEqual(hits(filename, text), [], f"{filename} : {text}")

    def test_every_rule_has_positive_cases(self):
        self.assertEqual({rule for _, _, rule, _ in POS}, set(IDS))

    def test_default_and_weak_credentials_are_findings_not_hidden(self):
        for value in ("password", "admin", "changeme", "secret", "test1234", "letmein"):
            self.assertTrue(hits("a.js", f"pass: '{value}'"), value)                                           # un identifiant par défaut est un VRAI constat d'audit
        for value in ("true", "false", "null", "None", "xxxx", "****", "....", "----"):
            self.assertEqual(hits("a.js", f"password: '{value}'"), [], value)                                   # ... mais pas ce qui n'est manifestement pas un identifiant

    def test_the_snippet_that_started_it_all(self):
        self.assertEqual(hits("sw/sw.js", SW_JS), [("aule-credential-quoted", "password")])                     # avec ses commentaires, en LF comme en CRLF
        self.assertEqual(hits("sw/sw.js", SW_JS.replace("\n", "\r\n")), [("aule-credential-quoted", "password")])


class PluginCase(AuditCase):
    def setUp(self):
        super().setUp()
        _gitleaks_version.cache_clear()
        self.argv = self.tmp / "gitleaks.argv"
        env = mock.patch.dict(os.environ, {"FAKE_GITLEAKS_HONOR_CONFIG": "1", "FAKE_GL_ARGV": str(self.argv)})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(_gitleaks_version.cache_clear)

    def project(self, name: str, files: dict[str, str]) -> Path:
        root = self.root / name
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return root

    def with_rules(self, rules: list | None = None, **options) -> Config:
        tool: dict = {"options": options}
        if rules is not None:
            tool["rules"] = [str(r) for r in rules]
        return parse_config({"tools": {"gitleaks": tool}}, self.tmp)

    def audit(self, config: Config | None = None, **kw):
        lines: list[str] = []
        run_id = run_audit(self.db, self.data, self.root, config=config or parse_config({}, self.tmp), tool_names=kw.pop("tools", ["cloc", "gitleaks"]), log=lines.append, **kw)
        self.lines = lines
        return run_id

    def found(self, run_id: str, project: str | None = None, mode: str | None = None) -> set[tuple[str, str, str]]:
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        return {(e["data"]["rule_id"], e["data"]["file"], e["data"]["mode"]) for e in self.db.entities(run_id, "secret")
                if (project is None or names.get(e["project_id"]) == project) and (mode is None or e["data"]["mode"] == mode)}

    def argvs(self) -> list[list[str]]:
        import json
        return [json.loads(line) for line in self.argv.read_text().splitlines()] if self.argv.exists() else []


class NothingIsInjectedTest(PluginCase):
    """Le contrat : Aulë n'ajoute AUCUNE règle à gitleaks. Sans `rules`, gitleaks tourne avec sa configuration par défaut, sans --config."""

    def test_without_your_rules_the_audit_does_not_see_a_low_entropy_password(self):
        self.project("web", {"mail.js": NODEMAILER})
        run_id = self.audit()
        self.assertEqual({r for r, _, _ in self.found(run_id, "web")}, set())                                   # aucune règle d'Aulë : c'est à vous de les définir
        self.assertTrue(self.argvs())
        self.assertFalse([a for a in self.argvs() if "--config" in a or "-c" in a], self.argvs())              # aucun --config, quel que soit le mode

    def test_nothing_is_bundled_in_the_plugin_or_the_doctor(self):
        for name in ("CREDENTIAL_RULES", "credential_rules_enabled"):
            self.assertFalse(hasattr(gitleaks_plugin, name) or hasattr(gitleaks_plugin.Gitleaks, name), name)
        self.assertFalse(hasattr(doctor, "CREDENTIAL_CANARY"))
        corpus = doctor.make_corpus(self.tmp / "corpus")
        names = {p.name for p in corpus.rglob("*") if p.is_file() and ".git" not in p.parts}
        self.assertFalse({"mail.js", "settings.xml", "db.js", ".env"} & names)                                  # le jeu d'essai du banc d'essai n'a plus de pièges d'identifiants

    def test_the_old_option_is_refused_with_the_way_out_instead_of_being_ignored(self):
        for value in (True, False):
            self.audit(self.with_rules(credential_rules=value))
            message = next((ln for ln in self.lines if "credential_rules n'existe plus" in ln), "")
            self.assertIn("tools.gitleaks.rules", message, value)
            self.assertIn("examples/gitleaks-credentials.example.toml", message)
            self.assertIn("AUCUNE règle", message)
            self.assertTrue((ROOT / "examples" / "gitleaks-credentials.example.toml").is_file())                # l'exemple cité existe
        self.assertFalse([a for a in self.argvs() if a[:1] == ["dir"]])                                         # gitleaks n'a pas tourné avec une configuration devenue sans effet

    def test_no_documentation_still_presents_the_option(self):
        for path in (ROOT / "aule.example.yaml", ROOT / "docker" / "aule.yaml", ROOT / "README.md"):
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                if "credential_rules" in line:
                    self.assertIn("n'existe plus", line, f"{path.name} : {line.strip()[:80]}")                  # seule mention admise : l'avis de migration


class DetectionWithYourRulesTest(PluginCase):
    def test_with_the_example_copied_as_your_rules_the_nodemailer_password_is_found(self):
        self.project("web", {"mail.js": NODEMAILER})
        run_id = self.audit(self.with_rules([EXAMPLE]))
        self.assertEqual(self.found(run_id, "web", "dir"), {("aule-credential-quoted", "mail.js", "dir")})

    def test_the_snippet_in_sw_js_is_found(self):
        self.project("webapp", {"sw/sw.js": SW_JS})
        run_id = self.audit(self.with_rules([EXAMPLE]))
        self.assertEqual(self.found(run_id, "webapp", "dir"), {("aule-credential-quoted", "sw/sw.js", "dir")})

    def test_the_shapes_of_a_real_project(self):
        self.project("shop", {
            "index.html": "<script>createTransport({auth:{user:'u',pass:'MotDePasse1'}})</script>\n", ".env": "SMTP_PASS=Tr0ub4dor3\n", "config/app.yml": "database:\n  password: hunter22x\n",
            "pom.xml": "<server><password>Abc12345xyz</password></server>\n", "db.properties": "db.password=abc12345\n", "Dockerfile": "FROM x\nENV DB_PASS=abc12345\n",
            "config.php": "<?php return ['password' => 'azerty12'];\n", "src/db.js": 'const url = "postgres://admin:s3cret-pw@db.exemple.invalid:5432/app";\n'})
        got = {(rule, file) for rule, file, _ in self.found(self.audit(self.with_rules([EXAMPLE])), "shop", "dir")}
        self.assertEqual(got, {("aule-credential-quoted", "index.html"), ("aule-credential-unquoted", ".env"), ("aule-credential-unquoted", "config/app.yml"), ("aule-credential-xml-element", "pom.xml"),
                               ("aule-credential-unquoted", "db.properties"), ("aule-credential-unquoted", "Dockerfile"), ("aule-credential-quoted", "config.php"), ("aule-credential-in-url", "src/db.js")})

    def test_ordinary_code_does_not_raise_findings(self):
        self.project("clean", {"app.js": ("const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST,\n  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });\n"
                                         "const password = req.body.password;\nconst cfg = { password: config.db.password, secret: process.env.SECRET };\n"),
                               "config.yml": "password: ${DB_PASSWORD}\nsecretName: my-secret\npassword_required: true\n", "README.md": "password: hunter22\n"})
        self.assertEqual(self.found(self.audit(self.with_rules([EXAMPLE])), "clean", "dir"), set())

    def test_a_removed_password_is_still_found_in_the_history(self):
        repo = self.root / "repo-git"
        (repo / "mail.js").write_text(NODEMAILER)
        git("add", "mail.js", cwd=repo)
        git("commit", "-qm", "ajoute le mail", cwd=repo)
        (repo / "mail.js").write_text("transporter = createTransport({ auth: { user: process.env.U, pass: process.env.P } });\n")
        git("commit", "-qam", "retire le mot de passe", cwd=repo)
        found = self.found(self.audit(self.with_rules([EXAMPLE])), "repo-git")
        self.assertEqual({(m, f) for _, f, m in found if f == "mail.js"}, {("git", "mail.js")})                # absent du code courant, présent dans l'historique


class MergedConfigurationTest(PluginCase):
    def test_the_example_is_merged_into_one_config_and_the_default_rules_survive(self):
        (self.root / "repo-git" / "keys.txt").write_text("AKIA" + "ABCDEFGHIJKLMNOP\n")
        run_id = self.audit(self.with_rules([EXAMPLE]))
        for mode in ("dir", "git"):
            merged = self.root.parent  # pour la lisibilité : le fichier fusionné est dans la sortie brute
            raw = self.data / "runs" / run_id / "repo-git" / "gitleaks" / mode / "rules.toml"
            data = tomllib.loads(raw.read_text())
            self.assertEqual(sorted(r["id"] for r in data["rules"]), sorted(IDS), mode)
            self.assertEqual(data["extend"], {"useDefault": True}, mode)                                        # l'exemple demande les règles par défaut
        configs = {a[a.index("--config") + 1] for a in self.argvs()}
        self.assertTrue(configs and all(c.endswith("rules.toml") and str(EXAMPLE) not in c for c in configs), configs)   # le fichier fusionné, jamais l'exemple lui-même
        self.assertIn("aws-access-token", {r for r, _, _ in self.found(run_id, "repo-git")})                   # `useDefault` : les règles par défaut tournent encore


if __name__ == "__main__":
    unittest.main()
