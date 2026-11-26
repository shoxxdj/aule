"""Image Docker d'Aulë : tous les outils, règles et bases préchargées, sans IA. Docker n'est pas disponible ici : on vérifie ce qui peut l'être — le Dockerfile, la
configuration, et les scripts, EXÉCUTÉS avec de faux curl / trivy / dependency-check / aule."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

import yaml

from aule.cli import build_parser
from aule.config import load_config
from aule.plugins import load_plugins
from common import git

ROOT = Path(__file__).parent.parent
DOCKER = ROOT / "docker"
TOOLS_VERSIONS = ["GITLEAKS", "TRUFFLEHOG", "TRIVY", "OSV", "OPENGREP", "DEPCHECK", "CODEQL", "CHECKOV"]
COMPROMISED_TRIVY = {"0.69.4", "0.69.5", "0.69.6"}   # avis GHSA-69fq-xp46-6x23 (mars 2026)


def instructions(text: str) -> list[tuple[str, str]]:
    """Instructions du Dockerfile (lignes continuées recollées, commentaires ignorés)."""
    out, buf = [], ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        full, buf = (buf + line).strip(), ""
        cmd, _, args = full.partition(" ")
        out.append((cmd.upper(), args.strip()))
    return out


DOCKERFILE = (DOCKER / "Dockerfile").read_text()
INSTR = instructions(DOCKERFILE)
ARGS: dict[str, str] = {}
for _cmd, _a in INSTR:
    if _cmd == "ARG":
        _name, _, _value = _a.partition("=")
        ARGS[_name] = _value.strip('"')
SCRIPTS_TEXT = "\n".join((DOCKER / n).read_text() for n in ("install-tools.sh", "prefetch-data.sh", "entrypoint.sh")).replace('"$OPT_DIR/', "/opt/").replace("$OPT_DIR/", "/opt/")  # OPT_DIR vaut /opt par défaut

CURL_SHIM = '''#!/usr/bin/env python3
import io, json, os, sys, zipfile
args = sys.argv[1:]
out, url = args[args.index("-o") + 1], args[-1]
open(os.environ["SHIM_LOG"], "a").write(url + "\\n")
for suffix, route in json.load(open(os.environ["SHIM_ROUTES"])).items():
    if url.endswith(suffix):
        if route is None:
            sys.exit(22)
        if route.startswith("file:"):
            import shutil
            shutil.copy(route[5:], out)
        elif route == "zip":
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("CVE-1.json", "{}")
            open(out, "wb").write(buf.getvalue())
        else:
            open(out, "w").write(route)
        sys.exit(0)
sys.exit(22)
'''


class ShellCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()

    def shim(self, name: str, body: str) -> Path:
        path = self.bin / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def curl(self, routes: dict) -> Path:
        self.shim("curl", CURL_SHIM)
        (self.tmp / "routes.json").write_text(json.dumps(routes))
        self.curl_log = self.tmp / "curl.log"
        return self.curl_log

    def sh(self, command: str, env: dict | None = None, **kw) -> subprocess.CompletedProcess:
        full = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "SHIM_ROUTES": str(self.tmp / "routes.json"), "SHIM_LOG": str(self.tmp / "curl.log"), **(env or {})}
        return subprocess.run(["sh", "-c", command], capture_output=True, text=True, env=full, **kw)

    def versions_env(self) -> dict:
        return {f"{k}_VERSION": ARGS[f"{k}_VERSION"] for k in TOOLS_VERSIONS if k != "CHECKOV"}


class DockerfileTest(unittest.TestCase):
    def test_every_tool_version_is_pinned_with_a_default(self):
        for tool in TOOLS_VERSIONS:
            self.assertRegex(ARGS.get(f"{tool}_VERSION", ""), r"^\d+\.\d+(\.\d+)?$", tool)                    # jamais « latest », jamais vide : `docker build` sans argument fonctionne

    def test_the_compromised_trivy_releases_are_never_the_default(self):
        self.assertNotIn(ARGS["TRIVY_VERSION"], COMPROMISED_TRIVY)
        self.assertIn("v0.69.4", DOCKERFILE)                                                                   # le Dockerfile explique pourquoi on fige

    def test_gitleaks_has_a_pinned_digest(self):
        self.assertRegex(ARGS["GITLEAKS_SHA256"], r"^[0-9a-f]{64}$")

    def test_no_secret_is_baked_into_the_image(self):
        for cmd, args in INSTR:
            if cmd in ("ARG", "ENV"):
                self.assertIsNone(re.search(r"(?i)(KEY|TOKEN|PASSWORD|PASSWD|SECRET)\w*\s*=", args), args)    # pas de secret dans une variable ni un argument (visibles dans `docker history`)
            if cmd in ("COPY", "ADD") and "--from=" not in args:
                for source in args.split()[:-1]:                                                               # les SOURCES copiées (la destination /etc/aule/aule.yaml est légitime)
                    self.assertNotRegex(source, r"llm\.ya?ml|\.pem|\.key")
                    self.assertTrue(source != "aule.yaml" and not source.endswith("/aule.yaml") or source == "docker/aule.yaml", source)
        secret_runs = [a for c, a in INSTR if c == "RUN" and "--mount=type=secret,id=nvd_api_key" in a]
        self.assertEqual(len(secret_runs), 1)
        self.assertIn("required=false", secret_runs[0])                                                         # la clé NVD est un SECRET de construction, facultatif
        self.assertIn("prefetch-data.sh depcheck", secret_runs[0])

    def test_dockerignore_keeps_local_secrets_and_data_out_of_the_image(self):
        ignored = {l.strip() for l in (ROOT / ".dockerignore").read_text().splitlines() if l.strip() and not l.startswith("#")}
        for must in ("aule.yaml", "llm.yaml", "data", "database", ".git", "tests", ".env", "**/*.db"):
            self.assertIn(must, ignored, must)                                                                  # `COPY . /opt/aule` copierait sinon vos clés dans l'image

    def test_volumes_entrypoint_and_defaults(self):
        volume = next(a for c, a in INSTR if c == "VOLUME")
        self.assertEqual(json.loads(volume), ["/database", "/source"])
        entry = next(a for c, a in INSTR if c == "ENTRYPOINT")
        self.assertEqual(json.loads(entry), ["/usr/local/bin/aule-docker"])
        self.assertFalse([1 for c, _ in INSTR if c == "CMD"])                                                   # sans argument : le point d'entrée audite /source
        self.assertFalse([1 for c, _ in INSTR if c == "USER"])                                                  # root, assumé et expliqué (chown final)
        env = next(a for c, a in INSTR if c == "ENV")
        self.assertIn("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-data", env)

    def test_system_packages_and_git_trust(self):
        apt = next(a for c, a in INSTR if c == "RUN" and "apt-get install" in a and "default-jre-headless" in a)
        for package in ("git", "cloc", "curl", "unzip", "default-jre-headless", "ca-certificates"):
            self.assertRegex(apt, rf"\b{re.escape(package)}\b", package)
        self.assertIn("git config --system --add safe.directory '*'", apt)                                      # sinon git refuse tout dépôt monté d'un autre propriétaire (« dubious ownership »)
        self.assertTrue([1 for c, a in INSTR if c == "RUN" and 'checkov==${CHECKOV_VERSION}' in a and "checkov --version" in a])

    def test_every_copied_file_exists_in_the_repository(self):
        for cmd, args in INSTR:
            if cmd == "COPY" and "--from=" not in args:
                *sources, _dest = args.split()
                for src in sources:
                    self.assertTrue((ROOT / src).exists(), f"COPY {src} : introuvable")

    def test_run_instructions_are_valid_shell(self):
        for cmd, args in INSTR:
            if cmd == "RUN":
                script = re.sub(r"^(--\S+\s+)+", "", args)
                done = subprocess.run(["sh", "-n", "-c", script], capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, f"{script[:80]} : {done.stderr}")

    def test_layers_are_ordered_so_that_editing_aule_downloads_nothing_again(self):
        runs = [(i, a) for i, (c, a) in enumerate(INSTR)]
        index = lambda needle: next(i for i, a in runs if needle in a)  # noqa: E731
        self.assertLess(index("install-tools.sh"), index("prefetch-data.sh opengrep-rules"))
        self.assertLess(index("prefetch-data.sh depcheck"), index("COPY") if False else next(i for i, (c, a) in enumerate(INSTR) if c == "COPY" and a.startswith(". /opt/aule")))
        self.assertLess(index("install-tools.sh"), next(i for i, (c, a) in enumerate(INSTR) if c == "COPY" and a.startswith(". /opt/aule")))

    def test_the_dependency_check_switch_follows_the_prefetch_marker(self):
        run = next(a for c, a in INSTR if c == "RUN" and "__DEPENDENCY_CHECK_ENABLED__" in a)
        for marker, expected in ((True, True), (False, False)):
            tmp = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, tmp, True)
            cfg, mark = tmp / "aule.yaml", tmp / "prefetched"
            cfg.write_text((DOCKER / "aule.yaml").read_text())
            if marker:
                mark.write_text("ok")
            script = run.replace("/etc/aule/aule.yaml", str(cfg)).replace("/opt/depcheck-db/.prefetched", str(mark))
            self.assertEqual(subprocess.run(["sh", "-c", script], capture_output=True).returncode, 0)
            self.assertNotIn("__DEPENDENCY_CHECK_ENABLED__", cfg.read_text())
            self.assertIs(load_config(cfg).tool("dependency-check").enabled, expected)                         # le fichier produit est valide, dans les deux cas


class InstallScriptTest(ShellCase):
    script = str(DOCKER / "install-tools.sh")

    def test_scripts_have_valid_syntax(self):
        for name in ("install-tools.sh", "prefetch-data.sh", "entrypoint.sh"):
            self.assertEqual(subprocess.run(["sh", "-n", str(DOCKER / name)], capture_output=True).returncode, 0, name)

    def test_urls_follow_the_publication_conventions_of_each_project(self):
        out = self.sh(f"sh {self.script} --print-urls", self.versions_env())
        self.assertEqual(out.returncode, 0, out.stderr)
        got = dict(line.split("\t") for line in out.stdout.splitlines())
        v = lambda k: ARGS[f"{k}_VERSION"]  # noqa: E731
        self.assertEqual(got, {
            "gitleaks": f"https://github.com/gitleaks/gitleaks/releases/download/v{v('GITLEAKS')}/gitleaks_{v('GITLEAKS')}_linux_x64.tar.gz",
            "trufflehog": f"https://github.com/trufflesecurity/trufflehog/releases/download/v{v('TRUFFLEHOG')}/trufflehog_{v('TRUFFLEHOG')}_linux_amd64.tar.gz",
            "trivy": f"https://github.com/aquasecurity/trivy/releases/download/v{v('TRIVY')}/trivy_{v('TRIVY')}_Linux-64bit.tar.gz",
            "osv-scanner": f"https://github.com/google/osv-scanner/releases/download/v{v('OSV')}/osv-scanner_linux_amd64",
            "opengrep": f"https://github.com/opengrep/opengrep/releases/download/v{v('OPENGREP')}/opengrep_manylinux_x86",
            "dependency-check": f"https://github.com/dependency-check/DependencyCheck/releases/download/v{v('DEPCHECK')}/dependency-check-{v('DEPCHECK')}-release.zip",
            "codeql": f"https://github.com/github/codeql-action/releases/download/codeql-bundle-v{v('CODEQL')}/codeql-bundle-linux64.tar.gz"})
        self.assertIn("v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz", got["gitleaks"])                             # nom d'archive relevé sur la page de publication

    def test_a_missing_version_is_named(self):
        env = self.versions_env()
        del env["TRIVY_VERSION"]
        env["TRIVY_VERSION"] = ""
        out = self.sh(f"sh {self.script} --print-urls", env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("TRIVY_VERSION requise", out.stderr)

    def test_verify_listed_accepts_only_the_listed_checksum(self):
        archive = self.tmp / "tool.tar.gz"
        archive.write_bytes(b"contenu")
        good = hashlib.sha256(b"contenu").hexdigest()
        sums = self.tmp / "sums.txt"
        run = lambda: self.sh(f". {self.script}; verify_listed {archive} {sums}", {"AULE_SOURCE_ONLY": "1"})  # noqa: E731
        sums.write_text(f"{good}  tool.tar.gz\n")
        self.assertEqual(run().returncode, 0)
        sums.write_text(f"{good} *tool.tar.gz\n")                                                               # forme « binaire » de sha256sum
        self.assertEqual(run().returncode, 0)
        sums.write_text(f"{'0' * 64}  tool.tar.gz\n")
        out = run()
        self.assertNotEqual(out.returncode, 0)
        self.assertRegex(out.stderr, r"INCORRECTE pour tool\.tar\.gz.*altérée")
        sums.write_text(f"{good}  autre.tar.gz\n")
        self.assertIn("ne figure pas", run().stderr)                                                            # absent de la liste : non vérifiable, donc refusé

    def test_verify_digest(self):
        archive = self.tmp / "g.tar.gz"
        archive.write_bytes(b"x")
        run = lambda digest: self.sh(f". {self.script}; verify_digest {archive} {digest}", {"AULE_SOURCE_ONLY": "1"})  # noqa: E731
        self.assertEqual(run(hashlib.sha256(b"x").hexdigest()).returncode, 0)
        out = run("0" * 64)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("GITLEAKS_SHA256", out.stderr)                                                            # dit quoi faire si on change de version

    def test_a_failed_download_names_the_tool_the_url_and_the_way_out(self):
        self.curl({})
        out = self.sh(f". {self.script}; fetch https://exemple.invalid/x.tgz {self.tmp / 'x'} trivy", {"AULE_SOURCE_ONLY": "1"})
        self.assertNotEqual(out.returncode, 0)
        for expected in ("trivy", "https://exemple.invalid/x.tgz", "--build-arg"):
            self.assertIn(expected, out.stderr)

    def test_download_enforces_the_published_checksum_and_says_when_it_cannot(self):
        base = "https://h/rel"
        work = self.tmp / "work"
        work.mkdir()
        good = hashlib.sha256(b"ABC").hexdigest()
        run = lambda: self.sh(f". {self.script}; download outil {base} a.tgz s.txt", {"AULE_SOURCE_ONLY": "1", "WORK": str(work)})  # noqa: E731
        self.curl({"/a.tgz": "ABC", "/s.txt": f"{good}  a.tgz\n"})
        self.assertEqual(run().returncode, 0)
        self.curl({"/a.tgz": "ABC", "/s.txt": f"{'f' * 64}  a.tgz\n"})
        self.assertIn("INCORRECTE", run().stderr)                                                               # archive altérée : la construction s'arrête
        self.curl({"/a.tgz": "ABC", "/s.txt": None})
        out = run()
        self.assertEqual(out.returncode, 0)
        self.assertIn("NON vérifiée", out.stderr)                                                               # liste introuvable : on le dit, on ne le cache pas

    def test_a_binary_that_does_not_start_stops_the_build(self):
        info = self.tmp / "info"
        info.mkdir()
        ok = self.sh(f". {self.script}; smoke outil echo 'outil 1.2.3'", {"AULE_SOURCE_ONLY": "1", "BUILD_INFO": str(info)})
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("outil\toutil 1.2.3", (info / "TOOLS-VERSIONS").read_text())                            # la version démarrée est consignée dans l'image
        bad = self.sh(f". {self.script}; smoke outil sh -c 'echo coupe; exit 3'", {"AULE_SOURCE_ONLY": "1", "BUILD_INFO": str(info)})
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("outil ne démarre pas", bad.stderr)                                                       # un binaire tronqué ou d'une autre architecture échoue ici, pas au premier audit

    def test_every_installed_binary_is_started_once_before_the_end_of_the_build(self):
        text = (DOCKER / "install-tools.sh").read_text()
        for tool in ("gitleaks", "trufflehog", "trivy", "osv-scanner", "opengrep", "dependency-check", "codeql"):
            self.assertRegex(text, rf"smoke {tool} ", tool)

    def test_the_pinned_gitleaks_digest_is_enforced_even_when_the_projects_own_list_agrees(self):
        """Une release dont l'archive ET la liste de sommes seraient remplacées passerait la liste du projet : le condensat figé dans le Dockerfile l'arrête."""
        payload = self.tmp / "gitleaks"
        payload.write_text("#!/bin/sh\necho 8.0.0\n")
        tarball = self.tmp / "g.tar.gz"
        with tarfile.open(tarball, "w:gz") as archive:
            archive.add(payload, arcname="gitleaks")
        digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
        self.curl({"/gitleaks_1.2.3_linux_x64.tar.gz": f"file:{tarball}", "/gitleaks_1.2.3_checksums.txt": f"{digest}  gitleaks_1.2.3_linux_x64.tar.gz\n"})
        bin_dir, work = self.tmp / "usrbin", self.tmp / "work"
        bin_dir.mkdir()
        work.mkdir()
        line = "gitleaks|https://h/rel|gitleaks_1.2.3_linux_x64.tar.gz|gitleaks_1.2.3_checksums.txt"
        run = lambda sha: self.sh(f". {self.script}; install_tool '{line}'", {"AULE_SOURCE_ONLY": "1", "BIN_DIR": str(bin_dir), "WORK": str(work), "GITLEAKS_SHA256": sha})  # noqa: E731
        out = run("0" * 64)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("condensat INCORRECT", out.stderr)
        self.assertFalse((bin_dir / "gitleaks").exists())                                                       # rien n'est installé
        out = run(digest)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue((bin_dir / "gitleaks").is_file())
        (bin_dir / "gitleaks").unlink()
        self.assertEqual(run("").returncode, 0)                                                                 # condensat vide : seule la liste du projet fait foi

    def test_an_unsupported_architecture_is_refused_before_downloading(self):
        self.shim("uname", "#!/bin/sh\necho aarch64\n")
        self.curl({})
        out = self.sh(f"sh {self.script}", {**self.versions_env(), "WORK": str(self.tmp / "w"), "BUILD_INFO": str(self.tmp / "b")})
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("aarch64 non prise en charge", out.stderr)
        self.assertFalse((self.tmp / "curl.log").exists())


class PrefetchScriptTest(ShellCase):
    script = str(DOCKER / "prefetch-data.sh")

    def env(self, **extra) -> dict:
        return {"OSV_DIR": str(self.tmp / "osv"), "TRIVY_CACHE": str(self.tmp / "trivy"), "RULES_DIR": str(self.tmp / "rules"), "DEPCHECK_DB": str(self.tmp / "dc"),
                "BUILD_INFO": str(self.tmp / "info"), "NVD_KEY_FILE": str(self.tmp / "nokey"), **extra}

    def test_osv_databases_land_where_offline_mode_looks_for_them(self):
        self.curl({"/PyPI/all.zip": "zip", "/npm/all.zip": "zip", "/Hex/all.zip": None})
        out = self.sh(f"sh {self.script} osv", self.env(OSV_ECOSYSTEMS="PyPI npm Hex", OSV_REQUIRED="PyPI npm", OSV_BASE="https://osv.example"))
        self.assertEqual(out.returncode, 0, out.stderr)
        for eco in ("PyPI", "npm"):
            self.assertTrue((self.tmp / "osv" / "osv-scanner" / eco / "all.zip").is_file(), eco)             # {dir}/osv-scanner/<écosystème>/all.zip
        self.assertFalse((self.tmp / "osv" / "osv-scanner" / "Hex").exists())
        self.assertIn("facultative absente : Hex", out.stderr)                                                  # facultatif : on continue, mais on le dit
        self.assertEqual((self.tmp / "osv" / ".prefetched").read_text().splitlines()[1], "PyPI npm")
        self.assertIn("https://osv.example/PyPI/all.zip", (self.tmp / "curl.log").read_text())

    def test_a_required_osv_database_failing_stops_the_build(self):
        self.curl({"/PyPI/all.zip": "zip", "/npm/all.zip": None})
        out = self.sh(f"sh {self.script} osv", self.env(OSV_ECOSYSTEMS="PyPI npm", OSV_REQUIRED="PyPI npm"))
        self.assertNotEqual(out.returncode, 0)
        self.assertRegex(out.stderr, r"obligatoire introuvable ou corrompue : npm")
        self.curl({"/PyPI/all.zip": "pas un zip", "/npm/all.zip": "zip"})                                       # téléchargement « réussi » mais corrompu
        out = self.sh(f"sh {self.script} osv", self.env(OSV_ECOSYSTEMS="PyPI npm", OSV_REQUIRED="PyPI npm"))
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("PyPI", out.stderr)

    def test_trivy_databases_are_downloaded_into_the_cache_and_checked(self):
        self.shim("trivy", '''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
cache = a[a.index("--cache-dir") + 1]
assert a[a.index("--cache-dir") + 2] == "image"
open(os.environ["SHIM_LOG"], "a").write(" ".join(a) + "\\n")
if "--download-db-only" in a:
    os.makedirs(cache + "/db", exist_ok=True); open(cache + "/db/trivy.db", "w").write("x")
if "--download-java-db-only" in a and not os.environ.get("NO_JAVA"):
    os.makedirs(cache + "/java-db", exist_ok=True); open(cache + "/java-db/trivy-java.db", "w").write("x")
''')
        out = self.sh(f"sh {self.script} trivy", self.env())
        self.assertEqual(out.returncode, 0, out.stderr)
        calls = (self.tmp / "curl.log").read_text().splitlines()
        self.assertEqual([c.split()[-1] for c in calls], ["--download-db-only", "--download-java-db-only"])
        shutil.rmtree(self.tmp / "trivy")
        out = self.sh(f"sh {self.script} trivy", self.env(NO_JAVA="1"))
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("base Java de Trivy absente", out.stderr)                                                 # un téléchargement qui « réussit » sans produire la base est détecté

    def test_nvd_database_is_prefetched_only_with_the_build_secret_and_never_leaks_it(self):
        self.shim("dc.sh", '''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
open(os.environ["SHIM_LOG"], "a").write(" ".join(a) + "\\n")
if os.environ.get("DC_FAIL"):
    print("NVD API 403 pour la clé " + a[a.index("--nvdApiKey") + 1]); sys.exit(1)
os.makedirs(a[a.index("--data") + 1], exist_ok=True)
''')
        base = self.env(DEPCHECK_SH=str(self.bin / "dc.sh"))
        out = self.sh(f"sh {self.script} depcheck", base)                                                       # pas de secret
        self.assertEqual(out.returncode, 0)
        self.assertIn("DÉSACTIVÉ", out.stderr)
        self.assertFalse((self.tmp / "dc" / ".prefetched").exists())
        key = self.tmp / "key"
        key.write_text("CLE-NVD-SECRETE-123")
        out = self.sh(f"sh {self.script} depcheck", {**base, "NVD_KEY_FILE": str(key)})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue((self.tmp / "dc" / ".prefetched").is_file())
        self.assertEqual((self.tmp / "curl.log").read_text().split()[:3], ["--updateonly", "--data", str(self.tmp / "dc")])
        self.assertNotIn("CLE-NVD-SECRETE-123", out.stdout + out.stderr)
        shutil.rmtree(self.tmp / "dc")
        out = self.sh(f"sh {self.script} depcheck", {**base, "NVD_KEY_FILE": str(key), "DC_FAIL": "1"})
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("mise à jour de la base NVD en échec", out.stderr)
        self.assertNotIn("CLE-NVD-SECRETE-123", out.stdout + out.stderr)                                        # même quand l'outil recopie la clé dans son erreur

    def test_opengrep_rules_are_cloned_and_their_revision_recorded(self):
        remote = self.tmp / "remote"
        (remote / "python").mkdir(parents=True)
        (remote / "python" / "rule.yaml").write_text("rules: []\n")
        git("init", "-q", cwd=remote)
        git("add", ".", cwd=remote)
        git("commit", "-qm", "rules", cwd=remote)
        head = git("rev-parse", "HEAD", cwd=remote)
        out = self.sh(f"sh {self.script} opengrep-rules", self.env(OPENGREP_RULES_REPO=f"file://{remote}"))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue((self.tmp / "rules" / "opengrep-rules" / "python" / "rule.yaml").is_file())
        self.assertTrue((self.tmp / "rules" / "opengrep-rules" / ".git").exists())                              # gardé : le rapport affiche la révision des règles
        self.assertIn(f"opengrep-rules\t{head}", (self.tmp / "info" / "TOOLS-VERSIONS").read_text())
        shutil.rmtree(remote / "python")
        (remote / "autre").mkdir()
        (remote / "autre" / "x").write_text("x")
        git("add", "-A", cwd=remote)
        git("commit", "-qm", "sans python", cwd=remote)
        out = self.sh(f"sh {self.script} opengrep-rules", self.env(OPENGREP_RULES_REPO=f"file://{remote}"))
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("jeu de règles inattendu", out.stderr)

    def test_usage_is_explicit(self):
        out = self.sh(f"sh {self.script} nimporte", self.env())
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("usage", out.stderr)


class EntrypointTest(ShellCase):
    script = str(DOCKER / "entrypoint.sh")

    def setUp(self):
        super().setUp()
        self.source, self.data = self.tmp / "source", self.tmp / "database"
        (self.source / "projet-a").mkdir(parents=True)
        self.config = self.tmp / "aule.yaml"
        self.config.write_text("tools: {}\n")
        self.log = self.tmp / "aule.argv"
        self.shim("aule", '''#!/usr/bin/env python3
import json, os, signal, sys, time
open(os.environ["AULE_LOG"], "a").write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("AULE_WRITE"):
    open(os.path.join(os.environ["AULE_DATA"], "audit.db"), "w").write("x")
if os.environ.get("AULE_WAIT"):
    def stop(*_):
        open(os.environ["AULE_WAIT"] + ".term", "w").write("TERM"); sys.exit(143)
    signal.signal(signal.SIGTERM, stop)
    open(os.environ["AULE_WAIT"] + ".started", "w").write("1")
    time.sleep(30)
sys.exit(int(os.environ.get("AULE_RC", "0")))
''')
        self.env = {"AULE_CONFIG": str(self.config), "AULE_DATA": str(self.data), "AULE_SOURCE": str(self.source), "AULE_LOG": str(self.log),
                    "AULE_DEPCHECK_MARKER": str(self.tmp / "marker"), "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"}
        (self.tmp / "marker").write_text("ok")

    def run_entry(self, *args, **extra) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", self.script, *args], capture_output=True, text=True, env={**os.environ, **self.env, **extra})

    def called(self) -> list[list[str]]:
        return [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []

    def head(self) -> list[str]:
        return ["--config", str(self.config), "--data", str(self.data)]

    def test_without_arguments_it_audits_the_source_folder(self):
        out = self.run_entry()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.called(), [[*self.head(), "run", str(self.source)]])

    def test_default_invocation_is_parseable_by_the_real_cli(self):
        """C'était cassé une fois (--config et --data avant la commande) : on lie l'image à l'analyseur d'arguments d'Aulë."""
        self.run_entry()
        for argv in (self.called()[0],):
            args = build_parser().parse_args(argv)
            self.assertEqual((args.command, str(args.config), str(args.data), str(args.root)), ("run", str(self.config), str(self.data), str(self.source)))
        self.log.unlink()
        self.run_entry("--unpack", "--history")
        args = build_parser().parse_args(self.called()[0])
        self.assertTrue(args.unpack and args.history)

    def test_flags_only_apply_to_the_audit_and_other_commands_pass_through(self):
        self.run_entry("--unpack", "--history")
        self.run_entry("doctor")
        self.run_entry("show", "--format", "x")
        self.assertEqual(self.called(), [[*self.head(), "run", str(self.source), "--unpack", "--history"], [*self.head(), "doctor"], [*self.head(), "show", "--format", "x"]])

    def test_a_shell_is_available_for_diagnosis(self):
        out = self.run_entry("sh", "-c", "echo bonjour")
        self.assertEqual(out.stdout.strip(), "bonjour")
        self.assertEqual(self.called(), [])

    def test_a_bad_source_is_explained_before_hours_of_analysis(self):
        (self.source / "projet-a").rmdir()
        (self.source / "fichier.py").write_text("x")
        (self.source / ".git").mkdir()                                                                          # un dossier caché n'est pas un projet
        out = self.run_entry()
        self.assertEqual(out.returncode, 2)
        self.assertIn("UN PROJET PAR SOUS-DOSSIER", out.stderr)
        self.assertIn("PARENT", out.stderr)
        shutil.rmtree(self.source)
        out = self.run_entry()
        self.assertEqual(out.returncode, 2)
        self.assertIn("n'existe pas", out.stderr)
        self.assertEqual(self.called(), [])                                                                     # aule n'a pas été lancé
        self.assertEqual(self.run_entry("doctor").returncode, 0)                                                # les autres commandes n'ont pas besoin de /source

    def test_the_exit_code_of_aule_is_the_exit_code_of_the_container(self):
        self.assertEqual(self.run_entry(AULE_RC="3").returncode, 3)

    def test_it_warns_when_dependency_check_has_no_database(self):
        self.assertNotIn("dependency-check", self.run_entry().stderr)
        (self.tmp / "marker").unlink()
        out = self.run_entry()
        self.assertIn("dependency-check est désactivé", out.stderr)
        self.assertEqual(out.returncode, 0)                                                                     # un avertissement, pas une erreur

    @unittest.skipUnless(os.geteuid() == 0, "chown : root requis")
    def test_files_written_by_root_are_given_back_to_the_owner_of_the_mounted_folder(self):
        self.data.mkdir()
        os.chown(self.data, 12345, 23456)
        self.run_entry(AULE_WRITE="1")
        stat_ = (self.data / "audit.db").stat()
        self.assertEqual((stat_.st_uid, stat_.st_gid), (12345, 23456))
        shutil.rmtree(self.data)
        self.data.mkdir()                                                                                       # propriétaire root : rien à rendre
        self.run_entry(AULE_WRITE="1")
        self.assertEqual((self.data / "audit.db").stat().st_uid, 0)

    def test_stopping_the_container_stops_aule_and_waits_for_it(self):
        wait = self.tmp / "wait"
        proc = subprocess.Popen(["sh", self.script], env={**os.environ, **self.env, "AULE_WAIT": str(wait)}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.time() + 10
        while not Path(f"{wait}.started").exists() and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(Path(f"{wait}.started").exists())
        proc.send_signal(signal.SIGTERM)                                                                        # `docker stop`
        proc.wait(timeout=10)
        self.assertTrue(Path(f"{wait}.term").exists())                                                          # le signal est transmis à aule (sinon : SIGKILL au bout de 10 s)
        self.assertEqual(proc.returncode, 143)


class ImageConfigTest(unittest.TestCase):
    def setUp(self):
        self.text = (DOCKER / "aule.yaml").read_text()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def loaded(self, enabled: str = "true"):
        path = self.tmp / "aule.yaml"
        path.write_text(self.text.replace("__DEPENDENCY_CHECK_ENABLED__", enabled))
        return load_config(path)

    def test_the_placeholder_is_unique_and_both_values_give_a_valid_config(self):
        self.assertEqual(self.text.count("__DEPENDENCY_CHECK_ENABLED__"), 1)
        self.assertIs(self.loaded("true").tool("dependency-check").enabled, True)
        self.assertIs(self.loaded("false").tool("dependency-check").enabled, False)

    def test_every_tool_is_configured_and_enabled(self):
        cfg = self.loaded()
        registry = set(load_plugins())
        self.assertEqual(set(cfg.tools), registry)                                                              # aucun outil oublié
        self.assertEqual({n for n in registry if cfg.tool(n).enabled is not True}, set())                       # et tous activés (gittools, opengrep… ne le sont pas par défaut)

    def test_there_is_no_ai_in_this_image(self):
        cfg = self.loaded()
        self.assertIsNone(cfg.llm)
        self.assertIs(cfg.critiq.enabled, False)
        self.assertNotIn("llm_file", self.text)
        self.assertFalse([l for l in (DOCKER / "Dockerfile").read_text().splitlines() if l.startswith(("COPY", "ADD")) and "llm" in l])

    def test_no_secret_is_in_the_config(self):
        cfg = self.loaded()
        self.assertNotIn("nvd_api_key", cfg.tool("dependency-check").options)
        self.assertIsNone(re.search(r"(?i)\b(api_key|passw|secret|token)\w*\s*:", re.sub(r"#.*", "", self.text)))

    def test_nothing_needs_the_network_at_run_time(self):
        cfg = self.loaded()
        self.assertIs(cfg.tool("osv-scanner").options["offline"], True)                                         # --offline : aucune donnée de projet ne sort
        self.assertEqual(cfg.tool("trivy").options["skip_db_update"], True)
        self.assertIs(cfg.tool("trivy").options["offline"], True)
        self.assertEqual(set(cfg.tool("trivy").extra_args), {"--skip-java-db-update", "--skip-check-update", "--skip-version-check"})
        self.assertIs(cfg.tool("dependency-check").options["update"], False)
        self.assertEqual(set(cfg.tool("dependency-check").extra_args),
                         {"--disableOssIndex", "--disableCentral", "--disableNodeAudit", "--disableYarnAudit", "--disableVersionCheck"})   # analyseurs qui interrogent un service externe
        self.assertIs(cfg.tool("trufflehog").options["verify"], False)                                          # jamais de « test » des secrets chez un tiers
        self.assertIs(cfg.tool("codeql").options["download"], False)

    def test_paths_in_the_config_are_created_by_the_image(self):
        for path in sorted(set(re.findall(r"/opt/[\w./-]+", re.sub(r"#.*", "", self.text)))):
            self.assertTrue(path in DOCKERFILE or path in SCRIPTS_TEXT or path.rsplit("/", 1)[0] in SCRIPTS_TEXT, f"{path} n'est créé nulle part")

    def test_config_and_prefetch_use_the_same_directories(self):
        cfg = self.loaded()
        prefetch = (DOCKER / "prefetch-data.sh").read_text()
        default = lambda var: re.search(rf"{var}=\$\{{{var}:-([^}}]+)\}}", prefetch).group(1)  # noqa: E731
        self.assertEqual(cfg.tool("opengrep").options["rules_path"], f"{default('RULES_DIR')}/opengrep-rules")
        self.assertEqual(cfg.tool("osv-scanner").env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"], default("OSV_DIR"))
        self.assertIn(f"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={default('OSV_DIR')}", DOCKERFILE)
        self.assertEqual(cfg.tool("trivy").options["cache_dir"], default("TRIVY_CACHE"))
        self.assertEqual(cfg.tool("dependency-check").options["data_path"], default("DEPCHECK_DB"))
        self.assertEqual(cfg.tool("dependency-check").path, default("DEPCHECK_SH"))
        self.assertEqual(cfg.tool("codeql").path, "/opt/codeql/codeql")
        self.assertIn("-C \"$OPT_DIR\"", (DOCKER / "install-tools.sh").read_text())                              # codeql : extrait dans /opt → /opt/codeql
        self.assertEqual(default("DEPCHECK_DB") + "/.prefetched", next(re.search(r"(/opt/[\w./-]*\.prefetched)", a).group(1) for c, a in INSTR if c == "RUN" and "__DEPENDENCY_CHECK_ENABLED__" in a))

    def test_gitleaks_runs_with_its_default_configuration_in_the_image(self):
        """Aulë n'embarque aucune règle : dans l'image, gitleaks tourne avec SA configuration par défaut (vos règles : voir le README)."""
        tool = self.loaded().tool("gitleaks")
        self.assertEqual((tool.extra_args, tool.rules, tool.options), ([], [], {}))                              # ni --config, ni règles, ni l'ancienne option
        self.assertNotIn("credential_rules", self.text)

    def test_gittools_uses_the_binary_installed_in_the_path(self):
        self.assertIsNone(self.loaded().tool("gittools").path)
        self.assertIn("COPY --from=gitrs /out/git-extractor-rs /usr/local/bin/git-extractor-rs", DOCKERFILE)


class DocsTest(unittest.TestCase):
    def test_readme_documents_build_and_run(self):
        readme = (ROOT / "README.md").read_text()
        for expected in ("docker build -f docker/Dockerfile -t aule .", "--secret id=nvd_api_key", '-v "$(pwd)/database:/database"', ":/source", "--network none"):
            self.assertIn(expected, readme, expected)
        self.assertNotIn("non testé, versions à fournir", readme)
        for expected in ("AULE_CONFIG=/conf/aule.yaml", "Vos propres règles dans l'image"):
            self.assertIn(expected, readme, expected)                                                           # comment utiliser VOS règles dans l'image                                               # l'ancienne mention (8 --build-arg obligatoires)


if __name__ == "__main__":
    unittest.main()
