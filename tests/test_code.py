"""Navigation dans le code : confinement, fenêtres de lignes, recherche, masquage en mode --mask, import de SARIF, API."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

import fakes
import aule.codeview as cv
from aule.cli import main
from aule.codeview import CodeError, Source, find_in_file, list_dir, list_files, read_lines, search_project
from aule.critiq import Redactor
from common import git
from test_rawview import rich_sarif
from test_rawview_api import RawServerCase

SECRET = "ghp_" + "Zx9Qm2Lp4Rt7Vb1Nc6Hd3Jf8Kg5Ws0AaBbCc"
q = urllib.parse.quote


def make_project(root: Path) -> Path:
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "Zeta").mkdir()
    (root / "alpha").mkdir()
    (root / "src" / "app.py").write_text("\n".join(f"line {i}" for i in range(1, 1001)) + "\n")
    (root / "src" / "pkg" / "util.py").write_text("def helper():\n    return 1\n")
    (root / "src" / "crlf.txt").write_bytes(b"one\r\ntwo\r\nthree\r\n")
    (root / "src" / "long.txt").write_text("x" * 5000 + "\nshort\n")
    (root / "src" / "keys.py").write_text(f'TOKEN = "{SECRET}"\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\nAWS = "AKIAJQWEXZRTMNBVCKSP"\n')
    (root / "src" / "empty.py").write_text("")
    (root / "bin.dat").write_bytes(b"\x00\x01\x02 needle-in-binary")
    (root / ".env").write_text(f"API_KEY={SECRET}\n")
    (root / "cert.pem").write_text("pem")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("[core]\n")
    (root / "node_modules" / "dep").mkdir(parents=True)
    (root / "node_modules" / "dep" / "index.js").write_text("needle_in_deps\n")
    (root / "src" / "needle.py").write_text("a = 1\nNeedle here\nb = needle\n")
    return root


class CodeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = make_project(self.tmp / "proj")
        outside = self.tmp / "outside.txt"
        outside.write_text("OUTSIDE")
        (self.root / "link.txt").symlink_to(outside)
        (self.root / "linkdir").symlink_to(self.tmp)
        self.src = Source(self.root)
        self.masked = Source(self.root, mask=True, redact=Redactor([SECRET]), deny=("**/.env", "**/.env.*", "**/*.pem", ".git/**"))


class ListDirTest(CodeCase):
    def test_dirs_first_case_insensitive_and_hides_internals(self):
        names = [(e["name"], e["type"]) for e in list_dir(self.src)["entries"]]
        self.assertEqual([n for n, t in names if t == "dir"], ["alpha", "node_modules", "src", "Zeta"])      # dossiers d'abord, sans casse
        self.assertNotIn(".git", [n for n, _ in names])
        self.assertIn(("link.txt", "link"), names)
        self.assertIn(("linkdir", "link"), names)                                 # lien : listé, jamais suivi
        self.assertEqual({e["name"]: e["size"] for e in list_dir(self.src, "src/pkg")["entries"]}, {"util.py": 27})
        self.assertEqual(list_dir(self.src, "./src/pkg/")["path"], "src/pkg")

    def test_confinement(self):
        for bad, status in (("..", 400), ("src/../..", 400), ("a\0b", 400), (".git", 403), (".git/objects", 403), ("linkdir", 403), ("nope", 404), ("src/app.py", 404)):
            with self.assertRaises(CodeError, msg=bad) as ctx:
                list_dir(self.src, bad)
            self.assertEqual(ctx.exception.status, status, bad)
        with self.assertRaises(CodeError) as ctx:
            list_dir(self.src, "/etc")                                            # le « / » initial est retiré : on reste dans le projet
        self.assertEqual(ctx.exception.status, 404)

    def test_cap_and_mask(self):
        with mock.patch.object(cv, "MAX_ENTRIES", 3):
            r = list_dir(self.src)
        self.assertEqual((len(r["entries"]), r["truncated"]), (3, True))
        names = {e["name"] for e in list_dir(self.masked)["entries"]}
        self.assertNotIn(".env", names)                                           # fichiers sensibles absents en mode --mask
        self.assertNotIn("cert.pem", names)
        self.assertIn(".env", {e["name"] for e in list_dir(self.src)["entries"]})   # visibles hors mode --mask


class ReadLinesTest(CodeCase):
    def test_windows(self):
        r = read_lines(self.src, "src/app.py")
        self.assertEqual((r["total"], r["start"], r["end"], len(r["lines"]), r["lines"][0], r["language"]), (1000, 1, 400, 400, "line 1", "python"))
        r = read_lines(self.src, "src/app.py", around=500, window=100)
        self.assertEqual((r["start"], r["end"], r["lines"][0], r["lines"][-1]), (450, 549, "line 450", "line 549"))
        r = read_lines(self.src, "src/app.py", around=3, window=100)
        self.assertEqual(r["start"], 1)                                           # centré mais jamais avant la ligne 1
        r = read_lines(self.src, "src/app.py", around=999, window=100)
        self.assertEqual((r["start"], r["end"]), (949, 1000))
        r = read_lines(self.src, "src/app.py", start=10, end=12)
        self.assertEqual(r["lines"], ["line 10", "line 11", "line 12"])
        r = read_lines(self.src, "src/app.py", start=5000)
        self.assertEqual((r["end"], len(r["lines"])), (1000, 400))                # au-delà : dernière fenêtre
        self.assertLessEqual(len(read_lines(self.src, "src/app.py", window=10**6)["lines"]), 1000)
        with mock.patch.object(cv, "MAX_WINDOW", 50):
            self.assertEqual(len(read_lines(self.src, "src/app.py", window=400)["lines"]), 50)

    def test_special_content(self):
        self.assertEqual(read_lines(self.src, "src/crlf.txt")["lines"], ["one", "two", "three"])
        r = read_lines(self.src, "src/long.txt")
        self.assertEqual((len(r["lines"][0]), r["long_lines_cut"], r["lines"][1]), (cv.MAX_LINE + 2, 1, "short"))
        r = read_lines(self.src, "src/empty.py")
        self.assertEqual((r["total"], r["lines"], r["end"]), (0, [], 0))

    def test_refusals(self):
        for rel, status in (("bin.dat", 415), ("nope.py", 404), ("src", 404), ("link.txt", 403), ("linkdir/x", 403), (".git/config", 403), ("../x", 400), ("", 400)):
            with self.assertRaises(CodeError, msg=rel) as ctx:
                read_lines(self.src, rel)
            self.assertEqual(ctx.exception.status, status, rel)
        with mock.patch.object(cv, "MAX_FILE", 100), self.assertRaises(CodeError) as ctx:
            read_lines(self.src, "src/app.py")
        self.assertEqual(ctx.exception.status, 413)

    def test_mask_redacts_and_refuses_sensitive_files(self):
        clear = "\n".join(read_lines(self.src, "src/keys.py")["lines"])
        self.assertIn(SECRET, clear)                                              # hors --mask : le code est montré tel quel
        masked = read_lines(self.masked, "src/keys.py")
        text = "\n".join(masked["lines"])
        self.assertTrue(masked["redacted"])
        for leaked in (SECRET, "AKIAJQWEXZRTMNBVCKSP", "BEGIN PRIVATE KEY", "AAAA"):
            self.assertNotIn(leaked, text)
        self.assertEqual(text.count("<SECRET"), 3)
        for rel in (".env", "cert.pem"):
            with self.assertRaises(CodeError) as ctx:
                read_lines(self.masked, rel)
            self.assertEqual(ctx.exception.status, 403)
        self.assertIn(SECRET, "\n".join(read_lines(self.src, ".env")["lines"]))      # l'auditeur peut lire .env hors --mask

    def test_historical_content_at_a_commit(self):
        repo = self.tmp / "repo"
        repo.mkdir()
        git("init", "-q", cwd=repo)
        (repo / "c.py").write_text("OLD = 1\nSECRET = 'abc'\n")
        git("add", ".", cwd=repo)
        git("commit", "-qm", "c1", cwd=repo)
        c1 = git("rev-parse", "HEAD", cwd=repo)
        (repo / "c.py").write_text("NEW = 2\n")
        git("commit", "-qam", "c2", cwd=repo)
        src = Source(repo, is_git=True)
        self.assertEqual(read_lines(src, "c.py")["lines"], ["NEW = 2"])
        old = read_lines(src, "c.py", ref=c1)
        self.assertEqual((old["lines"], old["ref"]), (["OLD = 1", "SECRET = 'abc'"], c1))
        self.assertEqual(read_lines(src, "c.py", ref="HEAD")["lines"], ["NEW = 2"])
        for ref, status in (("nope; rm -rf", 400), ("--output=x", 400), ("deadbeefdeadbeef", 404)):
            with self.assertRaises(CodeError, msg=ref) as ctx:
                read_lines(src, "c.py", ref=ref)
            self.assertEqual(ctx.exception.status, status, ref)
        with self.assertRaises(CodeError) as ctx:
            read_lines(src, "absent.py", ref=c1)
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(CodeError) as ctx:
            read_lines(Source(repo, is_git=False), "c.py", ref=c1)                  # pas un dépôt git
        self.assertEqual(ctx.exception.status, 400)


class SearchTest(CodeCase):
    def test_find_in_file(self):
        self.assertEqual(find_in_file(self.src, "src/needle.py", "needle")["matches"], [2, 3])      # sans casse par défaut
        self.assertEqual(find_in_file(self.src, "src/needle.py", "needle", case=True)["matches"], [3])
        self.assertEqual(find_in_file(self.src, "src/needle.py", "absent")["total"], 0)
        r = find_in_file(self.src, "src/app.py", "line")
        self.assertEqual((r["total"], len(r["matches"]), r["capped"]), (1000, 1000, False))
        for bad in ("", "x" * 201):
            with self.assertRaises(CodeError):
                find_in_file(self.src, "src/app.py", bad)
        self.assertEqual(find_in_file(self.masked, "src/keys.py", SECRET)["total"], 0)           # on ne retrouve pas un secret masqué

    def test_project_search_bounds_and_skips(self):
        r = search_project(self.src, "needle")
        files = {x["file"] for x in r["results"]}
        self.assertEqual(files, {"src/needle.py"})                                # node_modules ignoré
        self.assertEqual([(x["line"], x["text"]) for x in r["results"]], [(2, "Needle here"), (3, "b = needle")])
        self.assertEqual(search_project(self.src, "OUTSIDE")["results"], [])      # les liens ne sont pas suivis
        self.assertEqual(search_project(self.src, "needle-in-binary")["results"], [])     # binaires ignorés
        self.assertEqual(len(search_project(self.src, "line ", limit=5)["results"]), 5)
        self.assertTrue(search_project(self.src, "line ", limit=5)["capped"])
        with self.assertRaises(CodeError):
            search_project(self.src, "ab")
        masked = search_project(self.masked, SECRET[:12])
        self.assertEqual(masked["results"], [])                                   # ni dans le code, ni dans .env (refusé)
        self.assertEqual([x["file"] for x in search_project(self.src, "API_KEY")["results"]], [".env"])
        self.assertEqual(search_project(self.masked, "API_KEY")["results"], [])

    def test_go_to_file(self):
        r = list_files(self.src, "UTIL")
        self.assertEqual(r["files"], ["src/pkg/util.py"])
        names = list_files(self.src, ".py")["files"]
        self.assertEqual(names, sorted(names, key=lambda n: (len(n), n)))         # les plus courts d'abord
        self.assertNotIn(".git/config", list_files(self.src, "config")["files"])
        self.assertNotIn("node_modules/dep/index.js", list_files(self.src, "index")["files"])
        self.assertEqual(list_files(self.masked, ".env")["files"], [])


class CodeApiTest(RawServerCase):
    def setUp(self):
        super().setUp()
        (self.root / "repo-git" / ".env").write_text(f"API_KEY={SECRET}\n")

    def code(self, endpoint, **p):
        p.setdefault("project", "repo-git")
        return self.get(endpoint, **p)

    def test_tree_file_find_search_and_goto(self):
        status, tree, _ = self.code("code/tree")
        self.assertEqual(status, 200)
        names = {e["name"]: e["type"] for e in tree["entries"]}
        self.assertEqual((names["db.py"], names["service.py"], ".git" in names), ("file", "file", False))
        f = self.code("code/file", path="db.py")[1]
        self.assertEqual((f["total"], f["lines"][4].strip()[:11], f["language"]), (5, "cur.execute", "python"))
        self.assertEqual(self.code("code/find", path="db.py", q="execute")[1]["matches"], [5])
        self.assertEqual(self.code("code/search", q="eval(")[1]["results"][0]["file"], "service.py")
        self.assertEqual(self.code("code/files", q="serv")[1]["files"], ["service.py"])

    def test_secret_from_history_is_shown_at_its_commit(self):
        f = self.code("code/file", path="config.py", ref=self.commits[0])[1]
        self.assertIn(fakes.SECRET_A, "\n".join(f["lines"]))                      # au commit concerné : le secret supprimé depuis
        self.assertNotIn(fakes.SECRET_A, "\n".join(self.code("code/file", path="config.py")[1]["lines"]))
        self.assertEqual(self.code("code/file", path="config.py", ref="zz")[0], 400)

    def test_errors_and_guards(self):
        self.assertEqual(self.code("code/tree", project="nope")[0], 404)
        self.assertEqual(self.code("code/file", path="../audit.db")[0], 400)
        self.assertEqual(self.code("code/file", path=".git/config")[0], 403)
        self.assertEqual(self.code("code/file", path="absent.py")[0], 404)
        self.assertEqual(self.code("code/files", q="")[0], 400)
        self.assertEqual(self.code("code/search", q="ab")[0], 400)
        self.assertEqual(self.call("GET", "/api/code/tree?project=repo-git", token=False)[0], 403)
        shutil.rmtree(self.root / "repo-git")
        status, body, _ = self.code("code/tree")
        self.assertEqual((status, "aule purge" in body["error"]), (404, True))   # répertoire supprimé : message explicite

    def test_sarif_per_file_view(self):
        files = self.get("sarif/files", path=self.rich)[1]["files"]
        self.assertEqual({f["uri"]: f["count"] for f in files}, {"db.py": 1, "other.py": 1, "service.py": 1})
        self.assertEqual(files[0]["levels"], {"error": 1})


class MaskedCodeTest(RawServerCase):
    REVEAL = False

    def setUp(self):
        super().setUp()
        (self.root / "repo-git" / ".env").write_text(f"API_KEY={SECRET}\n")

    def code(self, endpoint, **p):
        return self.get(endpoint, project="repo-git", **p)

    def test_code_stays_browsable_but_secrets_never_leave(self):
        status, f, _ = self.code("code/file", path="settings.py")
        self.assertEqual(status, 200)
        text = "\n".join(f["lines"])
        self.assertNotIn(fakes.SECRET_B, text)                                    # secret connu du projet : expurgé
        self.assertIn("<SECRET>", text)
        self.assertTrue(f["redacted"])
        self.assertEqual(self.code("code/file", path=".env")[0], 403)
        self.assertNotIn(".env", {e["name"] for e in self.code("code/tree")[1]["entries"]})
        self.assertEqual(self.code("code/search", q=fakes.SECRET_B[:12])[1]["results"], [])
        self.assertEqual(self.code("code/search", q="API_KEY")[1]["results"], [])
        self.assertEqual(self.code("code/files", q=".env")[1]["files"], [])
        hist = self.code("code/file", path="config.py", ref=self.commits[0])[1]
        self.assertNotIn(fakes.SECRET_A, "\n".join(hist["lines"]))                # l'historique aussi est expurgé


class ImportTest(RawServerCase):
    def post(self, name, content, **kw):
        return self.call("POST", "/api/sarif/import", {"name": name, "content": content}, **kw)

    def test_import_makes_an_external_sarif_explorable(self):
        status, body, _ = self.post("../../CI report (nightly).sarif", json.dumps(rich_sarif()))
        self.assertEqual(status, 201)
        path = body["path"]
        self.assertRegex(path, r"^imports/\d{8}-\d{6}-CI_report_nightly\.sarif$")        # nom assaini, jamais de traversée
        self.assertTrue((self.data / path).is_file())
        self.assertEqual(self.get("sarif/summary", path=path)[1]["runs"][0]["tool"]["name"], "CodeQL")
        self.assertEqual(self.get("sarif/results", path=path, rule="py/unused-import")[1]["total"], 1)
        entries = self.get("raw/tree")[1]["entries"]
        imp = next(e for e in entries if e["tool"] == "sarif")
        self.assertEqual((imp["project"], [f["path"] for f in imp["files"]]), ("(importés)", [path]))
        self.assertEqual(self.get("raw/text", path=path)[0], 200)
        self.assertEqual(self.get("raw/text", path="imports/../audit.db")[0], 403)

    def test_never_overwrites_and_validates(self):
        p1 = self.post("a.sarif", json.dumps(rich_sarif()))[1]["path"]
        p2 = self.post("a.sarif", json.dumps(rich_sarif()))[1]["path"]
        self.assertNotEqual(p1, p2)
        for content, msg in (("{nope", "JSON invalide"), (json.dumps({"x": 1}), "n'est pas un SARIF"), (json.dumps([1]), "n'est pas un SARIF"), ("", "JSON invalide")):
            status, body, _ = self.post("b.sarif", content)
            self.assertEqual((status, msg in body["error"]), (400, True), content)
        self.assertEqual(self.call("POST", "/api/sarif/import", {"name": 3, "content": "{}"})[0], 400)
        self.assertEqual(self.post("a.sarif", "{}", token=False)[0], 403)
        self.assertEqual(len(list((self.data / "imports").glob("*.sarif"))), 2)

    def test_large_bodies_are_accepted_up_to_their_own_limit(self):
        doc = rich_sarif()
        doc["runs"][0]["results"] = [doc["runs"][0]["results"][1]] * 40000                        # ~ 7 Mo : dépasse la limite des autres routes
        self.assertGreater(len(json.dumps(doc)), 5 * 1024 * 1024)
        status, body, _ = self.post("big.sarif", json.dumps(doc))
        self.assertEqual(status, 201)
        self.assertEqual(self.get("sarif/results", path=body["path"], limit=1)[1]["all"], 40000)
        status, body413, resp = self.call("POST", "/api/sarif/import", "{}", headers={"Content-Length": str(65 * 1024 * 1024)})
        self.assertEqual((status, resp.headers["Connection"]), (413, "close"))

    def test_cli_import_and_list(self):
        src = self.tmp / "ci.sarif"
        src.write_text(json.dumps(rich_sarif()))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main(["sarif", "import", str(src), "--name", "pipeline", "--data", str(self.data)]), 0)
            self.assertEqual(main(["sarif", "list", "--data", str(self.data)]), 0)
        self.assertIn("SARIF importé", out.getvalue())
        self.assertIn("-pipeline.sarif", out.getvalue())
        self.assertIn("1 SARIF importé(s)", out.getvalue())
        bad = self.tmp / "bad.json"
        bad.write_text('{"x": 1}')
        with contextlib.redirect_stderr(err):
            self.assertEqual(main(["sarif", "import", str(bad), "--data", str(self.data)]), 2)
            self.assertEqual(main(["sarif", "import", str(self.tmp / "absent.sarif"), "--data", str(self.data)]), 2)
        self.assertIn("n'est pas un SARIF", err.getvalue())

    def test_imports_survive_a_purge_of_all_runs(self):
        path = self.post("keep.sarif", json.dumps(rich_sarif()))[1]["path"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["purge", "--keep", "0", "--yes", "--data", str(self.data)]), 0)
        self.assertTrue((self.data / path).is_file())                              # les imports appartiennent à la mission, pas à un run


class MaskedImportTest(RawServerCase):
    REVEAL = False

    def test_import_is_refused_in_mask_mode(self):
        status, body, _ = self.call("POST", "/api/sarif/import", {"name": "a.sarif", "content": json.dumps(rich_sarif())})
        self.assertEqual((status, "--mask" in body["error"]), (403, True))
        self.assertFalse((self.data / "imports").exists())


if __name__ == "__main__":
    unittest.main()
