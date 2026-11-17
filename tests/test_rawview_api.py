"""API des sorties brutes (contre le vrai serveur) et interface « Sorties brutes »."""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

import aule.rawview as rv
from aule.config import parse_config
from common import AuditCase
from test_rawview import rich_sarif
from test_sast_deps import make_rules
from test_server import ServerCase

HERE = Path(__file__).parent
q = urllib.parse.quote


class RawServerCase(ServerCase):
    """Run avec opengrep et CodeQL (vraies sorties SARIF des faux outils) + un SARIF riche, serveur lancé."""

    TOOLS = ["cloc", "gitleaks", "opengrep", "codeql"]
    REVEAL = True

    def setUp(self):
        AuditCase.setUp(self)
        repo = self.root / "repo-git"
        (repo / "service.py").write_text("import os\n\ndef run(cmd):\n    x = eval('1+1')\n    return x\n")
        (repo / "db.py").write_text("import sqlite3\n\ndef find(uid):\n    cur = sqlite3.connect('x').cursor()\n    cur.execute('SELECT * FROM t WHERE id=' + uid)\n")
        config = parse_config({"tools": {"opengrep": {"options": {"rules_path": str(make_rules(self.tmp))}}}}, self.tmp)
        self.run_id = self.run_audit(config, tool_names=self.TOOLS)
        base = self.data / "runs" / self.run_id / "repo-git"
        (base / "codeql" / "python" / "rich.sarif").write_text(json.dumps(rich_sarif()))
        self.rich = f"runs/{self.run_id}/repo-git/codeql/python/rich.sarif"
        self.codeql = f"runs/{self.run_id}/repo-git/codeql/python/report.sarif"
        self.opengrep = f"runs/{self.run_id}/repo-git/opengrep/scan/report.sarif"
        self.gitleaks = f"runs/{self.run_id}/repo-git/gitleaks/dir/report.json"
        self.start_server(self.REVEAL)

    def get(self, endpoint, **params):
        return self.call("GET", f"/api/{endpoint}?" + "&".join(f"{k}={q(str(v))}" for k, v in params.items()))


class RawApiTest(RawServerCase):
    def test_tree_puts_opengrep_and_codeql_first_and_lists_files(self):
        status, body, _ = self.get("raw/tree")
        self.assertEqual(status, 200)
        entries = body["entries"]
        order = [(e["tool"], e["mode"]) for e in entries if e["project"] == "repo-git"]
        self.assertIn(("opengrep", "scan"), order)
        self.assertIn(("codeql", "python"), order)
        ent = {(e["project"], e["tool"], e["mode"]): e for e in entries}
        cq = {f["name"]: f for f in ent[("repo-git", "codeql", "python")]["files"]}
        self.assertEqual((cq["report.sarif"]["kind"], cq["cmd.txt"]["kind"], cq["meta.json"]["kind"], cq["rich.sarif"]["path"]), ("sarif", "text", "json", self.rich))
        self.assertGreater(cq["report.sarif"]["size"], 100)
        self.assertEqual({f["name"] for f in ent[("repo-git", "codeql", "python")]["files"]} >= {"analyze.cmd.txt", "analyze.stdout.txt"}, True)
        self.assertEqual({f["kind"] for f in ent[("repo-git", "gitleaks", "dir")]["files"] if f["name"] == "report.json"}, {"json"})
        self.assertTrue(all(e["status"] for e in entries))

    def test_tree_survives_a_purged_run_directory(self):
        shutil.rmtree(self.data / "runs" / self.run_id / "repo-git" / "codeql")
        entries = self.get("raw/tree")[1]["entries"]
        gone = next(e for e in entries if e["tool"] == "codeql" and e["project"] == "repo-git")
        self.assertEqual(gone["files"], [])

    def test_text_paging_and_validation(self):
        path = f"runs/{self.run_id}/repo-git/opengrep/scan/cmd.txt"
        whole = (self.data / path).read_text()
        out, offset = "", 0
        while offset is not None:
            status, page, _ = self.get("raw/text", path=path, offset=offset, limit=11)
            self.assertEqual(status, 200)
            out, offset = out + page["text"], page["next"]
        self.assertEqual(out, whole)
        self.assertEqual(self.get("raw/text", path=path, offset="abc")[0], 400)
        self.assertEqual(self.get("raw/text", path=path + ".absent")[0], 404)

    def test_json_tree_and_table(self):
        status, root, _ = self.get("raw/json", path=self.gitleaks)
        self.assertEqual((status, root["type"], root["size"]), (200, "array", 1))
        node = self.get("raw/json", path=self.gitleaks, pointer="/0")[1]
        self.assertIn("RuleID", [c["key"] for c in node["children"]])
        leaf = self.get("raw/json", path=self.gitleaks, pointer="/0/RuleID")[1]
        self.assertEqual((leaf["type"], leaf["value"]), ("string", "github-pat"))
        self.assertEqual(self.get("raw/json", path=self.gitleaks, pointer="/9")[0], 404)
        rows = self.get("raw/rows", path=self.gitleaks)[1]
        self.assertIn("RuleID", rows["columns"])
        self.assertEqual((rows["total"], rows["rows"][0]["cells"]["RuleID"]), (1, "github-pat"))
        self.assertEqual(self.get("raw/rows", path=self.gitleaks, q="nothing-like-this")[1]["total"], 0)
        self.assertEqual(self.get("raw/rows", path=self.gitleaks, pointer="/0")[0], 400)               # pas un tableau

    def test_sarif_on_the_rich_file(self):
        s = self.get("sarif/summary", path=self.rich)[1]
        self.assertEqual((s["runs"][0]["tool"]["name"], s["runs"][0]["notifications_total"], s["runs"][0]["levels"]), ("CodeQL", 2, {"error": 1, "warning": 1, "note": 1}))
        rules = self.get("sarif/rules", path=self.rich)[1]["rules"]
        self.assertEqual({r["id"]: r["results"] for r in rules}, {"py/sql-injection": 2, "py/unused-import": 1, "py/never-fires": 0})
        page = self.get("sarif/results", path=self.rich, rule="py/sql-injection", limit=1)[1]
        self.assertEqual((page["total"], len(page["items"]), page["items"][0]["codeFlows_total"]), (2, 1, 2))
        one = self.get("sarif/results", path=self.rich, index=0)[1]["items"][0]
        self.assertEqual((one["rule"]["help"], one["codeFlows"][1]["threadFlows"][0]["steps"][0]["location"]["uri"]), ("## Overview\nUse parameters.", "web.py"))
        self.assertEqual(self.get("sarif/results", path=self.rich, line="15")[1]["items"][0]["index"], 1)
        self.assertEqual(self.get("sarif/results", path=self.rich, index=7)[0], 404)
        self.assertEqual(self.get("sarif/results", path=self.rich, run=3)[0], 404)
        self.assertEqual(self.get("sarif/results", path=self.rich, limit="x")[0], 400)

    def test_real_tool_outputs_are_complete_too(self):
        for path, tool in ((self.codeql, "CodeQL"), (self.opengrep, "Opengrep OSS")):
            s = self.get("sarif/summary", path=path)[1]
            self.assertEqual(s["runs"][0]["tool"]["name"], tool)
            r = self.get("sarif/results", path=path)[1]
            self.assertGreaterEqual(r["total"], 1)
            self.assertTrue(r["items"][0]["locations"][0]["uri"])
        d = self.get("sarif/results", path=self.codeql, rule="py/sql-injection")[1]["items"][0]
        self.assertEqual([s["location"]["message"] for s in d["codeFlows"][0]["threadFlows"][0]["steps"]], ["user-provided value", "sink reached here"])

    def test_errors_are_explicit(self):
        status, body, _ = self.get("sarif/summary", path=self.gitleaks)
        self.assertEqual((status, "n'est pas un SARIF" in body["error"]), (400, True))
        bad = self.data / "runs" / self.run_id / "bad.json"
        bad.write_text("{nope")
        status, body, _ = self.get("raw/json", path=f"runs/{self.run_id}/bad.json")
        self.assertEqual((status, "JSON invalide" in body["error"]), (400, True))
        with mock.patch.object(rv, "MAX_DOC_BYTES", 10):
            status, body, _ = self.get("raw/json", path=self.rich)
        self.assertEqual((status, "trop volumineux" in body["error"]), (413, True))

    def test_the_cache_follows_file_changes(self):
        self.assertEqual(self.get("sarif/results", path=self.rich)[1]["total"], 3)
        doc = rich_sarif()
        doc["runs"][0]["results"].append({"ruleId": "py/unused-import", "message": {"text": "nouveau"}})
        (self.data / self.rich).write_text(json.dumps(doc))
        self.assertEqual(self.get("sarif/results", path=self.rich)[1]["total"], 4)

    def test_confinement_and_token(self):
        endpoints = [("raw/text", {}), ("raw/json", {}), ("raw/rows", {}), ("sarif/summary", {}), ("sarif/rules", {}), ("sarif/results", {})]
        for endpoint, extra in endpoints:
            for bad in ("audit.db", "../audit.db", "runs/../audit.db", "/etc/passwd", f"runs/{self.run_id}/../../audit.db"):
                self.assertEqual(self.get(endpoint, path=bad, **extra)[0], 403, (endpoint, bad))
            self.assertEqual(self.call("GET", f"/api/{endpoint}?path={q(self.rich)}", token=False)[0], 403, endpoint)
        self.assertEqual(self.call("GET", "/api/raw/tree", token=False)[0], 403)


class MaskedRawTest(RawServerCase):
    REVEAL = False

    def test_raw_outputs_are_never_served_in_mask_mode(self):
        for endpoint, params in (("raw/tree", {}), ("raw/text", {"path": self.rich}), ("raw/json", {"path": self.rich}), ("raw/rows", {"path": self.gitleaks}),
                                 ("sarif/summary", {"path": self.rich}), ("sarif/rules", {"path": self.rich}), ("sarif/results", {"path": self.rich})):
            status, body, _ = self.get(endpoint, **params)
            self.assertEqual(status, 403, endpoint)
            self.assertIn("--mask", body["error"])


@unittest.skipUnless(shutil.which("node"), "node requis")
class RawUiTest(RawServerCase):
    def play(self) -> dict:
        import urllib.request
        page = self.tmp / "live.html"
        page.write_bytes(urllib.request.urlopen(self.base_url + "/").read())
        proc = subprocess.run(["node", str(HERE / "raw_scenario.js"), str(page), self.base_url], capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def test_auditor_explores_raw_outputs(self):
        out = self.play()
        tree = out["tree"]
        self.assertLess(tree.index("opengrep/scan"), tree.index("codeql/python"))             # opengrep et CodeQL en tête
        self.assertIn("gitleaks/dir", tree)
        self.assertIn("rich.sarif", tree)
        # SARIF : visionneuse complète
        self.assertIn("Résultats (3)", out["header"])
        for expected in ("Chemins de données (2)", "Chemin 1", "Chemin 2", "source", "essential", "web.py:9", "SQL query built from user-controlled sources", "Aide de la règle", "## Overview",
                         "Empreintes partielles", "abc:1", "Emplacements liés", "user-provided value", "Suppressions", "accepté", "contexte" if False else "context-lines", "db.find"):
            self.assertIn(expected, out["detail0"], expected)
        self.assertIn("#1", out["filtered"])
        self.assertNotIn("#0", out["filtered"])                                                # filtre « second » : un seul résultat
        self.assertIn("py/never-fires", out["rules"])                                          # règles sans résultat incluses
        self.assertIn("Python extractor: 2 files could not be parsed", out["notifs"])
        self.assertIn("à lire avant de conclure", out["notifs"])
        for expected in ("codeql/python-queries 1.4.0 (2 règles)", "réussie", "database analyze", "3 déclarée(s), 2 avec résultat(s)"):
            self.assertIn(expected, out["summary"])
        self.assertIn("racine", out["jsonRoot"])
        self.assertIn("runs", out["jsonOpen"])
        # autres outils : tableau JSON, ligne dépliée, texte
        self.assertIn("RuleID", out["table"])
        self.assertIn("github-pat", out["table"])
        self.assertIn("Secret", out["tableRow"])
        self.assertIn("opengrep scan", out["cmd"])
        # lien depuis un constat vers son résultat complet
        self.assertIn("py/sql-injection", out["deep"])
        self.assertIn("Chemins de données (1)", out["deep"])
        self.assertIn("sink reached here", out["deep"])


if __name__ == "__main__":
    unittest.main()
