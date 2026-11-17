"""Sorties brutes : pagination, arbre/tableau JSON, SARIF complet, API (confinement, --mask), interface, rapport de partage."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import aule.rawview as rv
from aule.config import Config, parse_config
from aule.rawview import DocCache, file_kind, json_node, json_rows, read_text, result_detail, sarif_results, sarif_rules, sarif_summary
from aule.server import make_server
from common import AuditCase
from test_server import ServerCase
from test_sast_deps import make_rules

HERE = Path(__file__).parent


def step(uri, line, msg, nesting=None, importance=None):
    out = {"location": {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}, "message": {"text": msg}}}
    if nesting is not None:
        out["nestingLevel"] = nesting
    if importance:
        out["importance"] = importance
    return out


def rich_sarif() -> dict:
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.20.1", "organization": "GitHub", "informationUri": "https://codeql.github.com", "rules": [
            {"id": "py/sql-injection", "name": "py/sql-injection", "shortDescription": {"text": "SQL query built from user-controlled sources"},
             "fullDescription": {"text": "Building a SQL query from user-controlled sources is vulnerable to insertion of malicious SQL code."},
             "help": {"text": "## Overview\nUse parameters.", "markdown": "## Overview\nUse **parameters**."}, "helpUri": "https://codeql.github.com/codeql-query-help/python/py-sql-injection/",
             "defaultConfiguration": {"level": "error", "enabled": True, "rank": 88.5},
             "properties": {"tags": ["security", "external/cwe/cwe-089"], "precision": "high", "security-severity": "8.8", "problem.severity": "error"},
             "relationships": [{"target": {"id": "CWE-89"}}]},
            {"id": "py/unused-import", "name": "py/unused-import", "defaultConfiguration": {"level": "note"}},
            {"id": "py/never-fires", "name": "never"}],
            }, "extensions": [{"name": "codeql/python-queries", "semanticVersion": "1.4.0", "organization": "GitHub", "rules": [{"id": "a"}, {"id": "b"}]}]},
        "invocations": [{"executionSuccessful": True, "exitCode": 0, "commandLine": "codeql database analyze db qls --format=sarif-latest", "startTimeUtc": "2026-01-01T10:00:00Z",
                         "endTimeUtc": "2026-01-01T10:05:00Z", "toolExecutionNotifications": [{"level": "warning", "message": {"text": "Python extractor: 2 files could not be parsed"},
                         "descriptor": {"id": "py/diagnostics/extraction-warnings"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "broken.py"}}}]}],
                         "toolConfigurationNotifications": [{"level": "note", "message": {"text": "config note"}}]}],
        "artifacts": [{"location": {"uri": "db.py"}}, {"location": {"uri": "service.py"}}], "taxonomies": [{"name": "CWE", "taxa": [{"id": "89"}, {"id": "79"}]}],
        "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///work/proj/"}}, "columnKind": "utf16CodeUnits", "defaultSourceLanguage": "python",
        "results": [
            {"ruleId": "py/sql-injection", "ruleIndex": 0, "rule": {"id": "py/sql-injection", "index": 0}, "kind": "fail", "baselineState": "new", "rank": 9.5,
             "message": {"text": "This query depends on a user-provided value.", "markdown": "This query depends on [a user-provided value](1)."},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "db.py", "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": 5, "startColumn": 5, "endLine": 5, "endColumn": 40, "snippet": {"text": "cur.execute(q + uid)"}},
                            "contextRegion": {"startLine": 4, "endLine": 6, "snippet": {"text": "context-lines"}}}, "logicalLocations": [{"fullyQualifiedName": "db.find"}]}],
             "relatedLocations": [{"id": 1, "physicalLocation": {"artifactLocation": {"uri": "db.py"}, "region": {"startLine": 3}}, "message": {"text": "user-provided value"}}],
             "codeFlows": [{"message": {"text": "flow A"}, "threadFlows": [{"id": "t1", "locations": [step("db.py", 3, "source", 0, "essential"), step("db.py", 5, "sink", 1)]}]},
                           {"message": {"text": "flow B"}, "threadFlows": [{"locations": [step("web.py", 9, "request.args"), step("db.py", 5, "sink")]}]}],
             "partialFingerprints": {"primaryLocationLineHash": "abc:1"}, "fingerprints": {"x/v1": "y"}, "suppressions": [{"kind": "inSource", "justification": "accepté"}],
             "properties": {"custom": 1}, "taxa": [{"id": "89", "toolComponent": {"name": "CWE"}}], "occurrenceCount": 2},
            {"ruleId": "py/sql-injection", "ruleIndex": 0, "level": "warning", "message": {"text": "second"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "other.py"}, "region": {"startLine": 10, "endLine": 20}}}]},
            {"ruleId": "py/unused-import", "ruleIndex": 1, "message": {"text": "unused"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "service.py"}, "region": {"startLine": 1}}}]},
        ]}]}


class FileKindAndTextTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_file_kinds(self):
        for name, kind in (("r.sarif", "sarif"), ("r.json", "json"), ("r.jsonl", "jsonl"), ("cmd.txt", "text"), ("x.log", "text"), ("page.html", "text")):
            self.assertEqual(file_kind(Path(name)), kind, name)
        (self.tmp / "blob.dat").write_bytes(b"\x00\x01binary")
        (self.tmp / "plain.dat").write_text("hello")
        self.assertEqual((file_kind(self.tmp / "blob.dat"), file_kind(self.tmp / "plain.dat"), file_kind(self.tmp / "absent.dat")), ("binary", "text", "binary"))

    def test_paging_reconstructs_the_file_and_never_splits_a_character(self):
        text = "é€😀" * 300 + "fin\n"
        f = self.tmp / "u.txt"
        f.write_text(text, encoding="utf-8")
        out, offset, pages = "", 0, 0
        while offset is not None:
            page = read_text(f, offset, 7)
            self.assertNotIn("\ufffd", page["text"])
            out, offset, pages = out + page["text"], page["next"], pages + 1
        self.assertEqual(out, text)
        self.assertGreater(pages, 100)
        self.assertEqual(read_text(f, 10**6)["text"], "")
        self.assertEqual(read_text(f, 0, 10**9)["end"], f.stat().st_size)         # plafonné à 1 Mo
        self.assertEqual(read_text(f, -5)["offset"], 0)


class DocCacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_invalidation_eviction_and_limits(self):
        cache, f = DocCache(maxdocs=2), self.tmp / "a.json"
        f.write_text('{"x": 1}')
        doc, _ = cache.get(f)
        self.assertIs(cache.get(f)[0], doc)                                    # servi depuis le cache
        f.write_text('{"x": 2, "y": 3}')
        self.assertEqual(cache.get(f)[0], {"x": 2, "y": 3})                    # fichier modifié : rechargé
        for i in range(3):
            (self.tmp / f"{i}.json").write_text("[]")
            cache.get(self.tmp / f"{i}.json")
        self.assertLessEqual(len(cache.docs), 2)
        (self.tmp / "bad.json").write_text("{nope")
        with self.assertRaisesRegex(ValueError, "JSON invalide"):
            cache.get(self.tmp / "bad.json")
        with mock.patch.object(rv, "MAX_DOC_BYTES", 5), self.assertRaisesRegex(ValueError, "trop volumineux"):
            DocCache().get(f)

    def test_jsonl_tolerates_bad_lines(self):
        f = self.tmp / "r.jsonl"
        f.write_text('{"a": 1}\n\nnot json\n{"a": 2}\n')
        doc, _ = DocCache().get(f)
        self.assertEqual([d.get("a") for d in doc], [1, None, 2])
        self.assertEqual(doc[1]["_ligne_invalide"], 3)


class JsonExplorerTest(unittest.TestCase):
    DOC = {"a/b": [1, {"c~d": "x" * 30_000}, "court"], "list": [{"k": 1, "n": {"z": 2}, "arr": [1, 2]}, {"k": 2}, {"k": 3, "extra": True}]}

    def test_tree_pointers_paging_and_escaping(self):
        root = json_node(self.DOC, "")
        self.assertEqual([(c["key"], c["type"], c["size"]) for c in root["children"]], [("a/b", "array", 3), ("list", "array", 3)])
        child = root["children"][0]["pointer"]
        self.assertEqual(child, "/a~1b")                                       # « / » dans une clé : échappé
        node = json_node(self.DOC, child)
        self.assertEqual([c["type"] for c in node["children"]], ["number", "object", "string"])
        inner = json_node(self.DOC, node["children"][1]["pointer"])
        self.assertEqual(inner["children"][0]["pointer"], "/a~1b/1/c~0d")      # « ~ » échappé aussi
        leaf = json_node(self.DOC, inner["children"][0]["pointer"])
        self.assertEqual((leaf["type"], leaf["size"], len(leaf["value"]), leaf["truncated"]), ("string", 30_000, 20_000, True))
        page = json_node({"big": list(range(250))}, "/big", offset=100, limit=50)
        self.assertEqual((page["total"], len(page["children"]), page["children"][0]["key"]), (250, 50, 100))
        with self.assertRaises(KeyError):
            json_node(self.DOC, "/nope")
        with self.assertRaises(KeyError):
            json_node(self.DOC, "/list/99")

    def test_table_view(self):
        t = json_rows(self.DOC, "/list")
        self.assertEqual(t["columns"], ["k", "n", "arr", "extra"])
        self.assertEqual(t["rows"][0]["cells"], {"k": "1", "n": "{1 clé(s)}", "arr": "[2]", "extra": ""})
        self.assertEqual((t["total"], t["all"]), (3, 3))
        q = json_rows(self.DOC, "/list", q="EXTRA")
        self.assertEqual([r["index"] for r in q["rows"]], [2])                  # filtre sur tout le contenu, sans casse
        self.assertEqual(json_rows(self.DOC, "/list", offset=1, limit=1)["rows"][0]["index"], 1)
        with self.assertRaisesRegex(ValueError, "tableau"):
            json_rows(self.DOC, "")
        self.assertEqual(json_rows({"x": [1, "a"]}, "/x")["columns"], ["valeur"])      # tableau de scalaires


class SarifTest(unittest.TestCase):
    def setUp(self):
        self.doc = rich_sarif()

    def test_summary(self):
        s = sarif_summary(self.doc)
        run = s["runs"][0]
        self.assertEqual((s["version"], run["tool"]["name"], run["tool"]["version"], run["tool"]["organization"]), ("2.1.0", "CodeQL", "2.20.1", "GitHub"))
        self.assertEqual(run["extensions"], [{"name": "codeql/python-queries", "version": "1.4.0", "organization": "GitHub", "rules": 2}])
        self.assertEqual(run["levels"], {"error": 1, "warning": 1, "note": 1})            # niveau de la règle quand le résultat n'en a pas
        self.assertEqual((run["results"], run["rules"]), (3, {"declared": 3, "with_results": 2}))
        self.assertEqual(run["top_rules"], [{"id": "py/sql-injection", "count": 2}, {"id": "py/unused-import", "count": 1}])
        self.assertEqual(run["notifications_total"], 2)
        self.assertEqual({n["kind"] for n in run["notifications"]}, {"exécution", "configuration"})
        n = next(n for n in run["notifications"] if n["kind"] == "exécution")
        self.assertEqual((n["level"], n["descriptor"], n["locations"][0]["uri"]), ("warning", "py/diagnostics/extraction-warnings", "broken.py"))
        self.assertEqual((run["invocations"][0]["executionSuccessful"], run["invocations"][0]["exitCode"]), (True, 0))
        self.assertIn("database analyze", run["invocations"][0]["commandLine"])
        self.assertEqual((run["artifacts"], run["taxonomies"], run["columnKind"], run["defaultSourceLanguage"]), (2, [{"name": "CWE", "taxa": 2}], "utf16CodeUnits", "python"))
        self.assertIn("%SRCROOT%", run["originalUriBaseIds"])

    def test_rules_include_those_without_results(self):
        rules = {r["id"]: r for r in sarif_rules(self.doc)}
        self.assertEqual({k: v["results"] for k, v in rules.items()}, {"py/sql-injection": 2, "py/unused-import": 1, "py/never-fires": 0})
        r = rules["py/sql-injection"]
        self.assertEqual((r["defaultLevel"], r["enabled"], r["rank"], r["helpUri"].split("/")[-2]), ("error", True, 88.5, "py-sql-injection"))
        self.assertEqual((r["help"], r["helpMarkdown"]), ("## Overview\nUse parameters.", "## Overview\nUse **parameters**."))
        self.assertEqual((r["properties"]["security-severity"], r["properties"]["tags"][1], r["relationships"][0]["target"]["id"]), ("8.8", "external/cwe/cwe-089", "CWE-89"))

    def test_a_result_is_returned_complete(self):
        d = sarif_results(self.doc, index=0)["items"][0]
        self.assertEqual((d["ruleId"], d["effectiveLevel"], d["level"], d["kind"], d["baselineState"], d["rank"], d["occurrenceCount"]), ("py/sql-injection", "error", None, "fail", "new", 9.5, 2))
        self.assertEqual(d["message"], {"text": "This query depends on a user-provided value.", "markdown": "This query depends on [a user-provided value](1)."})
        loc = d["locations"][0]
        self.assertEqual((loc["uri"], loc["uriBaseId"], loc["region"]["startColumn"], loc["region"]["snippet"], loc["contextRegion"]["snippet"], loc["logical"]),
                         ("db.py", "%SRCROOT%", 5, "cur.execute(q + uid)", "context-lines", ["db.find"]))
        self.assertEqual((d["relatedLocations"][0]["id"], d["relatedLocations"][0]["message"]), (1, "user-provided value"))
        self.assertEqual((d["codeFlows_total"], len(d["codeFlows"])), (2, 2))                  # TOUS les chemins, pas seulement le premier
        a, b = d["codeFlows"]
        self.assertEqual((a["message"], a["threadFlows"][0]["id"], [(s["location"]["message"], s["nestingLevel"], s["importance"]) for s in a["threadFlows"][0]["steps"]]),
                         ("flow A", "t1", [("source", 0, "essential"), ("sink", 1, None)]))
        self.assertEqual([s["location"]["uri"] for s in b["threadFlows"][0]["steps"]], ["web.py", "db.py"])
        self.assertEqual((d["partialFingerprints"], d["fingerprints"], d["suppressions"][0]["justification"], d["properties"], d["taxa"][0]["id"]),
                         ({"primaryLocationLineHash": "abc:1"}, {"x/v1": "y"}, "accepté", {"custom": 1}, "89"))
        rule = d["rule"]
        self.assertEqual((rule["id"], rule["shortDescription"], rule["properties"]["precision"]), ("py/sql-injection", "SQL query built from user-controlled sources", "high"))

    def test_filters_paging_and_index(self):
        ids = lambda **kw: [r["index"] for r in sarif_results(self.doc, **kw)["items"]]
        self.assertEqual(ids(), [0, 1, 2])
        self.assertEqual(ids(rule="py/sql-injection"), [0, 1])
        self.assertEqual((ids(level="error"), ids(level="note"), ids(level="warning")), ([0], [2], [1]))
        self.assertEqual((ids(q="SECOND"), ids(q="py/unused"), ids(q="other.py")), ([1], [2], [1]))
        self.assertEqual((ids(file="service"), ids(line=15), ids(line=5), ids(line=99)), ([2], [1], [0], []))
        self.assertEqual(ids(rule="py/sql-injection", line=15), [1])               # filtres cumulés
        p = sarif_results(self.doc, offset=1, limit=1)
        self.assertEqual(([r["index"] for r in p["items"]], p["total"]), ([1], 3))
        self.assertEqual(sarif_results(self.doc, index=2)["items"][0]["ruleId"], "py/unused-import")
        with self.assertRaises(KeyError):
            sarif_results(self.doc, index=3)
        with self.assertRaises(KeyError):
            sarif_results(self.doc, run_idx=4)

    def test_big_flows_are_capped_but_the_total_is_reported(self):
        doc = rich_sarif()
        res = doc["runs"][0]["results"][0]
        res["codeFlows"] = [{"threadFlows": [{"locations": [step("a.py", i, f"s{i}") for i in range(400)]}]} for _ in range(25)]
        d = sarif_results(doc, index=0)["items"][0]
        self.assertEqual((d["codeFlows_total"], len(d["codeFlows"])), (25, 20))
        tf = d["codeFlows"][0]["threadFlows"][0]
        self.assertEqual((tf["total_steps"], len(tf["steps"])), (400, 300))

    def test_malformed_documents_never_crash_the_explorer(self):
        weird = {"runs": [{"tool": None, "results": [{"locations": [None, "x", {"physicalLocation": None}], "message": None, "ruleId": None, "relatedLocations": [None],
                                                       "codeFlows": [{"threadFlows": [{"locations": [None, {"location": None}]}]}]},
                                                      {"ruleId": "r", "ruleIndex": "zero", "locations": None}], "rules": 5}, {"results": None}, {}]}
        s = sarif_summary(weird)
        self.assertEqual([r["results"] for r in s["runs"]], [2, 0, 0])
        page = sarif_results(weird, 0, q="r", file="x")                          # le filtrage parcourt aussi les éléments non conformes
        self.assertEqual(page["all"], 2)
        sarif_results(weird, 0, line=3)
        self.assertEqual(sarif_results(weird, 0, index=0)["items"][0]["codeFlows"][0]["threadFlows"][0]["total_steps"], 2)
        self.assertEqual(sarif_rules(weird, 1), [])
        odd = {"runs": [{"invocations": [None, "x", {"toolExecutionNotifications": [None, 3, {"message": None, "locations": "nope", "exception": "x"}], "workingDirectory": None}],
                         "taxonomies": [None, {"name": "CWE", "taxa": None}], "tool": {"driver": {"rules": [None, {"id": "ok"}]}, "extensions": [None, {"name": "e"}]},
                         "artifacts": "x", "results": [{"ruleId": "ok"}]}]}
        run = sarif_summary(odd)["runs"][0]
        self.assertEqual((run["notifications_total"], run["rules"], run["extensions"][0]["name"] if run["extensions"] else None), (1, {"declared": 1, "with_results": 1}, "e"))
        self.assertEqual(sarif_rules(odd, 0)[0]["id"], "ok")


if __name__ == "__main__":
    unittest.main()
