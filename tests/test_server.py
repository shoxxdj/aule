"""Serveur local : sécurité, API, jobs. (L'interface JS est testée avec le vrai serveur dans test_live_ui.py.)"""
from __future__ import annotations

import http.client
import json
import os
import threading
import time
import unittest
from unittest import mock

import fakes
from aule.config import Config
from aule.server import make_server
from common import AuditCase


class ServerCase(AuditCase):
    TOOLS = ["cloc", "gitleaks", "links"]
    REVEAL = True

    def setUp(self):
        super().setUp()
        self.run_id = self.run_audit(tool_names=self.TOOLS)
        self.start_server(self.REVEAL)

    def start_server(self, reveal: bool, **kw):
        self.server = make_server(self.data / "audit.db", self.data, Config(), port=0, reveal=reveal, **kw)
        self.port = self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), self.server.server_close(), thread.join(5)))

    def call(self, method, path, body=None, *, token=True, headers=None, raw=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"X-Audit-Token": self.server.token} if token is True else ({"X-Audit-Token": token} if token else {})
        data = None
        if body is not None:
            data, h["Content-Type"] = (body if isinstance(body, str) else json.dumps(body)), "application/json"
        h.update(headers or {})
        conn.request(method, path, body=data, headers=h)
        resp = conn.getresponse()
        payload = resp.read()
        conn.close()
        return resp.status, (payload if raw else json.loads(payload or b"null")), resp


class SecurityTest(ServerCase):
    def test_only_loopback_is_accepted(self):
        for host in ("0.0.0.0", "192.168.1.10", "example.com"):
            with self.assertRaisesRegex(ValueError, "boucle locale"):
                make_server(self.data / "audit.db", self.data, Config(), host=host, port=0)

    def test_host_header_is_checked_against_dns_rebinding(self):
        status, body, _ = self.call("GET", "/api/runs", headers={"Host": "evil.example:8765"})
        self.assertEqual((status, "Host" in body["error"]), (421, True))
        self.assertEqual(self.call("GET", "/", headers={"Host": "evil.example"}, token=False)[0], 421)
        self.assertEqual(self.call("GET", "/api/runs", headers={"Host": f"localhost:{self.port}"})[0], 200)

    def test_allowed_host_for_ssh_tunnels(self):
        self.start_server(True, allowed_hosts=("localhost:9000",))
        self.assertEqual(self.call("GET", "/api/runs", headers={"Host": "localhost:9000"})[0], 200)
        self.assertEqual(self.call("GET", "/api/runs", headers={"Host": "localhost:9001"})[0], 421)

    def test_token_is_required_for_the_whole_api(self):
        for path in ("/api/runs", "/api/data", "/api/jobs/current", "/api/raw?path=x", "/api/export"):
            self.assertEqual(self.call("GET", path, token=False)[0], 403, path)
            self.assertEqual(self.call("GET", path, token="wrong")[0], 403, path)
        self.assertEqual(self.call("POST", "/api/triage", {"fingerprints": [], "status": "confirmed"}, token=False)[0], 403)

    def test_page_carries_the_token_and_strict_headers(self):
        status, html, resp = self.call("GET", "/", token=False, raw=True)
        self.assertEqual(status, 200)
        self.assertIn(self.server.token.encode(), html)
        self.assertIn("connect-src 'self'", resp.headers["Content-Security-Policy"])
        self.assertIn("default-src 'none'", resp.headers["Content-Security-Policy"])
        self.assertEqual((resp.headers["X-Frame-Options"], resp.headers["Cache-Control"], resp.headers["X-Content-Type-Options"]),
                         ("DENY", "no-store", "nosniff"))
        self.assertEqual(html.count(b"</script>"), 2)

    def test_csrf_protections_on_writes(self):
        body = {"fingerprints": ["x" * 24], "status": "confirmed"}
        self.assertEqual(self.call("POST", "/api/triage", body, headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.call("POST", "/api/triage", body, headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)
        conn = http.client.HTTPConnection("127.0.0.1", self.port)           # formulaire « simple » : text/plain
        conn.request("POST", "/api/triage", body=json.dumps(body), headers={"X-Audit-Token": self.server.token, "Content-Type": "text/plain"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 415)
        self.assertEqual(self.call("POST", "/api/triage", "{not json")[0], 400)
        self.assertEqual(self.call("POST", "/api/triage", "[1,2]")[0], 400)
        # corps annoncé trop gros : refusé sur l'en-tête, sans le lire ni le recevoir
        status, body413, resp = self.call("POST", "/api/triage", "{}", headers={"Content-Length": str(5 * 1024 * 1024 + 10)})
        self.assertEqual((status, resp.headers["Connection"]), (413, "close"))

    def test_errors_close_the_connection_to_avoid_request_desync(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("POST", "/api/triage", body="x" * 10, headers={"X-Audit-Token": "wrong", "Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        self.assertEqual((resp.status, resp.headers["Connection"]), (403, "close"))
        conn.close()

    def test_unknown_routes_and_errors_are_json(self):
        self.assertEqual(self.call("GET", "/api/nope")[0], 404)
        self.assertEqual(self.call("GET", "/secret-file", token=False)[0], 404)
        status, body, _ = self.call("GET", "/api/data?run=nope")
        self.assertEqual((status, "nope" in body["error"]), (404, True))


class ApiTest(ServerCase):
    def test_data_payload(self):
        status, d, _ = self.call("GET", "/api/data")
        self.assertEqual(status, 200)
        self.assertTrue(d["options"]["live"] and d["options"]["token"] == self.server.token and d["options"]["reveal"])
        self.assertEqual([a["id"] for a in d["options"]["audits"]], [self.run_id])
        tools = {t["name"]: t for t in d["options"]["tools"]}
        self.assertTrue(tools["cloc"]["enabled"] and tools["cloc"]["available"])
        self.assertFalse(tools["codeql"]["enabled"])
        self.assertTrue(all(s["secret"] in (fakes.SECRET_A, fakes.SECRET_B) for s in d["secrets"]))
        self.assertEqual(self.call("GET", f"/api/data?run={self.run_id}")[1]["audit"]["id"], self.run_id)

    def test_triage_roundtrip_and_validation(self):
        fps = [e["fingerprint"] for e in self.db.entities(self.run_id, "secret")][:2]
        status, body, _ = self.call("POST", "/api/triage", {"fingerprints": fps, "status": "false_positive", "comment": "clé de démo"})
        self.assertEqual((status, body["updated"]), (200, 2))
        d = self.call("GET", "/api/data")[1]
        got = {s["fingerprint"]: (s["triage"], s["triage_comment"]) for s in d["secrets"]}
        self.assertEqual({got[f] for f in fps}, {("false_positive", "clé de démo")})
        self.assertEqual(self.call("POST", "/api/triage/clear", {"fingerprints": fps[:1]})[1]["cleared"], 1)
        self.assertIsNone(self.db.list_triage().get(fps[0]))
        self.assertEqual(self.call("POST", "/api/triage", {"fingerprints": fps, "status": "banana"})[0], 400)
        self.assertEqual(self.call("POST", "/api/triage", {"fingerprints": "nope", "status": "confirmed"})[0], 400)
        self.assertEqual(self.call("POST", "/api/triage", {"fingerprints": fps, "status": "confirmed", "comment": "x" * 3000})[0], 400)

    def test_findings_crud(self):
        status, f, _ = self.call("POST", "/api/findings", {"project": "plain", "title": "Clé dans le dépôt", "severity": "high", "refs": ["a" * 24]})
        self.assertEqual((status, f["status"], f["refs"]), (201, "draft", ["a" * 24]))
        status, f, _ = self.call("PUT", f"/api/findings/{f['id']}", {"status": "confirmed", "description": "Constaté."})
        self.assertEqual((status, f["status"], f["description"], f["title"]), (200, "confirmed", "Constaté.", "Clé dans le dépôt"))
        self.assertEqual([x["title"] for x in self.call("GET", "/api/data")[1]["findings"]], ["Clé dans le dépôt"])
        self.assertEqual(self.call("POST", "/api/findings", {"project": "p", "title": "t", "severity": "banana"})[0], 400)
        self.assertEqual(self.call("POST", "/api/findings", {"project": "p"})[0], 400)
        self.assertEqual(self.call("PUT", "/api/findings/999", {"title": "x"})[0], 404)
        self.assertEqual(self.call("PUT", "/api/findings/abc", {"title": "x"})[0], 404)
        self.assertEqual(self.call("DELETE", f"/api/findings/{f['id']}")[0], 200)
        self.assertEqual(self.call("DELETE", f"/api/findings/{f['id']}")[0], 404)

    def test_notes(self):
        self.assertEqual(self.call("PUT", "/api/notes/plain", {"text": "Exposé sur Internet"})[0], 200)
        self.assertEqual(self.call("PUT", "/api/notes/mon%20projet", {"text": "espace"})[0], 200)
        notes = self.call("GET", "/api/data")[1]["notes"]
        self.assertEqual(notes, {"plain": "Exposé sur Internet", "mon projet": "espace"})
        self.call("PUT", "/api/notes/plain", {"text": ""})
        self.assertNotIn("plain", self.call("GET", "/api/data")[1]["notes"])
        self.assertEqual(self.call("PUT", "/api/notes/plain", {})[0], 400)

    def test_diff_endpoint(self):
        run2 = self.run_audit(tool_names=self.TOOLS)
        status, d, _ = self.call("GET", f"/api/diff?a={self.run_id}&b={run2}")
        self.assertEqual((status, d["a"], d["b"]), (200, self.run_id, run2))
        self.assertEqual(d["counts"]["new"] + d["counts"]["fixed"], 0)
        self.assertEqual(self.call("GET", f"/api/diff?a=nope&b={run2}")[0], 404)
        self.assertEqual(self.call("GET", f"/api/diff?a={self.run_id}")[1]["b"], run2)       # b = dernier run par défaut

    def test_raw_files_are_confined_to_runs(self):
        rel = f"runs/{self.run_id}/plain/gitleaks/dir/report.json"
        status, body, resp = self.call("GET", f"/api/raw?path={rel}", raw=True)
        self.assertEqual((status, resp.headers["Content-Type"].split(";")[0]), (200, "text/plain"))
        self.assertIn(fakes.SECRET_A.encode(), body)
        for bad in ("audit.db", "../audit.db", f"runs/../audit.db", "../../etc/passwd", "/etc/passwd", f"runs/{self.run_id}/../../audit.db"):
            self.assertEqual(self.call("GET", f"/api/raw?path={bad}")[0], 403, bad)
        self.assertEqual(self.call("GET", f"/api/raw?path=runs/{self.run_id}/nope.txt")[0], 404)
        big = self.data / "runs" / self.run_id / "big.bin"
        big.write_bytes(b"x" * (5 * 1024 * 1024 + 1))
        self.assertEqual(self.call("GET", f"/api/raw?path=runs/{self.run_id}/big.bin")[0], 413)

    def test_export_download(self):
        status, body, resp = self.call("GET", "/api/export?format=csv", raw=True)
        self.assertEqual(status, 200)
        self.assertIn("text/csv", resp.headers["Content-Type"])
        self.assertIn("attachment", resp.headers["Content-Disposition"])
        self.assertIn(fakes.SECRET_B.encode(), body)
        self.assertNotIn(fakes.SECRET_B.encode(), self.call("GET", "/api/export?format=csv&mask=1", raw=True)[1])
        self.assertEqual(self.call("GET", "/api/export?format=pdf")[0], 400)
        self.assertEqual(self.call("GET", "/api/export?format=xlsx", raw=True)[1][:2], b"PK")


class MaskedServerTest(ServerCase):
    REVEAL = False

    def test_secrets_never_leave_unless_asked_one_by_one(self):
        d = self.call("GET", "/api/data")[1]
        self.assertFalse(d["options"]["reveal"])
        self.assertFalse(any("secret" in s or "match" in s for s in d["secrets"]))
        page = self.call("GET", "/", token=False, raw=True)[1]
        for secret in (fakes.SECRET_A, fakes.SECRET_B):
            self.assertNotIn(secret.encode(), page)
        fp = next(s["fingerprint"] for s in d["secrets"] if s["rule_id"] == "aws-access-token")
        status, one, _ = self.call("GET", f"/api/secret?fingerprint={fp}")
        self.assertEqual((status, one["secret"]), (200, fakes.SECRET_A))
        self.assertEqual(self.call("GET", "/api/secret?fingerprint=nope")[0], 404)

    def test_export_cannot_reveal_and_raw_is_disabled(self):
        self.assertNotIn(fakes.SECRET_B.encode(), self.call("GET", "/api/export?format=csv", raw=True)[1])    # mask=0 ignoré
        status, body, _ = self.call("GET", f"/api/raw?path=runs/{self.run_id}/plain/gitleaks/dir/report.json")
        self.assertEqual(status, 403)
        self.assertIn("--mask", body["error"])

    def test_tampered_raw_report_is_refused_not_trusted(self):
        fp = self.call("GET", "/api/data")[1]["secrets"][0]["fingerprint"]
        ent = next(e for e in self.db.entities(self.run_id, "secret") if e["fingerprint"] == fp)
        run = next(r for r in self.db.list_tool_runs(self.run_id) if r["id"] == ent["tool_run_id"])
        path = self.data / run["raw_dir"] / "report.json"
        path.write_text(path.read_text() + " ")
        status, body, _ = self.call("GET", f"/api/secret?fingerprint={fp}")
        self.assertEqual(status, 409)
        self.assertIn("modifiée", body["error"])


class JobTest(ServerCase):
    def wait(self, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            snap = self.call("GET", "/api/jobs/current")[1]
            if snap["state"] != "running":
                return snap
            time.sleep(0.1)
        self.fail("l'audit ne se termine pas")

    def test_launch_and_follow_an_audit(self):
        self.assertEqual(self.call("GET", "/api/jobs/current")[1]["state"], "idle")
        status, body, _ = self.call("POST", "/api/jobs", {"root": str(self.root), "tools": ["cloc", "gitleaks"]})
        self.assertEqual((status, body), (202, {"started": True}))
        snap = self.wait()
        self.assertEqual(snap["state"], "finished")
        self.assertEqual((snap["done"], snap["total"]) == (snap["total"], snap["total"]), True)
        self.assertTrue(any(ln.startswith("Run ") for ln in snap["log"]) and any("(1/" in ln for ln in snap["log"]))
        runs = self.call("GET", "/api/runs")[1]["runs"]
        self.assertEqual(len(runs), 2)
        self.assertEqual(snap["run_id"], runs[0]["id"])
        # lecture incrémentale du journal
        tail = self.call("GET", f"/api/jobs/current?since={snap['next']}")[1]
        self.assertEqual((tail["log"], tail["next"]), ([], snap["next"]))

    def test_second_launch_is_refused_while_running_then_allowed(self):
        with mock.patch.dict(os.environ, {"FAKE_CODEQL_DELAY": "1.5"}):
            self.assertEqual(self.call("POST", "/api/jobs", {"root": str(self.root), "tools": ["cloc", "codeql"]})[0], 202)
            status, body, _ = self.call("POST", "/api/jobs", {"root": str(self.root), "tools": ["cloc"]})
            self.assertEqual((status, "déjà en cours" in body["error"]), (409, True))
            self.assertEqual(self.wait()["state"], "finished")
        self.assertEqual(self.call("POST", "/api/jobs", {"root": str(self.root), "tools": ["cloc"]})[0], 202)
        self.assertEqual(self.wait()["state"], "finished")

    def test_validation(self):
        self.assertEqual(self.call("POST", "/api/jobs", {"root": "/nonexistent-dir"})[0], 400)
        status, body, _ = self.call("POST", "/api/jobs", {"root": str(self.root), "tools": ["nope"]})
        self.assertEqual((status, "inconnu" in body["error"]), (400, True))
        self.assertEqual(self.call("POST", "/api/jobs", {})[0], 400)
        self.assertEqual(self.call("GET", "/api/jobs/current")[1]["state"], "idle")          # aucun job lancé par erreur

    def test_options_with_unpack_and_history(self):
        from test_unpack import zip_dir
        zip_dir(self.root / "repo-git", self.root / "plain" / "site.zip", wrapper="repo-main")
        self.call("POST", "/api/jobs", {"root": str(self.root), "unpack": True, "history": True})
        self.assertEqual(self.wait()["state"], "finished")
        newest = self.call("GET", "/api/runs")[1]["runs"][0]["id"]
        names = {p["name"] for p in self.db.list_projects(newest)}
        self.assertIn("plain@site.zip", names)
        self.assertTrue(self.db.entities(newest, "commit"))                                  # gittools actif via « history »

    def test_a_failing_audit_reports_an_error_instead_of_hanging(self):
        (self.root / ".only-hidden").mkdir()
        empty = self.tmp / "empty-root"
        empty.mkdir()
        self.call("POST", "/api/jobs", {"root": str(empty)})
        snap = self.wait()
        self.assertEqual(snap["state"], "error")
        self.assertIn("aucun sous-dossier", snap["error"])
        self.assertEqual(self.call("POST", "/api/jobs", {"root": str(self.root), "tools": ["cloc"]})[0], 202)   # reprise possible


if __name__ == "__main__":
    unittest.main()
