"""Faux LibreChat (API Agents : jeton Bearer, /models, /chat/completions, /responses) pour les tests, avec pannes scriptables et TLS réel."""
from __future__ import annotations

import json
import ssl
import subprocess
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "lc-9f8e7d6c5b4a3210fedcba9876543210"
BASE = "/api/agents/v1"


def make_certs(folder: Path) -> dict[str, Path]:
    """Autorité privée + certificat serveur (localhost, 127.0.0.1) signé par elle : pour tester ca_file ET la vérification TLS."""
    def run(*cmd):
        subprocess.run(cmd, cwd=folder, check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=Aule Test CA", "-days", "2")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv.key", "-out", "srv.csr", "-subj", "/CN=localhost")
    (folder / "ext.cnf").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n")
    run("openssl", "x509", "-req", "-in", "srv.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", "srv.crt", "-days", "2", "-extfile", "ext.cnf")
    return {"ca": folder / "ca.crt", "cert": folder / "srv.crt", "key": folder / "srv.key"}


def verdict_json(v="uncertain", confidence=0.7, reasoning="Raison de test.", need=None) -> str:
    out = {"verdict": v, "confidence": confidence, "reasoning": reasoning, "injection_suspected": False}
    if need is not None:
        out["need"] = need
    return json.dumps(out)


class FakeLibreChat:
    """`responder(payload, n)` renvoie : un str (contenu de la réponse), ("http", statut, corps[, en-têtes]), ("sleep", s) ou ("raw", objet JSON complet)."""

    def __init__(self, token: str = TOKEN, agents: dict[str, str] | None = None, responder=None, tls: dict[str, Path] | None = None, echo_credentials: bool = False):
        self.token = token
        self.agents = agents if agents is not None else {"agent_abc123": "Relecteur sécurité", "agent_autre": "Autre agent"}
        self.responder = responder or (lambda payload, n: verdict_json())
        self.requests: list[dict] = []
        self.chats = 0
        self.echo = echo_credentials
        self.models_override = None  # ex. ("http", 403, {...}) pour simuler une panne sur la liste des agents
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _send(self, status: int, obj, headers: dict | None = None):
                body = obj if isinstance(obj, bytes) else json.dumps(obj).encode("utf-8")
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    for k, v in (headers or {}).items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def _auth(self) -> bool:
                got = self.headers.get("Authorization", "")
                if got == f"Bearer {outer.token}":
                    return True
                msg = "Invalid or expired API key" + (f" (received: {got})" if outer.echo else "")
                self._send(401, {"error": {"message": msg, "type": "invalid_request_error"}})
                return False

            def _record(self, payload):
                with outer.lock:
                    outer.requests.append({"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "json": payload})

            def do_GET(self):
                self._record(None)
                if not self._auth():
                    return
                if self.path == f"{BASE}/models" and outer.models_override:
                    res = outer.models_override
                    return self._send(res[1], res[2], res[3] if len(res) > 3 else None)
                if self.path == f"{BASE}/models":
                    return self._send(200, {"object": "list", "data": [{"id": i, "object": "model", "name": n, "owned_by": "you"} for i, n in outer.agents.items()]})
                self._send(404, {"error": {"message": "Not found"}})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                self._record(payload)
                if not self._auth():
                    return
                if self.path not in (f"{BASE}/chat/completions", f"{BASE}/responses"):
                    return self._send(404, {"error": {"message": "Not found"}})
                if payload.get("model") not in outer.agents:
                    return self._send(404, {"error": {"message": f"Agent not found: {payload.get('model')}"}})
                with outer.lock:
                    n = outer.chats
                    outer.chats += 1
                result = outer.responder(payload, n)
                if isinstance(result, tuple) and result[0] == "sleep":
                    time.sleep(result[1])
                    result = verdict_json()
                if isinstance(result, tuple) and result[0] == "http":
                    return self._send(result[1], result[2], result[3] if len(result) > 3 else None)
                if isinstance(result, tuple) and result[0] == "raw":
                    return self._send(200, result[1])
                if self.path.endswith("/responses"):
                    return self._send(200, {"id": "resp_1", "object": "response", "status": "completed", "model": payload["model"],
                                            "output": [{"type": "reasoning", "summary": []},
                                                       {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": result}]}],
                                            "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}})
                self._send(200, {"id": "chatcmpl_1", "object": "chat.completion", "model": payload["model"],
                                 "choices": [{"index": 0, "message": {"role": "assistant", "content": result}, "finish_reason": "stop"}],
                                 "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.scheme = "http"
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(tls["cert"]), str(tls["key"]))
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
            self.scheme = "https"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.server.server_address[1]}"

    def start(self) -> "FakeLibreChat":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def sent_text(self) -> str:
        return "\n".join(json.dumps(r["json"], ensure_ascii=False) for r in self.requests if r["json"])
