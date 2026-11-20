"""Faux point d'accès compatible Chat Completions, à en-tête de clé configurable (x-ai-api-key…), pannes scriptables, TLS réel."""
from __future__ import annotations

import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

KEY = "k-7f3a91c2d4e85b60a1f2c3d4e5f60718"


def verdict_json(v="uncertain", confidence=0.7, reasoning="Raison de test.") -> str:
    return json.dumps({"verdict": v, "confidence": confidence, "reasoning": reasoning, "injection_suspected": False})


class FakeOpenAI:
    """`responder(payload, n)` : str (texte de la réponse), ("http", statut, corps[, en-têtes]), ("sleep", s) ou ("raw", objet JSON complet)."""

    def __init__(self, key: str = KEY, auth_header: str = "x-ai-api-key", prefix: str = "", path: str = "/v1/chat/completions", models: tuple[str, ...] = ("triton", "autre"),
                 responder=None, shape: str = "openai", tls: dict[str, Path] | None = None, echo: bool = False):
        self.key, self.auth_header, self.prefix, self.path, self.models, self.shape, self.echo = key, auth_header.lower(), prefix, path, models, shape, echo
        self.responder = responder or (lambda payload, n: verdict_json())
        self.requests: list[dict] = []
        self.chats, self.lock = 0, threading.Lock()
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
                got = self.headers.get(outer.auth_header, "")
                if got == outer.prefix + outer.key:
                    return True
                self._send(401, {"error": {"message": "invalid api key" + (f" (received: {got})" if outer.echo else "")}})
                return False

            def _record(self, payload):
                with outer.lock:
                    outer.requests.append({"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "json": payload})

            def do_GET(self):
                self._record(None)
                if not self._auth():
                    return
                if self.path == "/v1/models":
                    return self._send(200, {"object": "list", "data": [{"id": m, "object": "model"} for m in outer.models]})
                self._send(404, {"error": {"message": "not found"}})

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                self._record(payload)
                if not self._auth():
                    return
                if self.path != outer.path:
                    return self._send(404, {"error": {"message": "not found"}})
                with outer.lock:
                    n, outer.chats = outer.chats, outer.chats + 1
                result = outer.responder(payload, n)
                if isinstance(result, tuple) and result[0] == "sleep":
                    time.sleep(result[1])
                    result = verdict_json()
                if isinstance(result, tuple) and result[0] == "http":
                    return self._send(result[1], result[2], result[3] if len(result) > 3 else None)
                if isinstance(result, tuple) and result[0] == "raw":
                    return self._send(200, result[1])
                if outer.shape == "custom":
                    return self._send(200, {"output": {"text": result}, "usage": {"input_tokens": 10, "output_tokens": 5}})
                self._send(200, {"id": "c1", "object": "chat.completion", "model": payload.get("model"), "choices": [{"index": 0, "message": {"role": "assistant", "content": result}, "finish_reason": "stop"}],
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
        return f"{self.scheme}://127.0.0.1:{self.server.server_address[1]}{self.path}"

    @property
    def models_url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.server.server_address[1]}/v1/models"

    def start(self) -> "FakeOpenAI":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def sent_text(self) -> str:
        return "\n".join(json.dumps(r["json"], ensure_ascii=False) for r in self.requests if r["json"])
