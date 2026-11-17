"""Faux serveur Ollama (API réelle : /api/version, /api/tags, /api/chat) pour les tests, avec pannes scriptables."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def verdict(v: str = "uncertain", confidence: float = 0.9, reasoning: str = "Raison de test.", need=None, injection: bool = False) -> dict:
    out = {"verdict": v, "confidence": confidence, "reasoning": reasoning, "injection_suspected": injection}
    if need is not None:
        out["need"] = need
    return out


def user_text(payload: dict) -> str:
    return next((m["content"] for m in reversed(payload["messages"]) if m["role"] == "user"), "")


def all_text(payload: dict) -> str:
    return "\n".join(m["content"] for m in payload["messages"])


class FakeOllama:
    """`responder(payload, n)` renvoie : un dict (verdict), un str (contenu brut),
    ("http", statut, corps) ou ("sleep", secondes) pour simuler une panne ou une lenteur."""

    def __init__(self, models=("qwen2.5-coder:7b",), responder=None):
        self.models = list(models)
        self.responder = responder or (lambda payload, n: verdict("uncertain", 0.5))
        self.chats: list[dict] = []
        self.gets: list[str] = []
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _send(self, status: int, obj) -> None:
                body = json.dumps(obj).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):  # le client a abandonné (délai) : pas de bruit dans les tests
                    pass

            def do_GET(self):
                outer.gets.append(self.path)
                if self.path == "/api/version":
                    self._send(200, {"version": "0.5.7"})
                elif self.path == "/api/tags":
                    self._send(200, {"models": [{"name": m} for m in outer.models]})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                with outer.lock:
                    n = len(outer.chats)
                    outer.chats.append(payload)
                result = outer.responder(payload, n)
                if isinstance(result, tuple) and result[0] == "sleep":
                    time.sleep(result[1])
                    result = verdict()
                if isinstance(result, tuple) and result[0] == "http":
                    return self._send(result[1], result[2])
                content = result if isinstance(result, str) else json.dumps(result)
                self._send(200, {"model": payload["model"], "message": {"role": "assistant", "content": content}, "done": True})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def start(self) -> "FakeOllama":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def sent_text(self) -> str:
        """Tout ce qui a été envoyé au « modèle » (messages de toutes les requêtes)."""
        return "\n".join(all_text(p) for p in self.chats)
