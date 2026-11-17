"""Clients de moteurs d'IA pour la critique. Ollama pour commencer ; `Provider` est l'interface d'un futur moteur.

Confidentialité : des extraits du code audité transitent par ces appels. On refuse donc tout endpoint non local sauf
`allow_remote` explicite, et on ignore les proxys de l'environnement (un extrait ne doit pas partir vers un proxy
d'entreprise par accident).
"""
from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from urllib.parse import urlparse

from .config import CritiqConfig


class LLMError(Exception):
    pass


def is_local_url(url: str) -> bool:
    host = urlparse(url).hostname
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return all(ipaddress.ip_address(a[4][0]).is_loopback for a in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM))
    except (OSError, ValueError):
        return False


class Provider(ABC):
    name: str
    model: str

    @abstractmethod
    def check(self) -> None:
        """Lève LLMError (message actionnable) si le moteur ou le modèle est inutilisable."""

    @abstractmethod
    def chat(self, messages: list[dict[str, str]], schema: dict) -> str:
        """Renvoie le texte de la réponse (JSON conforme à `schema` demandé au moteur)."""


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self, base_url: str, model: str | None, *, timeout: int = 300, num_ctx: int = 8192, temperature: float = 0.0):
        self.base_url, self.model, self.timeout, self.num_ctx, self.temperature = base_url.rstrip("/"), model or "", timeout, num_ctx, temperature
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # jamais de proxy d'environnement

    def _call(self, path: str, payload: dict | None = None, timeout: int | None = None) -> dict:
        req = urllib.request.Request(self.base_url + path, data=None if payload is None else json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="GET" if payload is None else "POST")
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            try:
                detail = json.loads(detail).get("error", detail)
            except ValueError:
                pass
            raise LLMError(f"Ollama a répondu {exc.code} : {detail}") from exc
        except (urllib.error.URLError, ConnectionError, socket.timeout, TimeoutError) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason):
                raise LLMError(f"délai de {timeout or self.timeout}s dépassé (modèle trop lent ? critiq.timeout)") from exc
            raise LLMError(f"Ollama injoignable à {self.base_url} ({reason}) : `ollama serve` est-il lancé ?") from exc
        except ValueError as exc:
            raise LLMError(f"réponse d'Ollama illisible : {exc}") from exc

    def check(self) -> None:
        self._call("/api/version", timeout=10)
        names = [m.get("name", "") for m in self._call("/api/tags", timeout=10).get("models", [])]
        shown = ", ".join(names) or "aucun"
        if not self.model:
            raise LLMError(f"aucun modèle configuré (critiq.model) ; modèles installés : {shown}")
        if self.model not in names and f"{self.model}:latest" not in names:
            raise LLMError(f"modèle « {self.model} » non installé (ollama pull {self.model}) ; modèles installés : {shown}")

    def chat(self, messages: list[dict[str, str]], schema: dict) -> str:
        data = self._call("/api/chat", {"model": self.model, "messages": messages, "stream": False, "format": schema,
                                        "options": {"temperature": self.temperature, "num_ctx": self.num_ctx, "seed": 7}})
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError("réponse d'Ollama sans message") from exc


def make_provider(cfg: CritiqConfig, model: str | None = None) -> Provider:
    if not is_local_url(cfg.base_url) and not cfg.allow_remote:
        raise LLMError(f"{cfg.base_url} n'est pas un endpoint local : des extraits du code audité y seraient envoyés. "
                       "Si c'est voulu, ajoutez `allow_remote: true` dans la section critiq de aule.yaml.")
    return OllamaProvider(cfg.base_url, model or cfg.model, timeout=cfg.timeout, num_ctx=cfg.num_ctx, temperature=cfg.temperature)
