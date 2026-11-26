"""Clients de moteurs d'IA pour la critique. Ollama pour commencer ; `Provider` est l'interface d'un futur moteur.

Confidentialité : des extraits du code audité transitent par ces appels. On refuse donc tout endpoint non local sauf
`allow_remote` explicite, et on ignore les proxys de l'environnement (un extrait ne doit pas partir vers un proxy
d'entreprise par accident).
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import urlparse

from .llmconf import LLMConfig


class LLMError(Exception):
    """`transient` : panne passagère du moteur (504, 503, 429, délai dépassé, connexion refusée…) qu'il est raisonnable de retenter ; sinon (clé refusée, adresse introuvable,
    certificat inconnu, réponse illisible…) réessayer ne servirait à rien."""

    def __init__(self, message: str = "", *, transient: bool = False):
        super().__init__(message)
        self.transient = transient


TRANSIENT_STATUSES = frozenset({408, 425, 429, 502, 503, 504, 520, 521, 522, 523, 524})   # pas le 500 : souvent déterministe, il bloquerait tout un passage


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
    label = "modèle"       # ce que `model` désigne : un modèle (Ollama), un agent (LibreChat)
    tokens = 0             # jetons consommés pendant cette session, si le moteur les rapporte (facturation)

    @abstractmethod
    def check(self) -> list[str]:
        """Lève LLMError (message actionnable) si le moteur ou le modèle est inutilisable ; sinon renvoie les modèles / agents disponibles."""

    def describe(self) -> list[str]:
        """Lignes d'information pour `critiq check` (jamais de secret)."""
        return []

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
            raise LLMError(f"Ollama a répondu {exc.code} : {detail}", transient=exc.code in TRANSIENT_STATUSES) from exc
        except (urllib.error.URLError, ConnectionError, socket.timeout, TimeoutError) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason):
                raise LLMError(f"délai de {timeout or self.timeout}s dépassé (modèle trop lent ? `timeout` dans llm.yaml)", transient=True) from exc
            raise LLMError(f"Ollama injoignable à {self.base_url} ({reason}) : `ollama serve` est-il lancé ?", transient=not isinstance(reason, socket.gaierror)) from exc
        except ValueError as exc:
            raise LLMError(f"réponse d'Ollama illisible : {exc}") from exc

    def check(self) -> list[str]:
        self._call("/api/version", timeout=10)
        names = [m.get("name", "") for m in self._call("/api/tags", timeout=10).get("models", [])]
        shown = ", ".join(names) or "aucun"
        if not self.model:
            raise LLMError(f"aucun modèle configuré (`model` dans llm.yaml) ; modèles installés : {shown}")
        if self.model not in names and f"{self.model}:latest" not in names:
            raise LLMError(f"modèle « {self.model} » non installé (ollama pull {self.model}) ; modèles installés : {shown}")
        return names

    def describe(self) -> list[str]:
        return [f"moteur : ollama — {self.base_url}", f"modèle : {self.model or '(non configuré)'}"]

    def chat(self, messages: list[dict[str, str]], schema: dict) -> str:
        data = self._call("/api/chat", {"model": self.model, "messages": messages, "stream": False, "format": schema,
                                        "options": {"temperature": self.temperature, "num_ctx": self.num_ctx, "seed": 7}})
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError("réponse d'Ollama sans message") from exc


# ------------------------------------------------------------------------------------------------ LibreChat
_AGENTS_SUFFIXES = ("/chat/completions", "/responses", "/models")


def scrub(text: str, token: str) -> str:
    """Retire le jeton (et tout motif « Bearer … ») d'un texte destiné à un message d'erreur ou à un journal."""
    if token:
        text = text.replace(token, "***")
    return re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1***", text)


def agents_url(base_url: str) -> str:
    """`https://chat.exemple.fr` -> `https://chat.exemple.fr/api/agents/v1` (on accepte aussi l'URL déjà complète ou un chemin d'endpoint)."""
    url = base_url.rstrip("/")
    for suffix in _AGENTS_SUFFIXES:
        if url.endswith("/api/agents/v1" + suffix):
            url = url[: -len(suffix)]
    return url if url.endswith("/api/agents/v1") else url + "/api/agents/v1"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None  # une redirection est une erreur : l'en-tête Authorization ne doit JAMAIS suivre vers une autre adresse


def _schema_rules(system: str, schema: dict) -> str:
    return (f"{system}\n\nOutput format: reply with ONE JSON object and nothing else (no code fence, no commentary) "
            f"conforming to this JSON Schema:\n{json.dumps(schema, ensure_ascii=False)}")


def public_url(url: str) -> str:
    """URL sans identifiants ni requête (qui peuvent porter un secret) : la seule forme affichée ou journalisée."""
    u = urlparse(url)
    if not u.hostname:
        return url.split("?")[0].split("@")[-1]
    host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    return f"{u.scheme}://{host}{':' + str(u.port) if u.port else ''}{u.path}".rstrip("/")


def _dig(data, path: str):
    """Valeur à un chemin pointé (`choices.0.message.content`) ; None si absente."""
    for part in path.split("."):
        if isinstance(data, list) and part.isdigit() and int(part) < len(data):
            data = data[int(part)]
        elif isinstance(data, dict) and part in data:
            data = data[part]
        else:
            return None
    return data


def _count_tokens(data) -> int:
    usage = data.get("usage") if isinstance(data, dict) else None
    if not isinstance(usage, dict):
        return 0
    total = usage.get("total_tokens") or (usage.get("input_tokens", 0) + usage.get("output_tokens", 0)) or (usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0))
    return int(total) if isinstance(total, (int, float)) and not isinstance(total, bool) else 0


def fold_messages(messages: list[dict[str, str]], schema: dict) -> list[dict[str, str]]:
    """Un agent LibreChat a ses propres instructions : on n'en dépend pas pour les nôtres. Le message système et le schéma JSON sont donc
    repliés dans le premier message utilisateur (le format de sortie est demandé explicitement : aucun `response_format` n'est envoyé)."""
    system = next((m["content"] for m in messages if m["role"] == "system"), "")
    rules = _schema_rules(system, schema)
    out, folded = [], False
    for m in messages:
        if m["role"] == "system":
            continue
        if m["role"] == "user" and not folded:
            out.append({"role": "user", "content": f"<instructions>\n{rules}\n</instructions>\n\n{m['content']}"})
            folded = True
        else:
            out.append({"role": m["role"], "content": m["content"]})
    return out


def _parts_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") in (None, "text", "output_text"))
    return ""


def extract_text(data, endpoint: str, agent: str = "") -> str:
    """Texte de la réponse d'un agent. Toute tentative d'appel d'outil est REFUSÉE : un agent muni d'outils (recherche web, exécution de code)
    pourrait être manipulé par du code audité ; utilisez un agent SANS outil."""
    refuse = LLMError(f"l'agent « {agent} » a tenté d'utiliser un outil : refusé (du code audité peut contenir des instructions pour le manipuler). "
                      "Utilisez un agent dédié, sans aucun outil.")
    if not isinstance(data, dict):
        raise LLMError("réponse de l'agent inattendue (objet JSON attendu)")
    if isinstance(data.get("error"), (dict, str)) and not data.get("choices") and not data.get("output"):
        err = data["error"]
        raise LLMError("l'agent a renvoyé une erreur : " + str(err.get("message") if isinstance(err, dict) else err)[:300])
    if endpoint == "responses":
        if data.get("status") in ("failed", "cancelled", "incomplete"):
            raise LLMError(f"réponse de l'agent {data['status']}" + (f" : {data['error']}" if data.get("error") else ""))
        text = ""
        for item in data.get("output") or []:
            kind = item.get("type") if isinstance(item, dict) else None
            if kind == "message":
                text += _parts_text(item.get("content"))
            elif kind and kind != "reasoning":
                raise refuse
        text = text or (data.get("output_text") if isinstance(data.get("output_text"), str) else "")
    else:
        choices = data.get("choices")
        if not (isinstance(choices, list) and choices and isinstance(choices[0], dict)):
            raise LLMError("réponse de l'agent sans choix (format Chat Completions attendu)")
        message = choices[0].get("message") or {}
        if message.get("tool_calls") or message.get("function_call"):
            raise refuse
        text = _parts_text(message.get("content"))
    if not text.strip():
        raise LLMError("réponse de l'agent vide")
    return text


class _HttpBase(Provider):
    """Socle HTTP commun (LibreChat, point d'accès personnalisé) : aucune redirection suivie (l'en-tête de clé ne part jamais ailleurs),
    secrets expurgés des erreurs, reprises sur 429/502/503/504. La vérification TLS est active sauf demande explicite (`verify_tls: false`, custom)."""

    base_url = ""

    def _setup_http(self, *, timeout: int, retries: int = 2, ca_file: str | None = None, verify_tls: bool = True, client_cert: str | None = None,
                    client_key: str | None = None, proxy: str | None = None) -> None:
        self.timeout, self.retries = timeout, retries
        try:
            if verify_tls:
                ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
            else:
                from .insecure_tls import unverified_context  # import local : ce n'est pas le cas normal
                ctx = unverified_context()
            if client_cert:
                ctx.load_cert_chain(client_cert, client_key)
        except (OSError, ssl.SSLError) as exc:
            raise LLMError(f"certificat illisible (ca_file / client_cert / client_key de llm.yaml) : {getattr(exc, 'strerror', None) or exc}") from None
        proxies = urllib.request.ProxyHandler() if proxy == "env" else urllib.request.ProxyHandler({"http": proxy, "https": proxy}) if proxy else urllib.request.ProxyHandler({})
        self._opener = urllib.request.build_opener(proxies, _NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    def _secrets(self) -> list[str]:
        return []

    def _scrub(self, text: str) -> str:
        for secret in self._secrets():
            text = scrub(text, secret)
        return scrub(text, "")

    def _request(self, method: str, url: str, payload: dict | None, headers: dict[str, str], timeout: int | None = None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        hdrs = {"Accept": "application/json", **headers}
        if body is not None:
            hdrs.setdefault("Content-Type", "application/json")
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
                with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                    raw = resp.read()
                try:
                    return json.loads(raw or b"{}")
                except ValueError as exc:
                    raise LLMError(f"réponse illisible (JSON attendu) : {exc}") from None
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 502, 503, 504) and attempt < self.retries:
                    try:
                        wait = float(exc.headers.get("Retry-After", ""))
                    except ValueError:
                        wait = float(2 ** attempt)
                    time.sleep(min(max(wait, 0.0), 30.0))
                    continue
                raise self._flag(self._http_error(exc, url), exc.code in TRANSIENT_STATUSES) from None
            except (urllib.error.URLError, ConnectionError, socket.timeout, TimeoutError, ssl.SSLError) as exc:
                raise self._flag(self._net_error(exc, timeout or self.timeout), self._net_transient(exc)) from None
        raise LLMError("service indisponible")  # pragma: no cover

    @staticmethod
    def _flag(err: LLMError, transient: bool) -> LLMError:
        err.transient = transient
        return err

    @staticmethod
    def _net_transient(exc: Exception) -> bool:
        """Délai dépassé, connexion refusée ou coupée : passager. Nom de domaine inconnu ou certificat refusé : une erreur de configuration, jamais retentée."""
        reason = getattr(exc, "reason", exc)
        return not (isinstance(reason, (socket.gaierror, ssl.SSLError)) and "timed out" not in str(reason))

    def _more(self, exc: urllib.error.HTTPError) -> str:
        """Détail d'erreur renvoyé par le serveur (JSON `error.message` ou texte), tronqué et expurgé : « — … » ou vide."""
        try:
            body = exc.read(2000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
        detail = body.strip()
        try:
            doc = json.loads(body)
            err = doc.get("error") if isinstance(doc, dict) else None
            detail = str((err.get("message") if isinstance(err, dict) else err) or (doc.get("message") if isinstance(doc, dict) else "") or "")
        except ValueError:
            if detail.lstrip().startswith("<"):  # page HTML d'une passerelle (504…) : on garde le texte, pas les balises
                detail = re.sub(r"<[^>]*>", " ", detail)
        detail = self._scrub(" ".join(detail.split())[:300])
        return f" — {detail}" if detail else ""

    def _http_error(self, exc: urllib.error.HTTPError, url: str) -> LLMError:
        more, code = self._more(exc), exc.code
        if code in (301, 302, 303, 307, 308):
            target = urlparse(exc.headers.get("Location", "") or "").netloc or "?"
            return LLMError(f"redirection ({code}) vers « {self._scrub(target)} » refusée : la clé d'API n'est jamais envoyée à une autre adresse (corrigez `url` dans llm.yaml)")
        hints = {401: "clé d'API refusée (401)", 403: "accès refusé (403)", 404: "adresse introuvable (404) : vérifiez `url` dans llm.yaml", 429: "limite de débit atteinte (429) après plusieurs essais"}
        return LLMError(hints.get(code, f"le service a répondu {code}") + more)

    def _net_error(self, exc: Exception, timeout: int) -> LLMError:
        reason = getattr(exc, "reason", exc)
        text = self._scrub(str(reason))
        if isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in text:
            return LLMError("certificat TLS non reconnu : si le serveur utilise une autorité privée, renseignez `ca_file` dans llm.yaml (avec provider: custom, `verify_tls: false` "
                            "désactive la vérification, à vos risques)" if getattr(self, "name", "") == "custom" else
                            "certificat TLS non reconnu : si LibreChat utilise une autorité privée, renseignez `ca_file` dans llm.yaml (la vérification TLS ne peut pas être désactivée)")
        if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in text:
            return LLMError(f"délai de {timeout}s dépassé (réponse trop lente ? `timeout` dans llm.yaml)")
        return LLMError(f"injoignable à {self.base_url} ({text})")


class LibreChatProvider(_HttpBase):
    """API Agents de LibreChat (bêta) : `model` = identifiant d'agent, `Authorization: Bearer <clé d'API>`.
    Le jeton n'est jamais affiché ni journalisé ; TLS toujours vérifié ; aucune redirection suivie."""

    name = "librechat"
    label = "agent"

    def __init__(self, base_url: str, agent: str | None, token: str, *, timeout: int = 300, endpoint: str = "chat_completions", ca_file: str | None = None,
                 origin: str = "llm.yaml", warnings: list[str] | None = None, retries: int = 2,
                 proxy: str | None = None, client_cert: str | None = None, client_key: str | None = None):
        self.base_url, self.model, self.timeout, self.endpoint = agents_url(base_url), agent or "", timeout, endpoint
        self._token, self.origin, self.warnings, self.tokens = token, origin, warnings or [], 0
        self._setup_http(timeout=timeout, retries=retries, ca_file=ca_file, client_cert=client_cert, client_key=client_key, proxy=proxy)

    def __repr__(self) -> str:
        return f"LibreChatProvider({self.base_url!r}, agent={self.model!r}, token=***)"

    def describe(self) -> list[str]:
        return [f"moteur : librechat — {self.base_url}", f"agent : {self.model or '(non configuré)'}", f"interface : {self.endpoint}",
                f"jeton : lu dans {self.origin} ({len(self._token)} caractères, jamais affiché)", *[f"⚠ {w}" for w in self.warnings]]

    def _call(self, method: str, path: str, payload: dict | None = None, timeout: int | None = None):
        return self._request(method, self.base_url + path, payload, {"Authorization": f"Bearer {self._token}"}, timeout)

    def _secrets(self) -> list[str]:
        return [self._token]

    def _http_error(self, exc: urllib.error.HTTPError, url: str) -> LLMError:
        path, more, code = url[len(self.base_url):], self._more(exc), exc.code
        if code in (301, 302, 303, 307, 308):
            target = urlparse(exc.headers.get("Location", "") or "").netloc or "?"
            return LLMError(f"redirection ({code}) vers « {self._scrub(target)} » refusée : le jeton n'est jamais envoyé à une autre adresse (corrigez `url` dans llm.yaml)")
        if code == 401:
            return LLMError("jeton refusé (401) : clé d'API expirée, supprimée ou mal copiée" + more)
        if code == 403:
            return LLMError("accès refusé (403) : rôle sans la permission « Remote Agents », ou agent non partagé (bouton Remote Access de l'agent)" + more)
        if code == 404:
            if path == "/models":
                return LLMError(f"API Agents introuvable à {self.base_url} (404) : version de LibreChat sans API Agents, ou `url` incorrecte dans llm.yaml" + more)
            return LLMError(f"agent « {self.model} » introuvable ou non accessible avec ce jeton (404)" + more)
        if code == 429:
            return LLMError("limite de débit de LibreChat atteinte (429) après plusieurs essais" + more)
        return LLMError(f"LibreChat a répondu {code}" + more)

    def check(self) -> list[str]:
        data = self._call("GET", "/models", timeout=15)
        items = data.get("data") if isinstance(data, dict) else data
        ids = [m["id"] for m in items or [] if isinstance(m, dict) and isinstance(m.get("id"), str)]
        shown = ", ".join(ids[:10]) + (f" … (+{len(ids) - 10})" if len(ids) > 10 else "") or "aucun"
        if not self.model:
            raise LLMError(f"aucun agent configuré (`model` de llm.yaml = identifiant d'agent) ; agents accessibles avec ce jeton : {shown}")
        if self.model not in ids:
            raise LLMError(f"agent « {self.model} » introuvable ou non accessible avec ce jeton ; agents accessibles : {shown}")
        return ids

    def chat(self, messages: list[dict[str, str]], schema: dict) -> str:
        folded = fold_messages(messages, schema)
        if self.endpoint == "responses":
            data = self._call("POST", "/responses", {"model": self.model, "input": folded, "stream": False})
        else:
            data = self._call("POST", "/chat/completions", {"model": self.model, "messages": folded, "stream": False})
        self.tokens += _count_tokens(data)
        return extract_text(data, self.endpoint, self.model)


PROBE_MESSAGE = "Say hello in one short sentence."
DEFAULT_RESPONSE_PATH = "choices.0.message.content"


class CustomProvider(_HttpBase):
    """Point d'accès HTTP personnalisé, compatible Chat Completions : URL, en-tête de clé, corps, chemin de la réponse, TLS… tout se règle dans llm.yaml.
    Garde-fous conservés : clé jamais affichée ni journalisée (expurgée des erreurs), aucune redirection suivie, aucune réponse d'outil acceptée."""

    name = "custom"

    def __init__(self, llm: LLMConfig, model: str | None, warnings: list[str] | None = None):
        self.cfg, self.model, self._key, self.warnings, self.tokens = llm, model or "", llm.api_key or "", warnings or [], 0
        self.origin = Path(llm.source).name if llm.source else "llm.yaml"
        self.url, self.base_url = llm.url, public_url(llm.url)
        self._setup_http(timeout=llm.timeout, retries=llm.retries, ca_file=llm.ca_file, verify_tls=llm.verify_tls, client_cert=llm.client_cert,
                         client_key=llm.client_key, proxy=llm.proxy)

    def __repr__(self) -> str:
        return f"CustomProvider({self.base_url!r}, model={self.model!r}, key=***)"

    def _secrets(self) -> list[str]:
        return [self._key, *[v for v in self.cfg.headers.values() if len(v) >= 8]]

    def _headers(self) -> dict[str, str]:
        c, h = self.cfg, {"Content-Type": "application/json"}
        if self._key:
            header = c.api_key_header or "Authorization"
            prefix = c.api_key_prefix if c.api_key_prefix is not None else ("Bearer " if header.lower() == "authorization" else "")
            h[header] = prefix + self._key
        h.update(c.headers)
        return h

    def describe(self) -> list[str]:
        c = self.cfg
        tls = "⚠ vérification DÉSACTIVÉE (verify_tls: false)" if not c.verify_tls else "vérification activée" + (f" (autorité : {c.ca_file})" if c.ca_file else "")
        key = (f"en-tête {c.api_key_header or 'Authorization'} ({len(self._key)} caractères, lue dans {self.origin}, jamais affichée)" if self._key else "aucune (requête sans authentification)")
        return [f"moteur : custom — {self.base_url}", f"modèle : {self.model or '(non configuré)'}", f"clé d'API : {key}", f"TLS : {tls}",
                f"max_tokens : {c.max_tokens if c.max_tokens is not None else 'non envoyé'} ; format JSON : {c.json_mode}{' ; système replié' if c.fold_system else ''} ; réponse lue à : {c.response_path}",
                *([f"en-têtes supplémentaires : {', '.join(c.headers)}"] if c.headers else []), *([f"corps supplémentaire : {', '.join(c.body)}"] if c.body else []),
                *[f"⚠ {w}" for w in self.warnings]]

    def _payload(self, messages: list[dict[str, str]], schema: dict | None) -> dict:
        c = self.cfg
        if schema is None:
            msgs = [dict(m) for m in messages]
        elif c.fold_system:
            msgs = fold_messages(messages, schema)
        else:  # la consigne de format rejoint le message système
            system = next((m["content"] for m in messages if m["role"] == "system"), "")
            msgs = [{"role": "system", "content": _schema_rules(system, schema)}, *[dict(m) for m in messages if m["role"] != "system"]]
        payload: dict = {"model": self.model, "messages": msgs}
        if c.max_tokens is not None:
            payload["max_tokens"] = c.max_tokens
        if schema is not None and c.json_mode == "json_object":
            payload["response_format"] = {"type": "json_object"}
        elif schema is not None and c.json_mode == "json_schema":
            payload["response_format"] = {"type": "json_schema", "json_schema": {"name": "critique", "schema": schema, "strict": False}}
        return {**payload, **c.body}  # le corps configuré l'emporte (model et messages sont réservés)

    def _text(self, data) -> str:
        if _dig(data, "choices.0.finish_reason") == "length":  # un JSON coupé ne se rattrape pas ; un modèle à raisonnement peut épuiser le budget avant de répondre
            spent = _dig(data, "usage.reasoning_tokens")
            raise LLMError("réponse tronquée par la limite de longueur (finish_reason: length) : augmentez `max_tokens` dans llm.yaml"
                           + (f" ({spent} jeton(s) consommés par le raisonnement avant la réponse)" if isinstance(spent, int) and not isinstance(spent, bool) and spent > 0 else ""))
        path = self.cfg.response_path
        if path == DEFAULT_RESPONSE_PATH:
            return extract_text(data, "chat_completions", self.model)  # forme OpenAI : refuse aussi tout appel d'outil
        value = _dig(data, path)
        value = _parts_text(value) if isinstance(value, list) else value
        if not isinstance(value, str) or not value.strip():
            keys = ", ".join(list(data)[:10]) if isinstance(data, dict) else type(data).__name__
            raise LLMError(f"rien à lire au chemin « {path} » dans la réponse (`response_path` dans llm.yaml) ; clés présentes : {keys}")
        return value

    def chat(self, messages: list[dict[str, str]], schema: dict | None) -> str:
        data = self._request("POST", self.url, self._payload(messages, schema), self._headers())
        self.tokens += _count_tokens(data)
        return self._text(data)

    def probe(self) -> str:
        """Essai de bout en bout, SANS aucun code audité : un message anodin (comme un `curl` de contrôle)."""
        return self.chat([{"role": "user", "content": PROBE_MESSAGE}], None)

    def check(self) -> list[str]:
        if not self.model:
            raise LLMError("aucun modèle configuré (`model` dans llm.yaml)")
        if not self.cfg.check_url:
            return []
        data = self._request("GET", self.cfg.check_url, None, self._headers())
        items = data.get("data") if isinstance(data, dict) else data
        ids = [m["id"] for m in items or [] if isinstance(m, dict) and isinstance(m.get("id"), str)]
        if ids and self.model not in ids:
            raise LLMError(f"modèle « {self.model} » absent de {public_url(self.cfg.check_url)} ; disponibles : {', '.join(ids[:10])}")
        return ids


def _loose_perms_warning(llm: LLMConfig) -> list[str]:
    """llm.yaml porte la clé d'API : avertir s'il est lisible par d'autres utilisateurs."""
    if not (llm.api_key and llm.source):
        return []
    try:
        loose = Path(llm.source).stat().st_mode & 0o044
    except OSError:
        return []
    return [f"{llm.source} contient une clé d'API et est lisible par d'autres utilisateurs : chmod 600"] if loose else []


def make_provider(llm: LLMConfig, model: str | None = None) -> Provider:
    local = is_local_url(llm.url)
    if not local and not llm.allow_remote:
        raise LLMError(f"{public_url(llm.url)} n'est pas un endpoint local : des extraits du code audité y seraient envoyés. "
                       "Si c'est voulu, ajoutez `allow_remote: true` dans llm.yaml.")
    if llm.provider == "ollama":
        return OllamaProvider(llm.url, model or llm.model, timeout=llm.timeout, num_ctx=llm.num_ctx, temperature=llm.temperature)
    if urlparse(llm.url).scheme == "http" and not local and not llm.insecure_http:
        raise LLMError("http:// vers un hôte distant : la clé d'API et le code audité transiteraient NON chiffrés. Utilisez https:// "
                       "(ou insecure_http: true dans llm.yaml, à vos risques).")
    warnings = _loose_perms_warning(llm)
    if llm.provider == "custom":
        if not llm.verify_tls:
            warnings.append("vérification TLS désactivée (verify_tls: false) : l'identité du serveur n'est pas contrôlée, la clé d'API et le code audité peuvent être interceptés")
        return CustomProvider(llm, model or llm.model, warnings)
    if not llm.api_key:
        raise LLMError("clé d'API LibreChat absente : renseignez `api_key` dans llm.yaml. Créez-la dans LibreChat : Paramètres > Données et confidentialité > Clés d'API d'agents.")
    return LibreChatProvider(llm.url, model or llm.model, llm.api_key, timeout=llm.timeout, endpoint=llm.endpoint, ca_file=llm.ca_file, origin=Path(llm.source).name if llm.source else "llm.yaml",
                             warnings=warnings, retries=llm.retries, proxy=llm.proxy, client_cert=llm.client_cert, client_key=llm.client_key)
