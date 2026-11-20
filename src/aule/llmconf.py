"""Réglages du moteur d'IA : un fichier à part, `llm.yaml`, SECRETS COMPRIS (chmod 600, hors du dépôt). `aule.yaml` n'en contient plus aucun.

Une seule clé par idée (pas de doublons) : `url` (adresse du moteur), `api_key` (la clé, dans ce fichier : jamais dans l'environnement), `proxy` (`env` ou une URL).
Chaque clé n'existe que pour les moteurs auxquels elle s'applique ; une clé sans effet pour le moteur choisi est REFUSÉE, jamais ignorée en silence."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .config import ConfigError, _expect

DEFAULT_LLM_NAME = "llm.yaml"
PROVIDERS = ("ollama", "librechat", "custom")
_COMMON = {"provider", "url", "model", "allow_remote", "timeout", "insecure_http"}
_REMOTE = {"api_key", "retries", "proxy", "ca_file", "client_cert", "client_key"}   # moteurs distants : librechat et custom
_ONLY = {
    "ollama": {"num_ctx", "temperature"},
    "librechat": {"endpoint"},
    "custom": {"api_key_header", "api_key_prefix", "headers", "body", "max_tokens", "verify_tls", "response_path", "json_mode", "fold_system", "check_url"},
}
_REMOVED = {  # anciennes clés : le message dit quoi faire
    "base_url": "utilisez `url`",
    "api_key_env": "aucun secret en variable d'environnement : écrivez la clé dans `api_key`",
    "api_key_file": "aucun secret dans un fichier à part : écrivez la clé dans `api_key`",
    "use_env_proxy": "utilisez `proxy: env`",
}
LEGACY_KEYS = frozenset(_COMMON | _REMOTE | set().union(*_ONLY.values()) | set(_REMOVED))   # réglages qui vivaient dans la section `critiq` de aule.yaml
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection"}


@dataclass
class LLMConfig:
    provider: str = "ollama"
    url: str = "http://127.0.0.1:11434"      # ollama : l'hôte ; librechat : le site (…/api/agents/v1 est ajouté) ; custom : l'URL COMPLÈTE de l'endpoint
    model: str | None = None                 # modèle (ollama, custom) ou identifiant d'agent (librechat)
    api_key: str | None = field(default=None, repr=False)   # la clé : dans ce fichier, jamais affichée ni journalisée
    allow_remote: bool = False               # consentement explicite : du code audité part vers un serveur qui n'est pas cette machine
    timeout: int = 300
    insecure_http: bool = False              # accepter http:// vers un hôte distant (clé et code NON chiffrés) : à vos risques
    retries: int = 2                         # nouvelles tentatives sur 429/502/503/504 (librechat, custom)
    proxy: str | None = None                 # `env` : suivre HTTP(S)_PROXY ; sinon une URL http(s)://hôte:port
    ca_file: str | None = None               # autorité de certification privée
    client_cert: str | None = None           # TLS mutuel
    client_key: str | None = None
    num_ctx: int = 8192                      # ollama : fenêtre de contexte
    temperature: float = 0.0                 # ollama
    endpoint: str = "chat_completions"       # librechat : chat_completions | responses
    api_key_header: str | None = None        # custom : en-tête de la clé (défaut Authorization)
    api_key_prefix: str | None = None        # custom : texte devant la clé (défaut « Bearer » pour Authorization)
    headers: dict = field(default_factory=dict, repr=False)   # custom : en-têtes supplémentaires (valeurs expurgées des erreurs)
    body: dict = field(default_factory=dict)  # custom : champs ajoutés au JSON envoyé (l'emportent sur le reste)
    max_tokens: int | None = 2048            # custom : null = non envoyé (certains serveurs plafonnent à 16)
    verify_tls: bool = True                  # custom seulement : false = comme curl --insecure (avertissement à chaque usage)
    response_path: str = "choices.0.message.content"   # custom : où lire le texte dans la réponse
    json_mode: str = "prompt"                # custom : prompt | json_object | json_schema
    fold_system: bool = False                # custom : replier le message système dans le premier message utilisateur
    check_url: str | None = None             # custom : GET de vérification pour `aule critiq check`
    source: str | None = field(default=None, repr=False)   # (interne) le fichier lu, pour avertir s'il est lisible par d'autres


def _bool(q: dict, key: str, default: bool) -> bool:
    value = q.get(key, default)
    if not isinstance(value, bool):  # strict : « false » (texte) serait lu comme vrai
        raise ConfigError(f"{key} : true ou false (sans guillemets)")
    return value


def _int(q: dict, key: str, default: int | None, lo: int, hi: int | None = None, nullable: bool = False) -> int | None:
    value = q.get(key, default)
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < lo or (hi is not None and value > hi):
        raise ConfigError(f"{key} : entier de {lo}" + (f" à {hi}" if hi is not None else " ou plus") + (", ou null" if nullable else "") + " attendu")
    return value


def _http_url(value: Any, where: str) -> str:
    """URL http(s) absolue, sans identifiants (ils finiraient dans les journaux) ; la requête peut porter un secret : elle n'est jamais affichée."""
    text = str(value).strip()
    u = urlparse(text)
    if u.scheme not in ("http", "https") or not u.hostname or re.search(r"[\s\x00-\x1f]", text):
        raise ConfigError(f"{where} : URL http(s):// complète attendue (ex. https://llm.exemple.fr/v1/chat/completions)")
    if u.username or u.password:
        raise ConfigError(f"{where} : pas d'identifiants dans l'URL (utilisez api_key ou headers)")
    return text


def _custom(q: dict) -> dict[str, Any]:
    """Réglages propres à `custom` (validés : rien de ce qui est secret n'est recopié dans un message d'erreur)."""
    out: dict[str, Any] = {}
    header = q.get("api_key_header")
    if header is not None and not (isinstance(header, str) and _HEADER_NAME.fullmatch(header) and header.lower() not in _FORBIDDEN_HEADERS):
        raise ConfigError("api_key_header : nom d'en-tête HTTP valide attendu (ex. Authorization, x-ai-api-key)")
    prefix = q.get("api_key_prefix")
    if prefix is not None and not (isinstance(prefix, str) and re.fullmatch(r"[\x20-\x7e]*", prefix)):
        raise ConfigError("api_key_prefix : texte ASCII imprimable attendu (ex. \"Bearer \" ; vide pour aucun)")
    out["api_key_header"], out["api_key_prefix"] = header, prefix
    headers = _expect(q.get("headers") or {}, dict, "headers")
    for name, value in headers.items():
        if not (isinstance(name, str) and _HEADER_NAME.fullmatch(name)) or name.lower() in _FORBIDDEN_HEADERS:
            raise ConfigError(f"headers : nom d'en-tête invalide ou interdit ({str(name)[:30]!r})")
        if not (isinstance(value, str) and re.fullmatch(r"[\x20-\x7e]*", value)):
            raise ConfigError(f"headers.{name} : valeur ASCII imprimable attendue (texte, sans retour à la ligne)")
    out["headers"] = dict(headers)
    body = _expect(q.get("body") or {}, dict, "body")
    if reserved := [k for k in ("messages", "model") if k in body]:
        raise ConfigError(f"body.{reserved[0]} : réservé (utilisez `model` ; les messages sont construits par Aulë)")
    if body.get("stream"):
        raise ConfigError("body.stream : la réponse en flux n'est pas gérée (laisser absent ou false)")
    out["body"] = dict(body)
    out["max_tokens"] = _int(q, "max_tokens", 2048, 1, nullable=True)
    out["verify_tls"] = _bool(q, "verify_tls", True)
    path = q.get("response_path", "choices.0.message.content")
    if not (isinstance(path, str) and re.fullmatch(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*", path)):
        raise ConfigError("response_path : chemin pointé attendu (ex. choices.0.message.content ou output.text)")
    out["response_path"] = path
    if q.get("json_mode", "prompt") not in ("prompt", "json_object", "json_schema"):
        raise ConfigError("json_mode : prompt, json_object ou json_schema")
    out["json_mode"], out["fold_system"] = q.get("json_mode", "prompt"), _bool(q, "fold_system", False)
    if q.get("check_url"):
        out["check_url"] = _http_url(q["check_url"], "check_url")
    return out


def parse_llm(data: dict[str, Any] | None, base: Path, source: Path | None = None) -> LLMConfig:
    """Valide le contenu de llm.yaml. `base` : dossier du fichier (les chemins relatifs s'y rapportent)."""
    q = _expect(data or {}, dict, "le fichier")
    provider = q.get("provider", "ollama")
    if provider not in PROVIDERS:
        raise ConfigError("provider : « ollama », « librechat » ou « custom »")
    for key in q:  # une seule table décide quelle clé est permise pour quel moteur
        if key in _REMOVED:
            raise ConfigError(f"{key} : {_REMOVED[key]}")
        if key in _COMMON or key in _ONLY[provider] or (provider != "ollama" and key in _REMOTE):
            continue
        owners = [p for p in PROVIDERS if key in _ONLY[p] or (p != "ollama" and key in _REMOTE)]
        raise ConfigError(f"{key} : " + (f"sans objet avec provider: {provider} (réservé à provider: {' ou '.join(owners)})" if owners else "clé inconnue"))
    if provider != "ollama" and not q.get("url"):
        raise ConfigError("url : requise (librechat : https://chat.exemple.fr ; custom : l'URL complète, ex. https://llm.exemple.fr/v1/chat/completions)")
    out: dict[str, Any] = {"provider": provider, "url": _http_url(q.get("url", LLMConfig.url), "url").rstrip("/") if provider != "custom" else _http_url(q["url"], "url"),
                           "model": str(q["model"]) if q.get("model") else None, "allow_remote": _bool(q, "allow_remote", False), "insecure_http": _bool(q, "insecure_http", False),
                           "timeout": _int(q, "timeout", 300, 1), "source": str(source) if source else None}
    if provider == "ollama":
        out["num_ctx"] = _int(q, "num_ctx", 8192, 512)
        temperature = q.get("temperature", 0.0)
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
            raise ConfigError("temperature : nombre attendu")
        out["temperature"] = float(temperature)
        return LLMConfig(**out)
    key = q.get("api_key")
    if key is not None:
        key = str(key).strip()
        if not re.fullmatch(r"[\x21-\x7e]+", key):
            raise ConfigError("api_key : ASCII imprimable sans espace attendu (retours à la ligne et caractères non ASCII interdits)")
    proxy = q.get("proxy")
    if proxy and proxy != "env" and (urlparse(str(proxy)).scheme not in ("http", "https") or not urlparse(str(proxy)).hostname):
        raise ConfigError("proxy : « env » ou une URL http(s)://hôte:port")
    if q.get("client_key") and not q.get("client_cert"):
        raise ConfigError("client_key : sans client_cert")
    where = lambda k: str((base / str(q[k])).resolve()) if q.get(k) else None  # noqa: E731 — chemins relatifs au fichier llm.yaml
    out.update(api_key=key, retries=_int(q, "retries", 2, 0, 5), proxy=str(proxy) if proxy else None, ca_file=where("ca_file"), client_cert=where("client_cert"), client_key=where("client_key"))
    if provider == "librechat":
        if q.get("endpoint", "chat_completions") not in ("chat_completions", "responses"):
            raise ConfigError("endpoint : chat_completions ou responses")
        out["endpoint"] = q.get("endpoint", "chat_completions")
    else:
        out.update(_custom(q))
    return LLMConfig(**out)


def load_llm(path: Path) -> LLMConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} : YAML invalide : {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path} : illisible ({exc.strerror})") from exc
    try:
        return parse_llm(data, path.resolve().parent, path.resolve())
    except ConfigError as exc:
        raise ConfigError(f"{path} : {exc}") from exc


def migrate(config_path: Path, out: Path, *, force: bool = False, env: dict[str, str] | None = None) -> tuple[list[str], list[str]]:
    """Crée `out` (llm.yaml, chmod 600) à partir des réglages du moteur de l'ancienne section `critiq` de `config_path`.
    Une clé qui venait d'une variable d'environnement ou d'un fichier est INSCRITE dans llm.yaml (c'est le but). Ne modifie PAS config_path.
    Renvoie (notes, clés à supprimer de la section critiq)."""
    env = os.environ if env is None else env
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"{config_path} : illisible ({exc})") from exc
    q = _expect(data.get("critiq") or {}, dict, "critiq")
    moved = {k: q[k] for k in q if k in LEGACY_KEYS}
    if not moved:
        raise ConfigError(f"rien à migrer : la section critiq de {config_path} ne contient aucun réglage du moteur d'IA")
    if out.exists() and not force:
        raise ConfigError(f"{out} existe déjà (--force pour l'écraser)")
    notes, llm = [], {}
    for key, value in moved.items():
        if key == "base_url":
            llm.setdefault("url", value)
        elif key == "use_env_proxy":
            if value:
                llm["proxy"] = "env"
        elif key not in ("api_key_env", "api_key_file"):
            llm[key] = value
    provider = llm.get("provider", "ollama")
    if provider != "ollama" and not llm.get("api_key"):
        var = moved.get("api_key_env") or ("LIBRECHAT_API_KEY" if provider == "librechat" else None)
        file = moved.get("api_key_file")
        if var and (env.get(var) or "").strip():
            llm["api_key"] = env[var].strip()
            notes.append(f"clé d'API lue dans ${var} et inscrite dans {out.name} : vous pouvez désormais retirer cette variable de votre environnement")
        elif file and (config_path.parent / str(file)).expanduser().is_file():
            llm["api_key"] = (config_path.parent / str(file)).expanduser().read_text(encoding="utf-8").strip()
            notes.append(f"clé d'API lue dans {file} et inscrite dans {out.name} : ce fichier n'est plus utilisé")
        else:
            notes.append(f"AUCUNE clé d'API trouvée (variable {var or '—'}, fichier {file or '—'}) : renseignez `api_key` dans {out.name}")
    if out.parent != config_path.parent:  # les chemins relatifs se rapportaient à aule.yaml : on les rend absolus
        for key in ("ca_file", "client_cert", "client_key"):
            if llm.get(key):
                llm[key] = str((config_path.parent / str(llm[key])).resolve())
    try:
        parse_llm(llm, out.parent, out)
    except ConfigError as exc:
        raise ConfigError(f"la configuration migrée serait invalide : {exc}") from exc
    order = ["provider", "url", "model", "api_key", "allow_remote", "timeout"]
    text = ("# llm.yaml — le moteur d'IA, SECRETS COMPRIS : chmod 600, ne pas versionner (voir llm.example.yaml pour toutes les clés)\n"
            + yaml.safe_dump({k: llm[k] for k in order if k in llm} | {k: v for k, v in llm.items() if k not in order}, allow_unicode=True, sort_keys=False))
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    out.chmod(0o600)  # un fichier écrasé garde ses anciens droits : on les force
    return notes, sorted(moved)
