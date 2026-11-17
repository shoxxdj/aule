"""Configuration YAML : chemins et options des outils, décompression des archives."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_NAME = "aule.yaml"
LEGACY_CONFIG_NAME = "audit.yaml"   # ancien nom, toujours reconnu (aule.yaml l'emporte)
DEFAULT_ARCHIVE_EXTENSIONS = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


class ConfigError(Exception):
    pass


@dataclass
class ToolConfig:
    enabled: bool | None = None          # None = valeur par défaut de l'outil
    path: str | None = None              # chemin du binaire/script (sinon : nom dans le PATH)
    launcher: list[str] = field(default_factory=list)   # ex. ["bash"] pour un script .sh
    extra_args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    timeout: int | None = None
    max_parallel: int | None = None      # exécutions simultanées de cet outil (défaut : propre à l'outil)
    modes: list[str] | None = None       # restreint les modes (ex. gitleaks : ["dir"], codeql : ["python"])
    options: dict[str, Any] = field(default_factory=dict)  # options propres à l'outil


@dataclass
class UnpackConfig:
    enabled: bool = False
    extensions: tuple[str, ...] = DEFAULT_ARCHIVE_EXTENSIONS
    max_depth: int = 1                   # 1 = archives du projet ; 2 = archives dans les archives...
    max_total_mb: int = 2048             # taille décompressée max par archive
    max_files: int = 200_000


CRITIQ_KINDS = {"secret": "secret", "sast": "sast_finding", "sast_finding": "sast_finding", "vuln": "vulnerability", "vulnerability": "vulnerability"}
DEFAULT_DENY_GLOBS = (".git/**", "**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/id_rsa*", "**/id_ed25519*", "**/*.p12", "**/*.pfx", "**/*.kdbx")


@dataclass
class CritiqConfig:
    """Critique par un modèle d'IA des résultats des outils (avis consultatif ; le triage humain reste maître)."""

    enabled: bool = False
    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str | None = None             # pas de défaut : on ne sait pas ce qui est installé
    allow_remote: bool = False           # sinon seul un endpoint local est accepté
    kinds: tuple[str, ...] = ("secret", "sast_finding")
    min_severity: str = "low"
    max_findings: int = 200
    context_lines: int = 15
    max_rounds: int = 3                  # tours de « demande de code complémentaire »
    max_request_lines: int = 120
    max_prompt_chars: int = 18000
    timeout: int = 300
    num_ctx: int = 8192                  # Ollama tronque en silence à 2048 par défaut : on fixe la fenêtre
    temperature: float = 0.0
    skip_triaged: bool = True            # ne critique pas ce que l'humain a déjà trié
    send_secret_values: bool = False     # ⚠ envoie les secrets en clair au modèle
    deny_globs: tuple[str, ...] = DEFAULT_DENY_GLOBS


@dataclass
class Config:
    jobs: int | None = None
    timeout: int | None = None
    data_dir: Path | None = None
    unpack: UnpackConfig = field(default_factory=UnpackConfig)
    tools: dict[str, ToolConfig] = field(default_factory=dict)
    critiq: CritiqConfig = field(default_factory=CritiqConfig)
    source: Path | None = None

    def tool(self, name: str) -> ToolConfig:
        return self.tools.get(name) or ToolConfig()


def _expect(value: Any, typ: type | tuple, where: str) -> Any:
    if not isinstance(value, typ):
        names = typ.__name__ if isinstance(typ, type) else "/".join(t.__name__ for t in typ)
        raise ConfigError(f"{where} : type attendu {names}, reçu {type(value).__name__}")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    _expect(value, list, where)
    return [str(v) for v in value]


def _check_keys(data: dict, allowed: set[str], where: str) -> None:
    unknown = set(data) - allowed
    if unknown:  # une faute de frappe silencieuse est pire qu'une erreur
        raise ConfigError(f"{where} : clé(s) inconnue(s) {sorted(unknown)} (autorisées : {sorted(allowed)})")


def _resolve_path(value: str, base: Path) -> str:
    """Chemin explicite (contenant un séparateur ou ~) : relatif au fichier de config.
    Nom nu (ex. 'cloc') : laissé tel quel, recherché dans le PATH."""
    if "/" in value or "\\" in value or value.startswith("~"):
        p = Path(value).expanduser()
        return str(p if p.is_absolute() else (base / p))
    return value


def parse_config(data: dict[str, Any] | None, base: Path, source: Path | None = None) -> Config:
    data = data or {}
    _expect(data, dict, "racine")
    _check_keys(data, {"jobs", "timeout", "data_dir", "unpack", "tools", "critiq"}, "racine")
    cfg = Config(source=source)
    if "jobs" in data:
        cfg.jobs = int(_expect(data["jobs"], int, "jobs"))
    if "timeout" in data:
        cfg.timeout = int(_expect(data["timeout"], int, "timeout"))
    if "data_dir" in data:
        cfg.data_dir = Path(_resolve_path(str(data["data_dir"]), base))

    if "unpack" in data:
        u = _expect(data["unpack"] or {}, dict, "unpack")
        _check_keys(u, {"enabled", "extensions", "max_depth", "max_total_mb", "max_files"}, "unpack")
        cfg.unpack = UnpackConfig(
            enabled=bool(u.get("enabled", False)),
            extensions=tuple(e.lower() for e in _str_list(u["extensions"], "unpack.extensions"))
            if "extensions" in u else DEFAULT_ARCHIVE_EXTENSIONS,
            max_depth=int(u.get("max_depth", 1)),
            max_total_mb=int(u.get("max_total_mb", 2048)),
            max_files=int(u.get("max_files", 200_000)),
        )

    if "critiq" in data:
        q = _expect(data["critiq"] or {}, dict, "critiq")
        _check_keys(q, {f.name for f in CritiqConfig.__dataclass_fields__.values()}, "critiq")
        kinds = tuple(dict.fromkeys(CRITIQ_KINDS.get(k, k) for k in _str_list(q["kinds"], "critiq.kinds"))) if "kinds" in q else CritiqConfig.kinds
        if bad := [k for k in kinds if k not in CRITIQ_KINDS.values()]:
            raise ConfigError(f"critiq.kinds : valeur(s) inconnue(s) {bad} (attendu : secret, sast, vuln)")
        if q.get("min_severity", "low") not in ("critical", "high", "medium", "low", "info"):
            raise ConfigError("critiq.min_severity : critical, high, medium, low ou info")
        if q.get("provider", "ollama") != "ollama":
            raise ConfigError("critiq.provider : seul « ollama » est géré pour l'instant")
        cfg.critiq = CritiqConfig(
            enabled=bool(q.get("enabled", False)), provider="ollama", base_url=str(q.get("base_url", CritiqConfig.base_url)).rstrip("/"),
            model=str(q["model"]) if q.get("model") else None, allow_remote=bool(q.get("allow_remote", False)), kinds=kinds,
            min_severity=q.get("min_severity", "low"), max_findings=max(1, int(q.get("max_findings", 200))),
            context_lines=max(0, int(q.get("context_lines", 15))), max_rounds=max(1, int(q.get("max_rounds", 3))),
            max_request_lines=max(10, int(q.get("max_request_lines", 120))), max_prompt_chars=max(2000, int(q.get("max_prompt_chars", 18000))),
            timeout=max(1, int(q.get("timeout", 300))), num_ctx=max(512, int(q.get("num_ctx", 8192))),
            temperature=float(q.get("temperature", 0.0)), skip_triaged=bool(q.get("skip_triaged", True)),
            send_secret_values=bool(q.get("send_secret_values", False)),
            deny_globs=tuple(_str_list(q["deny_globs"], "critiq.deny_globs")) if "deny_globs" in q else DEFAULT_DENY_GLOBS)

    for name, raw in (_expect(data.get("tools") or {}, dict, "tools")).items():
        where = f"tools.{name}"
        t = _expect(raw or {}, dict, where)
        _check_keys(t, {"enabled", "path", "launcher", "extra_args", "env", "timeout", "max_parallel", "modes", "options"}, where)
        tc = ToolConfig()
        if "enabled" in t:
            tc.enabled = bool(_expect(t["enabled"], bool, f"{where}.enabled"))
        if t.get("path"):
            tc.path = _resolve_path(str(t["path"]), base)
        if "launcher" in t:
            tc.launcher = _str_list(t["launcher"], f"{where}.launcher")
        if "extra_args" in t:
            tc.extra_args = _str_list(t["extra_args"], f"{where}.extra_args")
        if "env" in t:
            tc.env = {str(k): str(v) for k, v in _expect(t["env"], dict, f"{where}.env").items()}
        if t.get("timeout") is not None:
            tc.timeout = int(_expect(t["timeout"], int, f"{where}.timeout"))
        if t.get("max_parallel") is not None:
            tc.max_parallel = max(1, int(_expect(t["max_parallel"], int, f"{where}.max_parallel")))
        if t.get("modes") is not None:
            tc.modes = _str_list(t["modes"], f"{where}.modes")
        if "options" in t:
            tc.options = dict(_expect(t["options"] or {}, dict, f"{where}.options"))
            for key, value in tc.options.items():  # options *_path / *_dir : relatives au fichier YAML
                if key.endswith(("_path", "_dir")) and isinstance(value, str):
                    p = Path(value).expanduser()
                    tc.options[key] = str(p if p.is_absolute() else base / p)
        cfg.tools[str(name)] = tc
    return cfg


def load_config(path: Path | None) -> Config:
    """`path` explicite : doit exister. Sinon ./aule.yaml (ou l'ancien ./audit.yaml) s'il existe, sinon valeurs par défaut."""
    if path is None:
        candidate = next((c for c in (Path.cwd() / DEFAULT_CONFIG_NAME, Path.cwd() / LEGACY_CONFIG_NAME) if c.is_file()), None)
        if candidate is None:
            return Config()
        path = candidate
    elif not path.is_file():
        raise ConfigError(f"fichier de configuration introuvable : {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML invalide dans {path} : {exc}") from exc
    try:
        return parse_config(data, path.resolve().parent, path.resolve())
    except ConfigError as exc:
        raise ConfigError(f"{path} : {exc}") from exc
