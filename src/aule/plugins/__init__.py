"""Découverte automatique : tout module `plugins/<x>.py` est chargé et enregistre ses outils."""
from __future__ import annotations

import importlib
import pkgutil

from ..config import TOOL_ALIASES, Config
from .base import _REGISTRY, RunContext, Tool, ToolError

__all__ = ["RunContext", "Tool", "ToolError", "load_plugins", "select_tools"]


def load_plugins() -> dict[str, Tool]:
    for mod in pkgutil.iter_modules(__path__):
        if not mod.name.startswith("_") and mod.name != "base":
            importlib.import_module(f"{__name__}.{mod.name}")
    return dict(sorted(_REGISTRY.items()))  # ordre déterministe


def select_tools(config: Config, names: list[str] | None = None) -> list[Tool]:
    """--tools explicite : exactement ces outils (même s'ils sont désactivés par défaut).
    Sinon : outils activés par défaut, ajustés par `enabled:` dans aule.yaml."""
    registry = load_plugins()
    names = [TOOL_ALIASES.get(n, n) for n in names or []]
    unknown = [n for n in list(names or []) + list(config.tools) if n not in registry]
    if unknown:
        raise ValueError(f"outil(s) inconnu(s) : {', '.join(sorted(set(unknown)))} "
                         f"(disponibles : {', '.join(registry)})")
    if names:
        return [registry[n] for n in names]
    return [t for t in registry.values()
            if (config.tool(t.name).enabled if config.tool(t.name).enabled is not None else t.default_enabled)]
