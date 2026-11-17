"""Triage des résultats automatiques : sélection (empreintes ou filtres) et libellés communs."""
from __future__ import annotations

import fnmatch
from typing import Any

from .db import Database

KINDS = {"secret": "secret", "sast": "sast_finding", "vuln": "vulnerability"}
KIND_NAMES = {v: k for k, v in KINDS.items()}


def label(kind: str, d: dict[str, Any]) -> str:
    if kind == "secret":
        return f"{d.get('rule_id')} ({d.get('tool') or 'gitleaks'}/{d.get('mode')})"
    if kind == "sast_finding":
        return f"{d.get('rule_id')} ({d.get('tool') or '?'})"
    dep = d.get("dependency") or {}
    return f"{d.get('id')} · {dep.get('name')} {dep.get('version') or ''}".strip()


def location(kind: str, d: dict[str, Any]) -> str:
    if kind == "vulnerability":
        return (d.get("dependency") or {}).get("file") or ""
    line = d.get("start_line")
    return f"{d.get('file')}:{line}" if line else str(d.get("file") or "")


def severity_of(kind: str, d: dict[str, Any]) -> str:
    """Sévérité normalisée. Un secret n'a pas de sévérité native : élevée, critique si vérifié actif."""
    if kind == "secret":
        return "critical" if d.get("verified") else "high"
    return d.get("severity") or "medium"


def find_entities(db: Database, audit_id: str, *, kind: str | None = None, project: str | None = None,
                  rule: str | None = None, severity: str | None = None, mode: str | None = None,
                  tool: str | None = None, file_glob: str | None = None, untriaged: bool = False,
                  prefixes: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Entités triables d'un run, filtrées. `kind` : secret | sast | vuln (ou nom interne)."""
    kinds = [KINDS.get(kind, kind)] if kind else list(KINDS.values())
    names = {p["id"]: p["name"] for p in db.list_projects(audit_id)}
    out = []
    for k in kinds:
        for e in db.entities(audit_id, k):
            d, proj = e["data"], names[e["project_id"]]
            rid = d.get("rule_id") or d.get("id")
            if project and proj != project or rule and rid != rule:
                continue
            if severity and severity_of(k, d) != severity or mode and d.get("mode") != mode:
                continue
            if tool and (d.get("tool") or "gitleaks" if k == "secret" else d.get("tool")) != tool:
                continue
            if file_glob and not fnmatch.fnmatch(location(k, d).split(":")[0], file_glob):
                continue
            if untriaged and e["triage_status"]:
                continue
            if prefixes and not any(e["fingerprint"].startswith(p) for p in prefixes):
                continue
            out.append({**e, "kind": k, "project": proj, "label": label(k, d), "location": location(k, d),
                        "severity": severity_of(k, d)})
    return out


def resolve_prefixes(db: Database, audit_id: str, prefixes: list[str]) -> list[str]:
    """Empreintes complètes pour des préfixes (≥ 6 caractères) ; erreur si inconnu ou ambigu."""
    fingerprints = sorted({e["fingerprint"] for e in find_entities(db, audit_id)})
    resolved = []
    for prefix in prefixes:
        if len(prefix) < 6:
            raise ValueError(f"préfixe trop court : {prefix!r} (6 caractères minimum)")
        hits = [f for f in fingerprints if f.startswith(prefix)]
        if not hits:
            raise ValueError(f"aucun résultat ne correspond à {prefix!r} dans ce run")
        if len(hits) > 1:
            raise ValueError(f"préfixe ambigu : {prefix!r} correspond à {len(hits)} résultats")
        resolved.append(hits[0])
    return resolved
