"""Références de run : l'auditeur nomme ses passages ; l'horodatage reste l'identifiant technique immuable.

Un run se désigne par son libellé (libre, choisi par l'auditeur), son identifiant, ou un alias : `@dernier`,
`@précédent`. Les libellés sont uniques (sans distinction de casse) dans une mission.
"""
from __future__ import annotations

import re
from typing import Any

RUN_ID = re.compile(r"^\d{8}-\d{6}(-\d+)?$")
ALIASES_LAST = {"@dernier", "@last", "@latest"}
ALIASES_PREV = {"@précédent", "@precedent", "@previous", "@prev"}
MAX_LABEL = 80


class RunRefError(ValueError):
    """Référence de run inconnue ou ambiguë (message destiné à l'auditeur)."""


def validate_label(label: str, existing: list[dict[str, Any]], exclude: str | None = None) -> str:
    """Libellé nettoyé, ou ValueError. `existing` : les audits de la mission (id, label)."""
    label = " ".join((label or "").split())  # espaces normalisés
    if not label:
        raise ValueError("libellé vide")
    if len(label) > MAX_LABEL:
        raise ValueError(f"libellé trop long ({len(label)} > {MAX_LABEL} caractères)")
    if any(ord(c) < 32 for c in label):
        raise ValueError("caractères de contrôle interdits dans un libellé")
    if label.startswith("@"):
        raise ValueError("un libellé ne peut pas commencer par « @ » (réservé aux alias @dernier, @précédent)")
    if RUN_ID.match(label):
        raise ValueError("un libellé ne peut pas ressembler à un identifiant de run (AAAAMMJJ-HHMMSS)")
    clash = next((a for a in existing if a["id"] != exclude and (a.get("label") or "").casefold() == label.casefold()), None)
    if clash:
        raise ValueError(f"le libellé « {label} » désigne déjà le run {clash['id']}")
    return label


def display_name(audit: dict[str, Any]) -> str:
    return audit.get("label") or audit["id"]


def resolve_run(db, ref: str | None = None) -> str | None:
    """Identifiant du run désigné. None si `ref` est vide ET qu'il n'y a aucun audit ; RunRefError si `ref` est inconnue."""
    audits = db.list_audits()  # du plus récent au plus ancien
    if ref in (None, "") or ref in ALIASES_LAST:
        if audits:
            return audits[0]["id"]
        if ref in ALIASES_LAST:
            raise RunRefError("aucun audit : lancez d'abord `aule run <dossier>`")
        return None
    if ref in ALIASES_PREV:
        if len(audits) < 2:
            raise RunRefError("il n'y a pas de run précédent (un seul audit)")
        return audits[1]["id"]
    if any(a["id"] == ref for a in audits):
        return ref
    hits = [a for a in audits if (a.get("label") or "").casefold() == ref.casefold()]
    if len(hits) == 1:
        return hits[0]["id"]
    known = ", ".join(f"{a['label']} ({a['id']})" if a.get("label") else a["id"] for a in audits[:8]) or "aucun"
    raise RunRefError(f"run inconnu : {ref!r} ; disponibles : {known}")
