"""Briques communes aux outils de vulnérabilités (dependency-check, osv-scanner, trivy)."""
from __future__ import annotations

import re
from typing import Any

_PURL_RE = re.compile(r"^pkg:([^/]+)/(?:(.+)/)?([^/@?#]+)(?:@([^?#]+))?")
# écosystème OSV -> type purl
_PURL_TYPES = {"npm": "npm", "pypi": "pypi", "maven": "maven", "go": "golang", "rubygems": "gem",
               "crates.io": "cargo", "nuget": "nuget", "packagist": "composer", "pub": "pub", "hex": "hex"}


def parse_purl(purl: str | None) -> dict[str, str | None]:
    m = _PURL_RE.match(purl or "")
    if not m:
        return {"type": None, "name": None, "version": None}
    ns = f"{m[2]}/" if m[2] else ""
    return {"type": m[1], "name": ns + m[3], "version": m[4]}


def make_purl(ecosystem: str | None, name: str | None, version: str | None) -> str | None:
    """purl approché à partir d'un écosystème OSV/Trivy (None si inconnu)."""
    ptype = _PURL_TYPES.get((ecosystem or "").split(":")[0].lower())
    if not ptype or not name:
        return None
    path = name.replace(":", "/") if ptype == "maven" else name
    return f"pkg:{ptype}/{path}" + (f"@{version}" if version else "")


def normalize_severity(raw: str | None, score: float | None = None) -> str:
    raw = (raw or "").lower()
    raw = {"moderate": "medium", "informational": "info", "unknown": ""}.get(raw, raw)
    if raw in ("critical", "high", "medium", "low", "info"):
        return raw
    if score is None:
        return "medium"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def vulnerability_data(*, tool: str, vid: str, severity: str, dependency: dict[str, Any], source: str | None = None,
                       score: float | None = None, cvss_version: str | None = None, cwes: list[str] | None = None,
                       description: str = "", references: list[str] | None = None,
                       fixed_version: str | None = None, aliases: list[str] | None = None) -> dict[str, Any]:
    """Forme commune d'une entité `vulnerability` (consommée par le rapport, l'export, le diff)."""
    return {"tool": tool, "id": vid, "source": source, "severity": severity, "cvss_score": score,
            "cvss_version": cvss_version, "cwes": cwes or [], "description": description[:1500],
            "references": (references or [])[:6], "dependency": dependency, "fixed_version": fixed_version,
            "aliases": aliases or []}
