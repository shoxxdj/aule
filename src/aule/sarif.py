"""Parseur SARIF 2.1 générique (opengrep, CodeQL...) -> entités `sast_finding` normalisées."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

from .models import ParsedEntity, sha256_text as _sha

_CWE_RE = re.compile(r"CWE-(\d+)", re.I)


def severity_from(level: str | None, security_severity: float | None) -> str:
    """Sévérité normalisée. Le score `security-severity` (CodeQL, échelle CVSS) prime sur `level`."""
    if security_severity is not None:
        if security_severity >= 9.0:
            return "critical"
        if security_severity >= 7.0:
            return "high"
        if security_severity >= 4.0:
            return "medium"
        return "low" if security_severity > 0 else "info"
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get((level or "warning").lower(), "medium")


def relative_uri(uri: str, project_path: Path) -> str:
    """URI SARIF (relative, `file:///abs`, `./x`) -> chemin POSIX relatif au projet."""
    parsed = urlparse(uri)
    p = Path(unquote(parsed.path if parsed.scheme == "file" else uri))
    if p.is_absolute():
        try:
            return p.resolve().relative_to(project_path.resolve()).as_posix()
        except (ValueError, OSError):
            return p.as_posix()
    return p.as_posix()  # Path normalise déjà "./x" en "x"


def _read_lines(project_path: Path, file: str, start: int | None, end: int | None) -> str | None:
    if not start:
        return None
    try:
        lines = (project_path / file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    chunk = lines[start - 1:min(end or start, start + 14)]
    return "\n".join(chunk) or None


def _flow(res: dict, project_path: Path, limit: int = 25) -> list[dict]:
    """Premier chemin de données (codeFlows) : étapes source -> ... -> puits. Vide si le résultat n'en a pas."""
    steps: list[dict] = []
    for code_flow in (res.get("codeFlows") or [])[:1]:
        for thread_flow in (code_flow.get("threadFlows") or [])[:1]:
            for item in (thread_flow.get("locations") or [])[:limit]:
                loc = item.get("location") or {}
                phys = loc.get("physicalLocation") or {}
                steps.append({
                    "file": relative_uri((phys.get("artifactLocation") or {}).get("uri") or "", project_path),
                    "line": (phys.get("region") or {}).get("startLine"),
                    "message": ((loc.get("message") or {}).get("text") or "")[:200] or None,
                })
    return steps


def parse_sarif(report_path: Path, project_name: str, project_path: Path, *, kind: str = "sast_finding") -> list[ParsedEntity]:
    text = report_path.read_text(encoding="utf-8").strip() if report_path.exists() else ""
    if not text:
        return []
    entities: list[ParsedEntity] = []
    seen: dict[str, int] = {}
    for run_idx, run in enumerate(json.loads(text).get("runs") or []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = driver.get("name")
        rules = driver.get("rules") or []
        by_id = {r.get("id"): r for r in rules}
        for res_idx, res in enumerate(run.get("results") or []):
            idx = res.get("ruleIndex")
            rule = rules[idx] if isinstance(idx, int) and 0 <= idx < len(rules) else by_id.get(res.get("ruleId"), {})
            rule_id = res.get("ruleId") or rule.get("id") or "unknown"
            props = rule.get("properties") or {}
            tags = [str(t) for t in props.get("tags") or []]
            try:
                score = float(props["security-severity"]) if "security-severity" in props else None
            except (TypeError, ValueError):
                score = None
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level")

            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation") or {}
            file = relative_uri((phys.get("artifactLocation") or {}).get("uri") or "", project_path)
            region = phys.get("region") or {}
            start, end = region.get("startLine"), region.get("endLine") or region.get("startLine")
            snippet = (region.get("snippet") or {}).get("text") or _read_lines(project_path, file, start, end)
            message = ((res.get("message") or {}).get("text") or "").strip()

            # Empreinte stable : indépendante du numéro de ligne (le triage survit aux décalages de code)
            partial = next(iter((res.get("partialFingerprints") or {}).values()), None)
            basis = partial or _sha((snippet or message).strip())
            fp = _sha("|".join([project_name, str(tool_name), rule_id, file, str(basis)]))[:24]
            seen[fp] = seen.get(fp, 0) + 1
            cwe = sorted({f"CWE-{int(m.group(1))}" for t in tags if (m := _CWE_RE.search(t))})  # cwe-089 (CodeQL) -> CWE-89
            entities.append(ParsedEntity(kind, fp if seen[fp] == 1 else f"{fp}#{seen[fp]}", {
                "tool": tool_name, "rule_id": rule_id,
                "rule_name": rule.get("name") or (rule.get("shortDescription") or {}).get("text"),
                "severity": severity_from(level, score), "level": level, "security_severity": score,
                "message": message[:1000], "file": file,
                "start_line": start, "end_line": end,
                "start_col": region.get("startColumn"), "end_col": region.get("endColumn"),
                "snippet": snippet[:2000] if snippet else None,
                "cwe": cwe, "owasp": [t for t in tags if t.upper().startswith("OWASP")],
                "tags": [t for t in tags if not _CWE_RE.search(t) and not t.upper().startswith("OWASP")][:10],
                "confidence": props.get("precision") or props.get("confidence"),
                "help_uri": rule.get("helpUri"),
                "flow": _flow(res, project_path),
                # position exacte dans la sortie brute : permet d'ouvrir le résultat COMPLET (règle, tous les chemins, notifications...)
                "raw_index": res_idx, "sarif_run": run_idx,
            }))
    return entities
