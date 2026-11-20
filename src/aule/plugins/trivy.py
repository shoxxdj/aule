"""Trivy (`trivy fs`) : composants vulnérables ET mauvaises configurations IaC (Dockerfile, Terraform, K8s...).

Les vulnérabilités alimentent l'onglet Dépendances ; les mauvaises configurations (échecs seulement) l'onglet
Code (SAST) avec la catégorie `iac`. La base de vulnérabilités Trivy se télécharge au premier lancement
(réseau ; aucune donnée du projet n'est envoyée). Une seule exécution à la fois (cache partagé verrouillé).
Trivy ≥ 0.50 (`--scanners`).

Options aule.yaml (tools.trivy.options) :
  scanners         défaut [vuln, misconfig] (secret et license possibles)
  skip_db_update   true -> --skip-db-update
  offline          true -> --offline-scan
  cache_dir        --cache-dir
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models import ParsedEntity, Project, sha256_text as _sha
from ..techmap import detect_ecosystems
from ..vulns import make_purl, normalize_severity, vulnerability_data
from .base import RunContext, Tool, register


@register
class Trivy(Tool):
    name = "trivy"
    binary = "trivy"
    modes = ("fs",)
    default_enabled = False
    max_parallel = 1

    def phase(self, mode: str) -> int:
        return 2

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return bool(detect_ecosystems(ctx.languages(project.name), project.path))

    def reason(self, project: Project, mode: str, ctx: RunContext) -> str:
        return "aucun composant ni fichier d'infrastructure détecté (technologies : " + (", ".join(sorted(ctx.languages(project.name) or {})) or "aucune") + ")"

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        opts = ctx.cfg.options
        cmd = [*ctx.exe, "fs", "--format", "json", "--output", str(report_path), "--quiet",
               "--scanners", ",".join(opts.get("scanners", ["vuln", "misconfig"]))]
        if opts.get("skip_db_update"):
            cmd.append("--skip-db-update")
        if opts.get("offline"):
            cmd.append("--offline-scan")
        if opts.get("cache_dir"):
            cmd += ["--cache-dir", str(opts["cache_dir"])]
        return [*cmd, *ctx.cfg.extra_args, str(project.path)]

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        text = report_path.read_text(encoding="utf-8").strip() if report_path.exists() else ""
        if not text:
            return []
        entities: list[ParsedEntity] = []
        seen: dict[str, int] = {}

        def add(kind: str, key: str, data: dict) -> None:
            fp = _sha("|".join([project.name, self.name, kind, key]))[:24]
            seen[fp] = seen.get(fp, 0) + 1
            entities.append(ParsedEntity(kind, fp if seen[fp] == 1 else f"{fp}#{seen[fp]}", data))

        for res in json.loads(text).get("Results") or []:
            target, rtype = res.get("Target") or "", res.get("Type")
            vulns = res.get("Vulnerabilities") or []
            by_pkg: dict[tuple, int] = {}
            for v in vulns:
                name, version = v.get("PkgName"), v.get("InstalledVersion")
                purl = ((v.get("PkgIdentifier") or {}).get("PURL")) or make_purl(rtype, name, version)
                ident = {"name": name, "version": version, "purl": purl, "file": target}
                by_pkg[(name, version)] = by_pkg.get((name, version), 0) + 1
                scores = [c.get("V3Score") for c in (v.get("CVSS") or {}).values() if c.get("V3Score") is not None]
                score = max(scores) if scores else None
                add("vulnerability", f"{target}|{name}|{version}|{v.get('VulnerabilityID')}", vulnerability_data(
                    tool=self.name, vid=v.get("VulnerabilityID") or "unknown", source=(v.get("DataSource") or {}).get("Name") or "trivy",
                    severity=normalize_severity(v.get("Severity"), score), score=score, cvss_version="3" if scores else None,
                    cwes=list(v.get("CweIDs") or []), description=v.get("Description") or v.get("Title") or "",
                    references=[u for u in [v.get("PrimaryURL"), *(v.get("References") or [])] if u],
                    dependency=ident, fixed_version=v.get("FixedVersion") or None))
            for (name, version), count in by_pkg.items():
                add("dependency", f"{target}|{name}|{version}", {
                    "tool": self.name, "name": name, "version": version, "purl": make_purl(rtype, name, version), "file": target,
                    "type": rtype, "file_name": None, "sha256": None, "license": None, "is_virtual": False, "vulnerability_count": count})
            for m in res.get("Misconfigurations") or []:
                if m.get("Status") not in (None, "FAIL"):
                    continue
                cause = m.get("CauseMetadata") or {}
                lines = (cause.get("Code") or {}).get("Lines") or []
                add("sast_finding", f"{target}|{m.get('AVDID') or m.get('ID')}|{cause.get('StartLine')}|{m.get('Message')}", {
                    "tool": self.name, "rule_id": m.get("AVDID") or m.get("ID") or "unknown", "rule_name": m.get("Title"),
                    "severity": normalize_severity(m.get("Severity")), "level": None, "security_severity": None,
                    "message": (m.get("Message") or m.get("Description") or "")[:1000], "file": target,
                    "start_line": cause.get("StartLine"), "end_line": cause.get("EndLine"), "start_col": None, "end_col": None,
                    "snippet": "\n".join(str(ln.get("Content", "")) for ln in lines)[:2000] or None,
                    "cwe": [], "owasp": [], "tags": [t for t in [rtype, "iac"] if t], "confidence": None,
                    "help_uri": m.get("PrimaryURL"), "flow": [], "category": "iac", "resolution": m.get("Resolution")})
        return entities
