"""OWASP Dependency-Check : composants vulnérables (CVE) des projets.

Ciblage : lancé seulement si un écosystème pris en charge est détecté (langages cloc + manifestes/binaires
sur le disque : pom.xml, package-lock.json, *.jar...). Phase 2, une exécution à la fois (base de données
H2 partagée, non prévue pour les accès concurrents).

Préparation : `aule update dependency-check` télécharge la base NVD (long ; une clé d'API NVD est vivement
recommandée). La clé se donne par variable d'environnement, jamais dans le YAML ; elle est masquée dans
cmd.txt, meta.json et la base.

Options aule.yaml (tools.dependency-check.options) :
  data_path           dossier de la base (défaut : <data>/depcheck-db)
  nvd_api_key_env     nom de la variable d'environnement de la clé (défaut : NVD_API_KEY)
  update              false -> --noupdate (après `aule update`) ; défaut true
  enable_experimental true -> analyseurs expérimentaux (Go, Dart, Swift, C/C++...)
  formats             formats de rapport (défaut [JSON]) ; JSON est toujours produit, HTML est conservé en brut
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Callable

from ..config import ToolConfig
from ..models import ParsedEntity, Project, sha256_text as _sha
from ..techmap import detect_ecosystems
from ..vulns import normalize_severity, parse_purl, vulnerability_data
from .base import RunContext, Tool, ToolError, register

SUPPORTED = {"java", "node", "python", "ruby", "php", "dotnet"}
EXPERIMENTAL = {"go", "swift", "dart", "native"}


@register
class DependencyCheck(Tool):
    name = "dependency-check"
    binary = "dependency-check.sh"
    alt_binaries = ("dependency-check", "dependency-check.bat")
    modes = ("scan",)
    default_enabled = False
    updatable = True
    max_parallel = 1
    report_filename = "dependency-check-report.json"

    def phase(self, mode: str) -> int:
        return 2

    # --- options -----------------------------------------------------------
    def _db_path(self, cfg: ToolConfig, data_dir: Path) -> Path:
        return Path(cfg.options.get("data_path") or data_dir / "depcheck-db")

    def _api_key(self, cfg: ToolConfig) -> str | None:
        return os.environ.get(str(cfg.options.get("nvd_api_key_env") or "NVD_API_KEY")) or None

    def _ecosystems(self, project: Project, ctx: RunContext) -> set[str]:
        wanted = SUPPORTED | (EXPERIMENTAL if ctx.cfg.options.get("enable_experimental") else set())
        return detect_ecosystems(ctx.languages(project.name), project.path) & wanted

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return bool(self._ecosystems(project, ctx))

    def reason(self, project: Project, mode: str, ctx: RunContext) -> str:
        languages = ", ".join(sorted(ctx.languages(project.name) or {})) or "aucune"
        return f"aucun composant à analyser (écosystème non détecté ; technologies : {languages})"

    def sensitive_values(self, ctx: RunContext) -> list[str]:
        key = self._api_key(ctx.cfg)
        return [key] if key else []

    # --- exécution ---------------------------------------------------------
    def _common_args(self, cfg: ToolConfig, data_dir: Path) -> list[str]:
        db = self._db_path(cfg, data_dir)
        db.mkdir(parents=True, exist_ok=True)
        args = ["--data", str(db)]
        if key := self._api_key(cfg):
            args += ["--nvdApiKey", key]
        return args

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        cfg = ctx.cfg
        formats = ["JSON", *[f.upper() for f in cfg.options.get("formats", []) if f.upper() != "JSON"]]
        cmd = [*ctx.exe, "--scan", str(project.path), "--out", str(report_path.parent),
               "--project", project.name, *self._common_args(cfg, ctx.data_dir)]
        for fmt in formats:
            cmd += ["--format", fmt]
        if cfg.options.get("update", True) is False:
            cmd.append("--noupdate")
        if cfg.options.get("enable_experimental"):
            cmd.append("--enableExperimental")
        return [*cmd, *cfg.extra_args]

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        doc = json.loads(report_path.read_text(encoding="utf-8"))
        entities: list[ParsedEntity] = []
        seen: dict[str, int] = {}

        def add(kind: str, key: str, data: dict) -> None:
            fp = _sha("|".join([project.name, kind, key]))[:24]
            seen[fp] = seen.get(fp, 0) + 1
            entities.append(ParsedEntity(kind, fp if seen[fp] == 1 else f"{fp}#{seen[fp]}", data))

        for dep in doc.get("dependencies") or []:
            packages = dep.get("packages") or []
            purl = (packages[0].get("id") if packages else None) or None
            parsed = parse_purl(purl)
            file = self._relative(project, dep.get("filePath") or dep.get("fileName") or "")
            name = parsed["name"] or dep.get("fileName") or file
            ident = {"name": name, "version": parsed["version"], "purl": purl, "file": file}
            vulns = dep.get("vulnerabilities") or []
            dep_key = purl or dep.get("sha256") or f"{dep.get('fileName')}"
            add("dependency", f"{dep_key}|{file}", {
                "tool": self.name, **ident, "type": parsed["type"], "file_name": dep.get("fileName"), "sha256": dep.get("sha256"),
                "license": dep.get("license"), "is_virtual": bool(dep.get("isVirtual")), "vulnerability_count": len(vulns),
            })
            for v in vulns:
                cvss3, cvss2 = v.get("cvssv3") or {}, v.get("cvssv2") or {}
                score = cvss3.get("baseScore", cvss2.get("score"))
                score = float(score) if score is not None else None
                vid = v.get("name") or "unknown"
                add("vulnerability", f"{dep_key}|{file}|{vid}", vulnerability_data(
                    tool=self.name, vid=vid, source=v.get("source"),
                    severity=normalize_severity(v.get("severity") or cvss3.get("baseSeverity"), score),
                    score=score, cvss_version="3" if cvss3 else ("2" if cvss2 else None), cwes=v.get("cwes") or [],
                    description=v.get("description") or "",
                    references=[r.get("url") for r in (v.get("references") or []) if r.get("url")], dependency=ident))
        return entities

    @staticmethod
    def _relative(project: Project, file: str) -> str:
        try:
            return Path(file).resolve().relative_to(project.path.resolve()).as_posix()
        except (ValueError, OSError):
            return file.replace("\\", "/")

    # --- mise à jour de la base NVD ------------------------------------------
    def update(self, cfg: ToolConfig, exe: list[str] | None, data_dir: Path, log: Callable[[str], None]) -> None:
        if exe is None:
            raise ToolError("dependency-check introuvable (tools.dependency-check.path dans aule.yaml)")
        key = self._api_key(cfg)
        if not key:
            log("  ! pas de clé d'API NVD (variable NVD_API_KEY) : la mise à jour peut durer plusieurs heures")
        log(f"Mise à jour de la base : {self._db_path(cfg, data_dir)} (patience…)")
        try:
            out = subprocess.run([*exe, "--updateonly", *self._common_args(cfg, data_dir)],
                                 capture_output=True, text=True, timeout=cfg.timeout or 4 * 3600)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolError(f"échec de la mise à jour : {exc}") from exc
        if out.returncode != 0:
            tail = ((out.stderr or out.stdout).strip().splitlines() or [""])[-1]
            if key:
                tail = tail.replace(key, "***")
            raise ToolError(f"mise à jour en échec (code {out.returncode}) : {tail}")
        log("Base de vulnérabilités à jour")
