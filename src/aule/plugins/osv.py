"""OSV-Scanner (Google) : composants vulnérables d'après les fichiers de dépendances (lockfiles, manifestes).

⚠ Confidentialité : par défaut osv-scanner interroge l'API api.osv.dev, donc les NOMS ET VERSIONS des
dépendances du client quittent la machine. `options.offline: true` l'évite (base à télécharger au préalable).

Options aule.yaml (tools.osv-scanner.options) :
  command   sous-commande (défaut ["scan", "source"] = osv-scanner ≥ 2 ; ["scan"] ou [] pour les versions 1.x)
  offline   true -> --offline
"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import ToolConfig
from ..models import ParsedEntity, Project, sha256_text as _sha
from ..techmap import detect_ecosystems
from ..vulns import make_purl, normalize_severity, vulnerability_data
from .base import RunContext, Tool, register


@register
class OsvScanner(Tool):
    name = "osv-scanner"
    binary = "osv-scanner"
    modes = ("scan",)
    default_enabled = False
    capture_stdout = True
    report_optional = True  # 128 = aucun fichier de dépendances trouvé : pas de rapport
    ok_exit_codes = frozenset({0, 1, 128})  # 1 = vulnérabilités trouvées

    def phase(self, mode: str) -> int:
        return 2  # a besoin des technologies détectées

    def check_result(self, exit_code: int | None, report_path: Path) -> str | None:
        # 1 = « vulnérabilités trouvées » : le rapport existe forcément. Sans rapport, c'est une erreur
        # (commande/version incompatible) qu'il ne faut pas confondre avec « aucun résultat ».
        if exit_code == 1 and (not report_path.exists() or not report_path.read_text(encoding="utf-8").strip()):
            return "code retour 1 (vulnérabilités attendues) mais aucun rapport : commande ou version incompatible ? (options.command)"
        return None

    def notice(self, cfg: ToolConfig) -> str | None:
        if cfg.options.get("offline"):
            return None
        return ("osv-scanner interroge api.osv.dev : les noms et versions des dépendances quittent la machine "
                "(options.offline: true pour l'éviter)")

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return bool(detect_ecosystems(ctx.languages(project.name), project.path) - {"iac", "native"})

    def reason(self, project: Project, mode: str, ctx: RunContext) -> str:
        return "aucun fichier de dépendances détecté (technologies : " + (", ".join(sorted(ctx.languages(project.name) or {})) or "aucune") + ")"

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        opts = ctx.cfg.options
        cmd = [*ctx.exe, *[str(c) for c in opts.get("command", ["scan", "source"])], "--format", "json"]
        if opts.get("offline"):
            cmd.append("--offline")
        return [*cmd, *ctx.cfg.extra_args, "-r", str(project.path)]

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

        for res in json.loads(text).get("results") or []:
            path = (res.get("source") or {}).get("path") or ""
            try:
                file = Path(path).resolve().relative_to(project.path.resolve()).as_posix()
            except (ValueError, OSError):
                file = path.replace("\\", "/")
            for pkg in res.get("packages") or []:
                info = pkg.get("package") or {}
                vulns = pkg.get("vulnerabilities") or []
                if not vulns:
                    continue
                name, version, eco = info.get("name"), info.get("version"), info.get("ecosystem")
                purl = make_purl(eco, name, version)
                ident = {"name": name, "version": version, "purl": purl, "file": file}
                add("dependency", f"{name}|{version}|{file}", {
                    "tool": self.name, **ident, "type": (purl or "").split("/")[0].removeprefix("pkg:") or (eco or "").lower() or None,
                    "file_name": None, "sha256": None, "license": None, "is_virtual": False, "vulnerability_count": len(vulns)})
                max_sev = {i: g.get("max_severity") for g in pkg.get("groups") or [] for i in g.get("ids") or []}
                for v in vulns:
                    aliases = list(v.get("aliases") or [])
                    cve = next((a for a in aliases if a.startswith("CVE-")), None)
                    try:
                        score = float(max_sev.get(v.get("id")) or "")
                    except ValueError:
                        score = None
                    db = v.get("database_specific") or {}
                    fixed = sorted({ev["fixed"] for a in v.get("affected") or []
                                    if (a.get("package") or {}).get("name") == name
                                    for r in a.get("ranges") or [] for ev in r.get("events") or [] if "fixed" in ev})
                    add("vulnerability", f"{name}|{version}|{file}|{v.get('id')}", vulnerability_data(
                        tool=self.name, vid=cve or v.get("id") or "unknown", source="OSV",
                        severity=normalize_severity(db.get("severity"), score), score=score,
                        cwes=list(db.get("cwe_ids") or []),
                        description=v.get("summary") or v.get("details") or "",
                        references=[r.get("url") for r in v.get("references") or [] if r.get("url")],
                        dependency=ident, fixed_version=", ".join(fixed) or None,
                        aliases=[a for a in [v.get("id"), *aliases] if a and a != (cve or v.get("id"))]))
        return entities
