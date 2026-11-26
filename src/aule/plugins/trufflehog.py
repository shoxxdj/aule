"""TruffleHog : secrets (second avis à gitleaks), avec vérification OPTIONNELLE.

⚠ La vérification (`options.verify: true`) envoie chaque secret trouvé au service concerné (AWS, GitHub...)
pour savoir s'il est encore actif : c'est un test d'identifiants sur des systèmes tiers, hors périmètre de
la plupart des missions. Désactivée par défaut (`--no-verification`).

Les résultats alimentent l'onglet Secrets (même forme que gitleaks, champ `tool`), les liens entre projets
(secret partagé) et l'affichage en clair. Modes : dir (fichiers) et git (historique).

Options aule.yaml (tools.trufflehog.options) : verify (défaut false).
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterator

from ..config import ToolConfig
from ..rulesets import RuleSetError, expand, merge_trufflehog
from ..models import ParsedEntity, Project, sha256_text as _sha
from .base import RunContext, Tool, register
from .gitleaks import _relative, mask


@register
class TruffleHog(Tool):
    name = "trufflehog"
    binary = "trufflehog"
    modes = ("dir", "git")
    default_enabled = False
    secrets_source = True
    report_filename = "report.jsonl"
    capture_stdout = True  # un objet JSON par ligne sur stdout, journaux sur stderr
    ok_exit_codes = frozenset({0, 183})  # 183 = résultats trouvés avec --fail

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return project.is_git if mode == "git" else True

    def notice(self, cfg: ToolConfig) -> str | None:
        if cfg.options.get("verify"):
            return ("trufflehog : vérification ACTIVE — chaque secret trouvé est envoyé au service concerné "
                    "pour test (hors périmètre de la plupart des missions)")
        return None

    supports_rules = True  # détecteurs personnalisés (YAML) de tous les fichiers, fusionnés en un seul --config

    @staticmethod
    def _own_config(cfg: ToolConfig) -> bool:
        return any(a == "--config" or a.startswith("--config=") for a in cfg.extra_args)

    def check_rules(self, cfg: ToolConfig, exe: list[str]) -> str | None:
        if self._own_config(cfg):
            return "tools.trufflehog.rules et un --config dans extra_args ne peuvent pas être combinés (TruffleHog n'accepte qu'UN fichier de configuration) : retirez l'un des deux"
        try:
            merge_trufflehog(expand(cfg.rules, {".yml", ".yaml"}))
        except RuleSetError as exc:
            return f"tools.trufflehog.rules : {exc}"
        return None

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        target = ["filesystem", str(project.path)] if mode == "dir" else ["git", project.path.resolve().as_uri()]
        cmd = [*ctx.exe, *target, "--json", "--no-update"]
        if not ctx.cfg.options.get("verify"):
            cmd.append("--no-verification")
        if ctx.cfg.rules:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            merged = report_path.parent / "detectors.yaml"
            merged.write_text(merge_trufflehog(expand(ctx.cfg.rules, {".yml", ".yaml"})), encoding="utf-8")
            cmd += ["--config", str(merged)]
        return [*cmd, *ctx.cfg.extra_args]

    @staticmethod
    def _results(report_path: Path) -> Iterator[dict]:
        """Résultats dans l'ordre du fichier ; l'index sert de `raw_index` (tolère les lignes non JSON)."""
        text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except ValueError:
                    continue

    def clear_values(self, report_path: Path) -> dict[int, tuple[str, str]] | None:
        return {i: (r.get("Raw") or "", r.get("Redacted") or "") for i, r in enumerate(self._results(report_path))}

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        seen: Counter[str] = Counter()
        entities: list[ParsedEntity] = []
        for index, r in enumerate(self._results(report_path)):
            data = (r.get("SourceMetadata") or {}).get("Data") or {}
            src = data.get("Filesystem") or data.get("Git") or {}
            raw = r.get("Raw") or ""
            file = _relative(project.path, src.get("file") or "")
            detector = r.get("DetectorName") or "unknown"
            base = _sha("|".join([project.name, self.name, mode, detector, file, str(src.get("commit") or ""), _sha(raw)]))[:24]
            seen[base] += 1
            entities.append(ParsedEntity("secret", base if seen[base] == 1 else f"{base}#{seen[base]}", {
                "tool": self.name, "mode": mode, "rule_id": detector,
                "description": r.get("DetectorDescription"), "file": file,
                "start_line": src.get("line"), "end_line": src.get("line"),
                "commit": src.get("commit") or None, "author": None, "email": src.get("email") or None,
                "date": src.get("timestamp") or None, "commit_message": None, "entropy": None,
                "tags": [t for t in [r.get("DecoderName")] if t],
                "verified": r.get("Verified"),
                "secret_masked": mask(raw), "secret_sha256": _sha(raw),
                # jamais la chaîne « Redacted » de l'outil : elle expose un nombre de caractères variable selon le détecteur ;
                # seul NOTRE masquage figure dans un rapport partageable
                "match_masked": None,
                "raw_index": index,
            }))
        return entities
