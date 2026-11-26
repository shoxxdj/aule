"""CodeQL (CLI GitHub) : analyse sémantique avec chemins de données source -> puits.

Un mode par langage CodeQL (python, javascript-typescript, java-kotlin, csharp, go, c-cpp, ruby...) : un
projet polyglotte donne une exécution, un statut et une reprise PAR LANGAGE. Après cloc, seuls les langages
détectés sont analysés ; un projet sans langage pris en charge laisse une seule ligne « ignoré » (mode « - »).

Deux étapes par exécution : `codeql database create` (commande de l'outil) puis `codeql database analyze`
(hook `post_run`, ses fichiers bruts : analyze.cmd.txt / analyze.stdout.txt / analyze.stderr.txt).

Compilation : Java/Kotlin et C# s'analysent sans build (`--build-mode=none`, CodeQL ≥ 2.18) ; Go et C/C++
utilisent l'autobuild de CodeQL (toolchain + dépendances requises, souvent absentes sur du code client :
l'échec est alors visible) ; `build_commands` fournit une commande de build explicite.

Requêtes : suite `security-extended` du paquet `codeql/<langage>-queries`. Les paquets se téléchargent avec
`aule update codeql` (réseau) ; le « CodeQL bundle » les embarque déjà (hors ligne).

Ressources : une exécution à la fois (RAM/CPU), délai par défaut de 2 h.

Options aule.yaml (tools.codeql.options) :
  suite             code-scanning | security-extended (défaut) | security-and-quality
  queries           {langage: spécification de requêtes} (paquet:suite ou chemin) ; remplace la suite
  pack_versions     {langage: version} pour épingler un paquet (reproductibilité)
  build_modes       {langage: none|autobuild} (défaut : java-kotlin et csharp -> none)
  build_commands    {langage: commande de build} (-> --command)
  language_map      langage cloc -> identifiant CodeQL, en plus des défauts
  min_code_lines    ignorer un langage sous ce nombre de lignes (défaut 0)
  threads, ram      --threads (défaut 0 = tous les cœurs) / --ram (Mo)
  analyze_args      arguments ajoutés à `database analyze` (extra_args vaut pour `database create`)
  search_path       --search-path (dépôt github/codeql local : hors ligne)
  download          true -> `analyze --download` (télécharge les paquets manquants)
  keep_database     true -> conserve la base (défaut false : supprimée après une analyse réussie)
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from ..config import ToolConfig
from ..models import ParsedEntity, Project
from ..sarif import parse_sarif
from ..techmap import CODEQL_LANGUAGES
from .base import RunContext, Tool, ToolError, register

DEFAULT_LANGUAGES = ("python", "javascript-typescript", "java-kotlin", "csharp", "go", "c-cpp", "ruby")
# identifiant de langage CodeQL -> nom du paquet de requêtes (codeql/<nom>-queries)
PACKS = {"python": "python", "javascript-typescript": "javascript", "java-kotlin": "java", "csharp": "csharp",
         "go": "go", "c-cpp": "cpp", "ruby": "ruby", "swift": "swift", "rust": "rust"}
DEFAULT_BUILD_MODES = {"java-kotlin": "none", "csharp": "none"}
SUITES = ("code-scanning", "security-extended", "security-and-quality")


def _tail(raw: bytes | str | None) -> str:
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else (raw or "")
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    return lines[-1][:300] if lines else ""


@register
class CodeQL(Tool):
    name = "codeql"
    binary = "codeql"
    modes = (*DEFAULT_LANGUAGES, "swift", "rust")
    default_enabled = False
    updatable = True
    quiet_skip = True
    max_parallel = 1
    default_timeout = 7200
    report_filename = "report.sarif"

    def phase(self, mode: str) -> int:
        return 3  # 4ᵉ phase : après cloc/gitleaks, opengrep, dependency-check

    # --- langages ----------------------------------------------------------
    def _detected(self, project: Project, ctx: RunContext) -> set[str]:
        languages = ctx.languages(project.name)
        if not languages:
            return set()
        mapping = {**CODEQL_LANGUAGES, **(ctx.cfg.options.get("language_map") or {})}
        floor = int(ctx.cfg.options.get("min_code_lines", 0))
        return {mapping[lang] for lang, lines in languages.items() if lang in mapping and lines >= floor}

    def applicable(self, project: Project, mode: str, ctx: RunContext) -> bool:
        return mode in self._detected(project, ctx)

    def reason(self, project: Project, mode: str, ctx: RunContext) -> str:
        languages = ctx.languages(project.name)
        if languages is None:
            return "technologies inconnues : lancez cloc avant CodeQL (ex. --tools cloc,codeql)"
        if not languages:
            return "aucune technologie détectée par cloc"
        return "aucune technologie prise en charge par CodeQL : " + ", ".join(sorted(languages))

    # --- requêtes ----------------------------------------------------------
    supports_rules = True  # chaque dossier contient un sous-dossier par langage (python, javascript-typescript, java-kotlin…) : celui du langage analysé s'ajoute à la suite

    @staticmethod
    def _extra_specs(mode: str, cfg: ToolConfig) -> list[str]:
        return [str(Path(r) / mode) for r in cfg.rules if (Path(r) / mode).is_dir()]

    def check_rules(self, cfg: ToolConfig, exe: list[str]) -> str | None:
        if files := [r for r in cfg.rules if not Path(r).is_dir()]:
            return f"tools.codeql.rules : des DOSSIERS sont attendus (un sous-dossier par langage), pas des fichiers : {', '.join(files)}"
        return None

    def warnings(self, cfg: ToolConfig, exe: list[str]) -> list[str]:
        return [f"tools.codeql.rules : {r} n'a aucun sous-dossier de langage ({', '.join(sorted(PACKS))}) : ces règles ne seront appliquées à aucun langage"
                for r in cfg.rules if not any((Path(r) / m).is_dir() for m in PACKS)]

    def _query_spec(self, mode: str, cfg: ToolConfig) -> str:
        opts = cfg.options
        if (override := (opts.get("queries") or {}).get(mode)):
            return str(override)
        suite = opts.get("suite", "security-extended")
        if suite not in SUITES:
            raise ToolError(f"suite CodeQL inconnue : {suite} (attendu : {', '.join(SUITES)})")
        pack = PACKS[mode]
        version = (opts.get("pack_versions") or {}).get(mode)
        return f"codeql/{pack}-queries{'@' + str(version) if version else ''}:codeql-suites/{pack}-{suite}.qls"

    def prerequisites(self, cfg: ToolConfig, data_dir: Path) -> str | None:
        suite = cfg.options.get("suite", "security-extended")
        if suite not in SUITES:  # détecté avant la création (coûteuse) des bases
            return f"suite CodeQL inconnue : {suite!r} (attendu : {', '.join(SUITES)}) — tools.codeql.options.suite"
        return None

    def version_info(self, cfg: ToolConfig, data_dir: Path) -> str | None:
        return f"suite {cfg.options.get('suite', 'security-extended')}"

    # --- étape 1 : base de données -------------------------------------------
    def _db_dir(self, project: Project, mode: str, ctx: RunContext) -> Path:
        return ctx.data_dir / "work" / ctx.run_id / "codeql" / project.name / mode

    def build_command(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[str]:
        opts = ctx.cfg.options
        db = self._db_dir(project, mode, ctx)
        db.parent.mkdir(parents=True, exist_ok=True)
        cmd = [*ctx.exe, "database", "create", str(db), f"--language={mode}",
               f"--source-root={project.path}", "--overwrite", f"--threads={opts.get('threads', 0)}"]
        if command := (opts.get("build_commands") or {}).get(mode):
            cmd.append(f"--command={command}")
        elif (build := {**DEFAULT_BUILD_MODES, **(opts.get("build_modes") or {})}.get(mode)):
            cmd.append(f"--build-mode={build}")
        return [*cmd, *ctx.cfg.extra_args]

    # --- étape 2 : analyse ---------------------------------------------------
    def post_run(self, project: Project, mode: str, raw_dir: Path, report_path: Path, ctx: RunContext) -> None:
        opts = ctx.cfg.options
        db = self._db_dir(project, mode, ctx)
        cmd = [*ctx.exe, "database", "analyze", str(db), self._query_spec(mode, ctx.cfg), *self._extra_specs(mode, ctx.cfg), "--format=sarif-latest",
               f"--output={report_path}", "--sarif-add-snippets", f"--threads={opts.get('threads', 0)}"]
        if opts.get("ram"):
            cmd.append(f"--ram={opts['ram']}")
        if opts.get("download"):
            cmd.append("--download")
        if opts.get("search_path"):
            cmd.append(f"--search-path={opts['search_path']}")
        cmd += [str(a) for a in opts.get("analyze_args") or []]
        (raw_dir / "analyze.cmd.txt").write_text(shlex.join(cmd) + "\n", encoding="utf-8")
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=ctx.timeout, stdin=subprocess.DEVNULL,
                                  env={**os.environ, **ctx.cfg.env} if ctx.cfg.env else None)
        except subprocess.TimeoutExpired as exc:
            (raw_dir / "analyze.stdout.txt").write_bytes(exc.stdout or b"")
            (raw_dir / "analyze.stderr.txt").write_bytes(exc.stderr or b"")
            raise RuntimeError(f"codeql database analyze : délai de {ctx.timeout}s dépassé (base conservée : {db})") from exc
        (raw_dir / "analyze.stdout.txt").write_bytes(proc.stdout)
        (raw_dir / "analyze.stderr.txt").write_bytes(proc.stderr)
        if proc.returncode != 0:  # base conservée pour diagnostic
            raise RuntimeError(f"codeql database analyze : code {proc.returncode} : {_tail(proc.stderr)} "
                               f"(base conservée : {db})")
        if opts.get("keep_database"):
            (raw_dir / "database.txt").write_text(str(db) + "\n", encoding="utf-8")
        else:
            shutil.rmtree(db, ignore_errors=True)  # une base CodeQL pèse souvent plus que les sources

    def parse(self, project: Project, mode: str, report_path: Path, ctx: RunContext) -> list[ParsedEntity]:
        entities = parse_sarif(report_path, project.name, project.path)
        for e in entities:
            e.data["language"] = mode
        return entities

    # --- mise à jour des paquets de requêtes ---------------------------------
    def update(self, cfg: ToolConfig, exe: list[str] | None, data_dir: Path, log: Callable[[str], None]) -> None:
        if exe is None:
            raise ToolError("codeql introuvable (tools.codeql.path dans aule.yaml)")
        languages = cfg.modes or sorted(set(DEFAULT_LANGUAGES) | set((cfg.options.get("language_map") or {}).values()))
        versions = cfg.options.get("pack_versions") or {}
        packs = [f"codeql/{PACKS[lang]}-queries" + (f"@{versions[lang]}" if lang in versions else "")
                 for lang in languages if lang in PACKS]
        log(f"Téléchargement des paquets de requêtes : {', '.join(packs)}")
        try:
            out = subprocess.run([*exe, "pack", "download", *packs], capture_output=True, text=True,
                                 timeout=cfg.timeout or 3600)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolError(f"échec du téléchargement : {exc}") from exc
        if out.returncode != 0:
            raise ToolError(f"codeql pack download en échec (code {out.returncode}) : {_tail(out.stderr or out.stdout)}")
        log("Paquets de requêtes à jour")
