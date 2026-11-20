"""Parcourt les projets, lance les outils en parallèle par phase, reprend après interruption."""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from .config import Config, ToolConfig
from .db import Database, now_iso
from .discovery import discover_projects
from .correlate import correlate_run
from .critiq import run_critique
from .links import compute_relations
from .llm import LLMError
from .models import Project
from .plugins import load_plugins, select_tools
from .plugins.base import PLACEHOLDER_MODE, RunContext, Tool
from .runner import TaskResult, execute, tool_version
from .unpack import unpack_projects

Log = Callable[[str], None]
DEFAULT_TIMEOUT = 1800


class AuditError(Exception):
    pass


@dataclass
class Task:
    tool: Tool
    project: Project
    project_id: int
    mode: str
    raw_rel: Path  # relatif au dossier de données : le dossier reste déplaçable
    ctx: RunContext
    timeout: int
    version: str | None


def new_run_id(db: Database) -> str:
    base = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_id, n = base, 1
    while db.get_audit(run_id):  # deux runs dans la même seconde : suffixe
        n += 1
        run_id = f"{base}-{n}"
    return run_id


def resolve_timeout(tool: Tool, cfg: ToolConfig, explicit: int | None, default: int = DEFAULT_TIMEOUT) -> int:
    """Délai d'une exécution : `timeout:` de l'outil > --timeout / `timeout:` global > défaut de l'outil > 1800 s."""
    return cfg.timeout or explicit or tool.default_timeout or default


def _modes(tool: Tool, cfg: ToolConfig, selected: set[str]) -> list[str]:
    modes = [m for m in tool.modes if cfg.modes is None or m in cfg.modes]
    return [m for m in modes if tool.mode_requires.get(m, tool.name) in selected | {tool.name}]


def run_audit(
    db: Database, data_dir: Path, root: Path, *, config: Config | None = None,
    tool_names: list[str] | None = None, jobs: int | None = None, timeout: int | None = None,
    resume: str | None = None, exclude: tuple[str, ...] = (), unpack: bool | None = None, critiq: bool | None = None,
    label: str | None = None, log: Log = print, progress: Callable[[int, int, int], None] | None = None,
) -> str:
    config = config or Config()
    if not root.is_dir():
        raise AuditError(f"{root} n'est pas un dossier")
    tools = select_tools(config, tool_names)
    selected = {t.name for t in tools}
    projects = discover_projects(root, exclude=(data_dir, *exclude))
    if not projects:
        raise AuditError(f"aucun sous-dossier à analyser dans {root}")
    jobs = jobs or config.jobs or min(4, os.cpu_count() or 2)
    explicit_timeout = timeout or config.timeout

    if resume:
        if not db.get_audit(resume):
            raise AuditError(f"run inconnu : {resume}")
        run_id = resume
        db.set_audit_status(run_id, "running")
    else:
        run_id = new_run_id(db)
        db.create_audit(run_id, root.resolve(), label)  # libellé invalide ou déjà pris : ValueError, avant tout lancement d'outil
    log(f"Run {run_id} — {len(projects)} projet(s), outils : {', '.join(t.name for t in tools)}"
        + (f"  [config : {config.source}]" if config.source else ""))
    project_ids = {p.name: db.upsert_project(run_id, p) for p in projects}

    # --- archives (option) : chaque archive décompressée devient un projet dérivé
    if unpack if unpack is not None else config.unpack.enabled:
        derived, events = unpack_projects(projects, data_dir / "work" / run_id, config.unpack)
        for child in derived:
            project_ids[child.name] = db.upsert_project(run_id, child)
            db.set_relation(run_id, "project", project_ids[child.name], "project",
                            project_ids[child.parent], "extracted_from", {"archive": child.origin})
        for ev in events:
            detail = f"{ev.files} fichier(s), {ev.skipped} ignoré(s)" if ev.status == "ok" else None
            db.save_tool_run(run_id, project_ids[ev.project], "unpack", ev.archive, status=ev.status,
                             error=ev.error, command=detail, started_at=now_iso())
            log(f"  [{ev.status}] {ev.project} · archive {ev.archive}" + (f" : {ev.error}" if ev.error else f" ({detail})"))
        projects = projects + derived

    # --- résolution des outils
    exes: dict[str, list[str] | None] = {}
    versions: dict[str, str | None] = {}
    blocked: dict[str, str] = {}  # outil -> prérequis manquant (règles absentes...)
    for tool in tools:
        cfg = config.tool(tool.name)
        exes[tool.name] = tool.resolve(cfg)
        if exes[tool.name] is None:
            where = tool.wanted(cfg)
            log(f"  ! {tool.name} : '{where}' introuvable, exécutions ignorées (voir aule.yaml : tools.{tool.name}.path)")
            continue
        if problem := tool.prerequisites(cfg, data_dir):
            blocked[tool.name] = problem
            log(f"  ! {tool.name} : {problem}")
            continue
        versions[tool.name] = " · ".join(filter(None, [tool_version(tool, exes[tool.name], cfg.env),
                                                       tool.version_info(cfg, data_dir)])) or None
        if notice := tool.notice(cfg):
            log(f"  ⚠ {notice}")

    # --- exécution par phase : l'applicabilité est évaluée juste avant chaque phase,
    #     une phase pouvant dépendre des sorties des précédentes (gittools -> gitleaks history)
    phases = sorted({tool.phase(m) for tool in tools for m in _modes(tool, config.tool(tool.name), selected)})
    for phase in phases:
        tasks = _build_tasks(db, data_dir, run_id, config, tools, selected, projects, project_ids,
                             exes, versions, blocked, phase, explicit_timeout)
        log(f"Phase {phase + 1} : {len(tasks)} exécution(s)")  # affichée à partir de 1
        if progress:
            progress(0, len(tasks), phase + 1)
        _run_tasks(db, data_dir, run_id, tasks, jobs, root, log, progress, phase + 1)

    try:  # liens entre projets : une erreur ici ne doit jamais faire perdre un audit
        counts = compute_relations(db, run_id, config.tool("links").options.get("ignore_hosts") or ())
        if any(counts.values()):
            log("Liens entre projets : " + " · ".join(f"{k} {v}" for k, v in counts.items() if v))
    except Exception as exc:
        log(f"  ! calcul des liens en échec : {type(exc).__name__}: {exc}")

    try:  # recoupement : une même réalité vue par plusieurs détections = un seul constat à trier (jamais bloquant)
        correlate_run(db, data_dir, run_id, log=log)
    except Exception as exc:  # noqa: BLE001
        log(f"  ! recoupement en échec : {type(exc).__name__}: {exc} (relancez avec `aule correlate`)")

    if critiq if critiq is not None else config.critiq.enabled:
        try:  # avis consultatif d'un modèle d'IA : n'affecte jamais le statut de l'audit
            log("Phase 5 : critique IA des résultats")
            s = run_critique(db, data_dir, run_id, config.critiq, llm=config.llm, log=log, progress=progress)
            log("Critique IA : " + (", ".join(f"{k} {v}" for k, v in s["verdicts"].items()) or "rien à examiner")
                + f" ({s['cached']} en cache, {s['errors']} erreur(s))")
        except LLMError as exc:
            log(f"  ! critique IA impossible : {exc} (l'audit est intact ; relancez avec `aule critiq run`)")
        except Exception as exc:  # noqa: BLE001
            log(f"  ! critique IA en échec : {type(exc).__name__}: {exc} (l'audit est intact)")

    runs = db.list_tool_runs(run_id)
    bad = [r for r in runs if r["status"] not in ("ok", "skipped")]
    status = "complete" if not bad else "partial"
    db.set_audit_status(run_id, status, finished=True)
    log(f"Terminé : {status} ({len(runs) - len(bad)} ok/ignorées, {len(bad)} à examiner)")
    return run_id


def _build_tasks(db, data_dir, run_id, config, tools, selected, projects, project_ids, exes, versions,
                 blocked, phase, explicit_timeout) -> list[Task]:
    tasks: list[Task] = []
    for tool in tools:
        cfg = config.tool(tool.name)
        modes = [m for m in _modes(tool, cfg, selected) if tool.phase(m) == phase]
        if not modes:
            continue
        timeout = resolve_timeout(tool, cfg, explicit_timeout)
        for project in projects:
            pid = project_ids[project.name]
            ctx = RunContext(data_dir, run_id, cfg, exes[tool.name] or [], timeout)
            if tool.quiet_skip:
                db.delete_tool_run(run_id, pid, tool.name, PLACEHOLDER_MODE)  # ligne d'une exécution précédente
            marks = [PLACEHOLDER_MODE] if tool.quiet_skip else modes  # lignes « ignoré/indisponible »
            if exes[tool.name] is None:
                for m in marks:
                    db.save_tool_run(run_id, pid, tool.name, m, status="unavailable",
                                     error=f"'{tool.wanted(cfg)}' introuvable (PATH ou aule.yaml)")
                continue
            if tool.name in blocked:
                for m in marks:
                    db.save_tool_run(run_id, pid, tool.name, m, status="unavailable", error=blocked[tool.name])
                continue
            todo = []
            for mode in modes:
                if tool.applicable(project, mode, ctx):
                    todo.append(mode)
                elif not tool.quiet_skip:
                    db.save_tool_run(run_id, pid, tool.name, mode, status="skipped",
                                     error=tool.reason(project, mode, ctx))
            if tool.quiet_skip and not todo:
                db.save_tool_run(run_id, pid, tool.name, PLACEHOLDER_MODE, status="skipped",
                                 error=tool.reason(project, modes[0], ctx))
            for mode in todo:
                existing = db.get_tool_run(run_id, pid, tool.name, mode)
                if existing and existing["status"] == "ok":
                    continue  # déjà fait : reprise
                raw_rel = Path("runs") / run_id / project.name / tool.name / mode
                tasks.append(Task(tool, project, pid, mode, raw_rel, ctx, timeout, versions.get(tool.name)))
    return tasks


def _run_tasks(db: Database, data_dir: Path, run_id: str, tasks: list[Task], jobs: int, root: Path, log: Log,
               progress: Callable[[int, int, int], None] | None = None, phase_no: int = 1) -> None:
    gates = {t.tool.name: threading.Semaphore(t.ctx.cfg.max_parallel or t.tool.max_parallel)
             for t in tasks if t.ctx.cfg.max_parallel or t.tool.max_parallel}

    def run_one(t: Task) -> TaskResult:
        gate = gates.get(t.tool.name)  # ex. base de vulnérabilités partagée : une exécution à la fois
        if gate is None:
            return execute(t.tool, t.project, t.mode, data_dir / t.raw_rel, t.timeout, t.version, t.ctx)
        with gate:
            return execute(t.tool, t.project, t.mode, data_dir / t.raw_rel, t.timeout, t.version, t.ctx)

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = {pool.submit(run_one, t): t for t in tasks}
        done = 0
        try:
            for fut in as_completed(futures):
                task = futures[fut]
                try:
                    result = fut.result()
                except Exception as exc:  # l'échec d'un outil ne bloque pas le reste
                    result = TaskResult("failed", None, 0.0, "", "", error=repr(exc))
                done += 1
                _record(db, data_dir, run_id, task, result, log, f"({done}/{len(tasks)}) ")
                if progress:
                    progress(done, len(tasks), phase_no)
        except KeyboardInterrupt:
            pool.shutdown(wait=False, cancel_futures=True)
            db.set_audit_status(run_id, "interrupted")
            log(f"Interrompu. Reprise : aule run {root} --resume {run_id}")
            raise


def _record(db: Database, data_dir: Path, run_id: str, task: Task, result: TaskResult, log: Log, counter: str = "") -> None:
    status, error, entities = result.status, result.error, []
    if status == "ok":
        try:
            entities = task.tool.parse(task.project, task.mode,
                                       data_dir / task.raw_rel / task.tool.report_filename, task.ctx)
        except Exception as exc:  # sortie brute conservée : re-parsable avec `aule reparse`
            status, error = "parse_error", f"{type(exc).__name__}: {exc}"
    db.save_tool_run(
        run_id, task.project_id, task.tool.name, task.mode, status=status,
        exit_code=result.exit_code, duration_s=result.duration_s, tool_version=result.tool_version,
        command=result.command, raw_dir=str(task.raw_rel), report_sha256=result.report_sha256,
        started_at=result.started_at, error=error, entities=entities,
    )
    detail = f"{len(entities)} élément(s)" if status == "ok" else error
    log(f"  {counter}[{status}] {task.project.name} · {task.tool.name}/{task.mode} ({result.duration_s}s) {detail}")


def reparse(db: Database, data_dir: Path, run_id: str, config: Config | None = None, log: Log = print) -> None:
    """Rejoue les parseurs sur les sorties brutes déjà stockées (sans relancer les outils)."""
    config = config or Config()
    if not db.get_audit(run_id):
        raise AuditError(f"run inconnu : {run_id}")
    registry = load_plugins()
    projects = {p["id"]: p for p in db.list_projects(run_id)}
    for tr in db.list_tool_runs(run_id):
        tool = registry.get(tr["tool"])
        if tr["status"] not in ("ok", "parse_error") or tool is None:
            continue
        p = projects[tr["project_id"]]
        project = Project(p["name"], Path(p["path"]), bool(p["is_git"]), p["head_commit"], p["parent"], p["origin"])
        ctx = RunContext(data_dir, run_id, config.tool(tool.name), [])
        try:
            entities = tool.parse(project, tr["mode"], data_dir / tr["raw_dir"] / tool.report_filename, ctx)
            status, error = "ok", None
        except Exception as exc:
            entities, status, error = [], "parse_error", f"{type(exc).__name__}: {exc}"
        db.replace_entities(tr["id"], run_id, tr["project_id"], entities, status, error)
        log(f"  [{status}] {p['name']} · {tr['tool']}/{tr['mode']} : {len(entities)} élément(s)")
    correlate_run(db, data_dir, run_id, log=log)  # les détections ont changé : les groupes aussi
