"""Exécution d'une commande d'outil et conservation des sorties brutes.

Layout : <data>/runs/<run_id>/<projet>/<outil>/<mode>/
    cmd.txt  stdout.txt  stderr.txt  report.json  meta.json
Avec `default_pass`, la passe « rules » a son propre sous-dossier (<mode>/rules/ : cmd.txt, stdout.txt, stderr.txt, rapport) ; meta.json liste les passes.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path

from .db import now_iso
from .models import ParsedEntity, Project
from .plugins.base import RunContext, Tool


@dataclass
class TaskResult:
    status: str  # ok | failed | timeout
    exit_code: int | None
    duration_s: float
    command: str
    started_at: str
    error: str | None = None
    report_sha256: str | None = None
    tool_version: str | None = None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_version(tool: Tool, exe: list[str], env: dict[str, str] | None = None) -> str | None:
    cmd = tool.version_command(exe)
    if cmd is None:
        return None
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15, env={**os.environ, **env} if env else None)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return tool.parse_version((p.stdout or p.stderr).strip(), p.returncode)


def _redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


def _last_line(raw: bytes) -> str:
    lines = raw.decode("utf-8", "replace").strip().splitlines()
    return lines[-1][:300] if lines else ""


@dataclass
class _Pass:
    """Résultat d'UNE passe d'une tâche (voir Tool.passes)."""

    name: str
    report: Path
    status: str
    exit_code: int | None
    error: str | None
    command: str
    duration: float
    started: str


def _run_pass(tool: Tool, project: Project, mode: str, pass_dir: Path, timeout: int, ctx: RunContext, name: str) -> _Pass:
    pass_dir.mkdir(parents=True, exist_ok=True)
    report = pass_dir / tool.report_filename
    report.unlink(missing_ok=True)
    cmd = tool.build_command(project, mode, report, ctx)
    secrets = [v for v in tool.sensitive_values(ctx) if v]
    command = _redact(shlex.join(cmd), secrets)  # jamais de clé d'API dans cmd.txt, meta.json ou la base
    (pass_dir / "cmd.txt").write_text(command + "\n", encoding="utf-8")

    cwd = tool.cwd(project, mode, ctx)
    started, t0 = now_iso(), time.monotonic()
    status, exit_code, error = "ok", None, None
    stdout = stderr = b""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                              cwd=cwd,
                              env={**os.environ, **ctx.cfg.env} if ctx.cfg.env else None)
        exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        if exit_code not in tool.ok_exit_codes:
            status, error = "failed", f"code retour {exit_code}"
    except subprocess.TimeoutExpired as exc:
        status, error = "timeout", f"délai de {timeout}s dépassé"
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
    except OSError as exc:
        status, error = "failed", str(exc)

    redacted = [x.encode() for x in secrets]
    def clean(raw: bytes) -> bytes:
        for secret in redacted:
            raw = raw.replace(secret, b"***")
        return raw
    (pass_dir / "stdout.txt").write_bytes(clean(stdout))
    (pass_dir / "stderr.txt").write_bytes(clean(stderr))
    if status == "ok" and tool.capture_stdout:
        report.write_bytes(stdout)
    if status == "ok" and (problem := tool.check_result(exit_code, report)):
        status, error = "failed", problem
    if status == "ok":
        try:
            tool.post_run(project, mode, pass_dir, report, ctx)
        except Exception as exc:
            status, error = "failed", f"post-traitement : {_redact(str(exc), secrets)}"
    if status == "ok" and not report.exists() and not tool.report_optional:
        status, error = "failed", "rapport absent"
    if status == "failed" and exit_code is not None and (tail := _last_line(stderr)):
        error = f"{error} : {_redact(tail, secrets)}"
    if status == "failed" and error and (hint := tool.failure_hint(error)):
        error = f"{error} — {hint}"
    return _Pass(name, report, status, exit_code, error, command, round(time.monotonic() - t0, 2), started)


def _digest(reports: list[tuple[str | None, Path]]) -> str | None:
    """Empreinte des rapports d'une tâche : celle du fichier pour une passe, sinon l'empreinte des empreintes (nom de passe compris). None si l'un manque."""
    if any(not path.exists() for _, path in reports):
        return None
    if len(reports) == 1:
        return sha256_file(reports[0][1])
    h = hashlib.sha256()
    for name, path in reports:
        h.update(f"{name}:{sha256_file(path)}\n".encode())
    return h.hexdigest()


def pass_reports(raw_dir: Path, tool: Tool) -> list[tuple[str | None, Path]]:
    """[(nom de passe, rapport)] d'une tâche déjà exécutée : un seul rapport (nom None), ou ceux de meta.json quand la tâche avait plusieurs passes (default_pass)."""
    try:
        passes = json.loads((raw_dir / "meta.json").read_text(encoding="utf-8")).get("passes") or []
    except (OSError, ValueError):
        passes = []
    if len(passes) > 1:
        return [(p["name"], raw_dir / p["report"]) for p in passes]
    return [(None, raw_dir / tool.report_filename)]


def report_digest(raw_dir: Path, tool: Tool) -> str | None:
    return _digest(pass_reports(raw_dir, tool))


def raw_ref(data: dict) -> int | str | None:
    """Référence d'un constat dans son rapport brut : `raw_index` pour le rapport principal, `<rapport>:<indice>` pour celui d'une passe supplémentaire."""
    index = data.get("raw_index")
    return index if not data.get("report") or index is None else f"{data['report']}:{index}"


def clear_values_of(tool: Tool, raw_dir: Path) -> dict[int | str, tuple[str, str]]:
    """Valeurs en clair de TOUS les rapports d'une tâche, indexées comme `raw_ref`."""
    out: dict[int | str, tuple[str, str]] = {}
    for _, path in pass_reports(raw_dir, tool):
        main = path.parent == raw_dir
        for index, value in (tool.clear_values(path) or {}).items():
            out[index if main else f"{path.relative_to(raw_dir).as_posix()}:{index}"] = value
    return out


def parse_task(tool: Tool, project: Project, mode: str, raw_dir: Path, ctx: RunContext) -> list[ParsedEntity]:
    """Constats d'une tâche. Avec plusieurs passes, chaque rapport est analysé par le parseur de l'OUTIL (rien de propre à un format) puis les constats sont fusionnés par
    empreinte : celui que deux passes trouvent n'est compté qu'une fois. `config_pass` dit qui l'a trouvé (default, rules, default+rules) ; `report` dit où le relire."""
    reports = pass_reports(raw_dir, tool)
    if len(reports) == 1:
        return tool.parse(project, mode, reports[0][1], ctx)
    merged: dict[tuple[str, str], ParsedEntity] = {}
    order: list[ParsedEntity] = []
    for name, path in reports:
        for entity in tool.parse(project, mode, path, ctx):
            twin = merged.get((entity.kind, entity.fingerprint))
            if twin is not None:
                if name not in twin.data["config_pass"].split("+"):
                    twin.data["config_pass"] += f"+{name}"
                continue
            entity.data["config_pass"] = name
            if path.parent != raw_dir:
                entity.data["report"] = path.relative_to(raw_dir).as_posix()
            merged[(entity.kind, entity.fingerprint)] = entity
            order.append(entity)
    return order


def execute(tool: Tool, project: Project, mode: str, raw_dir: Path, timeout: int,
            version: str | None, ctx: RunContext) -> TaskResult:
    raw_dir.mkdir(parents=True, exist_ok=True)
    plan = tool.passes(ctx.cfg)
    done: list[_Pass] = []
    for index, (name, cfg) in enumerate(plan):
        result = _run_pass(tool, project, mode, raw_dir if index == 0 else raw_dir / name, timeout, replace(ctx, cfg=cfg), name)
        done.append(result)
        if result.status != "ok":
            break  # une passe en échec : les suivantes ne servent à rien, et le résultat ne serait pas complet
    bad = next((p for p in done if p.status != "ok"), None)
    last = bad or done[-1]
    status, exit_code, error = last.status, last.exit_code, last.error
    if bad is not None and len(plan) > 1 and error:
        error = f"passe « {bad.name} » : {error}"
    reports = [(p.name, p.report) for p in done]
    sha = _digest(reports if len(plan) > 1 and bad is None else reports[:1])
    duration = round(sum(p.duration for p in done), 2)
    cwd = tool.cwd(project, mode, ctx)
    meta = {
        "tool": tool.name, "mode": mode, "tool_version": version, "command": done[0].command, "cwd": str(cwd) if cwd else None,
        "status": status, "exit_code": exit_code, "duration_s": duration, "started_at": done[0].started,
        "report_sha256": sha, "error": error,
        "project": project.name, "project_path": str(project.path), "git_commit": project.head_commit,
        "parent_project": project.parent, "origin_archive": project.origin,
    }
    if len(plan) > 1:
        meta["passes"] = [{"name": p.name, "report": p.report.relative_to(raw_dir).as_posix(), "command": p.command, "status": p.status, "exit_code": p.exit_code,
                           "duration_s": p.duration} for p in done]
    (raw_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return TaskResult(status, exit_code, duration, done[0].command, done[0].started, error, sha, version)
