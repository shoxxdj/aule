"""Exécution d'une commande d'outil et conservation des sorties brutes.

Layout : <data>/runs/<run_id>/<projet>/<outil>/<mode>/
    cmd.txt  stdout.txt  stderr.txt  report.json  meta.json
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .db import now_iso
from .models import Project
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


def execute(tool: Tool, project: Project, mode: str, raw_dir: Path, timeout: int,
            version: str | None, ctx: RunContext) -> TaskResult:
    raw_dir.mkdir(parents=True, exist_ok=True)
    report = raw_dir / tool.report_filename
    report.unlink(missing_ok=True)
    cmd = tool.build_command(project, mode, report, ctx)
    secrets = [v for v in tool.sensitive_values(ctx) if v]
    command = _redact(shlex.join(cmd), secrets)  # jamais de clé d'API dans cmd.txt, meta.json ou la base
    (raw_dir / "cmd.txt").write_text(command + "\n", encoding="utf-8")

    started, t0 = now_iso(), time.monotonic()
    status, exit_code, error = "ok", None, None
    stdout = stderr = b""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                              cwd=tool.cwd(project, mode, ctx),
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
    (raw_dir / "stdout.txt").write_bytes(clean(stdout))
    (raw_dir / "stderr.txt").write_bytes(clean(stderr))
    if status == "ok" and tool.capture_stdout:
        report.write_bytes(stdout)
    if status == "ok" and (problem := tool.check_result(exit_code, report)):
        status, error = "failed", problem
    if status == "ok":
        try:
            tool.post_run(project, mode, raw_dir, report, ctx)
        except Exception as exc:
            status, error = "failed", f"post-traitement : {_redact(str(exc), secrets)}"
    if status == "ok" and not report.exists() and not tool.report_optional:
        status, error = "failed", "rapport absent"
    if status == "failed" and exit_code is not None and (tail := _last_line(stderr)):
        error = f"{error} : {_redact(tail, secrets)}"
    if status == "failed" and error and (hint := tool.failure_hint(error)):
        error = f"{error} — {hint}"
    duration = round(time.monotonic() - t0, 2)

    sha = sha256_file(report) if report.exists() else None
    (raw_dir / "meta.json").write_text(json.dumps({
        "tool": tool.name, "mode": mode, "tool_version": version, "command": command,
        "status": status, "exit_code": exit_code, "duration_s": duration, "started_at": started,
        "report_sha256": sha, "error": error,
        "project": project.name, "project_path": str(project.path), "git_commit": project.head_commit,
        "parent_project": project.parent, "origin_archive": project.origin,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return TaskResult(status, exit_code, duration, command, started, error, sha, version)
