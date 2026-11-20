"""Serveur local de travail de l'auditeur : le rapport devient interactif (triage, constats, notes, lancement d'audit).

Bibliothèque standard uniquement (http.server) : aucune dépendance, testé de bout en bout. L'API est du JSON simple,
facile à porter vers FastAPI plus tard.

Sécurité (le serveur sert des secrets en clair) :
  - écoute UNIQUEMENT sur la boucle locale ; accès distant : tunnel SSH (`ssh -L`) + `--allowed-host`
  - en-tête Host contrôlé (contre le DNS rebinding) ; jeton aléatoire exigé sur toute l'API ; Origin et
    Content-Type contrôlés sur les écritures (contre le CSRF) ; fichiers bruts servis uniquement sous runs/
  - `--mask` : les secrets ne quittent jamais le serveur sauf demande explicite d'une valeur (« révéler »)
"""
from __future__ import annotations

import dataclasses
import hmac
import ipaddress
import json
import re
import secrets
import socket
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

from .codeview import CodeError, Source, find_in_file, list_dir, list_files, read_lines, search_project
from .config import CRITIQ_KINDS, Config
from .critiq import Redactor
from .db import FINDING_STATUSES, SEVERITIES, TRIAGE_STATUSES, Database
from .diff import diff_runs
from .export import FORMATS, ExportError, collect, write_export
from .critiq import run_critique
from .llm import LLMError, public_url
from .orchestrator import AuditError, run_audit
from .plugins import load_plugins, select_tools
from .rawview import CACHE, import_sarif, json_node, json_rows, list_tree, read_text, sarif_files, sarif_results, sarif_rules, sarif_summary
from .report import build_report_data, load_clear_secrets, render_report, reveal_one
from .runs import RunRefError, resolve_run, validate_label

MAX_BODY = 5 * 1024 * 1024
MAX_RAW = 5 * 1024 * 1024
BIG_BODY = {"/api/sarif/import": 64 * 1024 * 1024}  # un SARIF de CI dépasse souvent 5 Mo
MIME = {"csv": "text/csv; charset=utf-8", "md": "text/markdown; charset=utf-8", "json": "application/json",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
PAGE_CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class JobBusy(Exception):
    pass


class JobManager:
    """Un audit à la fois, dans un thread, avec journal et progression consultables."""

    def __init__(self, db_path: Path, data_dir: Path, config: Config):
        self.db_path, self.data_dir, self.config = db_path, data_dir, config
        self.lock = threading.Lock()
        self.state: dict[str, Any] = {"state": "idle", "run_id": None, "done": 0, "total": 0, "phase": 0, "error": None, "log": []}
        self.thread: threading.Thread | None = None

    def _begin(self, run_id: str | None = None) -> None:
        with self.lock:
            if self.state["state"] == "running":
                raise JobBusy()
            self.state = {"state": "running", "run_id": run_id, "done": 0, "total": 0, "phase": 0, "error": None, "log": [], "started": time.time()}

    def start(self, root: Path, tool_names: list[str] | None, unpack: bool | None, exclude: tuple[str, ...], critiq: bool | None = None,
              label: str | None = None) -> None:
        self._begin()
        self.thread = threading.Thread(target=self._work, args=(root, tool_names, unpack, exclude, critiq, label), daemon=True)
        self.thread.start()

    def start_critique(self, run_id: str, kinds: tuple[str, ...] | None, force: bool, more_code: bool | None = None) -> None:
        self._begin(run_id)
        self.thread = threading.Thread(target=self._work_critique, args=(run_id, kinds, force, more_code), daemon=True)
        self.thread.start()

    def _work_critique(self, run_id: str, kinds, force: bool, more_code: bool | None = None) -> None:
        db = Database(self.db_path)
        cfg = self.config.critiq if more_code is None else dataclasses.replace(self.config.critiq, allow_more_code=more_code)
        llm = self.config.llm  # la case à cocher de l'interface l'emporte sur le fichier
        try:
            run_critique(db, self.data_dir, run_id, cfg, llm=llm, kinds=kinds, force=force, log=self._log, progress=self._progress)
            with self.lock:
                self.state.update(state="finished", run_id=run_id)
        except (LLMError, KeyError) as exc:
            with self.lock:
                self.state.update(state="error", error=str(exc.args[0] if isinstance(exc, KeyError) else exc))
        except Exception as exc:  # noqa: BLE001
            with self.lock:
                self.state.update(state="error", error=f"{type(exc).__name__}: {exc}")
        finally:
            db.close()

    def _log(self, line: str) -> None:
        with self.lock:
            self.state["log"].append(line)
            if (m := re.match(r"^Run (\S+) —", line)):
                self.state["run_id"] = m.group(1)

    def _progress(self, done: int, total: int, phase: int) -> None:
        with self.lock:
            self.state.update(done=done, total=total, phase=phase)

    def _work(self, root: Path, tool_names, unpack, exclude, critiq=None, label=None) -> None:
        db = Database(self.db_path)
        try:
            run_id = run_audit(db, self.data_dir, root, config=self.config, tool_names=tool_names, unpack=unpack,
                               exclude=exclude, critiq=critiq, label=label, log=self._log, progress=self._progress)
            with self.lock:
                self.state.update(state="finished", run_id=run_id)
        except Exception as exc:  # noqa: BLE001 — remonté à l'interface
            with self.lock:
                self.state.update(state="error", error=f"{type(exc).__name__}: {exc}")
        finally:
            db.close()

    def snapshot(self, since: int = 0) -> dict[str, Any]:
        with self.lock:
            s = {k: v for k, v in self.state.items() if k not in ("log", "started")}
            s["log"], s["next"] = self.state["log"][since:], len(self.state["log"])
            return s


class AuditServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], db_path: Path, data_dir: Path, config: Config, *, reveal: bool,
                 allowed_hosts: tuple[str, ...] = ()):
        super().__init__(address, Handler)
        self.db_path, self.data_dir, self.config, self.reveal = db_path, data_dir, config, reveal
        self.token = secrets.token_urlsafe(32)
        port = self.server_address[1]
        self.allowed_hosts = {f"{h}:{port}" for h in ("127.0.0.1", "localhost", "[::1]")} | set(allowed_hosts)
        self.jobs = JobManager(db_path, data_dir, config)
        self._lock, self._secrets = threading.Lock(), {}

    def redactor(self, db: Database, run_id: str, project: str) -> Redactor:
        """Secrets connus du projet (valeurs en clair relues, vérifiées) : sert à masquer le code en mode --mask. Mis en cache par run."""
        with self._lock:
            if run_id not in self._secrets:
                clear, _ = load_clear_secrets(db, run_id, self.data_dir)
                by_project: dict[str, list[str]] = {}
                for (proj, _tool, _mode), values in clear.items():
                    by_project.setdefault(proj, []).extend(v[0] for v in values.values() if v[0])
                self._secrets[run_id] = by_project
            return Redactor(self._secrets[run_id].get(project, []))

    def live_options(self, db: Database) -> dict[str, Any]:
        registry = load_plugins()
        enabled = {t.name for t in select_tools(self.config)}
        llm = self.config.llm
        return {"live": True, "token": self.token, "critiq": {"model": llm.model if llm else None, "more_code": self.config.critiq.allow_more_code, "base_url": public_url(llm.url) if llm else "", "provider": llm.provider if llm else None,
                                                              "enabled": self.config.critiq.enabled},
                "audits": [{k: a[k] for k in ("id", "label", "status", "root", "started_at")} for a in db.list_audits()],
                "tools": [{"name": t.name, "enabled": t.name in enabled, "available": t.resolve(self.config.tool(t.name)) is not None,
                           "modes": list(t.modes)} for t in registry.values()]}

    def payload(self, db: Database, run_id: str) -> dict[str, Any]:
        return build_report_data(db, run_id, self.data_dir, self.reveal, extra_options=self.live_options(db))


def make_server(db_path: Path, data_dir: Path, config: Config, *, host: str = "127.0.0.1", port: int = 8765,
                reveal: bool = True, allowed_hosts: tuple[str, ...] = ()) -> AuditServer:
    try:
        loopback = all(ipaddress.ip_address(a[4][0]).is_loopback for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
    except (OSError, ValueError):
        loopback = False
    if not loopback:
        raise ValueError(f"{host!r} n'est pas une adresse locale : le serveur sert des secrets en clair et n'écoute que sur la "
                         "boucle locale. Accès distant : ssh -L <port>:127.0.0.1:<port> serveur, puis --allowed-host localhost:<port>.")
    return AuditServer((host, port), db_path, data_dir, config, reveal=reveal, allowed_hosts=allowed_hosts)


class Handler(BaseHTTPRequestHandler):
    server: AuditServer
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # silencieux : pas de bruit dans le terminal de l'auditeur
        pass

    # ------------------------------------------------------------------ plomberie
    def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for k, v in {"Content-Type": ctype, "Content-Length": str(len(body)), "Cache-Control": "no-store",
                     "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                     **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: Any) -> None:
        extra = None
        if status >= 400:  # le corps de la requête a pu ne pas être lu : on ne réutilise pas la connexion (désynchronisation)
            self.close_connection = True
            extra = {"Connection": "close"}
        self._send(status, json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"), "application/json; charset=utf-8", extra)

    def _body(self, limit: int = MAX_BODY) -> dict[str, Any]:
        if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
            raise ApiError(415, "Content-Type application/json requis")
        length = int(self.headers.get("Content-Length") or 0)
        if length > limit:
            raise ApiError(413, "corps de requête trop volumineux")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError as exc:
            raise ApiError(400, f"JSON invalide : {exc}") from exc
        if not isinstance(data, dict):
            raise ApiError(400, "objet JSON attendu")
        return data

    def _guard(self, mutating: bool, api: bool) -> None:
        if (self.headers.get("Host") or "") not in self.server.allowed_hosts:   # DNS rebinding
            raise ApiError(421, "Host non autorisé (voir --allowed-host)")
        if not api:
            return
        if not hmac.compare_digest(self.headers.get("X-Audit-Token") or "", self.server.token):
            raise ApiError(403, "jeton manquant ou invalide : rechargez la page")
        origin = self.headers.get("Origin")
        if mutating and origin and origin != f"http://{self.headers.get('Host')}":   # CSRF
            raise ApiError(403, "Origin non autorisée")

    def _dispatch(self, method: str) -> None:
        db = None
        try:
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            api = url.path.startswith("/api/")
            self._guard(method != "GET", api)
            if method == "GET" and url.path == "/":
                db = Database(self.server.db_path)
                return self._page(db, q)
            if not api:
                raise ApiError(404, "introuvable")
            body = self._body(BIG_BODY.get(url.path, MAX_BODY)) if method in ("POST", "PUT") else {}
            for m, pattern, fn in ROUTES:
                if m == method and (match := re.fullmatch(pattern, url.path)):
                    db = Database(self.server.db_path)
                    result = fn(self, db, q, body, *[unquote(g) for g in match.groups()])
                    if isinstance(result, tuple) and isinstance(result[0], bytes):   # fichier
                        return self._send(200, result[0], result[1], result[2] if len(result) > 2 else None)
                    return self._json(*(result if isinstance(result, tuple) else (200, result)))
            raise ApiError(404, "route inconnue")
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
        finally:
            if db:
                db.close()

    do_GET = lambda self: self._dispatch("GET")  # noqa: E731
    do_POST = lambda self: self._dispatch("POST")  # noqa: E731
    do_PUT = lambda self: self._dispatch("PUT")  # noqa: E731
    do_DELETE = lambda self: self._dispatch("DELETE")  # noqa: E731

    # ------------------------------------------------------------------ page
    def _run(self, db: Database, q: dict) -> str:
        try:
            run_id = resolve_run(db, q.get("run") or None)
        except RunRefError as exc:
            raise ApiError(404, str(exc)) from exc
        if not run_id:
            raise ApiError(404, "aucun audit : lancez-en un depuis l'onglet Audit ou `aule run`")
        return run_id

    def _page(self, db: Database, q: dict) -> None:
        if not db.latest_audit_id():  # premier lancement : rien à afficher, mais l'onglet Audit doit rester utilisable
            raise ApiError(404, "aucun audit : lancez `aule run <dossier>` d'abord, puis rechargez cette page")
        html = render_report(db, self._run(db, q), self.server.data_dir, self.server.reveal,
                             extra_options=self.server.live_options(db))
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8", {"Content-Security-Policy": PAGE_CSP})


# ---------------------------------------------------------------------------------- API
def _strs(body: dict, key: str, limit: int = 100_000) -> list[str]:
    v = body.get(key)
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v) or len(v) > limit:
        raise ApiError(400, f"« {key} » : liste de chaînes attendue (max {limit})")
    return v


def _text(body: dict, key: str, limit: int, required: bool = False) -> str | None:
    v = body.get(key)
    if v is None and not required:
        return None
    if not isinstance(v, str) or len(v) > limit:
        raise ApiError(400, f"« {key} » : texte attendu (max {limit} caractères)")
    return v


def api_runs(h: Handler, db: Database, q: dict, body: dict):
    return {"runs": db.list_audits()}


def api_data(h: Handler, db: Database, q: dict, body: dict):
    return h.server.payload(db, h._run(db, q))


def api_triage(h: Handler, db: Database, q: dict, body: dict):
    status = body.get("status")
    if status not in TRIAGE_STATUSES:
        raise ApiError(400, f"statut inconnu : {status!r} (attendu : {', '.join(TRIAGE_STATUSES)})")
    comment = _text(body, "comment", 2000)
    return {"updated": db.set_triage_many(_strs(body, "fingerprints"), status, comment or None)}


def api_triage_clear(h: Handler, db: Database, q: dict, body: dict):
    return {"cleared": db.clear_triage(_strs(body, "fingerprints"))}


def _finding_fields(body: dict, partial: bool) -> dict[str, Any]:
    f: dict[str, Any] = {}
    for key, limit in (("project", 300), ("title", 500), ("description", 200_000)):
        if (v := _text(body, key, limit, required=not partial and key != "description")) is not None:
            f[key] = v
    for key, allowed in (("severity", SEVERITIES), ("status", FINDING_STATUSES)):
        if key in body:
            if body[key] not in allowed:
                raise ApiError(400, f"{key} inconnu : {body[key]!r}")
            f[key] = body[key]
    if "refs" in body:
        f["refs"] = _strs(body, "refs", 500)
    return f


def api_finding_create(h: Handler, db: Database, q: dict, body: dict):
    try:
        return 201, db.get_finding(db.add_finding(**{"severity": "medium", "status": "draft", **_finding_fields(body, False)}))
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc


def api_finding_update(h: Handler, db: Database, q: dict, body: dict, fid: str):
    if not fid.isdigit() or not db.get_finding(int(fid)):
        raise ApiError(404, f"constat inconnu : {fid}")
    try:
        db.update_finding(int(fid), **_finding_fields(body, True))
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc
    return db.get_finding(int(fid))


def api_finding_delete(h: Handler, db: Database, q: dict, body: dict, fid: str):
    if not fid.isdigit() or not db.delete_finding(int(fid)):
        raise ApiError(404, f"constat inconnu : {fid}")
    return {"deleted": int(fid)}


def api_note(h: Handler, db: Database, q: dict, body: dict, project: str):
    db.set_note(project, _text(body, "text", 100_000, required=True) or "")
    return {"project": project}


def api_diff(h: Handler, db: Database, q: dict, body: dict):
    try:
        return diff_runs(db, h._run(db, {"run": q.get("a", "")}) if q.get("a") else "", h._run(db, {"run": q.get("b")}))
    except KeyError as exc:
        raise ApiError(404, f"run inconnu : {exc.args[0]}") from exc


def api_secret(h: Handler, db: Database, q: dict, body: dict):
    try:
        return reveal_one(db, h._run(db, q), h.server.data_dir, q.get("fingerprint", ""))
    except LookupError as exc:
        raise ApiError(404, str(exc)) from exc
    except ValueError as exc:
        raise ApiError(409, str(exc)) from exc


def _raw_file(h: Handler, q: dict) -> Path:
    """Fichier brut demandé : sous runs/ uniquement, jamais en mode --mask (les sorties brutes contiennent les secrets en clair)."""
    if not h.server.reveal:
        raise ApiError(403, "mode --mask : les sorties brutes (qui contiennent les secrets en clair) ne sont pas servies")
    roots = [(h.server.data_dir / "runs").resolve(), (h.server.data_dir / "imports").resolve()]
    target = (h.server.data_dir / q.get("path", "")).resolve()
    if not any(target.is_relative_to(r) for r in roots):
        raise ApiError(403, "seules les sorties brutes (runs/) et les SARIF importés (imports/) sont accessibles")
    if not target.is_file():
        raise ApiError(404, "fichier introuvable")
    return target


def api_raw(h: Handler, db: Database, q: dict, body: dict):
    target = _raw_file(h, q)
    if target.stat().st_size > MAX_RAW:
        raise ApiError(413, f"fichier trop volumineux (> {MAX_RAW // 1024 // 1024} Mo) : utilisez la lecture par pages")
    return target.read_bytes(), "text/plain; charset=utf-8", {"Content-Disposition": "inline"}


def _int(q: dict, key: str, default: int, lo: int = 0, hi: int = 10**9) -> int:
    try:
        return min(hi, max(lo, int(q.get(key, default))))
    except (TypeError, ValueError):
        raise ApiError(400, f"« {key} » : entier attendu") from None


def _doc(h: Handler, q: dict):
    path = _raw_file(h, q)
    try:
        return CACHE.get(path)
    except ValueError as exc:
        raise ApiError(413 if "volumineux" in str(exc) else 400, str(exc)) from exc


def api_raw_tree(h: Handler, db: Database, q: dict, body: dict):
    if not h.server.reveal:
        raise ApiError(403, "mode --mask : les sorties brutes (qui contiennent les secrets en clair) ne sont pas servies")
    run_id = h._run(db, q)
    return {"run": run_id, "entries": list_tree(db, h.server.data_dir, run_id)}


def api_raw_text(h: Handler, db: Database, q: dict, body: dict):
    return read_text(_raw_file(h, q), _int(q, "offset", 0), _int(q, "limit", 200_000, 1, 1024 * 1024))


def api_raw_json(h: Handler, db: Database, q: dict, body: dict):
    doc, _ = _doc(h, q)
    try:
        return json_node(doc, q.get("pointer", ""), _int(q, "offset", 0), _int(q, "limit", 100, 1, 500))
    except KeyError as exc:
        raise ApiError(404, str(exc.args[0])) from exc


def api_raw_rows(h: Handler, db: Database, q: dict, body: dict):
    doc, _ = _doc(h, q)
    try:
        return json_rows(doc, q.get("pointer", ""), _int(q, "offset", 0), _int(q, "limit", 50, 1, 200), q.get("q") or None)
    except KeyError as exc:
        raise ApiError(404, str(exc.args[0])) from exc
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc


def _sarif(h: Handler, q: dict):
    doc, memo = _doc(h, q)
    if not (isinstance(doc, dict) and isinstance(doc.get("runs"), list)):
        raise ApiError(400, "ce fichier n'est pas un SARIF (clé « runs » absente)")
    return doc, memo


def api_sarif_summary(h: Handler, db: Database, q: dict, body: dict):
    doc, memo = _sarif(h, q)
    return sarif_summary(doc, memo)


def api_sarif_rules(h: Handler, db: Database, q: dict, body: dict):
    doc, _ = _sarif(h, q)
    try:
        return {"rules": sarif_rules(doc, _int(q, "run", 0))}
    except KeyError as exc:
        raise ApiError(404, str(exc.args[0])) from exc


def api_sarif_results(h: Handler, db: Database, q: dict, body: dict):
    doc, _ = _sarif(h, q)
    try:
        return sarif_results(doc, _int(q, "run", 0), _int(q, "offset", 0), _int(q, "limit", 25, 1, 100), rule=q.get("rule") or None,
                             level=q.get("level") or None, q=q.get("q") or None, file=q.get("file") or None,
                             line=_int(q, "line", 0) if q.get("line") else None, index=_int(q, "index", 0) if q.get("index") not in (None, "") else None)
    except KeyError as exc:
        raise ApiError(404, str(exc.args[0])) from exc


def _source(h: Handler, db: Database, q: dict) -> Source:
    run_id = h._run(db, q)
    name = q.get("project", "")
    proj = next((p for p in db.list_projects(run_id) if p["name"] == name), None)
    if proj is None:
        raise ApiError(404, f"projet inconnu dans ce run : {name!r}")
    root = Path(proj["path"])
    if not root.is_dir():
        raise ApiError(404, "répertoire du projet introuvable (supprimé par `aule purge --heavy` ou déplacé ?)")
    mask = not h.server.reveal
    return Source(root, is_git=bool(proj["is_git"]), mask=mask, redact=h.server.redactor(db, run_id, name) if mask else Redactor(),
                  deny=tuple(h.server.config.critiq.deny_globs))


def _code(fn):
    def wrapper(h: Handler, db: Database, q: dict, body: dict):
        try:
            return fn(h, db, q, _source(h, db, q))
        except CodeError as exc:
            raise ApiError(exc.status, exc.message) from exc
    return wrapper


@_code
def api_code_tree(h: Handler, db: Database, q: dict, src: Source):
    return list_dir(src, q.get("path", ""))


@_code
def api_code_file(h: Handler, db: Database, q: dict, src: Source):
    around = _int(q, "around", 0) if q.get("around") else None
    return read_lines(src, q.get("path", ""), start=_int(q, "start", 1, 1) if q.get("start") else None, end=_int(q, "end", 0, 1) if q.get("end") else None,
                      around=around, window=_int(q, "window", 400, 1, 2000), ref=q.get("ref") or None)


@_code
def api_code_find(h: Handler, db: Database, q: dict, src: Source):
    return find_in_file(src, q.get("path", ""), q.get("q", ""), case=q.get("case") == "1", ref=q.get("ref") or None)


@_code
def api_code_search(h: Handler, db: Database, q: dict, src: Source):
    return search_project(src, q.get("q", ""), case=q.get("case") == "1", limit=_int(q, "limit", 200, 1, 300))


@_code
def api_code_files(h: Handler, db: Database, q: dict, src: Source):
    if not q.get("q"):
        raise CodeError(400, "saisissez une partie du nom de fichier")
    return list_files(src, q["q"], _int(q, "limit", 50, 1, 100))


def api_sarif_files(h: Handler, db: Database, q: dict, body: dict):
    doc, _ = _sarif(h, q)
    try:
        return {"files": sarif_files(doc, _int(q, "run", 0))}
    except KeyError as exc:
        raise ApiError(404, str(exc.args[0])) from exc


def api_sarif_import(h: Handler, db: Database, q: dict, body: dict):
    if not h.server.reveal:
        raise ApiError(403, "mode --mask : l'explorateur de sorties brutes est désactivé")
    name, content = body.get("name"), body.get("content")
    if not isinstance(name, str) or not isinstance(content, str):
        raise ApiError(400, "« name » et « content » (texte du fichier SARIF) attendus")
    try:
        return 201, {"path": import_sarif(h.server.data_dir, name, content)}
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc


def api_export(h: Handler, db: Database, q: dict, body: dict):
    fmt = q.get("format", "md")
    if fmt not in FORMATS:
        raise ApiError(400, f"format inconnu : {fmt!r}")
    reveal = h.server.reveal and q.get("mask") not in ("1", "true")   # un serveur --mask ne révèle jamais
    try:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = h._run(db, q)
            out = write_export(collect(db, run_id, h.server.data_dir, reveal=reveal,
                                       include_false_positives=q.get("false_positives") == "1"), fmt, Path(tmp) / f"export.{fmt}")
            data = out.read_bytes()
    except ExportError as exc:
        raise ApiError(400, str(exc)) from exc
    return data, MIME[fmt], {"Content-Disposition": f'attachment; filename="export-{run_id}.{fmt}"'}


def api_job_start(h: Handler, db: Database, q: dict, body: dict):
    root = Path(_text(body, "root", 4096, required=True) or "").expanduser()
    if not root.is_dir():
        raise ApiError(400, f"{root} n'est pas un dossier (chemin côté serveur)")
    names = _strs(body, "tools") if body.get("tools") else None
    label = _text(body, "name", 200)
    if label and label.strip():
        try:
            label = validate_label(label, db.list_audits())  # refusé tout de suite, pas au bout de 20 minutes d'audit
        except ValueError as exc:
            raise ApiError(400, f"nom du passage : {exc}") from exc
    else:
        label = None
    extra = list(_strs(body, "with")) if body.get("with") else []
    if body.get("history"):
        extra.append("gittools")
    try:
        if names or extra:
            base = names or [t.name for t in select_tools(h.server.config)]
            names = [*base, *[n for n in extra if n not in base]]
        select_tools(h.server.config, names)  # valide les noms
        h.server.jobs.start(root, names, True if body.get("unpack") else None, tuple(_strs(body, "exclude")) if body.get("exclude") else (),
                            True if body.get("critiq") else None, label)
    except JobBusy:
        raise ApiError(409, "un audit est déjà en cours")
    except (ValueError, AuditError) as exc:
        raise ApiError(400, str(exc)) from exc
    return 202, {"started": True}


def api_critiq(h: Handler, db: Database, q: dict, body: dict):
    llm = h.server.config.llm
    if not (llm and llm.model):
        raise ApiError(400, "aucun modèle configuré : renseignez `model` dans llm.yaml")
    more = body.get("more_code")
    if more is not None and not isinstance(more, bool):
        raise ApiError(400, "more_code : booléen attendu (true ou false)")
    kinds = None
    if body.get("kinds"):
        mapped = [CRITIQ_KINDS.get(k) for k in _strs(body, "kinds")]
        if None in mapped:
            raise ApiError(400, "kinds : valeurs admises : secret, sast, vuln")
        kinds = tuple(dict.fromkeys(mapped))
    try:
        h.server.jobs.start_critique(h._run(db, {"run": body.get("run")} if body.get("run") else {}), kinds, bool(body.get("force")), more)
    except JobBusy:
        raise ApiError(409, "une tâche est déjà en cours")
    return 202, {"started": True}


def api_job_current(h: Handler, db: Database, q: dict, body: dict):
    return h.server.jobs.snapshot(int(q.get("since", 0) or 0))


ROUTES: list[tuple[str, str, Callable]] = [
    ("GET", r"/api/runs", api_runs), ("GET", r"/api/data", api_data), ("GET", r"/api/diff", api_diff),
    ("GET", r"/api/secret", api_secret), ("GET", r"/api/raw", api_raw), ("GET", r"/api/export", api_export),
    ("GET", r"/api/raw/tree", api_raw_tree), ("GET", r"/api/raw/text", api_raw_text), ("GET", r"/api/raw/json", api_raw_json),
    ("GET", r"/api/raw/rows", api_raw_rows), ("GET", r"/api/sarif/summary", api_sarif_summary),
    ("GET", r"/api/sarif/rules", api_sarif_rules), ("GET", r"/api/sarif/results", api_sarif_results),
    ("GET", r"/api/sarif/files", api_sarif_files), ("POST", r"/api/sarif/import", api_sarif_import),
    ("GET", r"/api/code/tree", api_code_tree), ("GET", r"/api/code/file", api_code_file), ("GET", r"/api/code/find", api_code_find),
    ("GET", r"/api/code/search", api_code_search), ("GET", r"/api/code/files", api_code_files),
    ("GET", r"/api/jobs/current", api_job_current), ("POST", r"/api/jobs", api_job_start),
    ("POST", r"/api/critiq", api_critiq), ("POST", r"/api/triage", api_triage), ("POST", r"/api/triage/clear", api_triage_clear),
    ("POST", r"/api/findings", api_finding_create),
    ("PUT", r"/api/findings/([^/]+)", api_finding_update), ("DELETE", r"/api/findings/([^/]+)", api_finding_delete),
    ("PUT", r"/api/notes/(.+)", api_note),
]
