"""Base objet : noyau relationnel stable + payloads JSON souples.

Un nouvel outil ajoute de nouveaux `kind` d'entités sans migration de schéma.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import ParsedEntity, Project
from .runs import validate_label

SCHEMA_VERSION = 6
VERDICTS = ("true_positive", "false_positive", "uncertain", "error")

TRIAGE_STATUSES = ("to_review", "confirmed", "false_positive", "accepted_risk")
FINDING_STATUSES = ("draft", "confirmed", "dismissed")
SEVERITIES = ("critical", "high", "medium", "low", "info")

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id TEXT PRIMARY KEY, root TEXT NOT NULL,
    started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS project (
    id INTEGER PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
    name TEXT NOT NULL, path TEXT NOT NULL,
    is_git INTEGER NOT NULL, head_commit TEXT,
    parent TEXT, origin TEXT,        -- projet dérivé d'une archive : projet d'origine, chemin de l'archive
    UNIQUE (audit_id, name)
);
CREATE TABLE IF NOT EXISTS tool_run (
    id INTEGER PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    tool TEXT NOT NULL, mode TEXT NOT NULL,
    status TEXT NOT NULL,            -- ok | failed | timeout | skipped | unavailable | parse_error
    exit_code INTEGER, duration_s REAL, tool_version TEXT, command TEXT,
    raw_dir TEXT, report_sha256 TEXT, started_at TEXT, error TEXT,
    UNIQUE (audit_id, project_id, tool, mode)
);
CREATE TABLE IF NOT EXISTS entity (
    id INTEGER PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, fingerprint TEXT NOT NULL,
    data TEXT NOT NULL               -- JSON
);
CREATE INDEX IF NOT EXISTS idx_entity_kind ON entity(audit_id, kind, project_id);
CREATE INDEX IF NOT EXISTS idx_entity_fp ON entity(fingerprint);
-- Liens entre projets / entités (alimentés à l'étape 3)
CREATE TABLE IF NOT EXISTS relation (
    id INTEGER PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
    src_type TEXT NOT NULL, src_id INTEGER NOT NULL,
    dst_type TEXT NOT NULL, dst_id INTEGER NOT NULL,
    type TEXT NOT NULL, data TEXT
);
-- Constats rédigés par l'auditeur et notes de projet : globaux (indépendants des runs), indexés par NOM de projet
CREATE TABLE IF NOT EXISTS manual_finding (
    id INTEGER PRIMARY KEY, project TEXT NOT NULL, title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL DEFAULT 'draft',
    description TEXT NOT NULL DEFAULT '', refs TEXT NOT NULL DEFAULT '[]',  -- JSON : empreintes d'éléments automatiques, chemins...
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS project_note (
    project TEXT PRIMARY KEY, text TEXT NOT NULL, updated_at TEXT NOT NULL
);
-- Recoupement : des détections d'outils différents qui décrivent la même réalité forment UN groupe (un seul constat à trier)
CREATE TABLE IF NOT EXISTS cluster (
    audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, id TEXT NOT NULL, kind TEXT NOT NULL, project_id INTEGER NOT NULL,
    members TEXT NOT NULL,                 -- JSON : empreintes des détections du groupe
    reasons TEXT NOT NULL DEFAULT '[]',    -- JSON : pourquoi elles sont groupées (same_secret, same_cwe_location, alias...)
    PRIMARY KEY (audit_id, id)
);
-- Avis consultatifs d'un modèle d'IA sur un résultat (par empreinte et par modèle) : jamais un triage
CREATE TABLE IF NOT EXISTS critique (
    fingerprint TEXT NOT NULL, model TEXT NOT NULL, audit_id TEXT,
    evidence_sha TEXT NOT NULL,          -- empreinte de ce qui a été montré au modèle : si le code change, l'avis est refait
    verdict TEXT NOT NULL, confidence REAL, reasoning TEXT NOT NULL DEFAULT '',
    requests TEXT NOT NULL DEFAULT '[]', sent TEXT NOT NULL DEFAULT '[]',   -- JSON : demandes du modèle, code réellement envoyé
    rounds INTEGER NOT NULL DEFAULT 1, injection_suspected INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
    PRIMARY KEY (fingerprint, model)
);
-- La mission : un nom choisi par l'auditeur (une base = une mission ; le triage, les constats et les notes lui appartiennent)
CREATE TABLE IF NOT EXISTS mission (
    id INTEGER PRIMARY KEY CHECK (id = 1), name TEXT NOT NULL, client TEXT, scope TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
-- Le triage est indexé par empreinte : il survit aux relances
CREATE TABLE IF NOT EXISTS triage (
    fingerprint TEXT PRIMARY KEY, status TEXT NOT NULL,
    comment TEXT, updated_at TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        with self.conn:
            self.conn.executescript(SCHEMA)
            self._migrate()
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _migrate(self) -> None:
        """Migrations idempotentes (v1 -> v2 : projets dérivés d'archives)."""
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(project)")}
        for col in ("parent", "origin"):
            if col not in cols:
                self.conn.execute(f"ALTER TABLE project ADD COLUMN {col} TEXT")
        if "label" not in {r["name"] for r in self.conn.execute("PRAGMA table_info(audit)")}:  # v5 : passages nommés
            self.conn.execute("ALTER TABLE audit ADD COLUMN label TEXT")

    def close(self) -> None:
        self.conn.close()

    # --- audits -----------------------------------------------------------
    def create_audit(self, audit_id: str, root: Path, label: str | None = None) -> None:
        label = validate_label(label, self.list_audits()) if label is not None else None
        with self.conn:
            self.conn.execute(
                "INSERT INTO audit(id, root, started_at, status, label) VALUES (?,?,?,'running',?)",
                (audit_id, str(root), now_iso(), label),
            )

    def set_audit_label(self, audit_id: str, label: str | None) -> str | None:
        """Nomme (ou, avec None / « », dé-nomme) un passage. ValueError si le libellé est invalide ou déjà pris."""
        if not self.get_audit(audit_id):
            raise ValueError(f"run inconnu : {audit_id}")
        clean = validate_label(label, self.list_audits(), exclude=audit_id) if label and label.strip() else None
        with self.conn:
            self.conn.execute("UPDATE audit SET label=? WHERE id=?", (clean, audit_id))
        return clean

    # --- recoupement -----------------------------------------------------------------------
    def replace_clusters(self, audit_id: str, clusters: list[dict[str, Any]]) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM cluster WHERE audit_id=?", (audit_id,))
            self.conn.executemany(
                "INSERT INTO cluster(audit_id, id, kind, project_id, members, reasons) VALUES (?,?,?,?,?,?)",
                [(audit_id, c["id"], c["kind"], c["project_id"], json.dumps(c["members"]), json.dumps(c["reasons"])) for c in clusters])

    def list_clusters(self, audit_id: str) -> list[dict[str, Any]]:
        return [{"id": r["id"], "kind": r["kind"], "project_id": r["project_id"], "members": json.loads(r["members"]), "reasons": json.loads(r["reasons"])}
                for r in self.conn.execute("SELECT * FROM cluster WHERE audit_id=? ORDER BY kind, id", (audit_id,))]

    def cluster_map(self, audit_id: str) -> dict[str, dict[str, Any]]:
        """empreinte -> son groupe (le même dict pour tous les membres)."""
        out: dict[str, dict[str, Any]] = {}
        for c in self.list_clusters(audit_id):
            for fp in c["members"]:
                out[fp] = c
        return out

    # --- mission ---------------------------------------------------------------------------
    def get_mission(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM mission WHERE id=1").fetchone()
        return dict(row) if row else None

    def set_mission(self, name: str, client: str | None = None, scope: str | None = None, *, keep_unset: bool = True) -> dict[str, Any]:
        name = " ".join((name or "").split())
        if not name or len(name) > 120 or any(ord(c) < 32 for c in name):
            raise ValueError("nom de mission invalide (1 à 120 caractères, sans caractère de contrôle)")
        now, current = now_iso(), self.get_mission()
        if current and keep_unset:
            client = client if client is not None else current["client"]
            scope = scope if scope is not None else current["scope"]
        with self.conn:
            self.conn.execute(
                """INSERT INTO mission(id, name, client, scope, created_at, updated_at) VALUES (1,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET name=excluded.name, client=excluded.client, scope=excluded.scope, updated_at=excluded.updated_at""",
                (name, client, scope, current["created_at"] if current else now, now))
        return self.get_mission()

    def set_audit_status(self, audit_id: str, status: str, finished: bool = False) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE audit SET status=?, finished_at=? WHERE id=?",
                (status, now_iso() if finished else None, audit_id),
            )

    def get_audit(self, audit_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM audit WHERE id=?", (audit_id,)).fetchone()
        return dict(row) if row else None

    def list_audits(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM audit ORDER BY id DESC")]

    def latest_audit_id(self) -> str | None:
        row = self.conn.execute("SELECT id FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return row["id"] if row else None

    # --- projets ----------------------------------------------------------
    def upsert_project(self, audit_id: str, p: Project) -> int:
        with self.conn:
            self.conn.execute(
                """INSERT INTO project(audit_id, name, path, is_git, head_commit, parent, origin)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(audit_id, name) DO UPDATE SET
                     path=excluded.path, is_git=excluded.is_git, head_commit=excluded.head_commit,
                     parent=excluded.parent, origin=excluded.origin""",
                (audit_id, p.name, str(p.path), int(p.is_git), p.head_commit, p.parent, p.origin),
            )
        return self.conn.execute(
            "SELECT id FROM project WHERE audit_id=? AND name=?", (audit_id, p.name)
        ).fetchone()["id"]

    def list_projects(self, audit_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM project WHERE audit_id=? ORDER BY name", (audit_id,))]

    # --- exécutions d'outils ----------------------------------------------
    def get_tool_run(self, audit_id: str, project_id: int, tool: str, mode: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM tool_run WHERE audit_id=? AND project_id=? AND tool=? AND mode=?",
            (audit_id, project_id, tool, mode),
        ).fetchone()
        return dict(row) if row else None

    def list_tool_runs(self, audit_id: str, project_id: int | None = None) -> list[dict[str, Any]]:
        sql, params = "SELECT * FROM tool_run WHERE audit_id=?", [audit_id]
        if project_id is not None:
            sql += " AND project_id=?"
            params.append(project_id)
        return [dict(r) for r in self.conn.execute(sql + " ORDER BY tool, mode", params)]

    def delete_tool_run(self, audit_id: str, project_id: int, tool: str, mode: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM tool_run WHERE audit_id=? AND project_id=? AND tool=? AND mode=?",
                              (audit_id, project_id, tool, mode))

    def save_tool_run(
        self, audit_id: str, project_id: int, tool: str, mode: str, *, status: str,
        exit_code: int | None = None, duration_s: float | None = None,
        tool_version: str | None = None, command: str | None = None,
        raw_dir: str | None = None, report_sha256: str | None = None,
        started_at: str | None = None, error: str | None = None,
        entities: Iterable[ParsedEntity] = (),
    ) -> int:
        """Enregistre l'exécution et remplace ses entités, dans une seule transaction."""
        with self.conn:
            self.conn.execute(
                """INSERT INTO tool_run(audit_id, project_id, tool, mode, status, exit_code, duration_s,
                       tool_version, command, raw_dir, report_sha256, started_at, error)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(audit_id, project_id, tool, mode) DO UPDATE SET
                       status=excluded.status, exit_code=excluded.exit_code, duration_s=excluded.duration_s,
                       tool_version=excluded.tool_version, command=excluded.command, raw_dir=excluded.raw_dir,
                       report_sha256=excluded.report_sha256, started_at=excluded.started_at, error=excluded.error""",
                (audit_id, project_id, tool, mode, status, exit_code, duration_s,
                 tool_version, command, raw_dir, report_sha256, started_at, error),
            )
            run_id = self.conn.execute(
                "SELECT id FROM tool_run WHERE audit_id=? AND project_id=? AND tool=? AND mode=?",
                (audit_id, project_id, tool, mode),
            ).fetchone()["id"]
            self._replace_entities(run_id, audit_id, project_id, entities)
        return run_id

    def replace_entities(self, tool_run_id: int, audit_id: str, project_id: int,
                         entities: Iterable[ParsedEntity], status: str, error: str | None) -> None:
        with self.conn:
            self.conn.execute("UPDATE tool_run SET status=?, error=? WHERE id=?", (status, error, tool_run_id))
            self._replace_entities(tool_run_id, audit_id, project_id, entities)

    def _replace_entities(self, tool_run_id: int, audit_id: str, project_id: int,
                          entities: Iterable[ParsedEntity]) -> None:
        self.conn.execute("DELETE FROM entity WHERE tool_run_id=?", (tool_run_id,))
        self.conn.executemany(
            "INSERT INTO entity(audit_id, project_id, tool_run_id, kind, fingerprint, data) VALUES (?,?,?,?,?,?)",
            [(audit_id, project_id, tool_run_id, e.kind, e.fingerprint, json.dumps(e.data, ensure_ascii=False))
             for e in entities],
        )

    # --- relations ----------------------------------------------------------
    def set_relation(self, audit_id: str, src_type: str, src_id: int, dst_type: str, dst_id: int,
                     rtype: str, data: dict[str, Any] | None = None) -> None:
        with self.conn:
            self.conn.execute(
                "DELETE FROM relation WHERE audit_id=? AND src_type=? AND src_id=? AND dst_type=? AND dst_id=? AND type=?",
                (audit_id, src_type, src_id, dst_type, dst_id, rtype))
            self.conn.execute(
                "INSERT INTO relation(audit_id, src_type, src_id, dst_type, dst_id, type, data) VALUES (?,?,?,?,?,?,?)",
                (audit_id, src_type, src_id, dst_type, dst_id, rtype, json.dumps(data or {}, ensure_ascii=False)))

    def list_relations(self, audit_id: str) -> list[dict[str, Any]]:
        out = []
        for r in self.conn.execute("SELECT * FROM relation WHERE audit_id=? ORDER BY id", (audit_id,)):
            d = dict(r)
            d["data"] = json.loads(d["data"] or "{}")
            out.append(d)
        return out

    # --- entités & triage ---------------------------------------------------
    def entities(self, audit_id: str, kind: str | None = None, project_id: int | None = None) -> list[dict[str, Any]]:
        sql = """SELECT e.id, e.project_id, e.tool_run_id, e.kind, e.fingerprint, e.data, t.status AS triage_status
                 FROM entity e LEFT JOIN triage t ON t.fingerprint = e.fingerprint
                 WHERE e.audit_id=?"""
        params: list[Any] = [audit_id]
        if kind:
            sql += " AND e.kind=?"
            params.append(kind)
        if project_id is not None:
            sql += " AND e.project_id=?"
            params.append(project_id)
        out = []
        for r in self.conn.execute(sql + " ORDER BY e.id", params):
            d = dict(r)
            d["data"] = json.loads(d["data"])
            out.append(d)
        return out

    def set_triage(self, fingerprint: str, status: str, comment: str | None = None) -> None:
        self.set_triage_many([fingerprint], status, comment)

    def set_triage_many(self, fingerprints: Iterable[str], status: str, comment: str | None = None) -> int:
        if status not in TRIAGE_STATUSES:
            raise ValueError(f"statut de triage inconnu : {status!r} (attendu : {', '.join(TRIAGE_STATUSES)})")
        rows = [(fp, status, comment, now_iso()) for fp in dict.fromkeys(fingerprints)]
        with self.conn:
            self.conn.executemany(
                """INSERT INTO triage(fingerprint, status, comment, updated_at) VALUES (?,?,?,?)
                   ON CONFLICT(fingerprint) DO UPDATE SET status=excluded.status,
                       comment=COALESCE(excluded.comment, triage.comment), updated_at=excluded.updated_at""", rows)
        return len(rows)

    def clear_triage(self, fingerprints: Iterable[str]) -> int:
        fps = list(dict.fromkeys(fingerprints))
        with self.conn:
            self.conn.executemany("DELETE FROM triage WHERE fingerprint=?", [(f,) for f in fps])
        return len(fps)

    def list_triage(self) -> dict[str, dict[str, Any]]:
        return {r["fingerprint"]: dict(r) for r in self.conn.execute("SELECT * FROM triage")}

    # --- avis du modèle d'IA ------------------------------------------------------------
    def save_critique(self, fingerprints: Iterable[str], *, model: str, audit_id: str | None, evidence_sha: str, verdict: str,
                      confidence: float | None, reasoning: str, requests: list | None = None, sent: list | None = None,
                      rounds: int = 1, injection_suspected: bool = False) -> int:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict inconnu : {verdict!r}")
        fps = list(dict.fromkeys(fingerprints))
        row = (model, audit_id, evidence_sha, verdict, confidence, reasoning, json.dumps(requests or [], ensure_ascii=False),
               json.dumps(sent or [], ensure_ascii=False), rounds, int(injection_suspected), now_iso())
        with self.conn:
            self.conn.executemany(
                """INSERT INTO critique(fingerprint, model, audit_id, evidence_sha, verdict, confidence, reasoning, requests, sent,
                       rounds, injection_suspected, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(fingerprint, model) DO UPDATE SET audit_id=excluded.audit_id, evidence_sha=excluded.evidence_sha,
                       verdict=excluded.verdict, confidence=excluded.confidence, reasoning=excluded.reasoning,
                       requests=excluded.requests, sent=excluded.sent, rounds=excluded.rounds,
                       injection_suspected=excluded.injection_suspected, created_at=excluded.created_at""",
                [(fp, row[0], *row[1:]) for fp in fps])
        return len(fps)

    @staticmethod
    def _critique(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["requests"], d["sent"] = json.loads(d["requests"] or "[]"), json.loads(d["sent"] or "[]")
        d["injection_suspected"] = bool(d["injection_suspected"])
        return d

    def critiques(self, model: str | None = None) -> dict[str, dict[str, Any]]:
        """Dernier avis par empreinte (tous modèles, ou un modèle précis)."""
        sql, params = "SELECT * FROM critique", []
        if model:
            sql, params = sql + " WHERE model=?", [model]
        return {r["fingerprint"]: self._critique(r) for r in self.conn.execute(sql + " ORDER BY created_at, rowid", params)}

    def critiques_for(self, fingerprints: Iterable[str], model: str) -> dict[str, dict[str, Any]]:
        out = {}
        for fp in fingerprints:
            row = self.conn.execute("SELECT * FROM critique WHERE fingerprint=? AND model=?", (fp, model)).fetchone()
            if row:
                out[fp] = self._critique(row)
        return out

    # --- constats manuels & notes de projet ------------------------------------
    @staticmethod
    def _check_finding(severity: str | None, status: str | None) -> None:
        if severity is not None and severity not in SEVERITIES:
            raise ValueError(f"sévérité inconnue : {severity!r} (attendu : {', '.join(SEVERITIES)})")
        if status is not None and status not in FINDING_STATUSES:
            raise ValueError(f"statut de constat inconnu : {status!r} (attendu : {', '.join(FINDING_STATUSES)})")

    def add_finding(self, project: str, title: str, severity: str = "medium", status: str = "draft",
                    description: str = "", refs: list[str] | None = None) -> int:
        self._check_finding(severity, status)
        if not title.strip() or not project.strip():
            raise ValueError("un constat a besoin d'un projet et d'un titre")
        now = now_iso()
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO manual_finding(project, title, severity, status, description, refs, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (project, title.strip(), severity, status, description, json.dumps(refs or [], ensure_ascii=False), now, now))
        return int(cur.lastrowid)

    def update_finding(self, finding_id: int, **fields: Any) -> bool:
        allowed = {"project", "title", "severity", "status", "description", "refs"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"champ(s) inconnu(s) : {sorted(unknown)}")
        self._check_finding(fields.get("severity"), fields.get("status"))
        if "refs" in fields:
            fields["refs"] = json.dumps(fields["refs"] or [], ensure_ascii=False)
        if not fields:
            return self.get_finding(finding_id) is not None
        sets = ", ".join(f"{k}=?" for k in fields)
        with self.conn:
            cur = self.conn.execute(f"UPDATE manual_finding SET {sets}, updated_at=? WHERE id=?",
                                    [*fields.values(), now_iso(), finding_id])
        return cur.rowcount > 0

    def delete_finding(self, finding_id: int) -> bool:
        with self.conn:
            return self.conn.execute("DELETE FROM manual_finding WHERE id=?", (finding_id,)).rowcount > 0

    @staticmethod
    def _finding(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["refs"] = json.loads(d["refs"] or "[]")
        return d

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM manual_finding WHERE id=?", (finding_id,)).fetchone()
        return self._finding(row) if row else None

    def list_findings(self, project: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        sql, params = "SELECT * FROM manual_finding WHERE 1=1", []
        if project:
            sql, params = sql + " AND project=?", [*params, project]
        if status:
            sql, params = sql + " AND status=?", [*params, status]
        return [self._finding(r) for r in self.conn.execute(sql + " ORDER BY id", params)]

    def set_note(self, project: str, text: str) -> None:
        with self.conn:
            if text.strip():
                self.conn.execute("""INSERT INTO project_note(project, text, updated_at) VALUES (?,?,?)
                                     ON CONFLICT(project) DO UPDATE SET text=excluded.text, updated_at=excluded.updated_at""",
                                  (project, text, now_iso()))
            else:
                self.conn.execute("DELETE FROM project_note WHERE project=?", (project,))

    def list_notes(self) -> dict[str, dict[str, Any]]:
        return {r["project"]: dict(r) for r in self.conn.execute("SELECT * FROM project_note ORDER BY project")}

    # --- maintenance -----------------------------------------------------------------
    def delete_relations(self, audit_id: str, types: Iterable[str]) -> None:
        with self.conn:
            self.conn.executemany("DELETE FROM relation WHERE audit_id=? AND type=?", [(audit_id, t) for t in types])

    def delete_audit(self, audit_id: str) -> None:
        with self.conn:  # cascade : projets, exécutions, entités, relations. Triage et constats sont conservés.
            self.conn.execute("DELETE FROM audit WHERE id=?", (audit_id,))
