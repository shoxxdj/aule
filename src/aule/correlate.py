"""Recoupement des résultats, une fois tous les outils passés : une même réalité vue par plusieurs détections = UN constat à trier.

Principe : un regroupement ne doit jamais cacher un vrai constat derrière un autre. Les règles sont donc prudentes et explicites :

  secrets   : même valeur (SHA-256) dans le MÊME fichier, quels que soient l'outil, le mode (dir / git / history) et le commit ;
              + valeurs imbriquées à la même ligne (un outil capture `password="abc"`, l'autre `abc`).
              Le même secret dans deux fichiers reste deux constats (même credential, mais deux endroits à corriger).
  SAST      : même fichier, CWE commune et lignes qui se recouvrent ; ou une extrémité du chemin de données d'un constat tombe sur
              l'autre (CodeQL ↔ opengrep) ; ou même règle au même emplacement. JAMAIS de tolérance « à quelques lignes ».
              Sans CWE commune, aucun regroupement (sauf même règle au même emplacement).
  dépendances : même composant (nom normalisé) et identifiants qui se recoupent, ALIAS compris (CVE ↔ GHSA), à version compatible.

Le résultat est enregistré (table `cluster`) : interface, export, critique IA et CLI voient les mêmes groupes. Un triage humain se
propage aux occurrences identiques encore non triées (jamais d'écrasement) ; des triages divergents sont signalés, pas tranchés.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from .runner import raw_ref
from .db import Database

KINDS = ("secret", "sast_finding", "vulnerability")
MAX_BUCKET = 1500          # au-delà (fichier avec des milliers de constats), seuls les regroupements exacts sont faits
PROPAGATED = "[propagé depuis un résultat identique]"


class _UF:
    def __init__(self, n: int):
        self.p = list(range(n))
        self.why: dict[int, set[str]] = defaultdict(set)

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int, reason: str) -> None:
        ra, rb = self.find(a), self.find(b)
        self.why[ra].add(reason)
        self.why[rb].add(reason)
        if ra != rb:
            self.p[rb] = ra
            self.why[ra] |= self.why.pop(rb, set())

    def groups(self) -> list[tuple[list[int], list[str]]]:
        out: dict[int, list[int]] = defaultdict(list)
        for i in range(len(self.p)):
            out[self.find(i)].append(i)
        return [(idx, sorted(self.why.get(root, set()))) for root, idx in out.items()]


def _end(d: dict) -> int | None:
    return d.get("end_line") if isinstance(d.get("end_line"), int) else d.get("start_line")


def _secrets(recs: list[dict]) -> list[tuple[list[int], list[str]]]:
    uf = _UF(len(recs))
    exact: dict[tuple, list[int]] = defaultdict(list)
    by_line: dict[tuple, list[int]] = defaultdict(list)
    for i, r in enumerate(recs):
        d = r["d"]
        if d.get("secret_sha256"):
            exact[(r["project_id"], d["secret_sha256"], d.get("file"))].append(i)
        clear = r.get("clear")
        if clear and len(clear) >= 8 and d.get("start_line") and d.get("file"):
            by_line[(r["project_id"], d["file"], d["start_line"])].append(i)
    for idxs in exact.values():
        for j in idxs[1:]:
            uf.union(idxs[0], j, "same_secret")
    for idxs in by_line.values():
        for x, i in enumerate(idxs):
            for j in idxs[x + 1:]:
                a, b = recs[i]["clear"], recs[j]["clear"]
                if a != b and (a in b or b in a):
                    uf.union(i, j, "nested_values")
    return uf.groups()


def _sast(recs: list[dict]) -> list[tuple[list[int], list[str]]]:
    uf = _UF(len(recs))
    info = []
    for r in recs:
        d = r["d"]
        flow = [s for s in d.get("flow") or [] if isinstance(s, dict) and s.get("file") and isinstance(s.get("line"), int)]
        info.append({"pid": r["project_id"], "file": d.get("file"), "start": d.get("start_line"), "end": _end(d), "tool": d.get("tool"),
                     "rule": d.get("rule_id"), "cwe": set(d.get("cwe") or []), "ends": [flow[0], flow[-1]] if flow else []})
    buckets: dict[tuple, list[int]] = defaultdict(list)
    for i, a in enumerate(info):
        if a["file"] and isinstance(a["start"], int):
            buckets[(a["pid"], a["file"])].append(i)
    for idxs in buckets.values():
        exact_only = len(idxs) > MAX_BUCKET
        for x, i in enumerate(idxs):
            for j in idxs[x + 1:]:
                a, b = info[i], info[j]
                if (a["tool"], a["rule"], a["start"], a["end"]) == (b["tool"], b["rule"], b["start"], b["end"]):
                    uf.union(i, j, "same_rule_location")
                elif not exact_only and a["cwe"] & b["cwe"] and a["start"] <= b["end"] and b["start"] <= a["end"]:
                    uf.union(i, j, "same_cwe_location")      # lignes qui se recouvrent, pas « proches »
    # une extrémité (source ou puits) du chemin de données d'un constat tombe sur l'autre : même vulnérabilité vue par deux outils
    at: dict[tuple, list[int]] = defaultdict(list)
    for i, a in enumerate(info):
        if a["file"] and isinstance(a["start"], int):
            for line in range(a["start"], min(a["end"], a["start"] + 50) + 1):
                at[(a["pid"], a["file"], line)].append(i)
    for i, a in enumerate(info):
        for step in a["ends"]:
            for j in at.get((a["pid"], step["file"], step["line"]), ()):
                if j != i and a["cwe"] & info[j]["cwe"]:
                    uf.union(i, j, "flow_endpoint")
    return uf.groups()


def _norm_component(dep: dict) -> str:
    purl = dep.get("purl") or ""
    m = re.match(r"pkg:([^/]+)/(.+?)(?:@[^?#]*)?(?:[?#].*)?$", purl)
    kind, name = (m.group(1).lower(), m.group(2)) if m else ("", dep.get("name") or "")
    name = name.lower()
    return re.sub(r"[-_.]+", "-", name) if kind == "pypi" else name   # PyPI seulement : en npm, « a.b » et « a-b » sont deux paquets


def _vuln_ids(d: dict) -> set[str]:
    return {str(x).upper() for x in [d.get("id"), *(d.get("aliases") or [])] if x}


def _vulns(recs: list[dict]) -> list[tuple[list[int], list[str]]]:
    uf = _UF(len(recs))
    buckets: dict[tuple, list[int]] = defaultdict(list)
    for i, r in enumerate(recs):
        dep = r["d"].get("dependency") or {}
        if dep.get("name"):
            buckets[(r["project_id"], _norm_component(dep))].append(i)
    for idxs in buckets.values():
        for x, i in enumerate(idxs):
            for j in idxs[x + 1:]:
                da, db_ = recs[i]["d"], recs[j]["d"]
                va, vb = (da.get("dependency") or {}).get("version"), (db_.get("dependency") or {}).get("version")
                if (not va or not vb or va == vb) and _vuln_ids(da) & _vuln_ids(db_):
                    uf.union(i, j, "same_component_vuln" if da.get("id") == db_.get("id") else "alias")
    return uf.groups()


_ALGOS: dict[str, Callable] = {"secret": _secrets, "sast_finding": _sast, "vulnerability": _vulns}


def _cluster_id(kind: str, project_id: int, fps: list[str]) -> str:
    return hashlib.sha1("|".join([kind, str(project_id), *sorted(fps)]).encode()).hexdigest()[:12]


def compute_clusters(db: Database, data_dir: Path | None, run_id: str, *, nested: bool = True) -> list[dict[str, Any]]:
    """Groupes du run (singletons compris) : [{id, kind, project_id, members: [empreintes], reasons: [...]}]. N'écrit rien."""
    clear: dict = {}
    if nested and data_dir is not None:
        try:
            from .report import load_clear_secrets  # import tardif : report n'importe pas ce module
            clear, _ = load_clear_secrets(db, run_id, data_dir)
        except Exception:  # noqa: BLE001 — les valeurs imbriquées sont un plus : sans elles on garde les regroupements exacts
            clear = {}
    names = {p["id"]: p["name"] for p in db.list_projects(run_id)}
    out = []
    for kind in KINDS:
        recs = []
        for e in db.entities(run_id, kind):
            d = e["data"]
            rec = {"fp": e["fingerprint"], "project_id": e["project_id"], "d": d}
            if kind == "secret":
                found = clear.get((names.get(e["project_id"]), d.get("tool") or "gitleaks", d.get("mode")), {}).get(raw_ref(d))
                rec["clear"] = found[0] if found else None
            recs.append(rec)
        for idxs, reasons in _ALGOS[kind](recs):
            fps = sorted({recs[i]["fp"] for i in idxs})
            pid = recs[idxs[0]]["project_id"]
            out.append({"id": _cluster_id(kind, pid, fps), "kind": kind, "project_id": pid, "members": fps, "reasons": reasons})
    return out


def conflicting(members: list[str], triage: dict[str, dict]) -> bool:
    return len({triage[fp]["status"] for fp in members if fp in triage and triage[fp]["status"]}) > 1


def correlate_run(db: Database, data_dir: Path | None, run_id: str, *, propagate: bool = True, persist: bool = True,
                  log: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Calcule, enregistre et propage le triage. Idempotent : le relancer ne change rien tant que les résultats ne changent pas."""
    if not db.get_audit(run_id):
        raise KeyError(run_id)
    clusters = compute_clusters(db, data_dir, run_id)
    if persist:
        db.replace_clusters(run_id, clusters)
    summary: dict[str, Any] = {k: {"detections": 0, "groups": 0} for k in KINDS}
    for c in clusters:
        summary[c["kind"]]["detections"] += len(c["members"])
        summary[c["kind"]]["groups"] += 1
    triage = db.list_triage()
    propagated = conflicts = 0
    for c in clusters:
        if len(c["members"]) < 2:
            continue
        if conflicting(c["members"], triage):
            conflicts += 1
            continue
        done = [fp for fp in c["members"] if fp in triage and triage[fp]["status"]]
        todo = [fp for fp in c["members"] if fp not in done]
        if propagate and persist and done and todo:
            src = triage[done[0]]
            note = (src.get("comment") or "").strip()
            db.set_triage_many(todo, src["status"], f"{PROPAGATED} {note}".strip())
            propagated += len(todo)
    summary.update(propagated=propagated, conflicts=conflicts)
    if log:
        parts = [f"{label} {s['detections']}→{s['groups']}" for label, k in (("secrets", "secret"), ("SAST", "sast_finding"), ("dépendances", "vulnerability"))
                 if (s := summary[k])["detections"] != s["groups"]]
        log("Recoupement : " + (" · ".join(parts) if parts else "aucun doublon") + (f" ; {propagated} triage(s) propagé(s)" if propagated else "")
            + (f" ; {conflicts} groupe(s) aux triages divergents" if conflicts else ""))
    return summary
