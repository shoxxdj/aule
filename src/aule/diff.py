"""Comparaison de deux runs : nouveaux, corrigés, persistants.

Un résultat n'est « nouveau » ou « corrigé » que si l'outil qui l'a produit a réussi sur ce projet dans LES
DEUX runs. Sinon (outil absent d'un des runs, ou en échec), il est listé à part : ce n'est pas une correction.
Projets : ceux AJOUTÉS dans B comptent comme nouveaux (rien à comparer, tout est nouveau) ; ceux RETIRÉS de B
ne sont pas déclarés « corrigés » (un projet qui disparaît du périmètre n'est pas un projet corrigé).
"""
from __future__ import annotations

from typing import Any

from .db import Database
from .triage import KIND_NAMES, KINDS, label, location, severity_of

DEFAULT_KINDS = tuple(KINDS.values())


def _ok_keys(db: Database, audit_id: str, names: dict[int, str]) -> dict[int, tuple[str, str, str]]:
    return {r["id"]: (names[r["project_id"]], r["tool"], r["mode"])
            for r in db.list_tool_runs(audit_id) if r["status"] == "ok"}


def _summary(kind: str, e: dict[str, Any], project: str) -> dict[str, Any]:
    d = e["data"]
    return {"fingerprint": e["fingerprint"], "project": project, "label": label(kind, d),
            "location": location(kind, d), "severity": severity_of(kind, d), "triage": e["triage_status"]}


def diff_runs(db: Database, run_a: str, run_b: str, kinds: tuple[str, ...] = DEFAULT_KINDS) -> dict[str, Any]:
    """A = base (avant), B = courant (après)."""
    for rid in (run_a, run_b):
        if not db.get_audit(rid):
            raise KeyError(rid)
    names = {rid: {p["id"]: p["name"] for p in db.list_projects(rid)} for rid in (run_a, run_b)}
    ok = {rid: _ok_keys(db, rid, names[rid]) for rid in (run_a, run_b)}
    comparable = set(ok[run_a].values()) & set(ok[run_b].values())
    projects_a, projects_b = set(names[run_a].values()), set(names[run_b].values())
    added = projects_b - projects_a

    def usable(rid: str, e: dict[str, Any]) -> bool:
        key = ok[rid].get(e["tool_run_id"])
        return key in comparable or (rid == run_b and key is not None and key[0] in added)

    result: dict[str, Any] = {
        "a": run_a, "b": run_b,
        "projects_added": sorted(projects_b - projects_a), "projects_removed": sorted(projects_a - projects_b),
        # exécutions réussies d'un seul côté, sur des projets présents des deux côtés
        "not_comparable": sorted(f"{p} · {t}/{m} (seulement dans {'A' if k in set(ok[run_a].values()) else 'B'})"
                                 for k in set(ok[run_a].values()) ^ set(ok[run_b].values())
                                 for p, t, m in [k] if p in projects_a & projects_b),
        "kinds": {},
    }
    for kind in kinds:
        items: dict[str, dict[str, dict]] = {}
        for rid in (run_a, run_b):
            items[rid] = {}
            for e in db.entities(rid, kind):
                if usable(rid, e):
                    items[rid][e["fingerprint"]] = _summary(kind, e, names[rid][e["project_id"]])
        a, b = items[run_a], items[run_b]
        entry = {"new": [b[f] for f in b if f not in a], "fixed": [a[f] for f in a if f not in b],
                 "persistent": [b[f] for f in b if f in a]}
        result["kinds"][kind] = {**entry, "counts": {k: len(v) for k, v in entry.items()}}
    result["counts"] = {s: sum(k["counts"][s] for k in result["kinds"].values()) for s in ("new", "fixed", "persistent")}
    return result


def format_diff(d: dict[str, Any], show_persistent: bool = False) -> str:
    lines = [f"Comparaison  A = {d['a']}  →  B = {d['b']}",
             f"Total : {d['counts']['new']} nouveau(x) · {d['counts']['fixed']} corrigé(s) · {d['counts']['persistent']} persistant(s)"]
    if d["projects_added"]:
        lines.append(f"Projets ajoutés dans B (leurs résultats comptent comme nouveaux) : {', '.join(d['projects_added'])}")
    if d["projects_removed"]:
        lines.append(f"Projets absents de B (non comptés comme corrigés) : {', '.join(d['projects_removed'])}")
    for item in d["not_comparable"]:
        lines.append(f"Non comparable : {item}")
    for kind, k in d["kinds"].items():
        lines.append(f"\n== {KIND_NAMES.get(kind, kind)} : +{k['counts']['new']} / -{k['counts']['fixed']} / ={k['counts']['persistent']}")
        for section, sign in (("new", "+"), ("fixed", "-"), *((("persistent", "="),) if show_persistent else ())):
            for r in sorted(k[section], key=lambda r: (r["project"], r["location"])):
                tri = f"  [{r['triage']}]" if r["triage"] else ""
                lines.append(f"  {sign} {r['fingerprint'][:10]}  {r['project']:<16} {r['severity']:<8} {r['label']}  {r['location']}{tri}")
    return "\n".join(lines)
