"""Génère un rapport HTML autonome (un seul fichier, sans serveur) à partir de la base.

Secrets : la base ne contient que des valeurs masquées. En mode `reveal`, les valeurs en clair sont relues
dans les sorties brutes de gitleaks (après vérification de leur empreinte SHA-256) et ajoutées au rapport :
le fichier produit est alors AUSSI sensible que `data/`.
"""
from __future__ import annotations

import html as html_lib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .db import Database
from .diff import diff_runs
from .plugins import load_plugins
from .rawview import CACHE, result_detail, sarif_results
from .rawview import _run as sarif_run
from .runner import clear_values_of, raw_ref, report_digest

TEMPLATE = Path(__file__).parent / "templates" / "report.html"
RAW_DETAIL_BUDGET = 15 * 1024 * 1024  # taille max des résultats SARIF complets embarqués dans un rapport statique
MAX_COMMITS_LISTED = 200  # par secret « history », pour borner la taille du fichier
# Mode masqué : le code d'une règle de type secret/identifiant peut contenir la valeur elle-même
_SECRETISH_RULE = re.compile(r"secret|passw(or)?d|passwd|credential|token|api[-_]?key|private[-_]?key|hardcoded", re.I)


def load_clear_secrets(db: Database, audit_id: str, data_dir: Path) -> tuple[dict, list[str]]:
    """{(projet, outil, mode): {raw_index: (secret, ligne)}} relu dans les sorties brutes (gitleaks, trufflehog...)
    + avertissements. Le rapport brut doit avoir gardé l'empreinte SHA-256 enregistrée pendant l'audit."""
    names = {p["id"]: p["name"] for p in db.list_projects(audit_id)}
    registry = load_plugins()
    clear: dict[tuple[str, str, str], dict[int, tuple[str, str]]] = {}
    warnings: list[str] = []
    for r in db.list_tool_runs(audit_id):
        tool = registry.get(r["tool"])
        if tool is None or not tool.secrets_source or r["status"] != "ok" or not r["raw_dir"]:
            continue
        raw_dir = data_dir / r["raw_dir"]
        label = f"{names[r['project_id']]} · {tool.name}/{r['mode']}"
        try:
            # un rapport brut a-t-il changé depuis l'audit ? alors les index ne sont plus fiables (l'empreinte couvre TOUS les rapports de la tâche : une passe par rapport avec default_pass)
            if report_digest(raw_dir, tool) != r["report_sha256"]:
                warnings.append(f"{label} : sortie brute modifiée depuis l'audit, valeurs en clair indisponibles")
                continue
            clear[(names[r["project_id"]], tool.name, r["mode"])] = clear_values_of(tool, raw_dir)
        except (OSError, ValueError):
            warnings.append(f"{label} : sortie brute illisible, valeurs en clair indisponibles")
    return clear, warnings


def reveal_one(db: Database, audit_id: str, data_dir: Path, fingerprint: str) -> dict[str, str]:
    """Valeur en clair d'UN secret (sur demande), après vérification de l'empreinte du rapport brut."""
    ent = next((e for e in db.entities(audit_id, "secret") if e["fingerprint"] == fingerprint), None)
    if ent is None:
        raise LookupError("secret inconnu dans ce run")
    run = next((r for r in db.list_tool_runs(audit_id) if r["id"] == ent["tool_run_id"]), None)
    tool = load_plugins().get(run["tool"]) if run else None
    if not (run and tool and tool.secrets_source and run["raw_dir"]):
        raise LookupError("cet élément n'a pas de sortie brute exploitable")
    raw_dir = data_dir / run["raw_dir"]
    try:
        if report_digest(raw_dir, tool) != run["report_sha256"]:
            raise ValueError("sortie brute modifiée depuis l'audit : valeur non fiable")
        found = clear_values_of(tool, raw_dir).get(raw_ref(ent["data"]))
    except OSError as exc:
        raise LookupError("sortie brute introuvable") from exc
    if not found:
        raise LookupError("valeur introuvable dans la sortie brute")
    return {"secret": found[0], "match": found[1]}


def build_report_data(db: Database, audit_id: str, data_dir: Path | None = None, reveal: bool = False, *,
                      extra_options: dict[str, Any] | None = None, compare: str | None = None, raw_details: bool = False,
                      hide_false_positives: bool = False) -> dict[str, Any]:
    audit = db.get_audit(audit_id)
    if not audit:
        raise KeyError(audit_id)
    if reveal and data_dir is None:
        raise ValueError("data_dir est requis pour afficher les secrets en clair")
    projects = db.list_projects(audit_id)
    names = {p["id"]: p["name"] for p in projects}
    clear, warnings = load_clear_secrets(db, audit_id, data_dir) if reveal else ({}, [])

    triage = db.list_triage()
    crit = db.critiques()

    def crit_of(fp: str) -> dict | None:
        c = crit.get(fp)
        return {k: c[k] for k in ("verdict", "confidence", "reasoning", "model", "injection_suspected", "sent", "rounds", "created_at")} if c else None
    clusters = {fp: c for c in db.list_clusters(audit_id) for fp in c["members"]}
    if not clusters:  # run antérieur au recoupement (ou jamais corrélé) : calculé à la volée, sans rien écrire
        from .correlate import compute_clusters
        clusters = {fp: c for c in compute_clusters(db, data_dir, audit_id, nested=reveal) for fp in c["members"]}

    def cluster_of(fp: str) -> dict | None:
        c = clusters.get(fp)
        if c is None:
            return None
        statuses = {triage[m]["status"] for m in c["members"] if m in triage and triage[m]["status"]}
        return {"id": c["id"], "size": len(c["members"]), "members": c["members"], "reasons": c["reasons"], "conflict": len(statuses) > 1}
    registry = load_plugins()
    runs_by_id = {r["id"]: r for r in db.list_tool_runs(audit_id)}

    def raw_report(tool_run_id: int, report: str | None = None) -> str | None:
        """Rapport brut où relire un constat : celui de la tâche, ou celui d'une passe supplémentaire (`report`, chemin relatif au dossier de la tâche)."""
        run = runs_by_id.get(tool_run_id)
        tool = registry.get(run["tool"]) if run else None
        return f"{run['raw_dir']}/{report or tool.report_filename}" if run and tool and run["raw_dir"] else None

    secrets = []
    for e in db.entities(audit_id, "secret"):
        d = dict(e["data"])
        if isinstance(d.get("commits"), list):
            d["commits"] = d["commits"][:MAX_COMMITS_LISTED]
        tool_name = d.get("tool") or "gitleaks"  # résultats antérieurs au champ `tool`
        item = {"project": names[e["project_id"]], "fingerprint": e["fingerprint"], "triage": e["triage_status"],
                "triage_comment": (triage.get(e["fingerprint"]) or {}).get("comment"), "critique": crit_of(e["fingerprint"]),
                "cluster": cluster_of(e["fingerprint"]), **d, "tool": tool_name, "raw_report": raw_report(e["tool_run_id"], d.get("report"))}
        found = clear.get((item["project"], tool_name, d["mode"]), {}).get(raw_ref(d))
        if found:
            item["secret"], item["match"] = found
        secrets.append(item)

    sast = []
    for e in db.entities(audit_id, "sast_finding"):
        d = dict(e["data"])
        d["raw_report"] = raw_report(e["tool_run_id"], d.get("report"))
        if not reveal and d.get("snippet") and _SECRETISH_RULE.search(d.get("rule_id") or ""):
            d["snippet"] = None  # best effort : le code de ces règles peut contenir la valeur du secret
        sast.append({"project": names[e["project_id"]], "fingerprint": e["fingerprint"], "triage": e["triage_status"],
                     "triage_comment": (triage.get(e["fingerprint"]) or {}).get("comment"), "critique": crit_of(e["fingerprint"]), "cluster": cluster_of(e["fingerprint"]), **d})

    if hide_false_positives:
        secrets = [x for x in secrets if x["triage"] != "false_positive"]
        sast = [x for x in sast if x["triage"] != "false_positive"]
    detail_info = _embed_raw_details(sast, data_dir, reveal) if raw_details and data_dir else None
    return {
        "audit": audit,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "options": {"reveal": reveal, "raw_details": detail_info, "hide_false_positives": hide_false_positives, **(extra_options or {})},
        "mission": db.get_mission(),
        "findings": db.list_findings(),
        "notes": {p: n["text"] for p, n in db.list_notes().items()},
        "diff": diff_runs(db, compare, audit_id) if compare else None,
        "warnings": warnings,
        "projects": [{k: p[k] for k in ("name", "path", "is_git", "head_commit", "parent", "origin")}
                     | {"is_git": bool(p["is_git"])} for p in projects],
        "runs": [{
            "project": names[r["project_id"]], "tool": r["tool"], "mode": r["mode"], "status": r["status"],
            "exit_code": r["exit_code"], "duration_s": r["duration_s"], "tool_version": r["tool_version"],
            "command": r["command"], "raw_dir": r["raw_dir"], "error": r["error"],
            "report_sha256": r["report_sha256"], "started_at": r["started_at"],
        } for r in db.list_tool_runs(audit_id)],
        "technologies": [{"project": names[e["project_id"]], **e["data"]} for e in db.entities(audit_id, "technology")],
        "secrets": secrets,
        "sast": sast,
        "vulns": [{"project": names[e["project_id"]], "fingerprint": e["fingerprint"], "triage": e["triage_status"],
                   "triage_comment": (triage.get(e["fingerprint"]) or {}).get("comment"), "critique": crit_of(e["fingerprint"]), "cluster": cluster_of(e["fingerprint"]), **e["data"], "tool": e["data"].get("tool") or "dependency-check", "raw_report": raw_report(e["tool_run_id"], e["data"].get("report"))}
                  for e in db.entities(audit_id, "vulnerability") if not (hide_false_positives and e["triage_status"] == "false_positive")],
        "deps": [{"project": names[e["project_id"]], **e["data"]} for e in db.entities(audit_id, "dependency")],
        "commits": [{"project": names[e["project_id"]], **e["data"]} for e in db.entities(audit_id, "commit")],
        "relations": [{"type": r["type"], "src": names.get(r["src_id"]), "dst": names.get(r["dst_id"]), **r["data"]}
                      for r in db.list_relations(audit_id)],
    }


def _embed_raw_details(sast: list[dict], data_dir: Path, reveal: bool) -> dict[str, Any]:
    """Résultat SARIF COMPLET de chaque constat SAST (règle, chemins de données, emplacements liés...), dans la limite d'un budget."""
    used = embedded = skipped = 0
    truncated = False
    for f in sast:
        if not f.get("raw_report"):
            continue
        if not reveal and f.get("rule_id") and _SECRETISH_RULE.search(f["rule_id"]):
            skipped += 1  # mode masqué : le code d'une règle de type secret peut contenir la valeur
            continue
        try:
            doc, _ = CACHE.get(data_dir / f["raw_report"])
            run_idx = f.get("sarif_run") or 0
            run = sarif_run(doc, run_idx)
            if f.get("raw_index") is not None:
                detail = result_detail(run, run["results"][f["raw_index"]], f["raw_index"])
            else:  # runs antérieurs à l'enregistrement de la position : on retrouve le résultat par règle, fichier, ligne
                items = sarif_results(doc, run_idx, 0, 1, rule=f.get("rule_id"), file=f.get("file"), line=f.get("start_line"))["items"]
                detail = items[0] if items else None
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            continue
        if detail is None:
            continue
        size = len(json.dumps(detail, ensure_ascii=False))
        if used + size > RAW_DETAIL_BUDGET:
            truncated = True
            break
        f["raw_detail"], used, embedded = detail, used + size, embedded + 1
    return {"embedded": embedded, "truncated": truncated, "skipped_masked": skipped, "bytes": used}


def render_report(db: Database, audit_id: str, data_dir: Path | None = None, reveal: bool = False, *,
                  extra_options: dict[str, Any] | None = None, compare: str | None = None, raw_details: bool = False,
                  hide_false_positives: bool = False) -> str:
    data = build_report_data(db, audit_id, data_dir, reveal, extra_options=extra_options, compare=compare,
                             raw_details=raw_details, hide_false_positives=hide_false_positives)
    # `<` échappé : aucune donnée (nom de fichier, message de commit...) ne peut refermer la balise <script>.
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    html = TEMPLATE.read_text(encoding="utf-8")
    if "__AUDIT_DATA__" not in html:
        raise RuntimeError("gabarit de rapport invalide")
    mission, audit = data.get("mission"), data["audit"]
    title = html_lib.escape((f"{mission['name']} — " if mission else "") + (audit.get("label") or audit["id"]))
    return html.replace("__AUDIT_DATA__", payload).replace("__AUDIT_ID__", title)
