"""Export consolidé : constats automatiques dédoublonnés (+ triage) et constats manuels, en CSV, Markdown,
JSON, Excel ou Word. Base de travail de l'auditeur : le livrable final reste son analyse.

Dédoublonnage (sans jamais masquer d'information : les empreintes fusionnées sont conservées) :
  secrets          même (projet, hash du secret, fichier, mode) vu par plusieurs outils -> une ligne
  SAST             même (projet, fichier, ligne) ET au moins une CWE commune -> une ligne « corroborée »
                   (sans CWE commune on ne fusionne pas : deux outils sur la même ligne ne disent pas forcément la même chose)
  vulnérabilités   même (projet, composant, identifiant) -> une ligne
Triage : une ligne n'est écartée comme faux positif que si TOUTES les empreintes fusionnées le sont.
Secrets : en clair par défaut (`reveal`), comme le rapport ; le fichier produit est alors aussi sensible que data/.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .db import Database
from .report import build_report_data

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: len(SEV_ORDER) - i for i, s in enumerate(SEV_ORDER)}
SEV_FR = {"critical": "critique", "high": "élevée", "medium": "moyenne", "low": "faible", "info": "info"}
TRIAGE_FR = {"confirmed": "confirmé", "to_review": "à revoir", "accepted_risk": "risque accepté", "false_positive": "faux positif", None: ""}
MODE_FR = {"dir": "fichiers actuels", "git": "historique git", "history": "historique reconstruit"}
FORMATS = ("csv", "md", "json", "xlsx", "docx")
_TRIAGE_PRECEDENCE = ["confirmed", "to_review", "accepted_risk"]
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class ExportError(Exception):
    pass


def _max_sev(a: str, b: str) -> str:
    return a if SEV_RANK.get(a, 0) >= SEV_RANK.get(b, 0) else b


def _merge_triage(statuses: list[str | None]) -> str | None:
    present = [s for s in statuses if s]
    if present and all(s == "false_positive" for s in present) and len(present) == len(statuses):
        return "false_positive"  # TOUS les éléments fusionnés sont des faux positifs
    for s in _TRIAGE_PRECEDENCE:
        if s in present:
            return s
    return None  # « faux positif » pour un seul des outils : la ligne reste d'actualité pour les autres


class _Groups:
    """Regroupement par clés (union-find) : deux éléments partageant une clé finissent dans la même ligne."""

    def __init__(self) -> None:
        self.parent: list[int] = []
        self.owner: dict[Any, int] = {}

    def add(self, keys: list[Any]) -> int:
        i = len(self.parent)
        self.parent.append(i)
        for k in keys:
            if k in self.owner:
                self.parent[self._find(i)] = self._find(self.owner[k])
            else:
                self.owner[k] = i
        return i

    def _find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def groups(self) -> dict[int, list[int]]:
        out: dict[int, list[int]] = defaultdict(list)
        for i in range(len(self.parent)):
            out[self._find(i)].append(i)
        return out


def _flow_text(flow: list[dict]) -> str:
    return "\n".join(f"  {i}. {s['file']}:{s.get('line') or '?'}" + (f" — {s['message']}" if s.get("message") else "")
                     for i, s in enumerate(flow, 1))


def _row(**kw: Any) -> dict[str, Any]:
    base = {"id": "", "category": "", "project": "", "severity": "medium", "title": "", "location": "", "tools": [],
            "rule": "", "cwe": [], "triage": None, "comment": "", "details": "", "evidence": "", "fingerprints": [],
            "corroboration": 1, "extra": {}, "critique": ""}
    return {**base, **kw}


def _by_cluster(items: list[dict]) -> list[list[dict]] | None:
    """Groupes issus du recoupement (correlate), s'ils existent pour toutes les détections ; sinon None (repli sur les règles historiques)."""
    if not items or not all(it.get("cluster") for it in items):
        return None
    groups: dict[str, list[dict]] = {}
    for it in items:
        groups.setdefault(it["cluster"]["id"], []).append(it)
    return list(groups.values())


def group_secrets(items: list[dict]) -> list[list[dict]]:
    """Groupes du recoupement ; repli : même (projet, hash du secret, fichier, mode) vu par plusieurs outils."""
    if (grouped := _by_cluster(items)) is not None:
        return grouped
    g = _Groups()
    for s in items:
        g.add([(s["project"], s["secret_sha256"], s["file"], s["mode"])])
    return [[items[i] for i in members] for members in g.groups().values()]


def group_sast(items: list[dict]) -> list[list[dict]]:
    """Groupes du recoupement ; repli : même (projet, fichier, ligne) ET une CWE commune ; sans CWE : jamais fusionné."""
    if (grouped := _by_cluster(items)) is not None:
        return grouped
    g = _Groups()
    for f in items:
        keys = [(f["project"], f["file"], f.get("start_line"), c) for c in f.get("cwe") or []]
        g.add(keys or [("solo", f["fingerprint"])])
    return [[items[i] for i in members] for members in g.groups().values()]


def group_vulns(items: list[dict]) -> list[list[dict]]:
    """Groupes du recoupement ; repli : même (projet, composant, identifiant)."""
    if (grouped := _by_cluster(items)) is not None:
        return grouped
    g = _Groups()
    for v in items:
        g.add([(v["project"], (v["dependency"].get("name") or "").lower(), v["id"])])
    return [[items[i] for i in members] for members in g.groups().values()]


def _secret_rows(items: list[dict], comments: dict) -> list[dict]:
    rows = []
    for grp in group_secrets(items):
        first = grp[0]
        tools = sorted({s["tool"] for s in grp})
        fps = [s["fingerprint"] for s in grp]
        clear = next((s["secret"] for s in grp if s.get("secret")), None)
        sev = "critical" if any(s.get("verified") for s in grp) else "high"
        rows.append(_row(
            id=fps[0][:10], category="secret", project=first["project"], severity=sev,
            title=f"Secret exposé : {first['rule_id']}", rule=first["rule_id"],
            location=f"{first['file']}:{first['start_line']}" if first.get("start_line") else first["file"],
            tools=tools, triage=_merge_triage([s["triage"] for s in grp]),
            comment=next((comments.get(f, {}).get("comment") or "" for f in fps if comments.get(f, {}).get("comment")), ""),
            details=f"{MODE_FR.get(first['mode'], first['mode'])}" + (f", dans {first['commits_count']} commit(s)" if first.get("commits_count") else "")
                    + (f", commit {first['commit'][:10]}" if first.get("commit") else "") + ("; VÉRIFIÉ ACTIF" if sev == "critical" else ""),
            evidence=clear if clear else first["secret_masked"], fingerprints=fps, corroboration=len(tools),
            extra={"mode": first["mode"], "masked": first["secret_masked"], "revealed": bool(clear)}))
    return rows


def _sast_rows(items: list[dict], comments: dict) -> list[dict]:
    rows = []
    for grp in group_sast(items):
        best = max(grp, key=lambda f: SEV_RANK.get(f["severity"], 0))
        fps = [f["fingerprint"] for f in grp]
        tools = sorted({f["tool"] or "?" for f in grp})
        flow = next((f["flow"] for f in grp if f.get("flow")), [])
        rows.append(_row(
            id=fps[0][:10], category="iac" if best.get("category") == "iac" else "sast", project=best["project"],
            severity=best["severity"], title=best.get("rule_name") or best["rule_id"],
            rule=", ".join(sorted({f["rule_id"] for f in grp})),
            location=f"{best['file']}:{best['start_line']}" if best.get("start_line") else best["file"],
            cwe=sorted({c for f in grp for c in f.get("cwe") or []}), tools=tools,
            triage=_merge_triage([f["triage"] for f in grp]),
            comment=next((comments.get(x, {}).get("comment") or "" for x in fps if comments.get(x, {}).get("comment")), ""),
            details=best.get("message") or "",
            evidence=(best.get("snippet") or "") + (("\n\nChemin de données :\n" + _flow_text(flow)) if flow else ""),
            fingerprints=fps, corroboration=len(tools)))
    return rows


def _vuln_rows(items: list[dict], comments: dict) -> list[dict]:
    rows = []
    for grp in group_vulns(items):
        best = max(grp, key=lambda v: SEV_RANK.get(v["severity"], 0))
        dep, fps = best["dependency"], [v["fingerprint"] for v in grp]
        tools = sorted({v["tool"] for v in grp})
        rows.append(_row(
            id=fps[0][:10], category="dependency", project=best["project"],
            severity=max((v["severity"] for v in grp), key=lambda s: SEV_RANK.get(s, 0)),
            title=f"{best['id']} — {dep.get('name')} {dep.get('version') or ''}".strip(), rule=best["id"],
            location=dep.get("file") or "", cwe=sorted({c for v in grp for c in v.get("cwes") or []}), tools=tools,
            triage=_merge_triage([v["triage"] for v in grp]),
            comment=next((comments.get(x, {}).get("comment") or "" for x in fps if comments.get(x, {}).get("comment")), ""),
            details=best.get("description") or "",
            evidence=(f"Correctif : {next((v['fixed_version'] for v in grp if v.get('fixed_version')), None)}"
                      if any(v.get("fixed_version") for v in grp) else ""),
            fingerprints=fps, corroboration=len(tools),
            extra={"cvss": max((v["cvss_score"] for v in grp if v.get("cvss_score") is not None), default=None),
                   "purl": dep.get("purl"), "references": best.get("references") or []}))
    return rows


def collect(db: Database, audit_id: str, data_dir: Path, *, reveal: bool = True, include_false_positives: bool = False,
            statuses: list[str] | None = None, min_severity: str | None = None, include_dismissed: bool = False) -> dict[str, Any]:
    data = build_report_data(db, audit_id, data_dir, reveal)
    comments = db.list_triage()
    rows = _secret_rows(data["secrets"], comments) + _sast_rows(data["sast"], comments) + _vuln_rows(data["vulns"], comments)
    verdict_fr = {"true_positive": "vrai positif probable", "false_positive": "faux positif probable", "uncertain": "incertain", "error": "erreur"}
    crit_by_fp = {i["fingerprint"]: i["critique"] for i in (*data["secrets"], *data["sast"], *data["vulns"]) if i.get("critique")}
    for r in rows:
        texts = dict.fromkeys(f"{verdict_fr[c['verdict']]}" + (f" ({c['confidence']:.0%}, {c['model']})" if c.get("confidence") is not None else "")
                              + (" ⚠ injection suspectée" if c.get("injection_suspected") else "")
                              for c in (crit_by_fp.get(fp) for fp in r["fingerprints"]) if c)
        r["critique"] = " ; ".join(texts)
    manual = [f for f in db.list_findings() if include_dismissed or f["status"] != "dismissed"]
    for f in manual:
        rows.append(_row(id=f"M-{f['id']}", category="manual", project=f["project"], severity=f["severity"], title=f["title"],
                         triage=f["status"], details=f["description"], tools=["auditeur"], fingerprints=[],
                         extra={"refs": f["refs"], "status": f["status"]}))
    if not include_false_positives:
        rows = [r for r in rows if r["triage"] != "false_positive"]
    if statuses:
        rows = [r for r in rows if (r["triage"] or "untriaged") in statuses]
    if min_severity:
        rows = [r for r in rows if SEV_RANK.get(r["severity"], 0) >= SEV_RANK[min_severity]]
    rows.sort(key=lambda r: (-SEV_RANK.get(r["severity"], 0), r["project"], r["category"], r["location"]))
    counts: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        counts[r["project"]][r["severity"]] += 1
    return {"audit": data["audit"], "generated_at": data["generated_at"], "revealed": reveal, "warnings": data["warnings"],
            "rows": rows, "notes": {k: v["text"] for k, v in db.list_notes().items()},
            "summary": {p: {s: c[s] for s in SEV_ORDER if c[s]} | {"total": sum(c.values())} for p, c in sorted(counts.items())},
            "filters": {"include_false_positives": include_false_positives, "statuses": statuses, "min_severity": min_severity}}


# ---------------------------------------------------------------------------------- formats
def _clean(text: Any) -> str:
    return _CONTROL.sub("", str(text if text is not None else ""))


def _csv_safe(value: Any) -> str:
    """Neutralise l'injection de formules : une cellule venant du code audité ne doit pas s'exécuter dans Excel."""
    s = _clean(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


COLUMNS = [("id", "ID"), ("category", "Catégorie"), ("project", "Projet"), ("severity", "Sévérité"), ("title", "Titre"),
           ("location", "Emplacement"), ("tools", "Outils"), ("rule", "Règle / CVE"), ("cwe", "CWE"), ("triage", "Triage"),
           ("comment", "Commentaire"), ("details", "Détails"), ("evidence", "Preuve"), ("corroboration", "Outils concordants"),
           ("critique", "Avis IA (consultatif)")]


def _cell(row: dict, key: str) -> str:
    v = row[key]
    if key == "tools" or key == "cwe":
        return ", ".join(v)
    if key == "severity":
        return SEV_FR.get(v, v)
    if key == "triage":
        return TRIAGE_FR.get(v, v) if row["category"] != "manual" else {"draft": "brouillon", "confirmed": "confirmé", "dismissed": "écarté"}.get(v, v)
    return str(v if v is not None else "")


def to_json(c: dict) -> str:
    return json.dumps(c, ensure_ascii=False, indent=2, default=str)


def to_csv(c: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow([label for _, label in COLUMNS])
    for r in c["rows"]:
        w.writerow([_csv_safe(_cell(r, k)) for k, _ in COLUMNS])
    return "\ufeff" + buf.getvalue()  # BOM : Excel lit correctement les accents


def to_markdown(c: dict) -> str:
    a = c["audit"]
    out = [f"# Constats — audit {a['id']}", "", f"Périmètre : `{a['root']}` · généré le {c['generated_at'].replace('T', ' ')}", ""]
    if c["revealed"]:
        out += ["> ⚠ **Ce document contient des secrets en clair.** Ne pas le diffuser ni le versionner.", ""]
    for w in c["warnings"]:
        out.append(f"> ⚠ {w}")
    out += ["## Synthèse", "", "| Projet | " + " | ".join(SEV_FR[s] for s in SEV_ORDER) + " | Total |", "|---|" + "---|" * (len(SEV_ORDER) + 1)]
    for p, cnt in c["summary"].items():
        out.append(f"| {p} | " + " | ".join(str(cnt.get(s, "")) for s in SEV_ORDER) + f" | {cnt['total']} |")
    by_project: dict[str, list[dict]] = defaultdict(list)
    for r in c["rows"]:
        by_project[r["project"]].append(r)
    for project in sorted(set(by_project) | set(c["notes"])):
        out += ["", f"## {project}", ""]
        if c["notes"].get(project):
            out += ["**Notes de l'auditeur**", "", c["notes"][project].strip(), ""]
        for r in by_project.get(project, []):
            tri = f" · triage : {_cell(r, 'triage')}" if r["triage"] else ""
            out += [f"### [{SEV_FR[r['severity']].upper()}] {r['title']}", "",
                    f"`{r['id']}` · {r['category']} · {', '.join(r['tools'])}" + (f" · {', '.join(r['cwe'])}" if r["cwe"] else "") + tri
                    + (f" · {r['corroboration']} outils concordants" if r["corroboration"] > 1 else "")]
            if r["location"]:
                out.append(f"\n**Emplacement** : `{r['location']}`")
            if r["details"]:
                out.append(f"\n{r['details'].strip()}")
            if r["comment"]:
                out.append(f"\n**Commentaire d'audit** : {r['comment']}")
            if r["critique"]:
                out.append(f"\n**Avis IA (consultatif, à vérifier)** : {r['critique']}")
            if r["evidence"]:
                out += ["", "```", r["evidence"].strip(), "```"]
            if r["category"] == "manual" and r["extra"].get("refs"):
                out.append("\n**Références** : " + ", ".join(f"`{x[:10] if len(x) > 30 else x}`" for x in r["extra"]["refs"]))
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def to_xlsx(c: dict, path: Path) -> None:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError as exc:
        raise ExportError("export Excel : installez openpyxl (uv sync --extra export)") from exc

    def put(ws, row: int, col: int, value: Any, **style):
        cell = ws.cell(row=row, column=col)
        text = _clean(value)
        cell.value = text
        cell.data_type = "s"  # toujours du texte : jamais interprété comme une formule
        return cell

    wb = Workbook()
    ws = wb.active
    ws.title = "Résumé"
    put(ws, 1, 1, f"Audit {c['audit']['id']} — {c['audit']['root']}").font = Font(bold=True, size=13)
    if c["revealed"]:
        put(ws, 2, 1, "⚠ Contient des secrets en clair : ne pas diffuser").font = Font(bold=True, color="C92A2A")
    for i, h in enumerate(["Projet", *[SEV_FR[s] for s in SEV_ORDER], "Total"], 1):
        put(ws, 4, i, h).font = Font(bold=True)
    for r, (p, cnt) in enumerate(c["summary"].items(), 5):
        put(ws, r, 1, p)
        for i, s in enumerate(SEV_ORDER, 2):
            if cnt.get(s):
                ws.cell(row=r, column=i, value=cnt[s])
        ws.cell(row=r, column=len(SEV_ORDER) + 2, value=cnt["total"])
    ws.column_dimensions["A"].width = 32

    ws = wb.create_sheet("Constats")
    for i, (_, label) in enumerate(COLUMNS, 1):
        cell = put(ws, 1, i, label)
        cell.font, cell.fill = Font(bold=True, color="FFFFFF"), PatternFill("solid", fgColor="3B5BDB")
    for r, row in enumerate(c["rows"], 2):
        for i, (k, _) in enumerate(COLUMNS, 1):
            put(ws, r, i, _cell(row, k)).alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{max(1, len(c['rows']) + 1)}"
    for i, w in enumerate([12, 12, 18, 11, 44, 30, 22, 26, 14, 14, 30, 50, 50, 10, 34], 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    ws = wb.create_sheet("Notes")
    put(ws, 1, 1, "Projet").font = Font(bold=True)
    put(ws, 1, 2, "Notes de l'auditeur").font = Font(bold=True)
    for r, (p, text) in enumerate(sorted(c["notes"].items()), 2):
        put(ws, r, 1, p)
        put(ws, r, 2, text).alignment = Alignment(wrap_text=True, vertical="top")
    ws.column_dimensions["A"].width, ws.column_dimensions["B"].width = 24, 100
    wb.save(path)


def to_docx(c: dict, path: Path) -> None:
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
    except ImportError as exc:
        raise ExportError("export Word : installez python-docx (uv sync --extra export)") from exc
    doc = Document()
    doc.add_heading(f"Constats — audit {c['audit']['id']}", 0)
    doc.add_paragraph(_clean(f"Périmètre : {c['audit']['root']} · généré le {c['generated_at'].replace('T', ' ')}"))
    if c["revealed"]:
        p = doc.add_paragraph()
        run = p.add_run("⚠ Ce document contient des secrets en clair. Ne pas le diffuser.")
        run.bold, run.font.color.rgb = True, RGBColor(0xC9, 0x2A, 0x2A)
    doc.add_heading("Synthèse", 1)
    table = doc.add_table(rows=1, cols=len(SEV_ORDER) + 2)
    table.style = "Light Grid Accent 1"
    for i, h in enumerate(["Projet", *[SEV_FR[s] for s in SEV_ORDER], "Total"]):
        table.rows[0].cells[i].text = h
    for p, cnt in c["summary"].items():
        cells = table.add_row().cells
        cells[0].text = _clean(p)
        for i, s in enumerate(SEV_ORDER, 1):
            cells[i].text = str(cnt.get(s, ""))
        cells[-1].text = str(cnt["total"])
    by_project: dict[str, list[dict]] = defaultdict(list)
    for r in c["rows"]:
        by_project[r["project"]].append(r)
    for project in sorted(set(by_project) | set(c["notes"])):
        doc.add_heading(_clean(project), 1)
        if c["notes"].get(project):
            doc.add_paragraph().add_run("Notes de l'auditeur").bold = True
            doc.add_paragraph(_clean(c["notes"][project]))
        for r in by_project.get(project, []):
            doc.add_heading(_clean(f"[{SEV_FR[r['severity']].upper()}] {r['title']}"), 3)
            meta = f"{r['id']} · {r['category']} · {', '.join(r['tools'])}" + (f" · {', '.join(r['cwe'])}" if r["cwe"] else "")
            if r["triage"]:
                meta += f" · triage : {_cell(r, 'triage')}"
            doc.add_paragraph(_clean(meta))
            for label, key in (("Emplacement", "location"), ("Détails", "details"), ("Commentaire d'audit", "comment"), ("Avis IA (consultatif)", "critique")):
                if r[key]:
                    para = doc.add_paragraph()
                    para.add_run(f"{label} : ").bold = True
                    para.add_run(_clean(r[key]).strip())
            if r["evidence"]:
                para = doc.add_paragraph()
                run = para.add_run(_clean(r["evidence"]).strip())
                run.font.name, run.font.size = "Consolas", Pt(9)
    doc.save(path)


def write_export(c: dict, fmt: str, out: Path) -> Path:
    if fmt not in FORMATS:
        raise ExportError(f"format inconnu : {fmt!r} (attendu : {', '.join(FORMATS)})")
    out.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "xlsx":
        to_xlsx(c, out)
    elif fmt == "docx":
        to_docx(c, out)
    else:
        out.write_text({"csv": to_csv, "md": to_markdown, "json": to_json}[fmt](c), encoding="utf-8", newline="")
    return out
