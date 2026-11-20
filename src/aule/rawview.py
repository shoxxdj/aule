"""Explorateur de sorties brutes : tout ce que les outils ont produit, lu À LA DEMANDE et par pages.

L'interface locale n'embarque jamais ces données : elle les demande au fur et à mesure (arbre JSON dépliable,
tableau paginé, journaux par tranches, résultats SARIF un par un). On peut donc afficher beaucoup plus que dans un
rapport statique sans le surcharger. Pour SARIF (opengrep, CodeQL...) on restitue TOUT le format : règles complètes,
tous les chemins de données, emplacements liés, notifications d'exécution, empreintes, propriétés.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any

from .db import Database

MAX_DOC_BYTES = 150 * 1024 * 1024     # au-delà : trop de mémoire pour un explorateur ; ouvrir depuis le disque
MAX_TEXT_CHUNK = 1024 * 1024
MAX_SCALAR = 20_000
TEXT_EXT = {".txt", ".log", ".md", ".yml", ".yaml", ".xml", ".csv", ".tf", ".py", ".js", ".java", ".toml", ".ini", ".cfg", ".sh", ".html", ".htm", ".properties"}


def file_kind(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".sarif":
        return "sarif"
    if ext == ".json":
        return "json"
    if ext == ".jsonl":
        return "jsonl"
    if ext in TEXT_EXT or path.name in ("cmd.txt", "stdout.txt", "stderr.txt"):
        return "text"
    try:
        with path.open("rb") as fh:
            return "binary" if b"\0" in fh.read(4096) else "text"
    except OSError:
        return "binary"


def list_tree(db: Database, data_dir: Path, run_id: str) -> list[dict[str, Any]]:
    """Une entrée par exécution d'outil (+ les conversations de la critique IA) avec ses fichiers bruts."""
    names = {p["id"]: p["name"] for p in db.list_projects(run_id)}
    out = []
    for r in db.list_tool_runs(run_id):
        if not r["raw_dir"]:
            continue
        raw = data_dir / r["raw_dir"]
        files = []
        for f in sorted(raw.iterdir()) if raw.is_dir() else []:
            if f.is_file():
                files.append({"name": f.name, "path": f"{r['raw_dir']}/{f.name}", "size": f.stat().st_size, "kind": file_kind(f)})
        out.append({"project": names[r["project_id"]], "tool": r["tool"], "mode": r["mode"], "status": r["status"], "error": r["error"],
                    "raw_dir": r["raw_dir"], "files": files})
    imported = data_dir / "imports"
    if imported.is_dir():
        files = [{"name": f.name, "path": f"imports/{f.name}", "size": f.stat().st_size, "kind": file_kind(f)} for f in sorted(imported.iterdir()) if f.is_file()]
        out.append({"project": "(importés)", "tool": "sarif", "mode": "import", "status": "ok", "error": None, "raw_dir": "imports", "files": files})
    critiq = data_dir / "runs" / run_id / "critiq"
    for model_dir in sorted(critiq.iterdir()) if critiq.is_dir() else []:
        files = [{"name": f.name, "path": f"runs/{run_id}/critiq/{model_dir.name}/{f.name}", "size": f.stat().st_size, "kind": "json"}
                 for f in sorted(model_dir.glob("*.json"))[:500]]
        out.append({"project": "(critique IA)", "tool": "critiq", "mode": model_dir.name, "status": "ok", "error": None,
                    "raw_dir": f"runs/{run_id}/critiq/{model_dir.name}", "files": files})
    return out


def _complete_utf8_tail(raw: bytes, fh) -> bytes:
    """Complète une séquence UTF-8 coupée en fin de tranche : on ne coupe jamais un caractère."""
    i, back = len(raw) - 1, 0
    while i >= 0 and back < 4 and (raw[i] & 0xC0) == 0x80:  # octets de continuation
        i, back = i - 1, back + 1
    if i < 0:
        return raw
    lead = raw[i]
    need = 4 if lead >= 0xF0 else 3 if lead >= 0xE0 else 2 if lead >= 0xC0 else 1
    have = len(raw) - i
    return raw + fh.read(need - have) if have < need else raw


def read_text(path: Path, offset: int = 0, limit: int = 200_000) -> dict[str, Any]:
    size = path.stat().st_size
    offset, limit = max(0, offset), max(1, min(limit, MAX_TEXT_CHUNK))
    with path.open("rb") as fh:
        fh.seek(offset)
        raw = _complete_utf8_tail(fh.read(limit), fh)
    end = offset + len(raw)
    return {"size": size, "offset": offset, "end": end, "next": end if end < size else None,
            "text": raw.decode("utf-8", "replace"), "lines": raw.count(b"\n")}


class DocCache:
    """Documents JSON analysés, gardés en mémoire (quelques-uns, invalidés si le fichier change)."""

    def __init__(self, maxdocs: int = 2):
        self.maxdocs, self.lock, self.docs = maxdocs, threading.Lock(), OrderedDict()

    def get(self, path: Path) -> tuple[Any, dict]:
        st = path.stat()
        key = (str(path), st.st_mtime_ns, st.st_size)
        with self.lock:
            if key in self.docs:
                self.docs.move_to_end(key)
                return self.docs[key]
        if st.st_size > MAX_DOC_BYTES:
            raise ValueError(f"fichier trop volumineux pour l'explorateur ({st.st_size // 1024 // 1024} Mo > {MAX_DOC_BYTES // 1024 // 1024} Mo) : ouvrez-le depuis le disque")
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() == ".jsonl":
            doc: Any = []
            for n, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    try:
                        doc.append(json.loads(line))
                    except ValueError:
                        doc.append({"_ligne_invalide": n, "_brut": line[:300]})
        else:
            try:
                doc = json.loads(text) if text.strip() else None
            except ValueError as exc:
                raise ValueError(f"JSON invalide : {exc}") from exc
        entry = (doc, {})
        with self.lock:
            self.docs[key] = entry
            while len(self.docs) > self.maxdocs:
                self.docs.popitem(last=False)
        return entry


CACHE = DocCache()


# ---------------------------------------------------------------------------------------- arbre JSON
def _ptr_unescape(part: str) -> str:
    return part.replace("~1", "/").replace("~0", "~")


def _ptr_escape(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


def resolve_pointer(doc: Any, pointer: str) -> Any:
    node = doc
    for raw in [p for p in pointer.split("/")[1:]] if pointer else []:
        key = _ptr_unescape(raw)
        try:
            node = node[int(key)] if isinstance(node, list) else node[key]
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise KeyError(f"chemin introuvable : {pointer}") from exc
    return node


def _type(v: Any) -> str:
    return "object" if isinstance(v, dict) else "array" if isinstance(v, list) else "string" if isinstance(v, str) else \
        "boolean" if isinstance(v, bool) else "null" if v is None else "number"


def _preview(v: Any, width: int = 120) -> str:
    if isinstance(v, dict):
        return "{" + f"{len(v)} clé(s)" + "}"
    if isinstance(v, list):
        return f"[{len(v)}]"
    text = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    text = text.replace("\n", "⏎ ")
    return text if len(text) <= width else text[:width] + "…"


def json_node(doc: Any, pointer: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
    node = resolve_pointer(doc, pointer)
    out: dict[str, Any] = {"pointer": pointer, "type": _type(node), "children": [], "offset": offset, "limit": limit}
    if isinstance(node, dict):
        items = list(node.items())
    elif isinstance(node, list):
        items = list(enumerate(node))
    else:
        text = node if isinstance(node, str) else json.dumps(node, ensure_ascii=False)
        out.update(size=len(text), value=text[:MAX_SCALAR], truncated=len(text) > MAX_SCALAR, total=0)
        return out
    out["size"] = out["total"] = len(items)
    for k, v in items[offset:offset + limit]:
        out["children"].append({"key": k, "pointer": f"{pointer}/{_ptr_escape(str(k))}", "type": _type(v),
                                "size": len(v) if isinstance(v, (dict, list)) else None, "preview": _preview(v)})
    return out


def json_rows(doc: Any, pointer: str, offset: int = 0, limit: int = 50, q: str | None = None) -> dict[str, Any]:
    """Vue « tableau » d'un tableau d'objets (résultats gitleaks, checks checkov, dépendances...)."""
    node = resolve_pointer(doc, pointer)
    if not isinstance(node, list):
        raise ValueError("la vue tableau s'applique à un tableau")
    needle = q.casefold() if q else None
    idx = [i for i, v in enumerate(node[:200_000]) if not needle or needle in json.dumps(v, ensure_ascii=False).casefold()] if needle else list(range(len(node)))
    cols: list[str] = []
    for v in node[:40]:
        if isinstance(v, dict):
            for k, val in v.items():
                if k not in cols and len(cols) < 12:
                    cols.append(k)
    rows = []
    for i in idx[offset:offset + limit]:
        v = node[i]
        rows.append({"index": i, "pointer": f"{pointer}/{i}", "cells": {c: (_preview(v[c], 80) if c in v else "") for c in cols} if isinstance(v, dict) else {"valeur": _preview(v, 80)}})
    return {"pointer": pointer, "columns": cols or ["valeur"], "rows": rows, "total": len(idx), "all": len(node), "offset": offset, "limit": limit}


# ---------------------------------------------------------------------------------------- SARIF complet
def _msg(m: Any) -> dict[str, Any]:
    m = m if isinstance(m, dict) else {}
    return {"text": m.get("text") or "", "markdown": m.get("markdown")}


def _region(r: Any) -> dict[str, Any]:
    r = r if isinstance(r, dict) else {}
    out = {k: r[k] for k in ("startLine", "startColumn", "endLine", "endColumn", "charOffset", "charLength", "byteOffset", "byteLength") if k in r}
    if isinstance(r.get("snippet"), dict):
        out["snippet"] = r["snippet"].get("text")
    return out


def _loc(l: Any) -> dict[str, Any]:
    l = l if isinstance(l, dict) else {}
    phys = l.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    ctx = phys.get("contextRegion")
    return {"id": l.get("id"), "uri": art.get("uri"), "uriBaseId": art.get("uriBaseId"), "region": _region(phys.get("region")),
            "contextRegion": _region(ctx) if ctx else None, "message": _msg(l.get("message"))["text"] or None,
            "logical": [x.get("fullyQualifiedName") or x.get("name") for x in l.get("logicalLocations") or [] if isinstance(x, dict)]}


def _rule(r: Any) -> dict[str, Any]:
    r = r if isinstance(r, dict) else {}
    cfg = r.get("defaultConfiguration") or {}
    help_ = r.get("help") or {}
    return {"id": r.get("id"), "name": r.get("name"), "shortDescription": _msg(r.get("shortDescription"))["text"], "fullDescription": _msg(r.get("fullDescription"))["text"],
            "help": help_.get("text") or help_.get("markdown"), "helpMarkdown": help_.get("markdown"), "helpUri": r.get("helpUri"),
            "defaultLevel": cfg.get("level"), "enabled": cfg.get("enabled"), "rank": cfg.get("rank"), "properties": r.get("properties") or {},
            "relationships": r.get("relationships") or [], "deprecatedIds": r.get("deprecatedIds") or []}


def _run(doc: Any, run_idx: int) -> dict[str, Any]:
    runs = (doc or {}).get("runs") if isinstance(doc, dict) else None
    if not isinstance(runs, list) or not (0 <= run_idx < len(runs)) or not isinstance(runs[run_idx], dict):
        raise KeyError(f"run SARIF introuvable : {run_idx}")
    return runs[run_idx]


def _driver(run: dict) -> dict:
    return _d(_d(run.get("tool")).get("driver"))


def _rules_of(run: dict) -> list[dict]:
    raw = _driver(run).get("rules")
    return [r for r in raw if isinstance(r, dict)] if isinstance(raw, list) else []


def _results_of(run: dict) -> list[dict]:
    raw = run.get("results")
    return [r if isinstance(r, dict) else {} for r in raw] if isinstance(raw, list) else []


def _find_rule(run: dict, res: dict) -> dict:
    rules = _rules_of(run)
    idx = res.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        return rules[idx]
    ref = res.get("rule") or {}
    if isinstance(ref.get("index"), int) and 0 <= ref["index"] < len(rules):
        return rules[ref["index"]]
    rid = res.get("ruleId") or ref.get("id")
    return next((r for r in rules if r.get("id") == rid), {})


def _level(run: dict, res: dict) -> str:
    return res.get("level") or ((_find_rule(run, res).get("defaultConfiguration") or {}).get("level")) or "warning"


def sarif_summary(doc: Any, cache_entry: dict | None = None) -> dict[str, Any]:
    if cache_entry is not None and "summary" in cache_entry:
        return cache_entry["summary"]
    runs = []
    for i, run in enumerate((doc or {}).get("runs") or [] if isinstance(doc, dict) else []):
        run = _d(run)
        driver, results = _driver(run), run.get("results") or []
        counts = Counter(_level(run, r) for r in results)
        by_rule = Counter(r.get("ruleId") or (_find_rule(run, r).get("id")) or "?" for r in results)
        notifs = []
        for inv in _dicts(run.get("invocations") or []):
            for kind in ("toolExecutionNotifications", "toolConfigurationNotifications"):
                for n in _dicts(inv.get(kind) or []):
                    notifs.append({"kind": "exécution" if kind.startswith("toolExec") else "configuration", "level": n.get("level") or "warning",
                                   "message": _msg(n.get("message"))["text"], "descriptor": (n.get("descriptor") or {}).get("id"),
                                   "locations": [_loc(l) for l in (n.get("locations") if isinstance(n.get("locations"), list) else [])][:3],
                                   "exception": _d(n.get("exception")).get("message")})
        invocations = [{"executionSuccessful": inv.get("executionSuccessful"), "exitCode": inv.get("exitCode"), "exitCodeDescription": inv.get("exitCodeDescription"),
                        "commandLine": inv.get("commandLine"), "workingDirectory": _d(inv.get("workingDirectory")).get("uri"),
                        "startTimeUtc": inv.get("startTimeUtc"), "endTimeUtc": inv.get("endTimeUtc"),
                        "machine": inv.get("machine"), "properties": inv.get("properties") or {}} for inv in _dicts(run.get("invocations") or [])]
        runs.append({
            "index": i, "tool": {"name": driver.get("name"), "version": driver.get("semanticVersion") or driver.get("version"), "fullName": driver.get("fullName"),
                                 "organization": driver.get("organization"), "informationUri": driver.get("informationUri")},
            "extensions": [{"name": e.get("name"), "version": e.get("semanticVersion") or e.get("version"), "organization": e.get("organization"),
                            "rules": len(e.get("rules") or [])} for e in _dicts(_d(run.get("tool")).get("extensions"))],
            "results": len(results), "levels": dict(counts), "rules": {"declared": len(_rules_of(run)), "with_results": len(by_rule)},
            "top_rules": [{"id": k, "count": v} for k, v in by_rule.most_common(40)],
            "notifications": notifs[:300], "notifications_total": len(notifs), "invocations": invocations,
            "artifacts": len(run.get("artifacts") or []), "taxonomies": [{"name": t.get("name"), "taxa": len(t.get("taxa") or [])} for t in _dicts(run.get("taxonomies") or [])],
            "originalUriBaseIds": run.get("originalUriBaseIds") or {}, "properties": run.get("properties") or {},
            "columnKind": run.get("columnKind"), "defaultSourceLanguage": run.get("defaultSourceLanguage"),
        })
    summary = {"version": (doc or {}).get("version") if isinstance(doc, dict) else None, "schema": (doc or {}).get("$schema") if isinstance(doc, dict) else None, "runs": runs}
    if cache_entry is not None:
        cache_entry["summary"] = summary
    return summary


def sarif_files(doc: Any, run_idx: int = 0) -> list[dict[str, Any]]:
    """Fichiers touchés (premier emplacement de chaque résultat), avec compteurs : navigation « par fichier »."""
    run = _run(doc, run_idx)
    files: dict[str, Counter] = {}
    for res in _results_of(run):
        uri = (_uris(res) or ["(sans emplacement)"])[0]
        files.setdefault(uri, Counter())[_level(run, res)] += 1
    rows = [{"uri": u, "count": sum(c.values()), "levels": dict(c)} for u, c in files.items()]
    return sorted(rows, key=lambda r: (-r["count"], r["uri"]))[:5000]


def sarif_rules(doc: Any, run_idx: int = 0) -> list[dict[str, Any]]:
    run = _run(doc, run_idx)
    counts = Counter(r.get("ruleId") or _find_rule(run, r).get("id") for r in _results_of(run))
    return [{**_rule(r), "results": counts.get(r.get("id"), 0)} for r in _rules_of(run)]


def _flow_steps(tf: dict, cap: int = 300) -> list[dict]:
    steps = []
    for n, item in enumerate(tf.get("locations") or []):
        if n >= cap:
            break
        item = item if isinstance(item, dict) else {}
        steps.append({"step": n + 1, "location": _loc(item.get("location")), "nestingLevel": item.get("nestingLevel"), "importance": item.get("importance"),
                      "kinds": item.get("kinds"), "executionOrder": item.get("executionOrder"), "state": item.get("state")})
    return steps


def result_detail(run: dict, res: dict, index: int) -> dict[str, Any]:
    rule = _find_rule(run, res)
    flows = []
    for cf in (res.get("codeFlows") or [])[:20]:
        flows.append({"message": _msg(cf.get("message"))["text"] or None,
                      "threadFlows": [{"id": tf.get("id"), "message": _msg(tf.get("message"))["text"] or None, "steps": _flow_steps(tf),
                                       "total_steps": len(tf.get("locations") or [])} for tf in (cf.get("threadFlows") or [])[:10]]})
    return {
        "index": index, "ruleId": res.get("ruleId") or rule.get("id"), "ruleIndex": res.get("ruleIndex"), "level": res.get("level"), "effectiveLevel": _level(run, res),
        "kind": res.get("kind"), "baselineState": res.get("baselineState"), "rank": res.get("rank"), "message": _msg(res.get("message")),
        "locations": [_loc(l) for l in res.get("locations") or []], "relatedLocations": [_loc(l) for l in res.get("relatedLocations") or []],
        "codeFlows": flows, "codeFlows_total": len(res.get("codeFlows") or []), "stacks": len(res.get("stacks") or []), "fixes": len(res.get("fixes") or []),
        "suppressions": res.get("suppressions") or [], "partialFingerprints": res.get("partialFingerprints") or {}, "fingerprints": res.get("fingerprints") or {},
        "occurrenceCount": res.get("occurrenceCount"), "taxa": res.get("taxa") or [], "properties": res.get("properties") or {},
        "analysisTarget": (res.get("analysisTarget") or {}).get("uri"), "rule": _rule(rule) if rule else None,
    }


def _d(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def _dicts(x: Any) -> list[dict]:
    """Les éléments objets d'une liste ; tout le reste (null, nombres, chaînes) est ignoré, jamais converti en objet vide."""
    return [e for e in x if isinstance(e, dict)] if isinstance(x, list) else []


def _locs(res: dict) -> list[dict]:
    raw = res.get("locations")
    return [l for l in raw if isinstance(l, dict)] if isinstance(raw, list) else []


def _uris(res: dict) -> list[str]:
    return [str(_d(_d(_d(l).get("physicalLocation")).get("artifactLocation")).get("uri") or "") for l in _locs(res)]


def _haystack(run: dict, res: dict) -> str:
    rule = _find_rule(run, res)
    return f"{_d(res.get('message')).get('text') or ''} {res.get('ruleId') or rule.get('id') or ''} {rule.get('name') or ''} {' '.join(_uris(res))}".casefold()


def _covers(res: dict, line: int) -> bool:
    for l in _locs(res):
        reg = _d(_d(l.get("physicalLocation")).get("region"))
        start = reg.get("startLine")
        if isinstance(start, int) and start <= line <= (reg.get("endLine") if isinstance(reg.get("endLine"), int) else start):
            return True
    return False


def sarif_results(doc: Any, run_idx: int = 0, offset: int = 0, limit: int = 25, *, rule: str | None = None, level: str | None = None,
                  q: str | None = None, file: str | None = None, line: int | None = None, index: int | None = None) -> dict[str, Any]:
    run = _run(doc, run_idx)
    results = _results_of(run)
    if index is not None:
        if not (0 <= index < len(results)):
            raise KeyError(f"résultat introuvable : {index}")
        return {"total": 1, "all": len(results), "offset": 0, "limit": 1, "items": [result_detail(run, results[index], index)]}
    needle, fneedle = (q.casefold() if q else None), (file.casefold() if file else None)
    hits = []
    for i, res in enumerate(results):
        if rule and (res.get("ruleId") or _find_rule(run, res).get("id")) != rule:
            continue
        if level and _level(run, res) != level:
            continue
        if needle and needle not in _haystack(run, res):
            continue
        if fneedle and fneedle not in " ".join(_uris(res)).casefold():
            continue
        if line is not None and not _covers(res, line):
            continue
        hits.append(i)
    return {"total": len(hits), "all": len(results), "offset": offset, "limit": limit,
            "items": [result_detail(run, results[i], i) for i in hits[offset:offset + limit]]}


def import_sarif(data_dir: Path, name: str, content: bytes | str) -> str:
    """Copie un SARIF extérieur (CI, client...) dans la mission : `imports/<horodatage>-<nom>.sarif`. Jamais d'écrasement.
    Renvoie le chemin relatif au dossier de données (consultable dans l'explorateur de sorties brutes)."""
    raw = content.encode("utf-8") if isinstance(content, str) else content
    if len(raw) > MAX_DOC_BYTES:
        raise ValueError(f"fichier trop volumineux ({len(raw) // 1024 // 1024} Mo > {MAX_DOC_BYTES // 1024 // 1024} Mo)")
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"JSON invalide : {exc}") from exc
    if not (isinstance(doc, dict) and isinstance(doc.get("runs"), list)):
        raise ValueError("ce fichier n'est pas un SARIF (clé « runs » absente)")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name or "import").stem).strip("._") or "import"
    folder = data_dir / "imports"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target, n = folder / f"{stamp}-{stem[:60]}.sarif", 1
    while target.exists():
        n += 1
        target = folder / f"{stamp}-{stem[:60]}-{n}.sarif"
    target.write_bytes(raw)
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return f"imports/{target.name}"
