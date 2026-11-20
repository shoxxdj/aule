"""Aulë — les écrans de la forge. Utilisé UNIQUEMENT en mode `forge` (terminal ou `--color always`) ; le mode `plain` garde le texte historique.

Le déroulé d'un passage suit le geste du forgeron : on prospecte le minerai (inventaire, premiers sondages), on le met à la fonte (motifs),
on martèle (dépendances), on passe à la grande forge (analyse approfondie), on fait l'alliage (recoupement), puis l'orfèvre examine (modèle IA).
"""
from __future__ import annotations

import re
import threading
import time
from collections import Counter
from typing import Any

from .models import SEVERITIES
from .runs import display_name
from .ui import Col, Live, Raw, S, Ui, cell_width, clip, human_duration, pad

PHASES = {1: ("ore", "Prospection", "inventaire et premiers sondages"), 2: ("fire", "Fonte", "analyse de motifs"), 3: ("hammer", "Martelage", "dépendances"),
          4: ("volcano", "Grande forge", "analyse approfondie"), 5: ("gem", "Orfèvrerie", "avis du modèle")}
STATUS = {"ok": ("ok", "ok"), "skipped": ("skip", "ash"), "error": ("fail", "flame"), "timeout": ("clock", "gold"), "unavailable": ("fail", "flame"),
          "parse_error": ("warn", "gold")}
VERDICT = {"true_positive": ("warn", "gold", "vrai positif"), "false_positive": ("skip", "ash", "faux positif"), "uncertain": ("dot", "iron", "incertain"),
           "error": ("fail", "flame", "erreur"), "erreur": ("fail", "flame", "erreur")}
SEV_ORDER = SEVERITIES


def sev_style(sev: str) -> str:
    return "flame bold" if sev in ("critical", "high") else "gold" if sev == "medium" else "ash"


def sev_text(ui: Ui, counter: Counter) -> str:
    return " · ".join(ui.c(f"{k} {counter[k]}", sev_style(k)) for k in SEV_ORDER if counter[k]) or ui.c("aucun", "ash")


def fit(ui: Ui, parts: list[str], limit: int, sep: str = "  ") -> str:
    """Joint des morceaux déjà décorés ; en terminal étroit, abandonne les détails secondaires (les derniers) plutôt que de déborder."""
    parts = [p for p in parts if p]
    while len(parts) > 1 and cell_width(sep.join(parts)) > limit:
        parts.pop()
    return sep.join(parts)


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n < 2 else (many or one + 's')}"


def tally(db, run_id: str, project_id: int | None = None) -> dict[str, dict[str, Any]]:
    """Constats (groupes recoupés) et détections par catégorie, avec la répartition par gravité des constats."""
    cmap = db.cluster_map(run_id)
    out: dict[str, dict[str, Any]] = {}
    for kind in ("secret", "sast_finding", "vulnerability"):
        groups: dict[str, str] = {}
        n = 0
        for e in db.entities(run_id, kind, project_id) if project_id else db.entities(run_id, kind):
            n += 1
            d = e["data"]
            sev = ("critical" if d.get("verified") else "high") if kind == "secret" else d.get("severity", "medium")
            gid = cmap[e["fingerprint"]]["id"] if e["fingerprint"] in cmap else e["fingerprint"]
            old = groups.get(gid)
            if old is None or SEV_ORDER.index(sev) < SEV_ORDER.index(old):
                groups[gid] = sev
        out[kind] = {"detections": n, "groups": len(groups), "sev": Counter(groups.values())}
    return out


class RunPrinter:
    """Reçoit le journal d'un passage (`log=`) et sa progression (`progress=`) et les met en scène : phases de la forge, résultats, barre."""

    RUN = re.compile(r"^Run (\S+) — (\d+) projet\(s\), outils : (.*?)(?:  \[config : (.*)\])?$")
    PHASE = re.compile(r"^Phase (\d+) : (?:(\d+) exécution\(s\)|(.*))$")
    ITEM = re.compile(r"^  \((\d+)/(\d+)\) \[(\w+)\] (.+?) · ([^/\s]+)/(\S+) \(([\d.]+)s\) ?(.*)$")
    CRIT = re.compile(r"^  \((\d+)/(\d+)\) \[([a-z_]+)(?: \((\d+)%\))?\] (.*)$")
    WARN = re.compile(r"^  [!⚠] (.*)$")
    UNPACK = re.compile(r"^  \[(\w+)\] (.+?) · archive (.*)$")
    END = re.compile(r"^Terminé : (\w+) \((\d+) ok/ignorées, (\d+) à examiner\)$")
    KV = re.compile(r"^(Liens entre projets|Recoupement|Critique IA) : (.*)$")
    KV_ICON = {"Liens entre projets": ("link", "Liens entre projets"), "Recoupement": ("alloy", "Alliage"), "Critique IA": ("gem", "Orfèvrerie")}

    def __init__(self, ui: Ui, db, root, label: str | None = None, animate: bool = True):
        self.ui, self.db, self.root, self.label = ui, db, root, label
        self.live = Live(ui, animate)
        self.lock = threading.RLock()
        self.phase: dict[str, Any] | None = None
        self.unmatched: list[str] = []
        self.status: str | None = None
        self.counts = (0, 0)
        self.run_id: str | None = None
        self.t0 = time.monotonic()

    def __enter__(self) -> "RunPrinter":
        self.live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        with self.lock:
            self._end_phase()
        self.live.__exit__(*exc)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.t0

    # --- entrées ------------------------------------------------------------------------------
    def progress(self, done: int, total: int, phase: int) -> None:
        with self.lock:
            if self.phase and self.phase["n"] == phase:
                self.phase.update(done=done, total=total)
                self.live.refresh()

    def log(self, line: str) -> None:
        with self.lock:
            if not self._dispatch(line):
                self.unmatched.append(line)
                self.live.print("  " + self.ui.c(line.strip(), "ash"))

    # --- mise en scène ------------------------------------------------------------------------
    def _dispatch(self, line: str) -> bool:
        ui = self.ui
        if m := self.END.match(line):
            self._end_phase()
            self.status, self.counts = m.group(1), (int(m.group(2)), int(m.group(3)))
            return True
        if m := self.RUN.match(line):
            self._banner(*m.groups())
            return True
        if m := self.PHASE.match(line):
            self._start_phase(int(m.group(1)), int(m.group(2)) if m.group(2) else 0)
            return True
        if m := self.ITEM.match(line):
            i, n, status, project, tool, mode, dur, detail = m.groups()
            icon, style = STATUS.get(status, ("warn", "gold"))
            if self.phase:
                self.phase.update(done=int(i), total=int(n))
            # largeurs adaptatives : projet et outil se partagent la place ; le détail est tronqué, voire abandonné, en terminal étroit
            room = ui.width - 2 - 2 - 1 - 8 - 2
            pw = min(16, max(8, room * 2 // 5))
            tw = min(26, max(10, room - pw - 1))
            left = (f"  {ui.icon(icon, style + ' bold')} {pad(ui.c(clip(project, pw), 'bold'), pw)} {pad(clip(f'{tool}/{mode}', tw), tw)} "
                    f"{ui.c(pad(f'{float(dur):.2f} s', 8, '>'), 'ash')}")
            left_w = cell_width(left)
            shown = clip(detail, ui.width - left_w - 2) if ui.width - left_w - 2 > 3 else ""
            self.live.print((left + (f"  {ui.c(shown, 'ash' if status == 'ok' else style)}" if shown else "")).rstrip())
            return True
        if (m := self.CRIT.match(line)) and m.group(3) in VERDICT:
            i, n, verdict, conf, rest = m.groups()
            icon, style, label = VERDICT[verdict]
            if self.phase and self.phase["n"] == 5:
                self.phase.update(done=int(i), total=int(n))
            shown = f"{label}{f' {conf} %' if conf else ''}"
            self.live.print(f"  {ui.icon(icon, style + ' bold')} {ui.c(pad(shown, 18), style)} {rest}")
            return True
        if m := self.WARN.match(line):
            self.live.print(f"  {ui.icon('warn', 'gold bold')} {ui.c(m.group(1), 'gold')}")
            return True
        if m := self.UNPACK.match(line):
            status, project, archive = m.groups()
            icon, style = STATUS.get(status, ("ok", "ok") if status in ("unpacked", "extracted") else ("warn", "gold"))
            self.live.print(f"  {ui.icon('package')} {ui.c(project, 'bold')} {ui.c('archive ' + archive, 'ash')}")
            return True
        if m := self.KV.match(line):
            key, rest = m.groups()
            icon, title = self.KV_ICON[key]
            if key == "Critique IA" and "à examiner par" in rest:  # début de la critique : la phase 5 est ouverte, on la garde (barre de progression)
                self.live.print(f"  {ui.c(rest, 'iron')}")
                return True
            self._end_phase()
            self.live.print(f"{ui.lead(icon, 'ember')}{ui.c(title, 'bold ember')}  {ui.c(rest, 'iron')}")
            return True
        if line.startswith("Interrompu"):
            self.live.print(f"{ui.icon('warn', 'gold bold')} {ui.c(line, 'gold')}")
            return True
        return False

    def _banner(self, run_id: str, n_projects: str, tools: str, config: str | None) -> None:
        ui, self.run_id = self.ui, run_id
        try:
            mission, audit = self.db.get_mission(), self.db.get_audit(run_id)
        except Exception:  # noqa: BLE001 — l'en-tête ne doit jamais faire échouer un passage
            mission, audit = None, None
        label = (audit or {}).get("label") or self.label
        who = " · ".join(x for x in (f"mission « {mission['name']} »" if mission else None, f"passage « {label} »" if label else None, run_id) if x)
        tool_list = tools.replace(", ", " · ")
        lines = [who, f"{self.root}  ·  {plural(int(n_projects), 'projet')}  ·  {plural(len(tools.split(', ')), 'outil')}"]
        lines.append(clip(tool_list, ui.width - 6))
        if config:
            lines.append(f"config {config}")
        with self.lock:
            ui.banner(lines)
            ui.say()

    def _start_phase(self, n: int, total: int) -> None:
        self._end_phase()
        icon, title, sub = PHASES.get(n, ("hammer", f"Phase {n}", ""))
        self.phase = {"n": n, "done": 0, "total": total, "t0": time.monotonic(), "icon": icon, "title": title}
        suffix = f"  ({plural(total, 'exécution')})" if total else ""
        self.live.print(self.ui.head(icon, title, sub + suffix))
        self.live.set(self._render)

    def _render(self, frame: int) -> str:
        p, ui = self.phase, self.ui
        if not p:
            return ""
        return f"  {self.live.spinner()} {ui.bar(p['done'], p['total'])} {p['done']}/{p['total']}  {ui.c(human_duration(time.monotonic() - p['t0']), 'ash')}"

    def _end_phase(self) -> None:
        p = self.phase
        if not p:
            return
        self.phase = None
        self.live.set(None)
        if p["total"]:
            self.live.print(f"  {self.ui.icon('ok', 'ok')} {self.ui.bar(p['done'], p['total'])} {p['done']}/{p['total']}  "
                            f"{self.ui.c(human_duration(time.monotonic() - p['t0']), 'ash')}")
        self.live.print("")


def summary(ui: Ui, db, run_id: str, printer: RunPrinter) -> None:
    """Le fruit de la forge : ce qui a été trouvé (en constats, doublons recoupés), l'état des exécutions, et la suite."""
    t = tally(db, run_id)
    ok_n, bad_n = printer.counts

    room = ui.width - 6 - 3 - 14   # largeur disponible pour le détail : cadre, icône, libellé

    def row(icon: str, label: str, *parts: str) -> str:
        return f"{ui.lead(icon)}{pad(ui.c(label, 'bold'), 14)}{fit(ui, list(parts), room)}"

    def found(kind: str, extra: str = "") -> list[str]:
        d = t[kind]
        if not d["groups"]:
            return [ui.c("aucun", "ash")]
        dup = ui.c(f"{d['detections']} détections recoupées", "ash") if d["detections"] != d["groups"] else ""
        return [pad(plural(d["groups"], "constat"), 11), sev_text(ui, d["sev"]), extra, dup]
    deps = len(db.entities(run_id, "dependency"))
    runs_line = f"{ui.icon('ok', 'ok bold')} {plural(ok_n, 'exécution')} ok" + (f"   {ui.icon('warn', 'gold bold')} {ui.c(str(bad_n) + ' à examiner', 'gold')}" if bad_n else "")
    status = "Terminé" if printer.status == "complete" else "Terminé avec des points à examiner"
    lines = [row("key", "Secrets", *found("secret")), row("sword", "SAST", *found("sast_finding")),
             row("package", "Dépendances", *found("vulnerability", ui.c(plural(deps, "composant"), "ash") if deps else "")), "",
             fit(ui, [runs_line, ui.c(human_duration(printer.elapsed), "ash")], ui.width - 6, "   ")]
    ui.lines(ui.panel(f"{status} — le fruit de la forge", lines, icon="gem", style="ok" if not bad_n else "gold"))
    problems = [r for r in db.list_tool_runs(run_id) if r["status"] not in ("ok", "skipped")]
    names = {p["id"]: p["name"] for p in db.list_projects(run_id)}
    for r in problems[:5]:
        ui.say(f"  {ui.icon('warn', 'gold bold')} {ui.c(names.get(r['project_id'], '?') + ' · ' + r['tool'] + '/' + r['mode'], 'bold')} {ui.c(str(r['error'] or r['status'])[:ui.width - 30], 'gold')}")
    if len(problems) > 5:
        ui.say(f"  {ui.c(f'… et {len(problems) - 5} autre(s) : aule show', 'ash')}")
    ui.say()
    ui.say("  " + fit(ui, [f"{ui.lead('forge', 'ember')}{ui.c('Suite', 'bold ember')}", f"{ui.c('aule serve --open', 'bold')}  {ui.c('explorer et trier', 'ash')}",
                         f"{ui.c('aule report --share', 'bold')}  {ui.c('partager', 'ash')}"], ui.width - 3, "   "))


# ---------------------------------------------------------------------------------------- autres écrans
def status_chip(ui: Ui, status: str) -> Raw:
    icon, style = {"complete": ("ok", "ok"), "partial": ("warn", "gold"), "failed": ("fail", "flame"), "running": ("run", "ember")}.get(status, ("dot", "iron"))
    return Raw(f"{ui.icon(icon, style + ' bold')} {ui.c(status, style)}")


def runs(ui: Ui, db) -> None:
    mission = db.get_mission()
    ui.heading("scroll", "Passages", f"mission « {mission['name']} »" + (f" · client {mission['client']}" if mission["client"] else "") if mission else "")
    ui.say()
    rows = [[S(a["label"] or "—", "bold" if a["label"] else "ash"), S(a["id"], "ash"), status_chip(ui, a["status"]), S(a["root"], "iron")] for a in db.list_audits()]
    ui.lines(ui.table([Col("Passage"), Col("Identifiant"), Col("Statut"), Col("Dossier", flex=True, min=12)], rows) if rows else [ui.c("  Aucun passage. Lancez : aule run <dossier>", "ash")])


def show(ui: Ui, db, run_id: str, project: str | None = None) -> None:
    audit, mission = db.get_audit(run_id), db.get_mission()
    ui.heading("scroll", f"Passage {display_name(audit)}", " · ".join(x for x in (f"mission « {mission['name']} »" if mission else None, audit["id"] if audit["label"] else None, audit["status"]) if x))
    ui.say("  " + ui.c(clip(str(audit["root"]), ui.width - 3), "ash"))
    ui.say()
    for p in db.list_projects(run_id):
        if project and project not in (p["name"], p["parent"]):
            continue
        t = tally(db, run_id, p["id"])
        git = f"git @ {p['head_commit'][:8]}" if p["head_commit"] else ("git" if p["is_git"] else "hors git")
        origin = f"   ↳ archive {p['origin']}" if p["parent"] else ""
        ui.say(f"{'  ' if p['parent'] else ''}{ui.lead('mountain', 'ember')}{ui.c(p['name'], 'bold ember')}  {ui.c(git + origin, 'ash')}")

        def line(icon: str, label: str, *parts: str) -> None:
            ui.say(f"   {ui.lead(icon)}{pad(ui.c(label, 'iron'), 13)}{fit(ui, list(parts), ui.width - 3 - 3 - 13 - 1)}")
        techs = sorted(db.entities(run_id, "technology", p["id"]), key=lambda e: -e["data"]["code"])
        if techs:
            langs = [f"{e['data']['language']} {e['data']['code']:,}".replace(",", " ") for e in techs[:6]]
            while len(langs) > 1 and cell_width(" · ".join(langs)) > ui.width - 24:
                langs.pop()
            line("brick", "Technologies", " · ".join(langs) + (f" · +{len(techs) - len(langs)}" if len(techs) > len(langs) else ""))
        secrets = db.entities(run_id, "secret", p["id"])
        modes = Counter(s["data"]["mode"] for s in secrets)
        d = t["secret"]
        dup = f" · {d['detections']} détections recoupées" if d["detections"] != d["groups"] else ""
        line("key", "Secrets", *([plural(d["groups"], "constat"), sev_text(ui, d["sev"]), ui.c("(" + " · ".join(f"{m} {c}" for m, c in sorted(modes.items())) + ")" + dup, "ash")] if d["groups"] else [ui.c("aucun", "ash")]))
        runs_ = db.list_tool_runs(run_id, p["id"])
        if t["sast_finding"]["groups"] or any(r["tool"] in ("opengrep", "codeql") and r["status"] == "ok" for r in runs_):
            line("sword", "SAST", *([plural(t["sast_finding"]["groups"], "constat"), sev_text(ui, t["sast_finding"]["sev"])] if t["sast_finding"]["groups"] else [ui.c("aucun", "ash")]))
        deps = db.entities(run_id, "dependency", p["id"])
        v = t["vulnerability"]
        if deps or v["groups"]:
            line("package", "Dépendances", *([plural(len(deps), "composant"), plural(v["groups"], "vulnérabilité"), sev_text(ui, v["sev"])] if v["groups"] else [plural(len(deps), "composant"), ui.c("aucune vulnérabilité", "ok")]))
        commits = db.entities(run_id, "commit", p["id"])
        if commits:
            line("scroll", "Historique", plural(len(commits), "commit") + " reconstruit(s)")
        ok = sum(1 for r in runs_ if r["status"] == "ok")
        bad = [r for r in runs_ if r["status"] not in ("ok", "skipped")]
        line("wrench", "Exécutions", f"{ui.icon('ok', 'ok')} {ok} ok", f"{ui.icon('warn', 'gold bold')} {ui.c(str(len(bad)) + ' à examiner', 'gold')}" if bad else "")
        for r in bad:
            name = r["tool"] + "/" + r["mode"]
            problem = str(r["error"] or r["status"]).replace("\n", " ")
            ui.say(f"       {ui.icon('warn', 'gold')} {ui.c(name, 'bold')} {ui.c(clip(problem, max(10, ui.width - 10 - cell_width(name) - 3)), 'gold')}")
        if project:  # détail par résultat (comme le texte historique avec --project)
            for s in secrets:
                d = s["data"]
                where = f"{d['file']}:{d['start_line']}" + (f" @ {d['commit'][:8]}" if d.get("commit") else "")
                ui.say(f"     {ui.icon('key')} {ui.c(pad('[' + d['mode'] + ']', 10), 'ash')} {pad(d['rule_id'], 20)} {pad(where, 34)} {ui.c(d['secret_masked'], 'flame')}  {ui.c(s['triage_status'] or '', 'ash')}")
            for f in db.entities(run_id, "sast_finding", p["id"]):
                d = f["data"]
                ui.say(f"     {ui.icon('sword')} {ui.c(pad(d['severity'], 10), sev_style(d['severity']))} {pad(str(d.get('tool') or '?'), 12)} {pad(d['rule_id'], 34)} {ui.c(str(d['file']) + ':' + str(d['start_line']), 'ash')}")
            for v_ in db.entities(run_id, "vulnerability", p["id"]):
                d = v_["data"]
                ui.say(f"     {ui.icon('package')} {ui.c(pad(d['severity'], 10), sev_style(d['severity']))} {pad(d['id'], 20)} {d['dependency']['name']} {ui.c(d['dependency']['version'] or '', 'ash')}")
        ui.say()


def tools(ui: Ui, rows: list[dict[str, Any]], source: str | None) -> None:
    ui.heading("toolbox", "Atelier", f"configuration {source}" if source else "aucune configuration (valeurs par défaut)")
    ui.say()
    table = []
    for r in rows:
        if not r["found"] and not r["enabled"]:  # option non activée et non installée : ce n'est pas une erreur
            state = Raw(f"{ui.icon('skip', 'ash')} {ui.c('option', 'ash')}")
            where = S("non installé (activez-la avec --with ou dans aule.yaml)", "ash")
        elif not r["found"]:
            state = Raw(f"{ui.icon('fail', 'flame bold')} {ui.c('introuvable', 'flame')}")
            where = S(f"« {r['wanted']} »", "flame")
        else:
            state = Raw(f"{ui.icon('ok', 'ok bold')} {ui.c('activé', 'ok')}") if r["enabled"] else Raw(f"{ui.icon('skip', 'ash')} {ui.c('option', 'ash')}")
            where = S(r["path"], "iron")
        table.append([S(r["name"], "bold"), state, S(r["modes"], "ash"), where, S(r["version"] or "", "ash")])
    ui.lines(ui.table([Col("Outil"), Col("État"), Col("Modes", flex=True, min=10), Col("Chemin", flex=True, min=24), Col("Version", flex=True, min=8)], table))
    for r in rows:
        if not r["found"] and r["enabled"]:  # deux lignes courtes, jamais tronquées : ce qui est cherché, puis quoi faire
            ui.say(f"  {ui.icon('arrow', 'ash')} {ui.c(r['name'] + ' :', 'bold')} {ui.c('cherché : ' + r['wanted'], 'ash')}")
            ui.say("    " + ui.c(f"ajoutez-le au PATH ou renseignez tools.{r['name']}.path dans aule.yaml", "ash"))
    ui.say()


def doctor(ui: Ui, checks, kept, strict: bool) -> None:
    icon = {"PASS": ("ok", "ok"), "WARN": ("warn", "gold"), "FAIL": ("fail", "flame"), "SKIP": ("skip", "ash")}
    rows = [[Raw(ui.icon(icon[c.status][0], icon[c.status][1] + " bold")), S(c.name, "bold"), S(c.status, icon[c.status][1]), S(c.detail, "iron" if c.status == "PASS" else icon[c.status][1]),
             S(f"{c.seconds} s" if c.seconds else "", "ash")] for c in checks]
    ui.lines(ui.table([Col(""), Col("Outil"), Col("Résultat"), Col("Détail", flex=True, min=16), Col("Durée", ">")], rows))
    for c in checks:
        if c.hint:
            ui.say(f"    {ui.icon('arrow', 'ash')} {ui.c(c.name + ' :', 'bold')} {ui.c(c.hint, 'ash')}")
    n = Counter(c.status for c in checks)
    parts = [f"{ui.icon('ok', 'ok bold')} {n['PASS']} ok", f"{ui.icon('warn', 'gold bold')} {n['WARN']} avertissement(s)", f"{ui.icon('fail', 'flame bold')} {n['FAIL']} échec(s)", f"{ui.icon('skip', 'ash')} {n['SKIP']} ignoré(s)"]
    bad = n["FAIL"] or (strict and n["WARN"])
    ui.say()
    ui.lines(ui.panel("Banc d'essai", ["   ".join(parts)] + ([f"{ui.c('Données de test conservées :', 'ash')} {kept}"] if kept else []), icon="search", style="flame" if bad else "ok"))


def diff(ui: Ui, d: dict[str, Any], show_persistent: bool = False) -> None:
    """Le comparatif de deux passages, à partir de ses données : nouveau en rouge, corrigé en vert, persistant en cendre."""
    from .diff import KIND_NAMES
    icons = {"secret": "key", "sast_finding": "sword", "vulnerability": "package"}
    ui.heading("scales", "Comparaison", f"A = {d['a']}  →  B = {d['b']}")
    c = d["counts"]
    ui.say("  " + fit(ui, [ui.c(f"{ui.icon('fail')} {c['new']} nouveau(x)", "flame bold" if c["new"] else "ash"), ui.c(f"{ui.icon('ok')} {c['fixed']} corrigé(s)", "ok bold" if c["fixed"] else "ash"),
                          ui.c(f"{ui.icon('dot')} {c['persistent']} persistant(s)", "ash")], ui.width - 3, "   "))
    notes = [f"Projets ajoutés dans B (leurs résultats comptent comme nouveaux) : {', '.join(d['projects_added'])}" if d["projects_added"] else "",
             f"Projets absents de B (non comptés comme corrigés) : {', '.join(d['projects_removed'])}" if d["projects_removed"] else "",
             *[f"Non comparable : {item}" for item in d["not_comparable"]]]
    for note in filter(None, notes):
        ui.say(f"  {ui.icon('warn', 'gold bold')} {ui.c(clip(note, ui.width - 5), 'gold')}")
    for kind, k in d["kinds"].items():
        ui.say()
        ui.say(ui.head(icons.get(kind, "hammer"), KIND_NAMES.get(kind, kind), f"+{k['counts']['new']} / -{k['counts']['fixed']} / ={k['counts']['persistent']}"))
        for section, sign, style in (("new", "+", "flame"), ("fixed", "-", "ok"), *((("persistent", "=", "ash"),) if show_persistent else ())):
            for r in sorted(k[section], key=lambda r: (r["project"], r["location"])):
                room = ui.width - 4 - 10 - 2 - 14 - 1 - 8 - 2
                tail = clip(f"{r['label']}  {r['location']}" + (f"  [{r['triage']}]" if r["triage"] else ""), max(0, room))
                ui.say(f"  {ui.c(sign, style + ' bold')} {ui.c(r['fingerprint'][:10], 'ash')}  {pad(ui.c(clip(r['project'], 14), 'bold'), 14)} "
                       f"{pad(ui.c(r['severity'], sev_style(r['severity'])), 8)}  {ui.c(tail, style if sign != '=' else 'ash')}".rstrip())


def triage_list(ui: Ui, rows: list[dict[str, Any]], comments: dict, run_id: str) -> None:
    style = {"confirmed": "flame", "to_review": "gold", "false_positive": "ash", "accepted_risk": "info"}
    table = []
    for e in rows:
        note = (comments.get(e["fingerprint"]) or {}).get("comment") or ""
        table.append([S(e["fingerprint"][:10], "ash"), Raw(ui.c(e["triage_status"], style.get(e["triage_status"], "iron") + " bold")), S(e["project"], "bold"),
                      Raw(ui.c(e["severity"], sev_style(e["severity"]))), S(f"{e['label']}  {e['location']}"), S(note, "ash")])
    ui.heading("hammer", "Trempe", f"{plural(len(rows), 'élément')} trié(s) dans {run_id}")
    ui.say()
    if rows:
        ui.lines(ui.table([Col("Empreinte"), Col("Triage"), Col("Projet"), Col("Gravité"), Col("Constat", flex=True, min=20), Col("Commentaire", flex=True, min=10)], table))


REL_FR = {"depends_on": "dépend de", "shared_secret": "secret partagé", "same_remote": "même dépôt d'origine", "shared_endpoint": "hôte commun", "extracted_from": "extrait de"}
REL_STYLE = {"depends_on": "info", "shared_secret": "flame", "same_remote": "ok", "shared_endpoint": "ember", "extracted_from": "ash"}
REL_DIRECTED = {"depends_on", "extracted_from"}


def link_detail(r: dict[str, Any]) -> str:
    d, t = r["data"], r["type"]
    if t == "depends_on":
        return "via " + ", ".join(d.get("via", []))
    if t == "shared_secret":
        return f"{d.get('count')} secret(s) : " + ", ".join(f"{s['rule']} {s['masked']}" for s in d.get("secrets", [])[:3])
    if t == "same_remote":
        return str(d.get("remote") or "")
    if t == "shared_endpoint":
        return f"{d.get('count')} hôte(s) : " + ", ".join(d.get("hosts", [])[:3])
    return f"archive {d.get('archive')}" if t == "extracted_from" else ""


def links(ui: Ui, rels: list[dict[str, Any]], names: dict[int, str], run_id: str) -> None:
    """Les liens, en arborescence par projet : une branche par relation, colorée comme dans le graphe de l'interface web."""
    ui.heading("link", "Liens", f"{plural(len(rels), 'relation')} dans {run_id}")
    by_src: dict[str, list[dict[str, Any]]] = {}
    for r in sorted(rels, key=lambda r: (r["type"], names.get(r["dst_id"], ""))):
        by_src.setdefault(names.get(r["src_id"], "?"), []).append(r)
    mid, last = ("├─ ", "└─ ") if ui.unicode else ("|- ", "`- ")
    for project in sorted(by_src):
        ui.say()
        ui.say(f"{ui.lead('mountain', 'ember')}{ui.c(project, 'bold ember')}")
        for i, r in enumerate(by_src[project]):
            arrow, branch = ("→" if r["type"] in REL_DIRECTED else "↔"), (mid if i < len(by_src[project]) - 1 else last)
            label, dst = pad(REL_FR.get(r["type"], r["type"]), 22), names.get(r["dst_id"], "?")
            head = f"{ui.c(branch, 'ash')}{ui.c(label, REL_STYLE.get(r['type'], 'iron') + ' bold')} {arrow} {ui.c(dst, 'bold')}"
            room = ui.width - 6 - cell_width(f"{branch}{label} {arrow} {dst}")
            detail = clip(link_detail(r), room) if room >= 12 else ""  # on tronque (…) plutôt que de perdre le détail
            ui.say("  " + head + (f"  {ui.c(detail, 'ash')}" if detail else ""))
    ui.say()
    ui.hint(clip("graphe interactif : aule serve --open, onglet Liens", ui.width - 6))


def correlate_groups(ui: Ui, groups: list[dict[str, Any]], total: int) -> None:
    icon = {"secret": "key", "sast_finding": "sword", "vulnerability": "package"}
    table = [[Raw(ui.icon(icon[g["kind"]])), S(g["project"], "bold"), S(g["where"]), S(g["what"], "iron"), Raw(ui.c(f"×{g['n']}", "ember bold")), S(g["seen"], "ash"), S(", ".join(g["reasons"]), "ash")] for g in groups]
    if table:
        ui.lines(ui.table([Col(""), Col("Projet"), Col("Où", flex=True, min=14), Col("Quoi", flex=True, min=12), Col("Dét.", ">"), Col("Vu par", flex=True, min=14), Col("Raison", flex=True, min=8)], table))
    ui.say(f"  {ui.c(plural(total, 'groupe') + ' de plusieurs détections', 'ash')}")
