from __future__ import annotations

import argparse
import getpass
import os
import shlex
import subprocess
import sys
import tempfile
import webbrowser
from collections import Counter
from pathlib import Path

from . import cli_pretty as pretty
from .ui import ui
from .config import CRITIQ_KINDS, Config, ConfigError, load_config
from .correlate import correlate_run, compute_clusters
from .critiq import _slug, apply_critiques, run_critique, select_applicable
import dataclasses
import json
import shutil

from .db import FINDING_STATUSES, SEVERITIES, TRIAGE_STATUSES, Database
from .export import FORMATS, ExportError, collect, write_export
from .links import LINK_TYPES, compute_relations, describe
from .llm import LLMError, PROBE_MESSAGE as PROBE_TEXT, make_provider, public_url
from .llmconf import migrate
from .diff import DEFAULT_KINDS, diff_runs, format_diff
from .doctor import run_doctor, summarize
from .orchestrator import AuditError, reparse, run_audit
from .plugins import ToolError, load_plugins, select_tools
from .purge import apply_purge, human, plan_purge
from .rawview import import_sarif
from .runs import RunRefError, display_name, resolve_run
from .seal import SealError, seal, unseal, verify
from .server import make_server
from .report import render_report
from .runner import tool_version
from .triage import KINDS, find_entities, resolve_prefixes


def _n(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def cmd_run(args, db: Database, config: Config) -> int:
    split = lambda text: [n.strip() for n in text.split(",") if n.strip()]  # noqa: E731
    names = split(args.tools) if args.tools else None
    if args.more_code:
        config = dataclasses.replace(config, critiq=dataclasses.replace(config.critiq, allow_more_code=True))
    try:
        extra = split(args.with_tools or "") + (["gittools"] if args.history else [])  # outils optionnels à ajouter
        if extra:
            base = names or [t.name for t in select_tools(config)]
            names = [*base, *[n for n in extra if n not in base]]
        kwargs = dict(config=config, tool_names=names, jobs=args.jobs, timeout=args.timeout, resume=resolve_run(db, args.resume) if args.resume else None,
                      exclude=tuple(args.exclude or ()), unpack=True if args.unpack else None, critiq=True if args.critiq else None, label=args.name)
        if ui.forge:
            with pretty.RunPrinter(ui, db, args.root, args.name) as printer:
                run_id = run_audit(db, args.data, args.root, log=printer.log, progress=printer.progress, **kwargs)
            pretty.summary(ui, db, run_id, printer)
        else:
            run_audit(db, args.data, args.root, **kwargs)
    except (AuditError, ValueError) as exc:
        ui.error(f"{exc}")
        return 2
    except KeyboardInterrupt:
        return 130
    return 0


def cmd_runs(args, db: Database, config: Config) -> int:
    if ui.forge:
        pretty.runs(ui, db)
        return 0
    mission = db.get_mission()
    if mission:
        print(f"Mission : {mission['name']}" + (f"  (client : {mission['client']})" if mission["client"] else "") + "\n")
    for a in db.list_audits():
        print(f"{a['id']}  {a['status']:<11} {a['label'] or '-':<22} {a['root']}")
    return 0


def cmd_tools(args, db: Database | None, config: Config) -> int:
    if ui.forge:
        enabled = {t.name for t in select_tools(config)}
        rows = []
        for tool in load_plugins().values():
            cfg = config.tool(tool.name)
            exe = tool.resolve(cfg)
            rows.append({"name": tool.name, "enabled": tool.name in enabled, "modes": ",".join(tool.modes), "found": bool(exe), "path": " ".join(exe) if exe else "",
                         "wanted": tool.wanted(cfg), "version": (tool_version(tool, exe, cfg.env) or "") if exe else ""})
        pretty.tools(ui, rows, str(config.source) if config.source else None)
        return 0
    if config.source:
        print(f"Configuration : {config.source}\n")
    enabled = {t.name for t in select_tools(config)}
    registry = load_plugins()
    width = max(len(n) for n in registry)
    for tool in registry.values():
        cfg = config.tool(tool.name)
        exe = tool.resolve(cfg)
        state = "activé" if tool.name in enabled else "désactivé (option)"
        head = f"{tool.name:<{width}}  {state:<19} modes={','.join(tool.modes):<20}"
        if exe:
            print(f"{head} {' '.join(exe)}  {tool_version(tool, exe, cfg.env) or ''}")
        else:
            print(f"{head} INTROUVABLE : '{tool.wanted(cfg)}' -> renseignez tools.{tool.name}.path dans aule.yaml")
    return 0


def _selection(args, db: Database, run_id: str) -> list[dict]:
    """Éléments visés par `triage set/clear` : empreintes (préfixes) ou filtres."""
    prefixes = resolve_prefixes(db, run_id, list(args.fingerprints)) if args.fingerprints else ()
    return find_entities(db, run_id, kind=args.kind, project=args.project, rule=args.rule, severity=args.severity,
                         mode=args.mode, tool=args.tool, file_glob=args.file, untriaged=args.untriaged,
                         prefixes=tuple(prefixes))


def cmd_triage(args, db: Database, config: Config) -> int:
    run_id = resolve_run(db, args.run)
    if not run_id or not db.get_audit(run_id):
        print("Aucun audit. Lancez d'abord : aule run <dossier>", file=sys.stderr)
        return 1
    try:
        if args.triage_cmd == "list":
            rows = [e for e in find_entities(db, run_id, kind=args.kind, project=args.project) if e["triage_status"]
                    and (not args.status or e["triage_status"] == args.status)]
            comments = db.list_triage()
            if ui.forge:
                pretty.triage_list(ui, sorted(rows, key=lambda e: (e["project"], e["location"])), comments, run_id)
                return 0
            for e in sorted(rows, key=lambda e: (e["project"], e["location"])):
                note = (comments.get(e["fingerprint"]) or {}).get("comment")
                print(f"{e['fingerprint'][:10]}  {e['triage_status']:<15} {e['project']:<16} {e['severity']:<8} "
                      f"{e['label']}  {e['location']}" + (f"  — {note}" if note else ""))
            print(f"{len(rows)} élément(s) trié(s) dans {run_id}")
            return 0
        if not args.fingerprints and not any((args.kind, args.project, args.rule, args.severity, args.mode,
                                              args.tool, args.file, args.untriaged)):
            raise ValueError("indiquez des empreintes ou au moins un filtre (--kind, --project, --rule, --severity…)")
        targets = _selection(args, db, run_id)
        if not targets:
            print("Aucun résultat ne correspond.")
            return 1
        if not args.fingerprints and not args.yes:  # sélection par filtre : on montre avant d'appliquer
            for e in targets[:15]:
                print(f"  {e['fingerprint'][:10]}  {e['project']:<16} {e['label']}  {e['location']}")
            print(f"{len(targets)} élément(s) seraient modifiés. Ajoutez --yes pour appliquer.")
            return 0
        fps = [e["fingerprint"] for e in targets]
        extra = 0
        if not args.single:  # un constat = toutes ses détections identiques (même secret / même vulnérabilité vue par plusieurs outils)
            cmap = db.cluster_map(run_id)
            full = list(dict.fromkeys(m for fp in fps for m in (cmap[fp]["members"] if fp in cmap else [fp])))
            extra, fps = len(full) - len(fps), full
        more = f" (dont {extra} détection(s) identique(s) recoupée(s))" if extra else ""
        if args.triage_cmd == "set":
            db.set_triage_many(fps, args.status, args.comment)
            ui.ok(f"{len(fps)} élément(s) marqué(s) « {args.status} »{more}")
        else:
            db.clear_triage(fps)
            ui.ok(f"Triage effacé pour {len(fps)} élément(s){more}")
    except ValueError as exc:
        ui.error(f"{exc}")
        return 2
    return 0


def cmd_diff(args, db: Database, config: Config) -> int:
    runs = [a["id"] for a in db.list_audits()]  # du plus récent au plus ancien
    try:
        if args.runs and len(args.runs) != 2:
            raise ValueError("indiquez deux runs (A puis B) ou aucun pour comparer les deux derniers")
        if not args.runs and len(runs) < 2:
            raise ValueError("il faut au moins deux audits pour comparer")
        run_a, run_b = [resolve_run(db, r) for r in args.runs] if args.runs else [runs[1], runs[0]]
        kinds = tuple(KINDS[k] for k in args.kind.split(",")) if args.kind else DEFAULT_KINDS
        result = diff_runs(db, run_a, run_b, kinds)
    except KeyError as exc:
        ui.error(f"run inconnu : {exc.args[0]}")
        return 2
    except ValueError as exc:
        ui.error(f"{exc}")
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif ui.forge:
        pretty.diff(ui, result, args.all)
    else:
        print(format_diff(result, args.all))
    return 0


def cmd_links(args, db: Database, config: Config) -> int:
    run_id = resolve_run(db, args.run)
    if not run_id or not db.get_audit(run_id):
        print("Aucun audit. Lancez d'abord : aule run <dossier>", file=sys.stderr)
        return 1
    if not args.no_recompute:
        compute_relations(db, run_id, config.tool("links").options.get("ignore_hosts") or ())
    names = {p["id"]: p["name"] for p in db.list_projects(run_id)}
    rels = [r for r in db.list_relations(run_id) if not args.type or r["type"] == args.type]
    if args.project:
        rels = [r for r in rels if args.project in (names.get(r["src_id"]), names.get(r["dst_id"]))]
    if ui.forge:
        pretty.links(ui, rels, names, run_id)
        return 0
    for r in sorted(rels, key=lambda r: (r["type"], names.get(r["src_id"], ""), names.get(r["dst_id"], ""))):
        print(f"[{r['type']}] {describe(r, names)}")
    print(f"{len(rels)} lien(s) dans {run_id}")
    return 0


def _edit_text(initial: str = "") -> str:
    """Ouvre $VISUAL / $EDITOR sur un fichier temporaire et renvoie le texte saisi."""
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or ("notepad" if os.name == "nt" else "vi")
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(initial)
        path = f.name
    try:
        if subprocess.run([*shlex.split(editor), path]).returncode != 0:
            raise ValueError(f"l'éditeur {editor!r} a échoué : rien n'a été enregistré")
        return Path(path).read_text(encoding="utf-8")
    finally:
        os.unlink(path)


def _text_option(args, initial: str = "") -> str | None:
    """Texte donné par --text/--description, --file/--description-file (« - » = stdin) ou --edit ; None si rien."""
    inline = getattr(args, "text", None) if getattr(args, "text", None) is not None else getattr(args, "description", None)
    file = getattr(args, "file", None) or getattr(args, "description_file", None)
    if file:
        return sys.stdin.read() if str(file) == "-" else Path(file).read_text(encoding="utf-8")
    if inline is not None:
        return inline
    return _edit_text(initial) if getattr(args, "edit", False) else None


def _resolve_refs(db: Database, refs: list[str]) -> list[str]:
    """Préfixes d'empreintes -> empreintes complètes ; le reste (chemin:ligne, commit...) est gardé tel quel."""
    run_id = db.latest_audit_id()
    out = []
    for ref in refs:
        if run_id and len(ref) >= 6 and all(ch in "0123456789abcdef" for ch in ref.lower()):
            try:
                out.append(resolve_prefixes(db, run_id, [ref])[0])
                continue
            except ValueError as exc:
                if "ambigu" in str(exc):
                    raise
        out.append(ref)
    return out


def _print_finding(f: dict) -> None:
    print(f"#{f['id']}  [{f['severity']}] {f['title']}")
    print(f"projet : {f['project']} · statut : {f['status']} · créé {f['created_at']} · modifié {f['updated_at']}")
    if f["refs"]:
        print("références : " + ", ".join(f["refs"]))
    if f["description"].strip():
        print("\n" + f["description"].strip())


def cmd_finding(args, db: Database, config: Config) -> int:
    try:
        if args.finding_cmd == "list":
            rows = db.list_findings(args.project, args.status)
            for f in rows:
                print(f"#{f['id']:<4} {f['status']:<10} {f['severity']:<8} {f['project']:<16} {f['title']}")
            print(f"{len(rows)} constat(s)")
        elif args.finding_cmd == "show":
            f = db.get_finding(args.id)
            if not f:
                raise ValueError(f"constat inconnu : #{args.id}")
            _print_finding(f)
        elif args.finding_cmd == "rm":
            if not db.delete_finding(args.id):
                raise ValueError(f"constat inconnu : #{args.id}")
            print(f"Constat #{args.id} supprimé")
        elif args.finding_cmd == "add":
            fid = db.add_finding(args.project, args.title, args.severity, args.status,
                                 _text_option(args) or "", _resolve_refs(db, args.ref or []))
            print(f"Constat #{fid} créé")
        else:  # edit
            current = db.get_finding(args.id)
            if not current:
                raise ValueError(f"constat inconnu : #{args.id}")
            fields = {k: v for k, v in (("project", args.project), ("title", args.title), ("severity", args.severity),
                                        ("status", args.status)) if v is not None}
            if (text := _text_option(args, current["description"])) is not None:
                fields["description"] = text
            if args.ref:
                fields["refs"] = [*current["refs"], *[r for r in _resolve_refs(db, args.ref) if r not in current["refs"]]]
            db.update_finding(args.id, **fields)
            print(f"Constat #{args.id} mis à jour ({', '.join(fields) or 'rien à changer'})")
    except (ValueError, OSError) as exc:
        ui.error(f"{exc}")
        return 2
    return 0


def cmd_note(args, db: Database, config: Config) -> int:
    try:
        if args.note_cmd == "list":
            for project, n in db.list_notes().items():
                print(f"== {project}  (modifié {n['updated_at']})\n{n['text'].strip()}\n")
        elif args.note_cmd == "show":
            note = db.list_notes().get(args.project)
            print(note["text"].strip() if note else f"(aucune note pour {args.project})")
        else:
            text = _text_option(args, (db.list_notes().get(args.project) or {}).get("text", ""))
            if text is None:
                raise ValueError("indiquez --text, --file ou --edit")
            db.set_note(args.project, text)
            print(f"Note de {args.project} " + ("enregistrée" if text.strip() else "supprimée (texte vide)"))
    except (ValueError, OSError) as exc:
        ui.error(f"{exc}")
        return 2
    return 0


def cmd_export(args, db: Database, config: Config) -> int:
    run_id = resolve_run(db, args.run_id)
    if not run_id or not db.get_audit(run_id):
        print("Aucun audit à exporter. Lancez d'abord : aule run <dossier>", file=sys.stderr)
        return 1
    reveal = not args.mask
    try:
        statuses = [x.strip() for x in args.status.split(",")] if args.status else None
        bad = [x for x in statuses or [] if x not in (*TRIAGE_STATUSES, "untriaged", "draft", "dismissed")]
        if bad:
            raise ExportError(f"statut(s) inconnu(s) : {', '.join(bad)}")
        data = collect(db, run_id, args.data, reveal=reveal, include_false_positives=args.include_false_positives,
                       statuses=statuses, min_severity=args.min_severity, include_dismissed=args.include_dismissed)
        ext = "md" if args.format == "md" else args.format
        out = write_export(data, args.format, (args.output or args.data / f"export-{run_id}{'' if reveal else '-masque'}.{ext}").resolve())
    except ExportError as exc:
        ui.error(f"{exc}")
        return 2
    if reveal:
        try:
            out.chmod(0o600)
        except OSError:
            pass
    ui.ok(f"Export : {out}  ({len(data['rows'])} ligne(s))")
    for w in data["warnings"]:
        print(f"⚠ {w}")
    if reveal:
        ui.warn("Cet export contient des secrets EN CLAIR : ne le partagez pas. Version partageable : --mask",
                plain="⚠ Cet export contient des secrets EN CLAIR : ne le partagez pas. Version partageable : --mask")
    return 0


def cmd_doctor(args, db, config: Config) -> int:
    if ui.forge:
        ui.heading("search", "Banc d'essai", "données de test synthétiques, dossier temporaire")
        ui.say()
        log = lambda m: ui.say("  " + ui.c(m, "ash"), err=True)  # noqa: E731
    else:
        print("Vérification de l'installation (données de test synthétiques, dossier temporaire)…")
        log = lambda m: print(m, file=sys.stderr)  # noqa: E731
    try:
        checks, kept = run_doctor(config, args.data, only=args.tool, full=args.full, timeout=args.timeout, keep=args.keep, log=log)
    except ValueError as exc:
        ui.error(f"{exc}")
        return 2
    if ui.forge:
        pretty.doctor(ui, checks, kept, args.strict)
        n = summarize(checks)
        return 1 if n["FAIL"] or (args.strict and n["WARN"]) else 0
    icons = {"PASS": "✓", "WARN": "!", "FAIL": "✗", "SKIP": "-"}
    width = max(len(c.name) for c in checks)
    for c in checks:
        timing = f"  ({c.seconds}s)" if c.seconds else ""
        print(f"  {icons[c.status]} {c.name:<{width}}  {c.status}  {c.detail}{timing}")
        if c.hint:
            print(f"    → {c.hint}")
    n = summarize(checks)
    print(f"\nBilan : {n['PASS']} ok · {n['WARN']} avertissement(s) · {n['FAIL']} échec(s) · {n['SKIP']} ignoré(s)")
    if kept:
        print(f"Données de test conservées : {kept}")
    return 1 if n["FAIL"] or (args.strict and n["WARN"]) else 0


def cmd_purge(args, db: Database, config: Config) -> int:
    if not (args.run or args.older_than is not None or args.keep is not None or args.heavy):
        ui.error("indiquez --run, --older-than, --keep et/ou --heavy")
        return 2
    try:
        doomed, items = plan_purge(db, args.data, runs=[resolve_run(db, r) for r in args.run or []] or None, older_than_days=args.older_than, keep=args.keep, heavy=args.heavy)
    except ValueError as exc:
        ui.error(f"{exc}")
        return 2
    for it in items:
        print(f"  {human(it.size):>9}  {it.kind:<9} {it.run}  {it.path.relative_to(args.data)}")
    total = sum(i.size for i in items)
    print(f"{len(doomed)} run(s) supprimé(s) de la base, {len(items)} élément(s), {human(total)}. "
          "Triage, constats et notes sont conservés.")
    if not args.yes:
        print("Plan seulement : ajoutez --yes pour appliquer.")
        return 0
    print(f"Libéré : {human(apply_purge(db, args.data, doomed, items))}")
    return 0


def _passphrase(args, confirm: bool) -> str:
    if args.passphrase_file:
        return Path(args.passphrase_file).read_text(encoding="utf-8").rstrip("\n")
    for var in ("AULE_PASSPHRASE", "AUDIT_PASSPHRASE"):  # le second est l'ancien nom, toujours accepté
        if os.environ.get(var):
            return os.environ[var]
    try:
        phrase = getpass.getpass("Phrase secrète : ")
        if confirm and getpass.getpass("Confirmez : ") != phrase:
            raise SealError("les deux saisies diffèrent")
    except (EOFError, KeyboardInterrupt):
        raise SealError("phrase secrète requise : $AULE_PASSPHRASE, --passphrase-file, ou un terminal interactif") from None
    return phrase


def cmd_seal(args, db, config: Config) -> int:
    try:
        out = args.output or args.data.with_name(args.data.name + ".tar.gz.gpg")
        phrase = _passphrase(args, confirm=True)
        path = seal(args.data, out, phrase)
        files = verify(path, phrase)  # on relit tout avant de parler de suppression
        print(f"Chiffré : {path}  ({files} fichier(s) vérifié(s))")
        if args.remove:
            shutil.rmtree(args.data)
            print(f"{args.data} supprimé. ⚠ Effacement non sécurisé (SSD, journalisation, sauvegardes) : "
                  "pour une vraie protection, chiffrez le volume qui héberge data/.")
    except SealError as exc:
        ui.error(f"{exc}")
        return 2
    return 0


def cmd_unseal(args, db, config: Config) -> int:
    try:
        dest = unseal(args.archive, args.to or Path.cwd(), _passphrase(args, confirm=False))
        print(f"Déchiffré dans {dest}")
    except SealError as exc:
        ui.error(f"{exc}")
        return 2
    return 0


def cmd_serve(args, db, config: Config) -> int:
    try:
        server = make_server(args.data / "audit.db", args.data, config, host=args.host, port=args.port,
                             reveal=not args.mask, allowed_hosts=tuple(args.allowed_host or ()))
    except (ValueError, OSError) as exc:
        ui.error(f"{exc}")
        return 2
    port = server.server_address[1]
    url = f"http://localhost:{port}/"
    if ui.forge:
        ui.banner([f"serveur de travail  {url}", "Ctrl+C pour arrêter"])
        (ui.warn("Les secrets sont affichés EN CLAIR.") if not args.mask else ui.say(f"{ui.icon('shield', 'ok')} {ui.c('Secrets masqués : « révéler » à la demande, valeur par valeur.', 'ok')}"))
    else:
        print(f"Serveur de travail : {url}   (Ctrl+C pour arrêter)", flush=True)
        print("⚠ Les secrets sont affichés EN CLAIR." if not args.mask else "Secrets masqués : « révéler » à la demande, valeur par valeur.", flush=True)
    print("Écoute sur la boucle locale uniquement. Accès distant : ssh -L, puis --allowed-host.", flush=True)
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt.")
    finally:
        server.server_close()
    return 0


def _sent_label(x: dict) -> str:
    """Ce qui a été servi au modèle : une recherche, la liste d'un dossier, ou une plage de fichier."""
    if x.get("search"):
        return f"recherche « {x['search']} » ({x.get('matches')} occurrence(s))"
    if x.get("kind") in ("list", "refused") and x.get("list") is not None:
        return f"liste du dossier « {x['list']} » ({x.get('entries', 0)} entrée(s))"
    return f"{x.get('file')}:{x.get('start')}-{x.get('end')}"


def cmd_llm_migrate(args, db, config) -> int:
    """Travaille sur le fichier BRUT : l'ancien format (réglages du moteur dans `critiq`) est refusé au chargement, donc cette commande passe avant."""
    from .config import DEFAULT_CONFIG_NAME, LEGACY_CONFIG_NAME, ConfigError
    path = args.config or next((c for c in (Path.cwd() / DEFAULT_CONFIG_NAME, Path.cwd() / LEGACY_CONFIG_NAME) if c.is_file()), None)
    if path is None or not path.is_file():
        ui.error("aucun aule.yaml à migrer (indiquez --config)")
        return 2
    out = args.out or path.resolve().parent / "llm.yaml"
    try:
        notes, keys = migrate(path, out, force=args.force)
    except ConfigError as exc:
        ui.error(str(exc))
        return 2
    ui.ok(f"{out} créé (droits 600) à partir de la section critiq de {path}")
    for note in notes:
        ui.warn(note)
    ui.say(f"À faire : supprimez de la section critiq de {path} ces clés, désormais dans llm.yaml : {', '.join(keys)}")
    ui.warn("llm.yaml contient la clé d'API : ne le versionnez pas (ajoutez-le à .gitignore)")
    return 0


def _critiq_check(args, config: Config) -> int:
    """Vérifie le moteur IA (connexion, jeton, modèle / agent) SANS envoyer de code."""
    if config.llm is None:
        ui.error("aucun moteur configuré : créez llm.yaml (voir llm.example.yaml, ou `aule llm migrate` pour reprendre l'ancienne section critiq)")
        return 2
    llm = dataclasses.replace(config.llm, model=args.model or config.llm.model)
    if ui.forge:
        ui.heading("search", "Moteur IA", "vérification de la connexion : aucun code n'est envoyé")
        ui.say()
    try:
        provider = make_provider(llm)
        for line in provider.describe():
            (ui.warn(line.removeprefix("⚠ "), plain=line) if line.startswith("⚠ ") else ui.say(("  " + ui.icon("dot", "ember") + " " + line) if ui.forge else line))
        ids = provider.check()
    except LLMError as exc:
        ui.error(str(exc))
        return 2
    if provider.name == "custom" and not llm.check_url:
        ui.ok("Configuration valide (aucune requête envoyée : check_url absent de llm.yaml). Essai réel, sans code : aule critiq check --probe")
    else:
        ui.ok(f"Connexion établie : {provider.label} « {provider.model} » disponible ({len(ids)} {provider.label}(s) visible(s) avec ce jeton)." + (" Aucun code n'a été envoyé." if not ui.forge else ""))
    if args.probe:
        probe = getattr(provider, "probe", None)
        if probe is None:
            ui.error("--probe : disponible avec provider: custom seulement")
            return 2
        try:
            reply = probe()
        except LLMError as exc:
            ui.error(f"essai en échec : {exc}")
            return 2
        ui.ok(f"Réponse du modèle à « {PROBE_TEXT} » : {reply.strip()[:120]} ({provider.tokens} jeton(s))")
    ui.hint("Aucun code n'a été envoyé. Essai réel : aule critiq run --max 3")
    return 0


def cmd_critiq(args, db: Database, config: Config) -> int:
    if args.critiq_cmd == "check":
        return _critiq_check(args, config)
    run_id = resolve_run(db, args.run)
    if not run_id or not db.get_audit(run_id):
        print("Aucun audit. Lancez d'abord : aule run <dossier>", file=sys.stderr)
        return 1
    cfg = dataclasses.replace(config.critiq, **({"allow_more_code": True} if getattr(args, "more_code", False) else {}))
    llm = dataclasses.replace(config.llm, model=args.model or config.llm.model) if config.llm else None
    try:
        if args.critiq_cmd == "run":
            kinds = tuple(dict.fromkeys(CRITIQ_KINDS[k.strip()] for k in args.kind.split(","))) if args.kind else None
            crit_args = dict(kinds=kinds, force=args.force, max_findings=args.max, dry_run=args.dry_run, show=args.show)
            if ui.forge and not args.dry_run:
                with pretty.RunPrinter(ui, db, None) as printer:
                    printer.log("Phase 5 : critique IA des résultats")
                    summary = run_critique(db, args.data, run_id, cfg, llm=llm, log=printer.log, progress=printer.progress, **crit_args)
            else:
                summary = run_critique(db, args.data, run_id, cfg, llm=llm, **crit_args)
            if args.dry_run:
                print(f"\nSimulation : rien n'a été envoyé. {summary['units']} constat(s) seraient examinés par « {(llm.model if llm else None) or '(modèle non configuré)'} » ({public_url(llm.url) if llm else 'aucun llm.yaml'}).")
                for pr in summary["prompts"]:
                    print(f"\n{'=' * 78}\n{pr['unit']}\nCode envoyé : " + (", ".join(f"{x.get('file')}:{x.get('start')}-{x.get('end')} ({x['chars']} car.)" for x in pr["sent"]) or "aucun")
                          + f"\n{'-' * 78}\n{pr['user']}")
                if summary["prompts"]:
                    print(f"\n{'=' * 78}\n(Message système identique pour tous :)\n{summary['prompts'][0]['system']}")
                else:
                    print("Ajoutez --show N pour afficher le texte exact des N premiers messages.")
                return 0
            v = summary["verdicts"]
            ui.ok(f"Terminé : {summary['critiqued']} nouveau(x) avis, {summary['cached']} en cache, {summary['errors']} erreur(s) — "
                  + (", ".join(f"{k} {n}" for k, n in v.items()) or "aucun avis") + ". Avis consultatifs : à vérifier avant tout triage."
                  + (f" Jetons consommés : {summary['tokens']}." if summary.get("tokens") else ""))
            return 1 if summary["aborted"] else 0
        crit = db.critiques(args.model)
        names = {p["id"]: p["name"] for p in db.list_projects(run_id)}
        if args.critiq_cmd == "list":
            rows = []
            for kind in ("secret", "sast_finding", "vulnerability"):
                for e in db.entities(run_id, kind):
                    c = crit.get(e["fingerprint"])
                    if c and (not args.verdict or c["verdict"] == args.verdict):
                        rows.append((e, c, kind))
            for e, c, kind in sorted(rows, key=lambda t: (names[t[0]["project_id"]], t[0]["fingerprint"])):
                d = e["data"]
                conf = f"{c['confidence']:.0%}" if c["confidence"] is not None else "  - "
                print(f"{e['fingerprint'][:10]}  {c['verdict']:<15} {conf:>4}  {names[e['project_id']]:<14} {d.get('rule_id') or d.get('id')}"
                      + ("  ⚠ injection suspectée" if c["injection_suspected"] else "") + (f"  [{e['triage_status']}]" if e["triage_status"] else ""))
            print(f"{len(rows)} avis dans {run_id}")
        elif args.critiq_cmd == "show":
            fp = resolve_prefixes(db, run_id, [args.fingerprint])[0]
            c = crit.get(fp)
            if not c:
                raise ValueError("pas d'avis pour ce résultat (aule critiq run)")
            print(f"{fp}\nmodèle : {c['model']} · {c['created_at']} · {c['rounds']} tour(s)\navis : {c['verdict']}"
                  + (f" (confiance {c['confidence']:.0%})" if c["confidence"] is not None else "") + ("  ⚠ INJECTION SUSPECTÉE (exclu de apply)" if c["injection_suspected"] else "")
                  + f"\n\n{c['reasoning']}\n")
            print("Code envoyé au modèle :")
            for x in c["sent"]:
                print("  - " + _sent_label(x) + f" ({x['chars']} car., {x.get('kind')})")
            if not c["sent"]:
                print("  (aucun extrait)")
            print(f"\nConversation brute : {args.data / 'runs' / run_id / 'critiq' / _slug(c['model']) / (fp[:20] + '.json')}")
        else:  # apply
            items = select_applicable(db, run_id, verdict=args.verdict, min_confidence=args.min_confidence, model=args.model)
            status = {"false_positive": "faux positif", "true_positive": "à revoir"}[args.verdict]
            for it in items[:25]:
                print(f"  {it['fingerprint'][:10]}  {it['project']:<14} {it['label']}  ({it['critique']['confidence']:.0%})  {it['critique']['reasoning'][:90]}")
            print(f"{len(items)} résultat(s) sélectionnés → « {status} » (avis {args.verdict}, confiance ≥ {args.min_confidence:.0%}, "
                  "hors injection suspectée, sans écraser un triage existant).")
            if not args.yes:
                print("Aperçu seulement : ajoutez --yes pour appliquer.")
            else:
                print(f"{apply_critiques(db, items, args.verdict)} résultat(s) triés. (L'IA ne « confirme » jamais : les vrais positifs passent « à revoir ».)")
    except LLMError as exc:
        ui.error(f"{exc}")
        return 2
    except (ValueError, KeyError) as exc:
        ui.error(f"{exc.args[0] if isinstance(exc, KeyError) else exc}")
        return 2
    return 0


def cmd_mission(args, db: Database, config: Config) -> int:
    try:
        if args.mission_cmd == "show":
            m = db.get_mission()
            if not m:
                print("Aucune mission nommée. Donnez-lui un nom : aule mission init \"NOM\"")
                return 0
            print(f"Mission : {m['name']}\nClient  : {m['client'] or '-'}\nPérimètre : {m['scope'] or '-'}\nCréée le {m['created_at']} · modifiée le {m['updated_at']}")
            print(f"Passages : {len(db.list_audits())}")
        else:
            m = db.set_mission(args.name, args.client, args.scope)
            ui.ok(f"Mission « {m['name']} » {'créée' if args.mission_cmd == 'init' else 'mise à jour'}. "
                  f"Triage, constats et notes de cette base lui appartiennent : une mission = un dossier de données (--data).")
    except ValueError as exc:
        ui.error(f"{exc}")
        return 2
    return 0


def cmd_label(args, db: Database, config: Config) -> int:
    run_id = resolve_run(db, args.run)
    if run_id is None:
        raise RunRefError("aucun audit")
    try:
        new = db.set_audit_label(run_id, args.label)
    except ValueError as exc:
        ui.error(f"{exc}")
        return 2
    ui.ok(f"Run {run_id} : " + (f"libellé « {new} »" if new else "libellé retiré"))
    return 0


def cmd_sarif(args, db, config: Config) -> int:
    imports = args.data / "imports"
    if args.sarif_cmd == "list":
        files = sorted(imports.glob("*.sarif")) if imports.is_dir() else []
        for f in files:
            print(f"{f.name}  ({f.stat().st_size // 1024} Ko)")
        print(f"{len(files)} SARIF importé(s) dans {imports}")
        return 0
    try:
        data = args.file.read_bytes()
        path = import_sarif(args.data, args.name or args.file.name, data)
    except (OSError, ValueError) as exc:
        ui.error(f"{exc}")
        return 2
    ui.ok(f"SARIF importé : {args.data / path}\nConsultable dans l'interface (aule serve) : onglet Sorties brutes > (importés).")
    return 0


def cmd_correlate(args, db: Database, config: Config) -> int:
    run_id = resolve_run(db, args.run)
    if not run_id:
        print("Aucun audit. Lancez d'abord : aule run <dossier>", file=sys.stderr)
        return 1
    log = (lambda l: ui.say(f"{ui.lead('alloy', 'ember')}{ui.c('Alliage', 'bold ember')}  {ui.c(l.removeprefix('Recoupement : '), 'iron')}")) if ui.forge else print
    s = correlate_run(db, args.data, run_id, propagate=not args.no_propagate, persist=not args.dry_run, log=log)
    if args.dry_run:
        ui.warn("Simulation : rien n'a été enregistré ni propagé.") if ui.forge else print("Simulation : rien n'a été enregistré ni propagé.")
    if args.show:
        clusters = compute_clusters(db, args.data, run_id) if args.dry_run else db.list_clusters(run_id)
        names = {p["id"]: p["name"] for p in db.list_projects(run_id)}
        ents = {e["fingerprint"]: e["data"] for k in ("secret", "sast_finding", "vulnerability") for e in db.entities(run_id, k)}
        shown = [c for c in clusters if len(c["members"]) > 1]
        groups = []
        for c in shown[:args.show]:
            d = ents[c["members"][0]]
            where = (d.get("dependency") or {}).get("name") if c["kind"] == "vulnerability" else f"{d.get('file')}"
            what = d.get("id") if c["kind"] == "vulnerability" else d.get("rule_id")
            seen = sorted({f"{ents[m].get('tool')}" + (f"/{ents[m]['mode']}" if ents[m].get("mode") else "") for m in c["members"]})
            if ui.forge:
                groups.append({"kind": c["kind"], "project": names[c["project_id"]], "where": str(where), "what": str(what), "n": len(c["members"]), "seen": ", ".join(seen), "reasons": c["reasons"]})
            else:
                print(f"  {c['kind']:<13} {names[c['project_id']]:<14} {where}  {what}  ← {len(c['members'])} détections : {', '.join(seen)}  [{', '.join(c['reasons'])}]")
        if ui.forge:
            pretty.correlate_groups(ui, groups, len(shown))
        else:
            print(f"{len(shown)} groupe(s) de plusieurs détections" + (f" (les {args.show} premiers affichés)" if len(shown) > args.show else ""))
    return 0


def cmd_update(args, db: Database | None, config: Config) -> int:
    registry = load_plugins()
    try:
        names = args.tools or [t.name for t in select_tools(config) if t.updatable]
        tools = [registry[n] for n in names] if all(n in registry for n in names) else None
        if tools is None:
            raise ValueError(f"outil(s) inconnu(s) : {', '.join(n for n in names if n not in registry)}")
    except ValueError as exc:
        ui.error(f"{exc}")
        return 2
    if not tools:
        print("Aucun outil à mettre à jour : activez opengrep / dependency-check dans aule.yaml "
              "ou nommez-les (aule update opengrep).")
        return 0
    code = 0
    for tool in tools:
        cfg = config.tool(tool.name)
        print(f"== {tool.name}")
        try:
            tool.update(cfg, tool.resolve(cfg), args.data, print)
        except ToolError as exc:
            ui.error(f"{exc}")
            code = 2
    return code


def cmd_reparse(args, db: Database, config: Config) -> int:
    try:
        reparse(db, args.data, resolve_run(db, args.run_id), config)
    except AuditError as exc:
        ui.error(f"{exc}")
        return 2
    return 0


def cmd_report(args, db: Database, config: Config) -> int:
    run_id = resolve_run(db, args.run_id)
    if not run_id or not db.get_audit(run_id):
        print("Aucun audit à présenter. Lancez d'abord : aule run <dossier>", file=sys.stderr)
        return 1
    if args.share:  # préset de partage : secrets masqués, faux positifs retirés, résultats SARIF complets des constats embarqués
        args.mask = args.hide_false_positives = args.raw_details = True
    reveal = not args.mask
    out = (args.output or args.data / f"report-{run_id}{'-partage' if args.share else '' if reveal else '-masque'}.html").resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    compare = resolve_run(db, args.compare) if args.compare else None
    out.write_text(render_report(db, run_id, args.data, reveal, compare=compare, raw_details=args.raw_details,
                                     hide_false_positives=args.hide_false_positives), encoding="utf-8")
    if reveal:
        try:
            out.chmod(0o600)  # contient des secrets en clair : lisible par son propriétaire seulement
        except OSError:
            pass  # systèmes de fichiers sans droits POSIX (Windows) : protégez le fichier vous-même
    ui.ok(f"Rapport : {out}")
    if reveal:
        ui.warn("Ce rapport contient des secrets EN CLAIR : ne le partagez pas. Version partageable : aule report --mask",
                plain="⚠ Ce rapport contient des secrets EN CLAIR : ne le partagez pas. Version partageable : aule report --mask")
    if args.open:
        webbrowser.open(out.as_uri())
    return 0


def cmd_show(args, db: Database, config: Config) -> int:
    run_id = resolve_run(db, args.run_id)
    audit = db.get_audit(run_id) if run_id else None
    if not audit:
        print("Aucun audit. Lancez d'abord : aule run <dossier>", file=sys.stderr)
        return 1
    if ui.forge:
        pretty.show(ui, db, run_id, args.project)
        return 0
    mission = db.get_mission()
    print((f"Mission « {mission['name']} » — " if mission else "") + f"Audit {display_name(audit)}" + (f" ({audit['id']})" if audit["label"] else "")
          + f" — {audit['status']} — {audit['root']}\n")
    for p in db.list_projects(run_id):
        if args.project and args.project not in (p["name"], p["parent"]):
            continue
        git = f"git @ {p['head_commit'][:8]}" if p["head_commit"] else ("git" if p["is_git"] else "hors git")
        origin = f"  ← archive {p['origin']}" if p["parent"] else ""
        print(f"{'  ↳ ' if p['parent'] else ''}■ {p['name']}  ({git}){origin}")
        techs = sorted(db.entities(run_id, "technology", p["id"]), key=lambda e: -e["data"]["code"])
        if techs:
            shown = " · ".join(f"{t['data']['language']} {_n(t['data']['code'])}" for t in techs[:6])
            more = f" · (+{len(techs) - 6})" if len(techs) > 6 else ""
            print(f"  Technologies : {shown}{more}  [lignes de code]")
        secrets = db.entities(run_id, "secret", p["id"])
        by_mode = Counter(s["data"]["mode"] for s in secrets)
        print("  Secrets      : " + (" · ".join(f"{m} {c}" for m, c in sorted(by_mode.items())) or "aucun"))
        def by_sev(entities):
            c = Counter(e["data"]["severity"] for e in entities)
            return " · ".join(f"{k} {c[k]}" for k in ("critical", "high", "medium", "low", "info") if c[k]) or "aucun"
        sast = db.entities(run_id, "sast_finding", p["id"])
        if sast or any(r["tool"] == "opengrep" and r["status"] == "ok" for r in db.list_tool_runs(run_id, p["id"])):
            print(f"  SAST         : {by_sev(sast)}")
        vulns = db.entities(run_id, "vulnerability", p["id"])
        deps = db.entities(run_id, "dependency", p["id"])
        if deps or vulns:
            print(f"  Dépendances  : {len(deps)} composant(s), vulnérabilités : {by_sev(vulns)}")
        commits = db.entities(run_id, "commit", p["id"])
        if commits:
            print(f"  Historique   : {len(commits)} commit(s) reconstruit(s)")
        runs = db.list_tool_runs(run_id, p["id"])
        print("  Exécutions   : " + " · ".join(f"{r['tool']}/{r['mode']} {r['status']}" for r in runs if r["status"] != "skipped"))
        for r in runs:
            if r["status"] not in ("ok", "skipped"):
                print(f"    ! {r['tool']}/{r['mode']} : {r['error']}")
        if args.project:
            for s in secrets:
                d = s["data"]
                where = f"{d['file']}:{d['start_line']}" + (f" @ {d['commit'][:8]}" if d["commit"] else "")
                extra = f" ({d['commits_count']} commits)" if d.get("commits_count") else ""
                print(f"    [{d['mode']}] {d['rule_id']:<20} {where}{extra}  {d['secret_masked']}  {s['triage_status'] or ''}")
            for f in sast:
                d = f["data"]
                print(f"    [sast/{d['severity']}] {d.get('tool') or '?'} · {d['rule_id']}  {d['file']}:{d['start_line']}")
            for v in vulns:
                d = v["data"]
                print(f"    [vuln/{d['severity']}] {d['id']}  {d['dependency']['name']} {d['dependency']['version'] or ''}")
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    def add_common(p: argparse.ArgumentParser) -> None:
        # default=SUPPRESS : l'option est acceptée AVANT comme APRÈS le nom de la commande (ex. `aule --data X runs` ou `aule runs --data X`) ;
        # celle qui est la plus proche de la commande l'emporte. Les valeurs par défaut sont posées par main().
        p.add_argument("--color", choices=["auto", "always", "never"], default=argparse.SUPPRESS,
                       help="décor de la forge (couleurs, emoji, tableaux) : auto = sur un terminal ; never = texte simple (aussi NO_COLOR)")
        p.add_argument("--ascii", action="store_true", default=argparse.SUPPRESS, help="sans emoji ni caractères de bordure (terminal non UTF-8)")
        p.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="fichier YAML des outils (défaut : ./aule.yaml s'il existe)")
        p.add_argument("--data", type=Path, default=argparse.SUPPRESS,
                       help="dossier de données : base SQLite + sorties brutes (défaut : data_dir du YAML, sinon ./data)")
    common = argparse.ArgumentParser(add_help=False)
    add_common(common)
    parser = argparse.ArgumentParser(prog="aule", description="Aulë — assistant d'audit de code : orchestre les outils, recoupe les résultats, aide à les trier.")
    add_common(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", parents=[common], help="analyse chaque sous-dossier de ROOT")
    run.add_argument("root", type=Path)
    run.add_argument("--name", metavar="LIBELLÉ", help="nom de ce passage, de votre choix (ex. « initial », « contre-audit ») : accepté partout à la place de l'identifiant")
    run.add_argument("--tools", help="liste séparée par des virgules (défaut : outils activés)")
    run.add_argument("--unpack", action="store_true", help="décompresse les archives (zip, tar.*) et les analyse")
    run.add_argument("--history", action="store_true",
                     help="reconstruit l'historique des .git avec gittools et le scanne (mode gitleaks history)")
    run.add_argument("--with", dest="with_tools", metavar="OUTILS",
                     help="ajoute des outils optionnels aux outils activés : opengrep, dependency-check, gittools")
    run.add_argument("--more-code", action="store_true", help="avec --critiq : le modèle peut réclamer beaucoup plus de code, donné automatiquement (critiq.allow_more_code)")
    run.add_argument("--critiq", action="store_true",
                     help="une fois les outils passés, demande l'avis d'un modèle d'IA (Ollama) sur les résultats (section critiq de aule.yaml)")
    run.add_argument("--jobs", type=int, help="exécutions en parallèle (défaut : YAML, sinon min(4, CPU))")
    run.add_argument("--timeout", type=int, help="secondes par exécution d'outil (défaut : YAML, sinon 1800)")
    run.add_argument("--resume", metavar="RUN_ID", help="reprend un run interrompu ou partiel")
    run.add_argument("--exclude", action="append", metavar="NOM", help="sous-dossier à ignorer (répétable)")
    run.set_defaults(func=cmd_run)

    sub.add_parser("runs", parents=[common], help="liste les audits").set_defaults(func=cmd_runs)
    sub.add_parser("tools", parents=[common], help="outils, chemins résolus et disponibilité").set_defaults(
        func=cmd_tools, needs_db=False)

    show = sub.add_parser("show", parents=[common], help="résumé d'un audit")
    show.add_argument("run_id", nargs="?", help="défaut : le dernier")
    show.add_argument("--project", help="détail d'un projet (liste les secrets masqués)")
    show.set_defaults(func=cmd_show)

    rep = sub.add_parser("report", parents=[common], help="génère le rapport HTML interactif (un seul fichier)")
    rep.add_argument("run_id", nargs="?", help="défaut : le dernier")
    rep.add_argument("-o", "--output", type=Path, help="fichier de sortie (défaut : <data>/report-<run>.html)")
    rep.add_argument("--mask", action="store_true",
                     help="masque les secrets (version partageable). Par défaut les valeurs sont affichées en clair")
    rep.add_argument("--compare", metavar="RUN", help="ajoute l'onglet Comparaison : ce run (avant) -> le run du rapport (après)")
    rep.add_argument("--raw-details", action="store_true",
                     help="embarque, pour chaque constat SAST, le résultat SARIF COMPLET (règle, chemins de données, emplacements liés) ; taille bornée")
    rep.add_argument("--hide-false-positives", action="store_true", help="retire du rapport les résultats triés « faux positif »")
    rep.add_argument("--share", action="store_true", help="préset de partage : --mask --hide-false-positives --raw-details")
    rep.add_argument("--open", action="store_true", help="ouvre le rapport dans le navigateur")
    rep.set_defaults(func=cmd_report)

    up = sub.add_parser("update", parents=[common], help="met à jour les règles opengrep / la base de vulnérabilités (réseau)")
    up.add_argument("tools", nargs="*", help="outils à mettre à jour (défaut : ceux activés dans aule.yaml)")
    up.set_defaults(func=cmd_update, needs_db=False)

    tri = sub.add_parser("triage", help="qualifie les résultats (faux positif, confirmé…) ; survit aux relances")
    tsub = tri.add_subparsers(dest="triage_cmd", required=True)

    def selection_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("fingerprints", nargs="*", metavar="EMPREINTE", help="empreintes ou préfixes (6 caractères min.)")
        p.add_argument("--run", help="run de référence (défaut : le dernier)")
        p.add_argument("--kind", choices=sorted(KINDS), help="secret | sast | vuln")
        p.add_argument("--project")
        p.add_argument("--rule", help="règle (secrets, SAST) ou identifiant CVE")
        p.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"])
        p.add_argument("--mode", help="secrets : dir, git, history")
        p.add_argument("--tool")
        p.add_argument("--file", help="motif de chemin (ex. 'tests/*')")
        p.add_argument("--untriaged", action="store_true", help="seulement les résultats non triés")
        p.add_argument("--yes", action="store_true", help="applique une sélection par filtre sans confirmation")
        p.add_argument("--single", action="store_true", help="ne pas étendre aux détections identiques recoupées (un seul résultat, sans ses doublons)")

    t_set = tsub.add_parser("set", parents=[common], help="marque des résultats")
    t_set.add_argument("status", choices=TRIAGE_STATUSES)
    selection_options(t_set)
    t_set.add_argument("-c", "--comment", help="justification, conservée avec le triage")
    t_clear = tsub.add_parser("clear", parents=[common], help="efface le triage")
    selection_options(t_clear)
    t_list = tsub.add_parser("list", parents=[common], help="liste les résultats triés")
    t_list.add_argument("--run")
    t_list.add_argument("--kind", choices=sorted(KINDS))
    t_list.add_argument("--project")
    t_list.add_argument("--status", choices=TRIAGE_STATUSES)
    tri.set_defaults(func=cmd_triage)

    dif = sub.add_parser("diff", parents=[common], help="compare deux runs : nouveaux, corrigés, persistants")
    dif.add_argument("runs", nargs="*", metavar="RUN", help="A puis B (défaut : les deux derniers)")
    dif.add_argument("--kind", help="secret,sast,vuln (défaut : tous)")
    dif.add_argument("--all", action="store_true", help="liste aussi les persistants")
    dif.add_argument("--json", action="store_true")
    dif.set_defaults(func=cmd_diff)

    lk = sub.add_parser("links", parents=[common], help="liens entre projets (dépendances, secrets partagés, hôtes communs…)")
    lk.add_argument("run", nargs="?", help="défaut : le dernier")
    lk.add_argument("--type", choices=["extracted_from", *LINK_TYPES])
    lk.add_argument("--project", help="seulement les liens de ce projet")
    lk.add_argument("--no-recompute", action="store_true", help="n'affiche que les liens déjà calculés")
    lk.set_defaults(func=cmd_links)

    fnd = sub.add_parser("finding", help="constats rédigés par l'auditeur (indépendants des runs)")
    fsub = fnd.add_subparsers(dest="finding_cmd", required=True)
    f_add = fsub.add_parser("add", parents=[common], help="crée un constat")
    f_add.add_argument("--project", required=True)
    f_add.add_argument("--title", required=True)
    f_edit = fsub.add_parser("edit", parents=[common], help="modifie un constat")
    f_edit.add_argument("id", type=int)
    f_edit.add_argument("--project")
    f_edit.add_argument("--title")
    for p in (f_add, f_edit):
        p.add_argument("--severity", choices=SEVERITIES, **({"default": "medium"} if p is f_add else {}))
        p.add_argument("--status", choices=FINDING_STATUSES, **({"default": "draft"} if p is f_add else {}))
        p.add_argument("--description", help="texte du constat")
        p.add_argument("--description-file", metavar="FICHIER", help="lit le texte dans un fichier (« - » = entrée standard)")
        p.add_argument("--edit", action="store_true", help="ouvre $EDITOR pour rédiger la description")
        p.add_argument("--ref", action="append", metavar="REF",
                       help="élément automatique (empreinte ou préfixe) ou référence libre (chemin:ligne, commit…) ; répétable")
    f_list = fsub.add_parser("list", parents=[common], help="liste les constats")
    f_list.add_argument("--project")
    f_list.add_argument("--status", choices=FINDING_STATUSES)
    fsub.add_parser("show", parents=[common], help="affiche un constat").add_argument("id", type=int)
    fsub.add_parser("rm", parents=[common], help="supprime un constat").add_argument("id", type=int)
    fnd.set_defaults(func=cmd_finding, needs_db=True)

    nt = sub.add_parser("note", help="notes libres par projet (indépendantes des runs)")
    nsub = nt.add_subparsers(dest="note_cmd", required=True)
    n_set = nsub.add_parser("set", parents=[common], help="écrit la note d'un projet (texte vide = supprime)")
    n_set.add_argument("project")
    n_set.add_argument("--text")
    n_set.add_argument("--file", metavar="FICHIER", help="« - » = entrée standard")
    n_set.add_argument("--edit", action="store_true", help="ouvre $EDITOR")
    nsub.add_parser("show", parents=[common], help="affiche la note d'un projet").add_argument("project")
    nsub.add_parser("list", parents=[common], help="toutes les notes")
    nt.set_defaults(func=cmd_note)

    ex = sub.add_parser("export", parents=[common], help="export consolidé et dédoublonné : csv, md, json, xlsx, docx")
    ex.add_argument("run_id", nargs="?", help="défaut : le dernier")
    ex.add_argument("--format", choices=FORMATS, default="md")
    ex.add_argument("-o", "--output", type=Path, help="défaut : <data>/export-<run>.<format>")
    ex.add_argument("--mask", action="store_true", help="masque les secrets (par défaut : en clair, comme le rapport)")
    ex.add_argument("--include-false-positives", action="store_true")
    ex.add_argument("--include-dismissed", action="store_true", help="inclut les constats manuels écartés")
    ex.add_argument("--status", help="liste : confirmed,to_review,accepted_risk,untriaged,draft…")
    ex.add_argument("--min-severity", choices=SEVERITIES)
    ex.set_defaults(func=cmd_export)

    doc = sub.add_parser("doctor", parents=[common], help="vérifie chaque outil sur un mini-projet embarqué")
    doc.add_argument("--tool", action="append", metavar="OUTIL", help="seulement cet outil (répétable)")
    doc.add_argument("--full", action="store_true", help="inclut les outils sans base locale (téléchargement long : NVD, Trivy)")
    doc.add_argument("--strict", action="store_true", help="les avertissements font échouer (code retour 1)")
    doc.add_argument("--timeout", type=int, default=900, help="secondes par outil (défaut 900)")
    doc.add_argument("--keep", action="store_true", help="conserve le dossier temporaire (sorties brutes) pour diagnostic")
    doc.set_defaults(func=cmd_doctor, needs_db=False)

    pg = sub.add_parser("purge", parents=[common], help="rétention : supprime des runs ou leurs données volumineuses")
    pg.add_argument("--run", action="append", metavar="RUN", help="run à supprimer (répétable)")
    pg.add_argument("--older-than", type=int, metavar="JOURS", help="runs plus anciens que N jours")
    pg.add_argument("--keep", type=int, metavar="N", help="ne garde que les N runs les plus récents")
    pg.add_argument("--heavy", action="store_true",
                    help="sur les runs conservés : supprime archives décompressées, bases CodeQL, arbres des commits reconstruits (rapports gardés)")
    pg.add_argument("--yes", action="store_true", help="applique (sinon : plan seulement)")
    pg.set_defaults(func=cmd_purge)

    sl = sub.add_parser("seal", parents=[common], help="chiffre data/ avec gpg (AES-256) ; POSIX")
    sl.add_argument("-o", "--output", type=Path, help="défaut : <data>.tar.gz.gpg")
    sl.add_argument("--remove", action="store_true", help="supprime data/ après vérification du fichier chiffré")
    sl.add_argument("--passphrase-file", metavar="FICHIER", help="sinon : $AULE_PASSPHRASE, sinon saisie")
    sl.set_defaults(func=cmd_seal, needs_db=False)
    us = sub.add_parser("unseal", parents=[common], help="déchiffre une archive produite par seal")
    us.add_argument("archive", type=Path)
    us.add_argument("--to", type=Path, help="dossier de destination (défaut : dossier courant)")
    us.add_argument("--passphrase-file", metavar="FICHIER")
    us.set_defaults(func=cmd_unseal, needs_db=False)

    sv = sub.add_parser("serve", parents=[common], help="serveur local interactif : triage, constats, notes, lancement d'audit")
    sv.add_argument("--host", default="127.0.0.1", help="adresse locale uniquement (défaut 127.0.0.1)")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument("--mask", action="store_true", help="secrets masqués, révélés valeur par valeur à la demande")
    sv.add_argument("--allowed-host", action="append", metavar="HOTE:PORT", help="nom d'hôte accepté en plus (tunnel SSH), répétable")
    sv.add_argument("--open", action="store_true", help="ouvre le navigateur")
    sv.set_defaults(func=cmd_serve)

    lm = sub.add_parser("llm", help="le moteur d'IA : llm.yaml (secrets compris, jamais dans l'environnement)")
    lsub = lm.add_subparsers(dest="llm_cmd", required=True)
    lmig = lsub.add_parser("migrate", parents=[common], help="crée llm.yaml à partir de l'ancienne section critiq de aule.yaml (clés tirées de l'environnement ou d'un fichier comprises)")
    lmig.add_argument("--out", type=Path, help="fichier à écrire (défaut : llm.yaml à côté de aule.yaml)")
    lmig.add_argument("--force", action="store_true", help="écrase un llm.yaml existant")
    lmig.set_defaults(func=cmd_llm_migrate, needs_db=False, raw_config=True)

    cq = sub.add_parser("critiq", help="avis d'un modèle d'IA (Ollama) sur les résultats : consultatif, ne modifie jamais le triage seul")
    csub = cq.add_subparsers(dest="critiq_cmd", required=True)

    def cq_common(p: argparse.ArgumentParser, run: bool = True) -> None:
        if run:
            p.add_argument("run", nargs="?", help="défaut : le dernier")
        p.add_argument("--model", help="modèle (défaut : `model` de llm.yaml)")

    c_run = csub.add_parser("run", parents=[common], help="demande l'avis du modèle (avis en cache réutilisés)")
    cq_common(c_run)
    c_run.add_argument("--kind", help="secret,sast,vuln (défaut : critiq.kinds)")
    c_run.add_argument("--force", action="store_true", help="refait les avis même en cache")
    c_run.add_argument("--more-code", action="store_true", help="le modèle peut réclamer beaucoup plus de code (fichiers entiers, dossiers, davantage de tours), donné automatiquement : critiq.allow_more_code")
    c_run.add_argument("--max", type=int, metavar="N", help="au plus N constats (défaut : critiq.max_findings)")
    c_run.add_argument("--dry-run", action="store_true", help="n'envoie RIEN : compte et, avec --show, affiche le texte exact qui serait envoyé")
    c_run.add_argument("--show", type=int, default=0, metavar="N", help="avec --dry-run : affiche les N premiers messages")
    c_check = csub.add_parser("check", parents=[common], help="vérifie le moteur IA (connexion, jeton, modèle ou agent) SANS envoyer de code")
    c_check.add_argument("--model", help="modèle ou agent à tester (défaut : `model` de llm.yaml)")
    c_check.add_argument("--probe", action="store_true", help="envoie un message anodin (« Say hello… », AUCUN code) pour valider toute la chaîne ; provider: custom")
    c_list = csub.add_parser("list", parents=[common], help="liste les avis")
    cq_common(c_list)
    c_list.add_argument("--verdict", choices=["true_positive", "false_positive", "uncertain", "error"])
    c_show = csub.add_parser("show", parents=[common], help="détail d'un avis : justification, code envoyé")
    c_show.add_argument("fingerprint", metavar="EMPREINTE")
    cq_common(c_show, run=False)
    c_show.add_argument("--run")
    c_apply = csub.add_parser("apply", parents=[common], help="reporte des avis dans le triage (aperçu sans --yes) ; jamais « confirmé »")
    cq_common(c_apply)
    c_apply.add_argument("--verdict", choices=["false_positive", "true_positive"], default="false_positive",
                         help="faux positif -> triage « faux positif » ; vrai positif -> « à revoir »")
    c_apply.add_argument("--min-confidence", type=float, default=0.8)
    c_apply.add_argument("--yes", action="store_true")
    cq.set_defaults(func=cmd_critiq)

    ms = sub.add_parser("mission", help="nom de la mission (de votre choix) : client, périmètre")
    msub = ms.add_subparsers(dest="mission_cmd", required=True)
    for name, helptext in (("init", "nomme la mission de cette base de données"), ("rename", "change le nom de la mission"), ("set", "met à jour client / périmètre")):
        mp = msub.add_parser(name, parents=[common], help=helptext)
        mp.add_argument("name", metavar="NOM")
        mp.add_argument("--client")
        mp.add_argument("--scope", metavar="PÉRIMÈTRE")
    msub.add_parser("show", parents=[common], help="affiche la mission")
    ms.set_defaults(func=cmd_mission)

    lb = sub.add_parser("label", parents=[common], help="nomme un passage déjà fait (libellé vide : le retire)")
    lb.add_argument("run", metavar="RUN", help="libellé, identifiant, @dernier ou @précédent")
    lb.add_argument("label", metavar="LIBELLÉ")
    lb.set_defaults(func=cmd_label)

    sr = sub.add_parser("sarif", help="SARIF extérieurs (CI, client) : importés dans la mission pour être explorés")
    ssub = sr.add_subparsers(dest="sarif_cmd", required=True)
    s_imp = ssub.add_parser("import", parents=[common], help="copie un fichier SARIF dans la mission (data/imports/)")
    s_imp.add_argument("file", type=Path)
    s_imp.add_argument("--name", help="nom (défaut : celui du fichier)")
    ssub.add_parser("list", parents=[common], help="liste les SARIF importés")
    sr.set_defaults(func=cmd_sarif, needs_db=False)

    co = sub.add_parser("correlate", parents=[common], help="recoupe les détections identiques (secrets, SAST, dépendances) en un seul constat")
    co.add_argument("run", nargs="?", help="défaut : le dernier")
    co.add_argument("--dry-run", action="store_true", help="calcule et affiche, n'enregistre ni ne propage rien")
    co.add_argument("--no-propagate", action="store_true", help="ne propage pas le triage déjà fait aux occurrences identiques")
    co.add_argument("--show", type=int, default=0, metavar="N", help="affiche les N premiers groupes de plusieurs détections")
    co.set_defaults(func=cmd_correlate)

    rp = sub.add_parser("reparse", parents=[common], help="rejoue les parseurs sur les sorties brutes")
    rp.add_argument("run_id")
    rp.set_defaults(func=cmd_reparse)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for name, default in (("color", "auto"), ("ascii", False), ("config", None), ("data", None)):
        if not hasattr(args, name):
            setattr(args, name, default)
    ui.configure(out=sys.stdout, err=sys.stderr, mode=getattr(args, "color", "auto"), ascii_only=getattr(args, "ascii", False))
    if getattr(args, "raw_config", False):  # commandes qui lisent le fichier brut (aule llm migrate) : l'ancien format est refusé par load_config
        return args.func(args, None, None)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        ui.error(f"{exc}", label="Erreur de configuration")
        return 2
    args.data = args.data or config.data_dir or Path("data")
    db = Database(args.data / "audit.db") if getattr(args, "needs_db", True) else None
    try:
        return args.func(args, db, config)
    except RunRefError as exc:
        ui.error(f"{exc}")
        return 2
    finally:
        if db:
            db.close()
