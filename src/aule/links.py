"""Liens entre projets d'un run, calculés une fois tous les outils passés.

Types de relation (table `relation`, projet -> projet) :
  shared_secret    même secret (hash) retrouvé dans deux projets            non orienté
  same_remote      même dépôt d'origine (remote git)                        non orienté
  depends_on       A dépend d'un paquet publié par B, ou référence son dossier   A -> B
  shared_endpoint  même hôte référencé (hors hôtes publics courants)        non orienté
  extracted_from   archive décompressée -> projet d'origine (posé par l'orchestrateur)
Un projet et ses archives dérivées partagent forcément du contenu : aucun lien « partagé » entre eux.
"""
from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Iterable

from .db import Database

LINK_TYPES = ("shared_secret", "same_remote", "depends_on", "shared_endpoint")

# Hôtes publics ou sans signification pour relier deux projets (suffixes de domaine inclus)
DEFAULT_IGNORED_HOSTS = frozenset("""
github.com gitlab.com bitbucket.org githubusercontent.com npmjs.org npmjs.com yarnpkg.com pypi.org pythonhosted.org
maven.org apache.org gradle.org rubygems.org packagist.org nuget.org golang.org go.dev crates.io docker.io docker.com
ghcr.io gcr.io quay.io microsoft.com w3.org xmlsoap.org json-schema.org schema.org example.com example.org example.net
localhost 127.0.0.1 0.0.0.0 ::1 google.com googleapis.com gstatic.com cloudflare.com jsdelivr.net unpkg.com
stackoverflow.com wikipedia.org creativecommons.org opensource.org shields.io readthedocs.io mozilla.org eclipse.org
""".split())


def _ignored(host: str, extra: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in (*DEFAULT_IGNORED_HOSTS, *extra))


def compute_relations(db: Database, audit_id: str, ignore_hosts: Iterable[str] = ()) -> dict[str, int]:
    """Recalcule les liens du run (idempotent) et retourne le nombre de relations par type."""
    projects = db.list_projects(audit_id)
    by_name = {p["name"]: p for p in projects}
    ancestors: dict[int, set[int]] = {}
    for p in projects:
        chain, cur = set(), p
        while cur["parent"] and cur["parent"] in by_name and by_name[cur["parent"]]["id"] not in chain:
            cur = by_name[cur["parent"]]
            chain.add(cur["id"])
        ancestors[p["id"]] = chain

    def related(a: int, b: int) -> bool:  # parent <-> archive dérivée : contenu partagé par construction
        return b in ancestors[a] or a in ancestors[b]

    found: dict[tuple[str, int, int], dict] = {}

    def link(rtype: str, a: int, b: int, directed: bool = False, **data) -> None:
        if a == b or related(a, b):
            return
        key = (rtype, a, b) if directed else (rtype, *sorted((a, b)))
        entry = found.setdefault(key, {})
        for k, v in data.items():
            if isinstance(v, list):
                entry.setdefault(k, [])
                entry[k] += [x for x in v if x not in entry[k]]
            else:
                entry[k] = v

    # secrets partagés (tous outils confondus : le hash du secret est commun)
    by_hash: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for e in db.entities(audit_id, "secret"):
        if e["data"].get("secret_sha256"):
            by_hash[e["data"]["secret_sha256"]].append((e["project_id"], e["data"]))
    for sha, hits in by_hash.items():
        ids = sorted({pid for pid, _ in hits})
        d0 = hits[0][1]
        for a, b in combinations(ids, 2):
            link("shared_secret", a, b, secrets=[{"rule": d0.get("rule_id"), "masked": d0.get("secret_masked"), "sha": sha[:8]}])

    # références extraites par le plugin `links`
    remotes, provides, requires, endpoints = defaultdict(set), defaultdict(set), defaultdict(set), defaultdict(set)
    paths: list[tuple[int, str]] = []
    for e in db.entities(audit_id, "reference"):
        r, pid = e["data"], e["project_id"]
        {"git_remote": remotes, "provides": provides, "requires": requires, "endpoint": endpoints}.get(
            r["type"], defaultdict(set))[r["value"]].add(pid)
        if r["type"] == "local_path":
            paths.append((pid, r["value"]))

    for remote, ids in remotes.items():
        for a, b in combinations(sorted(ids), 2):
            link("same_remote", a, b, remote=remote)
    for value, needers in requires.items():
        for a in needers:
            for b in provides.get(value, ()):
                link("depends_on", a, b, directed=True, via=[value])
    resolved = sorted(((Path(p["path"]).resolve(), p["id"]) for p in projects), key=lambda t: -len(t[0].parts))
    for a, target in paths:
        t = Path(target)
        owner = next((pid for root, pid in resolved if t == root or root in t.parents), None)  # projet le plus profond
        if owner is not None and owner != a:
            root = next(r for r, pid in resolved if pid == owner)
            link("depends_on", a, owner, directed=True, via=[f"chemin:{t.relative_to(root).as_posix() or '.'}"])
    pair_hosts: dict[tuple[int, int], list[str]] = defaultdict(list)
    for host, ids in endpoints.items():
        if len(ids) > 1 and not _ignored(host, ignore_hosts):
            for a, b in combinations(sorted(ids), 2):
                if not related(a, b):
                    pair_hosts[(a, b)].append(host)
    for (a, b), hosts in pair_hosts.items():
        link("shared_endpoint", a, b, hosts=sorted(hosts)[:20], count=len(hosts))

    db.delete_relations(audit_id, LINK_TYPES)
    for (rtype, a, b), data in sorted(found.items()):
        if "via" in data:
            data["via"] = data["via"][:10]
        if "secrets" in data:
            data["count"], data["secrets"] = len(data["secrets"]), data["secrets"][:10]
        db.set_relation(audit_id, "project", a, "project", b, rtype, data)
    counts = dict.fromkeys(LINK_TYPES, 0)
    for rtype, _, _ in found:
        counts[rtype] += 1
    return counts


def describe(rel: dict, names: dict[int, str]) -> str:
    a, b, d = names.get(rel["src_id"], "?"), names.get(rel["dst_id"], "?"), rel["data"]
    t = rel["type"]
    if t == "depends_on":
        return f"{a} → {b}  dépend de ({', '.join(d.get('via', []))})"
    if t == "shared_secret":
        return f"{a} ↔ {b}  secret partagé ({d.get('count')}) : " + ", ".join(f"{s['rule']} {s['masked']}" for s in d.get("secrets", [])[:3])
    if t == "same_remote":
        return f"{a} ↔ {b}  même dépôt d'origine : {d.get('remote')}"
    if t == "shared_endpoint":
        return f"{a} ↔ {b}  hôte(s) commun(s) : {', '.join(d.get('hosts', [])[:5])}"
    return f"{a} → {b}  {t}"
