"""Règles personnalisées (`tools.<outil>.rules`) : plusieurs dossiers ou fichiers de règles, et l'outil est lancé avec TOUTES.

Certains outils acceptent plusieurs sources de règles (opengrep : --config répété ; checkov : --external-checks-dir répété ; trivy : --config-check répété ; codeql :
plusieurs spécifications de requêtes). D'autres n'acceptent qu'UN fichier de configuration (gitleaks, trufflehog) : les fichiers sont alors FUSIONNÉS en un seul, écrit dans
la sortie brute de l'exécution, de sorte qu'on voit exactement quelles règles ont été utilisées.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import yaml


class RuleSetError(ValueError):
    """Un fichier de règles est introuvable, invalide ou en conflit avec un autre : le message dit lequel."""


def expand(paths: list[str] | list[Path], suffixes: set[str]) -> list[Path]:
    """Fichiers de règles : un fichier désigné est pris tel quel ; un dossier donne ses fichiers `suffixes` (récursif, ordre alphabétique, dossiers cachés ignorés). Sans doublon."""
    found: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            found += sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in suffixes and not any(part.startswith(".") for part in f.relative_to(p).parts))
        elif p.is_file():
            found.append(p)
        else:
            raise RuleSetError(f"introuvable : {p}")
    unique: list[Path] = []
    seen: set[Path] = set()
    for f in found:
        if (key := f.resolve()) not in seen:
            seen.add(key)
            unique.append(f)
    if not unique:
        raise RuleSetError(f"aucun fichier de règles ({', '.join(sorted(suffixes))}) dans {', '.join(map(str, paths))}")
    return unique


# ---------------------------------------------------------------------------------------------------------- écriture TOML
_BARE = re.compile(r"[A-Za-z0-9_-]+$")


def _key(k: str) -> str:
    return k if _BARE.match(k) else json.dumps(k, ensure_ascii=False)


def _value(v) -> str:
    if isinstance(v, bool):  # avant int : bool est un int
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False).replace("\x7f", "\\u007f")  # les chaînes JSON sont des chaînes TOML valides (sauf DEL)
    if isinstance(v, list):
        return "[" + ", ".join(_value(x) for x in v) + "]"
    raise RuleSetError(f"valeur TOML non gérée : {type(v).__name__}")


def _table(lines: list[str], prefix: str, data: dict) -> None:
    for k, v in data.items():  # d'abord les valeurs simples, puis les tables, puis les tableaux de tables
        if not isinstance(v, dict) and not (isinstance(v, list) and v and all(isinstance(x, dict) for x in v)):
            lines.append(f"{_key(k)} = {_value(v)}")
    for k, v in data.items():
        if isinstance(v, dict):
            lines += ["", f"[{prefix}{_key(k)}]"]
            _table(lines, f"{prefix}{_key(k)}.", v)
    for k, v in data.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            for item in v:
                lines += ["", f"[[{prefix}{_key(k)}]]"]
                _table(lines, f"{prefix}{_key(k)}.", item)


def toml_dumps(data: dict) -> str:
    """TOML pour la structure de la configuration de gitleaks (valeurs simples, tables, tableaux de tables). `tomllib.loads(toml_dumps(d)) == d` (testé)."""
    lines: list[str] = []
    _table(lines, "", data)
    return "\n".join(lines).lstrip("\n") + "\n"


# ----------------------------------------------------------------------------------------------------------------- gitleaks
_GITLEAKS_TOP = {"title", "extend", "rules", "allowlist", "allowlists", "minVersion"}
_ALLOW_LISTS = ("regexes", "paths", "commits", "stopwords")


def wants_default(files: list[Path]) -> bool:
    """Un des fichiers dit-il `[extend] useDefault = true` ? (C'est la façon, pour gitleaks, d'AJOUTER des règles aux règles par défaut au lieu de les remplacer.)"""
    for f in files:
        try:
            data = tomllib.loads(f.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            continue  # merge_gitleaks signale le fichier invalide, avec son nom
        if (data.get("extend") or {}).get("useDefault") is True:
            return True
    return False


def merge_gitleaks(files: list[Path], use_default: bool = True) -> str:
    """Une configuration gitleaks avec les règles de TOUS les fichiers, dont les exclusions globales sont réunies. `use_default` : étend aussi les règles PAR DÉFAUT de gitleaks
    (`[extend] useDefault = true`, avec leurs exclusions globales : vendor/, node_modules/, fichiers verrous, images…) ; sinon la configuration est autonome, comme `gitleaks -c fichier.toml`.
    Deux fichiers qui définissent le même id de règle sont une erreur."""
    rules: list[dict] = []
    owner: dict[str, Path] = {}
    lists: dict[str, list] = {k: [] for k in _ALLOW_LISTS}
    scalars: dict = {}
    plural: list[dict] = []
    for f in files:
        try:
            data = tomllib.loads(f.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise RuleSetError(f"{f} : TOML invalide : {exc}") from None
        if unknown := set(data) - _GITLEAKS_TOP:
            raise RuleSetError(f"{f} : clé(s) inconnue(s) de gitleaks : {sorted(unknown)}")
        if "path" in (data.get("extend") or {}):
            raise RuleSetError(f"{f} : `[extend] path` n'est pas pris en charge dans une fusion de règles (listez plutôt les deux fichiers dans `rules`)")
        for rule in data.get("rules") or []:
            rid = rule.get("id")
            if not isinstance(rid, str) or not rid:
                raise RuleSetError(f"{f} : règle sans `id`")
            if rid in owner:
                raise RuleSetError(f"règle « {rid} » définie deux fois : {owner[rid]} et {f}")
            owner[rid] = f
            rules.append(rule)
        for k, v in (data.get("allowlist") or {}).items():
            if k in lists:
                lists[k] += [x for x in v if x not in lists[k]]
            elif k == "description":
                scalars.setdefault(k, v)
            elif k in scalars and scalars[k] != v:
                raise RuleSetError(f"{f} : allowlist.{k} diffère d'un autre fichier ({scalars[k]!r} contre {v!r})")
            else:
                scalars[k] = v
        plural += data.get("allowlists") or []
    out: dict = {"title": "Aulë : règles fusionnées"}
    if use_default:
        out["extend"] = {"useDefault": True}
    allow = {**scalars, **{k: v for k, v in lists.items() if v}}
    if allow:
        out["allowlist"] = allow
    if plural:
        out["allowlists"] = plural
    out["rules"] = rules
    return toml_dumps(out)


# --------------------------------------------------------------------------------------------------------------- trufflehog
def merge_trufflehog(files: list[Path]) -> str:
    """Un fichier de configuration TruffleHog réunissant les détecteurs (et vérificateurs) personnalisés de TOUS les fichiers."""
    detectors: list[dict] = []
    owner: dict[str, Path] = {}
    verifiers: list = []
    for f in files:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise RuleSetError(f"{f} : YAML invalide : {str(exc).splitlines()[0]}") from None
        if not isinstance(data, dict):
            raise RuleSetError(f"{f} : un dictionnaire YAML est attendu (clé `detectors`)")
        if unknown := set(data) - {"detectors", "customVerifiers"}:
            raise RuleSetError(f"{f} : clé(s) non prises en charge dans une fusion : {sorted(unknown)} (`sources` ne concerne que `multi-scan`)")
        for d in data.get("detectors") or []:
            name = d.get("name") if isinstance(d, dict) else None
            if not name:
                raise RuleSetError(f"{f} : détecteur sans `name`")
            if name in owner:
                raise RuleSetError(f"détecteur « {name} » défini deux fois : {owner[name]} et {f}")
            owner[name] = f
            detectors.append(d)
        verifiers += data.get("customVerifiers") or []
    out: dict = {"detectors": detectors}
    if verifiers:
        out["customVerifiers"] = verifiers
    return yaml.safe_dump(out, sort_keys=False, allow_unicode=True)
