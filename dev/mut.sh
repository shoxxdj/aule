#!/bin/bash
# Mutation ciblée avec restauration GARANTIE (même si la commande est interrompue).
# Usage : dev/mut.sh FICHIER "description" "texte_ancien" "texte_nouveau" tests...   (tests : modules ou test_x.Classe.methode)
# Sortie : une ligne ; « DÉTECTÉE » = au moins un test échoue (bon signe), « SURVIT » = aucun test ne voit la mutation (trou de test).
f="$1"; desc="$2"; old="$3"; new="$4"; shift 4
root="$(cd "$(dirname "$0")/.." && pwd)"; file="$root/$f"; good="$(mktemp)"; cp "$file" "$good"
trap 'cp "$good" "$file"; rm -f "$good"' EXIT INT TERM
python3 - "$file" "$old" "$new" <<'PY' || { echo "ANCRE INTROUVABLE : $desc"; exit 2; }
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
if sys.argv[2] not in s: sys.exit(1)
p.write_text(s.replace(sys.argv[2], sys.argv[3], 1))
PY
out=$(cd "$root/tests" && PYTHONPATH="$root/src" timeout 100 python3 -m unittest "$@" 2>&1); rc=$?
res=$(echo "$out" | grep -E "^(OK|FAILED)" | tail -1)
case "$res" in FAILED*) echo "DÉTECTÉE  $desc";; OK*) echo "SURVIT    $desc";; *) [ $rc -ne 0 ] && echo "DÉTECTÉE  $desc (le lanceur de tests s'est interrompu)" || echo "INDÉTERMINÉ $desc";; esac
