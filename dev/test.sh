#!/bin/bash
# Lance des groupes de tests avec une sortie minimale (une ligne par groupe ; les échecs seulement, tronqués).
# Usage : dev/test.sh [groupe...]   groupes : core data tools ops live ai ui   (défaut : tous)
# Garde-fou : une commande ne doit pas dépasser ~300 s ; le script s'arrête avant et liste ce qui RESTE à lancer.
cd "$(dirname "$0")/../tests" || exit 2
export PYTHONPATH="$(cd ../src && pwd)"
declare -A MODS=(
  [core]="test_pipeline test_config test_llmconf test_unpack test_history test_report"                                   # ~20 s
  [ui]="test_ui test_forge_cli test_naming test_gitextractor test_graph"                                      # ~35 s
  [ops]="test_triage_diff test_export test_ops test_credrules test_docker test_gitleaks_parity test_passes"                                              # ~45 s
  [tools]="test_sast_deps test_codeql test_more_tools test_links test_rules_dirs"                              # ~50 s
  [live]="test_server test_live_ui"                                                                         # ~40 s
  [data]="test_missions test_rawview test_rawview_api test_share test_code test_code_ui test_correlate test_correlate_ui"   # ~55 s
  [ai]="test_critiq test_critiq_ui test_librechat test_custom_llm test_morecode test_autoretry"                  # ~230 s
)
declare -A EST=([core]=25 [ui]=40 [ops]=50 [tools]=55 [live]=45 [data]=60 [ai]=250)
groups=("$@"); [ ${#groups[@]} -eq 0 ] && groups=(core ui ops tools live data ai)
start=$(date +%s); rc=0; left=()
for g in "${groups[@]}"; do
  [ -z "${MODS[$g]}" ] && { echo "groupe inconnu : $g"; exit 2; }
  if [ $(( $(date +%s) - start + ${EST[$g]} )) -gt 270 ]; then left+=("$g"); continue; fi
  t0=$(date +%s)
  out=$(timeout 280 python3 -W error::ResourceWarning -m unittest ${MODS[$g]} 2>&1); code=$?
  last=$(echo "$out" | grep -E "^(OK|FAILED)" | tail -1); n=$(echo "$out" | grep -E "^Ran " | awk '{print $2}')
  printf "%-6s %-22s %s tests  %ss\n" "$g" "${last:-ÉCHEC DE LANCEMENT}" "${n:-?}" $(( $(date +%s) - t0 ))
  if [ $code -ne 0 ]; then rc=1; echo "$out" | grep -E "^(FAIL|ERROR):|Error|assert" | head -12 | cut -c1-200; fi
done
[ ${#left[@]} -gt 0 ] && echo "À LANCER ENSUITE (limite de temps) : dev/test.sh ${left[*]}"
exit $rc
