#!/bin/sh
# Installe les outils d'audit à partir de leurs binaires de publication. TOUTES les versions sont figées (ARG du Dockerfile) : jamais « la dernière ».
# Pourquoi : en mars 2026 une version de Trivy compromise (v0.69.4) a été publiée par les canaux officiels ; une image qui prendrait « latest » l'aurait installée.
# Chaque archive est vérifiée contre la liste de sommes de contrôle du projet quand elle existe ; gitleaks l'est en plus contre un condensat figé.
#
#   sh install-tools.sh               installe
#   sh install-tools.sh --print-urls  affiche « outil <TAB> URL » sans rien télécharger
set -eu

BIN_DIR=${BIN_DIR:-/usr/local/bin}
OPT_DIR=${OPT_DIR:-/opt}
WORK=${WORK:-/tmp/aule-install}
BUILD_INFO=${BUILD_INFO:-/opt/aule-build}

die() { echo "ERREUR : $*" >&2; exit 1; }
say() { echo "== $*"; }
need() { eval "value=\${$1:-}"; [ -n "$value" ] || die "variable $1 requise (ARG du Dockerfile)"; }

# outil|dossier de publication|archive|fichier de sommes de contrôle (vide : aucun connu)
spec() {
  for v in GITLEAKS_VERSION TRUFFLEHOG_VERSION TRIVY_VERSION OSV_VERSION OPENGREP_VERSION DEPCHECK_VERSION CODEQL_VERSION; do need "$v"; done
  cat <<SPEC
gitleaks|https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}|gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz|gitleaks_${GITLEAKS_VERSION}_checksums.txt
trufflehog|https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}|trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz|trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt
trivy|https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}|trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz|trivy_${TRIVY_VERSION}_checksums.txt
osv-scanner|https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}|osv-scanner_linux_amd64|osv-scanner_SHA256SUMS
opengrep|https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}|opengrep_manylinux_x86|
dependency-check|https://github.com/dependency-check/DependencyCheck/releases/download/v${DEPCHECK_VERSION}|dependency-check-${DEPCHECK_VERSION}-release.zip|
codeql|https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}|codeql-bundle-linux64.tar.gz|
SPEC
}

field() { echo "$1" | cut -d'|' -f"$2"; }

# fetch URL DEST QUOI : téléchargement avec un message qui dit quoi corriger
fetch() {
  curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1" \
    || die "téléchargement impossible : $3 ($1). Version introuvable (publication pas terminée ?) ou réseau coupé : choisissez une autre version avec --build-arg (voir docker/Dockerfile)."
}

# verify_listed FICHIER SOMMES : la somme de FICHIER doit figurer, identique, dans le fichier de sommes de contrôle du projet
verify_listed() {
  name=$(basename "$1")
  expected=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1; exit }' "$2")
  [ -n "$expected" ] || die "$name ne figure pas dans $(basename "$2") : archive non vérifiable"
  actual=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$expected" = "$actual" ] || die "somme de contrôle INCORRECTE pour $name : attendue $expected, obtenue $actual (archive corrompue ou altérée)"
}

# verify_digest FICHIER CONDENSAT
verify_digest() {
  actual=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$2" = "$actual" ] || die "condensat INCORRECT pour $(basename "$1") : attendu $2, obtenu $actual (version modifiée sans donner le nouveau GITLEAKS_SHA256, ou archive altérée ; GITLEAKS_SHA256= vide pour ne vérifier que la liste du projet)"
}

download() {
  tool=$1 base=$2 asset=$3 sums=$4
  fetch "$base/$asset" "$WORK/$asset" "$tool"
  if [ -z "$sums" ]; then
    echo "  ! $tool : aucune somme de contrôle publiée connue : archive NON vérifiée" >&2
  elif curl -fsSL --retry 2 -o "$WORK/$sums" "$base/$sums" 2>/dev/null; then
    verify_listed "$WORK/$asset" "$WORK/$sums"
    say "$tool : somme de contrôle vérifiée ($sums)"
  else
    echo "  ! $tool : liste de sommes introuvable ($base/$sums) : archive NON vérifiée" >&2
  fi
}

record() { printf '%s\t%s\n' "$1" "$2" >> "$BUILD_INFO/TOOLS-VERSIONS"; }

# smoke OUTIL COMMANDE… : le binaire doit au moins démarrer (un téléchargement tronqué ou d'une mauvaise architecture échoue ici, pas au premier audit)
smoke() {
  tool=$1; shift
  out=$("$@" 2>&1) || die "$tool ne démarre pas ($*) : $(echo "$out" | head -n 3)"
  record "$tool" "$(echo "$out" | head -n 1)"
}

install_tool() {
  tool=$(field "$1" 1) base=$(field "$1" 2) asset=$(field "$1" 3) sums=$(field "$1" 4)
  say "$tool"
  download "$tool" "$base" "$asset" "$sums"
  case $tool in
    gitleaks)
      [ -z "${GITLEAKS_SHA256:-}" ] || verify_digest "$WORK/$asset" "$GITLEAKS_SHA256"
      tar -xzf "$WORK/$asset" -C "$BIN_DIR" gitleaks ;;
    trufflehog) tar -xzf "$WORK/$asset" -C "$BIN_DIR" trufflehog ;;
    trivy) tar -xzf "$WORK/$asset" -C "$BIN_DIR" trivy ;;
    osv-scanner) install -m 0755 "$WORK/$asset" "$BIN_DIR/osv-scanner" ;;
    opengrep) install -m 0755 "$WORK/$asset" "$BIN_DIR/opengrep" ;;
    dependency-check)
      unzip -q "$WORK/$asset" -d "$OPT_DIR"
      chmod +x "$OPT_DIR/dependency-check/bin/dependency-check.sh" ;;
    codeql) tar -xzf "$WORK/$asset" -C "$OPT_DIR" ;;
    *) die "outil inconnu : $tool" ;;
  esac
  rm -f "$WORK/$asset" "$WORK/$sums"
}

main() {
  if [ "${1:-}" = "--print-urls" ]; then
    table=$(mktemp)
    spec > "$table"  # pas de tube : une version manquante (die) doit arrêter le script, ce qu'un `spec | while` ne fait pas en sh
    while IFS='|' read -r tool base asset sums; do printf '%s\t%s/%s\n' "$tool" "$base" "$asset"; done < "$table"
    rm -f "$table"
    return 0
  fi
  [ "$(uname -m)" = x86_64 ] || die "architecture $(uname -m) non prise en charge : seule linux/amd64 est gérée (binaires et bundle CodeQL x64)"
  mkdir -p "$WORK" "$BUILD_INFO" "$BIN_DIR" "$OPT_DIR"
  spec > "$WORK/spec.txt"
  while IFS= read -r line; do install_tool "$line"; done < "$WORK/spec.txt"
  smoke gitleaks "$BIN_DIR/gitleaks" version
  smoke trufflehog "$BIN_DIR/trufflehog" --version
  smoke trivy "$BIN_DIR/trivy" --version
  smoke osv-scanner "$BIN_DIR/osv-scanner" --version
  smoke opengrep "$BIN_DIR/opengrep" --version
  smoke dependency-check "$OPT_DIR/dependency-check/bin/dependency-check.sh" --version
  smoke codeql "$OPT_DIR/codeql/codeql" version
  rm -rf "$WORK"
  say "outils installés ; versions dans $BUILD_INFO/TOOLS-VERSIONS"
}

[ "${AULE_SOURCE_ONLY:-}" = 1 ] || main "$@"
