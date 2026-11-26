#!/bin/sh
# Télécharge À LA CONSTRUCTION de l'image les règles et les bases dont les outils ont besoin : au lancement, aucun accès réseau n'est nécessaire.
#   sh prefetch-data.sh opengrep-rules | trivy | osv | depcheck
set -eu

RULES_DIR=${RULES_DIR:-/opt/rules}
TRIVY_CACHE=${TRIVY_CACHE:-/opt/trivy-cache}
OSV_DIR=${OSV_DIR:-/opt/osv-data}
DEPCHECK_DB=${DEPCHECK_DB:-/opt/depcheck-db}
DEPCHECK_SH=${DEPCHECK_SH:-/opt/dependency-check/bin/dependency-check.sh}
NVD_KEY_FILE=${NVD_KEY_FILE:-/run/secrets/nvd_api_key}
BUILD_INFO=${BUILD_INFO:-/opt/aule-build}
OSV_BASE=${OSV_BASE:-https://osv-vulnerabilities.storage.googleapis.com}
OSV_REQUIRED=${OSV_REQUIRED:-"PyPI npm Maven Go crates.io NuGet Packagist RubyGems"}
OSV_ECOSYSTEMS=${OSV_ECOSYSTEMS:-"$OSV_REQUIRED Pub Hex Hackage CRAN SwiftURL"}

die() { echo "ERREUR : $*" >&2; exit 1; }
say() { echo "== $*"; }

# Règles d'opengrep : un clone superficiel ; la révision est conservée (le rapport l'affiche) et inscrite dans TOOLS-VERSIONS.
prefetch_opengrep_rules() {
  repo=${OPENGREP_RULES_REPO:-https://github.com/opengrep/opengrep-rules}
  dest="$RULES_DIR/opengrep-rules"
  mkdir -p "$RULES_DIR" "$BUILD_INFO"
  rm -rf "$dest"
  git clone --quiet --depth 1 "$repo" "$dest"
  if [ -n "${OPENGREP_RULES_REF:-}" ]; then
    git -C "$dest" fetch --quiet --depth 1 origin "$OPENGREP_RULES_REF"
    git -C "$dest" checkout --quiet FETCH_HEAD
  fi
  [ -d "$dest/python" ] || die "jeu de règles inattendu : pas de dossier python/ dans $repo"
  printf 'opengrep-rules\t%s\n' "$(git -C "$dest" rev-parse HEAD)" >> "$BUILD_INFO/TOOLS-VERSIONS"
}

# Trivy : base des vulnérabilités + base Java (jar). Le bundle de contrôles de configuration est dans le binaire (sans réseau).
prefetch_trivy() {
  mkdir -p "$TRIVY_CACHE"
  trivy --cache-dir "$TRIVY_CACHE" image --download-db-only
  trivy --cache-dir "$TRIVY_CACHE" image --download-java-db-only
  [ -s "$TRIVY_CACHE/db/trivy.db" ] || die "base Trivy absente après téléchargement ($TRIVY_CACHE/db/trivy.db)"
  [ -s "$TRIVY_CACHE/java-db/trivy-java.db" ] || die "base Java de Trivy absente après téléchargement ($TRIVY_CACHE/java-db/trivy-java.db)"
}

# OSV-Scanner : une archive par écosystème, rangée où `--offline` la cherche : $OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY/osv-scanner/<écosystème>/all.zip.
# Les écosystèmes de OSV_REQUIRED sont obligatoires (échec de la construction) ; les autres sont facultatifs. Une base absente donne ensuite une ERREUR à l'analyse, jamais un faux « rien ».
prefetch_osv() {
  mkdir -p "$OSV_DIR/osv-scanner"
  done_list=""
  for eco in $OSV_ECOSYSTEMS; do
    dest="$OSV_DIR/osv-scanner/$eco"
    mkdir -p "$dest"
    if curl -fsSL --retry 3 --retry-delay 2 -o "$dest/all.zip" "$OSV_BASE/$eco/all.zip" && unzip -tq "$dest/all.zip" >/dev/null 2>&1; then
      done_list="$done_list $eco"
    else
      rm -rf "$dest"
      case " $OSV_REQUIRED " in
        *" $eco "*) die "base OSV obligatoire introuvable ou corrompue : $eco ($OSV_BASE/$eco/all.zip)" ;;
      esac
      echo "  ! base OSV facultative absente : $eco" >&2
    fi
  done
  [ -n "$done_list" ] || die "aucune base OSV téléchargée"
  printf '%s\n%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${done_list# }" > "$OSV_DIR/.prefetched"
}

# dependency-check : la base NVD exige une clé d'API, donnée en SECRET de construction (docker build --secret id=nvd_api_key,src=…). Le secret n'est écrit dans aucune couche.
# Sans clé : la base n'est pas préparée et l'image désactive dependency-check (voir le Dockerfile).
prefetch_depcheck() {
  if [ ! -s "$NVD_KEY_FILE" ]; then
    echo "  ! pas de secret nvd_api_key : base NVD NON préparée, dependency-check sera DÉSACTIVÉ dans l'image" >&2
    return 0
  fi
  mkdir -p "$DEPCHECK_DB"
  key=$(cat "$NVD_KEY_FILE")
  log=$(mktemp)
  if ! "$DEPCHECK_SH" --updateonly --data "$DEPCHECK_DB" --nvdApiKey "$key" > "$log" 2>&1; then
    tail -n 8 "$log" | grep -vF -- "$key" >&2 || true  # jamais la clé dans une sortie
    rm -f "$log"
    die "mise à jour de la base NVD en échec (clé invalide ? limite de débit ?)"
  fi
  rm -f "$log"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$DEPCHECK_DB/.prefetched"
}

main() {
  case ${1:-} in
    opengrep-rules) say "règles opengrep"; prefetch_opengrep_rules ;;
    trivy) say "bases Trivy"; prefetch_trivy ;;
    osv) say "bases OSV"; prefetch_osv ;;
    depcheck) say "base NVD (dependency-check)"; prefetch_depcheck ;;
    *) die "usage : prefetch-data.sh opengrep-rules | trivy | osv | depcheck" ;;
  esac
}

[ "${AULE_SOURCE_ONLY:-}" = 1 ] || main "$@"
