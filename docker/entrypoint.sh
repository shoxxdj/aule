#!/bin/sh
# Point d'entrée de l'image Docker d'Aulë.
#
#   docker run --rm -v "$PWD/database:/database" -v "/chemin/du/code:/source:ro" aule             audite /source (un sous-dossier par projet), résultats dans /database
#   docker run … aule --unpack --history                                                          les options de `aule run /source`
#   docker run … aule doctor | tools | show …                                                     toute autre commande d'Aulë
#   docker run -it … aule sh                                                                      un shell (diagnostic)
#
# Les fichiers écrits par le conteneur (root) sont rendus à l'utilisateur de l'hôte qui possède le dossier monté sur /database.
set -u

CONFIG=${AULE_CONFIG:-/etc/aule/aule.yaml}
DATA=${AULE_DATA:-/database}
SOURCE=${AULE_SOURCE:-/source}
DEPCHECK_MARKER=${AULE_DEPCHECK_MARKER:-/opt/depcheck-db/.prefetched}

case ${1:-} in
  sh|bash) exec "$@" ;;
esac

if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
  # Audit de SOURCE. Quelques vérifications avant de lancer des heures d'analyse : Aulë traite chaque sous-dossier direct comme un projet.
  if [ ! -d "$SOURCE" ]; then
    echo "ERREUR : $SOURCE n'existe pas. Montez le code à auditer : -v \"/chemin/du/code:$SOURCE:ro\"" >&2
    exit 2
  fi
  if [ -z "$(find "$SOURCE" -mindepth 1 -maxdepth 1 -type d ! -name '.*' 2>/dev/null | head -n 1)" ]; then
    echo "ERREUR : $SOURCE ne contient aucun sous-dossier : Aulë audite UN PROJET PAR SOUS-DOSSIER." >&2
    echo "         Pour un seul projet, montez son dossier PARENT (ou un dossier qui le contient) : -v \"/chemin/du/parent:$SOURCE:ro\"" >&2
    exit 2
  fi
  if [ ! -f "$DEPCHECK_MARKER" ]; then
    echo "! dependency-check est désactivé dans cette image : sa base NVD n'a pas été préparée à la construction (docker build --secret id=nvd_api_key,src=…)" >&2
  fi
  set -- run "$SOURCE" "$@"
fi

mkdir -p "$DATA"
aule --config "$CONFIG" --data "$DATA" "$@" <&0 &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT
wait "$pid"
rc=$?
if [ "$rc" -gt 128 ]; then wait "$pid" 2>/dev/null; rc=$?; fi  # signal reçu : on attend la fin réelle d'aule
trap - TERM INT

if [ "$(id -u)" = 0 ]; then
  owner=$(stat -c '%u:%g' "$DATA" 2>/dev/null || echo "0:0")
  [ "$owner" = "0:0" ] || chown -R "$owner" "$DATA" 2>/dev/null || true
fi
exit "$rc"
