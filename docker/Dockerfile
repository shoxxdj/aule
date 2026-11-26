# syntax=docker/dockerfile:1
# Image d'Aulë avec TOUS les outils, leurs règles et leurs bases préchargées (aucun accès réseau nécessaire au lancement), SANS IA.
#
# ⚠ NON CONSTRUIT : ni Docker ni accès réseau n'étaient disponibles là où ce fichier a été écrit. Ce qui a pu être vérifié l'a été (versions et noms d'archives
# relevés dans les publications de chaque projet ; scripts exécutés avec de faux curl/trivy/aule ; cohérence Dockerfile ↔ aule.yaml). Un téléchargement qui échoue
# arrête la construction avec le nom de l'outil, l'URL et l'option à changer ; chaque outil est démarré (`--version`) avant la fin de la construction.
#
# CONSTRUCTION (depuis la racine du dépôt ; BuildKit requis) :
#   docker build -f docker/Dockerfile -t aule .
#   # + base NVD de dependency-check (longue : prévoir plusieurs dizaines de minutes ; clé : https://nvd.nist.gov/developers/request-an-api-key) :
#   docker build -f docker/Dockerfile -t aule --secret id=nvd_api_key,src=$HOME/.nvd_api_key .
#   Sans clé, la construction réussit et dependency-check est DÉSACTIVÉ dans l'image (le secret n'est écrit dans aucune couche).
#
# UTILISATION (/source : le dossier qui contient UN SOUS-DOSSIER PAR PROJET ; /database : base SQLite et sorties brutes) :
#   docker run --rm -v "$(pwd)/database:/database" -v "/chemin/du/code:/source:ro" aule
#   docker run --rm -v "$(pwd)/database:/database" -v "/chemin/du/code:/source:ro" aule --unpack --history      # options de `aule run`
#   docker run --rm --network none … aule                                                                          # prouve qu'aucun réseau n'est nécessaire
#   docker run --rm -v "$(pwd)/database:/database" aule show | doctor | tools …                                    # toute autre commande
#
# L'image est volumineuse (plusieurs Go : bundle CodeQL, bases de vulnérabilités). linux/amd64 uniquement.
# Versions FIGÉES : jamais « la dernière » (en mars 2026 une version de Trivy compromise, v0.69.4, a été publiée par les canaux officiels). Pour en changer :
#   --build-arg TRIVY_VERSION=… (et GITLEAKS_SHA256=… ou vide) ; la liste des versions installées est dans /opt/aule-build/TOOLS-VERSIONS.
# Le conteneur tourne en root (les scanners lisent /source) ; à la fin, les fichiers de /database sont rendus au propriétaire du dossier monté.

# git-extractor-rs (https://github.com/shoxxdj/git-tools-rs) : compilé ici. Ce dépôt n'a ni étiquette ni publication : sans GIT_TOOLS_RS_REF, la révision de tête est
# résolue À LA CONSTRUCTION et inscrite dans /opt/aule-build/GIT_TOOLS_RS_REF (donnez ce hash en --build-arg pour reconstruire à l'identique).
# Seul git-extractor-rs est copié dans l'image finale (git-dumper, qui télécharge un .git exposé depuis un site, n'a pas sa place dans un audit de code livré).
FROM rust:1-slim-bookworm AS gitrs
ARG GIT_TOOLS_RS_REF=
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    GIT_TOOLS_RS_REF="${GIT_TOOLS_RS_REF:-$(git ls-remote https://github.com/shoxxdj/git-tools-rs HEAD | cut -f1)}"; \
    test -n "${GIT_TOOLS_RS_REF}"; echo "git-tools-rs : révision ${GIT_TOOLS_RS_REF}"; \
    cargo install --locked --git https://github.com/shoxxdj/git-tools-rs --rev "${GIT_TOOLS_RS_REF}" --root /out; \
    echo "${GIT_TOOLS_RS_REF}" > /out/GIT_TOOLS_RS_REF
# Le binaire s'appelle git-extractor-rs ou git-extractor selon la version : on le normalise (Aulë cherche les deux, mais le COPY ci-dessous doit viser un nom certain).
RUN for n in git-extractor-rs git-extractor; do if [ -x "/out/bin/$n" ]; then install -m 0755 "/out/bin/$n" /out/git-extractor-rs; exit 0; fi; done; \
    echo "aucun binaire git-extractor(-rs) produit par cette révision" >&2; exit 1

FROM python:3.12-slim-bookworm

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG TRUFFLEHOG_VERSION=3.95.2
ARG TRIVY_VERSION=0.69.3
ARG OSV_VERSION=2.5.1
ARG OPENGREP_VERSION=1.30.0
ARG DEPCHECK_VERSION=12.1.8
ARG CODEQL_VERSION=2.27.0
ARG CHECKOV_VERSION=3.3.13
ARG OSV_ECOSYSTEMS="PyPI npm Maven Go crates.io NuGet Packagist RubyGems Pub Hex Hackage CRAN SwiftURL"
ARG OPENGREP_RULES_REF=

# git (historique), cloc, Java (dependency-check) ; git refuse sinon les dépôts d'un autre propriétaire que root (« dubious ownership »)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git cloc curl ca-certificates unzip default-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

# --- 1. Outils (couches stables, avant tout ce qui change souvent) ---
COPY docker/install-tools.sh docker/prefetch-data.sh /opt/aule-build/
RUN sh /opt/aule-build/install-tools.sh
RUN python -m venv /opt/checkov-venv \
    && /opt/checkov-venv/bin/pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" \
    && ln -s /opt/checkov-venv/bin/checkov /usr/local/bin/checkov \
    && checkov --version | tee -a /opt/aule-build/TOOLS-VERSIONS
COPY --from=gitrs /out/git-extractor-rs /usr/local/bin/git-extractor-rs
COPY --from=gitrs /out/GIT_TOOLS_RS_REF /opt/aule-build/GIT_TOOLS_RS_REF

# --- 2. Règles et bases (téléchargées maintenant : au lancement, plus de réseau) ---
RUN sh /opt/aule-build/prefetch-data.sh opengrep-rules
RUN sh /opt/aule-build/prefetch-data.sh trivy
RUN sh /opt/aule-build/prefetch-data.sh osv
RUN --mount=type=secret,id=nvd_api_key,required=false sh /opt/aule-build/prefetch-data.sh depcheck

# --- 3. Aulë lui-même (change souvent : en dernier pour ne rien retélécharger) ---
RUN pip install --no-cache-dir uv
COPY . /opt/aule
RUN cd /opt/aule && UV_PYTHON_DOWNLOADS=never uv sync --extra export --no-dev

# Configuration : dependency-check n'est actif que si sa base a été préparée (marqueur écrit par prefetch-data.sh)
COPY docker/aule.yaml /etc/aule/aule.yaml
RUN if [ -f /opt/depcheck-db/.prefetched ]; then enabled=true; else enabled=false; fi; \
    sed -i "s/__DEPENDENCY_CHECK_ENABLED__/${enabled}/" /etc/aule/aule.yaml; \
    echo "dependency-check actif dans l'image : ${enabled}"

COPY docker/entrypoint.sh /usr/local/bin/aule-docker
RUN chmod +x /usr/local/bin/aule-docker

ENV PATH="/opt/aule/.venv/bin:/opt/codeql:/opt/dependency-check/bin:${PATH}" \
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-data \
    PYTHONUNBUFFERED=1
VOLUME ["/database", "/source"]
WORKDIR /database
ENTRYPOINT ["/usr/local/bin/aule-docker"]
