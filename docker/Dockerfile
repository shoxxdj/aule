# ⚠ NON TESTÉ : ni Docker ni accès réseau n'étaient disponibles là où ce fichier a été écrit.
# Les noms d'archives de publication ci-dessous suivent les conventions habituelles de chaque projet mais DOIVENT
# être vérifiés (ils changent parfois entre versions). Aucune version n'est figée par défaut : donnez-les en --build-arg.
#
#   docker build -f docker/Dockerfile -t aule \
#     --build-arg GITLEAKS_VERSION=... --build-arg TRUFFLEHOG_VERSION=... --build-arg OSV_VERSION=... \
#     --build-arg TRIVY_VERSION=... --build-arg OPENGREP_VERSION=... --build-arg DEPCHECK_VERSION=... \
#     --build-arg CODEQL_VERSION=... --build-arg CHECKOV_VERSION=... --build-arg GITTOOLS_COMMIT=... .
#
# Usage (le code à auditer est monté en LECTURE SEULE, les résultats vont dans le volume /work) :
#   docker run --rm -it -v "$PWD/mission:/work" -v "/chemin/du/code:/audit:ro" -p 127.0.0.1:8765:8765 aule doctor
#   docker run --rm -it -v "$PWD/mission:/work" -v "/chemin/du/code:/audit:ro" aule run /audit --unpack --history
#   docker run --rm -it -v "$PWD/mission:/work" -p 127.0.0.1:8765:8765 aule serve --host 0.0.0.0 ...   # voir note serveur
#
# Note serveur : `aule serve` refuse toute adresse non locale (il sert des secrets en clair). Dans un conteneur il faut
# publier le port UNIQUEMENT sur 127.0.0.1 de l'hôte (-p 127.0.0.1:8765:8765) et lancer le serveur avec un nom de
# machine qui résout en boucle locale dans le conteneur ; adaptez selon votre réseau Docker ou utilisez un tunnel SSH.
FROM python:3.12-slim-bookworm

ARG GITLEAKS_VERSION
ARG TRUFFLEHOG_VERSION
ARG OSV_VERSION
ARG TRIVY_VERSION
ARG OPENGREP_VERSION
ARG DEPCHECK_VERSION
ARG CODEQL_VERSION
ARG CHECKOV_VERSION
ARG GITTOOLS_COMMIT

RUN apt-get update && apt-get install -y --no-install-recommends \
        git cloc gnupg curl ca-certificates unzip bash default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tools
RUN set -eux; \
    # gitleaks, trufflehog, trivy : archives tar.gz contenant le binaire
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" | tar -xz -C /usr/local/bin trufflehog; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin trivy; \
    # osv-scanner : binaire seul
    curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64"; \
    # opengrep : binaire seul (nom d'archive à vérifier)
    curl -fsSL -o /usr/local/bin/opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86"; \
    chmod +x /usr/local/bin/osv-scanner /usr/local/bin/opengrep; \
    # OWASP dependency-check (Java)
    curl -fsSL -o dc.zip "https://github.com/dependency-check/DependencyCheck/releases/download/v${DEPCHECK_VERSION}/dependency-check-${DEPCHECK_VERSION}-release.zip"; \
    unzip -q dc.zip -d /opt/tools && rm dc.zip && ln -s /opt/tools/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh; \
    # CodeQL bundle : CLI + requêtes précompilées (utilisable hors ligne)
    curl -fsSL "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" | tar -xz -C /opt/tools; \
    ln -s /opt/tools/codeql/codeql /usr/local/bin/codeql; \
    # GitTools (Extractor) à un commit précis
    git clone -q https://github.com/internetwache/GitTools /opt/tools/GitTools && git -C /opt/tools/GitTools checkout -q "${GITTOOLS_COMMIT}"; \
    pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" uv

COPY . /opt/aule
WORKDIR /opt/aule
RUN uv sync --extra export --no-dev || uv sync --extra export

COPY docker/aule.yaml /etc/aule/aule.yaml
RUN useradd -m aule && mkdir -p /work /audit && chown aule /work
USER aule
ENV PATH="/opt/aule/.venv/bin:${PATH}"
WORKDIR /work
ENTRYPOINT ["aule", "--config", "/etc/aule/aule.yaml", "--data", "/work/data"]
CMD ["tools"]
