"""Correspondances entre technologies détectées (noms de langages de cloc) et outils d'analyse."""
from __future__ import annotations

import os
from pathlib import Path

# langage cloc -> dossier de règles du dépôt opengrep-rules (les dossiers absents du clone local sont ignorés)
OPENGREP_RULE_DIRS = {
    "Python": "python", "JavaScript": "javascript", "JSX": "javascript", "Vuejs Component": "javascript",
    "TypeScript": "typescript", "Java": "java", "Kotlin": "kotlin", "Scala": "scala", "C#": "csharp",
    "Go": "go", "PHP": "php", "Ruby": "ruby", "Rust": "rust", "Swift": "swift", "C": "c",
    "C/C++ Header": "c", "C++": "cpp", "Bourne Shell": "bash", "Bourne Again Shell": "bash",
    "Dockerfile": "dockerfile", "HCL": "terraform", "YAML": "yaml", "JSON": "json", "HTML": "html",
    "Apex Class": "apex", "Apex Trigger": "apex", "Elixir": "elixir", "Clojure": "clojure",
    "OCaml": "ocaml", "Solidity": "solidity", "Dart": "dart", "Lua": "lua",
}

# langage cloc -> identifiant de langage CodeQL (≥ 2.17 : java-kotlin, javascript-typescript, c-cpp).
# Volontairement absents : Swift (macOS + build), Rust, GitHub Actions... à ajouter via `language_map`.
# « C/C++ Header » seul n'est pas analysable (aucune unité de compilation).
CODEQL_LANGUAGES = {
    "Python": "python",
    "JavaScript": "javascript-typescript", "JSX": "javascript-typescript",
    "Vuejs Component": "javascript-typescript", "TypeScript": "javascript-typescript",
    "Java": "java-kotlin", "Kotlin": "java-kotlin", "C#": "csharp", "Go": "go", "Ruby": "ruby",
    "C": "c-cpp", "C++": "c-cpp",
}

# langage cloc -> écosystème de dépendances (dependency-check)
LANGUAGE_ECOSYSTEMS = {
    "Java": "java", "Kotlin": "java", "Scala": "java", "Groovy": "java", "Maven": "java", "Gradle": "java",
    "JavaScript": "node", "TypeScript": "node", "JSX": "node", "Vuejs Component": "node",
    "Python": "python", "Ruby": "ruby", "PHP": "php",
    "C#": "dotnet", "Visual Basic": "dotnet", "F#": "dotnet", "ASP.NET": "dotnet",
    "Go": "go", "Swift": "swift", "Dart": "dart", "C": "native", "C++": "native",
}

# nom de fichier (ou suffixe) -> écosystème. Nécessaire car cloc ne compte pas les binaires (.jar, .dll)
# ni les fichiers de verrouillage : un projet livré en jars n'a aucun « langage Java ».
MANIFESTS = {
    "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "java", "ivy.xml": "java",
    ".jar": "java", ".war": "java", ".ear": "java", ".aar": "java",
    "package.json": "node", "package-lock.json": "node", "npm-shrinkwrap.json": "node",
    "yarn.lock": "node", "pnpm-lock.yaml": "node",
    "requirements.txt": "python", "pipfile": "python", "pipfile.lock": "python", "poetry.lock": "python",
    "pyproject.toml": "python", "setup.py": "python",
    "gemfile": "ruby", "gemfile.lock": "ruby", ".gemspec": "ruby",
    "composer.json": "php", "composer.lock": "php",
    ".csproj": "dotnet", ".vbproj": "dotnet", ".fsproj": "dotnet", ".sln": "dotnet", ".nuspec": "dotnet",
    "packages.config": "dotnet", ".dll": "dotnet",
    "go.mod": "go", "go.sum": "go",
    "package.swift": "swift", "podfile": "swift", "podfile.lock": "swift",
    "pubspec.yaml": "dart", "pubspec.lock": "dart",
    "conanfile.txt": "native", "conanfile.py": "native", "cmakelists.txt": "native",
    # infrastructure as code (Dockerfile* : voir detect_ecosystems)
    ".tf": "iac", ".tfvars": "iac", ".bicep": "iac", "docker-compose.yml": "iac", "docker-compose.yaml": "iac",
    "compose.yml": "iac", "compose.yaml": "iac", "chart.yaml": "iac", "kustomization.yaml": "iac", "serverless.yml": "iac",
}
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
_MAX_ENTRIES = 50_000


def detect_ecosystems(languages: dict[str, int] | None, root: Path) -> set[str]:
    """Écosystèmes présents : langages cloc (si connus) + manifestes et binaires trouvés sur le disque."""
    found = {LANGUAGE_ECOSYSTEMS[lang] for lang in (languages or {}) if lang in LANGUAGE_ECOSYSTEMS}
    seen = 0
    for _dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            seen += 1
            low = name.lower()
            eco = MANIFESTS.get(low) or MANIFESTS.get(os.path.splitext(low)[1]) or ("iac" if low.startswith("dockerfile") else None)
            if eco:
                found.add(eco)
        if seen > _MAX_ENTRIES:  # monorepo géant : on s'arrête, mieux vaut un résultat partiel que bloquer
            break
    return found
