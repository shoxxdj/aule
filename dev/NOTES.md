# Aulë — carte du projet (pour reprendre vite, sans relire le code)

Commande `aule` (alias `audit`) · paquet `src/aule` · Python ≥ 3.11 · seule dépendance : pyyaml (extra `export` : openpyxl, python-docx).
Une base = une mission (`data/audit.db`, SQLite, schéma v6) ; sorties brutes dans `data/runs/<run>/<projet>/<outil>/<mode>/`.

## Flux d'un passage (`aule run`)
`orchestrator.run_audit` : découverte des projets (+ archives `--unpack`) → phases d'outils 1-4 (cloc/gitleaks/links/checkov → opengrep →
dépendances → codeql) → liens → **recoupement** (`correlate`) → [critique IA, phase 5]. Chaque exécution : `runner.execute` (cmd.txt, stdout, stderr, meta.json) puis
`plugin.parse` → entités JSON (`entity`) ; tout est rejouable sans relancer l'outil (`aule reparse`).

## Modules
| Domaine | Fichiers |
|---|---|
| Outils | `plugins/<outil>.py` (`@register`, hooks dans `plugins/base.py`), `sarif.py`, `vulns.py`, `techmap.py`, `unpack.py`, `discovery.py` |
| Données | `db.py` (tables : audit, project, tool_run, entity, relation, triage, manual_finding, project_note, critique, cluster, mission), `models.py` (constantes partagées) |
| Moteur d'IA | `llmconf.py` (`LLMConfig`, `parse_llm` : UNE table décide quelle clé va avec quel moteur, `migrate`), `llm.yaml` à côté de `aule.yaml` ou `llm_file:` ; `aule.yaml` n'a AUCUN secret |
| Analyse | `correlate.py` (groupes de détections identiques), `links.py`+`linkscan.py` (relations par paires de projets ; le graphe interactif de l'interface en fait un graphe de propriétés : bloc `LG-MODEL` du gabarit, sans DOM, testé par `tests/js_model.js` + `test_graph.py`), `diff.py`, `triage.py`, `critiq.py`+`llm.py` (Ollama / LibreChat / `custom` : socle HTTP `_HttpBase` commun ; `insecure_tls.py` = seul contournement TLS, réservé à `custom`) |
| Sorties | `report.py` + `templates/report.html` (page unique : statique ET live), `export.py`, `rawview.py` (SARIF/JSON à la demande), `codeview.py` |
| Interfaces | `cli.py` (commandes), `cli_pretty.py` + `ui.py` (« forge »), `server.py` (http.server, boucle locale, jeton) |
| Exploitation | `doctor.py`, `purge.py`, `seal.py`, `config.py` (aule.yaml), `runs.py` (libellés de passages) |

## Règles à ne pas casser
- **Deux sorties CLI** : `plain` (texte historique, byte pour byte : les tests s'y appuient) et `forge` (terminal ou `--color always`). Toute commande garde son code plain.
- **Secrets** : jamais en clair en base (masqués + sha256) ; valeurs relues des sorties brutes (sha vérifié). `--mask` : jamais servis. Jetons d'API : dans `llm.yaml` (chmod 600, avertissement sinon), JAMAIS dans l'environnement ni dans `aule.yaml`, jamais journalisés ni dans les erreurs ; TLS toujours vérifié sauf `verify_tls: false` (custom seulement). L'ancien format (moteur dans `critiq`) est refusé : `aule llm migrate`. La clé NVD (dependency-check) est `options.nvd_api_key` dans aule.yaml (avertissement si lisible par d'autres) ; reste lu dans l'environnement : `AULE_PASSPHRASE` (scellement).
- **Critique IA** : avis consultatifs, jamais de triage automatique ; aucune valeur de secret envoyée ; code audité = donnée non fiable. Pannes du moteur : `LLMError.transient` (504/503/429/timeout… oui ; 401/404/500/certificat/DNS non), `critiq.auto_retry` = retenter SANS limite l'appel en échec (`_patiently`), pas le constat ; sans l'option : 3 erreurs de suite abandonnent. Demandes de code : standard (3 tours, 120 lignes) ou ÉTENDU par la case `allow_more_code` (plus de tours, liste de dossiers, budget) ; la case donne plus de CODE mais ne lève jamais secrets/deny_globs/confinement ; le mode n'entre dans l'empreinte de cache qu'étendu (avis existants préservés), un avis étendu sert au standard.
- **Aucune règle gitleaks embarquée** (décision de l'utilisateur : « laisse-moi les définir à part ») : sans `rules`, pas de --config ; `credential_rules` est REFUSÉE avec un message de migration ; l'exemple `examples/gitleaks-credentials.example.toml` n'est jamais chargé (testé : RE2, corpus). Ancienne note : `rules/credentials.gitleaks.toml` (4 règles, `[extend] useDefault`, exclusion GLOBALE `[allowlist]` seulement : la forme par règle a changé en 8.21 ; expressions RE2 : ni anticipation ni rétroréférence), ajouté par `Gitleaks._rules_args` sauf option `credential_rules: false`, `--config` de l'utilisateur ou gitleaks < 8.9.0 (avertissements via `Tool.warnings`). `aule doctor` = test de RAPPEL (`CREDENTIAL_CANARY`). Le faux gitleaks honore `--config` si `FAKE_GITLEAKS_HONOR_CONFIG`.
- **Règles personnalisées** : `tools.<outil>.rules` (liste de chemins, `ToolConfig.rules`), `Tool.supports_rules` + `Tool.check_rules`, contrôle central `orchestrator.rules_problem` (outil sans règles, chemin introuvable, validation propre à l'outil, AVANT tout lancement). `rulesets.py` : `expand`, `merge_gitleaks`/`merge_trufflehog` (UN seul --config : fusion écrite dans la sortie brute) et un écrivain TOML (`toml_dumps`, aller-retour testé). opengrep/checkov/trivy : option répétée ; codeql : sous-dossier par langage. Les faux outils journalisent leurs arguments (`FAKE_ARGV_DIR`).
- **Image Docker** : `docker/Dockerfile` ORCHESTRE trois scripts testables (exécutés avec de faux curl/trivy/aule dans `tests/test_docker.py`) : `install-tools.sh` (binaires de publication, versions FIGÉES en ARG, sommes de contrôle vérifiées, `--version` de chaque outil), `prefetch-data.sh` (règles opengrep, bases Trivy/OSV, base NVD par SECRET de construction), `entrypoint.sh` (`aule run /source` par défaut, `/database`, chown final, transmission des signaux). `docker/aule.yaml` : tous les outils activés, hors ligne, sans IA ; `__DEPENDENCY_CHECK_ENABLED__` remplacé selon le marqueur de la base NVD. `.dockerignore` écarte aule.yaml/llm.yaml/data. NON CONSTRUITE (ni Docker ni réseau là où elle a été écrite). Versions : Trivy ≠ 0.69.4/5/6 (GHSA-69fq-xp46-6x23).
- **gitleaks ≡ `gitleaks -c`** : `dir`/`history` s'exécutent DANS le dossier scanné avec la cible `.` (`Gitleaks.cwd`, `_anchored` pour les chemins relatifs d'`extra_args`, `_relative` accepte les chemins relatifs) car gitleaks teste `path` contre les chemins tels que donnés ; `default_rules: auto|true|false` (auto : `wants_default(fichiers)`, jamais le fichier d'Aulë) ; `meta.json` consigne `cwd` pour rejouer. Le faux gitleaks normalise ses chemins comme Go et modélise l'exclusion globale par défaut (node_modules/, vendor/).
- **`default_pass` (générique, tous les outils à `rules`)** : clé d'OUTIL (`ToolConfig.default_pass`). `Tool.passes(cfg)` → [("default", cfg sans rules), ("rules", cfg)] ; `runner.execute` exécute chaque passe (la passe 1 à la racine, les suivantes dans `<mode>/<nom>/` : noms de rapport imposés par l'outil, ex. checkov) ; `runner.parse_task` analyse chaque rapport avec le `parse` de l'outil et fusionne par empreinte (`config_pass`, `report` pour relire) ; `raw_ref`/`clear_values_of`/`report_digest` : indices de lecture en clair et empreinte couvrent TOUS les rapports. gitleaks : la passe 2 est autonome (`_use_default` → False). Preuve de généricité : `tests/test_passes.py` (faux outil qui ne connaît rien aux passes).
- **Triage** : par empreinte, étendu au groupe recoupé ; jamais d'écrasement d'une décision humaine.
- Un outil est **optionnel** (`default_enabled=False`) sauf cloc, gitleaks, links.

## Tests (`dev/test.sh [core ui ops tools live data ai]`, ~5 min au total, 1 CPU)
Faux outils : `tests/fakes.py` (dont git-extractor-rs fidèle au code source) ; faux serveurs : `fake_ollama.py`, `fake_librechat.py` (TLS réel) ;
interface : scénarios node `tests/*_scenario.js` sur `dom_stub.js` (pas de vrai navigateur). Mutations : `dev/mut.sh`. Code mort : `dev/deadcode.py`. Livraison : `dev/package.sh <nom>`.

## Pièges déjà rencontrés
- Une commande est limitée à 300 s : `dev/test.sh` s'arrête avant et dit ce qui reste. Un processus lancé en arrière-plan est tué à la fin de l'appel.
- Scripts de patch : une ancre introuvable interrompt TOUT le script en silence → vérifier que les fichiers ont été écrits (`grep`), ne pas se fier à « les tests passent ».
- `env -i` efface l'environnement (jeton, PATH). `shutil` est global : ne masquer que ce qui est visé. `os.chdir` dans un test : restituer le dossier.
- Une expression JS `const x = …` utilisée avant sa déclaration (zone morte) passe `node --check` mais échoue à l'exécution.
- Les options communes (`--data`, `--config`, `--color`, `--ascii`) acceptent l'avant ET l'après de la commande (valeurs par défaut posées dans `main()`).
- Ne pas deviner un format d'outil externe : lire sa source ou sa sortie réelle (git-extractor-rs : `snapshots.json` lu dans son code).

## Limites connues (jamais vérifié sur les vrais outils)
Aucun outil réel exécuté dans ce bac à sable (opengrep, CodeQL, gitleaks…, git-extractor-rs, LibreChat) ; rendu non vu dans un vrai navigateur ; Docker non construit ; Windows non testé.
