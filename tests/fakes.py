"""Faux binaires cloc / gitleaks / extractor.sh pour les tests et les démos (aucune installation requise).

Ils imitent les interfaces réelles (arguments, codes retour, formats de rapport), mais travaillent sur le
contenu réel des dossiers : le fake gitleaks cherche vraiment des clés AWS / jetons GitHub dans les
fichiers (dir) et dans l'historique git (git), le fake extractor reconstruit chaque commit.
"""
from __future__ import annotations

import stat
from pathlib import Path

SECRET_A = "AKIAIOSFODNN7EXAMPLE"          # présent dans config.py au 1er commit, supprimé ensuite
SECRET_B = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"  # settings.py, jamais supprimé

CLOC = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if "--version" in args:
    print("2.00"); sys.exit(0)
if os.environ.get("FAKE_LOG"):
    open(os.environ["FAKE_LOG"], "a").write("cloc\n")
report = [a.split("=", 1)[1] for a in args if a.startswith("--report-file=")][0]
excluded = set(next((a.split("=", 1)[1].split(",") for a in args if a.startswith("--exclude-dir=")), []))
path = args[-1]
names = {".py": "Python", ".js": "JavaScript", ".md": "Markdown", ".java": "Java", ".yml": "YAML", ".c": "C", ".go": "Go", ".cs": "C#"}
stats = {}
for dp, dns, fns in os.walk(path):
    dns[:] = [d for d in dns if d != ".git" and d not in excluded]
    for fn in fns:
        lang = names.get(os.path.splitext(fn)[1])
        if not lang:
            continue
        lines = open(os.path.join(dp, fn), errors="replace").read().splitlines()
        s = stats.setdefault(lang, {"nFiles": 0, "blank": 0, "comment": 0, "code": 0})
        s["nFiles"] += 1
        s["blank"] += sum(1 for l in lines if not l.strip())
        s["comment"] += sum(1 for l in lines if l.strip().startswith("#"))
        s["code"] += sum(1 for l in lines if l.strip() and not l.strip().startswith("#"))
if stats:
    out = {"header": {"cloc_version": "2.00"}, **stats,
           "SUM": {k: sum(s[k] for s in stats.values()) for k in ("nFiles", "blank", "comment", "code")}}
    json.dump(out, open(report, "w"))
'''

GITLEAKS = r'''#!/usr/bin/env python3
import json, os, re, subprocess, sys
args = sys.argv[1:]
if args[0] == "version":
    print(os.environ.get("FAKE_GITLEAKS_VERSION", "8.30.0")); sys.exit(0)
mode, path = args[0], args[-1]
if os.environ.get("FAKE_GL_ARGV"):
    open(os.environ["FAKE_GL_ARGV"], "a").write(json.dumps(args) + "\n")
if os.environ.get("FAKE_GL_NO_REPORT_CONFIG") and "--config" in args:  # sort « avec succès » sans écrire de rapport
    sys.exit(0)
if os.environ.get("FAKE_GL_FAIL_CONFIG") and "--config" in args:  # une configuration que le « vrai » gitleaks refuserait à l'exécution
    sys.stderr.write("boom : configuration refusée\n"); sys.exit(2)
if os.environ.get("FAKE_LOG"):
    open(os.environ["FAKE_LOG"], "a").write("gitleaks-" + mode + "\n")
if os.environ.get("FAKE_GITLEAKS_FAIL"):
    sys.stderr.write("fatal: boom\n"); sys.exit(2)
report = args[args.index("--report-path") + 1]
RULES = [("aws-access-token", re.compile(r"AKIA[0-9A-Z]{16}")), ("github-pat", re.compile(r"ghp_[A-Za-z0-9]{36}"))]
findings = []
# FAKE_GITLEAKS_HONOR_CONFIG : applique --config comme le vrai gitleaks (règles [[rules]] : regex, secretGroup, path ; [allowlist] global ; SANS
# `[extend] useDefault`, --config REMPLACE les règles par défaut). Désactivé par défaut : les corpus des autres tests contiennent des .env.
CUSTOM, ALLOW, ALLOW_PATHS = [], [], []
if os.environ.get("FAKE_GITLEAKS_HONOR_CONFIG"):
    defaults_active = True  # sans --config : la configuration par défaut de gitleaks
    if "--config" in args:
        import tomllib
        conf = tomllib.load(open(args[args.index("--config") + 1], "rb"))
        defaults_active = bool(conf.get("extend", {}).get("useDefault"))
        if not defaults_active:
            RULES = []
        CUSTOM = [(r["id"], re.compile(r["regex"]), r.get("secretGroup", 0), re.compile(r["path"]) if r.get("path") else None, r.get("description", "")) for r in conf.get("rules", [])]
        ALLOW = [re.compile(x) for x in conf.get("allowlist", {}).get("regexes", [])]
        ALLOW_PATHS = [re.compile(x) for x in conf.get("allowlist", {}).get("paths", [])]
    if defaults_active:  # MODÈLE SIMPLIFIÉ de l'exclusion globale par défaut de gitleaks (dossiers de dépendances) ; elle s'applique à TOUTES les règles quand on étend les règles par défaut
        ALLOW_PATHS += [re.compile(r"(?:^|/)node_modules/"), re.compile(r"(?:^|/)vendor/")]

def scan(text, **extra):
    if any(rx.search(str(extra.get("File", ""))) for rx in ALLOW_PATHS):  # exclusion globale par chemin, testée sur le chemin TEL QUE rapporté (absolu avec une cible absolue)
        return
    for i, line in enumerate(text.splitlines(), 1):
        for rule, rx in RULES:
            for m in rx.finditer(line):
                findings.append({"RuleID": rule, "Description": rule.replace("-", " ").title(), "Secret": m.group(0),
                                 "Match": line.strip(), "StartLine": i, "EndLine": i, "Entropy": 3.8, "Tags": ["key"], **extra})
        for rid, rx, group, path_rx, desc in CUSTOM:
            if path_rx and not path_rx.search(str(extra.get("File", ""))):
                continue
            for m in rx.finditer(line):
                secret = m.group(group)
                if not any(a.search(secret) for a in ALLOW):
                    findings.append({"RuleID": rid, "Description": desc, "Secret": secret, "Match": line.strip(), "StartLine": i, "EndLine": i,
                                     "Entropy": 2.0, "Tags": ["credential"], **extra})

if mode == "dir":
    for dp, dns, fns in os.walk(path):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in sorted(fns):
            full = os.path.normpath(os.path.join(dp, fn))  # comme filepath.WalkDir de Go : `src/app.js` pour la cible `.` (jamais `./src/app.js`)
            try:
                scan(open(full, errors="strict").read(), File=full)
            except (UnicodeDecodeError, OSError):
                pass
elif mode == "git":
    git = lambda *a: subprocess.run(["git", "-C", path, *a], capture_output=True, text=True)
    log = git("log", "--all", "--format=%H%x09%an%x09%ae%x09%aI%x09%s")
    if log.returncode != 0:
        sys.stderr.write("fatal: not a git repository\n"); sys.exit(2)
    for row in log.stdout.splitlines():
        h, an, ae, ad, subj = row.split("\t", 4)
        for f in git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", h).stdout.split():
            body = git("show", f"{h}:{f}")
            if body.returncode == 0:
                scan(body.stdout, File=f, Commit=h, Author=an, Email=ae, Date=ad, Message=subj)
json.dump(findings, open(report, "w"))
sys.exit(1 if findings else 0)  # gitleaks renvoie 1 quand il trouve des fuites
'''

# Imite GitTools Extractor : <dest>/<n>-<hash>/ (arbre complet) + commit-meta.txt (git cat-file -p)
EXTRACTOR = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
if os.environ.get("FAKE_ARGV"):
    open(os.environ["FAKE_ARGV"], "a").write(json.dumps(sys.argv[1:]) + "\n")  # journalisé dès l'entrée, même si l'appel est invalide
repo, dest = sys.argv[1:3]
if os.environ.get("FAKE_LOG"):
    open(os.environ["FAKE_LOG"], "a").write("extractor\n")
if os.environ.get("FAKE_EXTRACTOR_FAIL"):
    sys.stderr.write("extractor: broken repository\n"); sys.exit(1)
hashes = subprocess.run(["git", "-C", repo, "rev-list", "--reverse", "--all"], capture_output=True, text=True).stdout.split()
for i, h in enumerate(hashes):
    d = os.path.join(dest, f"{i}-{h}")
    os.makedirs(d)
    subprocess.run(f"git -C '{repo}' archive {h} | tar -x -C '{d}'", shell=True, check=True)
    with open(os.path.join(d, "commit-meta.txt"), "w") as fh:
        fh.write(subprocess.run(["git", "-C", repo, "cat-file", "-p", h], capture_output=True, text=True).stdout)
'''


# Imite git-extractor-rs (shoxxdj/git-tools-rs), d'après son CODE SOURCE (src/main.rs) : arguments clap (le dépôt ; la sortie en positionnel OU -o, jamais les deux),
# TOUS les objets (même inaccessibles) dans blobs/ commits/ trees/ tags/ (charges utiles brutes), metadata/objects.json [{hash, object_type, size, path}],
# un instantané par commit snapshots/<AAAAMMJJ-HHMM>_<hash>/ (fichiers réguliers seulement), metadata/snapshots.json
# [{commit, directory, date, timestamp, tz_offset, files}] et report.json {repository, total_objects, counts, includes_unreachable_objects}.
# Comportements repris du code : dépôt sans objet -> « No Git objects found. » code 0 et RIEN d'écrit ; le premier `git archive` en échec arrête TOUT
# (objets et objects.json déjà écrits, ni snapshots.json ni report.json) avec « Error: git archive failed for <hash>: … » code 1.
GIT_EXTRACTOR_RS = r'''#!/usr/bin/env python3
import io, json, os, re, subprocess, sys, tarfile
from datetime import datetime, timedelta, timezone
args = sys.argv[1:]
if os.environ.get("FAKE_ARGV"):
    open(os.environ["FAKE_ARGV"], "a").write(json.dumps(args) + "\n")
if args[:1] == ["--version"]:
    if os.environ.get("FAKE_EXTRACTOR_NO_VERSION"):      # une autre version de l'outil pourrait ne pas l'avoir
        sys.stderr.write("error: unexpected argument '--version' found\n"); sys.exit(2)
    print("git-extractor-rs 0.1.0"); sys.exit(0)
out, threads, date, report, positional = None, 4, "committer", True, []
i = 0
while i < len(args):
    a = args[i]
    if a in ("-o", "--output"):
        out = args[i + 1]; i += 2
    elif a in ("-j", "--threads"):
        threads = int(args[i + 1]); i += 2
    elif a == "--snapshot-date":
        date = args[i + 1]; i += 2
        if date not in ("committer", "author"):
            sys.stderr.write("error: invalid value '%s' for '--snapshot-date <SNAPSHOT_DATE>'\n" % date); sys.exit(2)
    elif a == "--report":
        report = args[i + 1] == "true"; i += 2
    else:
        positional.append(a); i += 1
repo = positional[0]
if len(positional) > 1:
    if out is not None:
        sys.stderr.write("error: the argument '[OUTPUT]' cannot be used with '--output <DIR>'\n"); sys.exit(2)
    out = positional[1]
out = out or "./xtracted"
if os.environ.get("FAKE_LOG"):
    open(os.environ["FAKE_LOG"], "a").write("extractor\n")
if os.environ.get("FAKE_EXTRACTOR_FAIL"):
    sys.stderr.write("extractor: broken repository\n"); sys.exit(1)
if threads == 0:
    sys.stderr.write("Error: --threads must be greater than zero\n"); sys.exit(1)
git = lambda *a, **k: subprocess.run(["git", "-C", repo, *a], capture_output=True, **k)
chk = git("rev-parse", "--git-dir", text=True)
if chk.returncode != 0:
    sys.stderr.write("Error: not a Git repository: " + chk.stderr.strip() + "\n"); sys.exit(1)
os.makedirs(out, exist_ok=True)
hashes = sorted(set(l.strip() for l in git("cat-file", "--batch-all-objects", "--batch-check=%(objectname)", text=True).stdout.splitlines() if l.strip()))
if not hashes:
    print("No Git objects found."); sys.exit(0)
folder = {"blob": "blobs", "commit": "commits", "tree": "trees", "tag": "tags"}
objects = []
for h in hashes:
    kind = git("cat-file", "-t", h, text=True).stdout.strip()
    payload = git("cat-file", kind, h).stdout
    os.makedirs(os.path.join(out, folder[kind]), exist_ok=True)
    path = os.path.join(out, folder[kind], h)
    open(path, "wb").write(payload)
    objects.append({"hash": h, "object_type": kind, "size": len(payload), "path": os.path.abspath(path)})
os.makedirs(os.path.join(out, "metadata"), exist_ok=True)
json.dump(objects, open(os.path.join(out, "metadata", "objects.json"), "w"), indent=2)
snaps = []
for o in (o for o in objects if o["object_type"] == "commit"):
    if os.environ.get("FAKE_EXTRACTOR_ARCHIVE_FAIL"):
        sys.stderr.write("Error: git archive failed for %s: fatal: unable to read tree (0000000000000000000000000000000000000000)\n" % o["hash"]); sys.exit(1)
    raw = open(o["path"], "rb").read().decode("utf-8", "replace")
    m = re.search(r"^" + date + r" .*> (\d+) ([+-])(\d{2})(\d{2})$", raw.partition("\n\n")[0], re.M)
    stamp = None
    if m:
        off = timedelta(hours=int(m[3]), minutes=int(m[4])) * (-1 if m[2] == "-" else 1)
        stamp = datetime.fromtimestamp(int(m[1]), tz=timezone(off)).strftime("%Y%m%d-%H%M")
    name = f"{stamp or '00000000-0000'}_{o['hash']}"
    d = os.path.join(out, "snapshots", name)
    os.makedirs(d, exist_ok=True)
    count = 0
    with tarfile.open(fileobj=io.BytesIO(git("archive", "--format=tar", o["hash"]).stdout)) as t:
        for member in t.getmembers():
            if member.isreg():
                t.extract(member, d); count += 1
    snaps.append({"commit": o["hash"], "directory": name, "date": stamp, "timestamp": int(m[1]) if m else None,
                  "tz_offset": (m[2] + m[3] + m[4]) if m else None, "files": count})
snaps.sort(key=lambda s: s["directory"])
json.dump(snaps, open(os.path.join(out, "metadata", "snapshots.json"), "w"), indent=2)
if report:
    counts = {}
    for o in objects:
        counts[o["object_type"]] = counts.get(o["object_type"], 0) + 1
    json.dump({"repository": repo, "total_objects": len(objects), "counts": counts, "includes_unreachable_objects": True}, open(os.path.join(out, "report.json"), "w"), indent=2)
'''


# Imite `opengrep scan --sarif --config <dir>... .` : SARIF sur stdout, chemins relatifs au dossier courant.
# Règle simulée par dossier de règles : python/javascript -> `eval(`.
OPENGREP = r'''#!/usr/bin/env python3
import json, os, re, sys
args = sys.argv[1:]
if "--version" in args:
    print("1.8.0"); sys.exit(0)
if os.environ.get("FAKE_OPENGREP_FAIL"):
    sys.stderr.write("opengrep: invalid rule\n"); sys.exit(2)
assert args[0] == "scan" and "--sarif" in args and args[-1] == ".", args
dirs = [os.path.basename(args[i + 1].rstrip("/")) for i, a in enumerate(args) if a == "--config"]
excluded = [args[i + 1] for i, a in enumerate(args) if a == "--exclude"]
if os.environ.get("FAKE_LOG"):
    open(os.environ["FAKE_LOG"], "a").write("opengrep:" + ",".join(sorted(dirs)) + "\nopengrep-cwd:" + os.path.basename(os.getcwd()) + "\n")
RULES = {"python": (".py", "python.lang.security.audit.eval-detected"), "javascript": (".js", "javascript.lang.security.audit.eval-detected")}
TAGS = ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "OWASP-A03:2021 - Injection", "security"]
active = [(d, *RULES[d]) for d in dirs if d in RULES]
rules = [{"id": rid, "name": rid.replace(".", "-"), "defaultConfiguration": {"level": "error"},
          "properties": {"tags": TAGS, "precision": "high"}, "helpUri": "https://semgrep.dev/r/" + rid} for _, _, rid in active]
results = []
for dp, dns, fns in os.walk("."):
    dns[:] = [d for d in dns if d != ".git" and d not in excluded]
    for fn in sorted(fns):
        for idx, (_, ext, rid) in enumerate(active):
            if fn.endswith(ext):
                path = os.path.join(dp, fn)
                for i, line in enumerate(open(path, errors="replace").read().splitlines(), 1):
                    if re.search(r"\beval\(", line):
                        results.append({"ruleId": rid, "ruleIndex": idx, "message": {"text": "Detected use of eval()."},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path[2:], "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": i, "endLine": i, "startColumn": 1, "endColumn": len(line) + 1, "snippet": {"text": line}}}}]})
print(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Opengrep OSS", "rules": rules}}, "results": results}]}))
'''

# Imite `dependency-check.sh --scan P --out D --format JSON --project N [--data X] [--nvdApiKey K] [--noupdate]`
DEPCHECK = r'''#!/usr/bin/env python3
import hashlib, json, os, sys, time
args = sys.argv[1:]
if "--version" in args:
    print("Dependency-Check Core version 10.0.3"); sys.exit(0)
val = lambda flag: args[args.index(flag) + 1]
log = lambda t: open(os.environ["FAKE_LOG"], "a").write(t + "\n") if os.environ.get("FAKE_LOG") else None
if "--updateonly" in args:
    log("depcheck-update:key=" + ("yes" if "--nvdApiKey" in args else "no")); sys.exit(0)
log("depcheck-start")
log("depcheck-key:" + ("yes" if "--nvdApiKey" in args else "no"))
log("depcheck-noupdate:" + ("yes" if "--noupdate" in args else "no"))
time.sleep(float(os.environ.get("FAKE_DEPCHECK_DELAY", "0")))
scan, out = val("--scan"), val("--out")
formats = [args[i + 1] for i, a in enumerate(args) if a == "--format"]
BAD = {("django", "2.2.0"): ("CVE-2019-19844", "CRITICAL", 9.8, "CWE-640"),
       ("pyyaml", "5.3"): ("CVE-2020-14343", "CRITICAL", 9.8, "CWE-20"),
       ("lodash", "4.17.4"): ("CVE-2018-16487", "HIGH", 7.5, "CWE-400")}
deps = []
def add(eco, name, version, path):
    purl = f"pkg:{eco}/{name}@{version}"
    d = {"isVirtual": False, "fileName": f"{name}:{version}", "filePath": path, "sha256": hashlib.sha256(purl.encode()).hexdigest(),
         "packages": [{"id": purl, "confidence": "HIGH"}]}
    if (name, version) in BAD:
        cve, sev, score, cwe = BAD[(name, version)]
        d["vulnerabilities"] = [{"source": "NVD", "name": cve, "severity": sev, "cvssv3": {"baseScore": score, "baseSeverity": sev},
                                 "cwes": [cwe], "description": "Fake vulnerability description for " + name,
                                 "references": [{"source": "MISC", "url": "https://nvd.nist.gov/vuln/detail/" + cve, "name": cve}]}]
    deps.append(d)
for dp, dns, fns in os.walk(scan):
    dns[:] = [d for d in dns if d != ".git"]
    for fn in fns:
        full = os.path.join(dp, fn)
        if fn == "requirements.txt":
            for line in open(full).read().split():
                if "==" in line: add("pypi", *line.split("=="), full)
        elif fn == "package.json":
            for n, v in json.load(open(full)).get("dependencies", {}).items(): add("npm", n, v, full)
os.makedirs(out, exist_ok=True)
json.dump({"reportSchema": "1.1", "scanInfo": {"engineVersion": "10.0.3"}, "projectInfo": {"name": val("--project")},
           "dependencies": deps}, open(os.path.join(out, "dependency-check-report.json"), "w"))
if "HTML" in formats:
    open(os.path.join(out, "dependency-check-report.html"), "w").write("<html>fake</html>")
log("depcheck-end")
'''


# Imite le CLI CodeQL : `database create`, `database analyze` (SARIF avec codeFlows), `pack download`.
CODEQL = r'''#!/usr/bin/env python3
import hashlib, json, os, re, sys, time
args = sys.argv[1:]
log = lambda t: open(os.environ["FAKE_LOG"], "a").write(t + "\n") if os.environ.get("FAKE_LOG") else None
flag = lambda name: next((a.split("=", 1)[1] for a in args if a.startswith(name + "=")), None)
if args[:1] == ["--version"]:
    print("CodeQL command-line toolchain release 2.20.1."); print("Copyright (C) 2019-2025 GitHub, Inc."); sys.exit(0)
sub = args[:2]
RULES = {  # langage -> (motif, règle, score security-severity, CWE, extension)
    "python": (r"execute\(.*\+", "py/sql-injection", "8.8", "external/cwe/cwe-089", ".py"),
    "javascript-typescript": (r"innerHTML\s*=", "js/xss", "6.1", "external/cwe/cwe-079", ".js"),
    "java-kotlin": (r"Runtime\.getRuntime\(\)\.exec\(", "java/command-line-injection", "9.8", "external/cwe/cwe-078", ".java"),
    "c-cpp": (r"\bstrcpy\(", "cpp/unbounded-write", "9.3", "external/cwe/cwe-120", ".c"),
}
if sub == ["database", "create"]:
    db, lang, src = args[2], flag("--language"), flag("--source-root")
    build = "none" if "--build-mode=none" in args else ("cmd" if any(a.startswith("--command=") for a in args) else "default")
    log("codeql-start"); log(f"codeql-create:{lang}:{build}")
    if os.environ.get("FAKE_CODEQL_FAIL_CREATE") == lang:
        sys.stderr.write("A fatal error occurred: Could not auto-detect a suitable build method\n"); sys.exit(2)
    time.sleep(float(os.environ.get("FAKE_CODEQL_DELAY", "0")))
    os.makedirs(db, exist_ok=True)
    open(os.path.join(db, "codeql-database.yml"), "w").write(json.dumps({"lang": lang, "src": src}))
    sys.exit(0)
if sub == ["database", "analyze"]:
    db, spec, out = args[2], args[3], flag("--output")
    meta = json.load(open(os.path.join(db, "codeql-database.yml"))); lang, src = meta["lang"], meta["src"]
    log(f"codeql-analyze:{lang}:{spec}")
    assert flag("--format") == "sarif-latest" and "--sarif-add-snippets" in args
    if os.environ.get("FAKE_CODEQL_FAIL_ANALYZE") == lang:
        sys.stderr.write("A fatal error occurred: Could not resolve queries\n"); sys.exit(2)
    rules, results = [], []
    if lang in RULES:
        pat, rid, score, cwe, ext = RULES[lang]
        rules.append({"id": rid, "name": rid, "shortDescription": {"text": rid}, "defaultConfiguration": {"level": "warning"},
                      "properties": {"tags": ["security", cwe], "security-severity": score, "precision": "high"}})
        for dp, dns, fns in os.walk(src):
            dns[:] = [d for d in dns if d != ".git"]
            for fn in sorted(fns):
                if not fn.endswith(ext): continue
                full = os.path.join(dp, fn); rel = os.path.relpath(full, src)
                for i, line in enumerate(open(full, errors="replace").read().splitlines(), 1):
                    if re.search(pat, line):
                        loc = lambda n, msg: {"location": {"physicalLocation": {"artifactLocation": {"uri": rel, "uriBaseId": "%SRCROOT%"},
                                              "region": {"startLine": n}}, "message": {"text": msg}}}
                        results.append({"ruleId": rid, "ruleIndex": 0, "message": {"text": "This query depends on a user-provided value."},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": rel, "uriBaseId": "%SRCROOT%"},
                                           "region": {"startLine": i, "endLine": i, "snippet": {"text": line}}}}],
                            "partialFingerprints": {"primaryLocationLineHash": hashlib.sha256(line.strip().encode()).hexdigest()[:16] + ":1"},
                            "codeFlows": [{"threadFlows": [{"locations": [loc(max(1, i - 1), "user-provided value"), loc(i, "sink reached here")]}]}]})
    json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.20.1", "rules": rules}}, "results": results}]}, open(out, "w"))
    log("codeql-end"); sys.exit(0)
if sub == ["pack", "download"]:
    log("codeql-packs:" + ",".join(args[2:]))
    if os.environ.get("FAKE_CODEQL_FAIL_PACKS"):
        sys.stderr.write("A fatal error occurred: unauthorized\n"); sys.exit(1)
    sys.exit(0)
sys.stderr.write("unknown command: " + " ".join(args) + "\n"); sys.exit(2)
'''


# Imite trufflehog : `filesystem <dir>` ou `git file://<repo>`, NDJSON sur stdout, version sur stderr.
TRUFFLEHOG = r'''#!/usr/bin/env python3
import json, os, re, subprocess, sys
args = sys.argv[1:]
if "--version" in args:
    sys.stderr.write("trufflehog 3.88.0\n"); sys.exit(0)
mode = "dir" if args[0] == "filesystem" else "git"
log = lambda t: open(os.environ["FAKE_LOG"], "a").write(t + "\n") if os.environ.get("FAKE_LOG") else None
log(f"trufflehog:{mode}:verify={'no' if '--no-verification' in args else 'yes'}")
assert "--json" in args and "--no-update" in args, args
DET = [("AWS", re.compile(r"AKIA[0-9A-Z]{16}")), ("Github", re.compile(r"ghp_[A-Za-z0-9]{36}"))]
out = []
def scan(text, meta_for):
    for i, line in enumerate(text.splitlines(), 1):
        for name, rx in DET:
            for m in rx.finditer(line):
                out.append({"SourceMetadata": {"Data": meta_for(i)}, "DetectorName": name, "DecoderName": "PLAIN",
                            "DetectorDescription": name + " credentials", "Verified": False, "Raw": m.group(0),
                            "RawV2": "", "Redacted": m.group(0)[:4] + "***"})
if mode == "dir":
    path = args[1]
    for dp, dns, fns in os.walk(path):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in sorted(fns):
            full = os.path.join(dp, fn)
            try: scan(open(full, errors="strict").read(), lambda i, f=full: {"Filesystem": {"file": f, "line": i}})
            except (UnicodeDecodeError, OSError): pass
else:
    repo = args[1].removeprefix("file://")
    git = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    for row in git("log", "--all", "--format=%H%x09%ae%x09%aI").stdout.splitlines():
        h, email, ts = row.split("\t")
        for f in git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", h).stdout.split():
            body = git("show", f"{h}:{f}")
            if body.returncode == 0:
                scan(body.stdout, lambda i, f=f, h=h, email=email, ts=ts: {"Git": {"commit": h, "file": f, "email": email, "repository": repo, "timestamp": ts, "line": i}})
sys.stderr.write("fake trufflehog log line\n")
for o in out: print(json.dumps(o))
'''

# Imite osv-scanner (v2) : `scan source --format json [--offline] -r <dir>` ; 128 s'il n'y a aucun fichier de dépendances.
OSV = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if "--version" in args:
    print("osv-scanner version: 2.0.0"); sys.exit(0)
log = lambda t: open(os.environ["FAKE_LOG"], "a").write(t + "\n") if os.environ.get("FAKE_LOG") else None
log("osv:offline=" + ("yes" if "--offline" in args else "no"))
assert args[:2] == ["scan", "source"] and "--format" in args, args
root = args[args.index("-r") + 1]
BAD = {("django", "2.2.0", "PyPI"): ("GHSA-h5jv-4p7w-64jg", "CVE-2019-19844", "CRITICAL", "9.8", "CWE-640", "3.0.1"),
       ("lodash", "4.17.4", "npm"): ("GHSA-4xc9-xhrj-v574", "CVE-2018-16487", "HIGH", "7.5", "CWE-400", "4.17.11")}
results = []
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in dns if d != ".git"]
    for fn in fns:
        full = os.path.join(dp, fn); pkgs = []
        if fn == "requirements.txt":
            pkgs = [(n, v, "PyPI") for n, v in (l.split("==") for l in open(full).read().split() if "==" in l)]
        elif fn == "package.json":
            pkgs = [(n, v, "npm") for n, v in json.load(open(full)).get("dependencies", {}).items()]
        if not pkgs: continue
        out = []
        for n, v, eco in pkgs:
            if (n, v, eco) in BAD:
                gid, cve, sev, score, cwe, fixed = BAD[(n, v, eco)]
                out.append({"package": {"name": n, "version": v, "ecosystem": eco},
                            "vulnerabilities": [{"id": gid, "aliases": [cve], "summary": "Fake vulnerability in " + n,
                                "details": "details", "database_specific": {"severity": sev, "cwe_ids": [cwe]},
                                "references": [{"type": "WEB", "url": "https://osv.dev/" + gid}],
                                "affected": [{"package": {"name": n, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}],
                            "groups": [{"ids": [gid], "max_severity": score}]})
        results.append({"source": {"path": full, "type": "lockfile"}, "packages": out})
if not results:
    sys.stderr.write("No package sources found\n"); sys.exit(128)
print(json.dumps({"results": [r for r in results if r["packages"]]}))
sys.exit(1 if any(r["packages"] for r in results) else 0)
'''

# Imite `trivy fs --format json --output F --quiet --scanners ... <dir>` (vulnérabilités + misconfigurations Dockerfile).
TRIVY = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if "--version" in args:
    print("Version: 0.58.0"); sys.exit(0)
log = lambda t: open(os.environ["FAKE_LOG"], "a").write(t + "\n") if os.environ.get("FAKE_LOG") else None
assert args[0] == "fs" and "--format" in args, args
scanners = args[args.index("--scanners") + 1]
out, root = args[args.index("--output") + 1], args[-1]
log("trivy:" + scanners + (":offline" if "--offline-scan" in args else ""))
log("trivy-start")
import time; time.sleep(float(os.environ.get("FAKE_TRIVY_DELAY", "0")))
results = []
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in dns if d != ".git"]
    for fn in fns:
        full = os.path.join(dp, fn); rel = os.path.relpath(full, root)
        if fn == "requirements.txt" and "vuln" in scanners:
            vulns = [{"VulnerabilityID": "CVE-2019-19844", "PkgName": "django", "InstalledVersion": "2.2.0", "FixedVersion": "3.0.1",
                      "Severity": "CRITICAL", "Title": "Django account takeover", "Description": "Password reset flaw.",
                      "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19844", "CweIDs": ["CWE-640"],
                      "CVSS": {"nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 8.1}}, "References": ["https://example.org/ref"],
                      "PkgIdentifier": {"PURL": "pkg:pypi/django@2.2.0"}}] if "django==2.2.0" in open(full).read() else []
            results.append({"Target": rel, "Class": "lang-pkgs", "Type": "pip", "Vulnerabilities": vulns})
        if fn == "Dockerfile" and "misconfig" in scanners and "USER root" in open(full).read():
            line = open(full).read().splitlines().index("USER root") + 1
            results.append({"Target": rel, "Class": "config", "Type": "dockerfile", "Misconfigurations": [
                {"ID": "DS002", "AVDID": "AVD-DS-0002", "Title": "Image user should not be 'root'", "Description": "Running as root is risky.",
                 "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument", "Severity": "HIGH",
                 "Resolution": "Add 'USER <non root user name>' line", "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002", "Status": "FAIL",
                 "CauseMetadata": {"StartLine": line, "EndLine": line, "Code": {"Lines": [{"Number": line, "Content": "USER root"}]}}},
                {"ID": "DS999", "AVDID": "AVD-DS-0999", "Title": "passed check", "Severity": "LOW", "Status": "PASS"}]})
json.dump({"SchemaVersion": 2, "ArtifactName": root, "Results": results}, open(out, "w"))
log("trivy-end")
'''

# Imite checkov : `-d <dir> -o json --output-file-path <dir> --quiet --compact` -> results_json.json (liste, 1 objet par framework).
CHECKOV = r'''#!/usr/bin/env python3
import json, os, re, sys
args = sys.argv[1:]
if "--version" in args:
    print("3.2.400"); sys.exit(0)
log = lambda t: open(os.environ["FAKE_LOG"], "a").write(t + "\n") if os.environ.get("FAKE_LOG") else None
log("checkov")
assert "-o" in args and "json" in args and "--output-file-path" in args, args
root, outdir = args[args.index("-d") + 1], args[args.index("--output-file-path") + 1]
failed = []
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in dns if d != ".git"]
    for fn in fns:
        full = os.path.join(dp, fn)
        if fn.endswith(".tf") and re.search(r'acl\s*=\s*"public-read"', open(full).read()):
            failed.append({"check_id": "CKV_AWS_20", "bc_check_id": "BC_AWS_S3_1", "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                           "check_result": {"result": "FAILED"}, "file_path": "/" + os.path.relpath(full, root), "file_abs_path": full,
                           "file_line_range": [1, 4], "resource": "aws_s3_bucket.data", "severity": None,
                           "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-1-acl-read-permissions-everyone",
                           "code_block": [[1, 'resource "aws_s3_bucket" "data" {\n'], [2, '  acl = "public-read"\n'], [3, "}\n"]]})
os.makedirs(outdir, exist_ok=True)
json.dump([{"check_type": "terraform", "results": {"passed_checks": [], "failed_checks": failed}, "summary": {"failed": len(failed)}}], open(os.path.join(outdir, "results_json.json"), "w"))
sys.exit(1 if failed else 0)
'''


ARGV_LOG = ("import json as _j, os as _o, sys as _s\nif _o.environ.get(\"FAKE_ARGV_DIR\"):\n"
            "    open(_o.path.join(_o.environ[\"FAKE_ARGV_DIR\"], _o.path.basename(_s.argv[0]) + \".argv\"), \"a\").write(_j.dumps(_s.argv[1:]) + \"\\n\")\n")


def install(bin_dir: Path, *, cloc: str | None = "cloc", gitleaks: str | None = "gitleaks",
            extractor: str | None = "git-extractor-rs", legacy_extractor: str | None = None, opengrep: str | None = "opengrep",
            depcheck: str | None = "dependency-check.sh", codeql: str | None = "codeql",
            trufflehog: str | None = "trufflehog", osv: str | None = "osv-scanner", trivy: str | None = "trivy",
            checkov: str | None = "checkov") -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name, body in ((cloc, CLOC), (gitleaks, GITLEAKS), (extractor, GIT_EXTRACTOR_RS), (legacy_extractor, EXTRACTOR), (opengrep, OPENGREP), (depcheck, DEPCHECK), (codeql, CODEQL),
                       (trufflehog, TRUFFLEHOG), (osv, OSV), (trivy, TRIVY), (checkov, CHECKOV)):
        if name:
            p = bin_dir / name
            p.write_text(body.replace("\n", "\n" + ARGV_LOG, 1))  # chaque faux outil journalise ses arguments si FAKE_ARGV_DIR est défini
            p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
