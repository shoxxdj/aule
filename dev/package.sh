#!/bin/bash
# Contrôles de livraison + archive, en une commande à sortie minimale. Usage : dev/package.sh [nom-archive]  (défaut : aule-etape)
# Vérifie : code mort, imports, wheel, compatibilité Python 3.11 (f-strings), puis nettoie et crée /mnt/user-data/outputs/<nom>.tar.gz
cd "$(dirname "$0")/.." || exit 2
name="${1:-aule-etape}"
python3 dev/deadcode.py | head -1 | sed 's/^/code mort   : /'
python3 - <<'PY'
import ast, pathlib
bad = []
for f in [*pathlib.Path("src").rglob("*.py"), *pathlib.Path("tests").rglob("*.py")]:
    src = f.read_text()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.JoinedStr):
            seg = ast.get_source_segment(src, node) or ""
            if seg.startswith(('f"""', "f'''")): continue
            q = next((c for c in seg if c in "\"'"), None)
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    e = ast.get_source_segment(src, v.value) or ""
                    if "\\" in e or (q and q in e): bad.append(f"{f.name}:{node.lineno}")
print("python 3.11  :", "ok" if not bad else "f-strings incompatibles " + ", ".join(bad))
PY
find . -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null; rm -rf .venv dist src/*.egg-info uv.lock
printf "wheel        : "; uv build --offline --wheel 2>&1 | tail -1 | cut -c1-70; rm -rf dist
rm -rf /mnt/user-data/outputs/aule /mnt/user-data/outputs/*.tar.gz
cp -r "$PWD" /mnt/user-data/outputs/aule && (cd /mnt/user-data/outputs && tar czf "$name.tar.gz" aule && ls -la "$name.tar.gz" | awk '{print "archive      : " $9 " (" int($5/1024) " Ko)"}')
