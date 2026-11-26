#!/usr/bin/env python3
"""Détecte le code mort (sans dépendance) : imports inutilisés, et définitions jamais référencées ailleurs que dans leur propre définition.
Usage : python3 dev/deadcode.py   (depuis la racine). « seulement testé » = référencé uniquement par les tests (mort en production)."""
import ast, re, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = sorted((ROOT / "src").rglob("*.py"))
ALL = [*SRC, *sorted((ROOT / "tests").glob("*.py")), *sorted((ROOT / "tests").glob("*.js")), *sorted((ROOT / "src").rglob("*.html")), ROOT / "README.md"]
words_src, words_tests = Counter(), Counter()
for f in ALL:
    c = words_tests if "tests" in f.parts or f.suffix == ".md" else words_src
    c.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", f.read_text(errors="replace")))
SKIP = {"main", "name", "binary", "modes", "register", "parse", "build_command", "phase"}

def unused_imports(path: Path, tree: ast.AST):
    names = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                names[(a.asname or a.name).split(".")[0]] = n.lineno
        elif isinstance(n, ast.ImportFrom) and n.module != "__future__":
            for a in n.names:
                names[a.asname or a.name] = n.lineno
    text = path.read_text()
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    used |= set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', text)) if path.name == "__init__.py" else set()
    return [(l, k) for k, l in names.items() if k not in used and not (path.name == "__init__.py")]

def refs(files):
    """Noms réellement UTILISÉS (AST) : variables, attributs, arguments nommés, et chaînes (getattr, clés de dictionnaire, JS)."""
    used = Counter()
    for f in files:
        text = f.read_text(errors="replace")
        if f.suffix != ".py":
            used.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text))
            continue
        for n in ast.walk(ast.parse(text)):
            if isinstance(n, ast.Name):
                used[n.id] += 1
            elif isinstance(n, ast.Attribute):
                used[n.attr] += 1
            elif isinstance(n, ast.alias):
                used[n.name] += 1  # un import (même renommé) est une utilisation
            elif isinstance(n, ast.keyword) and n.arg:
                used[n.arg] += 1
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n.value):
                used[n.value] += 1
    return used

prod = refs([*SRC, *sorted((ROOT / "src").rglob("*.html"))])
tests = refs([*sorted((ROOT / "tests").glob("*.py")), *sorted((ROOT / "tests").glob("*.js"))])
OVERRIDES = {"redirect_request", "log_message", "do_GET", "do_POST", "do_PUT", "do_DELETE", "__enter__", "__exit__"}
dead, tested_only, imports = [], [], []
for f in SRC:
    tree = ast.parse(f.read_text())
    imports += [(f, l, k) for l, k in unused_imports(f, tree)]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            n, registered = node.name, any(getattr(d, "id", getattr(d, "attr", "")) in ("register", "_code") for d in node.decorator_list)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.col_offset == 0:
            n, registered = node.targets[0].id, False
        else:
            continue
        if n.startswith("__") or n in SKIP or n in OVERRIDES or registered:
            continue
        if prod[n] == 0:
            (tested_only if tests[n] > 0 else dead).append((f.relative_to(ROOT), node.lineno, n))
print(f"imports inutilisés : {len(imports)}")
for f, l, k in imports: print(f"  {f.relative_to(ROOT)}:{l}  {k}")
print(f"définitions jamais utilisées : {len(dead)}")
for f, l, n in dead: print(f"  {f}:{l}  {n}")
print(f"utilisées SEULEMENT par les tests : {len(tested_only)}")
for f, l, n in tested_only: print(f"  {f}:{l}  {n}")
sys.exit(1 if imports or dead else 0)
