"""Graphe des liens (à la manière de Neo4j) : modèle en JavaScript pur, puis parcours d'un utilisateur sur la page."""
from __future__ import annotations

import json
import math
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from aule.report import render_report
from common import AuditCase

HERE = Path(__file__).parent
TEMPLATE = HERE.parent / "src" / "aule" / "templates" / "report.html"
REL = [
    {"type": "depends_on", "src": "repo-git", "dst": "plain", "via": ["npm:x"]},
    {"type": "shared_secret", "src": "plain", "dst": "repo-git", "count": 2, "secrets": [{"rule": "github-pat", "masked": "gh••••R8"}, {"rule": "aws-access-token", "masked": "AK••••LE"}]},
    {"type": "same_remote", "src": "repo-git", "dst": "api", "remote": "git@github.com:acme/app.git"},
    {"type": "shared_endpoint", "src": "plain", "dst": "api", "count": 2, "hosts": ["db.internal", "cache.internal"]},
    {"type": "extracted_from", "src": "api", "dst": "plain", "archive": "x.zip"},
]
BY = {"plain": {}, "repo-git": {}, "api": {"parent": "plain"}}   # `api` vient d'une archive : projet « dérivé »


def model(body: str):
    """Exécute `body` (corps d'une fonction JS recevant `api`, qui renvoie un objet) contre le modèle du gabarit."""
    prefix = f"const REL = {json.dumps(REL)}, BY = {json.dumps(BY)};"
    proc = subprocess.run(["node", str(HERE / "js_model.js"), str(TEMPLATE), prefix + body], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@unittest.skipUnless(shutil.which("node"), "node requis")
class BuildTest(unittest.TestCase):
    def test_shared_things_become_nodes(self):
        g = model("const G = api.lgBuild(REL, BY); return {nodes: G.nodes.map(n => [n.id, n.kind, n.label, n.deg]), edges: G.edges.map(e => [e.type, e.src, e.dst, e.directed])};")
        nodes = {n[0]: n[1:] for n in g["nodes"]}
        self.assertEqual({k: v[0] for k, v in nodes.items() if k.startswith("p:")}, {"p:plain": "project", "p:repo-git": "project", "p:api": "derived"})
        self.assertEqual(sorted(v[1] for k, v in nodes.items() if k.startswith("s:")), ["AK••••LE", "gh••••R8"])
        self.assertEqual(sorted(k for k in nodes if k.startswith("h:")), ["h:cache.internal", "h:db.internal"])
        self.assertEqual(nodes["r:git@github.com:acme/app.git"][:2], ["remote", "github.com/acme/app"])        # l'étiquette est courte et sans identifiants
        self.assertEqual((len(g["nodes"]), len(g["edges"])), (8, 12))
        self.assertEqual({k: nodes[k][2] for k in ("p:plain", "p:repo-git", "p:api")}, {"p:plain": 6, "p:repo-git": 4, "p:api": 4})
        directed = {(e[0], e[3]) for e in g["edges"]}
        self.assertEqual(directed, {("depends_on", True), ("extracted_from", True), ("shared_secret", False), ("same_remote", False), ("shared_endpoint", False)})

    def test_duplicates_and_degenerate_relations(self):
        g = model("""const again = [...REL, {type: "shared_secret", src: "repo-git", dst: "plain", secrets: [{rule: "github-pat", masked: "gh••••R8"}]},
                     {type: "depends_on", src: null, dst: "plain"}, {type: "depends_on", src: "plain", dst: undefined},
                     {type: "shared_secret", src: "plain", dst: "api", secrets: []}, {type: "shared_endpoint", src: "repo-git", dst: "api"}, {type: "same_remote", src: "plain", dst: "api"}];
                    const G = api.lgBuild(again, BY); return {nodes: G.nodes.length, edges: G.edges.map(e => e.id), deg: Object.fromEntries(G.nodes.map(n => [n.id, n.deg]))};""")
        self.assertEqual(g["nodes"], 8)                                                                         # le même secret vu deux fois : un seul nœud
        self.assertEqual(len(g["edges"]), 12 + 3)                                                               # + 3 liens directs de repli (secrets vides, hôtes absents, dépôt absent)
        self.assertTrue(all("null" not in e and "undefined" not in e for e in g["edges"]))                      # une relation sans extrémité est ignorée
        self.assertEqual({k: g["deg"][k] for k in ("p:plain", "p:repo-git", "p:api")}, {"p:plain": 8, "p:repo-git": 5, "p:api": 7})   # un doublon ne gonfle pas les degrés (donc pas la taille des nœuds)
        self.assertEqual(g["deg"]["s:github-pat|gh••••R8"], 2)

    def test_credentials_never_reach_a_label(self):
        out = model("""return ["https://user:s3cr3t@github.com/acme/app.git", "git@github.com:acme/app.git", "ssh://git@host:2222/x/y.git", "https://gitlab.com/g/p/", "plain/text"].map(api.lgShortRemote);""")
        self.assertEqual(out, ["github.com/acme/app", "github.com/acme/app", "host/2222/x/y", "gitlab.com/g/p", "plain/text"])
        self.assertFalse(any("s3cr3t" in x or "user" in x for x in out))

    def test_radius_and_clip(self):
        out = model("""const G = api.lgBuild(REL, BY); const r = n => api.lgRadius(G.nodes.find(x => x.id === n));
                       return {proj: r("p:plain"), hub: r("h:db.internal"), clip: [api.lgClip("court", 10), api.lgClip("x".repeat(40), 10)]};""")
        self.assertGreater(out["proj"], out["hub"])
        self.assertEqual(out["clip"], ["court", "xxxxxxxxx…"])


@unittest.skipUnless(shutil.which("node"), "node requis")
class NeighborhoodTest(unittest.TestCase):
    def test_depths(self):
        out = model("""const G = api.lgBuild(REL, BY), n = (id, d) => [...api.lgNeighborhood(G, id, d)].sort();
                       return {d0: n("p:plain", 0), d1: n("p:plain", 1), d2: n("s:github-pat|gh••••R8", 2), none: n("p:inconnu", 3)};""")
        self.assertEqual(out["d0"], ["p:plain"])
        self.assertEqual(out["d1"], sorted(["p:plain", "p:repo-git", "p:api", "s:github-pat|gh••••R8", "s:aws-access-token|AK••••LE", "h:db.internal", "h:cache.internal"]))
        self.assertEqual(out["d2"], sorted(["s:github-pat|gh••••R8", "p:plain", "p:repo-git", "p:api", "s:aws-access-token|AK••••LE", "h:db.internal", "h:cache.internal", "r:git@github.com:acme/app.git"]))
        self.assertEqual(out["none"], ["p:inconnu"])                                                            # nœud inconnu : lui seul, sans erreur


@unittest.skipUnless(shutil.which("node"), "node requis")
class PhysicsTest(unittest.TestCase):
    PRE = """const G = {nodes: [{id: "a", kind: "project", deg: 1, label: "a", data: {}}, {id: "b", kind: "project", deg: 1, label: "b", data: {}}], edges: [{src: "a", dst: "b", type: "depends_on"}]};
             const mk = (ax, ay, bx, by) => new Map([["a", {x: ax, y: ay, vx: 0, vy: 0}], ["b", {x: bx, y: by, vx: 0, vy: 0}]]);
             const run = (pos, vis, pinned, alpha, n) => { let m = 0; for (let i = 0; i < n; i++) m = api.lgRelax(G, pos, vis, pinned, alpha); return m; };
             const dist = pos => Math.hypot(pos.get("a").x - pos.get("b").x, pos.get("a").y - pos.get("b").y);"""

    def test_edges_pull_and_overlaps_push(self):
        out = model(self.PRE + """const far = mk(0, 0, 900, 0), near = mk(0, 0, 3, 0), both = new Set(["a", "b"]);
                                  run(far, both, new Set(), 0.5, 200); run(near, both, new Set(), 0.5, 200);
                                  return {far: dist(far), near: dist(near)};""")
        self.assertLess(out["far"], 400)                                                                       # trop loin : le ressort rapproche
        self.assertGreater(out["near"], 60)                                                                    # superposés : la répulsion sépare

    def test_pinned_hidden_and_frozen(self):
        out = model(self.PRE + """const pos = mk(0, 0, 900, 0); run(pos, new Set(["a", "b"]), new Set(["a"]), 0.5, 100);
                                  const hid = mk(0, 0, 900, 0); run(hid, new Set(["a"]), new Set(), 0.5, 50);
                                  const still = mk(0, 0, 900, 0), m = api.lgRelax(G, still, new Set(["a", "b"]), new Set(), 0);
                                  return {a: [pos.get("a").x, pos.get("a").y], bMoved: pos.get("b").x < 900, hidden: [hid.get("b").x, hid.get("b").y], alpha0: [still.get("a").x, still.get("b").x], m};""")
        self.assertEqual(out["a"], [0, 0])                                                                     # épinglé : n'a pas bougé d'un pixel
        self.assertTrue(out["bMoved"])                                                                         # son voisin non épinglé suit
        self.assertEqual(out["hidden"], [900, 0])                                                              # un nœud masqué n'est jamais déplacé
        self.assertEqual((out["alpha0"], out["m"]), ([0, 900], 0))                                             # alpha nul : rien ne bouge

    def test_stable_finite_and_converging(self):
        out = model(self.PRE + """const G2 = api.lgBuild(REL, BY), L = api.lgLayout(G2), vis = new Set(G2.nodes.map(n => n.id)), early = [], late = [];
                                  for (let i = 0; i < 300; i++) { const m = api.lgRelax(G2, L.pos, vis, new Set(), 0.6 * Math.pow(0.97, i)); (i < 20 ? early : late).push(m); }
                                  const all = [...L.pos.values()];
                                  const co = new Map([["a", {x: 5, y: 5, vx: 0, vy: 0}], ["b", {x: 5, y: 5, vx: 0, vy: 0}]]); api.lgRelax(G, co, new Set(["a", "b"]), new Set(), 0.5);
                                  return {finite: all.every(q => Number.isFinite(q.x) && Number.isFinite(q.y)), bounded: all.every(q => Math.abs(q.x) < 1e4 && Math.abs(q.y) < 1e4),
                                          calmer: Math.max(...late) < Math.max(...early), coincident: Number.isFinite(co.get("a").x) && Number.isFinite(co.get("b").y) && (co.get("a").x !== co.get("b").x || co.get("a").y !== co.get("b").y)};""")
        self.assertEqual(out, {"finite": True, "bounded": True, "calmer": True, "coincident": True})


@unittest.skipUnless(shutil.which("node"), "node requis")
class GeometryTest(unittest.TestCase):
    def test_layout_is_deterministic_and_inside_its_bounds(self):
        out = model("""const G = api.lgBuild(REL, BY), a = api.lgLayout(G), b = api.lgLayout(G), key = L => [...L.pos].map(([id, q]) => [id, q.x, q.y]);
                       const e = api.lgLayout({nodes: [], edges: []}), one = api.lgLayout({nodes: [{id: "x", kind: "project", deg: 0, label: "x", data: {}}], edges: []});
                       return {same: JSON.stringify(key(a)) === JSON.stringify(key(b)), inside: [...a.pos.values()].every(q => q.x >= 70 && q.x <= a.W - 70 && q.y >= 25 && q.y <= a.H - 25),
                               empty: e.pos.size, one: one.pos.size, distinct: new Set([...a.pos.values()].map(q => q.x.toFixed(0) + "," + q.y.toFixed(0))).size};""")
        self.assertEqual((out["same"], out["inside"], out["empty"], out["one"]), (True, True, 0, 1))
        self.assertEqual(out["distinct"], 8)                                                                   # aucun nœud n'est posé sur un autre

    def test_edge_paths(self):
        out = model("""const A = {x: 0, y: 0}, B = {x: 100, y: 0}, ex = (a, b, c, d) => api.lgEdgePath(a, 10, b, 10, c, d);
                       const straight = ex(A, B, 0, false), arrow = ex(A, B, 0, true), left = ex(B, A, 0, false), up = ex({x: 0, y: 0}, {x: 0, y: -100}, 0, false), down = ex({x: 0, y: -100}, {x: 0, y: 0}, 0, false);
                       const c1 = ex(A, B, 1, false), c2 = ex(A, B, -1, false), same = ex(A, A, 0, true);
                       return {straight, arrow: arrow.d, left: left.angle, vert: [up.angle, down.angle], curved: [c1.d, c1.ly, c2.ly], sameFinite: Object.values(same).every(v => typeof v === "string" || Number.isFinite(v))};""")
        self.assertEqual(out["straight"]["d"], "M10.0 0.0 L90.0 0.0")                                          # ni dans le cercle de départ, ni dans celui d'arrivée
        self.assertEqual(out["arrow"], "M10.0 0.0 L87.0 0.0")                                                  # la flèche s'arrête avant le bord du nœud
        self.assertEqual((out["left"], out["vert"]), (0, [-90, 90]))                                           # le texte n'est jamais à l'envers
        self.assertTrue(out["curved"][0].startswith("M10.0 0.0 Q"))
        self.assertGreater(out["curved"][1] * out["curved"][2] * -1, 0)                                        # deux arêtes parallèles s'écartent de part et d'autre
        self.assertTrue(out["sameFinite"])                                                                     # deux nœuds superposés ne produisent pas de NaN

    def test_fit(self):
        out = model("""const P = new Map([["a", {x: 0, y: 0}], ["b", {x: 1000, y: 400}]]), v = api.lgFit(P, ["a", "b"], 1000, 620), one = api.lgFit(new Map([["a", {x: 50, y: 50}]]), ["a"], 1000, 620);
                       const huge = api.lgFit(new Map([["a", {x: 0, y: 0}], ["b", {x: 1e6, y: 1e6}]]), ["a", "b"], 1000, 620);
                       const px = id => [P.get(id).x * v.k + v.x, P.get(id).y * v.k + v.y];
                       return {v, a: px("a"), b: px("b"), one, empty: api.lgFit(P, [], 1000, 620), huge: huge.k, missing: api.lgFit(P, ["zz"], 1000, 620)};""")
        for x, y in (out["a"], out["b"]):
            self.assertTrue(50 - 1e-6 <= x <= 950 + 1e-6 and 50 - 1e-6 <= y <= 570 + 1e-6, (x, y))             # tout entre dans la vue, avec une marge
        self.assertAlmostEqual(out["one"]["k"], 1.6)                                                           # un seul nœud : pas de zoom démesuré
        self.assertEqual(out["empty"], {"x": 0, "y": 0, "k": 1})
        self.assertEqual(out["missing"], {"x": 0, "y": 0, "k": 1})
        self.assertEqual(out["huge"], 0.15)                                                                    # plancher de zoom

    def test_search(self):
        out = model("""const G = api.lgBuild(REL, BY), f = q => api.lgSearch(G, q).map(n => n.id).sort();
                       return {name: f("PLAIN"), data: f("github-pat"), host: f("db.int"), empty: f(""), blanks: f("   "), none: f("zzz"), nul: f(null)};""")
        self.assertEqual(out["name"], ["p:plain"])
        self.assertEqual(out["data"], ["s:github-pat|gh••••R8"])                                                # cherche aussi dans les propriétés (la règle)
        self.assertEqual(out["host"], ["h:db.internal"])
        self.assertEqual((out["empty"], out["blanks"], out["none"], out["nul"]), ([], [], [], []))


@unittest.skipUnless(shutil.which("node"), "node requis")
class SvgExportTest(unittest.TestCase):
    def export(self, relations=None) -> ET.Element:
        body = ("const rel = {color: {depends_on: '#3b5bdb', shared_secret: '#c92a2a'}, label: {depends_on: 'dépend de', shared_secret: 'secret partagé'}};"
                f"const G = api.lgBuild({json.dumps(relations)} || REL, BY), L = api.lgLayout(G), vis = new Set(G.nodes.map(n => n.id));"
                "return {svg: api.lgSvgString(G, L.pos, vis, G.edges, 1000, 620, rel)};")
        return ET.fromstring(model(body)["svg"])

    def test_well_formed_and_complete(self):
        root = self.export()
        ns = "{http://www.w3.org/2000/svg}"
        self.assertEqual((root.tag, root.get("viewBox")), (ns + "svg", "0 0 1000 620"))
        self.assertEqual((len(root.findall(f".//{ns}circle")), len(root.findall(f".//{ns}path")) - 1), (8, 12))        # -1 : la pointe de flèche du <defs>
        self.assertEqual(len(root.findall(f".//{ns}text")), 8 + 12)                                              # une étiquette par nœud et par relation
        self.assertEqual(sum(1 for p in root.iter(f"{ns}path") if p.get("marker-end")), 2)                       # flèches : depends_on et extracted_from seulement

    def test_labels_are_escaped(self):
        root = self.export([{"type": "depends_on", "src": "a<b>&\"c", "dst": "plain", "via": []}])                # un nom hostile ne casse pas le SVG
        texts = [t.text for t in root.iter("{http://www.w3.org/2000/svg}text")]
        self.assertIn('a<b>&"c', texts)
        self.assertNotIn("<script", ET.tostring(root, encoding="unicode").lower())


@unittest.skipUnless(shutil.which("node"), "node requis")
class UserJourneyTest(AuditCase):
    def setUp(self):
        super().setUp()
        (self.root / "api").mkdir()
        (self.root / "api" / "app.py").write_text("x = 1\n")
        (self.root / "solo").mkdir()
        (self.root / "solo" / "a.py").write_text("y = 1\n")
        self.run_id = self.run_audit(tool_names=["cloc"])
        self.ids = {p["name"]: p["id"] for p in self.db.list_projects(self.run_id)}
        self.db.conn.execute("UPDATE project SET parent=?, origin=? WHERE id=?", ("plain", "x.zip", self.ids["api"]))   # `api` vient d'une archive : projet « dérivé »
        self.db.conn.commit()

    def relate(self, relations):
        self.db.delete_relations(self.run_id, ["depends_on", "shared_secret", "same_remote", "shared_endpoint", "extracted_from"])
        for r in relations:
            data = {k: v for k, v in r.items() if k not in ("type", "src", "dst")}
            self.db.set_relation(self.run_id, "project", self.ids[r["src"]], "project", self.ids[r["dst"]], r["type"], data)

    def play(self, mode="main"):
        page = self.tmp / f"links-{mode}.html"
        page.write_text(render_report(self.db, self.run_id, self.data, reveal=True), encoding="utf-8")
        proc = subprocess.run(["node", str(HERE / "links_scenario.js"), str(page), mode], capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_an_investigation_session(self):
        self.relate(REL)
        out = self.play()
        ini = out["initial"]
        self.assertEqual((ini["nodes"], ini["edges"], ini["circles"]), (8, 12, 8))                                # un cercle par nœud
        for label in ("dépend de", "secret partagé", "même dépôt d'origine", "hôte commun", "extrait de"):
            self.assertIn(label, ini["labels"])                                                                   # chaque relation est nommée sur l'arête
        for expected in ("Projet (2)", "Projet issu d'une archive (1)", "Secret partagé (2)", "Hôte commun (2)", "Dépôt d'origine (1)", "8 nœud(s), 12 relation(s) affiché(s)", "Cliquez un nœud"):
            self.assertIn(expected, ini["text"])
        # sélectionner un projet : l'inspecteur le décrit, le reste du graphe recule
        proj = out["project"]
        for expected in ("Inspecteur", "Projet", "plain", "Relations (6)", "Chemin", "secret(s)", "Filtrer sur ce projet", "Ses secrets"):
            self.assertIn(expected, proj["text"])
        self.assertEqual((proj["selected"], proj["dimNodes"], proj["dimEdges"]), (1, 1, 6))                       # seul le dépôt d'origine (hors voisinage) recule
        # un secret partagé est un nœud : on voit QUI le partage
        for expected in ("Secret partagé", "github-pat", "gh••••R8", "plain", "repo-git"):
            self.assertIn(expected, out["secret"]["text"])
        self.assertEqual(out["afterSearch"]["q"], "gh••••R8")                                                     # « Chercher dans les secrets » alimente la recherche globale
        self.assertEqual(out["selectionKept"], 1)                                                                 # la sélection survit à un changement d'onglet
        # légende : masquer un type de nœud ou de relation
        self.assertEqual((out["noSecrets"]["nodes"], out["noSecrets"]["edges"]), (6, 8))
        self.assertEqual((out["noDepends"]["edges"], out["noDepends"]["nodes"]), (11, 8))
        # isoler le voisinage d'un nœud
        self.assertEqual((out["focusLabel0"], out["focus1"]["label"], out["focus1"]["nodes"]), ("Isoler : non", "Isoler : voisins", 7))
        self.assertEqual((out["focus2"]["label"], out["focus2"]["nodes"]), ("Isoler : voisins de voisins", 8))
        # recherche d'un nœud
        self.assertIn("1 résultat(s)", out["search"]["text"])
        self.assertEqual(len(out["search"]["selected"]), 1)
        self.assertIn("api", out["search"]["selected"][0])
        # glisser : le nœud suit, reste épinglé, entraîne ses voisins ; le clic qui suit est ignoré ; double-clic libère
        d = out["drag"]
        self.assertGreater(d["moved"], 20)
        self.assertGreater(d["neighborMoved"], 0)
        self.assertEqual(d["pinned"], "4 2")
        self.assertEqual(out["dragClick"]["selected"], 0)
        self.assertEqual(d["button"], "Libérer les nœuds (1)")                                                    # compteur mis à jour tout de suite, sans re-dessiner
        self.assertEqual((out["dblclick"]["pinned"], out["dblclick"]["button"]), (None, "Libérer les nœuds (0)"))
        self.assertEqual((out["zoom"]["in"], out["zoom"]["out"], out["pan"]["changed"]), (True, True, True))
        self.assertTrue(0.15 <= out["fit"]["k"] <= 1.6)
        # une relation se sélectionne aussi
        self.assertIn("Relation", out["edge"]["text"])
        self.assertEqual(out["adjust"]["selectedEdge"], 1)

    def test_a_project_without_links_shows_nothing_not_everything(self):
        self.relate(REL)
        out = self.play("solo")
        self.assertEqual((out["nodes"], out["edges"]), (0, 0))
        self.assertIn("Aucun nœud pour ces filtres", out["text"])

    def test_the_graph_is_capped_for_readability(self):
        self.relate([{"type": "shared_endpoint", "src": "plain", "dst": "api", "count": 450, "hosts": [f"h{i}.internal" for i in range(450)]}])
        out = self.play("cap")
        self.assertEqual(out["nodes"], 400)
        self.assertIn("plafonné aux 400 plus connectés", out["text"])
        self.assertLessEqual(out["edges"], 800)

    def test_no_relations_keeps_the_explanatory_message(self):
        self.relate([])
        out = self.play("cap")
        self.assertEqual(out["nodes"], 0)
        self.assertIn("Aucun lien détecté", out["text"])


class LinksCommandTest(UserJourneyTest):
    """`aule links` : texte historique inchangé hors terminal, arborescence colorée en mode forge."""

    def cli(self, *argv, color="always", columns="100"):
        import contextlib, io, os
        from unittest import mock
        from aule.cli import main
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": columns}), contextlib.redirect_stdout(out):
            code = main(["links", "--no-recompute", *argv, "--data", str(self.data), "--color", color])
        return code, out.getvalue()

    def test_plain_output_is_the_historical_one(self):
        self.relate(REL)
        code, out = self.cli(color="never")
        self.assertEqual(code, 0)
        self.assertIn("[depends_on] repo-git → plain  dépend de (npm:x)", out)
        self.assertTrue(out.rstrip().endswith("5 lien(s) dans " + self.run_id))
        self.assertNotIn("\x1b", out)

    def test_forge_output_is_a_tree_per_project(self):
        from aule.ui import cell_width, strip_ansi
        self.relate(REL)
        _, out = self.cli()
        text = strip_ansi(out)
        for expected in ("🔗 Liens", "5 relations dans " + self.run_id, "⛰️ repo-git", "⛰️ plain", "⛰️ api", "├─", "└─", "dépend de", "→ plain", "↔ api", "via npm:x",
                         "2 secret(s) : github-pat", "github.com", "archive x.zip", "aule serve --open"):
            self.assertIn(expected, text, expected)
        self.assertIn("2 secret(s) : github-pat gh••••R8, aws-access-token AK••••LE", strip_ansi(self.cli(columns="140")[1]))   # large : le détail entier
        tight = strip_ansi(self.cli(columns="70")[1])
        self.assertIn("2 secret(s)", tight)
        self.assertIn("…", tight)                                                                              # étroit : tronqué avec « … », pas supprimé
        self.assertIn("\x1b[", out)
        for width in ("60", "80"):
            narrow = strip_ansi(self.cli(columns=width)[1])
            self.assertTrue(all(cell_width(l) <= int(width) for l in narrow.splitlines()), width)            # jamais plus large que le terminal
        ascii_text = strip_ansi(self.cli("--ascii")[1])
        self.assertIn("|- ", ascii_text)
        self.assertFalse([c for c in ascii_text if ord(c) >= 0x2500 and c not in "→↔"])                      # ASCII : ni emoji ni bordures (les flèches du texte restent)

    def test_filters_still_apply(self):
        self.relate(REL)
        text = __import__("aule.ui", fromlist=["strip_ansi"]).strip_ansi(self.cli("--type", "shared_secret")[1])
        self.assertIn("1 relation dans", text)
        self.assertNotIn("dépend de", text)


if __name__ == "__main__":
    unittest.main()
