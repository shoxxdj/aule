"""Interface interactive de bout en bout : le script de la page est exécuté (faux DOM) contre un VRAI serveur."""
from __future__ import annotations

import json
import shutil
import subprocess
import threading
import unittest
import urllib.request
from pathlib import Path

import fakes
from aule.config import Config
from aule.server import make_server
from common import AuditCase

HERE = Path(__file__).parent


@unittest.skipUnless(shutil.which("node"), "node requis")
class LiveUiTest(AuditCase):
    REVEAL = True

    def setUp(self):
        super().setUp()
        # `app` dépend du paquet publié par `lib` : un lien présent dans les deux runs (graphe)
        (self.root / "lib").mkdir()
        (self.root / "lib" / "package.json").write_text(json.dumps({"name": "@corp/lib"}))
        (self.root / "app").mkdir()
        (self.root / "app" / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"@corp/lib": "^1"}}))
        self.run1 = self.run_audit(tool_names=["cloc", "gitleaks", "links"])
        (self.root / "plain" / "keys.py").write_text("KEY = None\n")      # un secret corrigé entre les deux runs
        self.run2 = self.run_audit(tool_names=["cloc", "gitleaks", "links"])
        self.server = make_server(self.data / "audit.db", self.data, Config(), port=0, reveal=self.REVEAL)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), self.server.server_close(), thread.join(5)))

    def page(self) -> Path:
        html = urllib.request.urlopen(self.base + "/").read()
        path = self.tmp / "live.html"
        path.write_bytes(html)
        return path

    def play(self, *extra) -> dict:
        proc = subprocess.run(["node", str(HERE / "live_scenario.js"), str(self.page()), self.base, *extra],
                              capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)


class FullScenarioTest(LiveUiTest):
    def test_auditor_session(self):
        steps = self.play()
        self.assertIn("EN CLAIR", steps["liveBanner"])
        # triage individuel : brouillon conservé pendant un re-rendu, puis écrit en base avec son commentaire
        self.assertEqual(steps["draftKept"], "clé de démonstration")
        triaged = {fp: t for fp, t in self.db.list_triage().items() if t["comment"] == "clé de démonstration"}
        fp = next(iter(triaged))
        group = self.db.cluster_map(self.run2)[fp]["members"]
        self.assertGreater(len(group), 1)                                                # la ligne triée regroupe plusieurs détections identiques...
        self.assertEqual(set(triaged), set(group))                                       # ... et le triage s'applique au groupe entier, ni plus ni moins
        # ... puis le triage en masse a écrasé le statut de tous les résultats affichés (visible dans la page)
        self.assertIn("résultat(s) affichés", steps["bulkLabel"])
        statuses = {t["status"] for t in self.db.list_triage().values()}
        self.assertEqual(statuses, {"to_review"})
        self.assertEqual(self.db.list_triage()[fp]["comment"], "clé de démonstration")     # commentaire conservé
        n_secrets = len({e["fingerprint"] for e in self.db.entities(self.run2, "secret")})
        self.assertEqual(len(self.db.list_triage()), n_secrets)

        # constat créé depuis un résultat, avec la référence à l'empreinte ; puis modifié ; puis supprimé
        self.assertIn("Nouveau constat", steps["formTab"])
        self.assertIn("Secret AWS retrouvé en clair dans le dépôt", steps["findingsTable"])
        self.assertIn("un constat a besoin d'un projet et d'un titre", steps["flash"])         # erreur du serveur affichée
        self.assertIn("Titre modifié par l'auditeur", steps["afterEdit"])
        self.assertNotIn("Titre modifié par l'auditeur", steps["afterDelete"])
        self.assertEqual(self.db.list_findings(), [])
        # le constat créé depuis un résultat portait l'empreinte de CE résultat, son projet et une sévérité cohérente
        (created,) = steps["findingsApi"]
        secrets = {e["fingerprint"]: e for e in self.db.entities(self.run2, "secret")}
        self.assertEqual(len(created["refs"]), 1)
        self.assertIn(created["refs"][0], secrets)
        project = {p["id"]: p["name"] for p in self.db.list_projects(self.run2)}[secrets[created["refs"][0]]["project_id"]]
        self.assertEqual((created["project"], created["severity"], created["status"]), (project, "high", "draft"))
        self.assertIn("Constaté à la lecture du code.\nImpact", created["description"])
        # note de projet : enregistrée en base ET relue dans le champ après rechargement
        first = sorted(p["name"] for p in self.db.list_projects(self.run2))[0]
        note = "Application exposée sur Internet ; à confirmer avec le client."
        self.assertEqual(self.db.list_notes()[first]["text"], note)
        self.assertEqual(steps["noteValue"], note)

        # graphe : `app` -> `lib` (dépendance), dessiné avec ses deux nœuds et son arête fléchée
        self.assertEqual((steps["graph"]["circles"], steps["graph"]["lines"]), (2, 1))
        self.assertIn("dépend de", steps["graph"]["text"])
        self.assertIn("npm:@corp/lib", steps["graph"]["text"])
        # comparaison : le secret de `plain`, corrigé entre les deux runs
        self.assertIn("corrigés (1)", steps["diff"])
        self.assertIn("nouveaux (0)", steps["diff"])

        # lancement d'un audit depuis la page : nouveau run créé, la page bascule dessus
        self.assertEqual(len(self.db.list_audits()), 3)
        self.assertNotEqual(steps["titleBefore"], steps["titleAfter"])
        newest = self.db.latest_audit_id()
        self.assertEqual(steps["titleAfter"], f"Audit {newest}")
        self.assertIn(newest, steps["runSelect"])
        self.assertIn("terminé", steps["jobDone"])
        self.assertIn("(1/", steps["jobDone"])                                                  # journal et progression suivis


class GraphAndDiffTest(LiveUiTest):
    def test_graph_and_diff_render_with_real_data(self):
        # run 1 : secret AWS partagé plain <-> repo-git ; run 2 : corrigé dans plain
        from aule.diff import diff_runs
        d = diff_runs(self.db, self.run1, self.run2, ("secret",))
        self.assertEqual([r["project"] for r in d["kinds"]["secret"]["fixed"]], ["plain"])
        proc = subprocess.run(["node", str(HERE / "dom_smoke.js"), str(self.page()), self.base], capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        links = next(v for k, v in out["tabs"].items() if k.startswith("Liens"))
        self.assertIn("dépend de", links)
        self.assertNotIn("Aucun lien détecté", links)
        self.assertIn("Constats", " ".join(out["tabs"]))
        self.assertIn("Comparaison", " ".join(out["tabs"]))


class MaskedLiveUiTest(LiveUiTest):
    REVEAL = False

    def test_secrets_stay_hidden_until_revealed_one_by_one(self):
        page_bytes = self.page().read_bytes()
        for secret in (fakes.SECRET_A, fakes.SECRET_B):
            self.assertNotIn(secret.encode(), page_bytes)
        steps = self.play("mask")
        self.assertIn("Secrets masqués", steps["liveBanner"])
        before = steps["maskedBefore"]
        self.assertTrue(fakes.SECRET_A not in before and fakes.SECRET_B not in before)
        self.assertTrue(fakes.SECRET_A in steps["maskedAfter"] or fakes.SECRET_B in steps["maskedAfter"])   # révélé À LA DEMANDE


class StaticReportHasNoLiveControlsTest(LiveUiTest):
    def test_static_report_is_read_only(self):
        from aule.report import render_report
        static = self.tmp / "static.html"
        static.write_text(render_report(self.db, self.run2, self.data, reveal=True), encoding="utf-8")
        proc = subprocess.run(["node", str(HERE / "dom_smoke.js"), str(static)], capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        opened = " ".join(out["tabsOpen"].values())
        for live_only in ("Créer un constat", "Marquer les", "révéler", "Enregistrer la note", "+ Nouveau constat"):
            self.assertNotIn(live_only, opened)
        self.assertFalse(any(k.startswith("Audit") for k in out["tabs"]))     # pas d'onglet de lancement


if __name__ == "__main__":
    unittest.main()
