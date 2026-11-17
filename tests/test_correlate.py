"""Recoupement : ce qui doit être regroupé (même secret dir+git, CodeQL+opengrep, alias CVE/GHSA) et surtout ce qui ne doit PAS l'être."""
from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest import mock

import aule.correlate as corr
from aule.cli import main
from aule.correlate import compute_clusters, correlate_run
from aule.orchestrator import reparse, run_audit
from aule.report import build_report_data
from common import AuditCase
from test_export import Inject


class CorrCase(Inject, AuditCase):
    def setUp(self):
        super().setUp()
        self.run_id = self.run_audit(tool_names=["cloc"])

    def secret(self, fp, *, sha="s1", file="a.py", line=3, tool="gitleaks", mode="dir", project="plain", raw_index=0, **kw):
        self.inject("secret", project, fp, tool=tool, mode=mode, file=file, start_line=line, secret_sha256=sha, secret_masked="gh••••R8",
                    rule_id="r", raw_index=raw_index, **kw)

    def sast(self, fp, *, tool="codeql", rule="py/sqli", file="db.py", start=5, end=None, cwe=("CWE-89",), flow=(), project="plain", severity="high"):
        self.inject("sast_finding", project, fp, tool=tool, rule_id=rule, severity=severity, file=file, start_line=start, end_line=end if end is not None else start,
                    cwe=list(cwe), message="m", snippet="code", flow=[{"file": f, "line": n, "message": ""} for f, n in flow])

    def vuln(self, fp, *, vid="CVE-2024-1", name="django", version="2.2.0", aliases=(), tool="osv-scanner", purl=None, project="plain", severity="high"):
        self.inject("vulnerability", project, fp, tool=tool, id=vid, aliases=list(aliases), severity=severity, description="d",
                    dependency={"name": name, "version": version, "purl": purl, "file": "requirements.txt"})

    def groups(self, kind=None):
        return sorted(sorted(c["members"]) for c in compute_clusters(self.db, self.data, self.run_id) if len(c["members"]) > 1 and (kind is None or c["kind"] == kind))

    def reasons(self, kind):
        return {r for c in compute_clusters(self.db, self.data, self.run_id) if c["kind"] == kind and len(c["members"]) > 1 for r in c["reasons"]}


class SecretsTest(CorrCase):
    def test_same_secret_in_the_same_file_is_one_finding_whatever_the_mode_or_tool(self):
        self.secret("a" * 24, mode="dir")
        self.secret("b" * 24, mode="git", commit="c1")                              # le cas d'usage : gitleaks dir + git
        self.secret("c" * 24, mode="history", tool="gittools")
        self.secret("d" * 24, tool="trufflehog", mode="dir")
        self.assertEqual(self.groups("secret"), [["a" * 24, "b" * 24, "c" * 24, "d" * 24]])
        self.assertEqual(self.reasons("secret"), {"same_secret"})

    def test_what_must_stay_separate(self):
        self.secret("a" * 24, file="a.py")
        self.secret("b" * 24, file="b.py")                                          # même credential, autre fichier : autre endroit à corriger
        self.secret("c" * 24, file="a.py", sha="other")                             # autre valeur, même fichier
        self.secret("d" * 24, file="a.py", project="repo-git")                      # autre projet
        self.secret("e" * 24, file="a.py", sha=None)                                # pas d'empreinte : jamais fusionné
        self.secret("f" * 24, file="a.py", sha=None)
        self.assertEqual(self.groups("secret"), [])

    def test_nested_values_on_the_same_line(self):
        self.secret("a" * 24, sha="s-long", file="c.py", line=7, tool="gitleaks")       # capture `password="hunter2secret"`
        self.secret("b" * 24, sha="s-short", file="c.py", line=7, tool="trufflehog")    # capture `hunter2secret`
        self.secret("c" * 24, sha="s-other", file="c.py", line=9, tool="trufflehog")    # autre ligne
        self.secret("d" * 24, sha="s-tiny", file="c.py", line=7, tool="gitleaks", raw_index=3)
        clear = {("plain", "gitleaks", "dir"): {0: ('password="hunter2secret"', "l"), 3: ("er2", "l")}, ("plain", "trufflehog", "dir"): {0: ("hunter2secret", "l")}}
        with mock.patch("aule.report.load_clear_secrets", return_value=(clear, [])):
            clusters = compute_clusters(self.db, self.data, self.run_id)
        merged = sorted(sorted(c["members"]) for c in clusters if len(c["members"]) > 1)
        self.assertEqual(merged, [["a" * 24, "b" * 24]])                                 # « er2 » (< 8 caractères) ne fusionne jamais
        self.assertEqual(next(c for c in clusters if len(c["members"]) == 2)["reasons"], ["nested_values"])

    def test_headline_scenario_on_a_real_run(self):
        run = self.run_audit(tool_names=["cloc", "gitleaks"])
        clusters = [c for c in compute_clusters(self.db, self.data, run) if c["kind"] == "secret"]
        self.assertEqual((sum(len(c["members"]) for c in clusters), len(clusters)), (4, 3))      # 4 détections gitleaks -> 3 constats
        pair = next(c for c in clusters if len(c["members"]) == 2)
        files = {e["data"]["file"] for e in self.db.entities(run, "secret") if e["fingerprint"] in pair["members"]}
        modes = {e["data"]["mode"] for e in self.db.entities(run, "secret") if e["fingerprint"] in pair["members"]}
        self.assertEqual((files, modes), ({"settings.py"}, {"dir", "git"}))


class SastTest(CorrCase):
    def test_codeql_and_opengrep_on_the_same_vulnerability(self):
        self.sast("a" * 24, tool="codeql", start=5)
        self.sast("b" * 24, tool="opengrep", rule="python.sqli", start=4, end=6, cwe=("CWE-89", "CWE-564"))       # lignes qui se recouvrent
        self.assertEqual(self.groups("sast_finding"), [["a" * 24, "b" * 24]])
        self.assertEqual(self.reasons("sast_finding"), {"same_cwe_location"})

    def test_what_must_stay_separate(self):
        self.sast("a" * 24, start=5)
        self.sast("b" * 24, tool="opengrep", rule="o", start=6, cwe=("CWE-89",))                  # ligne voisine : deux injections distinctes
        self.sast("c" * 24, tool="opengrep", rule="x", start=5, cwe=("CWE-79",))                   # même ligne, autre CWE
        self.sast("d" * 24, tool="opengrep", rule="y", start=5, cwe=())                            # pas de CWE
        self.sast("e" * 24, tool="opengrep", rule="z", start=5, cwe=("CWE-89",), file="other.py")  # autre fichier
        self.sast("f" * 24, tool="opengrep", rule="w", start=5, cwe=("CWE-89",), project="repo-git")
        self.assertEqual(self.groups("sast_finding"), [])

    def test_a_data_flow_endpoint_links_the_two_tools(self):
        self.sast("a" * 24, tool="codeql", file="db.py", start=10, flow=[("web.py", 3), ("util.py", 20), ("db.py", 10)])
        self.sast("b" * 24, tool="opengrep", rule="src", file="web.py", start=3, cwe=("CWE-89",))      # le SOURCE du chemin
        self.sast("c" * 24, tool="opengrep", rule="mid", file="util.py", start=20, cwe=("CWE-89",))    # étape INTERMÉDIAIRE : pas une extrémité
        self.sast("d" * 24, tool="opengrep", rule="oth", file="web.py", start=3, cwe=("CWE-79",))      # même ligne mais autre CWE
        self.assertEqual(self.groups("sast_finding"), [["a" * 24, "b" * 24]])
        self.assertEqual(self.reasons("sast_finding"), {"flow_endpoint"})

    def test_same_rule_at_the_same_place_is_one_finding_even_without_cwe(self):
        self.sast("a" * 24, tool="opengrep", rule="r", cwe=())
        self.sast("b" * 24, tool="opengrep", rule="r", cwe=())
        self.sast("c" * 24, tool="opengrep", rule="r2", cwe=())
        self.sast("d" * 24, tool="trivy", rule="r", cwe=())                                        # autre outil : pas la même règle
        self.assertEqual(self.groups("sast_finding"), [["a" * 24, "b" * 24]])
        self.assertEqual(self.reasons("sast_finding"), {"same_rule_location"})

    def test_transitivity_and_the_bucket_cap(self):
        self.sast("a" * 24, tool="t1", rule="r1", start=1, end=3, cwe=("CWE-1",))
        self.sast("b" * 24, tool="t2", rule="r2", start=3, end=6, cwe=("CWE-1", "CWE-2"))
        self.sast("c" * 24, tool="t3", rule="r3", start=6, end=9, cwe=("CWE-2",))
        self.assertEqual(self.groups("sast_finding"), [["a" * 24, "b" * 24, "c" * 24]])           # A~B, B~C -> un seul groupe
        with mock.patch.object(corr, "MAX_BUCKET", 2):
            self.assertEqual(self.groups("sast_finding"), [])                                      # fichier énorme : seulement les doublons exacts

    def test_findings_without_a_location_are_never_grouped(self):
        for fp in ("a" * 24, "b" * 24):
            self.inject("sast_finding", "plain", fp, tool="x", rule_id="r", severity="high", file=None, start_line=None, cwe=["CWE-1"], message="m", snippet=None, flow=[])
        self.assertEqual(self.groups("sast_finding"), [])


class VulnerabilitiesTest(CorrCase):
    def test_same_component_and_vulnerability_across_tools_and_aliases(self):
        self.vuln("a" * 24, vid="CVE-2024-1", tool="osv-scanner")
        self.vuln("b" * 24, vid="CVE-2024-1", tool="trivy")
        self.vuln("c" * 24, vid="GHSA-xxxx-yyyy", aliases=["cve-2024-1"], tool="dependency-check")      # alias, casse différente
        self.assertEqual(self.groups("vulnerability"), [["a" * 24, "b" * 24, "c" * 24]])
        self.assertEqual(self.reasons("vulnerability"), {"same_component_vuln", "alias"})

    def test_what_must_stay_separate(self):
        self.vuln("a" * 24)
        self.vuln("b" * 24, version="3.0.0")                                        # autre version : autre dépendance à mettre à jour
        self.vuln("c" * 24, name="flask")                                           # autre composant, même CVE
        self.vuln("d" * 24, vid="CVE-2099-9")                                       # autre vulnérabilité
        self.vuln("e" * 24, project="repo-git")
        self.assertEqual(self.groups("vulnerability"), [])

    def test_unknown_version_matches_and_names_are_normalized_per_ecosystem(self):
        self.vuln("a" * 24, version=None)
        self.vuln("b" * 24, version="2.2.0", tool="trivy")                          # version inconnue d'un côté : compatible
        self.vuln("c" * 24, name="ruamel.yaml", vid="CVE-3", purl="pkg:pypi/ruamel.yaml@0.1")
        self.vuln("d" * 24, name="ruamel-yaml", vid="CVE-3", purl="pkg:pypi/ruamel-yaml@0.1", tool="trivy")          # PyPI : « . » = « - »
        self.vuln("e" * 24, name="lodash.merge", vid="CVE-4", purl="pkg:npm/lodash.merge@4")
        self.vuln("f" * 24, name="lodash-merge", vid="CVE-4", purl="pkg:npm/lodash-merge@4", tool="trivy")           # npm : deux paquets distincts
        self.assertEqual(self.groups("vulnerability"), [["a" * 24, "b" * 24], ["c" * 24, "d" * 24]])


class PersistenceAndTriageTest(CorrCase):
    def pair(self):
        self.secret("a" * 24, mode="dir")
        self.secret("b" * 24, mode="git")
        self.secret("c" * 24, file="other.py", mode="dir")
        return ["a" * 24, "b" * 24]

    def test_clusters_are_persisted_deterministic_and_idempotent(self):
        pair = self.pair()
        s = correlate_run(self.db, self.data, self.run_id)
        self.assertEqual(s["secret"], {"detections": 3, "groups": 2})
        first = self.db.list_clusters(self.run_id)
        self.assertEqual(sorted(len(c["members"]) for c in first if c["kind"] == "secret"), [1, 2])
        self.assertEqual(self.db.cluster_map(self.run_id)[pair[0]]["members"], pair)
        correlate_run(self.db, self.data, self.run_id)
        self.assertEqual(self.db.list_clusters(self.run_id), first)                   # mêmes identifiants, rien de dupliqué
        self.secret("d" * 24, mode="history")                                         # une nouvelle détection : le groupe grossit
        correlate_run(self.db, self.data, self.run_id)
        self.assertEqual(self.db.cluster_map(self.run_id)["d" * 24]["members"], pair + ["d" * 24])
        self.assertEqual(sum(1 for c in self.db.list_clusters(self.run_id) if c["kind"] == "secret"), 2)    # l'ancien groupe a été remplacé
        self.db.delete_audit(self.run_id)
        self.assertEqual(self.db.list_clusters(self.run_id), [])                       # supprimés avec le run

    def test_a_human_decision_propagates_to_untriaged_identical_detections_and_never_overwrites(self):
        pair = self.pair()
        self.db.set_triage(pair[0], "false_positive", "clé de test")
        s = correlate_run(self.db, self.data, self.run_id)
        t = self.db.list_triage()
        self.assertEqual((s["propagated"], t[pair[1]]["status"]), (1, "false_positive"))
        self.assertEqual(t[pair[1]]["comment"], "[propagé depuis un résultat identique] clé de test")
        self.assertEqual(t[pair[0]]["comment"], "clé de test")                         # la décision d'origine est intacte
        self.assertNotIn("c" * 24, t)                                                  # autre fichier : jamais touché
        self.assertEqual(correlate_run(self.db, self.data, self.run_id)["propagated"], 0)    # idempotent

    def test_divergent_decisions_are_flagged_not_arbitrated(self):
        pair = self.pair()
        self.db.set_triage(pair[0], "confirmed")
        self.db.set_triage(pair[1], "false_positive", "à moi")
        s = correlate_run(self.db, self.data, self.run_id)
        self.assertEqual((s["propagated"], s["conflicts"]), (0, 1))
        self.assertEqual(self.db.list_triage()[pair[1]]["status"], "false_positive")
        item = next(i for i in build_report_data(self.db, self.run_id, self.data)["secrets"] if i["fingerprint"] == pair[0])
        self.assertTrue(item["cluster"]["conflict"])                                   # l'interface l'affichera

    def test_dry_run_and_no_propagate_write_nothing(self):
        pair = self.pair()
        self.db.set_triage(pair[0], "confirmed")
        correlate_run(self.db, self.data, self.run_id, persist=False)
        self.assertEqual((self.db.list_clusters(self.run_id), list(self.db.list_triage())), ([], [pair[0]]))
        correlate_run(self.db, self.data, self.run_id, propagate=False)
        self.assertEqual((len(self.db.list_clusters(self.run_id)) > 0, list(self.db.list_triage())), (True, [pair[0]]))

    def test_report_items_carry_their_group_even_for_runs_never_correlated(self):
        pair = self.pair()
        for stored in (False, True):
            if stored:
                correlate_run(self.db, self.data, self.run_id)
            self.assertEqual(self.db.list_clusters(self.run_id) != [], stored)            # 1re passe : rien d'enregistré -> calculé à la volée
            items = {i["fingerprint"]: i for i in build_report_data(self.db, self.run_id, self.data)["secrets"]}
            c = items[pair[0]]["cluster"]
            self.assertEqual((c["size"], c["members"], c["reasons"], c["conflict"]), (2, pair, ["same_secret"], False))
            self.assertEqual(items[pair[0]]["cluster"]["id"], items[pair[1]]["cluster"]["id"])
            self.assertEqual(items["c" * 24]["cluster"]["size"], 1)


class PipelineAndCliTest(CorrCase):
    def test_every_audit_ends_with_the_correlation_and_it_never_breaks_the_audit(self):
        lines: list[str] = []
        run = run_audit(self.db, self.data, self.root, tool_names=["cloc", "gitleaks"], log=lines.append)
        self.assertTrue(any(ln.startswith("Recoupement : secrets 4→3") for ln in lines), lines[-6:])
        self.assertEqual(sum(1 for c in self.db.list_clusters(run) if c["kind"] == "secret"), 3)
        lines.clear()
        with mock.patch("aule.orchestrator.correlate_run", side_effect=RuntimeError("boom")):
            run2 = run_audit(self.db, self.data, self.root, tool_names=["cloc"], log=lines.append)
        self.assertTrue(any("recoupement en échec" in ln and "aule correlate" in ln for ln in lines))
        self.assertEqual(self.db.get_audit(run2)["status"], "complete")

    def test_reparse_recomputes_the_groups(self):
        run = self.run_audit(tool_names=["cloc", "gitleaks"])
        self.db.replace_clusters(run, [])
        reparse(self.db, self.data, run, log=lambda *_: None)
        self.assertEqual(sum(1 for c in self.db.list_clusters(run) if c["kind"] == "secret"), 3)

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--data", str(self.data)])
        return code, out.getvalue(), err.getvalue()

    def test_cli_correlate_and_triage_on_the_whole_group(self):
        run = self.run_audit(tool_names=["cloc", "gitleaks"])
        self.db.replace_clusters(run, [])
        code, out, _ = self.cli("correlate", "--dry-run", "--show", "5")
        self.assertIn("Recoupement : secrets 4→3", out)
        self.assertIn("Simulation : rien n'a été enregistré", out)
        self.assertIn("settings.py", out)
        self.assertIn("gitleaks/dir, gitleaks/git", out)
        self.assertIn("[same_secret]", out)
        self.assertEqual(self.db.list_clusters(run), [])
        self.cli("correlate")
        pair = next(c for c in self.db.list_clusters(run) if len(c["members"]) == 2)
        code, out, _ = self.cli("triage", "set", "false_positive", pair["members"][0][:10], "--comment", "fixture")
        self.assertIn("2 élément(s) marqué(s) « false_positive » (dont 1 détection(s) identique(s) recoupée(s))", out)
        self.assertEqual({self.db.list_triage()[m]["status"] for m in pair["members"]}, {"false_positive"})
        self.cli("triage", "clear", pair["members"][0][:10])
        self.assertEqual(self.db.list_triage(), {})
        code, out, _ = self.cli("triage", "set", "confirmed", pair["members"][0][:10], "--single")
        self.assertIn("1 élément(s) marqué(s)", out)
        self.assertEqual(list(self.db.list_triage()), [pair["members"][0]])           # --single : un seul résultat, sans ses doublons


if __name__ == "__main__":
    unittest.main()
