"""Export consolidé, constats manuels, notes : dédoublonnage, filtres, formats, CLI."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

import fakes
from aule.cli import main
from aule.export import ExportError, collect, to_csv, to_markdown, write_export
from common import AuditCase
from test_more_tools import MoreToolsCase

TOOLS = ["cloc", "gitleaks", "trufflehog", "osv-scanner", "trivy", "checkov"]


class Inject:
    """Insère des entités à la main (pour tester le dédoublonnage sans dépendre d'outils réels)."""

    def inject(self, kind, project, fingerprint, **data):
        pid = {p["name"]: p["id"] for p in self.db.list_projects(self.run_id)}[project]
        trid = next(r["id"] for r in self.db.list_tool_runs(self.run_id) if r["project_id"] == pid)
        self.db.conn.execute("INSERT INTO entity(audit_id, project_id, tool_run_id, kind, fingerprint, data) VALUES (?,?,?,?,?,?)",
                             (self.run_id, pid, trid, kind, fingerprint, json.dumps(data)))
        self.db.conn.commit()

    def sast(self, project, fp, tool, line, cwe, severity="high", file="f.py", **extra):
        rule = extra.pop("rule_id", f"{tool}.rule")
        self.inject("sast_finding", project, fp, tool=tool, rule_id=rule, severity=severity, file=file, start_line=line,
                    cwe=cwe, message="m", snippet="code", flow=[], **extra)

    def rows(self, **kw):
        return collect(self.db, self.run_id, self.data, **kw)["rows"]


class DedupTest(Inject, AuditCase):
    def setUp(self):
        super().setUp()
        self.run_id = self.run_audit(tool_names=["cloc"])

    def sast_rows(self, **kw):
        return [r for r in self.rows(**kw) if r["category"] == "sast"]

    def test_merge_needs_same_line_and_a_common_cwe_and_is_transitive(self):
        self.sast("plain", "a" * 24, "toolX", 3, ["CWE-89"], "high")
        self.sast("plain", "b" * 24, "toolY", 3, ["CWE-89", "CWE-564"], "medium")
        self.sast("plain", "c" * 24, "toolZ", 3, [], "high")                     # pas de CWE : jamais fusionné
        self.sast("plain", "d" * 24, "toolX", 9, ["CWE-89"], "high")             # autre ligne
        self.sast("plain", "e" * 24, "toolY", 3, ["CWE-79"], "high", rule_id="toolY.xss")   # autre règle, autre CWE : reste séparée
        rows = self.sast_rows()
        self.assertEqual(len(rows), 4)
        merged = next(r for r in rows if r["corroboration"] == 2)
        self.assertEqual((merged["tools"], merged["severity"], merged["cwe"]), (["toolX", "toolY"], "high", ["CWE-564", "CWE-89"]))
        self.assertEqual(sorted(merged["fingerprints"]), ["a" * 24, "b" * 24])     # rien n'est perdu
        self.sast("plain", "f" * 24, "toolW", 3, ["CWE-564"], "low")               # rejoint le groupe via B
        merged = next(r for r in self.sast_rows() if r["corroboration"] == 3)
        self.assertEqual(merged["tools"], ["toolW", "toolX", "toolY"])

    def test_partial_false_positive_keeps_the_row_but_total_false_positive_drops_it(self):
        self.sast("plain", "a" * 24, "toolX", 3, ["CWE-89"])
        self.sast("plain", "b" * 24, "toolY", 3, ["CWE-89"])
        self.db.set_triage("a" * 24, "false_positive")
        (row,) = self.sast_rows()
        self.assertIsNone(row["triage"])                                          # toolY le signale toujours
        self.db.set_triage("b" * 24, "false_positive")
        self.assertEqual(self.sast_rows(), [])
        (row,) = self.sast_rows(include_false_positives=True)
        self.assertEqual(row["triage"], "false_positive")

    def test_triage_precedence_when_statuses_differ(self):
        self.sast("plain", "a" * 24, "toolX", 3, ["CWE-89"])
        self.sast("plain", "b" * 24, "toolY", 3, ["CWE-89"])
        self.db.set_triage("a" * 24, "accepted_risk")
        self.db.set_triage("b" * 24, "confirmed", "vu sur site")
        (row,) = self.sast_rows()
        self.assertEqual((row["triage"], row["comment"]), ("confirmed", "vu sur site"))

    def test_filters(self):
        self.sast("plain", "a" * 24, "t", 1, ["CWE-1"], "critical")
        self.sast("plain", "b" * 24, "t", 2, ["CWE-2"], "low")
        self.sast("plain", "c" * 24, "t", 3, ["CWE-3"], "medium")
        self.db.set_triage("c" * 24, "to_review")
        self.assertEqual([r["severity"] for r in self.sast_rows()], ["critical", "medium", "low"])    # tri par gravité
        self.assertEqual([r["severity"] for r in self.sast_rows(min_severity="medium")], ["critical", "medium"])
        self.assertEqual([r["severity"] for r in self.sast_rows(statuses=["to_review"])], ["medium"])
        self.assertEqual(len(self.sast_rows(statuses=["untriaged"])), 2)

    def test_manual_findings_and_dismissed(self):
        a = self.db.add_finding("plain", "Absence de contrôle d'accès", "high", "confirmed", "Décrit.", ["src/a.py:3"])
        self.db.add_finding("plain", "Abandonné", "low", "dismissed")
        rows = [r for r in self.rows() if r["category"] == "manual"]
        self.assertEqual([(r["id"], r["triage"], r["tools"]) for r in rows], [(f"M-{a}", "confirmed", ["auditeur"])])
        self.assertEqual(len([r for r in self.rows(include_dismissed=True) if r["category"] == "manual"]), 2)
        self.assertEqual([r["id"] for r in self.rows(statuses=["draft"]) if r["category"] == "manual"], [])


class RunExportTest(MoreToolsCase):
    def setUp(self):
        super().setUp()
        self.run_id = self.go(TOOLS)

    def collect(self, **kw):
        return collect(self.db, self.run_id, self.data, **kw)

    def test_cross_tool_consolidation(self):
        rows = self.collect()["rows"]
        django = next(r for r in rows if r["category"] == "dependency" and "django" in r["title"])
        self.assertEqual((django["tools"], django["corroboration"], django["severity"], django["cwe"]),
                         (["osv-scanner", "trivy"], 2, "critical", ["CWE-640"]))
        self.assertEqual(len(django["fingerprints"]), 2)
        self.assertEqual(django["evidence"], "Correctif : 3.0.1")
        lodash = next(r for r in rows if "lodash" in r["title"])
        self.assertEqual((lodash["tools"], lodash["corroboration"]), (["osv-scanner"], 1))
        both = next(r for r in rows if r["category"] == "secret" and r["location"].startswith("settings.py") and r["extra"]["mode"] == "dir")
        self.assertEqual((both["tools"], both["corroboration"]), (["gitleaks", "trufflehog"], 2))
        self.assertEqual({r["category"] for r in rows}, {"secret", "dependency", "iac"})
        iac = {r["rule"] for r in rows if r["category"] == "iac"}
        self.assertEqual(iac, {"CKV_AWS_20", "AVD-DS-0002"})
        sev = [{"critical": 4, "high": 3, "medium": 2}[r["severity"]] for r in rows]
        self.assertEqual(sev, sorted(sev, reverse=True))

    def test_secrets_clear_or_masked(self):
        clear = [r for r in self.collect(reveal=True)["rows"] if r["category"] == "secret"]
        self.assertTrue(all(r["evidence"] in (fakes.SECRET_A, fakes.SECRET_B) for r in clear))
        masked = [r for r in self.collect(reveal=False)["rows"] if r["category"] == "secret"]
        self.assertTrue(masked and all(r["evidence"] in ("AK••••••LE", "gh••••••R8") for r in masked))
        for text in (to_csv(self.collect(reveal=False)), to_markdown(self.collect(reveal=False)), json.dumps(self.collect(reveal=False), default=str)):
            self.assertNotIn(fakes.SECRET_A, text)
            self.assertNotIn(fakes.SECRET_B, text)
        self.assertIn(fakes.SECRET_B, to_markdown(self.collect(reveal=True)))

    def test_markdown_content(self):
        self.db.set_note("repo-git", "Service exposé sur Internet ; à confirmer avec le client.")
        self.db.add_finding("repo-git", "Mot de passe administrateur par défaut", "critical", "confirmed", "Constaté en recette.", ["Dockerfile:2"])
        md = to_markdown(self.collect())
        for expected in ("# Constats — audit", "## Synthèse", "## repo-git", "**Notes de l'auditeur**", "à confirmer avec le client",
                         "### [CRITIQUE] Mot de passe administrateur par défaut", "```", "outils concordants", "⚠ **Ce document contient des secrets en clair.**"):
            self.assertIn(expected, md)
        self.assertNotIn("secrets en clair", to_markdown(self.collect(reveal=False)))

    def test_csv_is_excel_safe(self):
        self.db.add_finding("repo-git", '=HYPERLINK("http://evil","clique")', "low", "confirmed", "+cmd|' /C calc'!A0")
        text = to_csv(self.collect())
        self.assertTrue(text.startswith("\ufeff"))
        rows = list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))
        self.assertEqual(rows[0][:5], ["ID", "Catégorie", "Projet", "Sévérité", "Titre"])
        manual = next(r for r in rows if r[1] == "manual")
        self.assertEqual(manual[4], '\'=HYPERLINK("http://evil","clique")')        # neutralisé par une apostrophe
        self.assertTrue(manual[11].startswith("'+cmd"))
        self.assertEqual(len(rows) - 1, len(self.collect()["rows"]))

    def test_json_is_valid(self):
        d = json.loads(write_export(self.collect(), "json", self.tmp / "e.json").read_text())
        self.assertEqual(d["audit"]["id"], self.run_id)
        self.assertEqual(len(d["rows"]), len(self.collect()["rows"]))

    def test_xlsx(self):
        from openpyxl import load_workbook
        self.db.add_finding("repo-git", "=1+1 titre piégé\x00", "low", "confirmed", "détail\x07")
        out = write_export(self.collect(), "xlsx", self.tmp / "e.xlsx")
        wb = load_workbook(out)
        self.assertEqual(wb.sheetnames, ["Résumé", "Constats", "Notes"])
        ws = wb["Constats"]
        self.assertEqual([c.value for c in ws[1]][:5], ["ID", "Catégorie", "Projet", "Sévérité", "Titre"])
        self.assertEqual(ws.max_row - 1, len(self.collect()["rows"]))
        self.assertTrue(ws.auto_filter.ref.startswith("A1:"))
        cell = next(c for row in ws.iter_rows(min_row=2) for c in row if c.value and "titre piégé" in str(c.value))
        self.assertEqual((cell.value, cell.data_type), ("=1+1 titre piégé", "s"))     # texte, jamais une formule ; \x00 retiré
        summary = {r[0].value: [c.value for c in r[1:]] for r in wb["Résumé"].iter_rows(min_row=5)}
        self.assertIn("repo-git", summary)
        self.assertEqual(wb["Résumé"]["A2"].value, "⚠ Contient des secrets en clair : ne pas diffuser")

    def test_docx(self):
        from docx import Document
        self.db.add_finding("repo-git", "Titre\x00 avec contrôle", "high", "confirmed", "texte\x0b")
        self.db.set_note("repo-git", "Note de l'auditeur")
        doc = Document(str(write_export(self.collect(), "docx", self.tmp / "e.docx")))
        text = "\n".join(p.text for p in doc.paragraphs)
        for expected in ("Constats — audit", "repo-git", "Note de l'auditeur", "[ÉLEVÉE] Titre avec contrôle", "CVE-2019-19844"):
            self.assertIn(expected, text)
        self.assertTrue(doc.tables)

    def test_optional_dependencies_give_a_clear_message(self):
        with mock.patch.dict(sys.modules, {"openpyxl": None}), self.assertRaisesRegex(ExportError, "openpyxl"):
            write_export(self.collect(), "xlsx", self.tmp / "x.xlsx")
        with mock.patch.dict(sys.modules, {"docx": None}), self.assertRaisesRegex(ExportError, "python-docx"):
            write_export(self.collect(), "docx", self.tmp / "x.docx")
        with self.assertRaisesRegex(ExportError, "format inconnu"):
            write_export(self.collect(), "pdf", self.tmp / "x.pdf")

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main([*argv, "--data", str(self.data)])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_cli_default_is_clear_with_restricted_permissions(self):
        code, out, _ = self.cli("export", "--format", "csv")
        self.assertEqual(code, 0)
        path = self.data / f"export-{self.run_id}.csv"
        self.assertIn(fakes.SECRET_B, path.read_text(encoding="utf-8"))
        self.assertIn("EN CLAIR", out)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_cli_mask(self):
        code, out, _ = self.cli("export", "--format", "md", "--mask")
        self.assertEqual(code, 0)
        self.assertNotIn("EN CLAIR", out)
        text = (self.data / f"export-{self.run_id}-masque.md").read_text(encoding="utf-8")
        self.assertNotIn(fakes.SECRET_B, text)

    def test_cli_filters_and_errors(self):
        code, out, _ = self.cli("export", "--format", "json", "--min-severity", "critical", "-o", str(self.tmp / "c.json"))
        rows = json.loads((self.tmp / "c.json").read_text())["rows"]
        self.assertTrue(rows and {r["severity"] for r in rows} == {"critical"})
        self.assertIn(f"{len(rows)} ligne(s)", out)
        self.assertIn("statut(s) inconnu(s)", self.cli("export", "--status", "banana")[2])
        self.assertEqual(self.cli("export", "--format", "pdf")[0], 2)


class FindingNoteCliTest(AuditCase):
    def setUp(self):
        super().setUp()
        self.run_id = self.run_audit(tool_names=["cloc", "gitleaks"])

    def cli(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch("sys.stdin", io.StringIO(stdin or "")):
            try:
                code = main([*argv, "--data", str(self.data)])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def editor(self, body: str, exit_code: int = 0) -> str:
        script, text = self.tmp / "fake-editor.sh", self.tmp / "editor-body.txt"
        text.write_text(body + "\n", encoding="utf-8")  # le corps passe par un fichier : aucun souci de guillemets
        script.write_text(f'#!/bin/sh\ncat "{text}" >> "$1"\nexit {exit_code}\n')
        script.chmod(0o755)
        return str(script)

    def test_add_list_show_edit_rm_lifecycle(self):
        fp = self.db.entities(self.run_id, "secret")[0]["fingerprint"]
        code, out, _ = self.cli("finding", "add", "--project", "plain", "--title", "Clé AWS dans le dépôt", "--severity", "high",
                                "--description", "Trouvée en clair.", "--ref", fp[:10], "--ref", "keys.py:1")
        self.assertEqual((code, out.strip()), (0, "Constat #1 créé"))
        f = self.db.get_finding(1)
        self.assertEqual(f["refs"], [fp, "keys.py:1"])                  # préfixe résolu en empreinte complète ; référence libre gardée
        self.assertIn("#1    draft      high     plain            Clé AWS dans le dépôt", self.cli("finding", "list")[1])
        self.assertIn("Trouvée en clair.", self.cli("finding", "show", "1")[1])
        self.assertEqual(self.cli("finding", "edit", "1", "--status", "confirmed", "--severity", "critical", "--ref", "src/x.py:9")[0], 0)
        f = self.db.get_finding(1)
        self.assertEqual((f["status"], f["severity"], f["title"], f["refs"][-1]), ("confirmed", "critical", "Clé AWS dans le dépôt", "src/x.py:9"))
        self.assertEqual(f["description"], "Trouvée en clair.")         # champ non cité : inchangé
        self.assertIn("1 constat(s)", self.cli("finding", "list", "--status", "confirmed")[1])
        self.assertIn("0 constat(s)", self.cli("finding", "list", "--project", "ailleurs")[1])
        self.assertEqual(self.cli("finding", "rm", "1")[0], 0)
        self.assertIn("constat inconnu", self.cli("finding", "show", "1")[2])

    def test_description_from_stdin_file_and_editor(self):
        self.cli("finding", "add", "--project", "plain", "--title", "A", "--description-file", "-", stdin="Texte via stdin")
        self.assertEqual(self.db.get_finding(1)["description"], "Texte via stdin")
        f = self.tmp / "d.md"
        f.write_text("Texte via fichier", encoding="utf-8")
        self.cli("finding", "add", "--project", "plain", "--title", "B", "--description-file", str(f))
        self.assertEqual(self.db.get_finding(2)["description"], "Texte via fichier")
        with mock.patch.dict(os.environ, {"EDITOR": self.editor("Rédigé dans l'éditeur"), "VISUAL": ""}):
            self.assertEqual(self.cli("finding", "add", "--project", "plain", "--title", "C", "--edit")[0], 0)
            self.cli("finding", "edit", "1", "--edit")
        self.assertIn("Rédigé dans l'éditeur", self.db.get_finding(3)["description"])
        self.assertTrue(self.db.get_finding(1)["description"].startswith("Texte via stdin"))   # l'éditeur a reçu le texte existant
        self.assertIn("Rédigé dans l'éditeur", self.db.get_finding(1)["description"])

    def test_failing_editor_saves_nothing(self):
        with mock.patch.dict(os.environ, {"EDITOR": self.editor("x", exit_code=1), "VISUAL": ""}):
            code, _, err = self.cli("finding", "add", "--project", "plain", "--title", "C", "--edit")
        self.assertEqual(code, 2)
        self.assertIn("a échoué", err)
        self.assertEqual(self.db.list_findings(), [])

    def test_validation_errors(self):
        self.assertEqual(self.cli("finding", "add", "--project", "p", "--title", "t", "--severity", "banana")[0], 2)
        self.assertIn("d'un projet et d'un titre", self.cli("finding", "add", "--project", "p", "--title", "  ")[2])
        self.assertIn("constat inconnu", self.cli("finding", "edit", "99", "--title", "x")[2])
        self.assertIn("constat inconnu", self.cli("finding", "rm", "99")[2])

    def test_findings_and_notes_are_global_across_runs(self):
        self.cli("finding", "add", "--project", "plain", "--title", "Persistant")
        self.cli("note", "set", "plain", "--text", "Note persistante")
        run2 = self.run_audit(tool_names=["cloc"])
        self.assertNotEqual(run2, self.run_id)
        self.assertEqual([f["title"] for f in self.db.list_findings("plain")], ["Persistant"])
        self.assertIn("Note persistante", self.cli("note", "show", "plain")[1])

    def test_notes(self):
        self.assertIn("(aucune note pour plain)", self.cli("note", "show", "plain")[1])
        self.assertEqual(self.cli("note", "set", "plain", "--text", "Ligne 1\nLigne 2")[0], 0)
        self.assertIn("Ligne 2", self.cli("note", "show", "plain")[1])
        self.cli("note", "set", "repo-git", "--file", "-", stdin="Depuis stdin")
        out = self.cli("note", "list")[1]
        self.assertIn("== plain", out)
        self.assertIn("Depuis stdin", out)
        self.assertIn("supprimée", self.cli("note", "set", "plain", "--text", "  ")[1])
        self.assertNotIn("plain", self.db.list_notes())
        self.assertIn("indiquez --text", self.cli("note", "set", "plain")[2])
        with mock.patch.dict(os.environ, {"EDITOR": self.editor("Note éditée"), "VISUAL": ""}):
            self.cli("note", "set", "repo-git", "--edit")
        self.assertIn("Depuis stdin", self.db.list_notes()["repo-git"]["text"])
        self.assertIn("Note éditée", self.db.list_notes()["repo-git"]["text"])


if __name__ == "__main__":
    unittest.main()
