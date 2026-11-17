"""Liens entre projets : scanner de références, remotes, relations croisées."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fakes
from aule.cli import main
from aule.config import parse_config
from aule.linkscan import normalize_remote, scan_project
from aule.links import compute_relations
from aule.orchestrator import run_audit
from common import AuditCase


class NormalizeRemoteTest(unittest.TestCase):
    def test_variants_converge(self):
        same = ["git@github.com:Corp/Tool.git", "https://github.com/corp/tool", "https://user:TOKEN@GitHub.com/Corp/Tool.git/",
                "ssh://git@github.com/corp/tool.git", "git://github.com/corp/tool"]
        self.assertEqual({normalize_remote(u) for u in same}, {"github.com/corp/tool"})

    def test_edge_cases(self):
        self.assertIsNone(normalize_remote("   "))
        self.assertEqual(normalize_remote("/srv/git/x.git"), "path:/srv/git/x")
        self.assertEqual(normalize_remote("git@h.corp:a/b.git"), "h.corp/a/b")
        self.assertNotIn("TOKEN", normalize_remote("https://u:TOKEN@h.example/o/r.git"))


class ScanProjectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.p = self.tmp / "proj"
        files = {
            ".git/config": '[core]\n\tbare = false\n[remote "origin"]\n\turl = https://deploy:SECRETTOKEN123@GitHub.com/Corp/Repo.git\n'
                           '[remote "backup"]\n\turl = git@gitlab.corp.local:team/repo.git\n[branch "main"]\n\tremote = origin\n',
            "package.json": json.dumps({"name": "@corp/lib", "dependencies": {"lodash": "^4", "@corp/shared": "file:../shared"}}),
            "pyproject.toml": '[project]\nname = "My_Lib"\ndependencies = ["requests>=2", "corp-core[extra]==1.0"]\n'
                              '[tool.poetry.dependencies]\npython = "^3.11"\nlocal = {path = "../local"}\n',
            "requirements-dev.txt": "-e ../editable\nflask==2.0  # web\n# comment\n--index-url http://pypi.corp.local/simple\n",
            "pom.xml": '<project xmlns="http://maven.apache.org/POM/4.0.0"><parent><groupId>com.corp</groupId><artifactId>parent</artifactId>'
                       '<relativePath>../parent/pom.xml</relativePath></parent><artifactId>svc</artifactId>'
                       '<dependencies><dependency><groupId>com.corp</groupId><artifactId>common</artifactId></dependency>'
                       '<dependency><groupId>${x}</groupId><artifactId>skipped</artifactId></dependency></dependencies></project>',
            "build.gradle": "group = 'com.corp'\ndependencies {\n  implementation 'com.corp:billing-client:1.2'\n}\n",
            "settings.gradle": "rootProject.name = 'gradle-svc'\n",
            "go.mod": "module corp.example/svc\n\nrequire (\n\tcorp.example/lib v1.0.0\n)\n\nreplace corp.example/lib => ../lib\n",
            "Cargo.toml": '[package]\nname = "crate-a"\n[dependencies]\ncrate-b = { path = "../crate-b" }\nserde = "1"\n',
            "App.csproj": '<Project><PropertyGroup><AssemblyName>Corp.App</AssemblyName></PropertyGroup><ItemGroup>'
                          '<PackageReference Include="Newtonsoft.Json" Version="13"/><ProjectReference Include="..\\Common\\Common.csproj"/></ItemGroup></Project>',
            "docker-compose.yml": "services:\n  web:\n    build: ./web\n    image: corp/web:1.0\n  db:\n    image: postgres:15\n"
                                  "  other:\n    build:\n      context: ../shared\n",
            "Dockerfile": "FROM node:18 AS build\nFROM build AS test\nFROM nginx@sha256:abc\n",
            "src/app.py": 'A = "http://billing.corp.local:8080/api"\nB = "postgresql://user:hunter2pw@db.corp.local:5432/x"\n'
                          'C = "jdbc:mysql://mysql.corp.local/db"\nD = "https://github.com/x/y"\n',
            "node_modules/x/package.json": json.dumps({"name": "ignored-pkg"}),
            "package-lock.json": '{"resolved": "https://registry.npmjs.org/lodash/-/lodash.tgz"}',
            "composer.json": "{ this is not json",
        }
        for rel, text in files.items():
            (self.p / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.p / rel).write_text(text)
        self.refs = {(r["type"], r["value"]) for r in scan_project(self.p)}

    def has(self, rtype, value):
        self.assertIn((rtype, value), self.refs)

    def test_remotes_without_credentials(self):
        self.has("git_remote", "github.com/corp/repo")
        self.has("git_remote", "gitlab.corp.local/team/repo")
        self.assertNotIn("SECRETTOKEN123", json.dumps(sorted(self.refs)))

    def test_provides_and_requires_per_ecosystem(self):
        for v in ("npm:@corp/lib", "pypi:my-lib", "maven:com.corp:svc", "maven:com.corp:gradle-svc" if False else "maven:com.corp:svc",
                  "go:corp.example/svc", "cargo:crate-a", "nuget:Corp.App", "image:corp/web"):
            self.has("provides", v)
        for v in ("npm:lodash", "npm:@corp/shared", "pypi:requests", "pypi:corp-core", "pypi:flask", "maven:com.corp:common",
                  "maven:com.corp:billing-client", "go:corp.example/lib", "cargo:crate-b", "cargo:serde", "nuget:Newtonsoft.Json",
                  "image:postgres", "image:node", "image:nginx"):
            self.has("requires", v)
        self.assertNotIn(("requires", "pypi:python"), self.refs)
        self.assertNotIn(("requires", "image:build"), self.refs)       # alias de stage Dockerfile
        self.assertFalse([r for r in self.refs if "skipped" in r[1] or "ignored-pkg" in r[1]])  # ${x} et node_modules

    def test_local_paths_are_resolved(self):
        base = self.p
        for rel in ("../shared", "../local", "../editable", "../parent", "../lib", "../crate-b", "../Common/Common.csproj", "web"):
            self.has("local_path", str((base / rel).resolve()))

    def test_endpoints_without_credentials_and_lockfiles_ignored(self):
        hosts = {v for t, v in self.refs if t == "endpoint"}
        self.assertEqual(hosts, {"billing.corp.local", "db.corp.local", "mysql.corp.local", "github.com"})
        self.assertNotIn("hunter2pw", json.dumps(sorted(self.refs)))
        self.assertNotIn("registry.npmjs.org", hosts)

    def test_invalid_manifest_does_not_abort_the_scan(self):
        self.assertTrue(self.refs)  # composer.json cassé : le reste a bien été lu

    def test_cli_entry_point_writes_report(self):
        out = self.tmp / "r.json"
        from aule.linkscan import main as scan_main
        self.assertEqual(scan_main([str(self.p), str(out)]), 0)
        self.assertEqual(json.loads(out.read_text())["version"], 1)
        self.assertEqual(scan_main(["only-one-arg"]), 2)


class LinksTest(AuditCase):
    TOOLS = ["cloc", "gitleaks", "links"]

    def setUp(self):
        super().setUp()
        def put(rel, text):
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        put("lib/package.json", json.dumps({"name": "@corp/lib"}))
        put("app/package.json", json.dumps({"name": "app", "dependencies": {"@corp/lib": "^1"}}))
        put("stack/docker-compose.yml", "services:\n  api:\n    build: ../lib\n")
        put("svc-a/config.yml", "url: http://billing.corp.local/api\nother: https://github.com/x/y\n")
        put("svc-a/token.py", f'T = "{fakes.SECRET_B}"\n')
        put("svc-b/settings.json", json.dumps({"u": "https://billing.corp.local/v2"}))
        put("clone1/.git/config", '[remote "origin"]\n\turl = git@github.com:Corp/Tool.git\n')
        put("clone2/.git/config", '[remote "origin"]\n\turl = https://github.com/corp/tool\n')
        self.cfg = parse_config({"tools": {"gitleaks": {"modes": ["dir"]}}}, self.tmp)   # `.git` factices : pas de mode git

    def go(self, cfg=None, **kw):
        return self.run_audit(cfg or self.cfg, tool_names=self.TOOLS, **kw)

    def rels(self, run_id):
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        return sorted((r["type"], names[r["src_id"]], names[r["dst_id"]]) for r in self.db.list_relations(run_id))

    def by_type(self, run_id, rtype):
        return [r for r in self.db.list_relations(run_id) if r["type"] == rtype]

    def test_all_four_link_types(self):
        run_id = self.go()
        rels = self.rels(run_id)
        self.assertIn(("depends_on", "app", "lib"), rels)
        self.assertIn(("depends_on", "stack", "lib"), rels)                # contexte de build Compose
        self.assertIn(("same_remote", "clone1", "clone2"), rels)
        self.assertIn(("shared_endpoint", "svc-a", "svc-b"), rels)
        self.assertIn(("shared_secret", "repo-git", "svc-a"), rels)
        self.assertNotIn("plain", {x for r in rels for x in r[1:]})       # aucun lien parasite

    def test_relation_details(self):
        run_id = self.go()
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        dep = next(r for r in self.by_type(run_id, "depends_on") if names[r["src_id"]] == "app")
        self.assertEqual(dep["data"]["via"], ["npm:@corp/lib"])
        stack = next(r for r in self.by_type(run_id, "depends_on") if names[r["src_id"]] == "stack")
        self.assertEqual(stack["data"]["via"], ["chemin:."])
        (ep,) = self.by_type(run_id, "shared_endpoint")
        self.assertEqual((ep["data"]["hosts"], ep["data"]["count"]), (["billing.corp.local"], 1))   # github.com ignoré
        (rem,) = self.by_type(run_id, "same_remote")
        self.assertEqual(rem["data"]["remote"], "github.com/corp/tool")
        (sec,) = self.by_type(run_id, "shared_secret")
        self.assertEqual((sec["data"]["count"], sec["data"]["secrets"][0]["masked"], sec["data"]["secrets"][0]["rule"]), (1, "gh••••••R8", "github-pat"))
        for r in self.by_type(run_id, "shared_endpoint") + self.by_type(run_id, "shared_secret") + self.by_type(run_id, "same_remote"):
            self.assertLess(r["src_id"], r["dst_id"])                    # non orienté : ordre canonique

    def test_ignore_hosts_option_uses_domain_suffix(self):
        cfg = parse_config({"tools": {"gitleaks": {"modes": ["dir"]}, "links": {"options": {"ignore_hosts": ["corp.local"]}}}}, self.tmp)
        self.assertEqual(self.by_type(self.go(cfg), "shared_endpoint"), [])

    def test_recompute_is_idempotent(self):
        run_id = self.go()
        before = self.rels(run_id)
        compute_relations(self.db, run_id)
        compute_relations(self.db, run_id)
        self.assertEqual(self.rels(run_id), before)

    def test_no_shared_link_between_a_project_and_its_own_archive(self):
        from test_unpack import zip_dir
        zip_dir(self.root / "svc-a", self.root / "svc-b" / "copy.zip")      # svc-b embarque une copie de svc-a
        run_id = self.go(unpack=True)
        rels = self.rels(run_id)
        self.assertIn(("extracted_from", "svc-b@copy.zip", "svc-b"), rels)
        # la copie de svc-a dans svc-b relie bien svc-a (même secret, même hôte) ...
        self.assertIn(("shared_secret", "svc-a", "svc-b@copy.zip"), rels)
        self.assertIn(("shared_endpoint", "svc-a", "svc-b@copy.zip"), rels)
        # ... mais svc-b et sa propre archive partagent forcément du contenu : pas de lien « partagé »
        self.assertFalse([r for r in rels if r[0] != "extracted_from" and {r[1], r[2]} == {"svc-b", "svc-b@copy.zip"}])

    def test_run_log_summarizes_links_and_a_failure_never_loses_the_audit(self):
        lines: list[str] = []
        run_audit(self.db, self.data, self.root, config=self.cfg, tool_names=self.TOOLS, log=lines.append)
        self.assertTrue(any(ln.startswith("Liens entre projets :") and "depends_on 2" in ln for ln in lines))
        lines2: list[str] = []
        with mock.patch("aule.orchestrator.compute_relations", side_effect=RuntimeError("boom")):
            run_id = run_audit(self.db, self.data, self.root, config=self.cfg, tool_names=self.TOOLS, log=lines2.append)
        self.assertTrue(any("calcul des liens en échec" in ln and "boom" in ln for ln in lines2))
        self.assertEqual(self.db.get_audit(run_id)["status"], "complete")

    def test_links_tool_is_on_by_default_and_runs_for_every_project(self):
        run_id = self.run_audit()
        names = {p["id"]: p["name"] for p in self.db.list_projects(run_id)}
        runs = {(names[r["project_id"]], r["status"]) for r in self.db.list_tool_runs(run_id) if r["tool"] == "links"}
        self.assertIn(("lib", "ok"), runs)
        self.assertEqual({st for _, st in runs}, {"ok"})

    def test_cli_links(self):
        self.go()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["links", "--data", str(self.data)]), 0)
        text = out.getvalue()
        for expected in ("[depends_on] app → lib", "dépend de (npm:@corp/lib)", "hôte(s) commun(s) : billing.corp.local",
                         "même dépôt d'origine : github.com/corp/tool", "secret partagé (1)"):
            self.assertIn(expected, text)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["links", "--data", str(self.data), "--type", "depends_on", "--project", "lib"])
        self.assertEqual(out.getvalue().count("[depends_on]"), 2)
        self.assertNotIn("[shared_endpoint]", out.getvalue())

    def test_report_payload_carries_relations(self):
        from aule.report import build_report_data
        d = build_report_data(self.db, self.go())
        types = {r["type"] for r in d["relations"]}
        self.assertTrue({"depends_on", "same_remote", "shared_endpoint", "shared_secret"} <= types)
        self.assertTrue(all(r["src"] and r["dst"] for r in d["relations"]))


if __name__ == "__main__":
    unittest.main()
