"""Décompression des archives : fonctionnement et défenses contre archives hostiles."""
from __future__ import annotations

import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import fakes
from aule.config import UnpackConfig, parse_config
from aule.unpack import ArchiveError, extract_archive, find_archives
from common import AuditCase


def zip_dir(src: Path, dest: Path, wrapper: str | None = None) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                arc = p.relative_to(src).as_posix()
                zf.write(p, f"{wrapper}/{arc}" if wrapper else arc)


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.cfg = UnpackConfig(enabled=True)

    def test_zip_slip_is_blocked(self):
        z = self.tmp / "evil.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("../../evil.txt", "pwned")
            zf.writestr("/abs/evil2.txt", "pwned")
            zf.writestr("ok/file.txt", "fine")
        dest = self.tmp / "out" / "x"
        files, skipped = extract_archive(z, dest, self.cfg)
        self.assertEqual((files, skipped), (1, 2))
        self.assertTrue((dest / "ok" / "file.txt").exists())
        self.assertFalse((self.tmp / "evil.txt").exists())
        self.assertFalse((self.tmp / "out" / "evil.txt").exists())

    def test_zip_bomb_is_refused(self):
        z = self.tmp / "bomb.zip"
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\0" * (3 * 1024 * 1024))
        with self.assertRaisesRegex(ArchiveError, "limite"):
            extract_archive(z, self.tmp / "out", UnpackConfig(max_total_mb=1))

    def test_too_many_files(self):
        z = self.tmp / "many.zip"
        with zipfile.ZipFile(z, "w") as zf:
            for i in range(20):
                zf.writestr(f"f{i}.txt", "x")
        with self.assertRaisesRegex(ArchiveError, "entrées"):
            extract_archive(z, self.tmp / "out", UnpackConfig(max_files=10))

    def test_tar_symlinks_and_special_files_are_skipped(self):
        t = self.tmp / "a.tar.gz"
        with tarfile.open(t, "w:gz") as tf:
            data = b"hello"
            info = tarfile.TarInfo("dir/real.txt"); info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("dir/link"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/passwd"
            tf.addfile(link)
            evil = tarfile.TarInfo("../escape.txt"); evil.size = 1
            tf.addfile(evil, io.BytesIO(b"x"))
        dest = self.tmp / "out"
        files, skipped = extract_archive(t, dest, self.cfg)
        self.assertEqual((files, skipped), (1, 2))
        self.assertTrue((dest / "dir" / "real.txt").exists())
        self.assertFalse((dest / "dir" / "link").exists() or (dest / "dir" / "link").is_symlink())
        self.assertFalse((self.tmp / "escape.txt").exists())

    def test_garbage_and_wrong_extension(self):
        g = self.tmp / "garbage.zip"
        g.write_text("this is not an archive")
        with self.assertRaisesRegex(ArchiveError, "format non reconnu"):
            extract_archive(g, self.tmp / "o1", self.cfg)
        broken = self.tmp / "broken.zip"
        broken.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
        with self.assertRaises(ArchiveError):
            extract_archive(broken, self.tmp / "o2", self.cfg)

    def test_find_archives_ignores_git_and_node_modules(self):
        (self.tmp / "p" / ".git").mkdir(parents=True)
        (self.tmp / "p" / "node_modules").mkdir()
        (self.tmp / "p" / "sub").mkdir()
        for rel in (".git/a.zip", "node_modules/b.zip", "sub/c.TAR.GZ", "d.zip", "e.txt"):
            (self.tmp / "p" / rel).write_bytes(b"x")
        found = [p.relative_to(self.tmp / "p").as_posix() for p in find_archives(self.tmp / "p", self.cfg.extensions)]
        self.assertEqual(found, ["d.zip", "sub/c.TAR.GZ"])


class UnpackAuditTest(AuditCase):
    def setUp(self):
        super().setUp()
        # `plain` reçoit une archive d'un dépôt git (avec wrapper de dossier), comme un site sauvegardé
        zip_dir(self.root / "repo-git", self.root / "plain" / "site.zip", wrapper="repo-main")
        (self.root / "plain" / "broken.zip").write_text("not an archive")

    def test_disabled_by_default(self):
        names = {p["name"] for p in self.db.list_projects(self.run_audit())}
        self.assertEqual(names, {"repo-git", "plain"})

    def test_archive_becomes_project_with_history(self):
        run_id = self.run_audit(unpack=True)
        projects = {p["name"]: p for p in self.db.list_projects(run_id)}
        child = projects["plain@site.zip"]
        self.assertEqual((child["parent"], child["origin"], bool(child["is_git"])), ("plain", "site.zip", True))
        self.assertTrue(child["path"].endswith("repo-main"))  # dossier unique de l'archive = racine du projet
        st = self.statuses(run_id)
        self.assertEqual(st[("plain@site.zip", "gitleaks", "git")], "ok")   # le .git de l'archive est analysé
        self.assertEqual(len(self.secrets(run_id, "plain@site.zip", "git")), 2)
        self.assertEqual(len(self.secrets(run_id, "plain@site.zip", "dir")), 1)
        rels = self.db.list_relations(run_id)
        extracted = [r for r in rels if r["type"] == "extracted_from"]  # (d'autres liens, ex. secrets partagés, peuvent coexister)
        self.assertEqual([r["data"]["archive"] for r in extracted], ["site.zip"])
        self.assertEqual(extracted[0]["src_id"], child["id"])
        self.assertEqual(extracted[0]["dst_id"], projects["plain"]["id"])

    def test_failures_are_visible_not_fatal(self):
        run_id = self.run_audit(unpack=True)
        unpack_runs = {r["mode"]: r for r in self.db.list_tool_runs(run_id) if r["tool"] == "unpack"}
        self.assertEqual(unpack_runs["site.zip"]["status"], "ok")
        self.assertEqual(unpack_runs["broken.zip"]["status"], "failed")
        self.assertIn("format non reconnu", unpack_runs["broken.zip"]["error"])
        self.assertEqual(self.db.get_audit(run_id)["status"], "partial")

    def test_resume_does_not_unpack_twice_and_keeps_projects(self):
        run_id = self.run_audit(unpack=True)
        before = len(self.calls())
        self.run_audit(unpack=True, resume=run_id)
        self.assertEqual(len(self.calls()), before)
        self.assertEqual(len([p for p in self.db.list_projects(run_id) if p["parent"]]), 1)

    def test_enabled_from_yaml_and_depth(self):
        inner = self.tmp / "inner"
        inner.mkdir()
        (inner / "deep.py").write_text(f'K = "{fakes.SECRET_A}"\n')
        zip_dir(inner, self.tmp / "inner.zip")
        with zipfile.ZipFile(self.tmp / "inner.zip") as _:
            pass
        outer_dir = self.tmp / "outer"
        outer_dir.mkdir()
        (self.tmp / "inner.zip").replace(outer_dir / "inner.zip")
        zip_dir(outer_dir, self.root / "plain" / "outer.zip")
        shallow = parse_config({"unpack": {"enabled": True, "max_depth": 1}}, self.tmp)
        names = {p["name"] for p in self.db.list_projects(self.run_audit(shallow))}
        self.assertIn("plain@outer.zip", names)
        self.assertFalse([n for n in names if n.count("@") > 1])
        deep = parse_config({"unpack": {"enabled": True, "max_depth": 2}}, self.tmp)
        names = {p["name"] for p in self.db.list_projects(self.run_audit(deep))}
        self.assertIn("plain@outer.zip@inner.zip", names)


if __name__ == "__main__":
    unittest.main()
