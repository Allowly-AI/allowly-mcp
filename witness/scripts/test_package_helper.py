import importlib.util
import io
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE = Path(__file__).with_name("package_helper.py")
SPEC = importlib.util.spec_from_file_location("package_helper", MODULE)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class PackageHelperTests(unittest.TestCase):
    @staticmethod
    def sample_macos_arm64():
        return b"\xcf\xfa\xed\xfe" + (0x0100000C).to_bytes(4, "little") + bytes(24)

    def test_archive_is_repeatable_and_contains_only_executable(self):
        binary = self.sample_macos_arm64()
        first = helper.archive_bytes(binary)
        self.assertEqual(first, helper.archive_bytes(binary))
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as tar:
            self.assertEqual([entry.name for entry in tar], [helper.NAME])
            entry = tar.getmember(helper.NAME)
            self.assertEqual(entry.mode, 0o755)
            self.assertEqual(entry.mtime, 0)
            self.assertEqual(tar.extractfile(entry).read(), binary)

    def test_manifest_detects_changed_archive_and_unsafe_member(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            archive = folder / "{}-{}-{}.tar.gz".format(
                helper.NAME, helper.cargo_version(), "aarch64-apple-darwin",
            )
            archive.write_bytes(helper.archive_bytes(self.sample_macos_arm64()))
            manifest = helper.checksum_lines(folder)
            self.assertIn(archive.name.encode("ascii"), manifest)
            archive.write_bytes(helper.archive_bytes(self.sample_macos_arm64() + b"different"))
            self.assertNotEqual(manifest, helper.checksum_lines(folder))
            with tarfile.open(archive, "w:gz") as tar:
                member = tarfile.TarInfo("../escape")
                member.size = 1
                tar.addfile(member, io.BytesIO(b"x"))
            with self.assertRaisesRegex(ValueError, "root-level executable"):
                helper.checksum_lines(folder)

    def test_wrong_architecture_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "architecture does not match"):
            helper.check_binary_target(self.sample_macos_arm64(), "x86_64-apple-darwin")

    def test_source_is_repeatable_and_build_inputs_only(self):
        contents = helper.source_archive_bytes()
        self.assertEqual(contents, helper.source_archive_bytes())
        with tarfile.open(fileobj=io.BytesIO(contents), mode="r:gz") as tar:
            names = set(tar.getnames())
            self.assertTrue(helper.SOURCE_REQUIRED.issubset(names))
            self.assertEqual(names - helper.SOURCE_REQUIRED, {
                "src/evidence.rs", "src/execute.rs", "src/kms.rs",
            })
            for entry in tar:
                self.assertTrue(entry.isfile())
                self.assertEqual(entry.mtime, 0)
                self.assertEqual(entry.uid, 0)
                self.assertEqual(entry.gid, 0)
                self.assertEqual(tar.extractfile(entry).read(), (helper.ROOT / entry.name).read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "{}-{}-source.tar.gz".format(helper.NAME, helper.cargo_version())
            archive.write_bytes(contents)
            self.assertEqual(helper.check_archive(archive), (helper.cargo_version(), "source"))
            self.assertIn(archive.name.encode("ascii"), helper.checksum_lines(Path(temp)))

    def test_source_rejects_missing_unsafe_and_wrong_metadata_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "{}-{}-source.tar.gz".format(helper.NAME, helper.cargo_version())
            for extra in ("../escape", "execute_service.py", "src/excess.txt"):
                with self.subTest(extra=extra):
                    with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
                        for name in sorted(helper.SOURCE_REQUIRED | {extra}):
                            entry = tarfile.TarInfo(name)
                            entry.size = 1
                            entry.mode = 0o755 if name.startswith("scripts/") else 0o644
                            tar.addfile(entry, io.BytesIO(b"x"))
                    with self.assertRaisesRegex(ValueError, "unexpected source archive entry"):
                        helper.check_archive(archive)
            with tarfile.open(archive, "w:gz") as tar:
                entry = tarfile.TarInfo("Cargo.toml")
                entry.size = 1
                tar.addfile(entry, io.BytesIO(b"x"))
            with self.assertRaisesRegex(ValueError, "missing required files"):
                helper.check_archive(archive)
            with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
                for name in sorted(helper.SOURCE_REQUIRED):
                    entry = tarfile.TarInfo(name)
                    entry.size = 1
                    entry.mode = 0o644
                    tar.addfile(entry, io.BytesIO(b"x"))
            with self.assertRaisesRegex(ValueError, "unexpected source archive metadata"):
                helper.check_archive(archive)

    def test_source_symlinks_are_not_packaged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "scripts").mkdir()
            for name in helper.SOURCE_REQUIRED - {"src/main.rs"}:
                shutil.copyfile(helper.ROOT / name, root / name)
            (root / "src/main.rs").symlink_to(helper.ROOT / "src/main.rs")
            with patch.object(helper, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "source must be a regular file"):
                    helper.source_archive_bytes()

    def test_release_gate_accepts_witness_tag_alongside_npm_tag(self):
        with patch.object(helper.subprocess, "check_output", side_effect=[
            b"", "v0.4.0\nwitness-v{}\n".format(helper.cargo_version()),
        ]):
            helper.require_release_source()
        with patch.object(helper.subprocess, "check_output", side_effect=[b"", "v0.4.0\n"]):
            with self.assertRaisesRegex(ValueError, "HEAD must have tag witness-v"):
                helper.require_release_source()
        with patch.object(helper.subprocess, "check_output", return_value=b" M package.json\n"):
            with self.assertRaisesRegex(ValueError, "clean checkout"):
                helper.require_release_source()


if __name__ == "__main__":
    unittest.main()
