#!/usr/bin/env python3
"""Deterministic tests for the release-gate helpers.

Run with `python3 -m unittest discover -s scripts -p 'test_*.py'`. Everything
here uses a fixed synthetic commit SHA and fake digests; nothing contacts
crates.io, GitHub, or the network at all.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import archive_gate  # noqa: E402
import candidate_manifest  # noqa: E402
import registry_publish  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "89abcdef0123456789abcdef0123456789abcdef"
VERSION = "2.0.0"


def crate_bytes(name: str, version: str, sha: str) -> bytes:
    """A minimal `.crate` tarball carrying a `.cargo_vcs_info.json`."""
    buffer = io.BytesIO()
    payload = json.dumps({"git": {"sha1": sha}, "path_in_vcs": ""}).encode()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        info = tarfile.TarInfo(f"{name}-{version}/.cargo_vcs_info.json")
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def archive_record(target: str, sha: str = SHA) -> dict:
    return {
        "kind": "archive",
        "sha": sha,
        "target": target,
        "name": f"siloscan-v{VERSION}-{target}.tar.gz",
        "sha256": "a" * 64,
    }


def package_record(name: str, sha: str = SHA, version: str = VERSION) -> dict:
    return {
        "kind": "package",
        "sha": sha,
        "name": name,
        "version": version,
        "file": f"{name}-{version}.crate",
        "sha256": "b" * 64,
        "vcs_sha": sha,
    }


def complete_records() -> list[dict]:
    return [archive_record(t) for t in candidate_manifest.REQUIRED_TARGETS] + [
        package_record(p) for p in candidate_manifest.REQUIRED_PACKAGES
    ]


class ArchiveGateTest(unittest.TestCase):
    def test_checksum_line_is_found_for_the_archive(self):
        body = (
            "ffff  siloscan-v2.0.0-other.tar.gz\n"
            f"{'c' * 64}  siloscan-v2.0.0-x86_64-unknown-linux-musl.tar.gz\n"
        )
        self.assertEqual(
            archive_gate.parse_checksum_file(
                body, "siloscan-v2.0.0-x86_64-unknown-linux-musl.tar.gz"
            ),
            "c" * 64,
        )

    def test_binary_mode_star_and_paths_are_tolerated(self):
        body = f"{'d' * 64} *./release/siloscan-v2.0.0-win.zip\n"
        self.assertEqual(
            archive_gate.parse_checksum_file(body, "siloscan-v2.0.0-win.zip"), "d" * 64
        )

    def test_missing_entry_fails(self):
        with self.assertRaises(archive_gate.GateError):
            archive_gate.parse_checksum_file(f"{'e' * 64}  other.tar.gz\n", "wanted.tar.gz")

    def test_seven_unix_members_pass(self):
        archive_gate.check_members(sorted(archive_gate.expected_members("")), "")

    def test_seven_windows_members_pass(self):
        archive_gate.check_members(sorted(archive_gate.expected_members(".exe")), ".exe")

    def test_missing_member_fails(self):
        members = sorted(archive_gate.expected_members("") - {"NOTICE"})
        with self.assertRaises(archive_gate.GateError):
            archive_gate.check_members(members, "")

    def test_extra_member_fails(self):
        members = sorted(archive_gate.expected_members("")) + ["CHANGELOG.md"]
        with self.assertRaises(archive_gate.GateError):
            archive_gate.check_members(members, "")

    def test_unix_names_fail_the_windows_contract(self):
        with self.assertRaises(archive_gate.GateError):
            archive_gate.check_members(sorted(archive_gate.expected_members("")), ".exe")

    def test_nested_paths_fail(self):
        members = [f"siloscan/{name}" for name in archive_gate.expected_members("")]
        with self.assertRaises(archive_gate.GateError):
            archive_gate.check_members(members, "")

    def test_findings_are_counted(self):
        document = json.dumps({"findings": [{"rule_id": "r"}, {"rule_id": "s"}]})
        self.assertEqual(archive_gate.findings_count(document), 2)

    def test_unparseable_output_fails(self):
        with self.assertRaises(archive_gate.GateError):
            archive_gate.findings_count("not json")

    def test_document_without_findings_fails(self):
        with self.assertRaises(archive_gate.GateError):
            archive_gate.findings_count(json.dumps({"metrics": {}}))


class RegistryPublishTest(unittest.TestCase):
    def test_index_paths_follow_cargo_bucketing(self):
        self.assertEqual(registry_publish.index_path("a"), "1/a")
        self.assertEqual(registry_publish.index_path("ab"), "2/ab")
        self.assertEqual(registry_publish.index_path("abc"), "3/a/abc")
        self.assertEqual(registry_publish.index_path("siloscan"), "si/lo/siloscan")
        self.assertEqual(
            registry_publish.index_path("siloscan-core"), "si/lo/siloscan-core"
        )

    def test_exact_version_is_selected(self):
        body = "\n".join(
            json.dumps({"name": "siloscan", "vers": v, "cksum": "f" * 64, "yanked": False})
            for v in ("1.5.1", "2.0.0", "2.0.0-rc.1")
        )
        self.assertEqual(registry_publish.find_version(body, "2.0.0")["vers"], "2.0.0")
        self.assertIsNone(registry_publish.find_version(body, "2.0.1"))

    def test_absent_crate_yields_no_version(self):
        self.assertIsNone(registry_publish.find_version("", "2.0.0"))

    def test_vcs_sha_is_read_from_the_crate(self):
        data = crate_bytes("siloscan-core", VERSION, SHA)
        self.assertEqual(
            registry_publish.vcs_sha_from_crate(data, "siloscan-core", VERSION), SHA
        )

    def test_crate_without_vcs_info_fails(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
            info = tarfile.TarInfo(f"siloscan-{VERSION}/Cargo.toml")
            info.size = 0
            bundle.addfile(info, io.BytesIO(b""))
        with self.assertRaises(registry_publish.PublishError):
            registry_publish.vcs_sha_from_crate(buffer.getvalue(), "siloscan", VERSION)

    def _compare(self, **overrides):
        data = crate_bytes("siloscan", VERSION, SHA)
        digest = hashlib.sha256(data).hexdigest()
        arguments = {
            "entry": {"vers": VERSION, "cksum": digest, "yanked": False},
            "published": data,
            "published_vcs_sha": SHA,
            "local_digest": digest,
            "local_vcs_sha": SHA,
            "expected_sha": SHA,
        }
        arguments.update(overrides)
        return registry_publish.compare_published(**arguments)

    def test_matching_publication_has_no_problems(self):
        self.assertEqual(self._compare(), [])

    def test_yanked_publication_is_a_problem(self):
        data = crate_bytes("siloscan", VERSION, SHA)
        entry = {
            "vers": VERSION,
            "cksum": hashlib.sha256(data).hexdigest(),
            "yanked": True,
        }
        self.assertTrue(any("yanked" in p for p in self._compare(entry=entry)))

    def test_checksum_mismatch_is_a_problem(self):
        self.assertTrue(any("does not match local" in p for p in self._compare(local_digest="0" * 64)))

    def test_published_from_another_commit_is_a_problem(self):
        problems = self._compare(published_vcs_sha=OTHER_SHA)
        self.assertTrue(any("candidate is" in p for p in problems))

    def test_local_package_from_another_commit_is_a_problem(self):
        problems = self._compare(local_vcs_sha=OTHER_SHA)
        self.assertTrue(any("local .cargo_vcs_info.json" in p for p in problems))


class CandidateManifestTest(unittest.TestCase):
    RUN = {"repository": "RandomCodeSpace/siloscan", "id": "1234567890", "attempt": "1"}

    def build(self, records, sha=SHA, version=VERSION):
        return candidate_manifest.build_manifest(
            records, sha=sha, version=version, run=self.RUN
        )

    def test_complete_candidate_builds_a_manifest(self):
        manifest = self.build(complete_records())
        self.assertEqual(manifest["candidate_sha"], SHA)
        self.assertEqual(manifest["workspace_version"], VERSION)
        self.assertEqual(manifest["workflow_run"], self.RUN)
        self.assertEqual(len(manifest["archives"]), 3)
        self.assertEqual(len(manifest["packages"]), 3)
        self.assertEqual(
            {a["target"] for a in manifest["archives"]},
            set(candidate_manifest.REQUIRED_TARGETS),
        )

    def test_one_record_from_another_commit_breaks_the_chain(self):
        records = complete_records()
        records[1] = archive_record(records[1]["target"], sha=OTHER_SHA)
        with self.assertRaises(candidate_manifest.ManifestError):
            self.build(records)

    def test_missing_archive_target_fails(self):
        records = [r for r in complete_records() if r.get("target") != "aarch64-apple-darwin"]
        with self.assertRaises(candidate_manifest.ManifestError):
            self.build(records)

    def test_missing_package_fails(self):
        records = [r for r in complete_records() if r.get("name") != "siloscan-tui"]
        with self.assertRaises(candidate_manifest.ManifestError):
            self.build(records)

    def test_package_version_must_match_the_workspace(self):
        records = complete_records()
        records[-1] = package_record("siloscan", version="1.5.1")
        with self.assertRaises(candidate_manifest.ManifestError):
            self.build(records)

    def test_short_sha_is_rejected(self):
        with self.assertRaises(candidate_manifest.ManifestError):
            self.build(complete_records(), sha=SHA[:7])

    def test_package_records_are_written_from_crate_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crates, records = root / "package", root / "records"
            crates.mkdir()
            for name in candidate_manifest.REQUIRED_PACKAGES:
                (crates / f"{name}-{VERSION}.crate").write_bytes(
                    crate_bytes(name, VERSION, SHA)
                )
            candidate_manifest.package_records(crates, SHA, records)
            loaded = candidate_manifest.load_records(records)
            self.assertEqual(
                {r["name"] for r in loaded}, set(candidate_manifest.REQUIRED_PACKAGES)
            )
            self.assertEqual({r["vcs_sha"] for r in loaded}, {SHA})

    def test_package_from_another_commit_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crates, records = root / "package", root / "records"
            crates.mkdir()
            (crates / f"siloscan-{VERSION}.crate").write_bytes(
                crate_bytes("siloscan", VERSION, OTHER_SHA)
            )
            with self.assertRaises(candidate_manifest.ManifestError):
                candidate_manifest.package_records(crates, SHA, records)

    def test_downloaded_assets_must_match_the_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            payload = b"archive bytes"
            digest = hashlib.sha256(payload).hexdigest()
            manifest = {
                "archives": [{"target": "t", "name": "siloscan.tar.gz", "sha256": digest}]
            }
            (assets / "siloscan.tar.gz").write_bytes(payload)
            self.assertEqual(candidate_manifest.verify_assets(manifest, assets), [])

            manifest["archives"][0]["sha256"] = "0" * 64
            self.assertTrue(candidate_manifest.verify_assets(manifest, assets))

    def test_absent_asset_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = {"archives": [{"target": "t", "name": "gone.tar.gz", "sha256": "0" * 64}]}
            problems = candidate_manifest.verify_assets(manifest, Path(directory))
            self.assertTrue(any("was not downloaded" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
