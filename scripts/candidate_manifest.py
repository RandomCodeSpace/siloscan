#!/usr/bin/env python3
"""Bind every qualification job to one commit and emit the candidate manifest.

`packages` turns the locally packaged `.crate` files into identity records.
`build` reads every record produced by the archive and package jobs, refuses to
continue unless all of them name the same full commit SHA, and writes the
candidate manifest. The manifest is a workflow artifact: it is never committed,
and it never tries to record its own future source commit.

Only the standard library is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from registry_publish import vcs_sha_from_crate

# The three natively built and executed archives, and the three published
# crates. A manifest missing any of them is not a complete candidate.
REQUIRED_TARGETS = (
    "x86_64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
)
REQUIRED_PACKAGES = ("siloscan-core", "siloscan-tui", "siloscan")


class ManifestError(Exception):
    """A broken identity chain or an incomplete candidate."""


def is_full_sha(value: str) -> bool:
    return len(value) == 40 and all(c in "0123456789abcdef" for c in value.lower())


def build_manifest(records: list[dict], *, sha: str, version: str, run: dict) -> dict:
    """Collect records into a manifest, failing on any SHA that disagrees."""
    if not is_full_sha(sha):
        raise ManifestError(f"candidate SHA is not a full 40-character SHA: {sha!r}")

    mismatched = sorted(
        {r.get("sha", "<missing>") for r in records if r.get("sha") != sha}
    )
    if mismatched:
        raise ManifestError(
            f"records name other commits than the candidate {sha}: {mismatched}"
        )

    archives = sorted(
        (r for r in records if r.get("kind") == "archive"), key=lambda r: r["target"]
    )
    packages = sorted(
        (r for r in records if r.get("kind") == "package"), key=lambda r: r["name"]
    )

    missing_targets = sorted(set(REQUIRED_TARGETS) - {r["target"] for r in archives})
    if missing_targets:
        raise ManifestError(f"no archive record for: {missing_targets}")
    missing_packages = sorted(set(REQUIRED_PACKAGES) - {r["name"] for r in packages})
    if missing_packages:
        raise ManifestError(f"no packaged-crate record for: {missing_packages}")

    for record in packages:
        if record.get("version") != version:
            raise ManifestError(
                f"{record['name']} packaged as {record.get('version')}, "
                f"workspace version is {version}"
            )

    return {
        "candidate_sha": sha,
        "workspace_version": version,
        "workflow_run": run,
        "archives": [
            {"target": r["target"], "name": r["name"], "sha256": r["sha256"]}
            for r in archives
        ],
        "packages": [
            {
                "name": r["name"],
                "version": r["version"],
                "file": r["file"],
                "sha256": r["sha256"],
                "vcs_sha": r["vcs_sha"],
            }
            for r in packages
        ],
    }


def load_records(directory: Path) -> list[dict]:
    records = []
    for path in sorted(directory.rglob("record-*.json")):
        records.append(json.loads(path.read_text()))
    if not records:
        raise ManifestError(f"no record-*.json under {directory}")
    return records


def package_records(crate_dir: Path, sha: str, out_dir: Path) -> list[Path]:
    """One identity record per packaged `.crate`, digest and VCS commit included."""
    written = []
    crates = sorted(crate_dir.glob("*.crate"))
    if not crates:
        raise ManifestError(f"no .crate files under {crate_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    for crate in crates:
        data = crate.read_bytes()
        name, version = split_crate_filename(crate.stem)
        vcs_sha = vcs_sha_from_crate(data, name, version)
        if vcs_sha != sha:
            raise ManifestError(
                f"{crate.name} names commit {vcs_sha}, candidate is {sha}"
            )
        record = {
            "kind": "package",
            "sha": sha,
            "name": name,
            "version": version,
            "file": crate.name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "vcs_sha": vcs_sha,
        }
        destination = out_dir / f"record-package-{name}.json"
        destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(f"{crate.name}: sha256 {record['sha256']}, commit {vcs_sha}")
        written.append(destination)
    return written


def split_crate_filename(stem: str) -> tuple[str, str]:
    """Split `siloscan-2.0.0-rc.1` into its crate name and version.

    A crate name may contain hyphens and so may a pre-release version, so the
    split is at the first hyphen that starts the version number.
    """
    match = re.fullmatch(r"(?P<name>.+?)-(?P<version>\d[^-]*(?:-.*)?)", stem)
    if not match:
        raise ManifestError(f"cannot read a crate name and version from {stem!r}")
    return match.group("name"), match.group("version")


def compare_manifests(candidate: dict, release: dict) -> list[str]:
    """Every way a tagged build can fail to be the qualified candidate.

    Archive digests are deliberately not compared: a `.tar.gz` records the
    mtimes of freshly built binaries, so two runs of the same commit produce
    different archive bytes. `cargo package` output is reproducible for a
    commit, so the packaged crates are compared exactly.
    """
    problems = []
    if candidate["candidate_sha"] != release["candidate_sha"]:
        problems.append(
            f"candidate run qualified {candidate['candidate_sha']}, "
            f"this run built {release['candidate_sha']}"
        )
    if candidate["workspace_version"] != release["workspace_version"]:
        problems.append(
            f"candidate run qualified version {candidate['workspace_version']}, "
            f"this run built {release['workspace_version']}"
        )
    for field, key in (("archives", "name"), ("packages", "sha256")):
        left = {(entry.get("target") or entry.get("name"), entry[key]) for entry in candidate[field]}
        right = {(entry.get("target") or entry.get("name"), entry[key]) for entry in release[field]}
        if left != right:
            problems.append(
                f"{field} differ from the qualified candidate: "
                f"only in candidate={sorted(left - right)} only here={sorted(right - left)}"
            )
    return problems


def check_records(records: list[dict], sha: str) -> None:
    """Every artifact record in a run must name the same commit."""
    if not is_full_sha(sha):
        raise ManifestError(f"expected SHA is not a full 40-character SHA: {sha!r}")
    mismatched = sorted({r.get("sha", "<missing>") for r in records if r.get("sha") != sha})
    if mismatched:
        raise ManifestError(f"artifact records name other commits than {sha}: {mismatched}")
    kinds = sorted({r.get("kind", "<missing>") for r in records})
    print(f"{len(records)} artifact record(s) of kinds {kinds} all name {sha}")


def verify_assets(manifest: dict, assets_dir: Path) -> list[str]:
    """Every archive in the manifest must be present here with the same digest."""
    problems = []
    for archive in manifest["archives"]:
        path = assets_dir / archive["name"]
        if not path.is_file():
            problems.append(f"{archive['name']} was not downloaded")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != archive["sha256"]:
            problems.append(
                f"{archive['name']} hashes {digest}, manifest says {archive['sha256']}"
            )
        else:
            print(f"{archive['name']} matches the candidate manifest ({digest})")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    packages = sub.add_parser("packages", help="record the packaged .crate files")
    packages.add_argument("--crate-dir", required=True, type=Path)
    packages.add_argument("--sha", required=True)
    packages.add_argument("--out-dir", required=True, type=Path)

    build = sub.add_parser("build", help="aggregate records into the candidate manifest")
    build.add_argument("--records-dir", required=True, type=Path)
    build.add_argument("--sha", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--run-id", required=True)
    build.add_argument("--run-attempt", required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--output", required=True, type=Path)

    verify = sub.add_parser("verify-assets", help="match downloaded assets to the manifest")
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--assets-dir", required=True, type=Path)

    check = sub.add_parser("check-records", help="assert every record names one commit")
    check.add_argument("--records-dir", required=True, type=Path)
    check.add_argument("--sha", required=True)

    compare = sub.add_parser("compare", help="match this run against a qualified candidate")
    compare.add_argument("--candidate", required=True, type=Path)
    compare.add_argument("--release", required=True, type=Path)

    args = parser.parse_args(argv)

    if args.command == "check-records":
        check_records(load_records(args.records_dir), args.sha)
        return 0

    if args.command == "compare":
        problems = compare_manifests(
            json.loads(args.candidate.read_text()), json.loads(args.release.read_text())
        )
        if problems:
            raise ManifestError("; ".join(problems))
        print("this run matches the qualified candidate manifest")
        return 0

    if args.command == "packages":
        package_records(args.crate_dir, args.sha, args.out_dir)
        return 0

    if args.command == "verify-assets":
        problems = verify_assets(json.loads(args.manifest.read_text()), args.assets_dir)
        if problems:
            raise ManifestError("; ".join(problems))
        return 0

    manifest = build_manifest(
        load_records(args.records_dir),
        sha=args.sha,
        version=args.version,
        run={
            "repository": args.repository,
            "id": args.run_id,
            "attempt": args.run_attempt,
        },
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ManifestError as error:
        print(f"candidate manifest failed: {error}", file=sys.stderr)
        sys.exit(1)
