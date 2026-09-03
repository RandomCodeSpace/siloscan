#!/usr/bin/env python3
"""Verify one native release archive the way a user would consume it.

The archive is checked against its sibling checksum file, extracted into a
fresh directory outside ``target/``, asserted to hold exactly the seven members
of the release contract, and then *executed from that directory*: ``--version``
and ``--help`` on all three binaries plus one real scan of a credential
generated at runtime. Nothing here reads a binary that is still sitting in
``target/``.

Only the standard library is used so the same file runs on the Linux, macOS and
Windows runners without an install step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import platform
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

# The release archive contract: exactly these members, `.exe` on Windows for
# the three binaries.
BINARY_MEMBERS = ("siloscan", "ss", "siloscan-tui")
DATA_MEMBERS = ("README.md", "LICENSE", "NOTICE", "THIRD-PARTY-LICENSES")


class GateError(Exception):
    """A release-archive contract violation."""


def expected_members(exe_suffix: str) -> set[str]:
    """The exactly-seven member names an archive for this platform must hold."""
    return {name + exe_suffix for name in BINARY_MEMBERS} | set(DATA_MEMBERS)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_checksum_file(text: str, archive_name: str) -> str:
    """Return the recorded digest for ``archive_name`` from a SHA256SUMS body."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            raise GateError(f"malformed checksum line: {line!r}")
        digest, name = parts[0], parts[1].lstrip("*").replace("\\", "/")
        if name.rsplit("/", 1)[-1] == archive_name:
            if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest.lower()):
                raise GateError(f"malformed digest for {archive_name}: {digest!r}")
            return digest.lower()
    raise GateError(f"{archive_name} has no entry in its checksum file")


def check_members(names: list[str], exe_suffix: str) -> None:
    """Fail unless the archive holds exactly the seven contract members."""
    seen = {name.replace("\\", "/").rstrip("/") for name in names}
    nested = sorted(name for name in seen if "/" in name)
    if nested:
        raise GateError(f"archive holds nested paths: {nested}")
    wanted = expected_members(exe_suffix)
    if seen != wanted:
        missing = sorted(wanted - seen)
        extra = sorted(seen - wanted)
        raise GateError(f"archive members wrong: missing={missing} unexpected={extra}")


def findings_count(document: str) -> int:
    """Number of findings in a `--format json` document; raises if unparseable."""
    try:
        parsed = json.loads(document)
    except json.JSONDecodeError as error:
        raise GateError(f"--format json output is not parseable: {error}") from error
    if not isinstance(parsed, dict) or "findings" not in parsed:
        raise GateError("--format json output has no findings array")
    findings = parsed["findings"]
    if not isinstance(findings, list):
        raise GateError("findings is not an array")
    return len(findings)


def check_member_path(name: str) -> str:
    """Reject any member name that could write outside the extraction directory.

    The contract is seven flat regular files, so anything absolute, nested, or
    containing `..` is refused before a single byte is written.
    """
    normalized = name.replace("\\", "/")
    if not normalized or normalized in (".", ".."):
        raise GateError(f"archive holds an unusable member name: {name!r}")
    if normalized.startswith("/") or ntpath.splitdrive(normalized)[0]:
        raise GateError(f"archive holds an absolute member path: {name!r}")
    parts = normalized.split("/")
    if ".." in parts:
        raise GateError(f"archive holds a traversing member path: {name!r}")
    if len(parts) > 1:
        raise GateError(f"archive holds a nested member path: {name!r}")
    return normalized


def extract(archive: Path, destination: Path) -> list[str]:
    """Extract into a fresh destination and return the member names."""
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            names = []
            for entry in entries:
                names.append(check_member_path(entry.filename))
                if entry.is_dir():
                    raise GateError(f"archive member {entry.filename!r} is a directory")
                if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise GateError(f"archive member {entry.filename!r} is a symbolic link")
            bundle.extractall(destination)
        return names
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        names = []
        for member in members:
            names.append(check_member_path(member.name))
            if not member.isfile():
                raise GateError(f"archive member {member.name!r} is not a regular file")
        try:
            bundle.extractall(destination, members=members, filter="data")
        except TypeError:
            # Python without the extraction filter. The checks above already
            # refused absolute paths, traversal, links, devices and directories.
            bundle.extractall(destination, members=members)
    return names


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+ " + " ".join(command), flush=True)
    return subprocess.run(command, capture_output=True, text=True, **kwargs)


def check_binary(path: Path) -> None:
    """`--version` and `--help` must both succeed and say something."""
    for flag in ("--version", "--help"):
        result = run([str(path), flag])
        if result.returncode != 0:
            raise GateError(
                f"{path.name} {flag} exited {result.returncode}: {result.stderr.strip()}"
            )
        if not result.stdout.strip():
            raise GateError(f"{path.name} {flag} printed nothing")
        print(result.stdout.splitlines()[0])


def check_scan(siloscan: Path, work_root: Path) -> int:
    """One real scan of a runtime-generated credential, asserted on JSON."""
    scan_root = work_root / "scan"
    if scan_root.exists():
        shutil.rmtree(scan_root)
    scan_root.mkdir(parents=True)
    # Generated here so no credential-shaped literal lives in the repository.
    (scan_root / "config.env").write_text(f"API_TOKEN={secrets.token_hex(20)}\n")
    result = run([str(siloscan), str(scan_root), "--format", "json"])
    print(f"exit status: {result.returncode}")
    if result.returncode not in (0, 1):
        raise GateError(
            f"scan exited {result.returncode}, expected 0 or 1: {result.stderr.strip()}"
        )
    count = findings_count(result.stdout)
    if count == 0:
        raise GateError("the extracted scanner found nothing in the generated credential")
    print(f"findings: {count}")
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument(
        "--extract-root",
        required=True,
        type=Path,
        help="fresh directory to extract into; must not be inside target/",
    )
    parser.add_argument("--sha", required=True, help="full candidate commit SHA")
    parser.add_argument("--target", required=True)
    parser.add_argument("--record", type=Path, help="where to write the identity record")
    parser.add_argument(
        "--exe-suffix",
        default=".exe" if platform.system() == "Windows" else "",
    )
    args = parser.parse_args(argv)

    archive = args.archive.resolve()
    extract_root = args.extract_root.resolve()
    if "target" in extract_root.parts:
        raise GateError(f"refusing to extract inside a build directory: {extract_root}")

    recorded = parse_checksum_file(args.checksums.read_text(), archive.name)
    actual = sha256_file(archive)
    if recorded != actual:
        raise GateError(f"{archive.name} digest {actual} does not match recorded {recorded}")
    print(f"{archive.name} sha256 {actual} verified against {args.checksums.name}")

    names = extract(archive, extract_root)
    check_members(names, args.exe_suffix)
    print(f"archive members: {sorted(names)}")

    binaries = {name: extract_root / (name + args.exe_suffix) for name in BINARY_MEMBERS}
    for path in binaries.values():
        if os.name != "nt":
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        check_binary(path)

    with tempfile.TemporaryDirectory(prefix="siloscan-archive-gate-") as work:
        count = check_scan(binaries["siloscan"], Path(work))

    if args.record:
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(
            json.dumps(
                {
                    "kind": "archive",
                    "sha": args.sha,
                    "target": args.target,
                    "name": archive.name,
                    "sha256": actual,
                    "members": sorted(names),
                    "findings": count,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GateError as error:
        print(f"archive gate failed: {error}", file=sys.stderr)
        sys.exit(1)
