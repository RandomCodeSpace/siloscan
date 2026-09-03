#!/usr/bin/env python3
"""Publish one crate to crates.io, or prove the published one is already ours.

The release runs this once per crate in dependency order, and every run has to
be safe to repeat. If the exact version is already on the registry the script
does not publish: it downloads the published `.crate`, matches its registry
checksum and its `.cargo_vcs_info.json` commit against the locally packaged
bytes and the candidate SHA, and continues. Otherwise it publishes, then polls
the sparse index with a bounded timeout until a clean consumer -- an empty
cache fetching over the same index and download endpoints cargo uses -- can
retrieve that exact version, and verifies it the same way.

Only the standard library is used, and only the ``main`` path touches the
network.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

INDEX_BASE = "https://index.crates.io"
DOWNLOAD_BASE = "https://crates.io/api/v1/crates"
USER_AGENT = "siloscan-release-gate (https://github.com/RandomCodeSpace/siloscan)"


class PublishError(Exception):
    """A registry publication or verification failure."""


def index_path(name: str) -> str:
    """Sparse-index path for a crate name, using cargo's own bucketing rules."""
    name = name.lower()
    if not name:
        raise PublishError("empty crate name")
    if len(name) == 1:
        return f"1/{name}"
    if len(name) == 2:
        return f"2/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def find_version(index_body: str, version: str) -> dict | None:
    """The index entry for an exact version, or None if the registry lacks it."""
    for line in index_body.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        if entry.get("vers") == version:
            return entry
    return None


def vcs_sha_from_crate(data: bytes, name: str, version: str) -> str:
    """The commit SHA recorded in a `.crate` file's `.cargo_vcs_info.json`."""
    member = f"{name}-{version}/.cargo_vcs_info.json"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as bundle:
        try:
            extracted = bundle.extractfile(member)
        except KeyError:
            extracted = None
        if extracted is None:
            raise PublishError(f"{name}-{version}.crate has no {member}")
        info = json.loads(extracted.read().decode("utf-8"))
    sha = info.get("git", {}).get("sha1")
    if not sha:
        raise PublishError(f"{member} records no git.sha1")
    return sha


def compare_published(
    *,
    entry: dict,
    published: bytes,
    published_vcs_sha: str,
    local_digest: str,
    local_vcs_sha: str,
    expected_sha: str,
) -> list[str]:
    """Every way the published crate can fail to be the candidate's bytes."""
    problems = []
    if entry.get("yanked"):
        problems.append("the published version is yanked; it cannot be republished")
    published_digest = hashlib.sha256(published).hexdigest()
    if published_digest != entry.get("cksum"):
        problems.append(
            f"downloaded bytes hash {published_digest}, index says {entry.get('cksum')}"
        )
    if published_digest != local_digest:
        problems.append(
            f"published checksum {published_digest} does not match local package {local_digest}"
        )
    if published_vcs_sha != expected_sha:
        problems.append(
            f"published .cargo_vcs_info.json names {published_vcs_sha}, candidate is {expected_sha}"
        )
    if local_vcs_sha != expected_sha:
        problems.append(
            f"local .cargo_vcs_info.json names {local_vcs_sha}, candidate is {expected_sha}"
        )
    return problems


def _get(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_index(name: str, index_base: str) -> str:
    url = f"{index_base}/{index_path(name)}"
    try:
        return _get(url).decode("utf-8")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return ""  # The crate has never been published.
        raise


def download_crate(name: str, version: str, download_base: str) -> bytes:
    return _get(f"{download_base}/{name}/{version}/download")


def poll_for_version(
    name: str, version: str, index_base: str, timeout: int, interval: int
) -> dict:
    """Wait, bounded, until the exact version is visible to a clean consumer."""
    deadline = time.monotonic() + timeout
    attempt = 0
    while True:
        attempt += 1
        entry = find_version(fetch_index(name, index_base), version)
        if entry is not None:
            print(f"{name} {version} visible in the index after {attempt} attempt(s)")
            return entry
        if time.monotonic() >= deadline:
            raise PublishError(
                f"{name} {version} was not visible in the index within {timeout}s"
            )
        print(f"{name} {version} not in the index yet; retrying in {interval}s")
        time.sleep(interval)


def verify(
    *, name, version, entry, local_digest, local_vcs_sha, expected_sha, download_base
) -> str:
    published = download_crate(name, version, download_base)
    published_vcs_sha = vcs_sha_from_crate(published, name, version)
    problems = compare_published(
        entry=entry,
        published=published,
        published_vcs_sha=published_vcs_sha,
        local_digest=local_digest,
        local_vcs_sha=local_vcs_sha,
        expected_sha=expected_sha,
    )
    if problems:
        raise PublishError(f"{name} {version} verification failed: " + "; ".join(problems))
    print(f"{name} {version} verified: checksum {local_digest}, commit {published_vcs_sha}")
    return published_vcs_sha


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--crate-file",
        required=True,
        type=Path,
        help="the locally packaged .crate produced by cargo package",
    )
    parser.add_argument("--expected-sha", required=True, help="full candidate commit SHA")
    parser.add_argument("--record", type=Path, help="where to write the identity record")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--poll-interval", type=int, default=15)
    parser.add_argument("--index-base", default=INDEX_BASE)
    parser.add_argument("--download-base", default=DOWNLOAD_BASE)
    args = parser.parse_args(argv)

    name, version = args.package, args.version
    local_bytes = args.crate_file.read_bytes()
    local_digest = hashlib.sha256(local_bytes).hexdigest()
    local_vcs_sha = vcs_sha_from_crate(local_bytes, name, version)
    if local_vcs_sha != args.expected_sha:
        raise PublishError(
            f"local package names commit {local_vcs_sha}, candidate is {args.expected_sha}"
        )
    print(f"local {args.crate_file.name}: sha256 {local_digest}, commit {local_vcs_sha}")

    entry = find_version(fetch_index(name, args.index_base), version)
    if entry is not None:
        print(f"{name} {version} already on the registry; verifying instead of publishing")
        already_published = True
    else:
        print(f"publishing {name} {version}")
        subprocess.run(["cargo", "publish", "--locked", "-p", name], check=True)
        entry = poll_for_version(
            name, version, args.index_base, args.timeout, args.poll_interval
        )
        already_published = False

    published_vcs_sha = verify(
        name=name,
        version=version,
        entry=entry,
        local_digest=local_digest,
        local_vcs_sha=local_vcs_sha,
        expected_sha=args.expected_sha,
        download_base=args.download_base,
    )

    if args.record:
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(
            json.dumps(
                {
                    "kind": "publish",
                    "sha": args.expected_sha,
                    "name": name,
                    "version": version,
                    "sha256": local_digest,
                    "vcs_sha": published_vcs_sha,
                    "already_published": already_published,
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
    except (PublishError, subprocess.CalledProcessError) as error:
        print(f"registry publish failed: {error}", file=sys.stderr)
        sys.exit(1)
