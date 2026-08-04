#!/usr/bin/env python3
"""Generate THIRD-PARTY-LICENSES for the crates linked into the shipped binaries.

The file is derived from `cargo metadata` for one concrete target triple. Only
normal (non-dev, non-build) dependencies reachable from the requested workspace
packages are included, because those are the crates whose compiled code ends up
inside the redistributed binaries.

License text is taken from the crate's own registry source tree. When a crate
ships no license file, the declared SPDX expression from its manifest is
recorded instead and the crate is listed in a dedicated section so the gap is
visible in the shipped artifact. A crate that yields neither a license file nor
a declared license is a hard error: the caller is expected to fail the build.

Output is deterministic - identical inputs produce a byte-identical file. No
third-party Python packages are used.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

RULE = "=" * 78
THIN_RULE = "-" * 78

# Files that may carry license terms, matched case-insensitively against the
# file stem. Ordered by preference so the primary license lands first.
LICENSE_STEMS = ("license", "licence", "copying", "unlicense", "notice", "copyright")

# Extensions that never contain readable license terms.
SKIP_SUFFIXES = (".rs", ".toml", ".json", ".yaml", ".yml", ".lock", ".py", ".sh")

MAX_LICENSE_BYTES = 512 * 1024


def run_cargo_metadata(manifest_path: Path, target: str) -> dict:
    cmd = [
        os.environ.get("CARGO", "cargo"),
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--manifest-path",
        str(manifest_path),
        "--filter-platform",
        target,
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(f"cargo metadata failed with exit code {proc.returncode}")
    return json.loads(proc.stdout.decode("utf-8"))


def linked_packages(metadata: dict, roots: list[str]) -> list[dict]:
    """Walk normal dependency edges from the root packages.

    Returns the external (registry or git sourced) packages only. Workspace
    members are excluded: they are covered by the project's own LICENSE.
    """
    packages = {pkg["id"]: pkg for pkg in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    workspace = set(metadata["workspace_members"])

    root_ids = []
    for pkg_id in workspace:
        if packages[pkg_id]["name"] in roots:
            root_ids.append(pkg_id)
    missing = set(roots) - {packages[i]["name"] for i in root_ids}
    if missing:
        raise SystemExit(f"not a workspace member: {', '.join(sorted(missing))}")

    seen: set[str] = set()
    stack = list(root_ids)
    while stack:
        pkg_id = stack.pop()
        if pkg_id in seen:
            continue
        seen.add(pkg_id)
        for dep in nodes[pkg_id]["deps"]:
            kinds = {entry.get("kind") for entry in dep.get("dep_kinds", [])}
            if None in kinds:
                stack.append(dep["pkg"])

    external = [packages[i] for i in seen if i not in workspace]
    external.sort(key=lambda pkg: (pkg["name"], pkg["version"]))
    return external


def candidate_files(root: Path) -> list[Path]:
    found: list[Path] = []
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name)
    except OSError:
        return found
    for entry in entries:
        if entry.is_dir():
            if entry.name.lower() in ("licenses", "license", "licences"):
                found.extend(sorted(entry.iterdir(), key=lambda p: p.name))
            continue
        found.append(entry)
    return found


def collect_license_texts(pkg: dict) -> list[tuple[str, str]]:
    """Return (relative file name, text) pairs for one package, deterministic."""
    root = Path(pkg["manifest_path"]).parent
    texts: list[tuple[str, str]] = []
    seen_names: set[str] = set()

    declared = pkg.get("license_file")
    ordered: list[Path] = []
    if declared:
        explicit = root / declared
        if explicit.is_file():
            ordered.append(explicit)

    for path in candidate_files(root):
        if not path.is_file():
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        stem = path.name.lower()
        if not any(stem.startswith(prefix) for prefix in LICENSE_STEMS):
            continue
        ordered.append(path)

    for path in ordered:
        name = str(path.relative_to(root)).replace("\\", "/")
        if name in seen_names:
            continue
        try:
            if path.stat().st_size > MAX_LICENSE_BYTES:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        text = text.replace("\r\n", "\n").strip("\n")
        if not text.strip():
            continue
        seen_names.add(name)
        texts.append((name, text))

    return texts


def render(target: str, roots: list[str], entries: list[dict]) -> str:
    without_text = [e for e in entries if not e["texts"]]

    out: list[str] = []
    out.append(RULE)
    out.append("THIRD-PARTY LICENSES")
    out.append(RULE)
    out.append("")
    out.append(
        "The binaries in this archive statically link the crates listed below."
    )
    out.append(
        "Their license terms are reproduced here as required for redistribution."
    )
    out.append("siloscan's own license is in the accompanying LICENSE file, and")
    out.append("non-code third-party material is credited in NOTICE.")
    out.append("")
    out.append(f"Target triple: {target}")
    out.append(f"Linked from:   {', '.join(sorted(roots))}")
    out.append(f"Crates:        {len(entries)}")
    out.append("")
    out.append(
        "This file is generated from cargo metadata at release time by"
    )
    out.append("scripts/third-party-licenses.py. Do not edit it by hand.")
    out.append("")

    out.append(RULE)
    out.append("INDEX")
    out.append(RULE)
    out.append("")
    for entry in entries:
        out.append(f"{entry['name']} {entry['version']} - {entry['license']}")
    out.append("")

    if without_text:
        out.append(RULE)
        out.append("CRATES THAT SHIP NO LICENSE FILE")
        out.append(RULE)
        out.append("")
        out.append(
            "The following crates declare a license in their manifest but do not"
        )
        out.append(
            "distribute a license file in their published source. Only the declared"
        )
        out.append(
            "SPDX expression is available; consult the upstream repository for the"
        )
        out.append("full text and copyright notice.")
        out.append("")
        for entry in without_text:
            out.append(f"{entry['name']} {entry['version']} - {entry['license']}")
            if entry["repository"]:
                out.append(f"    {entry['repository']}")
        out.append("")

    for entry in entries:
        out.append(RULE)
        out.append(f"{entry['name']} {entry['version']}")
        out.append(RULE)
        out.append("")
        out.append(f"License: {entry['license']}")
        if entry["repository"]:
            out.append(f"Repository: {entry['repository']}")
        out.append("")
        if entry["texts"]:
            for name, text in entry["texts"]:
                out.append(THIN_RULE)
                out.append(name)
                out.append(THIN_RULE)
                out.append("")
                out.append(text)
                out.append("")
        else:
            out.append(
                "No license file is distributed with this crate. The license"
            )
            out.append(
                f"declared in its manifest is: {entry['license']}"
            )
            out.append("")

    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="target triple to resolve for")
    parser.add_argument(
        "--package",
        action="append",
        required=True,
        dest="packages",
        help="workspace package whose binaries are shipped (repeatable)",
    )
    parser.add_argument("--output", required=True, help="file to write")
    parser.add_argument(
        "--manifest-path", default="Cargo.toml", help="workspace manifest"
    )
    args = parser.parse_args()

    metadata = run_cargo_metadata(Path(args.manifest_path).resolve(), args.target)
    packages = linked_packages(metadata, args.packages)

    entries: list[dict] = []
    unlicensed: list[str] = []
    for pkg in packages:
        texts = collect_license_texts(pkg)
        license_expr = pkg.get("license") or ""
        if not texts and not license_expr:
            unlicensed.append(f"{pkg['name']} {pkg['version']}")
            continue
        entries.append(
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "license": license_expr or "see bundled license file",
                "repository": pkg.get("repository") or "",
                "texts": texts,
            }
        )

    if unlicensed:
        sys.stderr.write(
            "no license text and no declared license for:\n  "
            + "\n  ".join(unlicensed)
            + "\n"
        )
        return 1

    if not entries:
        sys.stderr.write("resolved zero linked third-party crates; refusing\n")
        return 1

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render(args.target, args.packages, entries))

    without_text = sum(1 for e in entries if not e["texts"])
    sys.stderr.write(
        f"{output}: {len(entries)} crates for {args.target}"
        f" ({without_text} with declared license only)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
