#!/usr/bin/env python3
"""Generate the frozen scale tree the paired performance gate measures.

The recipe is fixed by ``research/oracle-v1.5.1/measurements``:

    source   = crates/siloscan-core/src/lang.rs at the pinned v1.5.1 commit
    layout   = src/00/sample_0000.rs .. src/40/sample_4095.rs,
               100 files per shard except 96 in shard 40
    config   = research/oracle-v1.5.1/scale/siloscan.toml at the tree root

That is 4,096 sample files plus the config, so 4,097 files and roughly 31 MiB.
There is no random content and therefore no seed: determinism comes from a
pinned Git blob, which is stronger than a seeded generator because the bytes
cannot drift with a Python release. Generating the tree recomputes the recipe's
``generated_manifest_sha256`` and fails if it does not match, so a run either
produces the exact frozen tree or produces nothing usable.

``--verify`` re-reads an existing tree and prints its file count, total bytes
and manifest digest, so two generations on two machines can be compared.

Only the standard library is used.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

# The frozen recipe. Every value here is recorded in
# research/oracle-v1.5.1/measurements/reference-linux-amd64.tsv.
SOURCE_COMMIT = "880d211a463e97eb3c188f957e5592d88f36dcf8"
SOURCE_PATH = "crates/siloscan-core/src/lang.rs"
SOURCE_SHA256 = "53f38d5a9044dd55e8e0dd38bf5b9cdd3b49fcb9d46bda12d714a6cfd788c8fc"
CONFIG_SHA256 = "76d6af711d6be9472e3ddb35bba9eeafac4c7e47fde91fdb07fef6f2849af23e"
MANIFEST_SHA256 = "32e15ce82ca06db7643fc3162454782f593bcf7c8822aa7f46b744930b3b5fb4"

SAMPLES = 4096
SHARD_SIZE = 100
CONFIG_NAME = "siloscan.toml"
FILE_COUNT = SAMPLES + 1

ORACLE_CONFIG = "research/oracle-v1.5.1/scale/siloscan.toml"
ORACLE_RULES = "research/oracle-v1.5.1/scale/ast.yaml"


class RecipeError(Exception):
    """The generated tree does not match the frozen scale recipe."""


def sample_paths(samples: int = SAMPLES, shard_size: int = SHARD_SIZE) -> list[str]:
    """The recipe's relative sample paths, in generation order."""
    return [f"src/{index // shard_size:02d}/sample_{index:04d}.rs" for index in range(samples)]


def manifest_digest(entries: list[tuple[str, bytes]]) -> str:
    """SHA-256 over the sorted relative paths and their contents.

    The manifest body is ``sha256sum`` output over ``./``-prefixed paths sorted
    by relative path, one line per file. That is the exact encoding the frozen
    ``generated_manifest_sha256`` was recorded from.
    """
    content_digests: dict[bytes, str] = {}
    manifest = hashlib.sha256()
    for path, content in sorted(entries):
        digest = content_digests.get(content)
        if digest is None:
            digest = hashlib.sha256(content).hexdigest()
            content_digests[content] = digest
        manifest.update(f"{digest}  ./{path}\n".encode())
    return manifest.hexdigest()


def generate(
    out: Path,
    source: bytes,
    config: bytes,
    samples: int = SAMPLES,
    shard_size: int = SHARD_SIZE,
) -> tuple[int, int, str]:
    """Write the tree under ``out``; return (file count, total bytes, digest)."""
    out.mkdir(parents=True, exist_ok=True)
    entries: list[tuple[str, bytes]] = [(CONFIG_NAME, config)]
    (out / CONFIG_NAME).write_bytes(config)

    shard = None
    for relative in sample_paths(samples, shard_size):
        target = out / relative
        if target.parent != shard:
            shard = target.parent
            shard.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source)
        entries.append((relative, source))

    total = sum(len(content) for _, content in entries)
    return len(entries), total, manifest_digest(entries)


def read_tree(root: Path) -> list[tuple[str, bytes]]:
    """Every regular file under ``root`` as (relative POSIX path, contents)."""
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            entries.append((path.relative_to(root).as_posix(), path.read_bytes()))
    return entries


def pinned_source(repo: Path) -> bytes:
    """The pinned v1.5.1 ``lang.rs`` blob, read out of the local object store."""
    object_name = f"{SOURCE_COMMIT}:{SOURCE_PATH}"
    try:
        blob = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "-p", object_name],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise RecipeError(
            f"cannot read {object_name}; the checkout needs full history"
        ) from error
    digest = hashlib.sha256(blob).hexdigest()
    if digest != SOURCE_SHA256:
        raise RecipeError(f"{object_name} is {digest}, the recipe pins {SOURCE_SHA256}")
    return blob


def oracle_config(repo: Path) -> bytes:
    config = (repo / ORACLE_CONFIG).read_bytes()
    digest = hashlib.sha256(config).hexdigest()
    if digest != CONFIG_SHA256:
        raise RecipeError(f"{ORACLE_CONFIG} is {digest}, the recipe pins {CONFIG_SHA256}")
    return config


def report(count: int, total: int, digest: str) -> None:
    print(f"files {count}")
    print(f"bytes {total}")
    print(f"manifest_sha256 {digest}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="scale tree root")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository holding the pinned reference object and the oracle fixtures",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="read --out instead of writing it and report its identity",
    )
    args = parser.parse_args(argv)

    try:
        if args.verify:
            entries = read_tree(args.out)
            count, total = len(entries), sum(len(c) for _, c in entries)
            digest = manifest_digest(entries)
        else:
            count, total, digest = generate(
                args.out, pinned_source(args.repo), oracle_config(args.repo)
            )
        report(count, total, digest)
        if count != FILE_COUNT:
            raise RecipeError(f"{count} files, the recipe requires {FILE_COUNT}")
        if digest != MANIFEST_SHA256:
            raise RecipeError(f"manifest is {digest}, the recipe pins {MANIFEST_SHA256}")
    except (RecipeError, OSError) as error:
        print(f"scale_tree: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
