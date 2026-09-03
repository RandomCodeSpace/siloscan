#!/usr/bin/env python3
"""Measure the embedded profiles against the pinned external noise set.

The profile corpus under ``crates/siloscan-core/tests/profiles-corpus`` holds
hand-written positives and negatives. It measures what its author thought of.
The noise set measures what a rule does to real code nobody wrote for it: the
thirty repositories recorded in ``research/embedded-profiles/noise-set.md``,
each pinned to a commit, cloned into a temporary directory at measurement time
and never committed.

What this script does, in order:

1. Read the noise set out of the markdown. The markdown is the human record and
   the only record: nothing is derived from it into a second file that could
   drift.
2. Read ``noise/limits.tsv`` out of the profile corpus. Both false-positive
   ceilings live there - ``max_corpus`` for the corpus negatives, which
   ``tests/profile_corpus.rs`` enforces, and ``max_per_kloc`` for a single
   noise repository, which this script enforces. One rule, one budget, one
   file.
3. For each repository, clone it shallow at its pinned tag, verify the checked
   out ``HEAD`` is the pinned commit, and scan it once.
4. Write one result file per repository and one summary table, each under an
   oracle-style header block. The header is what makes a number re-derivable a
   year later.
5. Exit non-zero when any rule exceeds its ``max_per_kloc`` on any single
   repository. Per rule and per repository, because removal is a per-rule
   decision: a total says the profile is noisy and not which rule to delete.

Standard library only, and no network beyond ``git clone`` over https.

    python3 scripts/profile_noise.py --binary target/release/siloscan --out /tmp/noise

Unit tests live in ``scripts/test_profile_noise.py`` and clone nothing:

    python3 -m unittest discover -s scripts -p 'test_profile_*.py'
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_NOISE_SET = REPO_ROOT / "research" / "embedded-profiles" / "noise-set.md"
DEFAULT_LIMITS = (
    REPO_ROOT
    / "crates"
    / "siloscan-core"
    / "tests"
    / "profiles-corpus"
    / "noise"
    / "limits.tsv"
)

#: Markdown heading to the language name ``siloscan`` reports. The headings are
#: written for a human ("C++"), the language names are not.
LANGUAGES = {
    "Rust": "rust",
    "Python": "python",
    "JavaScript": "javascript",
    "TypeScript": "typescript",
    "Go": "go",
    "Java": "java",
    "C": "c",
    "C++": "cpp",
    "C#": "csharp",
    "Ruby": "ruby",
}

COMMIT = re.compile(r"^[0-9a-f]{40}$")


class NoiseError(Exception):
    """A malformed input, a moved pin, or a scan that did not run."""


@dataclass(frozen=True)
class Repository:
    language: str
    name: str
    url: str
    tag: str
    commit: str
    licence: str


@dataclass(frozen=True)
class Limit:
    """One rule's noise budget. Only ``max_per_kloc`` is spent here."""

    rule_id: str
    max_corpus: int
    max_per_kloc: float


#: What a rule with no row in ``limits.tsv`` is held to.
DEFAULT_LIMIT = Limit(rule_id="", max_corpus=0, max_per_kloc=0.0)


@dataclass(frozen=True)
class Result:
    """One repository, measured."""

    repo: Repository
    files_scanned: int
    code_lines: int
    elapsed_seconds: float
    #: rule id -> findings on this repository. Rules with no findings are absent.
    findings: dict[str, int]


# ------------------------------------------------------------------ parsing


def parse_noise_set(text: str) -> list[Repository]:
    """The pinned repositories, in the order the markdown lists them.

    A table row belongs to the language of the nearest ``##`` heading above it.
    Rows whose ``Status`` column is not ``pinned`` are refused rather than
    skipped: an unpinned row in a file whose whole purpose is pinning is a
    mistake, not an opt-out.
    """
    repositories: list[Repository] = []
    language: str | None = None

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("## "):
            heading = line[3:].strip()
            language = LANGUAGES.get(heading)
            continue
        if not line.startswith("|"):
            continue

        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells[0] in ("Repository", "") or set(cells[0]) <= {"-", ":"}:
            continue
        if language is None:
            raise NoiseError(f"line {number}: table row outside a language heading")
        if len(cells) != 9:
            raise NoiseError(
                f"line {number}: {len(cells)} columns, expected 9 "
                "(repository, url, tag, commit, licence, licence path, files, bytes, status)"
            )

        name, url, tag, commit, licence, _path, _files, _bytes, status = cells
        if not COMMIT.match(commit):
            raise NoiseError(f"line {number}: {commit!r} is not a 40-character commit")
        if status != "pinned":
            raise NoiseError(f"line {number}: {name} is {status!r}, expected pinned")
        if not url.startswith("https://"):
            raise NoiseError(f"line {number}: {name} is not cloned over https")

        repositories.append(
            Repository(
                language=language,
                name=name,
                url=url,
                tag=tag,
                commit=commit,
                licence=licence,
            )
        )

    if not repositories:
        raise NoiseError("the noise set names no repositories")
    return repositories


def parse_limits(text: str) -> dict[str, Limit]:
    """``rule_id -> Limit`` from the profile corpus' ``noise/limits.tsv``."""
    limits: dict[str, Limit] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.startswith("#") or raw.startswith("rule_id\t"):
            continue
        fields = raw.split("\t")
        if len(fields) != 5:
            raise NoiseError(
                f"limits line {number}: {len(fields)} fields, expected 5 "
                "(rule_id, max_corpus, max_per_kloc, measured_at, ticket)"
            )
        rule_id = fields[0]
        if rule_id in limits:
            raise NoiseError(f"limits line {number}: {rule_id} named twice")
        try:
            limit = Limit(
                rule_id=rule_id,
                max_corpus=int(fields[1]),
                max_per_kloc=float(fields[2]),
            )
        except ValueError as error:
            raise NoiseError(f"limits line {number}: {error}") from error
        if limit.max_corpus < 0 or limit.max_per_kloc < 0:
            raise NoiseError(f"limits line {number}: a negative ceiling")
        limits[rule_id] = limit
    return limits


def limit_for(limits: dict[str, Limit], rule_id: str) -> Limit:
    """A rule's declared budget, or zero on both counts."""
    return limits.get(rule_id, DEFAULT_LIMIT)


# -------------------------------------------------------------- measurement


def per_kloc(findings: int, code_lines: int) -> float:
    """Findings per thousand code lines. A repository the scan found no code
    in has no rate rather than a division: reporting ``inf`` for a rule that
    fired zero times would read as a breach."""
    if code_lines <= 0:
        return 0.0
    return findings * 1000.0 / code_lines


def breaches(results: list[Result], limits: dict[str, Limit]) -> list[str]:
    """Every (repository, rule) whose rate is above the rule's ceiling."""
    over = []
    for result in results:
        for rule_id in sorted(result.findings):
            count = result.findings[rule_id]
            rate = per_kloc(count, result.code_lines)
            ceiling = limit_for(limits, rule_id).max_per_kloc
            if rate > ceiling:
                over.append(
                    f"{rule_id} on {result.repo.name}: {rate:.4f} per kloc "
                    f"({count} findings over {result.code_lines} code lines), "
                    f"limit {ceiling:.4f}"
                )
    return over


def run(command: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=None if cwd is None else str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise NoiseError(
            f"{' '.join(command)} exited {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed.stdout


def clone(repo: Repository, dest: Path) -> None:
    """Shallow clone at the pinned tag, then prove the pin.

    Cloning the tag and verifying the commit is what the noise set itself was
    measured with, and it catches the one thing a tag cannot promise: a tag
    that moved after the row was written checks out a different tree, and the
    numbers below it would be measured against code nobody pinned.
    """
    run(
        [
            "git",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--single-branch",
            "--branch",
            repo.tag,
            repo.url,
            str(dest),
        ]
    )
    head = run(["git", "-C", str(dest), "rev-parse", "HEAD"]).strip()
    if head != repo.commit:
        raise NoiseError(
            f"{repo.name}: tag {repo.tag} is {head}, but the noise set pins {repo.commit}"
        )


def scan(binary: Path, tree: Path, profiles: str) -> tuple[dict, float]:
    """One scan of one repository, and how long it took.

    ``--no-cache`` because a cached result is a result measured by an earlier
    binary, and the whole point is what this binary does to this tree.
    ``--format json`` because the per-rule counts and the scanned line total
    are both in it.
    """
    command = [
        str(binary),
        str(tree),
        "--profiles",
        profiles,
        "--no-cache",
        "--format",
        "json",
    ]
    started = time.monotonic()
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - started
    # A scan that reports findings exits non-zero by design; a scan that could
    # not run says so on stderr and emits no document.
    if not completed.stdout.strip():
        raise NoiseError(
            f"{' '.join(command)} produced no report (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    try:
        return json.loads(completed.stdout), elapsed
    except json.JSONDecodeError as error:
        raise NoiseError(f"{' '.join(command)} produced no JSON: {error}") from error


def tally(report: dict) -> tuple[int, int, dict[str, int]]:
    """``(files scanned, code lines, findings per rule)`` out of one report.

    Suppressed and baselined findings are counted with the rest. A noise
    measurement asks what a rule reports about code that never heard of it, and
    a repository that happens to carry a `siloscan:ignore` comment did not make
    the rule quieter.
    """
    metrics = report.get("metrics", {})
    files = len(metrics.get("files", {}))
    code_lines = int(metrics.get("totals", {}).get("code_lines", 0))

    findings: dict[str, int] = {}
    for bucket in ("findings", "baselined", "suppressed"):
        for finding in report.get(bucket, []):
            rule_id = finding["rule_id"]
            findings[rule_id] = findings.get(rule_id, 0) + 1
    return files, code_lines, findings


# ------------------------------------------------------------------ output


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def header(binary: Path, profiles: str, noise_set: Path, limits: Path) -> list[str]:
    """The oracle-style block every result file opens with."""
    return [
        f"# generated={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"# binary={binary}",
        f"# binary_sha256={sha256(binary)}",
        f"# host={platform.system()} {platform.release()} {platform.machine()}",
        f"# python={platform.python_version()}",
        f"# command=siloscan REPO --profiles {profiles} --no-cache --format json",
        f"# noise_set={noise_set}",
        f"# limits={limits}",
    ]


def repository_file(result: Result, limits: dict[str, Limit], head: list[str]) -> str:
    """One repository's own result file: its pin, then its rules."""
    lines = list(head)
    lines += [
        f"# language={result.repo.language}",
        f"# repo={result.repo.name}",
        f"# url={result.repo.url}",
        f"# tag={result.repo.tag}",
        f"# commit={result.repo.commit}",
        f"# licence={result.repo.licence}",
        f"# files_scanned={result.files_scanned}",
        f"# code_lines={result.code_lines}",
        f"# elapsed_seconds={result.elapsed_seconds:.2f}",
        "rule_id\tfindings\tper_kloc\tmax_per_kloc\tverdict",
    ]
    for rule_id in sorted(result.findings):
        count = result.findings[rule_id]
        rate = per_kloc(count, result.code_lines)
        ceiling = limit_for(limits, rule_id).max_per_kloc
        verdict = "breach" if rate > ceiling else "within"
        lines.append(f"{rule_id}\t{count}\t{rate:.4f}\t{ceiling:.4f}\t{verdict}")
    return "\n".join(lines) + "\n"


def summary_table(
    results: list[Result], limits: dict[str, Limit], head: list[str]
) -> str:
    """Every repository, every rule, one row each.

    A repository that reported nothing still gets a row, with a rule id of
    ``-``: a missing repository and a quiet one are not the same measurement,
    and a table that only lists hits cannot tell them apart.
    """
    lines = list(head)
    lines.append(
        "language\trepo\tcommit\tfiles_scanned\tcode_lines\telapsed_seconds"
        "\trule_id\tfindings\tper_kloc\tmax_per_kloc\tverdict"
    )
    for result in results:
        prefix = (
            f"{result.repo.language}\t{result.repo.name}\t{result.repo.commit}"
            f"\t{result.files_scanned}\t{result.code_lines}"
            f"\t{result.elapsed_seconds:.2f}"
        )
        if not result.findings:
            lines.append(f"{prefix}\t-\t0\t0.0000\t0.0000\twithin")
            continue
        for rule_id in sorted(result.findings):
            count = result.findings[rule_id]
            rate = per_kloc(count, result.code_lines)
            ceiling = limit_for(limits, rule_id).max_per_kloc
            verdict = "breach" if rate > ceiling else "within"
            lines.append(
                f"{prefix}\t{rule_id}\t{count}\t{rate:.4f}\t{ceiling:.4f}\t{verdict}"
            )
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------------- entry


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure the embedded profiles against the pinned noise set."
    )
    parser.add_argument(
        "--binary", required=True, type=Path, help="the siloscan binary to measure"
    )
    parser.add_argument(
        "--out", required=True, type=Path, help="directory to write result files into"
    )
    parser.add_argument(
        "--profiles",
        default="auto",
        help="what to pass to --profiles; 'auto' or a comma-separated identity list",
    )
    parser.add_argument("--noise-set", type=Path, default=DEFAULT_NOISE_SET)
    parser.add_argument("--limits", type=Path, default=DEFAULT_LIMITS)
    parser.add_argument(
        "--only",
        default="",
        help="comma-separated repository names to measure instead of all of them",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.binary.is_file():
        print(f"error: {args.binary} is not a file", file=sys.stderr)
        return 2

    try:
        repositories = parse_noise_set(args.noise_set.read_text(encoding="utf-8"))
        limits = parse_limits(args.limits.read_text(encoding="utf-8"))
    except (OSError, NoiseError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.only:
        wanted = {name.strip() for name in args.only.split(",") if name.strip()}
        known = {repo.name for repo in repositories}
        missing = sorted(wanted - known)
        if missing:
            print(f"error: unknown repository: {', '.join(missing)}", file=sys.stderr)
            return 2
        repositories = [repo for repo in repositories if repo.name in wanted]

    args.out.mkdir(parents=True, exist_ok=True)
    head = header(args.binary, args.profiles, args.noise_set, args.limits)

    results: list[Result] = []
    for repo in repositories:
        print(f"{repo.language}/{repo.name} at {repo.commit[:12]}", file=sys.stderr)
        try:
            with tempfile.TemporaryDirectory(prefix="siloscan-noise-") as scratch:
                tree = Path(scratch) / repo.name.replace("/", "-")
                clone(repo, tree)
                report, elapsed = scan(args.binary, tree, args.profiles)
        except NoiseError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        files, code_lines, findings = tally(report)
        result = Result(
            repo=repo,
            files_scanned=files,
            code_lines=code_lines,
            elapsed_seconds=elapsed,
            findings=findings,
        )
        results.append(result)
        name = f"{repo.language}-{repo.name.replace('/', '-')}.tsv"
        (args.out / name).write_text(
            repository_file(result, limits, head), encoding="utf-8"
        )

    (args.out / "summary.tsv").write_text(
        summary_table(results, limits, head), encoding="utf-8"
    )

    over = breaches(results, limits)
    for line in over:
        print(f"BREACH {line}", file=sys.stderr)
    print(
        f"{len(results)} repositories measured into {args.out}, {len(over)} breaches",
        file=sys.stderr,
    )
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
