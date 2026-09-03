#!/usr/bin/env python3
"""Measure the embedded profiles against the pinned external noise set.

The profile corpus under ``crates/siloscan-core/tests/profiles-corpus`` holds
hand-written positives and negatives. It measures what its author thought of.
The noise set measures what a rule does to real code nobody wrote for it: the
twenty-nine repositories recorded in
``research/embedded-profiles/noise-set.md``, each pinned to a commit, cloned
into a temporary directory at measurement time and never committed.

Two things about the numerator and the denominator, both of which would be
wrong if taken at face value:

**Only profile findings are counted.** ``--profiles`` adds the embedded profile
documents to the secrets pack, it does not replace it, and ``--no-default-rules``
would suppress the profiles along with it. Every run therefore reports
``secrets.*`` findings as well, and those belong to the detection corpus and its
own gates, not to a profile's noise budget. So the tally keeps only ids whose
first segment is ``reliability`` or ``maintainability`` - the same closed family
set ``tests/profile_corpus.rs`` enforces on every shipped document.

**The denominator is the repository's own language.** ``metrics.totals.code_lines``
sums every tier-1 language in the tree, so a TypeScript repository carrying
JavaScript build scripts would divide a TypeScript rule's findings by both and
report a rate lower than the truth. The rate here is over the code lines of the
language the repository was pinned for, summed out of ``metrics.files``. The
report has no per-file language field, so the file's extension decides, using a
copy of the table in ``crates/siloscan-core/src/lang.rs``.

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

#: First segment of every rule id the profiles ship. A finding outside these two
#: families came from the embedded secrets pack, which ``--profiles`` adds to
#: rather than replaces, and is measured by the detection corpus instead.
#: ``PROFILE_FAMILIES`` in ``tests/profile_corpus.rs`` is the same list.
PROFILE_FAMILIES = ("reliability", "maintainability")

#: File extension to language, copied from ``detect_by_extension`` in
#: ``crates/siloscan-core/src/lang.rs``. The JSON report's per-file metrics
#: carry line counts and no language, so this is the only way to restrict the
#: denominator to the language a repository was pinned for. It is a copy and can
#: drift: if ``FileMetrics`` ever gains a language field, read that instead.
#:
#: ``h`` is the entry that is only half true. C and C++ share the extension and
#: the product decides between them from the file's content, so this table's
#: answer is the one to fall back on when the file cannot be read; see
#: ``is_cpp_header`` below.
EXTENSIONS = {
    "rs": "rust",
    "py": "python",
    "js": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "go": "go",
    "java": "java",
    "c": "c",
    "h": "c",
    "cpp": "cpp",
    "cc": "cpp",
    "cxx": "cpp",
    "hpp": "cpp",
    "hh": "cpp",
    "cs": "csharp",
    "rb": "ruby",
}


def is_profile_rule(rule_id: str) -> bool:
    """Whether a rule id belongs to a profile rather than the secrets pack."""
    return rule_id.split(".", 1)[0] in PROFILE_FAMILIES


#: Line prefixes that make a ``.h`` file C++ rather than C. One copy of the
#: list, mirroring ``is_cpp_header`` in ``crates/siloscan-core/src/lang.rs``:
#: that function is the product's own decision and the denominator here has to
#: agree with it, so the two change together or the rate counts a file's
#: findings under one language and its lines under the other.
CPP_HEADER_SIGNALS = (
    "namespace ",
    "class ",
    "template<",
    "template <",
    "public:",
    "private:",
    "protected:",
    'extern "C++"',
)


def is_cpp_header(content: str) -> bool:
    """Whether a ``.h`` file's content is C++, by the rule ``lang.rs`` applies.

    Comments are removed first, so prose that mentions a C++ keyword cannot
    decide the file, and every signal is then anchored at the start of the
    remaining code on the line, so an identifier or a string that contains one
    of these words cannot decide it either. An empty header is C.
    """
    in_block_comment = False
    for line in content.splitlines():
        code: list[str] = []
        rest = line
        while True:
            if in_block_comment:
                end = rest.find("*/")
                if end < 0:
                    break
                rest = rest[end + 2 :]
                in_block_comment = False
            else:
                block = rest.find("/*")
                slash = rest.find("//")
                if block >= 0 and (slash < 0 or block < slash):
                    code.append(rest[:block])
                    rest = rest[block + 2 :]
                    in_block_comment = True
                elif slash >= 0:
                    code.append(rest[:slash])
                    break
                else:
                    code.append(rest)
                    break
        if "".join(code).strip().startswith(CPP_HEADER_SIGNALS):
            return True
    return False


def language_of(path: str, tree: Path | None = None) -> str | None:
    """The language of one scanned path. ``None`` for anything the ten grammars
    do not cover, an extensionless file included - a file named ``go`` is not a
    Go file.

    The extension decides, except for ``.h``, which C and C++ share: given
    ``tree``, the file is read from it and its content decides, the way the
    product does it. Without ``tree``, or when the file cannot be read, the
    extension table's ``c`` stands.
    """
    name = path.rpartition("/")[2]
    if "." not in name:
        return None
    extension = name.rpartition(".")[2].lower()
    language = EXTENSIONS.get(extension)
    if extension == "h" and tree is not None:
        try:
            content = (tree / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return language
        return "cpp" if is_cpp_header(content) else "c"
    return language


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
    #: Files of the repository's own language. The denominator's population.
    files_scanned: int
    #: Every file the scan took metrics on, whatever its language. Recorded so
    #: a reader can see how much of the tree the rate does not speak for.
    files_total: int
    #: Code lines of the repository's own language, and nothing else.
    code_lines: int
    elapsed_seconds: float
    #: Profile rule id -> findings on this repository. Rules with no findings
    #: are absent, and secrets-pack ids never appear.
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
    """Every (repository, rule) whose rate is above the rule's ceiling.

    Profile rules only, for the reason in the module docstring. ``tally`` has
    already dropped everything else; this repeats the filter so a result built
    any other way cannot charge a ``secrets.*`` finding to a profile's budget.
    """
    over = []
    for result in results:
        for rule_id in sorted(result.findings):
            if not is_profile_rule(rule_id):
                continue
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


def tally(
    report: dict, language: str, tree: Path | None = None
) -> tuple[int, int, int, dict[str, int]]:
    """``(files of `language`, files total, code lines of `language`, findings
    per profile rule)`` out of one report.

    Two restrictions, both argued in the module docstring: only
    ``reliability.*`` and ``maintainability.*`` findings are counted, because
    ``--profiles`` adds to the secrets pack rather than replacing it; and the
    code lines are the ones belonging to ``language``, because
    ``metrics.totals.code_lines`` sums every tier-1 language in the tree.

    ``tree`` is the checkout the report was taken from, and it is passed so a
    ``.h`` file can be read: C and C++ share the extension, and a header the
    product scanned as C++ has to land in the C++ denominator or its findings
    are divided by lines that do not include it.

    Suppressed and baselined findings are counted with the rest. A noise
    measurement asks what a rule reports about code that never heard of it, and
    a repository that happens to carry a `siloscan:ignore` comment did not make
    the rule quieter.
    """
    files = report.get("metrics", {}).get("files", {})
    matching = [path for path in files if language_of(path, tree) == language]
    code_lines = sum(int(files[path].get("code_lines") or 0) for path in matching)

    findings: dict[str, int] = {}
    for bucket in ("findings", "baselined", "suppressed"):
        for finding in report.get(bucket, []):
            rule_id = finding["rule_id"]
            if not is_profile_rule(rule_id):
                continue
            findings[rule_id] = findings.get(rule_id, 0) + 1
    return len(matching), len(files), code_lines, findings


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
        f"# files_total={result.files_total}",
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
                # Inside the checkout's lifetime: a `.h` file's language is
                # decided by reading it, and the directory goes away below.
                files, files_total, code_lines, findings = tally(
                    report, repo.language, tree
                )
        except NoiseError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        result = Result(
            repo=repo,
            files_scanned=files,
            files_total=files_total,
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
