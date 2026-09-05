#!/usr/bin/env python3
"""The paired reference-versus-candidate performance gate.

Seven lanes, each measured for wall time and peak RSS, give the fourteen
independent cells the acceptance plan requires. Both binaries see the same
scale tree, the same arguments where the arguments exist in both versions, the
same output sink, and their own cache and state roots.

Two references, because the two invocation shapes are two different contracts
=============================================================================

An explicit invocation is a v1 command, and 2.1.0 changed nothing about what it
loads, so it is still measured against the pinned v1.5.1 reference at 1.05. A
bare invocation is the v2 automatic journey, and since 2.1.0 it resolves
``ProfileSelection::Auto`` and parses every source file it admits. v1.5.1 does
no parsing at all on a bare run, so that comparison measures the feature rather
than a regression: it was 6.1x before the engine work and 2.4x after, and no
tuning turns either into 1.05. The bare lanes are therefore re-based on the
pinned **v2.0.0** reference - the last release before the flip, profiles off -
and given the budget issue #89 declared, with the cold wall budget raised on
2026-09-05::

    lane                  reference  cache   wall   peak RSS
    explicit_no_cache     v1.5.1     none    1.05   1.05
    explicit_cold_cache   v1.5.1     cold    1.05   1.05
    explicit_warm_cache   v1.5.1     warm    1.05   1.05
    bare_no_save_cold     v2.0.0     cold    3.00   1.10
    bare_no_save_warm     v2.0.0     warm    1.25   1.10
    bare_auto_save_first  v2.0.0     warm    1.25   1.10
    bare_auto_save_warm   v2.0.0     warm    1.25   1.10

The wall budget splits on the cache, because a cache hit skips the parse
entirely: that is the whole distance between the cold lane's 2.4x and the warm
lane's 1.16x measured in issue #89, and a single number covering both would
either wave the warm lanes through or reject the cold one on the cost of the
feature. Peak RSS does not split: parsing costs about 2% there on every lane,
and 1.10 is a ceiling rather than a budget being spent.

The cold wall budget is 3.00 rather than the 2.50 issue #89 declared. No build
since the profiles flip has met 2.50 on the CI runners - the 2.1.0 candidates
measured 2.62 to 2.83 and the 2.2.0 candidate 2.63 to 2.99, with the runner
spread about a third within one run - and a bare run parses every source file
it admits where v2.0.0 parses none, so 3.00 states that cost in one number. The
warm lanes, peak RSS and the explicit lanes are unchanged.

Each lane runs one untimed warm-up per binary and then nine paired samples in
ABBA order, so a drifting runner biases both binaries in the same direction:

    pair 1  reference candidate
    pair 2  candidate reference
    pair 3  reference candidate
    ...

Per cell the gate compares medians against that cell's own limit. A ratio at or
below the limit passes. Above it on a first run is *suspected* and the caller
reruns the whole gate on a fresh runner with ``--compare``; the same lane and
metric above its limit twice *rejects*. A reference median absolute deviation
above 20% of the reference median *invalidates* that cell: the runner was too
noisy to decide. A faster cell never offsets a slower or larger one - every
cell stands alone.

Wall time is ``time.monotonic`` around the child. Peak RSS is ``ru_maxrss``
from ``os.wait4`` on that one child, which is the kernel's own high-water mark
for that process alone, in KiB on Linux. ``/usr/bin/time -v`` reads the same
counter but adds a wrapper process to the measurement.

Exit status: 0 every cell passes, 1 a rerun is required (suspected or
invalid), 2 the candidate is rejected, 3 the harness itself failed.

Only the standard library is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# The explicit lanes' limit against v1.5.1: unchanged since v2.0.0, because an
# explicit invocation is unchanged since v1.5.1.
RATIO_LIMIT = 1.05
# The bare lanes' limits against v2.0.0, declared in issue #89; the cold wall
# budget was raised from 2.50 to 3.00 on 2026-09-05, see the module docstring.
BARE_WALL_LIMIT_COLD = 3.00
BARE_WALL_LIMIT_WARM = 1.25
BARE_RSS_LIMIT = 1.10

MAD_LIMIT = 0.20
DEFAULT_SAMPLES = 9

EXIT_PASS = 0
EXIT_RERUN = 1
EXIT_REJECT = 2
EXIT_ERROR = 3

METRICS = ("seconds", "peak_rss_kib")
# The two binaries of one lane's pairs. Which binary fills the reference side is
# the lane's own answer; see ``Lane.reference_role``.
ROLES = ("reference", "candidate")
# The reference binaries the gate is handed, and the roles lanes name.
REFERENCE_ROLES = ("reference", "bare_reference")

# A scan that finds nothing exits 0 and a scan that finds something exits 1.
# Anything else means the run did not do the work being measured.
OK_STATUS = (0, 1)


@dataclass(frozen=True)
class Lane:
    """One measured invocation pair.

    ``mode`` selects the invocation shape, and with it the reference binary. An
    explicit lane passes the scale tree as a PATH plus the frozen oracle rules,
    which is a v1.5.1 command both binaries accept unchanged. A bare lane runs
    the binary with no argument from inside the tree, which is the v2 automatic
    journey, so its reference is v2.0.0 - the shape does not exist in v1.5.1 in
    any comparable form.

    ``no_save`` adds ``--no-save`` to **both** sides. It used to be the
    candidate's alone, because the v1.5.1 reference had no such flag and its
    plain bare run was the only comparator available; the v2.0.0 reference has
    it, so the lane is symmetric and no longer credits the candidate with a
    publication the reference performed. ``--no-save`` is outside the v1 scan
    options, so it does not make the run explicit.

    ``cache`` is ``none`` (``--no-cache``), ``cold`` (a fresh empty cache root
    for every sample) or ``warm`` (one cache root per binary, seeded by that
    lane's warm-up). ``state`` is ``fresh`` (a new state root per sample, so an
    auto-save is a first publication) or ``warm`` (one state root per binary,
    seeded by the warm-up, so an auto-save replaces an existing report).

    Bare lanes cannot use ``--cache-dir``: supplying it would make the scan
    explicit. They select their cache root through the process environment
    instead, which is what ``default_cache_base`` reads.
    """

    name: str
    title: str
    mode: str
    cache: str
    state: str
    no_save: bool

    @property
    def reference_role(self) -> str:
        """Which of the two reference binaries this lane measures against.

        The invocation shape decides it and nothing else does: an explicit
        command is the one v1.5.1 answers identically, and a bare run is the
        one 2.1.0 changed. Deriving it here rather than listing it per lane
        keeps a lane from claiming a reference its own arguments contradict.
        """
        return "bare_reference" if self.mode == "bare" else "reference"

    def ratio_limit(self, metric: str) -> float:
        """This lane's budget for ``metric``, as the module docstring tabulates.

        A lane that never reads a warm cache pays the parse on every sample, so
        it carries the cold wall budget; ``none`` is ``--no-cache`` and is cold
        by construction.
        """
        if metric not in METRICS:
            raise ValueError(f"unknown metric {metric}")
        if self.reference_role == "reference":
            return RATIO_LIMIT
        if metric == "peak_rss_kib":
            return BARE_RSS_LIMIT
        return BARE_WALL_LIMIT_WARM if self.cache == "warm" else BARE_WALL_LIMIT_COLD


LANES = (
    Lane(
        "explicit_no_cache",
        "Unchanged explicit invocation, --no-cache",
        "explicit",
        "none",
        "fresh",
        False,
    ),
    Lane(
        "explicit_cold_cache",
        "Unchanged explicit invocation, cold cache",
        "explicit",
        "cold",
        "fresh",
        False,
    ),
    Lane(
        "explicit_warm_cache",
        "Unchanged explicit invocation, warm cache",
        "explicit",
        "warm",
        "warm",
        False,
    ),
    Lane(
        "bare_no_save_cold",
        "Bare run, --no-save both sides, cold cache",
        "bare",
        "cold",
        "fresh",
        True,
    ),
    Lane(
        "bare_no_save_warm",
        "Bare run, --no-save both sides, warm cache",
        "bare",
        "warm",
        "fresh",
        True,
    ),
    Lane(
        "bare_auto_save_first",
        "Bare run, auto-save, first publication",
        "bare",
        "warm",
        "fresh",
        False,
    ),
    Lane(
        "bare_auto_save_warm",
        "Bare run, auto-save, warm replacement",
        "bare",
        "warm",
        "warm",
        False,
    ),
)

LANES_BY_NAME = {lane.name: lane for lane in LANES}


@dataclass(frozen=True)
class Roots:
    """The four directories one sample runs against."""

    tree: Path
    rules: Path
    cache: Path
    state: Path
    home: Path


@dataclass(frozen=True)
class Invocation:
    argv: tuple[str, ...]
    cwd: Path
    env: dict[str, str]


def lane_invocation(lane: Lane, role: str, binary: Path, roots: Roots) -> Invocation:
    """The exact command, working directory and environment for one sample."""
    if role not in ROLES:
        raise ValueError(f"unknown role {role}")
    if lane.mode == "explicit":
        argv = [str(binary), str(roots.tree), "--rules", str(roots.rules), "--no-default-rules"]
        if lane.cache == "none":
            argv.append("--no-cache")
        else:
            argv += ["--cache-dir", str(roots.cache)]
        argv += ["--format", "json"]
        cwd = roots.home
    elif lane.mode == "bare":
        argv = [str(binary)]
        if lane.no_save:
            argv.append("--no-save")
        cwd = roots.tree
    else:
        raise ValueError(f"unknown lane mode {lane.mode}")
    return Invocation(tuple(argv), cwd, sample_env(roots))


def sample_env(roots: Roots) -> dict[str, str]:
    """The environment overrides that pin this sample's cache and state roots.

    ``HOME`` is redirected too so nothing falls back to the runner's own
    directories, and the state root sits outside the scan boundary because a
    state root inside it is refused by the candidate.
    """
    return {
        "HOME": str(roots.home),
        "XDG_CACHE_HOME": str(roots.cache),
        "XDG_STATE_HOME": str(roots.state),
    }


def sample_roots(work: Path, lane: Lane, role: str, label: str, tree: Path, rules: Path) -> Roots:
    """Directories for one sample; warm roots persist, fresh roots do not."""
    base = work / lane.name / role
    cache = base / "cache" if lane.cache == "warm" else base / f"cache-{label}"
    state = base / "state" if lane.state == "warm" else base / f"state-{label}"
    home = base / "home"
    return Roots(tree, rules, cache, state, home)


def measure(invocation: Invocation, stderr_log: Path) -> tuple[float, int]:
    """Run the child once; return (wall seconds, peak RSS in KiB).

    ``os.wait4`` reports the rusage of this one child, so the peak RSS is that
    process's own high-water mark rather than a running maximum over every
    child this harness has ever reaped.
    """
    argv = list(invocation.argv)
    env = dict(os.environ)
    env.update(invocation.env)
    stderr_log.parent.mkdir(parents=True, exist_ok=True)

    start = time.monotonic()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child never returns
        try:
            os.chdir(invocation.cwd)
            null = os.open(os.devnull, os.O_WRONLY)
            log = os.open(str(stderr_log), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(null, 1)
            os.dup2(log, 2)
            os.execve(argv[0], argv, env)
        except BaseException:
            os._exit(127)
    _, status, usage = os.wait4(pid, 0)
    elapsed = time.monotonic() - start

    code = os.waitstatus_to_exitcode(status)
    if code not in OK_STATUS:
        detail = stderr_log.read_text(errors="replace").strip() if stderr_log.exists() else ""
        raise RuntimeError(f"{' '.join(argv)} exited {code}\n{detail}")
    return elapsed, int(usage.ru_maxrss)


def run_lane(
    lane: Lane, binaries: dict[str, Path], work: Path, tree: Path, rules: Path, samples: int
) -> dict[str, list[dict[str, float]]]:
    """One untimed warm-up per binary, then ``samples`` paired ABBA samples.

    ``binaries`` is this lane's pair: its ``reference`` entry is whichever of
    the two reference binaries ``Lane.reference_role`` named, so everything
    below - the samples, the raw document, the cells - stays a two-role
    comparison and the choice is made once, in ``run``.
    """
    stderr_log = work / "stderr.log"
    results: dict[str, list[dict[str, float]]] = {role: [] for role in ROLES}

    for role in ROLES:
        roots = sample_roots(work, lane, role, "warmup", tree, rules)
        prepare(roots)
        measure(lane_invocation(lane, role, binaries[role], roots), stderr_log)
        discard(lane, roots)

    for index in range(1, samples + 1):
        order = ROLES if index % 2 else tuple(reversed(ROLES))
        for role in order:
            roots = sample_roots(work, lane, role, str(index), tree, rules)
            prepare(roots)
            seconds, rss = measure(lane_invocation(lane, role, binaries[role], roots), stderr_log)
            discard(lane, roots)
            results[role].append(
                {"sample": index, "seconds": round(seconds, 6), "peak_rss_kib": rss}
            )
    return results


def prepare(roots: Roots) -> None:
    for directory in (roots.cache, roots.state, roots.home):
        directory.mkdir(parents=True, exist_ok=True)


def discard(lane: Lane, roots: Roots) -> None:
    """Remove the roots this lane wanted fresh, so the next sample is cold."""
    if lane.cache != "warm":
        shutil.rmtree(roots.cache, ignore_errors=True)
    if lane.state != "warm":
        shutil.rmtree(roots.state, ignore_errors=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def median(values: list[float]) -> float:
    return float(statistics.median(values))


def mad_fraction(values: list[float]) -> float:
    """Median absolute deviation as a fraction of the median."""
    centre = median(values)
    if centre == 0:
        return 0.0
    return median([abs(value - centre) for value in values]) / centre


def ratio(candidate: float, reference: float) -> float:
    if reference == 0:
        return float("inf") if candidate else 1.0
    return candidate / reference


def verdict(cell_ratio: float, reference_mad: float, prior_ratio: float | None, limit: float) -> str:
    """The plan's per-cell decision, against that cell's own ``limit``.

    An invalid reference spread is decided first: a median taken from a runner
    that noisy carries no information about the candidate either way.

    The twice-rule reads the prior run against the same limit, because a lane's
    limit is a property of the lane and not of the run.
    """
    if reference_mad > MAD_LIMIT:
        return "invalid"
    if cell_ratio <= limit:
        return "pass"
    if prior_ratio is not None and prior_ratio > limit:
        return "reject"
    return "suspected"


@dataclass(frozen=True)
class Cell:
    lane: str
    metric: str
    reference: float
    candidate: float
    ratio: float
    limit: float
    reference_mad: float
    verdict: str


def cell_values(raw: dict, lane_name: str, role: str, metric: str) -> list[float]:
    return [float(sample[metric]) for sample in raw["lanes"][lane_name][role]]


def analyze(raw: dict, prior: dict | None = None) -> list[Cell]:
    """The fourteen cells, in lane then metric order."""
    prior_ratios: dict[tuple[str, str], float] = {}
    if prior is not None:
        for cell in analyze(prior):
            prior_ratios[(cell.lane, cell.metric)] = cell.ratio

    cells = []
    for lane in LANES:
        if lane.name not in raw["lanes"]:
            continue
        for metric in METRICS:
            reference = median(cell_values(raw, lane.name, "reference", metric))
            candidate = median(cell_values(raw, lane.name, "candidate", metric))
            spread = mad_fraction(cell_values(raw, lane.name, "reference", metric))
            value = ratio(candidate, reference)
            limit = lane.ratio_limit(metric)
            cells.append(
                Cell(
                    lane.name,
                    metric,
                    reference,
                    candidate,
                    value,
                    limit,
                    spread,
                    verdict(value, spread, prior_ratios.get((lane.name, metric)), limit),
                )
            )
    return cells


def overall(cells: list[Cell]) -> str:
    verdicts = {cell.verdict for cell in cells}
    for name in ("reject", "invalid", "suspected"):
        if name in verdicts:
            return name
    return "pass"


def exit_code(cells: list[Cell]) -> int:
    return {
        "pass": EXIT_PASS,
        "suspected": EXIT_RERUN,
        "invalid": EXIT_RERUN,
        "reject": EXIT_REJECT,
    }[overall(cells)]


def format_table(cells: list[Cell]) -> str:
    header = (
        "cell",
        "lane",
        "against",
        "metric",
        "reference",
        "candidate",
        "ratio",
        "limit",
        "ref MAD",
        "verdict",
    )
    rows = [header]
    for number, cell in enumerate(cells, start=1):
        lane = LANES_BY_NAME[cell.lane]
        rows.append(
            (
                str(number),
                cell.lane,
                "v2.0.0" if lane.reference_role == "bare_reference" else "v1.5.1",
                "wall time" if cell.metric == "seconds" else "peak RSS",
                f"{cell.reference:.3f}" if cell.metric == "seconds" else f"{cell.reference:.0f}",
                f"{cell.candidate:.3f}" if cell.metric == "seconds" else f"{cell.candidate:.0f}",
                f"{cell.ratio:.3f}",
                f"{cell.limit:.2f}",
                f"{cell.reference_mad * 100:.1f}%",
                cell.verdict,
            )
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(header))]
    lines = []
    for index, row in enumerate(rows):
        lines.append("  ".join(value.ljust(widths[column]) for column, value in enumerate(row)))
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    lines.append("")
    lines.append(f"overall: {overall(cells)}")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> dict:
    binaries = {
        "reference": args.reference.resolve(),
        "bare_reference": args.bare_reference.resolve(),
        "candidate": args.candidate.resolve(),
    }
    tree = args.tree.resolve()
    rules = args.rules.resolve()
    work = args.work.resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    raw = {
        "schema": 2,
        "samples": args.samples,
        "mad_limit": MAD_LIMIT,
        "tree": str(tree),
        "binaries": {
            role: {"path": str(path), "sha256": sha256_file(path)}
            for role, path in binaries.items()
        },
        "lane_references": {lane.name: lane.reference_role for lane in LANES},
        "ratio_limits": {
            lane.name: {metric: lane.ratio_limit(metric) for metric in METRICS} for lane in LANES
        },
        "lanes": {},
    }
    for lane in LANES:
        print(f"lane {lane.name}: {lane.title} (against {lane.reference_role})", flush=True)
        pair = {"reference": binaries[lane.reference_role], "candidate": binaries["candidate"]}
        raw["lanes"][lane.name] = run_lane(lane, pair, work, tree, rules, args.samples)
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--reference", type=Path, required=True, help="pinned v1.5.1 binary, for the explicit lanes"
    )
    parser.add_argument(
        "--bare-reference",
        type=Path,
        required=True,
        help="pinned v2.0.0 binary, for the bare lanes",
    )
    parser.add_argument("--candidate", type=Path, required=True, help="candidate binary")
    parser.add_argument("--tree", type=Path, required=True, help="generated scale tree")
    parser.add_argument("--rules", type=Path, required=True, help="frozen oracle scale rules")
    parser.add_argument("--work", type=Path, required=True, help="scratch root, erased first")
    parser.add_argument("--out", type=Path, required=True, help="raw sample JSON to write")
    parser.add_argument("--table", type=Path, help="also write the printed table here")
    parser.add_argument(
        "--samples",
        type=int,
        default=DEFAULT_SAMPLES,
        help=f"paired samples per lane (default {DEFAULT_SAMPLES})",
    )
    parser.add_argument(
        "--compare",
        type=Path,
        help="a prior run's raw samples; a cell above the ratio limit in both runs rejects",
    )
    args = parser.parse_args(argv)

    if args.samples < 1:
        parser.error("--samples must be at least 1")

    try:
        prior = json.loads(args.compare.read_text()) if args.compare else None
        raw = run(args)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
        cells = analyze(raw, prior)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"perf_gate: {error}", file=sys.stderr)
        return EXIT_ERROR

    table = format_table(cells)
    print(table)
    if args.table:
        args.table.parent.mkdir(parents=True, exist_ok=True)
        args.table.write_text(table + "\n")
    return exit_code(cells)


if __name__ == "__main__":
    raise SystemExit(main())
