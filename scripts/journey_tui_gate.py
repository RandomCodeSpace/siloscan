#!/usr/bin/env python3
"""Run the hosted TUI lane: every session a user can open, driven through a pty.

Each step is one `tui_pty.py` invocation. They live here rather than in the
workflow so the lane can be run locally against a debug build, and so the
marker strings and the expected screen text stay next to each other.

The fixtures are copied or generated under the work directory: a session that
mutates something must not be able to reach the checkout, and the planted
credential is generated at runtime so no credential-shaped literal lives in the
repository.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import secrets
import shutil
import sys

import tui_pty

# The live oracle fixture's frozen first frame, from
# research/oracle-v1.5.1/golden/tui-states.tsv.
ORACLE_LIVE_READY = "2 new, 0 baselined, 1 suppressed"
ORACLE_SNAPSHOT_READY = "23 new, 0 baselined, 1 suppressed"
# One planted credential and nothing else, so every generated session settles on
# the same counts whichever entry point opened it.
GENERATED_READY = "1 new, 0 baselined, 0 suppressed"
# The status bar is 120 columns wide and truncates. This is the part of
# state::READ_ONLY_BASELINE that survives at that width.
READ_ONLY_BASELINE = "snapshot is read-only: the baseline needs"


def generate_fixture(root: pathlib.Path) -> pathlib.Path:
    tree = root / "live-fixture"
    (tree / "src").mkdir(parents=True, exist_ok=True)
    (tree / "Cargo.toml").write_text('[package]\nname = "live"\nversion = "0.1.0"\n')
    (tree / "src" / "main.rs").write_text(
        'fn main() {\n    let token = "glptt-%s";\n    println!("{token}");\n}\n'
        % secrets.token_hex(20)
    )
    return tree


def drive(name: str, environment: list[str], arguments: list[str]) -> bool:
    print(f"--- {name}")
    status = tui_pty.main([*[f"--env={pair}" for pair in environment], *arguments])
    if status != 0:
        print(f"--- {name}: FAILED", file=sys.stderr)
    return status == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--siloscan", required=True)
    parser.add_argument("--ss", required=True)
    parser.add_argument("--siloscan-tui", required=True)
    parser.add_argument("--oracle", required=True, help="research/oracle-v1.5.1")
    parser.add_argument("--work", required=True, help="a directory this gate owns")
    parser.add_argument("--timeout", type=float, default=180.0)
    arguments = parser.parse_args(argv)
    # Sessions run with the fixture as their working directory, so a
    # relative binary path would stop resolving there.
    for name in ("siloscan", "ss", "siloscan_tui"):
        setattr(arguments, name, str(pathlib.Path(getattr(arguments, name)).resolve()))

    if os.name != "posix":
        print("skip: this lane needs a POSIX pseudo-terminal; the TUI gate runs on Linux")
        return 0

    oracle = pathlib.Path(arguments.oracle).resolve()
    work = pathlib.Path(arguments.work).resolve()
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    cache = work / "cache"
    state = work / "state"
    cache.mkdir()
    state.mkdir()
    environment = [f"XDG_CACHE_HOME={cache}", f"XDG_STATE_HOME={state}"]

    live = work / "oracle-live"
    shutil.copytree(oracle / "tui-live" / "fixture", live)
    snapshot = work / "report.json"
    shutil.copy(oracle / "golden" / "report.json", snapshot)
    generated = generate_fixture(work)
    timeout = ["--timeout", str(arguments.timeout)]

    # A bare scan first, so the implicit `review` step below has a saved report
    # to open and opens the one this scan wrote.
    saved = run_bare_scan(arguments.siloscan, generated, cache, state)

    results = [
        drive(
            "standalone live session",
            environment,
            [
                "--marker",
                ORACLE_LIVE_READY,
                "--key",
                "q",
                "--expect",
                "Quality Gate",
                "--expect",
                "oracle.regex",
                *timeout,
                "--",
                arguments.siloscan_tui,
                str(live),
                "--rules",
                str(oracle / "tui-live" / "rules"),
                "--no-default-rules",
            ],
        ),
        drive(
            "siloscan review --live",
            environment,
            [
                "--marker",
                GENERATED_READY,
                "--key",
                "q",
                "--expect",
                "Quality Gate",
                *timeout,
                "--",
                arguments.siloscan,
                "review",
                "--live",
                str(generated),
            ],
        ),
        drive(
            "ss review --live",
            environment,
            [
                "--marker",
                GENERATED_READY,
                "--key",
                "q",
                "--expect",
                "Quality Gate",
                *timeout,
                "--",
                arguments.ss,
                "review",
                "--live",
                str(generated),
            ],
        ),
        drive(
            "siloscan review, the saved report of a bare scan",
            environment,
            [
                "--marker",
                GENERATED_READY,
                "--key",
                "q",
                "--expect",
                "read-only",
                "--cwd",
                str(generated),
                *timeout,
                "--",
                arguments.siloscan,
                "review",
            ],
        ),
        drive(
            "siloscan review --report",
            environment,
            [
                "--marker",
                GENERATED_READY,
                "--key",
                "q",
                "--expect",
                "read-only",
                *timeout,
                "--",
                arguments.siloscan,
                "review",
                "--report",
                saved,
            ],
        ),
        drive(
            "snapshot baseline refusal",
            environment,
            [
                "--marker",
                ORACLE_SNAPSHOT_READY,
                "--key",
                "3",
                "--key",
                "b",
                "--key",
                "q",
                "--expect",
                READ_ONLY_BASELINE,
                "--unchanged",
                str(snapshot),
                *timeout,
                "--",
                arguments.siloscan_tui,
                "--report",
                str(snapshot),
            ],
        ),
    ]

    failed = results.count(False)
    print(f"{len(results) - failed} of {len(results)} TUI sessions passed")
    return 1 if failed else 0


def run_bare_scan(
    siloscan: str, tree: pathlib.Path, cache: pathlib.Path, state: pathlib.Path
) -> str:
    """One bare scan of the generated fixture, returning the report it saved."""
    import subprocess

    environment = dict(os.environ)
    environment["XDG_CACHE_HOME"] = str(cache)
    environment["XDG_STATE_HOME"] = str(state)
    result = subprocess.run(
        [siloscan], cwd=tree, env=environment, capture_output=True, text=True
    )
    if result.returncode != 1:
        raise SystemExit(
            f"the bare scan exited {result.returncode}, expected 1\n{result.stdout}\n{result.stderr}"
        )
    for line in result.stdout.splitlines():
        if line.startswith("Report: "):
            return line[len("Report: ") :]
    raise SystemExit(f"the bare scan saved no report\n{result.stdout}")


if __name__ == "__main__":
    sys.exit(main())
