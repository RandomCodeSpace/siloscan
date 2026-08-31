# One-command scan and review integration

- Date: 2026-08-31
- Behavioral reference: `880d211a463e97eb3c188f957e5592d88f36dcf8`
- Decision ticket: [Choose the one-command scan and review integration seam](https://github.com/RandomCodeSpace/siloscan/issues/57)
- Wayfinder map: [Siloscan v2 wayfinder map: one install, one scan, one report](https://github.com/RandomCodeSpace/siloscan/issues/56)

## Decision

Keep the current three packages. Add a library target to `siloscan-tui`, make the
`siloscan` package depend on that library, and add `review` to the existing Clap
subcommand enum.

The dependency direction is:

```text
siloscan binaries: siloscan, ss
    |-- siloscan-core
    `-- siloscan-tui library
            `-- siloscan-core

siloscan-tui binary
    `-- siloscan-tui library
            `-- siloscan-core
```

There is no new package and no dependency cycle. `siloscan-core` owns resolved
scan setup. The CLI owns command parsing, report rendering, persistence
orchestration, and exit status. The TUI library owns terminal setup, the event
loop, terminal restoration, and rendering. It does not own a second copy of
config, rule, baseline, cache, or project-detection semantics.

This is the minimum integration that satisfies one installation. Cargo installs
the binary targets of the selected package, not the binaries of its
dependencies. Calling a sibling `siloscan-tui` process would therefore keep the
second-install problem for `cargo install siloscan`. Linking the existing TUI
package as a library puts review inside `siloscan` and `ss` without deleting the
standalone program. Cargo supports a library and binary targets in the same
package, and a package binary can call its library API. See the official
[Cargo install contract](https://doc.rust-lang.org/cargo/commands/cargo-install.html)
and [Cargo target contract](https://doc.rust-lang.org/cargo/reference/cargo-targets.html).

## Command contract

The v2 command grammar should be:

| Command | Behavior |
| --- | --- |
| `siloscan` | Detect the current project, scan it, save the latest report, print the selected scan format, and exit. |
| `siloscan PATH [scan options]` | Keep the existing explicit scan meaning. Detection may fill only fields that CLI and config did not set. |
| `siloscan review` | Open the saved latest report for the project owning the current directory. Do not rescan. |
| `siloscan review PATH` | Open the saved latest report for the project owning `PATH`. Do not rescan. |
| `siloscan review --report FILE` | Open that report as the existing read-only snapshot mode. |
| `siloscan review --live [PATH]` | Open the existing live TUI, using the one resolved scan plan. |
| `ss ...` | Behave exactly like the corresponding `siloscan ...` form, while retaining `ss` in help and error text. |
| `siloscan-tui [PATH]` | Keep the existing live TUI command and arguments. |
| `siloscan-tui --report FILE` | Keep the existing snapshot command and arguments. |

`review` remains explicit. A normal scan must never open a terminal UI based on
TTY detection, a prompt, or a scan result. That would make automation depend on
the terminal attached to the process. The default scan saves the report and
prints a review hint; the user decides whether to run `siloscan review`.

### Review argument rules

The `review` argument type should express these rules through Clap:

- `PATH` is optional. Code applies `.` after parsing, so Clap can distinguish an
  omitted path from an explicit path.
- `--report FILE` conflicts with `PATH` and `--live`.
- `--live` accepts `PATH` and the current standalone live-TUI setup options.
- Live-only options such as `--rules`, `--no-default-rules`, and walk controls
  require `--live`. They must not be accepted and ignored while reading a saved
  report.
- `--config FILE` remains valid for an explicit or saved snapshot because the
  current snapshot mode uses config to shape its silo views.
- A missing latest report is an exit-2 setup error that says which project was
  resolved and tells the user to run `siloscan [PATH]`. It must not trigger an
  implicit rescan.

Clap already models this program as an optional subcommand plus flattened scan
arguments. Its derive API supports tuple subcommands, reusable `Args`, and
argument conflicts, so `Review(ReviewArgs)` fits the existing parser without a
new command framework. See the current
[`Cli` and `Command` definitions](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan/src/main.rs#L24-L89)
and Clap's official [derive reference](https://docs.rs/clap/4.6.5/clap/_derive/).

### The `review` path collision

Adding a subcommand reserves one word that v1 can interpret as a relative path.
Silently opening a report when a user expected `siloscan review` to scan a real
`./review` entry violates the map's explicit-invocation rule.

Use one narrow compatibility parser before the normal v2 parser. When
`./review` exists, try the complete argument list against the v1 scan-only
grammar. If that parse succeeds with `review` as its path, run the scan. This
preserves scan options before and after the path, including forms such as
`siloscan --format json review` and `siloscan review --config FILE`. Apply the
same rule to `ss`.

If the v1 scan-only parse fails, continue with the normal v2 parser. The new
command is unambiguous when it has a second positional or a review-only flag:

```text
siloscan ./review          # scan the path named review
siloscan review .          # review the current project's latest report
siloscan review --live .   # open a live review of the current project
```

Do not list old scan flags by hand or add more filesystem-sensitive command
guessing. Reusing the v1 scan argument type is what keeps this guard complete as
the CLI evolves. Add compatibility tests with shared flags such as `--config`
and scan-only flags such as `--format`, on both sides of the `review` path and
for both binary names.

## Crate ownership

| Component | Owns | Must not own |
| --- | --- | --- |
| `siloscan-core` | Project evidence processing, config precedence, resolved scan setup, rule and baseline resolution, scan execution inputs, deterministic scan report | Clap, terminal state, presentation, process exits |
| `siloscan` | Clap grammar, command dispatch, human/JSON/SARIF selection, persistence call, stdout and stderr routing, exit codes | Duplicate setup rules, TUI event loop |
| `siloscan-tui` library | Snapshot loading, live/snapshot session boot from resolved inputs, terminal lifecycle, event loop, UI state and actions | CLI parsing, process exit, a second setup resolver |
| `siloscan-tui` binary | Its existing compatibility grammar and mapping into the TUI library request | TUI implementation or scan semantics |

The current split makes this change small. The CLI already owns the Clap parser
and scan dispatch, and both `siloscan` and `ss` compile that same entry point.
See [`main` dispatch](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan/src/main.rs#L341-L350)
and the [`ss` alias](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan/src/bin/ss.rs#L1-L2).

The TUI implementation is currently trapped in its binary target. Its
`main.rs` declares all UI modules, parses arguments, loads scan setup, initializes
the terminal, runs the event loop, restores the terminal, and exits the
process. See the current
[`siloscan-tui` entry point](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-tui/src/main.rs#L1-L145).
Move the reusable part behind one library entry point. Leave a thin standalone
binary that parses the old syntax and calls it.

### TUI library boundary

The library needs one small request enum and one fallible function. Exact names
can be settled by the `ResolvedScanPlan` prototype ticket, but the boundary is:

```rust
pub enum ReviewSession {
    SavedReport {
        report: PathBuf,
        source_base: PathBuf,
        config: Option<PathBuf>,
    },
    Live { plan: ResolvedScanPlan },
}

pub fn run(session: ReviewSession) -> Result<(), TuiError>;
```

The library must return errors. It must not call `process::exit`, print CLI
errors, or parse process arguments. It owns terminal initialization and must
restore the terminal before returning success or failure. Ratatui's documented
application flow follows the same order: initialize, run the app, restore, then
propagate the result. See the official
[Ratatui application tutorial](https://ratatui.rs/tutorials/counter-app/basic-app/)
and Crossterm's [raw-mode and alternate-screen contract](https://docs.rs/crossterm/0.29.0/crossterm/terminal/).

The sketch deliberately has no generic renderer trait, plugin hook, process
launcher, or new application crate. None is needed for two callers.

### Resolved scan setup

`siloscan-core` must be the semantic owner because both front ends already
depend on it. The default CLI scan and `review --live` must send their explicit
inputs to the same resolver and execute the resulting plan through the same
scan path. The standalone TUI maps its existing arguments to that resolver too.

The current TUI independently loads config, rules, and a baseline before
starting a scan. Its scan worker then constructs a separate `ScanOptions`
without the CLI's coverage or cache setup. See
[`boot_live`](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-tui/src/main.rs#L124-L146)
and [`spawn_scan`](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-tui/src/app.rs#L43-L79).
The CLI has its own fuller setup path. See
[`run_scan`](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan/src/main.rs#L422-L469).
Keeping both is how config anchoring, cache, baseline, and later project
detection drift. v2 should remove the TUI-owned setup copy rather than teach it
the same rules again.

This ticket fixes ownership, not the exact public shape. The
`ResolvedScanPlan` prototype should choose the concrete core API and show how it
derives today's `ScanOptions` without changing any engine.

Snapshot review is different. It reads a completed report and does not resolve
or execute a scan. The CLI asks the persistence component for the exact latest
report path and the source base for paths inside that report, then passes both
to the TUI library. This matters when `siloscan review PATH` runs outside the
project and when a config-anchored report uses the config root rather than the
caller's current directory. The saved-report ticket owns how v2 persists and
recovers that base. The current report records no scan root, and snapshot boot
therefore uses `.` for source context. See the
[snapshot format note](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-tui/src/snapshot.rs#L18-L19)
and [snapshot boot](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-tui/src/main.rs#L148-L172).
For an arbitrary legacy `--report FILE`, use the explicit config directory when
the report says its paths are config-anchored. If no base can be derived, keep
the current working directory as the compatibility fallback.

## Stdout, stderr, and exit status

| Path | Stdout | Stderr | Exit status |
| --- | --- | --- | --- |
| Human scan | Existing human renderer and the v2 human summary | Warnings and diagnostics | Existing 0, 1, or 2 contract |
| JSON scan | Exactly one JSON document | Warnings, save status, and diagnostics | Existing 0, 1, or 2 contract |
| SARIF scan | Exactly one SARIF document | Warnings, save status, and diagnostics | Existing 0, 1, or 2 contract |
| Saved snapshot review | Alternate-screen TUI only | Setup or terminal errors after restoration | 0 on normal close, 2 on setup failure |
| Live review | Existing live TUI | Setup or terminal errors after restoration | Preserve current live-TUI behavior |

The integration must not print a report path, a project-detection banner, or a
review hint into JSON or SARIF stdout. It must not launch the TUI after a scan.
This keeps shell redirection and CI parsers valid. The separate summary and
saved-report tickets may choose exact human wording and stderr status, but they
cannot add a second value to machine stdout.

## Installation, publication, and archives

The package changes are limited to:

1. Add `src/lib.rs` to `siloscan-tui` and make its existing binary call that
   library.
2. Add the existing `siloscan-tui` package as a path-plus-version dependency of
   `siloscan`.
3. Publish in dependency order: `siloscan-core`, `siloscan-tui`, then
   `siloscan`.

`cargo install siloscan` continues to install the package's `siloscan` and `ss`
binaries. Both now contain review capability. It does not need to install the
standalone TUI binary. `cargo install siloscan-tui` still installs that binary
for existing users.

The release workflow can keep building both packages and keep the current
archive members: `siloscan`, `ss`, `siloscan-tui`, license files, and the
README. The existing Linux/macOS tar and Windows zip shapes therefore do not
change. See the current
[build and archive steps](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/.github/workflows/release.yml#L65-L145).
Those steps package the executables but do not extract or run the resulting
archives. v2 must add that missing archive-level smoke gate rather than claim it
already exists. The current CI smoke command runs an unarchived Windows debug
binary only. See the
[Windows smoke step](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/.github/workflows/ci.yml#L38-L76).

Only the crates.io publication order changes from its current core, CLI, TUI
order. See the current
[publish step](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/.github/workflows/release.yml#L210-L229).
Verify the interdependent package set together with Cargo's workspace package
mode, which accounts for interdependent selected packages when it generates
their lockfiles. See the official
[Cargo package contract](https://doc.rust-lang.org/cargo/commands/cargo-package.html).
Separate dry runs cannot resolve same-version dependencies that none of the dry
runs uploads. During the real publish, wait for or verify each crate's
registry-index entry before publishing the next dependent crate.

Linking the TUI into `siloscan` and `ss` will increase those executable and
archive sizes. It must not initialize terminal code on any scan path. The
compatibility oracle must measure cold and warm scan time and peak RSS after
the link change. A repeated result over the map's 5 percent limit rejects the
candidate. Do not trade scan performance for installation convenience.

## Rejected alternatives

| Alternative | Reason for rejection |
| --- | --- |
| Spawn `siloscan-tui` from `siloscan review` | Cargo does not install dependency binaries. This still requires a second install and adds executable discovery and version-skew failures. |
| Move all TUI code into the `siloscan` package | This breaks `cargo install siloscan-tui`, changes package ownership, and does more work than adding a library target. |
| Move terminal code into `siloscan-core` | Core would gain Ratatui and Crossterm concerns, and every core consumer would inherit a terminal dependency. |
| Make `siloscan-tui` depend on a new CLI library while the CLI depends on the TUI | This creates a cycle or forces a new shared package. Core already exists as the common semantic owner. |
| Add a new application or orchestration crate | It adds a package, publication step, and API boundary without removing any required dependency. |
| Automatically open review after scanning | It breaks non-interactive use, machine output, and predictable exit behavior. |
| Reimplement a smaller reviewer in the CLI | It duplicates the existing snapshot reader, state model, actions, and rendering, then immediately creates parity work. |

## Acceptance contract for this seam

Implementation is acceptable only when all of these hold on the same candidate
commit:

- A clean `cargo install siloscan` provides working `siloscan`, `ss`,
  `siloscan review`, and `ss review` with no second install.
- Every existing `siloscan` and `ss` scan, baseline, test, and cache CLI test
  remains green.
- `siloscan --format json` and `siloscan --format sarif` each write one parseable
  document to stdout, with no review or persistence prose mixed in.
- `siloscan review`, `review PATH`, and `review --report FILE` select the intended
  saved report and never rescan.
- `siloscan review --live [PATH]` and `siloscan-tui [PATH]` derive equivalent
  live scan setup from the same core resolver.
- All current snapshot compatibility tests pass through both `siloscan review
  --report` and `siloscan-tui --report`.
- The exact `siloscan-tui` help, version identity, live workflow, snapshot
  workflow, and interactive actions remain available.
- The `./review` compatibility parser has tests for `siloscan` and `ss`, shared
  flags, scan-only flags, and flags on either side of the path.
- One `cargo package --locked --workspace` verification succeeds for the
  interdependent package set. The real publish follows core, TUI, CLI order and
  verifies each registry-index entry before continuing.
- Release archives for Linux x86-64 musl, macOS arm64, and Windows x86-64 keep
  all three executable names. Each archive is extracted and all three packaged
  executables pass an archive-level smoke command.
- The black-box compatibility oracle reports no feature difference and no
  repeated cold-time, warm-time, or peak-RSS regression over 5 percent.

## Implementation order handed to the plan

1. Freeze the compatibility oracle before moving code.
2. Add the TUI library entry point and make the standalone binary a wrapper,
   with no behavior change.
3. Implement the shared core plan resolver chosen by the plan prototype and
   move live TUI setup onto it.
4. Add the `siloscan-tui` library dependency and `Review(ReviewArgs)` dispatch
   to the CLI.
5. Connect latest-report lookup from the saved-report decision.
6. Update publication order, package checks, archive smoke tests, and user docs.
7. Run the complete feature and performance oracle. Keep v1 behavior until the
   candidate passes.

## Sources

Repository evidence is pinned to
[`880d211a463e97eb3c188f957e5592d88f36dcf8`](https://github.com/RandomCodeSpace/siloscan/tree/880d211a463e97eb3c188f957e5592d88f36dcf8).

- [Cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html)
- [Cargo targets](https://doc.rust-lang.org/cargo/reference/cargo-targets.html)
- [Cargo dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
- [Cargo package](https://doc.rust-lang.org/cargo/commands/cargo-package.html)
- [Cargo publish](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)
- [Clap derive reference](https://docs.rs/clap/4.6.5/clap/_derive/)
- [Clap argument groups and conflicts](https://docs.rs/clap/4.6.5/clap/builder/struct.ArgGroup.html)
- [Ratatui basic application flow](https://ratatui.rs/tutorials/counter-app/basic-app/)
- [Crossterm terminal contract](https://docs.rs/crossterm/0.29.0/crossterm/terminal/)
