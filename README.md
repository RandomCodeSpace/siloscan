<h1 align="center">siloscan</h1>

<p align="center">
  <strong>Scan repositories for secrets, risky patterns, architecture drift, coverage gaps, and duplicated code.</strong><br>
  Fast, deterministic, and fully offline.
</p>

<p align="center">
  <a href="https://github.com/RandomCodeSpace/siloscan/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/RandomCodeSpace/siloscan/ci.yml?branch=main&amp;style=for-the-badge&amp;label=CI&amp;logo=github"></a>
  <a href="https://crates.io/crates/siloscan"><img alt="Crates.io" src="https://img.shields.io/crates/v/siloscan?style=for-the-badge&amp;logo=rust"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge"></a>
  <a href="https://www.rust-lang.org"><img alt="Rust 1.96 or newer" src="https://img.shields.io/badge/MSRV-1.96-orange?style=for-the-badge&amp;logo=rust"></a>
</p>

<p align="center">
  <img src="assets/siloscan-hero.png" alt="Source files passing through a scanner into organized silos" width="100%">
</p>

Point siloscan at a repository and get a clear, ordered list of findings. It
ships with secret detection out of the box, accepts project-specific YAML
rules, and produces human-readable, JSON, or SARIF reports.

Everything runs on your machine. There is no account, server, daemon,
telemetry, or network call.

## Start scanning

Install the command-line scanner:

```sh
cargo install siloscan
```

Then scan the current repository:

```sh
siloscan .
```

That is enough to run the embedded secret rules. Add your own rules when you
need project-specific checks:

```sh
siloscan . --rules ./rules
```

Prefer a prebuilt binary? Download one from
[GitHub Releases](https://github.com/RandomCodeSpace/siloscan/releases).
Archives are published for Linux x86-64, macOS arm64, and Windows x86-64.

> [!NOTE]
> Installing `siloscan` also installs the short alias `ss`. On Linux, that
> can shadow the iproute2 socket-statistics command when Cargo's bin directory
> comes first in `PATH`.

## What it finds

| Check | Useful for |
| --- | --- |
| Secrets | Tokens, private keys, connection strings, and other credentials |
| Text patterns | TODOs, banned APIs, unsafe settings, and team conventions |
| Syntax-aware patterns | Matching code structure without fragile text searches |
| Boundaries | Preventing one repository area from importing a forbidden area |
| Coverage | Enforcing line-coverage targets from lcov or Cobertura reports |
| Duplication | Keeping repeated code below a project-defined budget |

Siloscan understands Rust, Python, JavaScript, TypeScript, Go, Java, C, C++,
C#, and Ruby for syntax-aware rules. Text and secret rules work with any UTF-8
text file.

## Add a rule

Rules are ordinary YAML files. This one reports TODO markers while ignoring
fixture files:

```yaml
version: 1
rules:
  - id: cleanup.todo-marker
    severity: warning
    message: "TODO left in source"
    paths:
      exclude: ["**/fixtures/**"]
    regex:
      pattern: '\bTODO\b'
      group: 0
      redact: false
```

Save it under `rules/`, then run:

```sh
siloscan . --rules ./rules
```

To check a rule against fixtures before using it in CI:

```sh
siloscan test ./rules/fixtures --rules ./rules --no-default-rules
```

Place `siloscan-expect: cleanup.todo-marker` on the line before an expected
fixture match. The test fails for both missing and unexpected findings.

## Keep existing debt under control

You do not have to fix an old repository in one heroic weekend. Record current
findings as the baseline:

```sh
siloscan baseline .
```

The baseline is written to `.siloscan/baseline.json`. Commit it when the
accepted debt should be shared by the team. Future scans still show that debt,
but only new findings fail the scan.

For a reviewed exception next to the code, suppress one rule on the current or
following line:

```text
let value = fixture(); // siloscan-ignore-line: cleanup.todo-marker

// siloscan-ignore: cleanup.todo-marker
TODO
```

Suppressed findings remain visible in JSON and the terminal UI instead of
quietly disappearing.

## Review findings in the terminal

Install and open the interactive UI:

```sh
cargo install siloscan-tui
siloscan-tui .
```

Use it to:

- see repository-wide counts and severity at a glance;
- filter findings and inspect nearby code;
- review baseline and inline-suppression decisions;
- explore duplication groups and dependencies between silos.

You can also open a saved JSON report without rescanning:

```sh
siloscan-tui --report siloscan.json
```

Snapshot mode is read-only. Live-mode actions that change a baseline or source
file require an explicit verdict.

## Use it in CI

Write JSON for automation or SARIF for code-scanning tools:

```sh
siloscan . --format json > siloscan.json
siloscan . --format sarif > siloscan.sarif
```

Control what fails and what gets printed independently:

```sh
siloscan . --fail-on warning --min-severity error
```

| Exit status | Meaning |
| --- | --- |
| `0` | No new finding reached the failure threshold |
| `1` | At least one new finding reached the threshold |
| `2` | The command, configuration, rules, or required input was invalid |

Reports use stable finding fingerprints and deterministic ordering, so results
remain useful in diffs and automation.

## Set repository defaults

Add `siloscan.toml` at the repository root when the team should share rule
paths, source roots, or architecture silos:

```toml
rules = ["rules"]
source_roots = ["src"]

[silos]
core = ["src/core/**"]
api = ["src/api/**"]
storage = ["src/storage/**"]
```

Command-line options can still override the scan for one run. Use
`siloscan --help` and `siloscan-tui --help` for the complete option list.

## Safe defaults

- Hidden files such as `.env` are scanned.
- Repository `.gitignore` and `.ignore` files are honored.
- Symlinks are not followed outside the scan root.
- Secret matches are redacted from serialized reports and the UI.
- The cache never stores matched secret text.
- Skipped, ignored, binary, and unreadable paths are accounted for in reports.

## Build and test

The workspace contains the scanner library, CLI, and terminal UI.

```sh
cargo build --locked --workspace
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

## Limits

- Generic secret rules favor fewer false positives. Add rules for private
  credential formats and deployment conventions.
- Boundary checks resolve imports inside the scanned file set; they are not a
  replacement for a compiler or build system.
- Binary and non-UTF-8 files are reported as skipped rather than treated as
  clean.
- Large files still receive text checks but may skip syntax-aware parsing,
  depending on the configured parse limit.

## License

Siloscan is available under the [MIT License](LICENSE). The embedded secret
pack is derived from [gitleaks](https://github.com/gitleaks/gitleaks), also
under MIT; see [NOTICE](NOTICE) for attribution.
