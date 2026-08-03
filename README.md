# siloscan

[![CI](https://img.shields.io/github/actions/workflow/status/RandomCodeSpace/siloscan/ci.yml?branch=main&style=for-the-badge&label=CI&logo=github)](https://github.com/RandomCodeSpace/siloscan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-v1-brightgreen?style=for-the-badge)](https://github.com/RandomCodeSpace/siloscan/issues/1)

A universal, rule-based static code scanner. Quick, deterministic, fully offline.

siloscan walks a directory tree, applies declarative YAML rules to every text
file, and reports findings with stable fingerprints. No server, no daemon, no
network access, no machine learning - the same input always produces the same
output, byte for byte.

## Features

- **Four rule domains**: `regex:` and `secret:` rules work on any text file in
  any language; `ast:` (tree-sitter structural queries) and `boundary:`
  (architecture rules) cover ten tier-1 languages: Rust, Python, JavaScript,
  TypeScript, Go, Java, C, C++, C#, Ruby. `coverage:` rules gate on parsed
  test-coverage reports (lcov / cobertura).
- **Batteries included**: a default secrets ruleset (derived from the MIT
  gitleaks rules, see NOTICE) is embedded in the binary; `--no-default-rules`
  opts out.
- **Brownfield-ready**: `siloscan baseline` records existing findings as
  accepted debt; from then on only new findings fail the build. Inline
  `siloscan-ignore` comments handle per-site exceptions.
- **Architecture boundaries**: declare named silos in `siloscan.toml`; boundary
  rules flag direct cross-silo imports, resolved against the scanned tree.
- **Interactive TUI**: `siloscan-tui` - dashboard charts, filterable triage
  board with code context, a ratchet console for per-finding debt decisions,
  and a silo dependency matrix. Mouse and keyboard.
- **Deterministic**: canonical finding order (path, line, column, rule id);
  warm and cold cache runs produce byte-identical output.
- **Offline**: static binaries. Nothing is fetched, ever.
- **Ignore-aware**: respects `.gitignore` and `.ignore`, skips binaries and
  non-UTF-8 files.
- **Stable finding identity**: SHA-256 fingerprints survive unrelated line
  drift and feed baselines and SARIF `partialFingerprints`.

## Install

```sh
cargo install siloscan        # scanner (binaries: siloscan and ss)
cargo install siloscan-tui    # interactive TUI
```

Prebuilt binaries (Linux musl, macOS, Windows) are attached to
[GitHub releases](https://github.com/RandomCodeSpace/siloscan/releases).
`ss` is a short alias binary for `siloscan` - note it shadows the iproute2
socket-statistics tool if `~/.cargo/bin` precedes `/usr/bin` in your PATH.

## Usage

```sh
siloscan .                          # scan with the embedded secrets ruleset
ss . --rules ./rules                # add your own rules (ss = same binary)
siloscan . --format json            # machine-readable
siloscan . --format sarif           # GitHub code scanning
siloscan . --fail-on warning        # tighten the gate
siloscan baseline .                 # accept current findings as debt
siloscan test ./rules/fixtures      # verify rules against annotated fixtures
siloscan . --coverage-report cov.lcov
siloscan-tui .                      # interactive triage
```

Exit codes: `0` clean, `1` new findings at or above the `--fail-on` threshold
(default `error`), `2` usage, config, or rule-load error. Baselined and
suppressed findings are reported but never fail the build.

## Rule schema

Every rule shares one envelope and carries exactly one payload:

```yaml
version: 1
rules:
  - id: secrets.example            # lowercase dotted id, globally unique
    severity: error                # error | warning | info
    message: "shown with each finding"
    paths:
      exclude: ["**/testdata/**"]
    secret:
      pattern: "(?i)key(.{0,20})?([a-z0-9]{20,})"
      group: 2
      entropy: 3.5
      keywords: [key]
      allowlist:
        stopwords: [example]

  - id: debug.print-statement
    severity: info
    message: "debug print left in code"
    ast:                           # per-language tree-sitter queries
      rust: |
        (macro_invocation
          macro: (identifier) @m
          (#eq? @m "dbg")) @report
      python: |
        (call function: (identifier) @f (#eq? @f "print")) @report

  - id: arch.core-no-web
    severity: error
    message: "core must not depend on web"
    boundary:
      from: core                   # silos declared in siloscan.toml
      deny: [web]

  - id: quality.min-coverage
    severity: warning
    message: "coverage below threshold"
    coverage:
      min: 80
```

```toml
# siloscan.toml - discovered walking up from the scan root
[silos]
core = ["crates/core/**"]
web  = ["crates/web/**"]
```

Unknown keys, duplicate ids, invalid patterns, and unknown silo names are load
errors - rules fail loudly, never silently.

## Suppression and baselines

```text
let key = load();        // siloscan-ignore-line: secrets.example
// siloscan-ignore: debug.print-statement
print(diagnostics)
```

`siloscan baseline .` writes `.siloscan/baseline.json` (check it in). Only an
explicit re-baseline updates it; the ratchet only tightens. The TUI's ratchet
console makes these decisions per finding.

## Architecture

Cargo workspace: `siloscan-core` (library: walker, loader, four engines,
semantic graph, cache, baseline, outputs), `siloscan` (CLI, also built as
`ss`), `siloscan-tui` (ratatui interface). Grammars sit behind per-language
cargo features (`lang-all` by default). The incremental cache
(`.siloscan/cache/`, content-hash keyed) keeps rescans fast; `--no-cache`
bypasses it.

The full design record - every decision with its alternatives - lives in the
[planning map](https://github.com/RandomCodeSpace/siloscan/issues/1).

## License

MIT. See [LICENSE](LICENSE). The embedded secrets ruleset is derived from
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT); see [NOTICE](NOTICE).
