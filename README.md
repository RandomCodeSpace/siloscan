# siloscan

[![CI](https://img.shields.io/github/actions/workflow/status/RandomCodeSpace/siloscan/ci.yml?branch=main&style=for-the-badge&label=CI&logo=github)](https://github.com/RandomCodeSpace/siloscan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-phase_1_of_4-yellow?style=for-the-badge)](https://github.com/RandomCodeSpace/siloscan/issues/1)

A universal, rule-based static code scanner. Quick, deterministic, fully offline.

siloscan walks a directory tree, applies declarative YAML rules to every text
file, and reports findings with stable fingerprints. No server, no daemon, no
network access, no machine learning - the same input always produces the same
output, byte for byte.

## Features

- **Universal**: regex and secret rules work on any text file in any language.
  Structural (AST) and architecture-boundary rules cover a tiered set of
  languages (planned: Rust, Python, JavaScript, TypeScript, Go, Java, C, C++,
  C#, Ruby).
- **Deterministic**: findings are sorted canonically (path, line, column,
  rule id); parallelism never changes output.
- **Offline**: a single static binary. Nothing is fetched, ever.
- **Ignore-aware**: respects `.gitignore` and `.ignore`, skips binaries
  (NUL detection) and files that are not valid UTF-8.
- **Stable finding identity**: every finding carries a SHA-256 fingerprint that
  survives unrelated line drift - the foundation for baselines and ratchet
  gating on existing codebases.

## Install

```sh
cargo install --git https://github.com/RandomCodeSpace/siloscan siloscan
```

Prebuilt binaries and a crates.io release arrive with v1.

## Usage

Write a rule file:

```yaml
# rules/no-todo.yaml
version: 1
rules:
  - id: hygiene.no-todo
    severity: warning
    message: "TODO left in code"
    regex:
      pattern: "(?i)\\bTODO\\b"
```

Scan:

```sh
siloscan . --rules ./rules
# src/main.rs:14:8 warning hygiene.no-todo TODO left in code

siloscan . --rules ./rules --format json   # machine-readable output
siloscan . --rules ./rules --fail-on warning
```

Exit codes: `0` clean, `1` findings at or above the `--fail-on` threshold
(default `error`), `2` usage or rule-load error.

## Rule schema

Every rule shares one envelope and carries exactly one payload
(`regex:` today; `secret:`, `ast:`, and `boundary:` are on the roadmap):

```yaml
version: 1
rules:
  - id: secrets.example        # lowercase dotted id, globally unique
    severity: error            # error | warning | info
    message: "shown with each finding"
    paths:
      exclude: ["**/testdata/**"]
    metadata:
      description: "longer explanation"
      tags: [example]
    regex:
      pattern: "..."           # Rust regex syntax, whole-file matching
      group: 1                 # optional: report this capture's span
```

Unknown keys, duplicate ids, and invalid patterns are load errors - rules
fail loudly, never silently.

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Substrate: walker, YAML rules, regex engine, fingerprints, CLI/JSON | this PR |
| 2 | Secrets engine, embedded ruleset, baseline/ratchet, SARIF | [planned](https://github.com/RandomCodeSpace/siloscan/issues/13) |
| 3 | tree-sitter AST rules, semantic graph, incremental cache | designed |
| 4 | Architecture boundary (silo) rules | designed |

The full design record - every decision with its alternatives - lives in the
[planning map](https://github.com/RandomCodeSpace/siloscan/issues/1).

## License

MIT. See [LICENSE](LICENSE).
