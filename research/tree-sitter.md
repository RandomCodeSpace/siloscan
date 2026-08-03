# Research: tree-sitter in Rust — crates, grammar bundling, query surface

Ticket: RandomCodeSpace/siloscan#4
Date: 2026-08-03

## Question

Which crate stack should siloscan use for structural AST rules — the `tree-sitter`
crate directly vs the ast-grep core crates? How are many grammars bundled
(compiled-in vs cargo features), and what is the realistic binary-size and
compile-time cost at 10+ languages? How can tree-sitter queries (or ast-grep
patterns) surface in YAML rule files per language?

## Findings

### 1. Candidate crates (versions and licenses verified on crates.io, 2026-08-03)

| Crate | Latest | License | Last update | Notes |
|---|---|---|---|---|
| `tree-sitter` | 0.26.11 | MIT | 2026-07-12 | Rust bindings to the C library; 30M+ downloads |
| `tree-sitter-language` | 0.1.7 | MIT | 2026-02-01 | Tiny ABI crate shared by core and grammar crates |
| `ast-grep-core` | 0.45.0 | MIT | 2026-07-23 | Pattern-matching engine; 179 published versions |
| `ast-grep-config` | 0.45.0 | MIT | 2026-07-23 | YAML rule schema parser |
| `ast-grep-language` | 0.45.0 | MIT | 2026-07-23 | 26 bundled tree-sitter grammars behind features |

Both projects are actively maintained (releases within the last month as of
2026-08-03).

- tree-sitter repo: https://github.com/tree-sitter/tree-sitter
- ast-grep repo: https://github.com/ast-grep/ast-grep
- docs: https://docs.rs/tree-sitter/latest/tree_sitter/

### 2. Grammar bundling model

The ecosystem-standard model is compiled-in grammars:

- Each language is its own crate (`tree-sitter-python`, `tree-sitter-go`, ...)
  containing the generated `parser.c`, compiled by `cc` at build time and
  statically linked. Fully offline and deterministic — no runtime loading,
  matching siloscan's constraints. (A `wasm` feature on the core crate exists
  for dynamic grammar loading, but it adds a wasm runtime and is not needed.)
- Grammar crates depend on `tree-sitter-language` (0.1.7) rather than on the
  core crate, which decouples grammar releases from core version bumps.
  Verified in practice: grammar crates spanning `tree-sitter-java` 0.23.5
  through `tree-sitter-python` 0.25.0 all load into `tree-sitter` 0.26.11 in
  one binary.
- Feature gating: the established pattern (see `ast-grep-language`'s
  Cargo.toml, https://github.com/ast-grep/ast-grep/blob/main/crates/language/Cargo.toml)
  is one cargo feature per language, all enabled by default, plus an umbrella
  `builtin-parser` feature. Users who want a slim custom build disable default
  features and pick languages.
- Licensing: all 11 crates in the test build below are MIT (verified via
  `cargo metadata` against the resolved lockfile).

### 3. Measured cost at 10 languages

Measured locally for this ticket (x86_64 Linux, default `--release` profile,
no LTO or size tuning, binaries stripped):

| Configuration | Stripped binary | Clean release build |
|---|---|---|
| core + 3 grammars (python, javascript, rust) | 2.4 MB | ~12 s wall |
| core + 10 grammars (+ go, java, c, cpp, typescript, ruby, json) | 11 MB | ~12 s wall / 39 s CPU |
| ast-grep 0.45.0 official CLI (25+ grammars + full rule engine) | 49 MB | n/a (release artifact) |

- Target directory for the 10-grammar build: 129 MB.
- Compile time is a non-issue: grammar C files compile in parallel, so wall
  time barely moves between 3 and 10 languages on a multi-core machine.
  Absolute times depend on hardware; the ratio is the signal.
- Binary size is dominated by a few large parser tables (cpp and typescript
  are the heavy ones in the 10-language set). Realistic expectation for 10+
  languages: roughly 10-25 MB depending on grammar mix. The 49 MB ast-grep
  binary (measured from the 0.45.0 `x86_64-unknown-linux-gnu` release asset,
  8.25 MB zipped) is the upper reference point at 25+ languages plus a full
  CLI.
- Unverified: whether `opt-level = "z"` / LTO meaningfully shrinks parser
  tables (they are mostly static data, so likely only marginal gains).

### 4. Query surface, and how it maps to YAML rules

**tree-sitter queries** are S-expression strings executed via `Query` /
`QueryCursor` (https://docs.rs/tree-sitter/latest/tree_sitter/struct.Query.html).
Verified empirically on 0.26.11: text predicates (`#eq?`, `#match?`) are
evaluated automatically by the `matches` iterator when source text is
provided — a query for `(call function: (identifier) @fn (#eq? @fn "eval"))`
matched `eval(x)` and correctly skipped `print(y)`. Custom predicates surface
through `Query::general_predicates` for the host to interpret.

Queries embed naturally in YAML as per-language strings:

```yaml
id: no-eval
severity: error
message: "Use of eval"
languages:
  python:
    query: |
      (call function: (identifier) @fn
        (#eq? @fn "eval")) @finding
  javascript:
    query: |
      (call_expression function: (identifier) @fn
        (#eq? @fn "eval")) @finding
```

**ast-grep patterns** (https://astgrep.com/reference/yaml.html) are an
alternative surface: YAML rules with `id` / `language` / `rule`, where `rule`
supports pattern-by-example (`console.log($$$ARGS)` with metavariables),
`kind`, `regex`, and relational/composite operators (`inside`, `any`, `all`,
`not`), plus `severity` / `message` / `fix`. `ast-grep-config` parses this
schema; `ast-grep-core` executes it. Patterns are more ergonomic for rule
authors than raw S-expressions, but the semantics come from ast-grep's engine.

### 5. Recommendation

Use the `tree-sitter` crate directly, with grammar crates compiled in behind
one cargo feature per language (all on by default, `ast-grep-language` style).
Surface raw tree-sitter S-expression queries in siloscan's YAML rules under a
per-language key, as sketched above.

Rationale:

- Smallest dependency surface; the query language is a cross-tool standard
  (editors, highlighters, nvim) with an existing corpus of queries to crib
  from, and the measured cost at 10 languages (11 MB, ~12 s clean build) is
  comfortably acceptable for a static-analysis CLI.
- `ast-grep-core` would buy pattern-by-example ergonomics and a ready-made
  rule schema, but it couples siloscan's rule format to a fast-moving 0.x API
  (179 releases of `ast-grep-core`; all crates version-locked at 0.45.0) and
  imports ast-grep's rule semantics wholesale. Because ast-grep sits on the
  same tree-sitter grammars, it can be added later as an optional pattern
  engine without reworking the grammar layer — adopting it now is a one-way
  door on rule-file semantics; deferring it is not.

### 6. Open caveats

- Grammar crate quality and cadence are uneven: core-org grammars (python,
  go, javascript, ...) are well maintained; several languages ast-grep ships
  (kotlin, swift, solidity, hcl) come from third-party or forked grammar
  crates. Each language siloscan adds needs a per-crate maintenance and
  license check.
- `tree-sitter` core is pre-1.0; 0.x bumps can require coordinated grammar
  updates. `tree-sitter-language` mitigates but does not eliminate this. Pin
  exact versions.
- Size and time numbers above were measured on one x86_64 Linux machine with
  the default release profile; treat them as order-of-magnitude, not targets.
- Raw queries are written against per-grammar node kinds, so every rule is
  authored per language; there is no cross-language pattern abstraction. That
  is the trade accepted by not adopting ast-grep's pattern layer.

## Sources

- https://crates.io/crates/tree-sitter
- https://crates.io/crates/tree-sitter-language
- https://crates.io/crates/ast-grep-core
- https://crates.io/crates/ast-grep-config
- https://crates.io/crates/ast-grep-language
- https://docs.rs/tree-sitter/latest/tree_sitter/
- https://github.com/tree-sitter/tree-sitter
- https://github.com/ast-grep/ast-grep
- https://github.com/ast-grep/ast-grep/blob/main/crates/language/Cargo.toml
- https://astgrep.com/reference/yaml.html
- https://github.com/ast-grep/ast-grep/releases/tag/0.45.0 (binary measurement)
