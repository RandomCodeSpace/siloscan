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

- **Six rule domains**: `regex:`, `secret:` and `duplication:` (code duplication
  gates) rules work on any text file in any language; `ast:` (tree-sitter
  structural queries) and `boundary:` (architecture rules) cover ten tier-1
  languages: Rust, Python, JavaScript, TypeScript, Go, Java, C, C++, C#, Ruby.
  `coverage:` rules gate on parsed test-coverage reports (lcov / cobertura).
- **Batteries included**: a default secrets ruleset (derived from the MIT
  gitleaks rules, see NOTICE) is embedded in the binary; `--no-default-rules`
  opts out.
- **Brownfield-ready**: `siloscan baseline` records existing findings as
  accepted debt; from then on only new findings fail the build. Inline
  `siloscan-ignore` comments handle per-site exceptions. Baseline fingerprints
  are stable across module and repository scans via the `anchor` config.
- **Size and duplication metrics**: per-file line counts, code-line counts
  (tier-1 languages only), and duplicated-line counts; scan-wide totals.
  Deterministic metrics embedded in JSON reports.
- **Duplication detection**: language-agnostic normalized-line rolling-window
  matching; configurable minimum block size; reported as duplicate-block
  findings with 12-hex SHA-256 block identity. Block findings respect baselines
  and suppression like any finding.
- **Architecture boundaries**: declare named silos in `siloscan.toml`; boundary
  rules flag direct cross-silo imports, resolved against the scanned tree.
- **Multi-module support**: root config can include module-level configs; each
  module's silos, source roots and rules are merged and rebased to the root's
  convention. Enables per-module configuration without duplicate roots.
- **Interactive TUI**: `siloscan-tui` - dashboard with KPI cards and silo
  severity matrix, filterable triage board with code context, ratchet console
  for per-finding debt decisions, and silo dependency matrix. Snapshot mode
  loads JSON reports read-only. Mouse and keyboard.
- **Deterministic**: canonical finding order (path, line, column, rule id);
  warm and cold cache runs produce byte-identical output. Metrics and duplication
  blocks sort consistently.
- **Offline**: static binaries. Nothing is fetched, ever.
- **Ignore-aware, not blind**: respects `.gitignore` and `.ignore`, honored
  whether or not a `.git` directory exists. Hidden files and directories are
  scanned - `.env`, `.npmrc`, `.github/workflows/` and `.circleci/` are where
  secrets actually live - while version-control internals (`.git`, `.hg`,
  `.svn`, `.jj`, `.bzr`) and siloscan's own `.siloscan` state directory are
  excluded by name at any depth below the scan root. A dotfile listed in an
  ignore file stays ignored. Binaries and non-UTF-8 files are skipped.

> **Upgrading from 1.1.0**: hidden files are now scanned. A repository with a
> committed `.env`, `.npmrc`, or `.github/workflows/` will gain findings that
> earlier versions never looked for, and an existing baseline does not cover
> them - it was written before those files were walked. If those findings are
> accepted, run `siloscan baseline .` once and commit the result.
- **Stable finding identity**: SHA-256 fingerprints survive unrelated line
  drift and feed baselines and SARIF `partialFingerprints`. Duplication block
  identity is the normalized-line hash.

## Install

```sh
cargo install siloscan        # scanner (binaries: siloscan and ss)
cargo install siloscan-tui    # interactive TUI
```

`cargo install` works on any platform with a Rust toolchain and a C compiler;
see [Building from source](#building-from-source).

Prebuilt archives are attached to
[GitHub releases](https://github.com/RandomCodeSpace/siloscan/releases) for
three targets only, each with a matching `SHA256SUMS` file:

| Target | Archive |
| --- | --- |
| `x86_64-unknown-linux-musl` | `.tar.gz` |
| `aarch64-apple-darwin` | `.tar.gz` |
| `x86_64-pc-windows-msvc` | `.zip` |

Each archive carries `siloscan`, `ss`, `siloscan-tui`, `LICENSE`, `NOTICE` and
this README. Nothing is published for any other target - x86_64 macOS, aarch64
Linux and aarch64 Windows are `cargo install` only.

`ss` is a short alias binary for `siloscan` - note it shadows the iproute2
socket-statistics tool if `~/.cargo/bin` precedes `/usr/bin` in your PATH.

## Building from source

```sh
cargo build --release
```

- **Rust 1.96 or newer.** Declared as `rust-version` in the workspace manifest;
  older toolchains refuse the build.
- **A C toolchain on `PATH`.** The tree-sitter runtime and the ten bundled
  grammars ship C sources that are compiled by build scripts, so `cc` and `ar`
  (binutils) must be available. There is no prebuilt-grammar path.

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
siloscan-tui --report report.json   # load snapshot (read-only)
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

  - id: quality.too-much-duplication
    severity: warning
    message: "duplication density exceeds threshold"
    duplication:
      max_percent: 20           # 0 < max_percent <= 100
      scope: scan               # scan | file | silo
```

```toml
# siloscan.toml - discovered walking up from the scan root
[silos]
core = ["crates/core/**"]
web  = ["crates/web/**"]

# Optional: metrics configuration
[duplication]
min_lines = 10                # min_lines >= 2 (default 10)

# Optional: path anchoring
anchor = "config"             # "scan-root" (default) or "config"

# Optional: resource limits
[limits]
max_parse_bytes = 2097152     # default 2 MiB

# Optional: multi-module config (root-only)
include = ["modules/api/siloscan.toml"]
```

`[limits] max_parse_bytes` caps the size of any single file the scanner will
hand to a parser. A file larger than the cap is still read, still matched by the
regex and secret engines, and still measured; only its parse tree is skipped, so
it contributes no ast findings. Every such file is recorded in the report's
`skipped` array with a reason naming the limit, so the findings it could not
produce are never read as a clean file. The default is 2 MiB (2097152 bytes).

The cap has one exception: when a boundary rule is loaded, every file is parsed
regardless of size. The boundary engine resolves imports against the whole
graph, so a gated file is not a hole in its own results alone - an import
pointing at it stops resolving, and the violation the importing file really
commits goes unreported. A partial graph changes results for files nowhere near
the cap, so the graph is built whole and boundary scans do not honour the limit.

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
console makes these decisions per finding. Fingerprints remain stable across
module and repository scans when `anchor = "config"` is set.

## JSON report format

The `--format json` output includes a machine-readable findings array and
schema metadata:

```json
{
  "version": "1.1.1",
  "findings": [
    {
      "rule_id": "metrics.duplicate-block",
      "severity": "info",
      "message": "10 duplicated lines (block abc123456789)",
      "path": "src/main.rs",
      "line": 42,
      "column": 1,
      "matched": "10 duplicated lines (block abc123456789)",
      "fingerprint": "00f13c99a1d5c00060ab482949f6206276bf13a3410527de9dae109d6913d53d"
    }
  ],
  "baselined": [],
  "suppressed": [],
  "skipped": [],
  "schema_version": "1.2",
  "metrics": {
    "files": {
      "src/main.rs": {
        "lines": 150,
        "code_lines": 120,
        "duplicated_lines": 10
      }
    },
    "totals": {
      "lines": 500,
      "code_lines": 400,
      "duplicated_lines": 30,
      "duplication_density": 6.0
    }
  },
  "anchor": "scan-root"
}
```

The `schema_version` field declares the report contract version. It is
additive-only: a consumer unknown to version X but supporting version Y >= X
can read the report. Absent `code_lines` indicates a non-tier-1 language.
Duplicate-block findings carry the 12-hex normalized-block hash in the matched
text. The `anchor` key names the path convention all findings, skipped files,
and metrics keys use.

A finding from a secret rule reports `matched` as `<redacted>`: the credential
itself never reaches the report, in any of the three finding arrays. Its
`fingerprint` is unchanged - it is computed over the real matched text - so
baselines, suppressions and SARIF `partialFingerprints` written before the
redaction still identify the same occurrence.

`fingerprint` is a bare lowercase-hex SHA-256 digest - 64 hex characters, no
`sha256-` prefix or any other decoration - over the rule id, the path, the
whitespace-normalized matched text, and the occurrence index within the file.
Line and column are deliberately excluded, so edits above a finding leave its
fingerprint untouched.

## Known trade-offs

- **Memory cost of duplication detection**: file contents are held in memory
  during the cross-file normalized-line pass, so a very large tree still costs
  memory proportional to the text it contains. `[limits] max_parse_bytes` does
  not bound this - it gates parsing, not reading, and an oversized file still
  reaches the duplication pass. It does not bound parsing either when a boundary
  rule is loaded: the import graph has to be whole, so those scans parse past
  the cap.
- **Duplication block filtering**: findings respect ignore files (`gitignore`,
  `.ignore`) and inline suppression like any rule, but have no dedicated
  path-filter configuration separate from rule paths. A duplication rule with
  `paths.exclude` filters its blocks before they are reported, not per-block
  location.
- **Duplication scope and silos**: `scope: silo` requires silos to be declared
  in the config. Without a config, or with a config defining no silos, the scan
  refuses to run with an error naming the rule rather than reporting a passing
  gate.

## Architecture

Cargo workspace: `siloscan-core` (library: walker, loader, six engines,
semantic graph, cache, baseline, metrics, outputs), `siloscan` (CLI, also
built as `ss`), `siloscan-tui` (ratatui interface). Grammars sit behind
per-language cargo features (`lang-all` by default). The incremental cache
(`.siloscan/cache/`, content-hash keyed) keeps rescans fast; `--no-cache`
bypasses it, and `siloscan cache prune PATH` drops entries left behind by an
older build when no scan is coming to do it.

The full design record - every decision with its alternatives - lives in the
[planning map](https://github.com/RandomCodeSpace/siloscan/issues/1).

## Default pack coverage

The embedded secrets ruleset is derived from [gitleaks](https://github.com/gitleaks/gitleaks)
v8.30.1 (MIT); see [NOTICE](NOTICE) for full attribution.

Three high-noise gitleaks rules are intentionally omitted:
- `generic-api-key`: pattern's compiled regex exceeds the Rust regex crate's 10 MiB size limit
- `pypi-upload-token`: same regex size limit
- `vault-batch-token`: same regex size limit

If you need a generic high-entropy secret rule, write a `secret:` rule with a pattern
narrower than the gitleaks version, a minimal keyword requirement, or both. Example:

```yaml
- id: secrets.high-entropy-token
  severity: warning
  message: "high-entropy string without obvious use"
  secret:
    pattern: '[a-f0-9]{64,}'
    entropy: 4.5
    keywords: [token, key, secret]
```

## Scanner scope and ignore semantics

A scan reads the ignore files inside the tree it was pointed at, and no others.
`.gitignore` and `.ignore` files at or below `PATH` are honored, whether or not
a `.git` directory exists. Ignore files in parent directories, git's global
`core.excludesFile`, and `PATH/.git/info/exclude` are deliberately **not**
consulted.

That is a narrower rule than "files ignored in version control stay ignored in
the scan", and the difference is the point: the three sources left out all live
outside the tree under review. `core.excludesFile` belongs to whoever invoked
the scan, `.git/info/exclude` is per-clone and untracked, and a parent
directory's `.gitignore` is not part of the tree at all. Consulting them makes
the same commit scan differently on two machines. Leaving them out makes a scan
self-contained and reproducible.

**Behavior change from 1.1.1**: those three sources used to affect the walk and
no longer do. Each is recoverable with the matching `--respect-*` flag below.

### Scanning a subdirectory

The rule has a consequence worth stating plainly. A scan rooted below the
repository root only sees ignore files at or below that root, so a repository
whose `.gitignore` sits at the top does not prune anything for
`siloscan services/api`. The scan will descend into build output, `node_modules`,
`target/`, `vendor/` and anything else the root `.gitignore` would have
excluded - slower, and noisy with findings from code nobody wrote.

Three ways out, in the order worth trying:

- scan from the repository root and narrow with a rule's `paths` envelope or a
  silo config;
- put a `.gitignore` or `.ignore` inside the directory being scanned, which
  makes the exclusion part of the tree and therefore reproducible;
- pass `--respect-parent-ignores`, which restores the 1.1.1 behavior for this
  source and reintroduces its machine-dependence.

Every ignore source is a flag, on both `siloscan` and `siloscan-tui`:

| Flag | Effect |
| --- | --- |
| `--no-ignore` | Scan every file: no `.gitignore`, no `.ignore` |
| `--no-gitignore` | Ignore `.ignore` files but not `.gitignore` files |
| `--respect-parent-ignores` | Also honor ignore files above the scan root |
| `--respect-git-exclude` | Also honor `PATH/.git/info/exclude` |
| `--respect-global-gitignore` | Also honor git's global `core.excludesFile` |

The three `--respect-*` flags restore the 1.1.1 walk, one source at a time.
Each one makes the scan depend on something outside the tree it was pointed
at, which is why none is on by default, and why `--no-ignore` does not turn
them on either - "scan everything under the root" is not a reason to start
reading files above it.

When a boundary rule is loaded, a file over `[limits] max_parse_bytes`
(default 2 MiB) is not dropped and does not halt the scan. It is entered in the
import graph as a node with no imports of its own: imports *of* it still
resolve, so other files' violations are still reported, while the imports it
makes are not analysed. The skip is recorded per file in the report's `skipped`
array, with a reason naming the file's size and the cap. The reason names no
rule, because the decision is per file rather than per rule - the cap is a
property of the file, and the same file is skipped whichever rule wanted its
tree.

Binary files and non-UTF-8 files are detected and skipped. Every skipped file is
recorded in the report's `skipped` array with a reason, so findings are never
silently omitted.

### Skip reporting caps

The `skipped` array in the JSON report is never capped: it is the complete
record, and consumers that care read it there. The two human- and
tool-facing summaries are bounded, because an asset-heavy repository can skip
tens of thousands of files:

| Channel | Cap | Behavior past the cap |
| --- | --- | --- |
| CLI stderr | 10 individual `warning: skipped` lines | one `warning: ... and N more files skipped` line |
| SARIF `siloscan/skipped` | 100 entries | a `siloscan/skippedTruncated` count of the remainder |
| JSON `skipped` | none | every skipped file, always |

Both caps keep the head of a list the scanner already sorted by path, so the
sample and the count are identical across runs of the same tree.

## License

MIT. See [LICENSE](LICENSE). The embedded secrets ruleset is derived from
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT); see [NOTICE](NOTICE).
