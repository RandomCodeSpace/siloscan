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

- **Five rule domains**: `regex:` and `secret:` rules work on any text file in
  any language; `ast:` (tree-sitter structural queries) and `boundary:`
  (architecture rules) cover ten tier-1 languages: Rust, Python, JavaScript,
  TypeScript, Go, Java, C, C++, C#, Ruby. `coverage:` rules gate on parsed
  test-coverage reports (lcov / cobertura).
- **Batteries included**: a default secrets ruleset (derived from the MIT
  gitleaks rules, see NOTICE) is embedded in the binary; `--no-default-rules`
  opts out. Three high-noise gitleaks rules are intentionally omitted due to
  regex complexity limits.
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
  non-UTF-8 files. Hidden files are scanned - `.env`, `.npmrc`, `.github/workflows/`
  are where secrets actually live.
- **Untrusted input handling**: the cache lives outside the scanned tree and
  entries are authenticated per directory. Symlinks are not followed. Paths
  named in config are contained to the config directory.
- **Stable finding identity**: SHA-256 fingerprints survive unrelated line
  drift and feed baselines and SARIF `partialFingerprints`.

## Install

```sh
cargo install siloscan        # scanner (binaries: siloscan and ss)
cargo install siloscan-tui    # interactive TUI
```

Prebuilt binaries are attached to
[GitHub releases](https://github.com/RandomCodeSpace/siloscan/releases) for
Linux musl, macOS arm64, and Windows x86-64. `ss` is a short alias binary for
`siloscan` - note it shadows the iproute2 socket-statistics tool if `~/.cargo/bin`
precedes `/usr/bin` in your PATH.

## Usage

```sh
siloscan .                          # scan with the embedded secrets ruleset
ss . --rules ./rules                # add your own rules (ss = same binary)
siloscan . --format json            # machine-readable
siloscan . --format sarif           # GitHub code scanning
siloscan . --fail-on warning        # tighten the gate
siloscan . --min-severity warning   # print less, without changing the gate
siloscan . --follow-symlinks        # read in-root symlink targets too
siloscan . --cache-dir /tmp/sscache # cache somewhere specific
siloscan baseline .                 # accept current findings as debt
siloscan test ./rules/fixtures      # verify rules against annotated fixtures
siloscan cache prune .              # drop stale entries now
siloscan . --coverage-report cov.lcov
siloscan-tui .                      # interactive triage
```

`--fail-on` and `--min-severity` do different jobs and are deliberately
independent. `--fail-on` decides the exit code, over everything the scan found.
`--min-severity` decides what gets printed, in every format and across all three
lists (`findings`, `baselined`, `suppressed`). Filtering the output can neither
turn a failing run green nor a green run red, and it moves no fingerprint.

Exit codes: `0` clean, `1` new findings at or above the `--fail-on` threshold
(default `error`), `2` usage, config, or rule-load error. Baselined and
suppressed findings are reported but never fail the build.

A scan that cannot be evaluated exits `2` rather than `0`. An empty report is
indistinguishable from a clean tree, so siloscan refuses cases where it would
produce one for the wrong reason:

- **No rules loaded**: `--no-default-rules` with no `--rules`, or `--rules`
  pointing at a directory holding no rule files. The error message names the
  rule directories searched and whether the built-in pack was in play.
- **A gate with no input**: A `coverage` rule with no `--coverage-report`,
  or a boundary rule with no `siloscan.toml` defining `[silos]`. The error
  names the rule and the missing input rather than silently passing.

## Upgrading from 1.3.0

**`metrics.duplicate-block` findings are off by default.** Duplication is still
measured and still reported - `metrics.files[*].duplicated_lines`, the totals
and the density are unchanged - but the per-copy locations are no longer emitted
as findings. They were emitted per copy of every duplicated block, so on a real
tree they outnumbered everything else by two or three orders of magnitude: 46,891
of 47,102 findings on one Rust codebase, a SARIF file too large for GitHub code
scanning to ingest, and every secret in the run buried under them.

Turn them back on either way:

```toml
# siloscan.toml
[duplication]
report_blocks = true
```

or by loading a `duplication:` rule, since gating on duplication is asking where
the duplication is:

```yaml
- id: quality.max-duplication
  severity: warning
  message: "duplication above threshold"
  duplication:
    max_percent: 5
```

Either way you get exactly the findings 1.3.0 produced, with the same
fingerprints, so an existing baseline still covers them.

**New generic secret rules.** The pack gained three; see
[Default secrets pack](#default-secrets-pack) for what they match. Two ship at
`error` and can fail a build that was green on 1.3.0, on findings no existing
baseline covers. Re-run `siloscan baseline .` to accept them as debt, or scan
once with `--min-severity` to read them before deciding.

**New `--min-severity` flag.** It decides what gets printed and never what gets
found, so it cannot turn a failing run green. When it is in play the threshold is
recorded in the report - `min_severity` in JSON, `siloscan/minSeverity` in the
SARIF run properties - so a consumer can tell a report that withheld findings
from one that had none to withhold. An unfiltered run carries neither key.

**Scan warnings reach the machine-readable formats.** What the scan narrowed and
why - a coverage report that landed on none of the files a subdirectory scan
walked, for instance - was previously only on stderr. It is now also the
`warnings` array in JSON and `invocations[].toolExecutionNotifications` in SARIF.
A run that narrowed nothing emits an empty `warnings` array and no `invocations`
at all.

**The cache moved out of the scanned tree.** See
[Cache location and authentication](#cache-location-and-authentication).

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
# siloscan.toml - discovered at the scan root or walking up to the nearest
# repository root (.git), from there up to filesystem root, then stopping
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

## Cache location and authentication

The cache lives outside the scanned tree to prevent a committed cache from
suppressing findings. Cache entries are stored under the invoking user's cache
directory:

- **Unix**: `$XDG_CACHE_HOME/siloscan` (or `$HOME/.cache/siloscan` if
  `XDG_CACHE_HOME` is unset)
- **Windows**: `%LOCALAPPDATA%\siloscan`

Within that directory, each scan root gets a subdirectory named by a hash of
its canonical absolute path. An in-tree `.siloscan/cache` is never read or
written.

Versions up to and including 1.3.0 kept the cache in the scanned tree at
`.siloscan/cache`. Since 1.4.0 that directory is ignored entirely; if an older
release left one behind, it is dead weight and can be deleted. `.siloscan/`
still holds the baseline, which is live and should be kept.

Use `--cache-dir DIR` to store entries in a specific directory instead. The
per-scan-root subdirectory still applies inside it, providing correctness
guarantees for scans of different roots that might share a cache directory.

Entries carry authentication tags computed with a per-directory salt. The salt
is derived solely from the operating system's random source (`/dev/urandom` on
unix, `getrandom` on other platforms). A tag that is absent, malformed, or
does not recompute is a cache miss - never an error, never a warning. A
committed cache or a moved cache costs a rescan rather than a wrong answer.

Where the OS random source cannot be reached, there is no salt at all: every
entry is a miss and every scan runs cold. A cold scan is a correct scan and is
the only safe direction to fail.

Entries are removed when they were written by a different build, and when
nothing has written them for 30 days. The second is what bounds the directory:
an entry is keyed by content, so every edit to a file abandons the entry for its
previous contents. The sweep runs after an upgrade and otherwise at most once a
month; `siloscan cache prune PATH` runs it on demand. Removing an entry that was
still wanted costs one file re-scanned once.

Use `--no-cache` to bypass the cache entirely.

## Symlinks

Symlinks are not followed by default, and **a link whose target is outside the
scan root is never followed, with or without a flag**. A scan that reads files
above its own root is a scan of the machine it ran on, and its result stops
being a statement about the tree under review.

Every link the walk meets is accounted for. The ones whose target the scan did
not read appear in the `skipped` array, each with the reason it was not read:

| Link | Target read? | In `skipped`? |
| --- | --- | --- |
| Target outside the scan root | no, refused | yes |
| Broken (target does not exist) | no | yes |
| Target could not be resolved | no | yes |
| Target inside the scan root | yes, on its own path | no |
| Directory containing the link | yes, on its own path | no |

The last two are the reason `skipped` stays worth reading. A link to a file
inside the scan root costs no coverage, because the walk reaches that file on
its own path anyway; listing it as skipped would claim the scan missed
something it read, and would bury the links that do cost coverage.

`--follow-symlinks` additionally reads an in-root target *through* the link, so
a file behind one is scanned twice and reported under both paths. That double
report is what following means, and it is why the flag is opt-in. Its use is
reaching a file the walk would not otherwise open - a link naming an ignored
path, say. It does not widen the scan past the scan root.

## Config path containment

Every path declared in `siloscan.toml` - including `rules`, `source_roots`,
and `include` - must resolve inside the config directory when all symlinks are
followed. Absolute paths are refused with an error at load time, and a path
that climbs out of the config root via `..` or lands outside via a symlink is
refused. An included config file inherits the same containment boundary from
its location.

This closes the path by which a repository could point the scan at rule
directories outside itself. Shared rule packs are passed on the command line
with `--rules`, which takes any path because the operator chose it.

## Default secrets pack

The embedded ruleset is derived from gitleaks v8.30.1 (MIT). Three rules are
intentionally omitted because their patterns exceed the Rust regex crate's
10 MiB size limit: `generic-api-key`, `pypi-upload-token`, and
`vault-batch-token`.

Since 1.4.0 the pack also carries three hand-written generic rules, which cover
the ground `generic-api-key` did with narrower patterns:

| Rule | Severity | Matches |
| --- | --- | --- |
| `secrets.generic-credentialed-url` | `error` | a password inside a `scheme://user:pass@host` URL |
| `secrets.aws-secret-access-key` | `error` | a 40-character AWS secret beside an AWS-secret identifier |
| `secrets.generic-secret-assignment` | `warning` | a high-entropy value assigned to a secret-like name |

The first two match a specific shape and ship at `error`. The third is a
heuristic - it matches on the shape of the assignment, not on the credential -
and ships at `warning` so it stays out of the default `--fail-on error` gate.
It does not fire on a value another rule already names: one credential is one
finding, so a `ghp_` literal is `secrets.github-pat` and nothing else.

There is no per-rule off switch. To silence one of these, use a
`siloscan-ignore` comment per site, `siloscan baseline .` for existing debt, or
`--no-default-rules` with a `--rules` directory of your own.

A narrower rule of your own looks like this:

```yaml
- id: secrets.high-entropy-token
  severity: warning
  message: "high-entropy string without obvious use"
  secret:
    pattern: '[a-f0-9]{64,}'
    entropy: 4.5
    keywords: [token, key, secret]
```

## Architecture

Cargo workspace: `siloscan-core` (library: walker, loader, five engines,
semantic graph, cache, baseline, outputs), `siloscan` (CLI, also built as
`ss`), `siloscan-tui` (ratatui interface). Grammars sit behind per-language
cargo features. The incremental cache keeps rescans fast; `--no-cache`
bypasses it.

The full design record lives in the
[planning map](https://github.com/RandomCodeSpace/siloscan/issues/1).

## Known limitations

- **Memory cost of large trees**: File contents are held in memory during
  scanning. Peak memory is roughly 6x the scanned source bytes.
- **Scanning below repository root**: A scan rooted below `.git` only sees
  ignore files at or below that root. A repository whose `.gitignore` sits at
  the top does not prune anything for `siloscan services/api`. Scan from the
  repository root instead, or call `siloscan --no-default-rules` and add rules
  with explicit `paths:` filters to control scope.
- **Windows behavior**: Cache authentication and symlink handling are implemented
  and unit-tested in CI but not manually exercised on Windows. Releases target
  `x86_64-pc-windows-msvc` only.
- **Config path discovery**: Config path containment stops at the declared
  config directory. The filesystem boundary is the config root; an ancestor
  config outside that directory is not consulted even if a `.git` marker would
  have brought the walk there.

## License

MIT. See [LICENSE](LICENSE). The embedded secrets ruleset is derived from
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT); see [NOTICE](NOTICE).
