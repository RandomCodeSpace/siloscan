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
  names the rule and the missing input rather than silently passing. Exception:
  a coverage rule in a subdirectory scan whose report file exists but names
  none of the scanned files is not an error (the gate did not run), and a
  warning is emitted instead.

## Release notes

### v1.5.0

**Generic secret rules rebuilt against a detection corpus.** The pack shipped
three generic secret rules through 1.4.1 - `secrets.generic-credentialed-url`,
`secrets.aws-secret-access-key` and `secrets.generic-secret-assignment` - and
ships six now. The three new ones are `secrets.generic-password-assignment`
(short passwords, 8 to 19 characters), `secrets.generic-authorization-header`
(`Authorization: Bearer` and `Basic` outside a curl command) and
`secrets.generic-markup-config-secret` (XML `<password>` elements and .NET
`appSettings` attribute pairs). All six were rebuilt by measuring them against a
committed detection corpus of real-shaped credentials and false positives. Rule
changes must be validated against this corpus going forward. The corpus lives in
`crates/siloscan-core/tests/corpus/` and the harness that evaluates rules
against it is in `crates/siloscan-core/tests/detection_corpus.rs`.

Before this release the generic rules were tuned in a single pass against no
corpus, and the defects that produced were structural rather than incidental:
an allowlist entry reading `^[A-Za-z0-9/+]{40}$` dropped every credential
exactly forty characters long, a password containing `!` or `(` was
undetectable, the canonical `scheme://:password@host` form was never reported,
and a case-folded character class made a value both continue and terminate at
the letter `k`, so one credential reported twice at two different lengths. Each
of the first three is a corpus row now, with the justification beside it; the
fourth is fixed by turning case folding off for the two character classes it
applied to, and is argued in `rules/default/generic.yaml`.

**Cache directory creation and permission handling.** On Unix every directory
the cache creates - the per-user root and the per-scan-root directory inside it
- is created with mode 0700 and chmod'ed to 0700 immediately afterwards, so the
process umask can no longer decide who else may read the cache. A cache is an
inventory of a private tree: paths, rule ids, line and column, and the byte
length of every secret found. On Windows the cache sets no modes; it relies on
the per-user profile directory, and the salt lives in an NTFS alternate data
stream so a copied or checked-out cache carries none.

An in-tree cache directory (legacy `.siloscan/cache/`) is never read or
written; an old entry can be safely deleted. A cache directory owned by another
user is rejected and nothing in it is read, written or repaired. One of ours
that grants anything to group or other is tightened back to 0700, its salt is
deleted - everything written while it stood open is unauthenticatable, which is
the point - and that run goes cold. The salt file (`.salt`) is accepted only
when it is owned by this process's effective uid, is at mode 0600, and parses
as the hex it was written as; a cache moved between systems or users is safely
invalid, not silently reused.

**`--min-severity` now visible in human output and the TUI.** The threshold is
printed as a line in plain-text output and displayed in the TUI summary so the
user can see what was filtered. In JSON and SARIF, the key `min_severity` and
`siloscan/minSeverity` respectively records what was withheld, allowing a
consumer to distinguish a report that filtered findings from one that had none
to filter.

**Improved generic secret detection.** The rebuilt rules detect a wider range of
assignments to secret-like names, including values with special characters,
passwords of 8 to 19 characters, `Authorization` headers outside a curl
command, XML `<password>` elements, .NET `appSettings` pairs, and credentialed
URLs with no username. The [Detection coverage](#detection-coverage) section
carries the recall and precision the corpus measures, and the limitations that
remain.

### Upgrading from 1.3.0

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
# siloscan.toml - discovered walking upward from the scan root and stopping at
# the first .git (repository boundary) or at the filesystem root, whichever
# comes first
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

Since 1.4.0 the pack also carries hand-written generic rules, which cover the
ground `generic-api-key` did with narrower patterns. There were three of them
through 1.4.1 and there are six since 1.5.0:

| Rule | Severity | Matches |
| --- | --- | --- |
| `secrets.generic-credentialed-url` | `error` | a password inside a `scheme://user:pass@host` URL, username optional |
| `secrets.aws-secret-access-key` | `error` | a 40-character AWS secret beside an AWS-secret identifier |
| `secrets.generic-secret-assignment` | `warning` | a high-entropy value of 20 to 128 characters assigned to a secret-like name |
| `secrets.generic-password-assignment` | `warning` | a value of 8 to 19 characters assigned to a `pass`, `password` or `passphrase` name |
| `secrets.generic-authorization-header` | `warning` | a hardcoded `Authorization: Bearer` or `Basic` credential |
| `secrets.generic-markup-config-secret` | `warning` | an XML `<password>` element or a .NET `appSettings` `key=`/`value=` pair |

The first two match a specific shape and ship at `error`. The other four are
heuristics - they match on the shape of the assignment, not on the credential -
and ship at `warning` so they stay out of the default `--fail-on error` gate.
Severity is an upgrade contract: a new rule at `error` would fail the first
build after an upgrade against a baseline whose fingerprints could not cover it.

A generic rule does not fire on a value another rule already names: one
credential is one finding, so a `ghp_` literal is `secrets.github-pat` and
nothing else. Three overlaps are the exception, because an allowlist is matched
against the captured value and cannot see the rest of the line: an AWS secret
access key and a Cloudflare API key are both a bare 40-character run with
nothing in the value to recognise, and `secrets.curl-auth-header` is told apart
from `secrets.generic-authorization-header` only by the word `curl` beside it.
Each is a second report of a credential that was already reported, and each is
pinned by a test in `crates/siloscan-core/src/default_pack.rs`.

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

## Detection coverage

The siloscan pack detects vendor-prefixed credentials extremely well. Tokens
from GitHub, AWS, Google, Azure, Stripe, and a dozen other major vendors carry
prefixes that uniquely identify them, and the patterns for these are high-fidelity
and vendor-specific. These rules ship at `error` severity and rarely produce false
positives.

The generic secret detection rules in this release are measured against a
committed corpus of real-shaped credentials and false positives. The rules use
entropy thresholding (2.5 to 4.2 bits per byte depending on rule), keyword
matching (at least one keyword must be present), and allowlisted patterns to
reduce false positives.

Measured, on `cargo test -p siloscan-core --test detection_corpus`:

    recall     0.9884  (170 of 172 positives reported, floor 0.95)
    precision  1.0000  (121 of 121 negatives left alone, floor 1.00)

Recall is over lines the corpus manifest marks as credentials; the precision
number is a proxy over lines it marks as things the pack must leave alone, each
justified individually in `manifest.tsv`. The two misses are a `.netrc`
password written into a Docker image layer and a connection-string password
that spells `password`. Off the corpus, the same pack over 1.8 GB of published
Rust and C source in a cargo registry reports 4 lines under
`secrets.generic-password-assignment` and 77 under
`secrets.generic-secret-assignment`; the 1.4.1 pack reported 324 and 569 on the
same tree.

Details of what is detected:
- **Secret assignment detection** (generic-secret-assignment rule): High-entropy
  values (3.4+ bits per byte) assigned to names containing keywords like
  `password`, `secret`, `token`, `api_key`, etc. Value length is 20 to 128
  characters. Excludes placeholder patterns and known vendor-prefixed formats.
- **Password assignment detection** (generic-password-assignment rule): values
  of 8 to 19 characters (2.5+ bits per byte, which is 2.5 of a possible 3.0 at
  eight characters) assigned to a `pass`, `passwd`, `password` or `passphrase`
  name. Excludes values with no digit, numeric literals and identifiers.
- **Credentialed URL detection** (generic-credentialed-url rule): Credentials
  embedded in URLs of the form scheme://username:password@host, including the
  empty-username `redis://:password@host` form Redis and AMQP document.
  Minimum password length is 6 characters. Requires a URL scheme keyword (://)
  to be present.
- **Authorization header detection** (generic-authorization-header rule):
  `Authorization: Bearer <token>` and `Basic <base64>` written anywhere - a Go
  `req.Header.Set`, a Java constant, a Kubernetes env value, a YAML config, a
  Python string. Inside a curl command `secrets.curl-auth-header` reports it
  too.
- **Markup and .NET configuration** (generic-markup-config-secret rule):
  `<password>value</password>` elements and `<add key="ApiKey" value="..." />`
  attribute pairs, where the name and the value sit in different places.
- **AWS secret key detection** (aws-secret-access-key rule): AWS secret access
  keys identifiable by context (aws/secret keywords) and 40-character base64
  value shape. Entropy threshold 4.2 bits per byte.

Known limitations of the generic rules:
- **Passwords under 6 characters in URLs**: the credentialed-url rule requires
  6+ character passwords. Shorter ones are not detected.
- **Passwords under 8 characters in assignments**: no generic rule accepts a
  value shorter than eight characters. Shannon entropy over bytes cannot exceed
  log2(length), so below that a value carries no evidence of its own and the
  identifier alone is not enough.
- **All-letter passwords in assignments**: a value with no digit at all is not
  reported by the assignment rules. At these lengths it is overwhelmingly a
  word, a path fragment or an identifier, and it is the cheapest thing standing
  between the rules and every `password = someIdentifier` in a real tree.
- **Low-entropy strings**: values below the rule's floor are not reported even
  if keywords are present. This is by design to reduce false positives on
  placeholder values.
- **Passwords with certain special characters**: the assignment rules capture a
  value up to its first backtick, quote, whitespace, `;`, `,`, `:`, bracket,
  brace, parenthesis, `<`, `>`, `|`, `?`, backslash or non-Latin letter. A
  password containing one of those is reported at the shortened span, or - when
  fewer than eight characters precede it - not reported at all. `:` is
  excluded from the value class because in source it is scope resolution:
  admitting it turned every `Type::method` on a secret-like name into a
  finding, 474 of them in one cargo registry.
- **Credentials without nearby keywords**: the secret rules require at least one
  keyword (password, secret, token, api_key, etc.) to be present near the
  match. A high-entropy value without context will not be reported.

The pack is deliberately narrow. A real deployment will need rules tailored to
your own credentials, frameworks, and deployment methods - configuration
management tools, CI/CD systems, cloud SDKs - that these generic rules do not
and cannot see. Use the rule schema in the documentation to build them, and the
`siloscan test ./rules` harness to validate them against your own fixture
corpus before committing them.

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
