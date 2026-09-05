# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Seven gitleaks rules the converter used to skip: `secrets.freemius-secret-key`,
  `secrets.hashicorp-tf-password`, `secrets.kubernetes-secret-yaml`,
  `secrets.nuget-config-password`, `secrets.pkcs12-file`,
  `secrets.pypi-upload-token` and `secrets.vault-batch-token`. The translation
  now covers 221 of gitleaks v8.30.1's 222 rules; the one left out is
  `generic-api-key`, excluded on purpose because `rules/default/generic.yaml`
  covers the same ground more narrowly and importing it would report every
  credential they overlap twice. A Kubernetes Secret manifest is reported once,
  at the `kind:` line the match starts on.
- Presence rules: a rule with a `paths.include` and no payload reports the file
  existing at a matching path, at line 1, with the file's name as the match
  text. It reports binary and unreadable files too, which is the point for
  `secrets.pkcs12-file` - a committed keystore is a finding because of what it
  is, not because of anything readable inside it. A rule with no payload and no
  `paths.include` is a load error, as it was before.
- `paths.case_insensitive` on a rule's path envelope, applying to both
  `include` and `exclude`. Absent means false, so every existing rule keeps
  matching exactly what it matched.

### Changed

- Rule patterns compile under a 32 MiB program size limit rather than the
  `regex` crate's 10 MiB default, which is what admitted the two wide bounded
  repetitions above. `secrets.pypi-upload-token` and
  `secrets.vault-batch-token` are translated with `\w` spelled as its ASCII
  class `[0-9A-Za-z_-]`, which is what gitleaks means by `\w` and what keeps
  each program at 1 MiB and single-digit milliseconds to build.
- `secrets.nuget-config-password` reports its captured value rather than the
  whole `<add key=... />` element, so the upstream allowlist that stands down
  on `%ENVIRONMENT_VARIABLE%` placeholders applies, as it does in gitleaks.

## 2.2.0 - 2026-09-05

### Added

- Two predicates for ast rules, `(#has-descendant? @node "<sub-pattern>")` and
  `(#not-has-descendant? @node "<sub-pattern>")`, which keep or reject a match
  by whether the sub-pattern - a tree-sitter query in its own right, with its
  own `#eq?` and `#match?`, compiled once at load against the same grammar -
  matches inside the captured node's subtree. An optional third argument lists
  node kinds that stop the descent, so `(#not-has-descendant? @fn
  "(await_expression) @a" "arrow_function function_expression")` ignores an
  `await` that belongs to a nested function; an unknown predicate name, a wrong
  argument count, a sub-pattern that does not compile and an unknown stop kind
  are load errors that name the rule.
- One hundred and thirty-four profile rules, from the per-language pitfall
  lists and from a re-examination of candidates the 2.1.0 work had dropped.
  With the five removals below, the twenty embedded documents now carry 211
  rules rather than 82: 27 for JavaScript, 22 each for TypeScript and Go, 21
  each for Rust and C, 20 each for Java, C++, and Ruby, and 19 each for Python
  and C#. Every added rule was measured on its own language's pinned
  repositories with at least five of its findings read before it shipped. The
  policy it was measured against is 0.25 findings per kLOC for a `warning` rule
  and 1.0 for an `info` rule, on each pinned repository rather than across
  them, with one `paths` exclusion allowed to bring a rule under its ceiling
  before it is removed instead.
- `scripts/profile_noise.py --rules DIR`, repeatable, passes each directory
  through to the scan the harness runs, so a rule document that is not embedded
  yet is measured over the same 33 pinned repositories on the same terms as a
  shipped one. The directories appear in the command line the run records in
  its header, so a result file says what was measured.

### Changed

- `reliability.ruby.rescue-exception`, `reliability.ruby.rescue-modifier`,
  `reliability.rust.unimplemented-marker`, and
  `reliability.c.assignment-in-condition` are `info` rather than `warning`. A
  reliability rule is `warning` by default, and one whose measured noise is
  over the 0.25 warning ceiling but under the 1.0 info ceiling now ships as
  `info` rather than being removed, which is what these four measured. Eleven
  of the 211 rules are reliability rules at `info`. Nothing in either family is
  `error`, so no profile finding changes an exit status at the default
  threshold.
- `reliability-python`, `maintainability-python`, and `reliability-csharp` are
  loaded as `@2`; the other seventeen documents stay at `@1`. The identity is
  what the `rules:` line and `setup.rule_sources` report and what the cache
  keys on, so a cache entry written against the 2.1.0 document is not read
  against this one. `--profiles auto` and a bare run pick up the new identities
  by themselves; an explicit `--profiles reliability-python@1` no longer
  resolves, and exits `2` naming the identity and listing what is available.
- The pinned noise set is 33 repositories rather than 29, and every rule was
  re-measured over all of them. Go gains prometheus/client_golang v1.24.1,
  which is heavy in error handling where cobra and gin are 36 and 98 files of
  it; TypeScript gains mantine 9.6.0, because zod, rxjs, and nest carry no
  meaningful `.tsx` and React idioms could not be measured without it; C# gains
  dotnet/eShop dotnet8 for logging and service code three libraries do not
  have; and Python gains boto v2.13.2, a 2013 tree with no ruff configuration,
  because the rest of the pinned Python set is ruff-maintained and reads zero
  on a ruff-derived rule.
- The cold bare wall budget against the pinned v2.0.0 reference is 3.00 rather
  than 2.50. No build since the profiles flip has met 2.50 on the CI runners:
  the 2.1.0 candidates measured 2.62 to 2.83 and this candidate 2.63 to 2.99,
  with the spread between runners about a third within one run. A bare run
  parses every source file it admits and v2.0.0 parses none, so 3.00 states
  that cost in one number. No other lane changed: the warm bare lanes hold
  1.25, peak RSS holds 1.10 on all four bare lanes, and the explicit lanes hold
  1.05 against v1.5.1 on both metrics.

### Removed

- `reliability.python.bare-except`. 68 findings on boto v2.13.2, 0.8198 per
  kLOC against the 0.25 warning ceiling. Every finding read is a real bare
  `except:` in shipping library code, so the rule is right and the repository
  is simply pre-2015 Python; 50 of the 68 are under `boto/` itself, so
  excluding tests still leaves 0.7113 and no `paths` class carries the breach.
- `reliability.python.mutable-default-argument`. 24 findings on boto, 0.2893
  per kLOC, every one a genuine `=[]` or `={}` default. 16 are under `boto/`
  and 0.1929 per kLOC on their own, and excluding tests alone leaves 0.2652,
  still over the warning ceiling.
- `maintainability.python.parameter-count`. 239 findings on boto, 2.8812 per
  kLOC against the 1.0 info ceiling. The findings are not wrong, they are what
  a keyword-argument-per-API-field SDK looks like, and 211 of the 239 are under
  `boto/` itself at 2.5436 per kLOC on their own, so no path class carries the
  breach and a threshold high enough to accept boto would stop the rule saying
  anything on the other three Python repositories. Python is now the one
  language with no parameter-count rule.
- `reliability.csharp.async-void`. 8 findings on dotnet/eShop, 0.4113 per kLOC
  against the 0.25 warning ceiling. All eight are `async void` overrides of
  MAUI framework virtuals - `OnStart`, `OnAppearing`, `OnHandlerChanged`,
  `OnPropertyChanged`, `ApplyQueryAttributes` - or a `BindableProperty` changed
  callback. An override cannot change its return type, so the rule is asking
  for something the code cannot give, and every finding sits in `src/ClientApp`
  with no narrower path class inside it.
- `reliability.csharp.empty-catch`. 10 findings on eShop, 0.5141 per kLOC. Nine
  are the same `catch (InvalidOperationException) {}` around `AbortAnimation`
  in one file, `VisualElementExtensions.cs`. The catches are genuinely empty,
  but one file's idiom carries the whole breach and no `paths` class excludes
  it.

### Fixed

- A `.tsx` file is parsed with tree-sitter-typescript's TSX grammar rather than
  the plain TypeScript one. The two grammars are not a superset of one another
  - `<T>x` is a type assertion in `.ts` and the start of a JSX element in
  `.tsx` - so JSX used to be read as a broken type assertion, and error
  recovery from that misparse made every TypeScript ast rule, every metric and
  the import graph unreliable on React code. The grammar is chosen by
  extension; the language label stays `typescript` in reports, `--profiles
  auto`, metrics, corpus directories, and the noise harness, and no new
  language is selectable.

## 2.1.0 - 2026-09-04

### Fixed

- A `.h` file whose content is C++ is detected as `cpp` rather than `c`, so the
  C rules stop running over C++ headers. The content decides: after comments are
  removed, a line that opens `namespace `, `class `, `template<`, `template <`,
  `public:`, `private:`, `protected:`, or `extern "C++"` makes the file C++, and
  everything else stays C. Per-file metrics attribution and the `languages:`
  setup line change only for `.h` files that are C++.

### Added

- Twenty embedded profile documents, one per (family, language) pair, carrying
  82 rules across Rust, Python, JavaScript, TypeScript, Go, Java, C, C++, C#,
  and Ruby. A reliability rule reports code likely to be a bug and is
  `warning`; a maintainability rule reports code that is hard to work on and is
  `info`. Nothing in either family is `error`, so no profile finding changes an
  exit status at the default threshold. Each document is loaded under its own
  identity - `reliability-rust@1`, `maintainability-go@1` - which is what the
  `rules:` line and `setup.rule_sources` report and what the cache keys on.
- `--profiles <auto|none|LIST>` selects them: `auto` loads every document whose
  language the tree contains, `none` loads none, and a comma-separated list of
  identities loads exactly those whatever was detected. An identity with no
  document exits `2` and lists what is available. `--no-default-rules` still
  disables every embedded document, profiles included.
- A `profiles` capability on the setup report: `enabled` when a document
  loaded, `not_configured` when nothing was there to load, and `skipped` when
  `--no-default-rules` suppressed a selection that was asked for. A run that
  selects no profile carries no such capability, which is why an explicit
  invocation's report is still byte-identical to the one v1.5.1 wrote.
- A `metric:` rule payload, with `measure: function-length | parameter-count |
  nesting-depth | cyclomatic-complexity` and an integer `max`. It reports one
  finding per function-like node whose measure exceeds `max`, on the function's
  name so the fingerprint survives edits to the body, with the measured value
  and the threshold appended to the rule's message. Ten languages, and an
  optional rule-level `languages` filter. The maintainability profiles use it:
  function length 150 for C, Go, and JavaScript and 120 for Rust, Python, Java,
  and C#; parameter count 7; nesting depth 5; cyclomatic complexity 30 for C
  and 25 elsewhere.
- A profile corpus harness, `crates/siloscan-core/tests/profile_corpus.rs`,
  with a per-language recall floor, a per-rule false-positive limit measured
  against a pinned noise set, and load rules that refuse an unimplemented
  predicate or a severity above `warning`. Every threshold above was set from
  those measurements; 32 candidate rules were removed rather than tuned, each
  with its reason recorded in its document.

### Changed

- A bare `siloscan` loads the profiles for the languages it detected. Its
  `rules:` line now names those identities after `default-secrets@1`, its
  `capabilities:` line carries `profiles`, and its findings include profile
  results. An invocation that names a `PATH`, or supplies any scan option, is
  unchanged and loads no profile unless it asks with `--profiles`.
- The bare performance lanes are re-based on the pinned v2.0.0 reference, the
  last release whose bare run loads no profile, under a declared budget: wall
  time 2.50 on the cold lane and 1.25 on the warm ones, peak RSS 1.10 on all
  four. A bare run parses every source file it admits, which v1.5.1 does not do
  at all, so the old comparison measured the feature rather than a regression.
  The explicit lanes keep the pinned v1.5.1 reference at 1.05 on both metrics,
  because an explicit invocation is unchanged.
- `siloscan-core`: `CompiledPayload::Ast` carries `Vec<AstQuery>` rather than
  `Vec<(String, Arc<Query>)>`, so a rule's query source travels with its
  compiled query; `engines::ast::AstQueries` is new, and
  `engines::ast::scan_file` takes it as a second parameter.
- `siloscan-core`: `ScanReport::graph` is populated only when a boundary rule
  is loaded. A scan that parsed every file for its ast rules now leaves it
  empty, because the import facts had no reader.

### Performance

- The ast engine runs one tree-sitter query per language per file, holding
  every applicable rule's patterns, instead of one query - one full tree
  traversal - per rule.
- Import facts are extracted only for a scan with a boundary rule. Walking a
  parsed tree for them cost about as much as the parse itself.

## 2.0.0 - 2026-09-03

### Added

- A bare `siloscan`, with no path and no scan option, detects the project from
  repository files, scans the current directory with the embedded pack, prints
  the setup it resolved, and saves the report. Detection runs no project tool
  and makes no network call. `ss` behaves the same way.
- `siloscan review` opens a saved report in the terminal UI without scanning
  again, in four forms: `review`, `review PATH`, `review --report FILE`, and
  `review --live [PATH]`. `ss review` is the same command.
- The `siloscan` crate links `siloscan-tui`, so one `cargo install siloscan`
  provides `siloscan`, `ss`, saved review, and live review.
- `--save` opts an explicit scan into its scope's saved-report slot,
  `--no-save` disables the bare command's save, and `--output FILE` writes the
  report to a named file. The three conflict pairwise, so a scan writes at most
  one report.
- Saved reports live in this user's platform state directory, one per scan
  scope, at `siloscan/reports/<scope-key>/latest.json`: `$XDG_STATE_HOME` (or
  `~/.local/state`) on Linux, the user Application Support directory on macOS,
  and `FOLDERID_LocalAppData` on Windows. The scope key is a hash of the
  canonical scanned path and its kind. Each report is published by atomic
  replacement, so a reader sees a complete report or the previous one. Nothing
  is written into the scanned repository, and no report history is kept.
- A save failure exits `2` after stdout is complete, and never claims that a
  report was saved.
- `siloscan_core::project` and `siloscan_core::plan` are public: deterministic
  project detection, and one resolved scan plan that resolves setup once over a
  single walk.

### Changed

- Bare human output adds the resolved setup and capabilities lines before the
  findings, and the report and review lines after them. With `--format json` or
  `--format sarif` those two lines go to stderr, so stdout stays one document.
- The embedded pack is reported as `default-secrets@1` in the new setup output.
  Its 220 rules are unchanged.

### Fixed

- `[languages]` mappings in `siloscan.toml` now take effect. They were accepted
  and then ignored by the runtime language detector.
- The terminal UI writes baseline merges and inline suppressions through the
  same temporary-file, sync, and rename path the baseline writer uses, so an
  interrupted write leaves the previous baseline and the original source file
  byte-identical. A suppression preserves the source file's mode.
- The terminal UI restores the terminal when its own initialization fails,
  instead of leaving raw mode enabled.
- Both source-context panes render the redaction placeholder over a secret
  finding's span instead of the matched bytes.

### Compatibility

- Every 1.x explicit invocation is unchanged. Naming a path, including
  `siloscan .`, or supplying any scan option keeps its 1.5.1 meaning and stays
  stateless unless `--save` or `--output` is added. Human output, exit codes,
  baselines, and SARIF documents are unchanged, as are the existing public Rust
  API signatures.
- Explicit JSON output carries four appended fields: `report_kind`, `scope`,
  `outcome`, and `setup`. Every field 1.x wrote keeps its name, position, and
  value.
- `siloscan-tui` now refuses a report whose `findings` key is missing or null
  rather than presenting it as an empty result. This is the one deliberate
  tightening of the report reader.
- A bare `siloscan` in a script now saves a report. Add `--no-save` where that
  is not wanted.

## 1.5.1

See the [v1.5.1 release](https://github.com/RandomCodeSpace/siloscan/releases/tag/v1.5.1)
and earlier releases for the history before this file existed.
