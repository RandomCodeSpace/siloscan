# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- `siloscan-core`: `CompiledPayload::Ast` carries `Vec<AstQuery>` rather than
  `Vec<(String, Arc<Query>)>`, so a rule's query source travels with its
  compiled query; `engines::ast::AstQueries` is new, and
  `engines::ast::scan_file` takes it as a second parameter.

### Performance

- The ast engine runs one tree-sitter query per language per file, holding
  every applicable rule's patterns, instead of one query - one full tree
  traversal - per rule.

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
