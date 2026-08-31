# Siloscan Rust v2 implementation and acceptance plan

| Field | Value |
| --- | --- |
| Status | Implementation-ready |
| Reference implementation | `880d211a463e97eb3c188f957e5592d88f36dcf8` (`v1.5.1`) |
| Target release | `v2.0.0` |
| Tracking issue | [#64](https://github.com/RandomCodeSpace/siloscan/issues/64) |
| Wayfinder map | [#56](https://github.com/RandomCodeSpace/siloscan/issues/56) |
| Primary reader | The engineer taking the next v2 work package |

## Outcome

One `cargo install siloscan` must provide this complete journey:

```text
siloscan
  -> keep the current directory as the exact requested scope
  -> inspect repository evidence without running project tools or using the network
  -> resolve setup once and walk the scope once
  -> run every existing scanner and metric
  -> print the report and atomically replace that scope's one saved latest report

siloscan review
  -> open that exact saved report in the existing TUI without rescanning
```

`ss` must provide the same journey. `siloscan-tui` must remain independently
installable. Every supported explicit v1.5.1 invocation remains compatible and
stateless unless the user asks to save.

This plan is complete when an implementer can take one work package, know the
owning files and contracts, run only its targeted local checks, and hand the
result to the next package without reopening a settled product decision.

The product is complete only after one exact main commit passes all hosted
acceptance gates, is tagged, is published in dependency order, passes a fresh
registry install, and becomes the public GitHub release. The Wayfinder map stays
open until that point.

## Decision record

The linked decisions own detailed behavior. This document only orders their
implementation and collects the gates that cross package boundaries.

Before starting a work package, read its linked decision artifact at the exact
commit below. Those immutable artifacts are required implementation inputs,
not optional background. If an artifact is unavailable, stop rather than infer
the missing behavior. This plan resolves ordering and cross-package acceptance;
it does not override a detailed contract in its owning artifact.

| Decision | Approved answer | Artifact |
| --- | --- | --- |
| [#57](https://github.com/RandomCodeSpace/siloscan/issues/57) | Three Rust packages; TUI library linked into both CLI names; standalone TUI retained | [`8de5674`](https://github.com/RandomCodeSpace/siloscan/blob/8de56740887619a51e851a6d14e48eaba81011c3/research/one-command-integration.md) |
| [#58](https://github.com/RandomCodeSpace/siloscan/issues/58) | Exact v1.5.1 behavior, fixtures, release targets, and paired 5% replacement gate | [`223063a`](https://github.com/RandomCodeSpace/siloscan/blob/223063a49233316511151d41bb8b39f86a1bc363/research/v1.5.1-compatibility-oracle.md) |
| [#59](https://github.com/RandomCodeSpace/siloscan/issues/59) | Deterministic additive detection over the admitted inventory; requested root remains authoritative | [`039565b`](https://github.com/RandomCodeSpace/siloscan/blob/039565b66a16695e5084628a8de5a33f5f61d80f/research/project-detection-semantics.md) |
| [#60](https://github.com/RandomCodeSpace/siloscan/issues/60) | Additive v2 rollout, four-field report markers, exact-SHA qualification, patch-forward recovery | [`5adda3b`](https://github.com/RandomCodeSpace/siloscan/blob/5adda3b909cae7b00f040e35eed851376ca5204a/research/prototypes/v2-rollout-compatibility.html) |
| [#61](https://github.com/RandomCodeSpace/siloscan/issues/61) | Exact-scope platform state, one atomic `latest.json`, explicit scans opt in | [`8f80fd1`](https://github.com/RandomCodeSpace/siloscan/blob/8f80fd12cf1a78d28dbabdbadc9d442a26d5bc54/research/saved-report-contract.md) |
| [#62](https://github.com/RandomCodeSpace/siloscan/issues/62) | Keep all 220 current embedded rules and metrics; launch no ecosystem add-on | [`7ceccbe`](https://github.com/RandomCodeSpace/siloscan/blob/7ceccbe48257bcf3694c246dda927ee3cc6819d6/research/prototypes/zero-config-profile-policy.html) |
| [#63](https://github.com/RandomCodeSpace/siloscan/issues/63) | Public opaque core plan, one prepared inventory, unchanged legacy scan and report APIs | [`51efdbf`](https://github.com/RandomCodeSpace/siloscan/blob/51efdbff1b5fa9191a26d8b8aa7abb43fb61544c/research/prototypes/resolved-scan-plan.html) |

## Fixed acceptance boundaries

| Boundary | Required behavior | Owner |
| --- | --- | --- |
| Automatic invocation | Automatic mode means no positional PATH and no supplied v1 scan option. New save controls may alter persistence, not scan semantics. | CLI parser |
| Explicit invocation | Any supplied PATH, including `.`, or supplied v1 scan option keeps v1.5.1 meaning. Detection may explain setup but cannot change findings except for the `Config.languages` correction below. | CLI and core |
| Scan scope | The canonical requested path and file kind define identity. Detection never promotes to a Git, manifest, package, or workspace root. | Core and CLI persistence |
| Setup | Config, rules, baseline, coverage, cache, anchoring, project facts, capabilities, and one admitted `WalkResult` resolve once in core. | `siloscan-core` |
| Scan | The six engines, ten AST languages, metrics, suppressions, baselines, cache semantics, ordering, warnings, and statuses remain. | `siloscan-core` |
| Public Rust API | Existing `ScanReport`, `ScanOptions`, `JsonReport`, `ReportFinding`, `to_json`, SARIF writer, and public scan function signatures remain source-compatible. | `siloscan-core` |
| Output | Existing explicit human output stays byte-compatible. JSON and SARIF stdout remain one parseable document. Bare human output may add the approved setup, report, and review lines. | CLI |
| Saved report | Bare scans auto-save unless `--no-save`; explicit scans save only with `--save` or `--output`. Save failure is status 2 and never claims success. | CLI persistence |
| Review | Saved review never scans. Live review and every TUI rescan resolve a fresh core plan. No scan automatically opens the TUI. | TUI library and CLI |
| Embedded policy | The unchanged pack is still `default-pack` internally and is reported as `default-secrets@1`, with 220 rules. No ecosystem profile ships in v2.0.0. | Core report metadata |
| Offline operation | Detection does not spawn Cargo, Go, npm, Python, Maven, Gradle, CMake, dotnet, Bundler, tests, scripts, or network clients. | Core project detector |
| Performance | Every one of the 14 wall-time and peak-RSS cells passes independently. No feature may be removed, deferred, or hidden to improve a number. | Hosted candidate gate |
| Distribution | One CLI install provides `siloscan`, `ss`, saved review, and live review. The standalone TUI and three native archives remain. | Manifests and release workflow |

### One explicit correction resolved by this plan

`Config.languages` is accepted by v1.5.1 but ignored by the runtime language
detector. The implementation must make each valid mapping authoritative for
the matching files while retaining current `lang::detect` behavior everywhere
else. Rejecting an accepted key would remove behavior, and continuing to ignore
it would leave the closed detection decision incomplete.

Issue #59 delegated this choice but did not settle it. Issue #64 selects the
no-feature-loss route under the maintainer's explicit no-regression direction.
This is the only approved explicit-output compatibility exception introduced
by the plan. Record it in the #64 resolution and map pointer, and add the exact
mapped-file delta to the oracle allowlist.

Add one focused old-versus-new fixture. Only files matched by a configured
mapping may change language selection; admitted files, findings, fingerprints,
metrics, output, and status for every unrelated file must stay exact.

## Dependency and ownership graph

```text
frozen oracle harness ------------------------------------------+
                                                               |
TUI library extraction ----------------------+                 |
                                             v                 v
prepared scan -> project detector -> resolved plan/writer -> TUI sessions
                                                               |
                                                               v
                                              CLI + persistence + review
                                                               |
                                                               v
                                         candidate qualification and release
```

The oracle import, behavior-neutral TUI extraction, and prepared scanner may
start in separate worktrees. Everything after their merge follows the arrows.

## Ordered work packages

### 0. Materialize the frozen oracle

- Owner: one isolated fixture and hosted-test worktree.
- Dependency: none. It can run beside packages 1 and 2.
- Product behavior change: none.

Import `research/oracle-v1.5.1/` unchanged from commit `223063a`. Do not
recapture any golden from the candidate. Add the smallest black-box harness
that can build the pinned reference, run the existing explicit journeys, apply
the approved normalization rules, and retain raw diffs. Do not add disabled or
skipped tests for behavior that does not exist yet; add the bare v2 and
persistence lanes in package 7.

The import must verify `CAPTURES.sha256`, `inputs.manifest.sha256`, and
`mixed.manifest.sha256`. If the known Clippy failure at the reference main still
blocks ordinary GitHub CI, keep the reference checkout at `880d211` untouched
and make only the proven correction in the candidate product tree as a separate
commit. Do not combine it with cleanup.

Local stop:

- `cargo test --locked -p siloscan --test v2_oracle_harness explicit_v1`
  verifies the fixture checksums and runs only explicit v1 parity cases;
- when a candidate-only Clippy correction is needed,
  `cargo clippy --locked -p siloscan-core --lib -- -D warnings` passes;
- the checkout has no regenerated golden or unrelated diff.

### 1. Extract the TUI library without changing behavior

- Owner: one `siloscan-tui` worktree.
- Dependency: none for extraction; migration waits for package 5.
- Primary files: `crates/siloscan-tui/src/lib.rs`, `main.rs`, and the existing
  session modules.

Expose one fallible library entry point for the existing live and snapshot
sessions. Keep Clap and process exit in the standalone binary, which becomes a
thin compatibility wrapper. Preserve help, version identity, terminal restore,
all actions, and read-only snapshot refusal. Make this a distinct first commit
so later session changes cannot hide a TUI extraction regression.

Local stop:

- `cargo check --locked -p siloscan-tui --all-targets` passes;
- `cargo test --locked -p siloscan-tui --test v2_sessions library_entry`
  proves the linked and standalone entry points converge;
- `cargo test --locked -p siloscan-tui app::tests`,
  `cargo test --locked -p siloscan-tui actions::tests`, and
  `cargo test --locked -p siloscan-tui snapshot::tests` pass;
- `cargo test --locked -p siloscan-tui --test v2_sessions standalone_surface`
  proves existing standalone help and version captures are unchanged.

### 2. Extract the prepared scanner

- Owner: the sole core integration worktree.
- Dependency: none.
- Primary files: `crates/siloscan-core/src/scan.rs` and its nearest tests.

Extract a private scanner body that accepts the owned, already admitted
`WalkResult`. Existing `scan`, `scan_with_progress`, and `scan_opts` keep their
public signatures and current behavior: they perform the current walk and then
delegate. Engine APIs do not move.

This is the seam that prevents both project detection and execution from
walking the scope independently.

Local stop:

- `cargo check --locked -p siloscan-core --all-targets` passes;
- `cargo test --locked -p siloscan-core scan::tests::prepared_scan` exercises
  the private prepared body and proves one walk and byte-identical legacy
  output;
- only the directly reached existing scan and walk test filters run.

### 3. Add deterministic project detection

- Owner: the same serial core stack as package 2.
- Dependency: package 2.
- Primary files: one new `project` module, focused detector fixtures, and the
  smallest `lib.rs` registration.

Implement fixed Rust detectors over the prepared inventory using current
`toml`, `serde_json`, `roxmltree`, `globset`, walker, and language code. Emit
sorted evidence, units, workspace relations, languages, source-root hints, and
complete, partial, or invalid status. Mixed repositories form a union. Invalid
or unsupported evidence remains visible while the generic scan continues.

Do not add a detector walker, subprocess adapter, plugin registry, project-tool
runner, JSONC parser, or ecosystem profile. Wire valid `Config.languages`
mappings as the explicit override described above.

Local stop:

- `cargo test --locked -p siloscan-core project::tests` passes its private
  detector and precedence cases;
- all 16 approved detector fixtures produce byte-identical normalized detector
  facts on repeated scheduling;
- `cargo test --locked -p siloscan-core --test detection_corpus` preserves the
  directly affected 240-positive and 311-negative language corpus cases.

### 4. Add the core resolved-plan and report contract

- Owner: the same serial core stack.
- Dependency: package 3.
- Primary files: one new plan module plus `scan.rs`, `output.rs`, and `lib.rs`.

Add `ScanRequest`, public opaque `ResolvedScanPlan`, `ResolvedScanReport`,
deterministic `ScanSetupReport`, and opaque `ScanOutputContext`. Preserve
omitted PATH versus every explicit form. Resolution owns config, rule,
baseline, coverage, cache, anchoring, capabilities, project facts, and the one
inventory. Execution derives temporary current `ScanOptions` and calls the
private prepared scanner.

Keep legacy writers and public report structs unchanged. Add a separate
resolved JSON serializer that reuses the legacy projection and appends exactly
these four trailing fields in stable order:

```text
report_kind
scope
outcome
setup
```

Its owning implementation is an internal `Write`-based serializer. The public
String-returning helper, if retained from the approved core prototype, wraps
that writer. This lets persistence write canonical resolved JSON directly to a
buffered temporary file without an extra full-report String.

The saved report remains schema `1.2`; baseline stays schema `1`; SARIF stays
unchanged. Do not serialize an absolute root, current directory, command line,
cache path, output path, manifest content, host, or timestamp.

Local stop:

- `cargo test --locked -p siloscan-core --test v2_resolved_plan` passes all
  plan, override, single-walk, failure, and deterministic-order cases;
- `cargo test --locked -p siloscan-core --test v2_report_contract` passes;
- a counting writer fixture proves one resolved serialization and the direct
  writer path without cloning `ScanReport`;
- a small external compile fixture proves the existing public Rust API still
  compiles without source changes;
- no baseline, fingerprint, SARIF, or engine owner changed without a failing
  direct contract test that required it.

### 5. Migrate live and saved TUI sessions

- Owner: the sole TUI worktree, rebased after packages 1 and 4 land.
- Dependency: packages 1 and 4.
- Primary files: `lib.rs`, `main.rs`, `app.rs`, `state.rs`, `actions.rs`, and
  `snapshot.rs` as one serial slice.

Live sessions retain a `ScanRequest`, resolve one fresh immutable plan in the
worker for initial scan and every `r`, and carry source and baseline context
without re-resolving setup in TUI code. Saved sessions load a report and never
resolve a plan or scan.

Use marker completeness, not product major, to classify reports:

| Reader path | Marker-free supported 1.x or omitted schema plus findings | Complete four-marker v2 | Partial markers | Marker-free v2 core writer |
| --- | --- | --- | --- | --- |
| v1.5.1 TUI | Full v1 view | Findings and metrics; new fields ignored | Tolerant legacy view, but candidate must never publish it | Legacy view |
| v2 explicit `--report` | Accept; setup and outcome unavailable | Authoritative | Reject | Accept as legacy/core |
| v2 implicit latest | Reject | Accept only for matching scope identity and kind | Reject | Reject |

Also reject schema-only objects, missing or null `findings`, malformed product
versions, and unrelated JSON. Retain unknown future setup-status strings for a
supported same-major report. A legacy filtered report must never be presented
as authoritatively clean.

Local stop:

- `cargo test --locked -p siloscan-tui --test v2_sessions` passes;
- focused `snapshot::tests`, `actions::tests`, and `app::tests` pass;
- the standalone binary and linked entry point produce the same semantic
  120x40 states and restore the terminal on every tested exit.

### 6. Implement CLI invocation, persistence, and review

- Owner: one CLI worktree.
- Dependency: packages 4 and 5.
- Primary files: `crates/siloscan/src/main.rs`, one private `saved_report`
  module, `crates/siloscan/Cargo.toml`, `Cargo.lock`, and isolated CLI tests.
  `ss.rs` continues to include the shared implementation and needs no duplicate
  policy. The CLI owner commits these package dependency and lockfile changes,
  then hands sole manifest ownership to package 7 after merge.

Keep argument provenance so omitted PATH differs from explicit `.` and from
every supplied v1 scan option, including a value equal to its default. Add
pairwise-conflicting `--save`, `--no-save`, and `--output FILE`. Preflight the
scope and destination before the expensive resolve, decide `--fail-on` before
output filtering, serialize the filtered resolved report once, publish it, and
preserve stdout even when a post-scan save fails.

When stdout is JSON, reuse one serialized byte buffer for stdout and the saved
file. When stdout is human or SARIF, stream the separate saved resolved JSON
through the internal writer directly to the buffered temporary file. Never
clone the full report, build an extra full-report String only for persistence,
or serialize the saved document twice.

Add `review`, `review PATH`, `review --report FILE`, and `review --live [PATH]`
through the TUI library. Reuse the complete v1 scan argument type for the real
`./review` path collision. Do not maintain a copied list of old scan flags.
Keep alias-correct help, errors, and human review hints.

The private persistence module owns:

```text
state_root
canonical_scope
automatic_report_path
write_report_atomic
latest_report_path
source_base
```

It implements the exact #61 contract:

- Linux uses absolute `XDG_STATE_HOME`, then absolute
  `$HOME/.local/state`; macOS uses the user Application Support directory;
  Windows uses `FOLDERID_LocalAppData`. No valid platform state root is status
  2, not a repository fallback.
- Before creating a directory, reject an automatic state root inside the scan
  boundary, the parent of a single-file scope, or the nearest `.git` boundary,
  including a symlinked ancestor into one of those boundaries.
- The scope key is the full SHA-256 of the versioned, platform-native encoding
  of the canonical requested path plus its directory or file kind. Relative,
  absolute, and symlinked spellings of the same scope converge; different
  nested scopes and worktrees do not.
- Write a unique same-directory temporary, serialize, flush, sync, and publish
  with the platform's atomic replace. Sync the directory on Linux. Review
  ignores temporaries and never falls back to another scope or guessed newest
  report.
- `--output` requires an existing parent. Automatic state never writes into
  the repository, and no path keeps history or `previous.json`.

Use the standard library for Linux state resolution. On macOS add
`objc2-foundation = 0.3.2` as a target dependency with default features off and
only `std`, `NSError`, `NSFileManager`, `NSPathUtilities`, and `NSURL`. Call
`NSFileManager::URLForDirectory_inDomain_appropriateForURL_create_error` with
`NSApplicationSupportDirectory`, `NSUserDomainMask`, no appropriate URL, and
`create = false`, then use the returned file-system representation. Do not
construct `~/Library/Application Support` by hand.

On Windows add `windows-sys = 0.61.2` only as a target dependency, with the
narrow Foundation, Storage FileSystem, System Com, System WindowsProgramming,
and UI Shell features required for `FOLDERID_LocalAppData`,
`SHGetKnownFolderPath`, `FileRenameInfoEx`, and
`SetFileInformationByHandle`. Publish with both `REPLACE_IF_EXISTS` and
`POSIX_SEMANTICS`. Use existing `sha2` directly for the scope key. There is no
weaker Windows rename fallback.

Dependency review on 2026-08-31 found `objc2-foundation 0.3.2` and
`windows-sys 0.61.2` to be the current stable releases, both Rust 1.71
compatible and permissively licensed. Both upstream repositories were active
and had multiple contributors; the RustSec advisory database had no match for
either crate. `objc2-foundation` is target-only with defaults disabled and the
five features above. `windows-sys` depends only on `windows-link 0.2.1`.
These narrow generated bindings are smaller and less error-prone than
handwritten Objective-C and Win32 declarations.

Local stop:

- `cargo test --locked -p siloscan --test v2_persistence` passes current-host
  identity, platform API adapter, publication, one-serialization, recovery,
  conflict, and status cases;
- `cargo test --locked -p siloscan --test v2_cli` passes both binaries and all
  command, stream, collision, and review cases;
- only named existing cases directly affected in `tests/cli.rs` run locally;
- `cargo check --locked -p siloscan --all-targets` and the directly affected
  TUI library check pass.

### 7. Complete hosted compatibility and candidate qualification

- Owner: one final manifest and workflow worktree.
- Dependency: packages 0 and 6.
- Primary files: all Cargo manifests and lockfile,
  `.github/workflows/ci.yml`, release-candidate automation,
  `.github/workflows/release.yml`, root README, and release notes. No other
  writer touches these files while this package runs.

Bring the oracle harness forward with the new automatic, persistence, reader,
TUI, package, archive, and performance lanes. Keep ordinary CI as the full
repository gate. Add one pre-tag candidate workflow that mutates no public
release state and binds every result and artifact to one full commit SHA.

The candidate manifest is a generated, uncommitted hosted workflow artifact.
It records the checked-out SHA, workspace version, oracle SHA, workflow run,
archive digests, and packaged-crate digests. It never tries to embed its own
future source commit.

Update the user README only after the command behavior is stable. Lead with
`cargo install siloscan`, bare `siloscan`, and `siloscan review`; retain the
existing `style=for-the-badge` badges and hero image; explain explicit-scan
compatibility without turning the README into an architecture document.

Make the workspace and all three crate versions `2.0.0` in the final candidate
commit. Any code, fixture, README, version, or workflow edit after qualification
creates a new candidate and reruns every hosted gate.

Local stop:

- workflow syntax and deterministic helper tests pass;
- candidate-manifest helper tests pass with a fixed synthetic SHA and fixed
  fake digests; the real manifest is generated only after hosted artifacts
  exist;
- no full workspace test, full oracle, performance job, cross-version job,
  package install, or archive matrix runs locally.

### 8. Stage and publish the qualified release

- Owner: release operator and release workflow.
- Dependency: package 7 green on the exact current main SHA.
- Source change: none.

The tag workflow must first prove this identity chain:

```text
candidate input
= checked-out HEAD
= remote main tip
= ordinary CI head_sha
= candidate qualification head_sha
= every candidate artifact manifest SHA
= tag commit
= release workflow GITHUB_SHA
```

Create a draft release and promote the exact qualified archive bytes. Publish
and verify crates in immutable dependency order:

```text
siloscan-core -> siloscan-tui -> siloscan
```

Each crate is a separate retry-safe job. If the exact version already exists,
continue only when its registry checksum and `.cargo_vcs_info.json` SHA match.
Otherwise publish, poll with a bounded timeout until a clean consumer can fetch
that exact version, verify it, and then start the dependent crate.

After `siloscan` is registry-visible, install it into new Cargo and install
roots. Prove `siloscan`, `ss`, bare save, explicit stateless scan,
`siloscan review`, and `ss review` without a second TUI install. Re-download
the draft assets, verify them against the candidate manifest, then and only
then make the GitHub release public.

## Isolated work and merge rules

| Mutable surface | Single owner | Parallel rule |
| --- | --- | --- |
| `scan.rs`, core plan types, `output.rs`, `lib.rs` | Core integrator | Packages 2 through 4 are one serial stack. Optional leaf detector files start only after shared types freeze. |
| TUI `lib.rs`, `main.rs`, `app.rs`, `state.rs`, `actions.rs`, `snapshot.rs` | TUI integrator | Library extraction may run beside core. Live-plan migration waits for core and uses the same TUI owner. |
| CLI `main.rs` and saved-report module | CLI integrator | No concurrent CLI writer. Both aliases are tested from the shared implementation. |
| CLI manifest and `Cargo.lock` during package 6 | CLI integrator | Commit the direct CLI, TUI, SHA-256, macOS Foundation, and Windows target dependency graph with package 6. No other manifest writer runs. |
| All manifests and `Cargo.lock` after package 6 merges | Final integration owner | Take sole ownership for final dependency convergence and version `2.0.0`; do not overlap the CLI branch. |
| CI and release workflows | Release integrator | Oracle authors provide scripts and fixtures; one workflow owner wires the final DAG. |
| Root README and release notes | Final integration owner | Written after behavior freezes and before the candidate SHA freezes. |

Every worktree starts from the recorded dependency commit. Before integration,
the owner fetches, verifies divergence, and uses a fast-forward or clean rebase
without resetting another worktree. Existing dirty files remain user-owned.

## Targeted local verification ledger

The named integration targets make the local-test boundary enforceable.

| Group | Local command | Scope |
| --- | --- | --- |
| L1 Core plan and detection | `cargo test --locked -p siloscan-core --test v2_resolved_plan` | Provenance, exact root, one inventory, precedence, detector fixtures, ordering, setup failures |
| L2 Core report and API | `cargo test --locked -p siloscan-core --test v2_report_contract` | Legacy public API compile, four trailing fields, deterministic bytes, forbidden metadata |
| L3 Persistence | `cargo test --locked -p siloscan --test v2_persistence` | Current-host state, scope keys, first write, replacement, failure retention, stale and corrupt state |
| L4 CLI and aliases | `cargo test --locked -p siloscan --test v2_cli` | Automatic and explicit modes, save controls, streams, statuses, review forms, collision, `ss` parity |
| L5 TUI sessions | `cargo test --locked -p siloscan-tui --test v2_sessions` | Linked and standalone entry points, fresh live plans, no-scan snapshots, reader matrix, terminal restore |
| L6 Nearest regressions | Named tests only from the owning existing test module | Only behavior directly reached by the patch |
| L7 Changed-package compile | `cargo check --locked -p <owner> --all-targets` | Owning package, plus a direct dependent when its public cross-crate contract changed |

Do not run local `cargo test --workspace`, workspace Clippy, workspace
packaging, the complete black-box oracle, the performance harness, or any
native release matrix. GitHub CI is the repository-level authority.

For CLI changes, the nearest existing regression list starts with these named
cases and is narrowed further when a patch does not reach one of them:

```text
findings_exit_one_in_canonical_order
json_format_parses_and_carries_fingerprints
no_findings_exits_zero
missing_scan_path_exits_two
baseline_then_rescan_reports_baselined_and_exits_zero
sarif_format_parses_with_schema_and_results
warm_cache_reproduces_the_cold_output_byte_for_byte
no_cache_produces_identical_output_and_writes_no_entries
a_bare_invocation_scans_the_working_directory
a_scan_path_scans_that_tree_and_not_the_working_directory
help_documents_only_the_forms_that_work
```

## Compatibility fixtures and comparisons

| Fixture | Required assertion |
| --- | --- |
| `mixed/`, synthetic rules, and coverage | All six engines, all ten AST languages, 23 new findings, one suppression, exact metrics, order, paths, and statuses |
| `golden/human.stdout` | Explicit stateless human output byte-for-byte |
| `golden/report.json` | Deep equality after normalizing product version and removing only `report_kind`, `scope`, `outcome`, and `setup` from candidate output |
| `golden/report.sarif.json` | Deep equality after removing only the tool version |
| `golden/baseline.json` | Exact baseline bytes and fingerprints in both version directions |
| `default-pack/` | One exact redacted finding through `siloscan` and `ss`; unchanged 220-rule pack |
| Help and version captures | Both aliases, standalone TUI, and every existing nested subcommand; only approved additions differ |
| `tui-live/` and semantic state capture | Fixed 120x40 live and snapshot transitions, mutation/refusal behavior, file effects, and terminal restore |
| Existing detection corpus | All 240 positives and 311 negatives remain; configured mapping fixture is the one approved correction |
| New setup microfixtures | Config anchoring, nested module, single file, missing or malformed config, ignore sources, binaries, in-root and refused out-of-root symlinks |
| New persistence fixtures | First save, identical repeat, replacement, injected failures, concurrent writers, stale temporary, invalid latest, scope mismatch |
| Scale recipe | Exact generated 4,097-file, roughly 31 MiB tree for paired performance runs |
| Package and archive fixtures | Empty install roots and exact seven-member native archives |

Bidirectional baseline acceptance uses independent fixture copies:

1. The reference writes a baseline equal to `golden/baseline.json`.
2. The candidate reads it as 0 new, 23 baselined, 1 suppressed, status 0.
3. The candidate writes a byte-identical baseline.
4. The reference reads the candidate baseline with the same partition and status.
5. After one finding changes, both versions classify only that finding as new.

Saved-report metadata never enters a baseline or fingerprint input.

## Hosted GitHub CI gates

These run only after the contributing package's targeted local checks pass.

| Hosted gate | Pass condition |
| --- | --- |
| Ordinary CI | Full locked workspace format, Clippy, build, and tests on Linux; full Windows build/tests; Rust 1.96 MSRV all-target check |
| Explicit compatibility | Every v1 command, option, engine, language, output, status, baseline, suppression, cache, TUI action, and alias matches the frozen oracle |
| Automatic journey | Exact approved bare human setup, capability, report, and review lines; clean JSON/SARIF routing; unchanged 220-rule pack and current metrics; no ecosystem add-on across Rust, Go, JavaScript/TypeScript, Python, Java, C/C++, C#, Ruby, mixed, and generic fixtures |
| Cross-version readers | Real v1.5.1 reads complete candidate output; candidate explicit reader opens supported marker-free reports; implicit latest accepts only complete matching v2 |
| Platform persistence | Native Linux, macOS, and Windows state paths, identity, first save, old/new handle replacement behavior, interruption, concurrency, and unsupported Windows atomic failure |
| TUI PTY | Fixed-size live and snapshot flows through standalone and linked entries, including restore and read-only refusal |
| Performance | All 14 cells below pass, including any required fresh-runner repeat |
| Native archives | Linux musl x64, macOS arm64, and Windows x64 archives contain exactly seven members, verify their sibling checksum, extract, and run all three binaries natively |
| Package and install | `cargo package --locked --workspace`; empty-root candidate install; post-publish empty-root crates.io install; one CLI install provides both aliases and review |
| Candidate aggregate | Every job and artifact names the same full candidate SHA, which is still the exact main tip |

### Fourteen independent performance cells

| Lane | Wall time | Peak RSS |
| --- | ---: | ---: |
| Unchanged explicit invocation, `--no-cache` | 1 | 2 |
| Unchanged explicit invocation, cold cache | 3 | 4 |
| Unchanged explicit invocation, warm cache | 5 | 6 |
| Bare reference versus candidate `--no-save`, cold | 7 | 8 |
| Bare reference versus candidate `--no-save`, warm | 9 | 10 |
| Bare reference versus candidate auto-save, first publication | 11 | 12 |
| Bare reference versus candidate auto-save, warm replacement | 13 | 14 |

For each lane, use the same hosted runner, toolchain, release profile, input
bytes, CPU allocation, environment, and output sink. Use separate caches per
binary and fresh cache and state roots for cold samples. Run one untimed
warm-up, then nine paired samples in ABBA order. Retain raw samples.

Compare candidate and reference medians per cell. A ratio above `1.05` is
suspected and reruns the complete pair once on a fresh runner. The same lane
and metric above `1.05` twice rejects the candidate. Reference median absolute
deviation above 20% invalidates the job and requires a rerun. A faster cell
never offsets a slower or larger one.

## Release archive and publication contract

Each native archive contains exactly these seven members, using `.exe` on
Windows:

```text
siloscan
ss
siloscan-tui
README.md
LICENSE
NOTICE
THIRD-PARTY-LICENSES
```

Release CI must execute the extracted files, not binaries left in `target/`.
Before tagging, candidate artifacts remain private workflow artifacts. After
tagging, the GitHub release remains a draft until registry and re-download
verification finish.

The current release workflow creates a public release too early, rebuilds
assets after tagging, has no exact-SHA or extracted-archive gate, and publishes
core, CLI, TUI in the wrong order. Replace that path; do not wrap it with a
second public-release path.

## Failure and recovery boundaries

| Failure point | Required action |
| --- | --- |
| Before tag | Reject the candidate, fix on a new commit, and rerun every hosted gate. |
| One performance cell above 1.05 once | Repeat the complete pair on a fresh runner. |
| Same cell above 1.05 twice | Reject the candidate. There is no waiver or offset. |
| After tag, before any crate is accepted | Resume only with unchanged tag, source, packages, and artifacts. A source fix requires a new patch version. |
| Partial crates.io publication | Keep the GitHub release draft private. Resume remaining crates only from identical bytes, or qualify a patch. |
| Defect after publication starts | Preserve published tags, crates, assets, reports, and baselines. Yank only an unusable crate and qualify a patch through the full gate. |
| After public release | Keep v1.5.1 available, publish a fully qualified patch, never move the tag, and never replace public assets. |

Cache state is disposable and never serves as migration or rollback state.

## Non-goals

- Go or another language port.
- Security hardening, security audit work, signing changes, or workflow
  permission redesign.
- Dependency upgrades unrelated to the one target-specific Windows binding.
- New engines, grammars, rules, or ecosystem add-on profiles.
- Scan-root promotion, project-tool execution, repository scripts, or network
  access.
- Plugin systems, framework changes, a fourth crate, or a second TUI.
- Report history, retention, cloud storage, daemon mode, telemetry, or automatic
  TUI launch.
- Baseline, fingerprint, cache, SARIF, `test`, `baseline`, or `cache prune`
  refactors unless a direct parity failure proves the smallest owning fix is
  required.
- Performance work beyond correcting a measured blocking regression.
- Unrelated cleanup, formatting, dependency audits, or technical-doc rewrites.

## Exact stop condition

Stop and mark Rust v2 complete only when all statements below are true for one
full 40-character commit SHA:

1. That SHA is the current main tip, ordinary GitHub CI head, candidate
   qualification head, artifact manifest identity, and tag target.
2. Every targeted local verification entry for every changed package is
   recorded green, with no local full-suite claim.
3. Every frozen explicit compatibility comparison passes with no unapproved
   behavior or public Rust API difference.
4. Detection, one-walk planning, automatic save, exact-scope review, aliases,
   standalone TUI, and all platform persistence cases pass.
5. Supported prior reports and baselines read correctly in both required
   directions; fingerprints and baseline bytes remain exact.
6. All 14 performance cells pass under the repeat and invalidation rules.
7. All three extracted native archives and the candidate package/install gate
   pass.
8. The immutable tag points to the qualified SHA. Core, TUI, and CLI are
   registry-visible and verified in that order.
9. A fresh crates.io install proves the one-install workflow. Re-downloaded
   draft assets match the qualified digests.
10. The GitHub release is public, every child of Wayfinder map
    [#56](https://github.com/RandomCodeSpace/siloscan/issues/56) is closed, and
    no decision remains unresolved. Add the exact-SHA, CI, registry-install,
    asset, and release links to #56, then close the map.

An older green run, local workspace suite, different worktree, PR head, stale
artifact, or manually waived performance result is not completion evidence.
