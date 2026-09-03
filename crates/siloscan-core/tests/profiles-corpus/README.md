# The profile corpus

What `tests/profile_corpus.rs` measures the embedded profile documents under
`crates/siloscan-core/rules/profiles/` against. It is a second corpus, not an
extension of `tests/corpus/`, because the two hold different contracts: the
detection corpus holds one global precision floor of 1.0 over individually
justified negatives, and profile rules cannot be held to that — "this `unwrap`
is fine, it is in a test" is a judgement call. Here the false-positive budget is
per rule and the recall floor is per language, so Rust can ship while Ruby is
still being tuned.

This directory is excluded from the published crate (`exclude` in
`crates/siloscan-core/Cargo.toml`). `cargo package --list -p siloscan-core`
shows nothing under it.

## Layout

```text
profiles-corpus/
  manifest.tsv      path, 1-based line, expectation, justification
  floors.tsv        per-language recall floor
  noise/limits.tsv  per-rule false-positive ceilings, corpus and noise set
  tree/
    rust/           positive.rs  negative.rs  ...
    python/         positive.py  negative.py  ...
    ...one directory per language...
```

`tree/` does not exist until the first language lands; the harness reads an
absent or empty tree as a corpus of zero rows and passes.

## The row format

A case is a snippet of real source committed verbatim into a file under
`tree/<language>/`, plus one row in `manifest.tsv` per measured line. Nothing
is generated and nothing is substituted: the snippet on disk is the bytes the
scanner sees, so `git diff` shows the case and the expectation side by side.

- **The language is the directory.** `tree/rust/positive.rs` is a Rust case.
  Every file under a language directory must be detected as that language,
  which the harness checks.
- **The rule id is the expectation.** `expect` is either `NONE` or one or more
  rule ids joined by `|`.
- **The snippet is the file.** The rule matrix's `positive_example` and
  `negative_example` are appended verbatim to `positive.<ext>` and
  `negative.<ext>`. Appending never moves an existing row's line number.
- **The expected line is the row.** A snippet whose rule must fire on two lines
  gets two rows.

Four tab-separated fields, one header line, `#` comments:

```text
path	line	expect	justification
rust/positive.rs	2	reliability.rust.self-comparison	both operands are the identical identifier
rust/negative.rs	2	NONE	the operands are different identifiers, which is an ordinary comparison
```

## What the harness holds

`cargo test --locked -p siloscan-core --test profile_corpus`

- `the_corpus_and_its_manifest_agree` — every row points at a line that exists,
  no line is claimed twice, and every corpus file is the language of its
  directory.
- `every_shipped_document_loads_strictly` — every document loads, its identity
  is `<profile>-<language>@<n>`, every rule id is `<profile>.<language>.<check>`,
  every severity is `warning` or `info`, and no AST query uses a predicate the
  engine does not implement. The last one matters because tree-sitter parses an
  unknown predicate, hands it back as a general predicate, and the match loop
  ignores it — which silently turns a narrow rule into "match every node".
- `every_shipped_rule_has_a_positive_row` — a document may not ship a rule the
  corpus does not measure. Separate from the recall test so a language can land
  one rule at a time.
- `profile_recall_meets_its_floor_per_language` — positives reported over
  positives, per language directory, against `floors.tsv`.
- `no_rule_exceeds_its_false_positive_limit` — per rule, findings on `NONE`
  rows against `max_corpus` in `noise/limits.tsv`, which defaults to zero.
- `the_harness_measures_an_in_test_document` — the same measurement run over a
  document and a corpus built in the test, so the harness is proved to measure
  something while the shipped registry is still empty.

## The noise set

`noise/limits.tsv` also carries `max_per_kloc`, the ceiling a rule may reach on
any single repository of the thirty pinned external repositories recorded in
`research/embedded-profiles/noise-set.md`. `scripts/profile_noise.py` clones
them at their pinned commits, scans each one, and fails when a rule exceeds its
ceiling. Nothing is cloned during `cargo test`: the harness reads the limits
file and the manifest, and never the network.
