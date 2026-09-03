# Embedded bug-risk and maintainability profiles: Phase 1 technical design

| Field | Value |
| --- | --- |
| Status | Design for review; nothing here is implemented |
| Ticket | [#78](https://github.com/RandomCodeSpace/siloscan/issues/78) |
| Base | `main` at `1aff36f`, after the `v2.0.0` release commit `b1ffbdc` |
| Scope | The machinery. The rule matrix is a separate ticket and a separate owner. |
| Primary reader | The engineer taking the first implementation package below |

## What this document is not

It proposes no rule. Every rule id, query, threshold and severity that appears
here is a spike artifact chosen to exercise a mechanism, and the spike files say
so in their first line. The rule matrix — which checks ship, at which severity,
for which of the ten languages — is being drafted in parallel and owns those
decisions. What this document owns is: how a profile is packaged, how one is
selected, what the engine has to grow to express a metric threshold, what the
report and the cache do about it, what it costs, and how the noise is measured.

### Map issue

The map is #89 ("Siloscan v2.1 wayfinder map: zero-config bug-risk and
maintainability profiles"). It was not visible to the search this document was
written against, so the boundaries below were reconstructed from #78, the v2
acceptance plan's "Fixed acceptance boundaries" and its fourteen performance
cells, and then checked against #89 afterwards: they agree. Where this document
says a map decision is missing, #89's Phase 1 comment records the decision that
was taken.

The licensing boundary is reconstructed from `NOTICE` and `deny.toml`, which are
unambiguous about the shape it has to take:

- `rules/default/secrets.yaml` is a mechanical translation of the gitleaks MIT
  configuration, regenerated wholesale, with attribution in `NOTICE`.
- `rules/default/generic.yaml` is original work, and `NOTICE` says so explicitly
  so the two cannot be confused.
- Every profile document must fall in the second category. Queries and
  thresholds must be written against the grammars' own `node-types.json`, not
  transcribed from another analyser's rule set. Semgrep's registry (LGPL-2.1 for
  the engine, per-rule licensing on the registry), SonarSource's rule
  specifications, PMD's and ESLint's rule implementations are all off limits as
  copy sources; the *names* of well-known checks are not ownable and a rule that
  independently implements "bare except" is fine. If any profile document ever
  does derive from an external corpus, it gets its own `NOTICE` stanza in the
  same commit, and `deny.toml`'s permissive-only allow list is the standard.

---

## 1. Profile mechanism

### 1.1 Packaging: one document per profile per language

**Recommendation: one YAML document per (profile, language) pair**, under
`crates/siloscan-core/rules/profiles/`:

```text
crates/siloscan-core/rules/profiles/
  reliability/
    c.yaml  cpp.yaml  csharp.yaml  go.yaml  java.yaml
    javascript.yaml  python.yaml  ruby.yaml  rust.yaml  typescript.yaml
  maintainability/
    ... the same ten ...
```

Each is a complete, self-loading rule document with its own `version: 1` header,
exactly like the two halves of the current pack.

Why not one document per profile with `languages:` envelopes:

- **The loader has no sub-document unit.** `rules::load_str(src, origin)` takes
  one document and one origin, and the origin is both the `source_hash` input
  and the identity `setup.rule_sources` reports. A ten-language document is one
  origin, so the report could not say which languages actually contributed and
  the cache could not distinguish "Rust profile changed" from "Ruby profile
  changed".
- **Selection would have to split YAML at run time.** `default_pack.rs` already
  joins two documents by locating the byte sequence `"\nrules:\n"` and splicing;
  that trick exists once, is documented as fragile, and needed a CRLF
  normalisation fix after it panicked on Windows checkouts. Doing it ten times,
  in the other direction, to drop the languages a repository does not use, is
  the same trick with more edges.
- **Selection is the performance mitigation.** Section 5 measures the cost of
  parsing every source file. The only structural lever against it is not loading
  the languages the tree does not contain, and that is a file-granularity
  decision.
- **An `ast:` rule cannot carry a `languages:` key at all.** `compile_rule`
  rejects `ast` + `languages` (`LoadError::AstLanguages`) because an ast rule's
  language coverage *is* its query map. A `languages:` envelope around ast rules
  would either be that rejected key or a new nesting level in the document
  schema.

Cost of the recommendation: twenty files instead of two, and twenty
`rule_sources` entries on a hypothetical repository that contains all ten
languages. Both are honest — a repository really did load twenty documents.

### 1.2 Naming and versioning

Identity strings follow `default-secrets@1` exactly:

```text
reliability-rust@1        maintainability-rust@1
reliability-python@1      maintainability-python@1
...
```

Flat, one segment plus `@N`, so `setup.rule_sources[].id` stays a short opaque
label and the bare `rules:` line stays readable:

```text
rules: default-secrets@1, maintainability-rust@1, reliability-rust@1
```

Rule ids inside them use three dot segments, `family.language.check`:

```text
reliability.rust.unwrap-call
maintainability.python.function-complexity
```

`rules::id_pattern` is `^[a-z0-9-]+(\.[a-z0-9-]+)+$`, so this validates. The
language segment is redundant with the document but is what makes a baseline
entry, a SARIF `ruleId` and a suppression comment readable on their own, and it
guarantees no collision when two languages express the same check differently.

The `@N` suffix is the document's **contract** generation, not its content
version, which is the same meaning `default-secrets@1` already carries across
wholesale gitleaks regenerations. Bump it only when a rule id is removed or
renamed — the two changes that can silently invalidate a consumer's baseline
entry or suppression comment. Content changes ride the same number and are
visible through `RuleSet::source_hash` and through the corpus floors in section
6.

### 1.3 Selection

Selection is `ProjectFacts.languages` ∩ available profile documents, filtered by
the request's `ProfileSelection`:

```rust
pub enum ProfileSelection {
    /// Every profile that has a document for a detected language.
    Auto,
    /// No embedded profile.
    None,
    /// Exactly these profile identities, whatever was detected.
    Named(Vec<String>),
}
```

`Auto` never loads a document for a language the detector did not report, which
is both the performance lever and the reason a Go-only repository never sees a
Ruby rule id.

`Named` deliberately ignores detection: a user naming `reliability-rust@1` on a
tree the detector called generic asked for it, and silently loading nothing
would be the "clean scan that proved nothing" failure the codebase already
refuses elsewhere. A named profile with no document is a resolve error, listing
the available identities.

#### Where it lives, and the one ordering problem

Selection has to happen in `plan.rs::resolve`, and there is exactly one obstacle:
`ProjectFacts` does not exist until after the walk, and the current order is

```text
root -> config -> rules -> silos -> coverage -> anchor -> baseline
     -> cache -> prepared_setup -> walk -> detect -> setup
```

`open_cache` takes `&RuleSet` because `Cache::bind` folds
`RuleSet::source_hash()` into every entry key. Appending profile documents after
the cache is bound would key every entry on a rule set that is not the one that
produced it — silent cross-profile cache poisoning, the worst available failure.

**Recommendation: move `open_cache` after `project::detect`.**

The only thing the cache is needed for before the walk is
`Cache::exclusion_under`, which strips the cache's own files out of the
inventory. That answer depends on the scan root and the requested cache
directory and *not* on the rules. Extract it:

```rust
// cache.rs, new free function; the body is what `bind` already computes.
pub fn exclusion_dir(scan_root: &Path, cache_dir: Option<&Path>) -> Option<PathBuf>;
```

The resolved order becomes:

```text
root -> config -> rules -> silos -> coverage -> anchor -> baseline
     -> exclusion_dir -> prepared_setup -> walk -> filter -> detect
     -> select profiles + append documents -> duplicate-id check
     -> open_cache(final rules) -> setup
```

Nothing about the failure ordering moves: `open_cache` returns
`Option<Cache>` and cannot fail, so no error changes position, and every
`ResolveError` the oracle asserts on is raised before the walk exactly as
before. The duplicate-id check moves after the append, which it must — a
`--rules` directory can now collide with a profile id, and that has to be the
same `duplicate rule id: {id}` error it already is.

Two rejected alternatives, recorded so they are not re-argued:

- *Bind the cache twice.* `Cache::bind` runs `secure_dir` and `prune_if_stale`;
  doing that twice per scan is two filesystem passes for no gain.
- *Add `Cache::rebind(&RuleSet)`.* One more public method on the most
  security-sensitive type in the crate, to avoid moving a call that cannot fail.

`prepared_setup` stays where it is: it validates silo and coverage rules, and
profiles carry neither (enforced by a load test, section 1.5).

### 1.4 Report surface

`ScanSetupReport` needs no new field.

- **`rule_sources`** gains one `{id, origin: "embedded"}` entry per selected
  document. The existing sort — embedded first, then by id — puts
  `default-secrets@1` first and then the profiles alphabetically
  (`maintainability-*` before `reliability-*`), so no existing entry moves.
- **`capabilities`** gains one `profiles` entry. `CapabilityState` is built for
  exactly this: it refuses to exist without a reason when it is not enabled.

  | Situation | Status | Reason |
  | --- | --- | --- |
  | one or more documents loaded | `enabled` | — |
  | `--profiles none`, or an explicit request that did not ask | `skipped` | `the embedded profiles are disabled for this scan` |
  | `--no-default-rules` | `skipped` | `the embedded pack is disabled for this scan` |
  | `auto` and no detected language has a document | `not_configured` | `no detected language has an embedded profile` |

  The list is sorted by id, so `profiles` lands between `embedded-rules` and
  `project-detection`. The bare `capabilities:` line therefore gains one clause
  in a fixed position, which is a `v2_journey.rs` change (section 2).

### 1.5 `--no-default-rules`

`--no-default-rules` disables **every** embedded document, profiles included.
In v1 it meant "the built-in pack", and a flag that left ten new documents
loaded would mean something else under the same spelling. Implementation is one
line — the existing `request.no_embedded_rules` guard wraps the profile
selection as well as the secrets pack — and it is worth a direct test, because
the two loads are in different places in `resolve` once selection moves after
the walk.

A load-time test asserts what a profile document may contain: `ast` and
`metric` payloads only. No `secret` (that is the other pack's job and its
severity contract), no `boundary` or `coverage` (both need config the profile
cannot assume, and `prepared_setup` would fail the scan), no `duplication` (the
metrics channel owns that id). Same test asserts no rule ships at `error`; see
section 4.

---

## 2. Explicit-mode opt-in

### 2.1 The flag

```text
--profiles <auto|none|LIST>
```

`LIST` is a comma-separated list of profile identities
(`reliability-rust@1,maintainability-rust@1`). It lives on `ScanArgs`, beside
`--rules` and `--no-default-rules`.

**On `ScanArgs`, so supplying it makes the run explicit.** That is one rule
("any supplied scan option means explicit") rather than two, it is what
`Provenance::of` derives automatically from the type, and it means no future
edit to the flag can accidentally change what automatic mode is. The v2 plan's
sentence "New save controls may alter persistence, not scan semantics" is about
save controls; `--profiles` is a scan option and belongs with the scan options.

Consequence, stated plainly: `siloscan --profiles none` is an *explicit* run, so
it prints no `setup:`/`capabilities:` lines and does not auto-save. There is
therefore no way to get the bare journey with profiles off from the command line
alone. At launch the answers are `--profiles none` (accepting explicit mode) or
`--no-default-rules`. If real use shows that is not enough, the right home for a
persistent per-repository choice is a `[profiles]` section in `siloscan.toml`,
which is automatic-mode-compatible by construction — listed as an optional
package in section 7, not as launch scope.

### 2.2 Defaults by provenance

The default is a property of the request, not of the CLI:

```rust
ScanRequest::automatic()   // ProfileSelection::Auto
ScanRequest::explicit(..)  // ProfileSelection::None
```

`with_profiles(selection)` records `profiles` in `explicit_overrides` like every
other option. The CLI passes it through only when
`Provenance::has("profiles")`, exactly as it does for `--cache-dir`.

This is what keeps the oracle green without a single conditional in the output
path: every v1.5.1 oracle case supplies a `PATH`, so every one of them resolves
`ProfileSelection::None`, loads exactly the 220-rule pack, and produces the same
bytes. The one surface that changes is `--help`, which gains a line;
`v2_oracle_harness.rs::first_dropped_line` allows additions anywhere and fails
only on a removal, a reorder or a rewording.

### 2.3 Does the bare journey enable profiles in 2.1.0?

**It needs its own gate, and it must not ride along with the machinery.**

Two independent things break the moment `automatic()` means `Auto`:

1. `v2_journey.rs` asserts the bare first two lines exactly, across ten
   ecosystem fixtures and both binary names, including
   `rules: default-secrets@1` and a `rule_sources` array of exactly one entry.
   That is a deliberate freeze of the bare contract and changing it is a
   decision, not a test fix.
2. The paired 5% performance gate compares the candidate against the pinned
   v1.5.1 reference, which parses nothing on a bare run. Section 5 measures the
   ratio at **6.1x wall time and 1.16x peak RSS** on the frozen scale tree,
   with a rule pack that reports nothing at all. No
   mitigation closes a gap that size, because the gap *is* the feature: the
   reference does not parse and the candidate must.

So the flip requires the 2.1 baseline question to be answered first — most
plausibly by re-basing the bare lanes on v2.0.0-with-profiles-off and giving
profiles-on their own declared budget — and that is a maintainer decision this
document cannot make. **Unverified:** whether the missing v2.1 map already
states a default-change rule that settles it.

Recommended sequencing: packages P0–P4 land with `automatic()` still meaning
`Auto` in the *type* but with **no profile documents shipped**, so the selection
resolves to nothing, the journey lines are unchanged, and the machinery is
provably inert. P5 ships the documents and the flip together, under the new
gate. That way every package before the last one has an empty output diff.

---

## 3. Metric rules

### 3.1 The engine addition

The AST engine reports one finding per query match and cannot count: a
tree-sitter query has no aggregation, so `cyclomatic-complexity > 15` is not
expressible. Four measures are wanted — cyclomatic complexity, nesting depth,
function length, parameter count — and all four are "one number per function
node, compared to a threshold".

**Recommendation: a new `metric:` payload with a dedicated engine, not a
query-plus-counter hybrid.**

```yaml
- id: maintainability.rust.function-complexity
  severity: warning
  message: function is more branched than the profile allows
  languages: [rust]          # the ordinary rule-level filter; no new envelope
  metric:
    measure: cyclomatic-complexity
    max: 15
```

```rust
// rules.rs
CompiledPayload::Metric { measure: Measure, max: u32 }

pub enum Measure { CyclomaticComplexity, NestingDepth, FunctionLines, ParameterCount }
```

`languages:` is the existing rule-level key that `applies()` already honours, so
a metric rule needs no new schema nesting. The AST payload's `languages`
rejection does not apply: it exists because an ast rule's coverage is its query
map, and a metric rule has no query map.

Why not the hybrid (a query that matches branch nodes plus a counter that groups
matches by enclosing function):

- Grouping by enclosing function needs a "which node kinds are functions" table
  per language anyway. The hybrid pays for the table *and* a query-engine pass.
- A query cannot express "count only `binary_expression` whose `operator` field
  is `&&` or `||`". `#eq?` predicates apply to captured text; the operator is an
  anonymous node, and matching it in the pattern (`operator: "&&"`) means two
  patterns per language per rule.
- Nesting depth is not a count of anything; it is a maximum over paths.
- A rule author writing `max: 15` in YAML should not also be maintaining ten
  queries whose job is to enumerate the branch grammar of ten languages. That
  table is the engine's, versioned with the grammar bumps that can invalidate
  it.

### 3.2 Engine shape

`crates/siloscan-core/src/engines/metric.rs`, mirroring `ast.rs`:

```rust
pub fn scan_file(
    rules: &[CompiledRule],
    path_rel: &str,
    language: Option<&str>,
    content: &str,
    tree: Option<&Tree>,
) -> Vec<Finding>
```

It reuses the tree `scan_text` already builds, so a file with a metric rule
loaded is parsed on exactly the same terms as one with an ast rule.
`ParseNeeds` grows a third arm: `CompiledPayload::Metric` contributes every
language that has a node-kind table.

One walk per file with a `TreeCursor`. At each node whose kind is in the
language's `FUNCTION` set, compute all four measures over the subtree and report
each rule whose `max` is exceeded.

**Nested functions are measured separately and are not attributed to their
parent.** A closure inside a function is its own unit: its branches do not
inflate the enclosing function's complexity, and its own complexity is reported
against itself. That is what every established implementation does and it is
what keeps one edit from moving two findings.

**The reported span is the function's `name` node when it has one, otherwise the
function node's first token.** This is the single most important detail in the
engine, because `findings::fingerprint` is `(rule_id, path, matched,
occurrence)`: reporting the whole function body as `matched` would move the
fingerprint on *any* edit inside the function, so every baseline entry and every
`--fail-on` gate would churn on unrelated changes. Anonymous functions
(closures, lambdas, arrow functions) have no name and fall back to the first
token, with the occurrence index separating two anonymous functions in one file
— the same mechanism the ast engine already uses for repeated identical matches.

Measures:

| Measure | Definition |
| --- | --- |
| `cyclomatic-complexity` | `1 + count(branch nodes in the function's own subtree)`, where a `BINARY` node counts only when its `operator` field is one of the language's short-circuit operators |
| `nesting-depth` | maximum number of enclosing `NESTING` nodes reached inside the function's own subtree |
| `function-lines` | `end_position.row - start_position.row + 1` of the function node |
| `parameter-count` | named children of the node's parameter list (see the per-language column) |

### 3.3 Per-language node kinds

Every kind below was read out of `node-types.json` in
`~/.cargo/registry/src/index.crates.io-*/tree-sitter-*` at the versions the
workspace pins: c 0.24.2, cpp 0.23.4, c-sharp 0.23.5, go 0.25.0, java 0.23.5,
javascript 0.25.0, python 0.25.0, ruby 0.23.1, rust 0.24.2, typescript 0.23.2
(the `typescript/` grammar, not `tsx/`). A grammar bump is a change to these
tables and must fail a test rather than silently drop a kind — see the
`every_named_kind_still_exists` test in section 7's P2.

**FUNCTION** — the units measured.

| Language | Kinds |
| --- | --- |
| c | `function_definition` |
| cpp | `function_definition`, `lambda_expression` |
| csharp | `method_declaration`, `constructor_declaration`, `destructor_declaration`, `operator_declaration`, `local_function_statement`, `accessor_declaration`, `lambda_expression`, `anonymous_method_expression` |
| go | `function_declaration`, `method_declaration`, `func_literal` |
| java | `method_declaration`, `constructor_declaration`, `compact_constructor_declaration`, `lambda_expression` |
| javascript | `function_declaration`, `function_expression`, `generator_function`, `generator_function_declaration`, `arrow_function`, `method_definition` |
| python | `function_definition`, `lambda` |
| ruby | `method`, `singleton_method`, `lambda`, `do_block`, `block` |
| rust | `function_item`, `closure_expression` |
| typescript | `function_declaration`, `function_expression`, `generator_function`, `generator_function_declaration`, `arrow_function`, `method_definition` |

Deliberate exclusions: TypeScript's `function_signature`, `method_signature` and
`abstract_method_signature` have no `body` field — there is nothing to measure.
C++ `function_definition` covers methods, templates and `operator` overloads,
which is why the row is short. Ruby's `do_block`/`block` are included because in
Ruby a block is where the code is; a profile that measured only `method` would
miss most of a Rails codebase.

**BRANCH** — each occurrence adds 1 to cyclomatic complexity.

| Language | Kinds | Short-circuit operators on `BINARY` |
| --- | --- | --- |
| c | `if_statement`, `while_statement`, `do_statement`, `for_statement`, `case_statement`, `conditional_expression` | `binary_expression`: `&&`, `\|\|` |
| cpp | the c set plus `for_range_loop`, `catch_clause` | `binary_expression`: `&&`, `\|\|`, `and`, `or` |
| csharp | `if_statement`, `while_statement`, `do_statement`, `for_statement`, `foreach_statement`, `switch_section`, `switch_expression_arm`, `catch_clause`, `when_clause`, `conditional_expression`, `conditional_access_expression` | `binary_expression`: `&&`, `\|\|`, `??` |
| go | `if_statement`, `for_statement`, `expression_case`, `type_case`, `communication_case`, `default_case` | `binary_expression`: `&&`, `\|\|` |
| java | `if_statement`, `while_statement`, `do_statement`, `for_statement`, `enhanced_for_statement`, `switch_label`, `catch_clause`, `ternary_expression` | `binary_expression`: `&&`, `\|\|` |
| javascript | `if_statement`, `while_statement`, `do_statement`, `for_statement`, `for_in_statement`, `switch_case`, `switch_default`, `catch_clause`, `ternary_expression` | `binary_expression`: `&&`, `\|\|`, `??` |
| python | `if_statement`, `elif_clause`, `while_statement`, `for_statement`, `except_clause`, `case_clause`, `conditional_expression`, `if_clause` | `boolean_operator`: `and`, `or` |
| ruby | `if`, `elsif`, `unless`, `while`, `until`, `for`, `when`, `in_clause`, `rescue`, `conditional`, `if_modifier`, `unless_modifier`, `while_modifier`, `until_modifier` | `binary`: `&&`, `\|\|`, `and`, `or` |
| rust | `if_expression`, `while_expression`, `loop_expression`, `for_expression`, `match_arm` | `binary_expression`: `&&`, `\|\|` |
| typescript | the javascript set | `binary_expression`: `&&`, `\|\|`, `??` |

Notes that are decisions, not observations:

- `else` is not counted. `else_clause` (c, cpp, javascript, typescript, rust,
  python) and Ruby's `else` add no independent path.
- Python's `if_clause` is the comprehension guard (`[x for x in y if p(x)]`),
  which is a real branch; `elif_clause` is a separate node from `if_statement`
  and must be counted or `elif` chains read as complexity 2.
- Rust counts every `match_arm` including the wildcard, which is the same
  convention as `switch_case`/`when`.
- Go's four `*_case` kinds cover `switch`, type switches and `select`; `for` has
  no separate range form.
- Java counts `switch_label` and not `switch_rule`. The label is the arm in
  both switch styles: an arrow `switch_rule` holds a `switch_label` as its first
  child, so counting both would count every arm of an arrow switch twice and
  leave the two styles disagreeing about the same code. Corrected during P2,
  against a fixture that measures the same switch written both ways.
- The `operator` field exists on the binary node in all ten grammars and its
  value is the operator's anonymous node kind, so the check is
  `node.child_by_field_name("operator").map(|n| n.kind())`.

**NESTING** — nodes that increase depth. The BRANCH set minus the expression
forms (`conditional_expression`, `ternary_expression`, `*_modifier`, the
short-circuit operators, `case`/`when`/`arm` labels), plus the language's block
constructs: `try_statement` and `with_statement` in python, `try_statement` in
java/javascript/typescript/csharp/cpp, `switch_statement`/`expression_switch_statement`/
`type_switch_statement`/`select_statement` in c/cpp/csharp/java/javascript/
typescript/go, `case` in ruby, `match_expression` in rust. Counting the switch
*statement* rather than each label is what keeps a 30-case dispatch from reading
as depth 30.

**PARAMETERS** — the field or child holding the parameter list, and what counts
as one parameter.

| Language | Where | Counted children |
| --- | --- | --- |
| c | `declarator` → `function_declarator` → field `parameters` (`parameter_list`) | `parameter_declaration`, `variadic_parameter` |
| cpp | as c; `lambda_expression` → `declarator` → `abstract_function_declarator` → `parameters` | `parameter_declaration`, `optional_parameter_declaration`, `variadic_parameter_declaration` |
| csharp | field `parameters` (`parameter_list`), or `implicit_parameter` on a lambda | `parameter` |
| go | field `parameters` (`parameter_list`); `receiver` is a separate field and is not counted | `parameter_declaration`, `variadic_parameter_declaration` |
| java | field `parameters` (`formal_parameters`) | `formal_parameter`, `spread_parameter`; `receiver_parameter` is not counted |
| javascript | field `parameters` (`formal_parameters`), or field `parameter` for a bare-identifier arrow | named children |
| python | field `parameters` (`parameters`) or `lambda_parameters` | `identifier`, `default_parameter`, `typed_parameter`, `typed_default_parameter`, `list_splat_pattern`, `dictionary_splat_pattern`; `positional_separator` and `keyword_separator` are not parameters |
| ruby | field `parameters` (`method_parameters`, `block_parameters`, `lambda_parameters`) | named children |
| rust | field `parameters` (`parameters`, `closure_parameters`) | `parameter`, `variadic_parameter`; `self_parameter` is not counted |
| typescript | as javascript, over `required_parameter` and `optional_parameter` | named children |

C and C++ are the only two where the parameter list is not a direct field of the
function node; both go through the declarator chain, which the engine walks once
and caches per function node.

### 3.4 Serialized metric or finding only

**Recommendation: finding only for launch.** Do not add complexity to
`FileMetrics`; do not bump the schema to 1.3.

The decisive reason is the cache. `scan.rs` computes `measure_file` *outside*
`scan_text`, with the comment "a cache hit replaces the engine work below, and
metrics must not move with the cache" — the current three metrics are derived
from the file's text, so a warm-cache run recomputes them for free. A
tree-derived metric has only two homes, and both are expensive:

- Recompute it on every run, which means **parsing on warm-cache hits**. The
  warm lanes are the cheapest thing siloscan does (0.45 s median on the frozen
  tree at v1.5.1); section 5 measures a parse-and-query pass at several seconds
  on the same tree. That converts the four warm cells into guaranteed failures.
- Move it into `CachedFile`, which changes the cache entry shape, and puts a
  per-function measurement into a per-file record that has no place for it.

Two supporting reasons: `FileMetrics` is one number per file and complexity is
one number per function, so serializing it needs a shape decision (max? mean?
the whole distribution?) that no consumer has asked for; and `SCHEMA_VERSION`'s
own doc comment says the minor moves when an existing field changes meaning,
which this would not — so it would be an appended optional field, i.e. exactly
the kind of speculative surface the report has so far refused.

The finding path already carries everything a consumer needs: rule id, path,
line, the function name in `matched`, and a stable fingerprint. If a serialized
distribution is ever wanted, it is additive later and nothing here forecloses
it.

---

## 4. Report and fingerprint impact

**Findings: no schema change, confirmed.** `ReportFinding` is
`{rule_id, severity, message, path, line, column, matched, fingerprint}` and
carries no rule taxonomy. A profile finding is a `Finding` like any other, it
gets a fingerprint from the same `findings::fingerprint`, it is filtered by
`--min-severity`, baselined and suppressed by the same code, and rendered by the
same human/JSON/SARIF writers.

**SARIF needs nothing either, provided profiles load as ordinary rules.**
`to_sarif` builds its `rules[]` descriptors by looking up each reported rule id
in the `RuleSet` it is handed. A profile rule that is a `CompiledRule` in that
set gets a descriptor with its message and severity automatically. This is the
concrete reason the design loads profiles into the one `RuleSet` rather than
running them through a side channel: a side channel would need a second
synthesized-descriptor path, which currently exists exactly once, for
`metrics.duplicate-block`, and is documented as an exception.

**`setup` changes are the two in section 1.4** — extra `rule_sources` entries and
one extra `capabilities` entry. `report_kind`, `scope` and `outcome` are
untouched; none of them mentions rules. The resolved document stays schema 1.2
and the four trailing markers keep their order.

**Baselines.** Schema 1 is unchanged. Every fingerprint of an existing rule is
unchanged, because a fingerprint is `(rule_id, path, matched, occurrence)` and
none of the three inputs moves. A 2.0.0 baseline therefore stays valid against a
2.1.0 scan; the profile findings are simply new and unbaselined, which is what a
baseline is for.

The real compatibility hazard is not the format, it is `--fail-on error`:
profile findings that are new and unbaselined fail a build on the first run
after an upgrade, against a baseline that could not possibly cover them.
`default_pack.rs` already made and documented this argument for the generic
secret rules. **Every launch profile rule must ship at `warning` or `info`.**
Enforce it in the load test from section 1.5, so promoting one to `error` is a
decision someone has to take deliberately.

---

## 5. Cache and performance

### 5.1 What invalidates

`RuleSet::source_hash` hashes `(origin, source)` for every document in load
order, and `Cache::bind` folds it into every entry key. Shipping profiles
changes the loaded document set on any run that selects one, so **every cache
entry for those scans is invalidated once**, on the first run after the upgrade.
That is correct and unavoidable — the entries were produced by a different rule
set — and it is the same one-time cost every pack bump has always had. Cache
state is explicitly disposable in the v2 plan. What must not happen is a scan
whose entries are keyed on a hash that excludes the profiles, which is what
section 1.3's reordering exists to prevent.

There is a second-order effect worth naming: because `Auto` selects on detected
languages, two scans of *different* trees now legitimately have different rule
hashes. Entries are already namespaced per scan root, so nothing collides.

### 5.2 The measurement

Today the shipped pack contains no ast rule, so `ParseNeeds::wants` is false for
every file and a bare scan never reaches tree-sitter. With profiles, every
source file of a detected language is parsed. That is the whole cost, and it was
measured rather than estimated.

Method (`spike-measure.sh`, raw samples in `spike-timings.txt`):

- Tree: `python3 scripts/scale_tree.py --out …`, the frozen 4,097-file / 31 MiB
  scale tree. Its `generated_manifest_sha256` matched the recipe
  (`32e15ce8…5fb4`), so this is the same input the oracle measures.
- Binary: one `cargo build --locked --release -p siloscan` of this worktree.
- Three arms over the identical tree, binary and sink (`--format json` to
  `/dev/null`):
  - **A** — the shipped default pack alone. Nothing is parsed.
  - **B** — default pack plus `spike-pack/`, ten Rust ast rules shaped like a
    reliability/maintainability profile. Parse + ten queries + findings.
  - **C** — default pack plus `spike-pack-silent/`, the same ten query shapes
    with predicates that cannot match. Parse + ten queries, no findings.
- Nine paired samples per arm per cache state in ABBA order after one untimed
  warm-up, medians compared — the acceptance plan's own rule.

Host: Linux 6.8.0-136-generic, 8 CPU, release profile, `--locked`.

| Cache state | Arm | n | Median wall (s) | Ratio vs A | Median peak RSS (KiB) | Ratio vs A |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| no-cache | A (pack only, no parse) | 9 | 1.340 | 1.000 | 200,248 | 1.000 |
| no-cache | B (pack + 10 firing ast rules) | 9 | 8.870 | **6.619** | 348,884 | **1.742** |
| no-cache | C (pack + 10 silent ast rules) | 9 | 8.200 | **6.119** | 233,064 | **1.164** |
| warm | A | 9 | 0.430 | 1.000 | 156,224 | 1.000 |
| warm | B | 9 | 0.870 | **2.023** | 291,276 | **1.864** |
| warm | C | 9 | 0.530 | **1.233** | 185,164 | **1.185** |

Sample dispersion, as the acceptance plan's 20% invalidation rule requires:
median absolute deviation is 2.3%–3.8% of the median in all six cells, so the
job would be valid and the numbers are not noise.

Supplementary measurement — the same silent pack against a one-file tree, which
isolates rule loading from scanning: 0.02 s (A) versus 0.05 s (C), seven samples
each. Ten `Query` compilations cost about 30 ms, or roughly 3 ms per query.

### 5.3 Reading the numbers

**The 5% gate is not close.** Against the shipped pack on the frozen scale tree,
turning parsing on costs **6.1x wall time** and **1.16x peak RSS** with no
findings produced at all (arm C), rising to 6.6x and 1.74x once ten rules
actually report (arm B). The gate rejects at 1.05, on either metric, with no
offsetting allowed. There is no tuning that turns 6.1 into 1.05: arm C reports
nothing, so what is being measured is tree-sitter parsing 31 MiB of Rust, and
that work simply does not exist in the reference.

Three things follow.

1. **The bare default cannot flip while the bare lanes are compared against
   v1.5.1.** Cells 7–14 all fail. This is the arithmetic behind section 2.3, and
   it is a baseline decision, not an optimisation problem.
2. **Explicit invocations are unaffected**, because they resolve
   `ProfileSelection::None` and load exactly what they load today. Cells 1–6 do
   not move. That is the whole reason the default is a property of the request.
3. **A warm cache is what makes profiles affordable in practice.** 1.23x on the
   warm lane (arm C) is still over the gate, but it is the difference between
   "CI got slower" and "CI got six times slower". Of that 0.10 s, about 0.03 s
   is query compilation at load and the rest is the extra rules being consulted
   per file; a cache hit skips the parse entirely, which is the whole gap
   between 6.1x and 1.23x.

Arm B versus arm C is worth naming separately: the extra 0.67 s and 116 MB come
from carrying findings, and the scale tree is 4,096 copies of one file, so ten
firing rules produce roughly 160,000 findings. That is an artefact of the
fixture, not a forecast for a real repository. **Arm C is the number to quote**
for the cost of the mechanism; arm B is the ceiling when a profile is badly
tuned, and it is a second argument for the per-rule false-positive limits in
section 6.

Extrapolating the load cost: a repository where `Auto` selects all twenty
documents at ~15 rules each would compile roughly 300 queries, about 0.9 s per
run, on every run including warm ones. A single-language repository compiles
about 30, or 0.09 s. That is the measured reason section 1.3 selects on detected
languages and section 5.4 keeps lazy compilation on the list.

### 5.4 Mitigations, and what they are worth

| Mitigation | Effect | Verdict |
| --- | --- | --- |
| Restrict `Auto` to detected languages | Saves ~0.8 s of query compilation per run on a single-language tree (measured 3 ms per query). Does not reduce the number of files parsed, which is the dominant cost. | Required anyway; real but second-order. |
| `limits.max_parse_bytes` (exists) | Caps the tail. The scale tree's files are ~7.8 KiB, so it does nothing here. | Real protection against a 100 MB bundle; irrelevant to the median. |
| Lazy query compilation | `compile_ast` builds every `Query` eagerly at load, at a measured 3 ms each, on every run including warm ones. `LazyRegex` is the pattern the crate already uses for exactly this. Worth ~0.03 s per ten rules; more when several languages are selected. | Worth doing; does not change the verdict. |
| Warm cache | A cache hit skips the parse entirely, which is why the warm ratio is what it is. | The only thing that makes profiles affordable in CI. |
| Profile-aware parse budget (new) | Skip parsing for a file whose language has profiles but which no profile rule's `paths` envelope selects. | Only helps profiles that are path-scoped; launch profiles are not. |

None of them changes the conclusion in section 2.3. The cost is the feature.

---

## 6. Corpus and false-positive gates

### 6.1 Why the existing corpus cannot absorb this

`crates/siloscan-core/tests/detection_corpus.rs` measures the *secrets* pack
against `tests/corpus/`, with per-family recall floors and one global precision
proxy at 1.0. Two of its properties do not transfer:

- **Precision 1.0 global.** Every negative is justified individually, so one
  spurious hit is one defect. That is right for credentials, where a false
  positive is a human reading a line that has no secret on it. It is wrong for
  reliability rules, where "this `unwrap` is fine, it is in a test" is a
  judgement call and a global 1.0 would either be false or would force the rules
  down to triviality.
- **Marker substitution.** The whole `{{KIND_PARAM_TAG}}` machinery exists
  because the repository must not spell a credential. Profile positives are
  ordinary code; there is nothing to hide.

So: a parallel corpus with the same discipline and different floors.

### 6.2 Layout

```text
crates/siloscan-core/tests/profiles-corpus/
  tree/
    rust/         positive.rs  negative.rs  ...
    python/       ...
    ...one directory per language...
  manifest.tsv        path, 1-based line, expectation, justification
  noise/
    repos.tsv         the pinned external noise set (section 6.4)
    limits.tsv        per-rule false-positive ceiling, measured at landing
    results.tsv       last recorded measurement, regenerated by the script
  README.md
crates/siloscan-core/tests/profile_corpus.rs
```

`manifest.tsv` keeps the existing four-column shape and the existing
expectations — `NONE`, `ANY`, or one or more rule ids joined by `|` — so a
reader who knows the detection corpus knows this one. `crates/siloscan-core/Cargo.toml`
already carries `exclude = ["tests/corpus/**"]`; it gains
`"tests/profiles-corpus/**"` in the same commit, and `cargo package --list`
proves it.

**The family is the language directory, not a topic.** A per-language floor is
what lets Rust ship while Ruby is still being tuned.

### 6.3 Test shape

`profile_corpus.rs` mirrors `detection_corpus.rs` and asserts three things:

1. **`the_corpus_and_its_manifest_agree`** — every manifest row points at a line
   that exists and no line is claimed twice. Unchanged in spirit from the
   existing harness.
2. **`profile_recall_meets_its_floor_per_language`** — positives reported over
   positives, per language directory, against `RECALL_FLOORS`. Same rule as
   today: the floor is the measured value at landing, descriptive not
   aspirational, and the ticket that closes a gap raises the floor in the same
   commit that moves the number.
3. **`no_rule_exceeds_its_false_positive_limit`** — **per rule**, not global.
   For each rule, the number of findings on manifest `NONE` lines plus the
   findings-per-KLoC over the pinned noise set (6.4), each against that rule's
   row in `noise/limits.tsv`. Per-rule because removal is a per-rule decision:
   a global number tells you the profile is noisy and not which rule to delete.

**Removal rule.** A rule whose measured false-positive rate exceeds its limit is
not widened, re-tuned in place, or given a bigger limit. It is **removed from the
profile** in the release that measures the second consecutive breach, its
manifest rows and justifications stay in place, and its `@N` document version is
bumped because a rule id disappeared (section 1.2). One breach is a regression to
investigate; two is the rule failing to earn its place. The row survives removal
for the same reason the detection corpus refuses to delete a re-argued negative:
the row is the record of a decision.

### 6.4 The noise set

The local repositories under `/home/dev/projects` are almost entirely Go —
`otelcontext` (~5,100 files, mature, ~2,500 tests), `kb` (~300 files), `aiusage`
(~500 files), plus `scanner` (~45) and `rig` (~11), and one small TypeScript
repository. Go noise can therefore be measured against real local code; the
other nine languages cannot, and a corpus of hand-written negatives measures
only what its author thought of.

**Per-language pinned external repositories, cloned at measurement time into a
temporary directory and never committed** — exactly what
`v2_oracle_harness.rs::build_reference` already does with the v1.5.1 reference
checkout. `noise/repos.tsv` is the pinned list:

```text
language  repo_url  commit_sha  license  approx_files  note
```

Proposed set. **Sizes are approximate and from memory; the implementer verifies
the license file and pins an actual commit SHA before the row lands.** The
selection criteria are: permissive licence (`deny.toml`'s allow list is the
standard even though nothing is redistributed), mature, and carrying real tests
— test code is where reliability rules generate their most arguable hits.

| Language | Repository | Licence | Approx. size |
| --- | --- | --- | --- |
| rust | `BurntSushi/ripgrep` | MIT / Unlicense | ~40k LoC |
| rust | `tokio-rs/tokio` | MIT | ~150k LoC |
| rust | `serde-rs/serde` | MIT / Apache-2.0 | ~30k LoC |
| python | `psf/requests` | Apache-2.0 | ~10k LoC |
| python | `pallets/flask` | BSD-3-Clause | ~15k LoC |
| python | `psf/black` | MIT | ~30k LoC |
| javascript | `expressjs/express` | MIT | ~15k LoC |
| javascript | `lodash/lodash` | MIT | ~25k LoC |
| javascript | `axios/axios` | MIT | ~10k LoC |
| typescript | `colinhacks/zod` | MIT | ~20k LoC |
| typescript | `ReactiveX/rxjs` | Apache-2.0 | ~60k LoC |
| typescript | `nestjs/nest` | MIT | ~80k LoC |
| go | `spf13/cobra` | Apache-2.0 | ~20k LoC |
| go | `gin-gonic/gin` | MIT | ~15k LoC |
| go | local `otelcontext` | in-house | ~5,100 files |
| java | `google/gson` | Apache-2.0 | ~30k LoC |
| java | `apache/commons-lang` | Apache-2.0 | ~80k LoC |
| java | `google/guava` | Apache-2.0 | ~500k LoC |
| c | `curl/curl` | curl (MIT-like) | ~150k LoC |
| c | `jqlang/jq` | MIT | ~30k LoC |
| c | `redis/redis` at a `6.2.x` tag | BSD-3-Clause | ~150k LoC |
| cpp | `fmtlib/fmt` | MIT | ~20k LoC |
| cpp | `nlohmann/json` | MIT | ~25k LoC |
| cpp | `abseil/abseil-cpp` | Apache-2.0 | ~200k LoC |
| csharp | `JamesNK/Newtonsoft.Json` | MIT | ~50k LoC |
| csharp | `DapperLib/Dapper` | Apache-2.0 | ~15k LoC |
| csharp | `AutoMapper/AutoMapper` | MIT | ~25k LoC |
| ruby | `sinatra/sinatra` | MIT | ~10k LoC |
| ruby | `puma/puma` | BSD-3-Clause | ~15k LoC |
| ruby | `rails/rails` (`activesupport/` only) | MIT | ~50k LoC |

Two licence traps to check rather than assume: **redis** relicensed away from
BSD-3 after 7.x, so the row must pin a `6.2.x` tag; **sidekiq** was deliberately
left out for the same reason (LGPL from 6.x). `jq` is listed instead of SQLite
because SQLite is not a Git repository that pins cleanly.

### 6.5 Reproducibility of the limits

The script (not implemented here) does exactly this:

1. Read `noise/repos.tsv`. For each row, `git clone --filter=blob:none` into a
   temp directory and `git checkout <commit_sha>` — pinned, so the bytes are the
   same on every machine and in every year.
2. Run the release binary once per repository with `--no-default-rules
   --profiles <the profile under test> --format json --no-cache`, so only the
   profile's own findings are counted and no cache state can affect the result.
3. Write `noise/results.tsv`:

   ```text
   # tool_version=...   # binary_sha256=...   # host=...   # generated=<UTC date>
   rule_id  language  repo  commit  files_scanned  code_lines  findings  per_kloc
   ```

   with a header block in the style of
   `research/oracle-v1.5.1/measurements/reference-linux-amd64.tsv`: the header
   is what makes a number re-derivable a year later.
4. `noise/limits.tsv` holds `rule_id  max_per_kloc  measured_at_landing  ticket`.
   Like `RECALL_FLOORS`, each limit is the value measured when the rule landed,
   with a stated ticket, never a hoped-for number.

The harness reads `limits.tsv` and `results.tsv`. It does **not** clone during
`cargo test`: cloning three repositories per language in a unit test is a
network dependency in the test suite, and #78 forbids network dependencies.
Results are regenerated deliberately, committed, and reviewed as a diff — which
is also what makes a rule's noise regression visible in a pull request.

---

## 7. Implementation packages

Each package has one owner, one local stop, and an empty product-output diff
except where stated.

### P0 — Profile format and the selection seam (core)

- Files: `crates/siloscan-core/src/profiles.rs` (new), `plan.rs`, `cache.rs`
  (one new free function), `rules.rs` (no change yet).
- Adds `ProfileSelection`, `ScanRequest::with_profiles`, the `profiles`
  capability, and profile entries in `rule_sources`. Extracts
  `cache::exclusion_dir` and moves `open_cache` after `project::detect`.
  Ships **no profile document**, so selection resolves to nothing.
- Product output change: none. Every existing test must pass untouched.
- Stop: `cargo test --locked -p siloscan-core --test v2_resolved_plan`;
  new `profile_selection` cases proving `Auto`/`None`/`Named` and the
  `--no-default-rules` interaction; `cargo test --locked -p siloscan --test
  v2_oracle_harness explicit_v1`.

### P1 — `--profiles` on the CLI

- Files: `crates/siloscan/src/main.rs`, `crates/siloscan/tests/v2_cli.rs`.
- Depends on P0.
- Product output change: one `--help` line.
- Stop: `cargo test --locked -p siloscan --test v2_cli`;
  `--test v2_oracle_harness explicit_v1`; `--test v2_journey` unchanged.

### P2 — The `metric:` payload and its engine

- Files: `crates/siloscan-core/src/rules.rs`, `src/engines/metric.rs` (new),
  `src/engines/mod.rs`, `src/scan.rs` (`ParseNeeds`, `scan_text`).
- Depends on nothing in P0/P1; can run in a separate worktree, but `rules.rs`
  and `scan.rs` are shared with nothing else in this plan, so serialise it
  against P0 if the same person takes both.
- Includes `every_named_kind_still_exists`, which asserts every kind in the
  section 3.3 tables is a named node of its grammar, so a grammar bump fails
  loudly instead of silently dropping a branch kind.
- Product output change: none until a document uses it.
- Stop: `cargo test --locked -p siloscan-core engines::metric::tests`;
  `cargo test --locked -p siloscan-core rules::tests`; one fixture per language
  asserting a known complexity, nesting depth, length and parameter count.

### P3 — The profile corpus harness

- Files: `crates/siloscan-core/tests/profile_corpus.rs`,
  `tests/profiles-corpus/**`, `crates/siloscan-core/Cargo.toml` (`exclude`),
  plus the noise script under `scripts/`.
- Depends on P2 (the harness has to be able to load a metric rule).
- Lands with an empty corpus and floors of zero; the rule matrix fills it.
- Stop: `cargo test --locked -p siloscan-core --test profile_corpus`;
  `cargo package --list -p siloscan-core` shows no corpus file.

### P4 — The profile documents

- Files: `crates/siloscan-core/rules/profiles/**`, corpus rows, floors, limits.
- Depends on P0–P3. Owned by the rule-matrix ticket, one language per commit,
  each landing with its own corpus rows and its measured floors.
- Product output change: none while `Auto` selects nothing for explicit runs and
  the bare default has not flipped. A user passing `--profiles` gets findings.
- Stop: per language, `--test profile_corpus` with that language's floor.

### P5 — The bare default, behind its own gate

- Files: `crates/siloscan-core/src/plan.rs` (one line),
  `crates/siloscan/tests/v2_journey.rs`, the performance lane definitions,
  `CHANGELOG.md`, `README.md`.
- Depends on P4 and on a maintainer decision about the 2.1 performance baseline
  (section 2.3). **Do not start this package before that decision exists.**
- Stop: `cargo test --locked -p siloscan --test v2_journey`; the fourteen cells
  under whatever baseline the decision names; `--test v2_oracle_harness` still
  byte-identical, because explicit runs are untouched.

### Optional, not launch scope

- `[profiles]` in `siloscan.toml`, so a repository can turn profiles off without
  leaving automatic mode (section 2.1). Trigger: real complaints, not
  speculation.
- Lazy `Query` compilation (section 5.4).

---

## Appendix: the spike

Committed beside this document, and obviously throwaway.

- `crates/siloscan-core/tests/spike_profiles.rs` — proves that one ast rule per
  language, written in the profile envelope, compiles through `rules::load_str`
  and fires through `scan::scan_opts` for Rust, Python and JavaScript, and that
  a single-language profile stays silent on the other two. Both tests pass.
- `spike-pack/profiles.yaml`, `spike-pack-silent/profiles.yaml` — the ten-rule
  stand-in packs, firing and silent.
- `spike-measure.sh`, `spike-medians.py`, `spike-timings.txt` — the section 5
  measurement and its raw samples.
