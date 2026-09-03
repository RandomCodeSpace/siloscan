# Embedded reliability and maintainability profiles: candidate rule matrix

Phase 1 research for issue #78. This document decides *what the rules would be*.
It writes no rule YAML and no engine code; it is the input to that work, not the
work itself. The machine-readable form of everything below is
`research/embedded-profiles/rule-matrix.json`.

## Summary

- 100 candidate rules: 93 `ast`, 3 `regex`, 4 `metric`.
- 77 reliability, 23 maintainability.
- 71 rules are recommended for the launch set (6-8 per language); every one of them is rated low noise.
- Every `ast` query compiles against the pinned grammar, defines a `@report`
  capture, matches its own positive example and does not match its own negative
  example. See [Verification](#verification).
- No pattern text, query text or message text was copied from any upstream
  project. Every `concept_source` entry is concept-only and carries
  `text_taken: false`. See [Licensing disposition](#licensing-disposition).

### Launch set per language

| Language | Candidates | Launch set | Reliability | Maintainability |
| --- | --- | --- | --- | --- |
| Rust | 10 | 7 | 6 | 1 |
| Python | 10 | 7 | 7 | 0 |
| JavaScript | 9 | 6 | 6 | 0 |
| TypeScript | 12 | 8 | 8 | 0 |
| Go | 9 | 6 | 6 | 0 |
| Java | 9 | 6 | 6 | 0 |
| C | 8 | 7 | 7 | 0 |
| C++ | 9 | 8 | 7 | 1 |
| C# | 9 | 7 | 7 | 0 |
| Ruby | 9 | 8 | 8 | 0 |
| cross-language | 6 | 1 | 0 | 1 |

Every language also inherits the cross-language regex rules, so the effective
default rule count per language is the launch set plus
1.

## How a candidate maps onto the shipped rule schema

Read against `crates/siloscan-core/src/rules.rs` and
`crates/siloscan-core/src/engines/ast.rs` at v2.0.0. Nothing below asks for a
schema change except the `metric` rules, which are called out separately.

- **One payload per rule.** `regex`, `secret`, `ast`, `boundary`, `coverage` and
  `duplication` are mutually exclusive; two payloads is a `MultiplePayloads` load
  error. Every candidate here uses exactly one of `regex` or `ast`.
- **An `ast` rule must not set `languages`.** Setting both is an `AstLanguages`
  load error; a rule's language coverage *is* its query-map keys. So a
  cross-language AST rule is one rule with ten query entries, not ten rules —
  but then all ten share one id, one severity and one message. The matrix keeps
  them as separate per-language rules so that noise can be tuned, and a rule
  retired, per language.
- **`@report` narrows the reported span.** Without it the engine reports the
  match's first capture. Every `ast` candidate defines `@report` explicitly so
  the reported node is a deliberate choice rather than a consequence of capture
  order.
- **The engine de-duplicates on `(rule id, start, end)`.** A query with several
  patterns that can hit the same node — the two-pattern string-comparison rules —
  reports once. That is what makes the two-pattern form safe.
- **Id pattern is `^[a-z0-9-]+(\.[a-z0-9-]+)+$`.** `reliability.<lang>.<slug>`
  and `maintainability.<slug>` both satisfy it. `metrics.duplicate-block` is
  reserved by the duplication metrics and is rejected at load, so no candidate
  may claim it.
- **There is no profile field in the schema.** A profile is therefore the id
  prefix, plus `metadata.tags` if the report wants a machine-readable grouping.
  Adding report categories is additive and does not change finding identity.
- **Fingerprints are `(rule id, path, matched text, occurrence index)`.** Moving a
  rule's `@report` capture to a different node changes every fingerprint that
  rule ever produced, which invalidates baselines. The reported node is part of
  the rule's contract from the first release, not an implementation detail.
- **The regex engine matches over whole file content, not line by line.** `^` and
  `$` need an explicit `(?m)`; `.` does not cross a newline.

### The maintainability profile is thin, and that is the finding

Of 23 maintainability
candidates, 3 survive into the launch set: `maintainability.todo-marker`, `maintainability.rust.dbg-macro`, `maintainability.cpp.using-namespace-in-header`.

That is not an oversight. Maintainability splits cleanly into two halves, and
neither half produces many low-noise rules:

- The **size and shape** half — long function, deep nesting, too many
  parameters, high complexity — is entirely `metric`. A tree-sitter query
  cannot count, so none of it is expressible today.
- The **hygiene** half — empty bodies, leftover prints, commented-out code — is
  expressible and mostly *noisy*. An empty function body is the correct
  spelling of a Python `Protocol`, a Java adapter override, a Go interface
  no-op and a C# virtual hook. A `println!` is a CLI's output. Every one of
  these rules fires hardest on code that is right.

So the honest launch shape is a strong reliability profile and a deliberately
small maintainability profile, with the rest of maintainability parked behind a
corpus measurement (hygiene) or an engine decision (metrics). Shipping a
maintainability profile padded with medium-noise rules would make the first run
of `siloscan` on a real repository unreadable, which is the failure mode the
zero-config framing exists to avoid.

## Profile definitions

**reliability** — the code is likely wrong. Severity `error` is reserved for
shapes with no correct reading at all (`a == a`, `a = a`, a discarded `append`,
a mutable default argument, a C# `throw e;` inside its own catch). Severity
`warning` is for shapes that are wrong in nearly every case but have a
recognised, rare, legitimate use.

**maintainability** — the code is a cost signal rather than a defect. Severity
is `info` throughout, because a maintainability finding that fails a build by
default is a change in what `siloscan` means, and issue #78 forbids that.

## Cross-language rules

### Rules that are language-independent regex, and why regex is safe there

Two rules are pure text and are scoped to no language at all.

`maintainability.todo-marker` is safe as a regex because the thing it looks for
is *lexical, not syntactic*: an uppercase marker word inside a comment. Every
AST alternative is strictly worse. Tree-sitter keeps a comment as one opaque
token, so an AST rule would have to be `(comment) @report (#match? @report ...)`
— the same regex, run over the same bytes, after paying for a parse, and
available only in the ten languages that have a grammar. The regex form works in
a Makefile, a Dockerfile, a shell script and a YAML manifest, which is where
half the abandoned TODOs in a repository actually live. Case sensitivity carries
the precision: `TODO` and `FIXME` in capitals are markers, `todos` and `Todo`
are identifiers, and the pattern only matches the former.

`maintainability.commented-out-code` is a heuristic and is *not* in the launch
set. It is regex for the same reason — commented-out code is text inside an
opaque token — but the false-positive shape is prose that quotes a statement,
which no amount of pattern tightening removes. It is recorded so the decision is
on the record, and held out pending corpus measurement.

`reliability.typescript.ts-suppression-comment` is a third regex rule, but it is
language-scoped with a `languages: [typescript]` envelope rather than global,
because `@ts-ignore` in a non-TypeScript file is a quotation, not a suppression.
A `languages` envelope is legal on a `regex` payload; only `ast`, `boundary`,
`coverage` and `duplication` payloads reject it.

Everything else is AST. The rule of thumb the matrix applies: **regex when the
evidence is lexical and the same in every language; AST when the evidence is a
relationship between nodes.** `a == a` is a relationship. `TODO` is a word.

### Metric rules (engine work, decided separately)

4 candidates cannot be expressed as a tree-sitter query at all,
because a query can match a shape but cannot count, compare or measure depth.
They are listed here so the decision is explicit, and every one of them is
`default: no` — none is proposed for the launch set.

| id | what the engine would have to do | why not a query |
| --- | --- | --- |
| `maintainability.function-length` | count statement lines in a function body | a query has no arithmetic |
| `maintainability.parameter-count` | count parameter nodes | a query cannot compare a child count to a threshold |
| `maintainability.nesting-depth` | measure block nesting | a query cannot express "at least N levels" without N hand-written patterns |
| `maintainability.cyclomatic-complexity` | count decision points per function | needs both counting and a per-language definition of a decision point |

A `metric` payload would be a seventh payload kind with a per-language threshold
map. That is a schema addition, a new engine and a new finding shape, and it is
out of scope for a rule pack. **Recommendation: ship the profiles without any
metric rule.** The existing `duplication` payload already covers the one
size-shaped signal the pack has today, and it emits under the reserved
`metrics.duplicate-block` id.

## Rust

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.rust.self-comparison` | ast | error | low | yes |
| `reliability.rust.self-assignment` | ast | error | low | yes |
| `reliability.rust.identical-if-branches` | ast | warning | low | yes |
| `reliability.rust.unreachable-after-return` | ast | warning | low | yes |
| `reliability.rust.unimplemented-marker` | ast | warning | low | yes |
| `reliability.rust.mem-forget` | ast | warning | low | yes |
| `reliability.rust.unwrap-in-library` | ast | warning | medium | no |
| `maintainability.rust.dbg-macro` | ast | info | low | yes |
| `maintainability.rust.empty-function-body` | ast | info | medium | no |
| `maintainability.rust.print-in-library` | ast | info | high | no |

#### `reliability.rust.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: rust-clippy — `eq_op` (Apache-2.0 OR MIT). Concept only; no text taken.

Noise: Only fires when both operands are the identical identifier token; a deliberate NaN check is written `x.is_nan()`, not `x == x`, in idiomatic Rust.

```scheme
((binary_expression left: (identifier) @l operator: "==" right: (identifier) @r) @report (#eq? @l @r))
```

```rust
// fires
fn f(a: i32) -> bool {
    a == a
}

// does not fire
fn f(a: i32, b: i32) -> bool {
    a == b
}
```

#### `reliability.rust.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: rust-clippy — `self_assignment` (Apache-2.0 OR MIT). Concept only; no text taken.

Noise: `a = a` has no effect in any Rust program; the only false positive shape would be a macro expansion, which this query never sees.

```scheme
((assignment_expression left: (identifier) @l right: (identifier) @r) @report (#eq? @l @r))
```

```rust
// fires
fn f(mut a: i32) {
    a = a;
}

// does not fire
fn f(mut a: i32, b: i32) {
    a = b;
}
```

#### `reliability.rust.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rust-clippy — `if_same_then_else` (Apache-2.0 OR MIT). Concept only; no text taken.

Noise: Compares the two block texts byte for byte, so it fires only when both arms are literally the same source, which is a copy-paste mistake rather than a style.

```scheme
((if_expression consequence: (block) @a alternative: (else_clause (block) @b)) @report (#eq? @a @b))
```

```rust
// fires
fn f(c: bool) -> i32 {
    if c { 1 } else { 1 }
}

// does not fire
fn f(c: bool) -> i32 {
    if c { 1 } else { 2 }
}
```

#### `reliability.rust.unreachable-after-return`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rustc — `unreachable_code` (Apache-2.0 OR MIT (rust-lang/rust; not re-verified in this pass)). Concept only; no text taken.

Noise: A statement immediately following `return;` in the same block is dead in every case; rustc warns about it too, so the finding rarely survives review.

```scheme
(block (expression_statement (return_expression)) . (_) @report)
```

```rust
// fires
fn f() -> i32 {
    return 1;
    let x = 2;
}

// does not fire
fn f() -> i32 {
    let x = 2;
    return x;
}
```

#### `reliability.rust.unimplemented-marker`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rust-clippy — `todo / unimplemented` (Apache-2.0 OR MIT). Concept only; no text taken.

Noise: `todo!` and `unimplemented!` panic at runtime; both are placeholders by definition, so a hit is always an unfinished path.

```scheme
((macro_invocation macro: (identifier) @report (#match? @report "^(todo|unimplemented)$")))
```

```rust
// fires
fn f() {
    todo!()
}

// does not fire
fn f() {
    println!("done")
}
```

#### `reliability.rust.mem-forget`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rust-clippy — `mem_forget` (Apache-2.0 OR MIT). Concept only; no text taken.

Noise: `mem::forget` is rare and always deliberate-looking; the query requires the `mem::` path so a local helper named `forget` does not match.

```scheme
((call_expression function: (scoped_identifier path: (identifier) @p name: (identifier) @f) @report (#eq? @p "mem") (#eq? @f "forget")))
```

```rust
// fires
use std::mem;
fn f(v: Vec<u8>) {
    mem::forget(v);
}

// does not fire
fn f(v: Vec<u8>) {
    drop(v);
}
```

#### `reliability.rust.unwrap-in-library`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: rust-clippy — `unwrap_used / expect_used` (Apache-2.0 OR MIT). Concept only; no text taken.

Noise: Fires on every `unwrap()`/`expect()`, including the ones guarded by an invariant a line above; on a real crate this is the highest-count rule in the Rust set even after excluding tests.

Note: Held out of the launch set on noise. Ships enabled only if a corpus run puts it under the per-rule false-positive limit.

```scheme
((call_expression function: (field_expression field: (field_identifier) @report) (#match? @report "^(unwrap|expect)$")))
```

Paths: `{"exclude": ["**/tests/**", "**/benches/**", "**/examples/**", "**/build.rs"]}`

```rust
// fires
fn f(x: Option<i32>) -> i32 {
    x.unwrap()
}

// does not fire
fn f(x: Option<i32>) -> i32 {
    x.unwrap_or(0)
}
```

#### `maintainability.rust.dbg-macro`

maintainability · ast · severity `info` · noise **low** · launch set: **yes**

Concept source: rust-clippy — `dbg_macro` (Apache-2.0 OR MIT). Concept only; no text taken.

Noise: `dbg!` is a debugging aid that is never intended to ship; the pack's own AST engine test already uses this exact shape.

```scheme
((macro_invocation macro: (identifier) @report (#eq? @report "dbg")))
```

```rust
// fires
fn f(x: i32) {
    dbg!(x);
}

// does not fire
fn f(x: i32) {
    let _ = x;
}
```

#### `maintainability.rust.empty-function-body`

maintainability · ast · severity `info` · noise **medium** · launch set: **no**

Concept source: original to this repository.

Noise: Empty bodies are legitimate for default trait method overrides and for no-op `Drop` implementations, which are common in real crates.

```scheme
(function_item body: (block "{" . "}") @report)
```

```rust
// fires
fn f() {}

// does not fire
fn f() {
    let x = 1;
}
```

#### `maintainability.rust.print-in-library`

maintainability · ast · severity `info` · noise **high** · launch set: **no**

Concept source: rust-clippy — `print_stdout / print_stderr` (Apache-2.0 OR MIT). Concept only; no text taken.

Noise: Fires on every line of a CLI crate's own output code, which is the majority of `println!` uses in this repository's own workspace.

Note: Rejected for the launch set: not separable from intentional CLI output without a path convention the pack cannot assume.

```scheme
((macro_invocation macro: (identifier) @report (#match? @report "^(print|println|eprint|eprintln)$")))
```

```rust
// fires
fn f() {
    println!("hi");
}

// does not fire
fn f() {
    log::info!("hi");
}
```

## Python

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.python.mutable-default-argument` | ast | error | low | yes |
| `reliability.python.self-comparison` | ast | error | low | yes |
| `reliability.python.bare-except` | ast | warning | low | yes |
| `reliability.python.swallowed-exception` | ast | warning | low | yes |
| `reliability.python.assert-on-tuple` | ast | error | low | yes |
| `reliability.python.identical-if-branches` | ast | warning | low | yes |
| `reliability.python.unreachable-after-return` | ast | warning | low | yes |
| `reliability.python.type-equality` | ast | warning | medium | no |
| `maintainability.python.empty-function-body` | ast | info | high | no |
| `maintainability.python.print-call` | ast | info | high | no |

#### `reliability.python.mutable-default-argument`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: ruff — `B006 mutable-argument-default` (MIT). Concept only; no text taken.

Noise: A literal list, dict or set as a default is shared across calls in every Python version; there is no idiom that wants this.

```scheme
(default_parameter value: [(list) (dictionary) (set)] @report)
(typed_default_parameter value: [(list) (dictionary) (set)] @report)
```

```python
# fires
def f(items=[]):
    return items

# does not fire
def f(items=None):
    return items or []
```

#### `reliability.python.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: ruff — `PLR0124 comparison-with-itself` (MIT). Concept only; no text taken.

Noise: Both operands must be the same identifier token; the one legitimate use, a NaN test, is written `math.isnan(x)` in practice.

```scheme
((comparison_operator (identifier) @l "==" (identifier) @r) @report (#eq? @l @r))
```

```python
# fires
def f(a):
    return a == a

# does not fire
def f(a, b):
    return a == b
```

#### `reliability.python.bare-except`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: ruff — `E722 bare-except` (MIT). Concept only; no text taken.

Noise: A bare `except:` also catches `KeyboardInterrupt` and `SystemExit`; the query requires the colon to follow `except` directly, so `except Exception:` does not match.

```scheme
(except_clause "except" . ":") @report
```

```python
# fires
def f():
    try:
        g()
    except:
        pass

# does not fire
def f():
    try:
        g()
    except ValueError:
        pass
```

#### `reliability.python.swallowed-exception`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: ruff — `S110 try-except-pass` (MIT). Concept only; no text taken.

Noise: The handler body must be exactly one `pass`; a handler that logs, comments or re-raises does not match, so intentional suppression written with `contextlib.suppress` is untouched.

```scheme
(except_clause (block . (pass_statement) .) @report)
```

```python
# fires
def f():
    try:
        g()
    except ValueError:
        pass

# does not fire
def f():
    try:
        g()
    except ValueError:
        log.warning('x')
```

#### `reliability.python.assert-on-tuple`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: ruff — `F631 assert-on-string-literal family` (MIT). Concept only; no text taken.

Noise: A non-empty tuple is always truthy, so `assert (x, 'msg')` never fails; there is no correct program with this shape.

```scheme
(assert_statement (tuple) @report)
```

```python
# fires
def f(x):
    assert (x, 'must be set')

# does not fire
def f(x):
    assert x, 'must be set'
```

#### `reliability.python.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: SonarSource S1871 — `identical branches` (SONAR Source-Available License v1.0 (non-OSI; upstream repo now private)). Concept only; no text taken.

Noise: Byte-identical branch bodies only; indentation differences alone keep it from firing on coincidentally similar arms.

```scheme
((if_statement consequence: (block) @a alternative: (else_clause body: (block) @b)) @report (#eq? @a @b))
```

```python
# fires
def f(c):
    if c:
        return 1
    else:
        return 1

# does not fire
def f(c):
    if c:
        return 1
    else:
        return 2
```

#### `reliability.python.unreachable-after-return`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: SonarSource S1763 — `unreachable code` (SONAR Source-Available License v1.0 (non-OSI; upstream repo now private)). Concept only; no text taken.

Noise: A statement immediately after `return` in the same block is dead; Python has no fallthrough construct that makes this legal.

```scheme
(block (return_statement) . (_) @report)
```

```python
# fires
def f():
    return 1
    x = 2

# does not fire
def f():
    x = 2
    return x
```

#### `reliability.python.type-equality`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: ruff — `E721 type-comparison` (MIT). Concept only; no text taken.

Noise: `type(x) == T` is usually meant as `isinstance`, but exact-type dispatch is a real pattern in serialization code, so a minority of hits are deliberate.

```scheme
((comparison_operator (call function: (identifier) @f) "==") @report (#eq? @f "type"))
```

```python
# fires
def f(x):
    return type(x) == int

# does not fire
def f(x):
    return isinstance(x, int)
```

#### `maintainability.python.empty-function-body`

maintainability · ast · severity `info` · noise **high** · launch set: **no**

Concept source: original to this repository.

Noise: `def f(): ...` and `pass` bodies are the normal spelling of a Protocol, an abstract base method and a stub file, so most hits are correct code.

Note: Rejected for the launch set: indistinguishable from Protocol and ABC stubs.

```scheme
(function_definition body: (block . (pass_statement) .) @report)
```

```python
# fires
def f():
    pass

# does not fire
def f():
    return 1
```

#### `maintainability.python.print-call`

maintainability · ast · severity `info` · noise **high** · launch set: **no**

Concept source: ruff — `T201 print` (MIT). Concept only; no text taken.

Noise: Fires on every script and CLI entry point; the pack cannot tell a debug print from a program's own output.

Note: Rejected for the launch set on noise.

```scheme
((call function: (identifier) @report (#eq? @report "print")))
```

```python
# fires
def f():
    print('hi')

# does not fire
def f():
    log.info('hi')
```

## JavaScript

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.javascript.self-comparison` | ast | error | low | yes |
| `reliability.javascript.self-assignment` | ast | error | low | yes |
| `reliability.javascript.empty-catch` | ast | warning | low | yes |
| `reliability.javascript.identical-if-branches` | ast | warning | low | yes |
| `reliability.javascript.unreachable-after-return` | ast | warning | medium | no |
| `reliability.javascript.debugger-statement` | ast | error | low | yes |
| `reliability.javascript.constant-condition` | ast | warning | low | yes |
| `reliability.javascript.loose-equality` | ast | warning | medium | no |
| `maintainability.javascript.empty-function-body` | ast | info | medium | no |

#### `reliability.javascript.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: eslint — `no-self-compare` (MIT). Concept only; no text taken.

Noise: Both operands must be the same identifier; the NaN idiom is `Number.isNaN(x)` in any code new enough to have a linter.

```scheme
((binary_expression left: (identifier) @l operator: ["==" "==="] right: (identifier) @r) @report (#eq? @l @r))
```

```javascript
// fires
function f(a) {
  return a === a;
}

// does not fire
function f(a, b) {
  return a === b;
}
```

#### `reliability.javascript.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: eslint — `no-self-assign` (MIT). Concept only; no text taken.

Noise: `a = a` is a no-op; the only near-miss, a property assignment such as `this.a = a`, is a different node shape and does not match.

```scheme
((assignment_expression left: (identifier) @l right: (identifier) @r) @report (#eq? @l @r))
```

```javascript
// fires
function f(a) {
  a = a;
  return a;
}

// does not fire
function f(a, b) {
  a = b;
  return a;
}
```

#### `reliability.javascript.empty-catch`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: eslint — `no-empty` (MIT). Concept only; no text taken.

Noise: The block must be literally `{}`; a handler containing only a comment keeps its comment node and does not match, which is the documented way to opt out.

```scheme
(catch_clause body: (statement_block "{" . "}") @report)
```

```javascript
// fires
try {
  g();
} catch (e) {}

// does not fire
try {
  g();
} catch (e) {
  log(e);
}
```

#### `reliability.javascript.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: SonarSource S1871 — `identical branches` (SONAR Source-Available License v1.0 (non-OSI; upstream repo now private)). Concept only; no text taken.

Noise: Byte-identical block text on both arms, which is a copy-paste error rather than a style choice.

```scheme
((if_statement consequence: (statement_block) @a alternative: (else_clause (statement_block) @b)) @report (#eq? @a @b))
```

```javascript
// fires
function f(c) {
  if (c) {
    return 1;
  } else {
    return 1;
  }
}

// does not fire
function f(c) {
  if (c) {
    return 1;
  } else {
    return 2;
  }
}
```

#### `reliability.javascript.unreachable-after-return`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: eslint — `no-unreachable` (MIT). Concept only; no text taken.

Noise: A hoisted `function` declaration written after `return` is still reachable and is legal, idiomatic JavaScript; the candidate query does not exclude it, so every helper declared at the bottom of a function would report.

Note: Held out of the launch set until the query excludes `function_declaration` as the following sibling. The other nine languages have no hoisting rule and keep this rule on by default.

```scheme
(statement_block (return_statement) . (_) @report)
```

```javascript
// fires
function f() {
  return 1;
  const x = 2;
}

// does not fire
function f() {
  const x = 2;
  return x;
}
```

#### `reliability.javascript.debugger-statement`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: eslint — `no-debugger` (MIT). Concept only; no text taken.

Noise: `debugger` has exactly one meaning and never belongs in shipped code.

```scheme
(debugger_statement) @report
```

```javascript
// fires
function f() {
  debugger;
  return 1;
}

// does not fire
function f() {
  return 1;
}
```

#### `reliability.javascript.constant-condition`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: eslint — `no-constant-condition` (MIT). Concept only; no text taken.

Noise: Only a literal `true`/`false` as the whole condition matches; the `while (true)` loop idiom is a different node and is not covered by this if-only query.

```scheme
(if_statement condition: (parenthesized_expression [(true) (false)]) @report)
```

```javascript
// fires
function f() {
  if (true) {
    return 1;
  }
  return 0;
}

// does not fire
function f(c) {
  if (c) {
    return 1;
  }
  return 0;
}
```

#### `reliability.javascript.loose-equality`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: eslint — `eqeqeq` (MIT). Concept only; no text taken.

Noise: `x == null` as a combined null/undefined check is deliberate and common, and the query cannot separate it from an accidental coercion.

Note: Held out of the launch set; ships only with a `null`-operand exclusion and a corpus measurement.

```scheme
(binary_expression operator: ["==" "!="]) @report
```

```javascript
// fires
function f(a, b) {
  return a == b;
}

// does not fire
function f(a, b) {
  return a === b;
}
```

#### `maintainability.javascript.empty-function-body`

maintainability · ast · severity `info` · noise **medium** · launch set: **no**

Concept source: eslint — `no-empty-function` (MIT). Concept only; no text taken.

Noise: Empty callbacks and no-op default handlers are idiomatic, so a meaningful share of hits are intentional.

```scheme
(function_declaration body: (statement_block "{" . "}") @report)
```

```javascript
// fires
function f() {}

// does not fire
function f() {
  return 1;
}
```

## TypeScript

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.typescript.self-comparison` | ast | error | low | yes |
| `reliability.typescript.self-assignment` | ast | error | low | yes |
| `reliability.typescript.empty-catch` | ast | warning | low | yes |
| `reliability.typescript.identical-if-branches` | ast | warning | low | yes |
| `reliability.typescript.unreachable-after-return` | ast | warning | medium | no |
| `reliability.typescript.debugger-statement` | ast | error | low | yes |
| `reliability.typescript.constant-condition` | ast | warning | low | yes |
| `reliability.typescript.loose-equality` | ast | warning | medium | no |
| `maintainability.typescript.empty-function-body` | ast | info | medium | no |
| `reliability.typescript.any-assertion` | ast | warning | low | yes |
| `reliability.typescript.non-null-assertion` | ast | warning | medium | no |
| `reliability.typescript.ts-suppression-comment` | regex | warning | low | yes |

#### `reliability.typescript.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: eslint — `no-self-compare` (MIT). Concept only; no text taken.

Noise: Both operands must be the same identifier; the NaN idiom is `Number.isNaN(x)` in any code new enough to have a linter.

```scheme
((binary_expression left: (identifier) @l operator: ["==" "==="] right: (identifier) @r) @report (#eq? @l @r))
```

```typescript
// fires
function f(a) {
  return a === a;
}

// does not fire
function f(a, b) {
  return a === b;
}
```

#### `reliability.typescript.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: eslint — `no-self-assign` (MIT). Concept only; no text taken.

Noise: `a = a` is a no-op; the only near-miss, a property assignment such as `this.a = a`, is a different node shape and does not match.

```scheme
((assignment_expression left: (identifier) @l right: (identifier) @r) @report (#eq? @l @r))
```

```typescript
// fires
function f(a) {
  a = a;
  return a;
}

// does not fire
function f(a, b) {
  a = b;
  return a;
}
```

#### `reliability.typescript.empty-catch`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: eslint — `no-empty` (MIT). Concept only; no text taken.

Noise: The block must be literally `{}`; a handler containing only a comment keeps its comment node and does not match, which is the documented way to opt out.

```scheme
(catch_clause body: (statement_block "{" . "}") @report)
```

```typescript
// fires
try {
  g();
} catch (e) {}

// does not fire
try {
  g();
} catch (e) {
  log(e);
}
```

#### `reliability.typescript.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: SonarSource S1871 — `identical branches` (SONAR Source-Available License v1.0 (non-OSI; upstream repo now private)). Concept only; no text taken.

Noise: Byte-identical block text on both arms, which is a copy-paste error rather than a style choice.

```scheme
((if_statement consequence: (statement_block) @a alternative: (else_clause (statement_block) @b)) @report (#eq? @a @b))
```

```typescript
// fires
function f(c) {
  if (c) {
    return 1;
  } else {
    return 1;
  }
}

// does not fire
function f(c) {
  if (c) {
    return 1;
  } else {
    return 2;
  }
}
```

#### `reliability.typescript.unreachable-after-return`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: eslint — `no-unreachable` (MIT). Concept only; no text taken.

Noise: A hoisted `function` declaration written after `return` is still reachable and is legal, idiomatic JavaScript; the candidate query does not exclude it, so every helper declared at the bottom of a function would report.

Note: Held out of the launch set until the query excludes `function_declaration` as the following sibling. The other nine languages have no hoisting rule and keep this rule on by default.

```scheme
(statement_block (return_statement) . (_) @report)
```

```typescript
// fires
function f() {
  return 1;
  const x = 2;
}

// does not fire
function f() {
  const x = 2;
  return x;
}
```

#### `reliability.typescript.debugger-statement`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: eslint — `no-debugger` (MIT). Concept only; no text taken.

Noise: `debugger` has exactly one meaning and never belongs in shipped code.

```scheme
(debugger_statement) @report
```

```typescript
// fires
function f() {
  debugger;
  return 1;
}

// does not fire
function f() {
  return 1;
}
```

#### `reliability.typescript.constant-condition`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: eslint — `no-constant-condition` (MIT). Concept only; no text taken.

Noise: Only a literal `true`/`false` as the whole condition matches; the `while (true)` loop idiom is a different node and is not covered by this if-only query.

```scheme
(if_statement condition: (parenthesized_expression [(true) (false)]) @report)
```

```typescript
// fires
function f() {
  if (true) {
    return 1;
  }
  return 0;
}

// does not fire
function f(c) {
  if (c) {
    return 1;
  }
  return 0;
}
```

#### `reliability.typescript.loose-equality`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: eslint — `eqeqeq` (MIT). Concept only; no text taken.

Noise: `x == null` as a combined null/undefined check is deliberate and common, and the query cannot separate it from an accidental coercion.

Note: Held out of the launch set; ships only with a `null`-operand exclusion and a corpus measurement.

```scheme
(binary_expression operator: ["==" "!="]) @report
```

```typescript
// fires
function f(a, b) {
  return a == b;
}

// does not fire
function f(a, b) {
  return a === b;
}
```

#### `maintainability.typescript.empty-function-body`

maintainability · ast · severity `info` · noise **medium** · launch set: **no**

Concept source: eslint — `no-empty-function` (MIT). Concept only; no text taken.

Noise: Empty callbacks and no-op default handlers are idiomatic, so a meaningful share of hits are intentional.

```scheme
(function_declaration body: (statement_block "{" . "}") @report)
```

```typescript
// fires
function f() {}

// does not fire
function f() {
  return 1;
}
```

#### `reliability.typescript.any-assertion`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: typescript-eslint — `no-explicit-any` (MIT). Concept only; no text taken.

Noise: `as any` discards every type guarantee at that point; it is always a deliberate escape hatch and worth a finding even when intentional.

```scheme
((as_expression (predefined_type) @t) @report (#eq? @t "any"))
```

```typescript
// fires
function f(x: unknown) {
  return (x as any).id;
}

// does not fire
function f(x: unknown) {
  return (x as { id: string }).id;
}
```

#### `reliability.typescript.non-null-assertion`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: typescript-eslint — `no-non-null-assertion` (MIT). Concept only; no text taken.

Noise: The `!` operator is the TypeScript analogue of `unwrap()`; it is frequent enough in well-typed code that a default-on rule would dominate the report.

```scheme
(non_null_expression) @report
```

```typescript
// fires
function f(x?: string) {
  return x!.length;
}

// does not fire
function f(x?: string) {
  return x?.length ?? 0;
}
```

#### `reliability.typescript.ts-suppression-comment`

reliability · regex · severity `warning` · noise **low** · launch set: **yes**

Concept source: typescript-eslint — `ban-ts-comment` (MIT). Concept only; no text taken.

Noise: `@ts-ignore` is an exact literal that appears only where a type error was silenced; `@ts-expect-error` is deliberately excluded because it fails when the error goes away.

Note: Regex rather than AST: tree-sitter keeps comments as opaque tokens, so a query cannot inspect their text without a `#match?` on a comment node, and the plain literal is cheaper and equally precise. Scoped with `languages: [typescript]`.

```
@ts-ignore\b
```

```typescript
// fires
// @ts-ignore
const x: number = 'a';

// does not fire
// @ts-expect-error deliberate
const x: number = 'a';
```

## Go

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.go.self-comparison` | ast | error | low | yes |
| `reliability.go.self-assignment` | ast | error | low | yes |
| `reliability.go.append-result-discarded` | ast | error | low | yes |
| `reliability.go.defer-in-loop` | ast | warning | low | yes |
| `reliability.go.identical-if-branches` | ast | warning | low | yes |
| `reliability.go.unreachable-after-return` | ast | warning | low | yes |
| `reliability.go.unchecked-type-assertion` | ast | warning | medium | no |
| `maintainability.go.empty-function-body` | ast | info | medium | no |
| `maintainability.go.panic-in-library` | ast | info | high | no |

#### `reliability.go.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: go-tools (staticcheck) — `SA4000` (MIT). Concept only; no text taken.

Noise: Go has no NaN-comparison idiom that needs `x == x`; `math.IsNaN` is the spelling, so a hit is a mistake.

```scheme
((binary_expression left: (identifier) @l operator: "==" right: (identifier) @r) @report (#eq? @l @r))
```

```go
// fires
package p

func f(a int) bool {
	return a == a
}

// does not fire
package p

func f(a, b int) bool {
	return a == b
}
```

#### `reliability.go.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: go-tools (staticcheck) — `SA4018` (MIT). Concept only; no text taken.

Noise: Requires exactly one identifier on each side of a plain `=`; multi-value assignments and struct-field writes are different node shapes.

```scheme
((assignment_statement left: (expression_list . (identifier) @l .) operator: "=" right: (expression_list . (identifier) @r .)) @report (#eq? @l @r))
```

```go
// fires
package p

func f(a int) int {
	a = a
	return a
}

// does not fire
package p

func f(a, b int) int {
	a = b
	return a
}
```

#### `reliability.go.append-result-discarded`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: golang/go vet — `unusedresult (with go-tools SA4010 as the second reference)` (BSD-3-Clause (go vet) / MIT (go-tools)). Concept only; no text taken.

Noise: `append` returns a new slice header; calling it as a statement always loses the result, and there is no correct program that does it.

```scheme
((expression_statement (call_expression function: (identifier) @f) @report (#eq? @f "append")))
```

```go
// fires
package p

func f(xs []int) []int {
	append(xs, 1)
	return xs
}

// does not fire
package p

func f(xs []int) []int {
	xs = append(xs, 1)
	return xs
}
```

#### `reliability.go.defer-in-loop`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: go-tools staticcheck SA9001-family and the Go review-comments guidance — `defer inside a loop` (MIT / BSD-3-Clause). Concept only; no text taken.

Noise: A `defer` in a loop body runs only when the enclosing function returns, so it accumulates handles; the rare deliberate case is written in a closure, which is a different node.

```scheme
(for_statement body: (block (statement_list (defer_statement) @report)))
```

```go
// fires
package p

func f(paths []string) {
	for _, p := range paths {
		defer close(p)
	}
}

// does not fire
package p

func f(paths []string) {
	for _, p := range paths {
		close(p)
	}
}
```

#### `reliability.go.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: SonarSource S1871 — `identical branches` (SONAR Source-Available License v1.0 (non-OSI; upstream repo now private)). Concept only; no text taken.

Noise: Byte-identical blocks on both arms.

```scheme
((if_statement consequence: (block) @a alternative: (block) @b) @report (#eq? @a @b))
```

```go
// fires
package p

func f(c bool) int {
	if c {
		return 1
	} else {
		return 1
	}
}

// does not fire
package p

func f(c bool) int {
	if c {
		return 1
	} else {
		return 2
	}
}
```

#### `reliability.go.unreachable-after-return`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: go-tools (staticcheck) — `SA4006-family / unreachable` (MIT). Concept only; no text taken.

Noise: The Go compiler rejects most of these already, so a surviving hit is in a branch the compiler could not see; either way it is dead.

```scheme
(statement_list (return_statement) . (_) @report)
```

```go
// fires
package p

func f() int {
	return 1
	println(2)
}

// does not fire
package p

func f() int {
	println(2)
	return 1
}
```

#### `reliability.go.unchecked-type-assertion`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: go-tools (staticcheck) / errcheck — `unchecked type assertion` (MIT). Concept only; no text taken.

Noise: The single-value form panics on a wrong type, but it is idiomatic wherever the type is already known from a switch a few lines above, which the query cannot see.

```scheme
(short_var_declaration left: (expression_list . (identifier) .) right: (expression_list . (type_assertion_expression) @report .))
```

```go
// fires
package p

func f(x interface{}) int {
	v := x.(int)
	return v
}

// does not fire
package p

func f(x interface{}) int {
	v, ok := x.(int)
	if !ok {
		return 0
	}
	return v
}
```

#### `maintainability.go.empty-function-body`

maintainability · ast · severity `info` · noise **medium** · launch set: **no**

Concept source: original to this repository.

Noise: Empty bodies are the normal way to satisfy an interface with a no-op implementation, which is common in Go test doubles and adapters.

```scheme
(function_declaration body: (block "{" . "}") @report)
```

```go
// fires
package p

func f() {}

// does not fire
package p

func f() {
	println(1)
}
```

#### `maintainability.go.panic-in-library`

maintainability · ast · severity `info` · noise **high** · launch set: **no**

Concept source: original to this repository.

Noise: `panic` in `main` and in initialisation code is normal Go; the pack has no way to tell library code from a program entry point by path alone.

Note: Rejected for the launch set on noise.

```scheme
((call_expression function: (identifier) @report (#eq? @report "panic")))
```

```go
// fires
package p

func f() {
	panic("boom")
}

// does not fire
package p

import "errors"

func f() error {
	return errors.New("boom")
}
```

## Java

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.java.empty-catch` | ast | warning | low | yes |
| `reliability.java.self-comparison` | ast | error | low | yes |
| `reliability.java.self-assignment` | ast | error | low | yes |
| `reliability.java.string-literal-identity` | ast | error | low | yes |
| `reliability.java.identical-if-branches` | ast | warning | low | yes |
| `reliability.java.unreachable-after-return` | ast | warning | low | yes |
| `reliability.java.print-stack-trace` | ast | warning | medium | no |
| `maintainability.java.empty-method-body` | ast | info | high | no |
| `maintainability.java.system-out-print` | ast | info | high | no |

#### `reliability.java.empty-catch`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: PMD EmptyCatchBlock, SpotBugs DE_MIGHT_IGNORE — `empty catch` (PMD BSD-style with DARPA acknowledgement (not SPDX BSD-3-Clause) / SpotBugs LGPL-2.1-or-later). Concept only; no text taken.

Noise: The block must be literally `{}`; a handler holding only a comment keeps a comment node and is not reported, which is the documented opt-out.

```scheme
(catch_clause body: (block "{" . "}") @report)
```

```java
// fires
class C {
  void m() {
    try { g(); } catch (Exception e) {}
  }
}

// does not fire
class C {
  void m() {
    try { g(); } catch (Exception e) { log(e); }
  }
}
```

#### `reliability.java.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: error-prone — `SelfComparison / SelfEquals` (Apache-2.0). Concept only; no text taken.

Noise: Both operands are the same identifier token; the NaN idiom in Java is `Double.isNaN`, so a hit is a mistake.

```scheme
((binary_expression left: (identifier) @l operator: "==" right: (identifier) @r) @report (#eq? @l @r))
```

```java
// fires
class C {
  boolean m(int a) {
    return a == a;
  }
}

// does not fire
class C {
  boolean m(int a, int b) {
    return a == b;
  }
}
```

#### `reliability.java.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: error-prone — `SelfAssignment` (Apache-2.0). Concept only; no text taken.

Noise: `a = a` is a no-op; the field-shadowing shape `this.a = a` is a different node and is excluded.

```scheme
((assignment_expression left: (identifier) @l right: (identifier) @r) @report (#eq? @l @r))
```

```java
// fires
class C {
  void m(int a) {
    a = a;
  }
}

// does not fire
class C {
  int a;
  void m(int a) {
    this.a = a;
  }
}
```

#### `reliability.java.string-literal-identity`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: error-prone — `ReferenceEquality / StringEquality` (Apache-2.0). Concept only; no text taken.

Noise: Comparing to a string literal with `==` tests reference identity; interning makes it work by accident often enough that it is a real, hard bug, and there is no correct reason to write it.

```scheme
(binary_expression left: (_) operator: "==" right: (string_literal)) @report
(binary_expression left: (string_literal) operator: "==") @report
```

```java
// fires
class C {
  boolean m(String s) {
    return s == "x";
  }
}

// does not fire
class C {
  boolean m(String s) {
    return "x".equals(s);
  }
}
```

#### `reliability.java.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: SonarSource S1871 — `identical branches` (SONAR Source-Available License v1.0 (non-OSI; upstream repo now private)). Concept only; no text taken.

Noise: Byte-identical block text on both arms.

```scheme
((if_statement consequence: (block) @a alternative: (block) @b) @report (#eq? @a @b))
```

```java
// fires
class C {
  int m(boolean c) {
    if (c) {
      return 1;
    } else {
      return 1;
    }
  }
}

// does not fire
class C {
  int m(boolean c) {
    if (c) {
      return 1;
    } else {
      return 2;
    }
  }
}
```

#### `reliability.java.unreachable-after-return`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: SonarSource S1763 — `unreachable code` (SONAR Source-Available License v1.0 (non-OSI; upstream repo now private)). Concept only; no text taken.

Noise: javac rejects this, so a hit means the file does not compile or the statement sits behind a construct the query flattened; either is worth a look.

```scheme
(block (return_statement) . (_) @report)
```

```java
// fires
class C {
  int m() {
    return 1;
    // trailing
  }
}

// does not fire
class C {
  int m() {
    int x = 1;
    return x;
  }
}
```

#### `reliability.java.print-stack-trace`

reliability · ast · severity `warning` · noise **medium** · launch set: **no**

Concept source: concept: PMD AvoidPrintStackTrace — `print stack trace` (PMD BSD-style with DARPA acknowledgement (not SPDX BSD-3-Clause)). Concept only; no text taken.

Noise: `printStackTrace()` is wrong in a service but correct in a sample, a test harness and a command-line tool, and the query cannot tell them apart.

```scheme
((method_invocation name: (identifier) @report (#eq? @report "printStackTrace")))
```

```java
// fires
class C {
  void m() {
    try { g(); } catch (Exception e) { e.printStackTrace(); }
  }
}

// does not fire
class C {
  void m() {
    try { g(); } catch (Exception e) { log.error("g", e); }
  }
}
```

#### `maintainability.java.empty-method-body`

maintainability · ast · severity `info` · noise **high** · launch set: **no**

Concept source: original to this repository.

Noise: Empty bodies are the normal spelling of an adapter override, a no-arg constructor and a `@Override` no-op, all of which are correct.

Note: Rejected for the launch set on noise.

```scheme
(method_declaration body: (block "{" . "}") @report)
```

```java
// fires
class C {
  void m() {}
}

// does not fire
class C {
  void m() {
    g();
  }
}
```

#### `maintainability.java.system-out-print`

maintainability · ast · severity `info` · noise **high** · launch set: **no**

Concept source: concept: PMD SystemPrintln — `system println` (PMD BSD-style with DARPA acknowledgement (not SPDX BSD-3-Clause)). Concept only; no text taken.

Noise: Fires on every command-line tool and every teaching example in a repository.

Note: Rejected for the launch set on noise.

```scheme
((method_invocation object: (field_access object: (identifier) @o) name: (identifier) @report (#eq? @o "System") (#match? @report "^print(ln)?$")))
```

```java
// fires
class C {
  void m() {
    System.out.println("x");
  }
}

// does not fire
class C {
  void m() {
    log.info("x");
  }
}
```

## C

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.c.self-comparison` | ast | error | low | yes |
| `reliability.c.self-assignment` | ast | error | low | yes |
| `reliability.c.assignment-in-condition` | ast | warning | low | yes |
| `reliability.c.empty-if-body` | ast | warning | low | yes |
| `reliability.c.identical-if-branches` | ast | warning | low | yes |
| `reliability.c.unreachable-after-return` | ast | warning | low | yes |
| `maintainability.c.empty-function-body` | ast | info | medium | no |
| `reliability.c.string-literal-comparison` | ast | error | low | yes |

#### `reliability.c.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: clang-tidy — `misc-redundant-expression` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: Both operands are the same identifier token; the float NaN idiom is written with `isnan()` in any code that has a build system.

```scheme
((binary_expression left: (identifier) @l operator: "==" right: (identifier) @r) @report (#eq? @l @r))
```

```c
// fires
int f(int a) {
  return a == a;
}

// does not fire
int f(int a, int b) {
  return a == b;
}
```

#### `reliability.c.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: clang-tidy — `misc-redundant-expression / bugprone-branch-clone family` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: `a = a` is a no-op; the copy-assignment-operator shape uses `this->a`, which is a different node.

```scheme
((assignment_expression left: (identifier) @l operator: "=" right: (identifier) @r) @report (#eq? @l @r))
```

```c
// fires
void f(int a) {
  a = a;
}

// does not fire
void f(int a, int b) {
  a = b;
}
```

#### `reliability.c.assignment-in-condition`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang / clang-tidy — `-Wparentheses diagnostic` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: The deliberate form is written with a second pair of parentheses, which produces a nested parenthesized node the query does not match; that is the same escape hatch compilers use.

```scheme
(if_statement condition: (parenthesized_expression (assignment_expression) @report))
```

```c
// fires
int f(int a, int b) {
  if (a = b) {
    return 1;
  }
  return 0;
}

// does not fire
int f(int a, int b) {
  if ((a = b)) {
    return 1;
  }
  return 0;
}
```

#### `reliability.c.empty-if-body`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang / clang-tidy — `-Wempty-body diagnostic` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: `if (x);` is a stray semicolon in every case; a genuinely empty branch is written `{}`, which is a different node.

```scheme
(if_statement consequence: (expression_statement . ";" .) @report)
```

```c
// fires
int f(int a) {
  if (a);
  return a;
}

// does not fire
int f(int a) {
  if (a) {}
  return a;
}
```

#### `reliability.c.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang-tidy — `bugprone-branch-clone` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: Byte-identical block text on both arms.

```scheme
((if_statement consequence: (compound_statement) @a alternative: (else_clause (compound_statement) @b)) @report (#eq? @a @b))
```

```c
// fires
int f(int c) {
  if (c) {
    return 1;
  } else {
    return 1;
  }
}

// does not fire
int f(int c) {
  if (c) {
    return 1;
  } else {
    return 2;
  }
}
```

#### `reliability.c.unreachable-after-return`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang / clang-tidy — `-Wunreachable-code diagnostic` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: A statement directly after `return` in the same block is dead unless it carries a label, which is a distinct node and is excluded.

Note: A `labeled_statement` after `return` is a legal goto target; the shipped query must exclude it.

```scheme
(compound_statement (return_statement) . (_) @report)
```

```c
// fires
int f(void) {
  return 1;
  g();
}

// does not fire
int f(void) {
  g();
  return 1;
}
```

#### `maintainability.c.empty-function-body`

maintainability · ast · severity `info` · noise **medium** · launch set: **no**

Concept source: original to this repository.

Noise: Empty bodies are used for weak-symbol stubs and for platform no-ops, both of which are correct.

```scheme
(function_definition body: (compound_statement "{" . "}") @report)
```

```c
// fires
void f(void) {}

// does not fire
void f(void) {
  g();
}
```

#### `reliability.c.string-literal-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: clang-tidy — `bugprone-suspicious-string-compare family` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: In C, `s == "x"` compares pointers and is never what the author meant; `strcmp` is the only correct spelling.

```scheme
(binary_expression left: (_) operator: "==" right: (string_literal)) @report
(binary_expression left: (string_literal) operator: "==") @report
```

```c
// fires
int f(const char *s) {
  return s == "x";
}

// does not fire
#include <string.h>
int f(const char *s) {
  return strcmp(s, "x") == 0;
}
```

## C++

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.cpp.self-comparison` | ast | error | low | yes |
| `reliability.cpp.self-assignment` | ast | error | low | yes |
| `reliability.cpp.assignment-in-condition` | ast | warning | low | yes |
| `reliability.cpp.empty-if-body` | ast | warning | low | yes |
| `reliability.cpp.identical-if-branches` | ast | warning | low | yes |
| `reliability.cpp.unreachable-after-return` | ast | warning | low | yes |
| `maintainability.cpp.empty-function-body` | ast | info | medium | no |
| `reliability.cpp.empty-catch` | ast | warning | low | yes |
| `maintainability.cpp.using-namespace-in-header` | ast | info | low | yes |

#### `reliability.cpp.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: clang-tidy — `misc-redundant-expression` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: Both operands are the same identifier token; the float NaN idiom is written with `isnan()` in any code that has a build system.

```scheme
((binary_expression left: (identifier) @l operator: "==" right: (identifier) @r) @report (#eq? @l @r))
```

```cpp
// fires
int f(int a) {
  return a == a;
}

// does not fire
int f(int a, int b) {
  return a == b;
}
```

#### `reliability.cpp.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: clang-tidy — `misc-redundant-expression / bugprone-branch-clone family` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: `a = a` is a no-op; the copy-assignment-operator shape uses `this->a`, which is a different node.

```scheme
((assignment_expression left: (identifier) @l operator: "=" right: (identifier) @r) @report (#eq? @l @r))
```

```cpp
// fires
void f(int a) {
  a = a;
}

// does not fire
void f(int a, int b) {
  a = b;
}
```

#### `reliability.cpp.assignment-in-condition`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang / clang-tidy — `-Wparentheses diagnostic` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: The deliberate form is written with a second pair of parentheses, which produces a nested parenthesized node the query does not match; that is the same escape hatch compilers use.

```scheme
(if_statement condition: (condition_clause value: (assignment_expression) @report))
```

```cpp
// fires
int f(int a, int b) {
  if (a = b) {
    return 1;
  }
  return 0;
}

// does not fire
int f(int a, int b) {
  if ((a = b)) {
    return 1;
  }
  return 0;
}
```

#### `reliability.cpp.empty-if-body`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang / clang-tidy — `-Wempty-body diagnostic` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: `if (x);` is a stray semicolon in every case; a genuinely empty branch is written `{}`, which is a different node.

```scheme
(if_statement consequence: (expression_statement . ";" .) @report)
```

```cpp
// fires
int f(int a) {
  if (a);
  return a;
}

// does not fire
int f(int a) {
  if (a) {}
  return a;
}
```

#### `reliability.cpp.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang-tidy — `bugprone-branch-clone` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: Byte-identical block text on both arms.

```scheme
((if_statement consequence: (compound_statement) @a alternative: (else_clause (compound_statement) @b)) @report (#eq? @a @b))
```

```cpp
// fires
int f(int c) {
  if (c) {
    return 1;
  } else {
    return 1;
  }
}

// does not fire
int f(int c) {
  if (c) {
    return 1;
  } else {
    return 2;
  }
}
```

#### `reliability.cpp.unreachable-after-return`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang / clang-tidy — `-Wunreachable-code diagnostic` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: A statement directly after `return` in the same block is dead unless it carries a label, which is a distinct node and is excluded.

Note: A `labeled_statement` after `return` is a legal goto target; the shipped query must exclude it.

```scheme
(compound_statement (return_statement) . (_) @report)
```

```cpp
// fires
int f(void) {
  return 1;
  g();
}

// does not fire
int f(void) {
  g();
  return 1;
}
```

#### `maintainability.cpp.empty-function-body`

maintainability · ast · severity `info` · noise **medium** · launch set: **no**

Concept source: original to this repository.

Noise: Empty bodies are used for weak-symbol stubs and for platform no-ops, both of which are correct.

```scheme
(function_definition body: (compound_statement "{" . "}") @report)
```

```cpp
// fires
void f(void) {}

// does not fire
void f(void) {
  g();
}
```

#### `reliability.cpp.empty-catch`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: clang-tidy — `bugprone-empty-catch` (Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

Noise: The handler must be literally `{}`; a comment inside keeps a comment node and opts out.

```scheme
(catch_clause body: (compound_statement "{" . "}") @report)
```

```cpp
// fires
void f() {
  try { g(); } catch (...) {}
}

// does not fire
void f() {
  try { g(); } catch (...) { h(); }
}
```

#### `maintainability.cpp.using-namespace-in-header`

maintainability · ast · severity `info` · noise **low** · launch set: **yes**

Concept source: concept: C++ Core Guidelines SF.7 — `do not write using namespace at global scope in a header` (CC-BY-4.0 (guideline prose; not reused)). Concept only; no text taken.

Noise: Scoped to header paths only, where a `using namespace` directive leaks into every translation unit that includes the file; in a .cpp file it is fine and is not scanned.

```scheme
(using_declaration "namespace" (identifier) @report)
```

Paths: `{"include": ["**/*.h", "**/*.hpp", "**/*.hh", "**/*.hxx"]}`

```cpp
// fires
namespace ns { int g(); }
using namespace ns;
int f() { return g(); }

// does not fire
namespace ns { int g(); }
int f() { return ns::g(); }
```

## C#

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.csharp.empty-catch` | ast | warning | low | yes |
| `reliability.csharp.self-comparison` | ast | error | low | yes |
| `reliability.csharp.self-assignment` | ast | error | low | yes |
| `reliability.csharp.rethrow-loses-stack` | ast | error | low | yes |
| `reliability.csharp.async-void` | ast | warning | low | yes |
| `reliability.csharp.identical-if-branches` | ast | warning | low | yes |
| `reliability.csharp.unreachable-after-return` | ast | warning | low | yes |
| `maintainability.csharp.empty-method-body` | ast | info | medium | no |
| `maintainability.csharp.console-write` | ast | info | high | no |

#### `reliability.csharp.empty-catch`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: roslyn-analyzers — `CA1031-family (concept)` (MIT). Concept only; no text taken.

Noise: The block must be literally `{}`; a handler containing a comment or a `// intentionally ignored` note keeps its comment node and does not match.

```scheme
(catch_clause body: (block "{" . "}") @report)
```

```csharp
// fires
class C { void M() { try { G(); } catch (System.Exception) {} } }

// does not fire
class C { void M() { try { G(); } catch (System.Exception e) { Log(e); } } }
```

#### `reliability.csharp.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: roslyn-analyzers — `CA2242-family (concept)` (MIT). Concept only; no text taken.

Noise: Both operands are the same identifier token.

```scheme
((binary_expression left: (identifier) @l operator: "==" right: (identifier) @r) @report (#eq? @l @r))
```

```csharp
// fires
class C { bool M(int a) { return a == a; } }

// does not fire
class C { bool M(int a, int b) { return a == b; } }
```

#### `reliability.csharp.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: roslyn — `CS1717 compiler warning (concept)` (MIT). Concept only; no text taken.

Noise: `a = a` is a no-op; `this.a = a` is a different node shape and is excluded.

```scheme
((assignment_expression left: (identifier) @l right: (identifier) @r) @report (#eq? @l @r))
```

```csharp
// fires
class C { void M(int a) { a = a; } }

// does not fire
class C { int a; void M(int a) { this.a = a; } }
```

#### `reliability.csharp.rethrow-loses-stack`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: roslyn-analyzers — `CA2200 rethrow to preserve stack details` (MIT). Concept only; no text taken.

Noise: `catch (Exception e) { throw e; }` resets the stack trace; the correct spelling is a bare `throw;`, which is a different node and does not match.

```scheme
((catch_clause (catch_declaration name: (identifier) @n) body: (block (throw_statement (identifier) @t))) @report (#eq? @n @t))
```

```csharp
// fires
class C { void M() { try { G(); } catch (System.Exception e) { throw e; } } }

// does not fire
class C { void M() { try { G(); } catch (System.Exception e) { throw; } } }
```

#### `reliability.csharp.async-void`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: microsoft/vs-threading VSTHRD100 — `avoid async void` (MIT (microsoft/vs-threading; not re-verified in this pass)). Concept only; no text taken.

Noise: `async void` swallows exceptions outside event handlers; the handler case is a small, recognisable minority and is worth confirming anyway.

```scheme
((method_declaration (modifier) @m returns: (predefined_type) @r) @report (#eq? @m "async") (#eq? @r "void"))
```

```csharp
// fires
class C { async void M() { await G(); } }

// does not fire
class C { async System.Threading.Tasks.Task M() { await G(); } }
```

#### `reliability.csharp.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: concept: SonarSource S1871 — `identical branches` (SONAR Source-Available License v1.0 (non-OSI; upstream repo now private)). Concept only; no text taken.

Noise: Byte-identical block text on both arms.

```scheme
((if_statement consequence: (block) @a alternative: (block) @b) @report (#eq? @a @b))
```

```csharp
// fires
class C { int M(bool c) { if (c) { return 1; } else { return 1; } } }

// does not fire
class C { int M(bool c) { if (c) { return 1; } else { return 2; } } }
```

#### `reliability.csharp.unreachable-after-return`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: roslyn — `CS0162 unreachable code detected (concept)` (MIT). Concept only; no text taken.

Noise: A statement directly after `return` in the same block is dead; Roslyn warns about it too.

```scheme
(block (return_statement) . (_) @report)
```

```csharp
// fires
class C { int M() { return 1; G(); } }

// does not fire
class C { int M() { G(); return 1; } }
```

#### `maintainability.csharp.empty-method-body`

maintainability · ast · severity `info` · noise **medium** · launch set: **no**

Concept source: original to this repository.

Noise: Empty bodies are the normal spelling of a virtual hook and of an interface no-op implementation.

```scheme
(method_declaration body: (block "{" . "}") @report)
```

```csharp
// fires
class C { void M() {} }

// does not fire
class C { void M() { G(); } }
```

#### `maintainability.csharp.console-write`

maintainability · ast · severity `info` · noise **high** · launch set: **no**

Concept source: original to this repository.

Noise: Fires on every console application's own output.

Note: Rejected for the launch set on noise.

```scheme
((invocation_expression function: (member_access_expression name: (identifier) @report) (#match? @report "^Write(Line)?$")))
```

```csharp
// fires
class C { void M() { System.Console.WriteLine("x"); } }

// does not fire
class C { void M() { _log.Info("x"); } }
```

## Ruby

| id | engine | severity | noise | default |
| --- | --- | --- | --- | --- |
| `reliability.ruby.rescue-exception` | ast | warning | low | yes |
| `reliability.ruby.rescue-modifier` | ast | warning | low | yes |
| `reliability.ruby.self-comparison` | ast | error | low | yes |
| `reliability.ruby.self-assignment` | ast | error | low | yes |
| `reliability.ruby.assignment-in-condition` | ast | warning | low | yes |
| `reliability.ruby.identical-if-branches` | ast | warning | low | yes |
| `reliability.ruby.unreachable-after-return` | ast | warning | low | yes |
| `reliability.ruby.ensure-return` | ast | error | low | yes |
| `maintainability.ruby.puts-in-library` | ast | info | high | no |

#### `reliability.ruby.rescue-exception`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rubocop — `Lint/RescueException` (MIT (source tree; docs are CC BY-SA 4.0)). Concept only; no text taken.

Noise: `rescue Exception` catches `SignalException` and `NoMemoryError`; the constant must be exactly `Exception`, so `rescue StandardError` does not match.

```scheme
((rescue exceptions: (exceptions (constant) @report) (#eq? @report "Exception")))
```

```ruby
# fires
def f
  g
rescue Exception => e
  h(e)
end

# does not fire
def f
  g
rescue StandardError => e
  h(e)
end
```

#### `reliability.ruby.rescue-modifier`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rubocop — `Style/RescueModifier` (MIT (source tree; docs are CC BY-SA 4.0)). Concept only; no text taken.

Noise: The `expr rescue fallback` modifier swallows every StandardError with no way to see which; it has one syntactic form and no legitimate variant.

```scheme
(rescue_modifier) @report
```

```ruby
# fires
def f
  x = g rescue nil
  x
end

# does not fire
def f
  begin
    g
  rescue StandardError
    nil
  end
end
```

#### `reliability.ruby.self-comparison`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: rubocop — `Lint/BinaryOperatorWithIdenticalOperands` (MIT (source tree; docs are CC BY-SA 4.0)). Concept only; no text taken.

Noise: Both operands are the same identifier token.

```scheme
((binary left: (identifier) @l operator: "==" right: (identifier) @r) @report (#eq? @l @r))
```

```ruby
# fires
def f(a)
  a == a
end

# does not fire
def f(a, b)
  a == b
end
```

#### `reliability.ruby.self-assignment`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: rubocop — `Lint/SelfAssignment` (MIT (source tree; docs are CC BY-SA 4.0)). Concept only; no text taken.

Noise: `a = a` is a no-op; `@a = a` is a different node and is excluded.

```scheme
((assignment left: (identifier) @l right: (identifier) @r) @report (#eq? @l @r))
```

```ruby
# fires
def f(a)
  a = a
  a
end

# does not fire
def f(a)
  @a = a
  @a
end
```

#### `reliability.ruby.assignment-in-condition`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rubocop — `Lint/AssignmentInCondition` (MIT (source tree; docs are CC BY-SA 4.0)). Concept only; no text taken.

Noise: Ruby's own parser warns about this; the deliberate form is written with explicit parentheses around the assignment, which is a different node.

```scheme
(if condition: (assignment) @report)
```

```ruby
# fires
def f(a, b)
  if a = b
    a
  end
end

# does not fire
def f(a, b)
  if a == b
    a
  end
end
```

#### `reliability.ruby.identical-if-branches`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rubocop — `Lint/DuplicateBranch` (MIT (source tree; docs are CC BY-SA 4.0)). Concept only; no text taken.

Noise: Compares the single statement of each arm byte for byte; multi-statement arms are not compared at all, which keeps the rule conservative.

```scheme
((if consequence: (then . (_) @a .) alternative: (else . (_) @b .)) @report (#eq? @a @b))
```

```ruby
# fires
def f(c)
  if c
    1
  else
    1
  end
end

# does not fire
def f(c)
  if c
    1
  else
    2
  end
end
```

#### `reliability.ruby.unreachable-after-return`

reliability · ast · severity `warning` · noise **low** · launch set: **yes**

Concept source: rubocop — `Lint/UnreachableCode` (MIT (source tree; docs are CC BY-SA 4.0)). Concept only; no text taken.

Noise: A statement directly after `return` in the same body is dead.

```scheme
(body_statement (return) . (_) @report)
```

```ruby
# fires
def f
  return 1
  g
end

# does not fire
def f
  g
  return 1
end
```

#### `reliability.ruby.ensure-return`

reliability · ast · severity `error` · noise **low** · launch set: **yes**

Concept source: rubocop — `Lint/EnsureReturn` (MIT (source tree; docs are CC BY-SA 4.0)). Concept only; no text taken.

Noise: A `return` inside `ensure` discards the pending exception; there is no correct program with this shape.

```scheme
(ensure (return) @report)
```

```ruby
# fires
def f
  g
ensure
  return 1
end

# does not fire
def f
  g
ensure
  h
end
```

#### `maintainability.ruby.puts-in-library`

maintainability · ast · severity `info` · noise **high** · launch set: **no**

Concept source: original to this repository.

Noise: Fires on every rake task and script; Ruby CLI code is written with `puts`.

Note: Rejected for the launch set on noise.

```scheme
((call method: (identifier) @report (#match? @report "^(puts|print|p)$")))
```

```ruby
# fires
def f
  puts 'x'
end

# does not fire
def f
  logger.info('x')
end
```

## Cross-language rule detail

#### `maintainability.todo-marker`

maintainability · regex · severity `info` · noise **low** · launch set: **yes**

Noise: Case-sensitive uppercase markers only, so identifiers such as `todos` and `Todo` do not match; the residual noise is vendored third-party text, which the pack's existing path excludes already handle.

Note: Already shipped as the README's `Add a rule` example; this promotes it into the default maintainability profile.

```
\b(?:TODO|FIXME|HACK|XXX)\b
```

```
fires:
// TODO: handle the empty case
fn f() {}

does not fire:
// the todos list is rendered elsewhere
let todos = vec![];
```

#### `maintainability.commented-out-code`

maintainability · regex · severity `info` · noise **medium** · launch set: **no**

Noise: A commented line that ends in `;` or `{` after a control keyword is usually dead code, but it also fires on prose documentation that quotes a statement and on commented-out example code in headers.

Note: Held out of the launch set; needs corpus measurement first.

```
(?m)^[ \t]*(?://|#)[ \t]*(?:if|for|while|switch|return|else)\b[^\n]*[;{}][ \t]*$
```

```
fires:
// if (x > 0) { return 1; }
int f(void) { return 0; }

does not fire:
// if the value is positive we return early
int f(void) { return 0; }
```

## Rules held out of the launch set

These are in the matrix, verified, and `default: no`. They are candidates for a
second release once a corpus run gives a false-positive number.

| id | noise | why it is held out |
| --- | --- | --- |
| `maintainability.commented-out-code` | medium | A commented line that ends in `;` or `{` after a control keyword is usually dead code, but it also fires on prose documentation that quotes a statement and on commented-out example code in headers. |
| `reliability.rust.unwrap-in-library` | medium | Fires on every `unwrap()`/`expect()`, including the ones guarded by an invariant a line above; on a real crate this is the highest-count rule in the Rust set even after excluding tests. |
| `maintainability.rust.empty-function-body` | medium | Empty bodies are legitimate for default trait method overrides and for no-op `Drop` implementations, which are common in real crates. |
| `maintainability.rust.print-in-library` | high | Fires on every line of a CLI crate's own output code, which is the majority of `println!` uses in this repository's own workspace. |
| `reliability.python.type-equality` | medium | `type(x) == T` is usually meant as `isinstance`, but exact-type dispatch is a real pattern in serialization code, so a minority of hits are deliberate. |
| `maintainability.python.empty-function-body` | high | `def f(): ...` and `pass` bodies are the normal spelling of a Protocol, an abstract base method and a stub file, so most hits are correct code. |
| `maintainability.python.print-call` | high | Fires on every script and CLI entry point; the pack cannot tell a debug print from a program's own output. |
| `reliability.javascript.unreachable-after-return` | medium | A hoisted `function` declaration written after `return` is still reachable and is legal, idiomatic JavaScript; the candidate query does not exclude it, so every helper declared at the bottom of a function would report. |
| `reliability.javascript.loose-equality` | medium | `x == null` as a combined null/undefined check is deliberate and common, and the query cannot separate it from an accidental coercion. |
| `maintainability.javascript.empty-function-body` | medium | Empty callbacks and no-op default handlers are idiomatic, so a meaningful share of hits are intentional. |
| `reliability.typescript.unreachable-after-return` | medium | A hoisted `function` declaration written after `return` is still reachable and is legal, idiomatic JavaScript; the candidate query does not exclude it, so every helper declared at the bottom of a function would report. |
| `reliability.typescript.loose-equality` | medium | `x == null` as a combined null/undefined check is deliberate and common, and the query cannot separate it from an accidental coercion. |
| `maintainability.typescript.empty-function-body` | medium | Empty callbacks and no-op default handlers are idiomatic, so a meaningful share of hits are intentional. |
| `reliability.typescript.non-null-assertion` | medium | The `!` operator is the TypeScript analogue of `unwrap()`; it is frequent enough in well-typed code that a default-on rule would dominate the report. |
| `reliability.go.unchecked-type-assertion` | medium | The single-value form panics on a wrong type, but it is idiomatic wherever the type is already known from a switch a few lines above, which the query cannot see. |
| `maintainability.go.empty-function-body` | medium | Empty bodies are the normal way to satisfy an interface with a no-op implementation, which is common in Go test doubles and adapters. |
| `maintainability.go.panic-in-library` | high | `panic` in `main` and in initialisation code is normal Go; the pack has no way to tell library code from a program entry point by path alone. |
| `reliability.java.print-stack-trace` | medium | `printStackTrace()` is wrong in a service but correct in a sample, a test harness and a command-line tool, and the query cannot tell them apart. |
| `maintainability.java.empty-method-body` | high | Empty bodies are the normal spelling of an adapter override, a no-arg constructor and a `@Override` no-op, all of which are correct. |
| `maintainability.java.system-out-print` | high | Fires on every command-line tool and every teaching example in a repository. |
| `maintainability.c.empty-function-body` | medium | Empty bodies are used for weak-symbol stubs and for platform no-ops, both of which are correct. |
| `maintainability.cpp.empty-function-body` | medium | Empty bodies are used for weak-symbol stubs and for platform no-ops, both of which are correct. |
| `maintainability.csharp.empty-method-body` | medium | Empty bodies are the normal spelling of a virtual hook and of an interface no-op implementation. |
| `maintainability.csharp.console-write` | high | Fires on every console application's own output. |
| `maintainability.ruby.puts-in-library` | high | Fires on every rake task and script; Ruby CLI code is written with `puts`. |

## Rules rejected outright

Not in the matrix at all. Each line says which of the three reasons applies:
**noise**, **licence**, or **not expressible** with the six engines and a
tree-sitter query.

| Candidate | Reason | Detail |
| --- | --- | --- |
| `using` on a non-disposable (C#) | not expressible | Named in issue #78. Requires knowing whether the type implements `IDisposable`, which is symbol resolution. Tree-sitter has no symbol table and siloscan has no type engine. |
| `goto` past initialisation (C, C++) | not expressible | Named in issue #78. Requires control-flow reachability plus scope tracking. A query can find a `goto_statement` and a `declaration`, but not the path between them. |
| Ignoring an error return (Go, errcheck) | not expressible | Named in issue #78. Requires the callee's signature to know a call returns an `error`. The one shape that is decidable from syntax alone — a discarded `append` — is in the matrix as `reliability.go.append-result-discarded`. |
| Unused assignment / ineffectual assignment | not expressible | Data-flow analysis. Out of reach for a query. |
| Float equality (`==` on floats) | not expressible | Requires operand types. The identifier-only self-comparison rules are the decidable subset and are in the matrix. |
| Null dereference, use-after-free, resource leak | not expressible | Flow-sensitive whole-function analyses. |
| Magic numbers | noise | Issue #78 allows a magic-number rule "only where a precise pattern exists". No precise pattern exists: array indices, HTTP status codes, bit masks, exit codes and time constants are all bare integer literals, and the ones that matter are indistinguishable from the ones that do not. |
| Duplicate code blocks | not expressible / already shipped | Already covered by the `duplication` payload, which emits under the reserved id `metrics.duplicate-block`. A rule claiming that id is a `ReservedId` load error. |
| Switch fallthrough (C, C++, C#) | noise | Intentional fallthrough is marked with a comment or an attribute that the query cannot read reliably, and grouped empty cases are the common legitimate form. |
| Empty method body (Ruby) | not expressible | `def f; end` produces no body node to anchor against, and the query language has no negation, so "a method whose body has no statements" cannot be written. The other nine languages express it with the `"{" . "}"` anchor instead. |
| Cyclomatic complexity as an AST rule | not expressible | A query cannot count. Kept in the matrix as a `metric` candidate instead. |
| Any Semgrep registry pattern | licence | Semgrep Rules License v1.0 forbids redistributing the rules. Not OSI. No text, and no concept citation either, since the concepts overlap with permissively licensed sources that can be cited instead. |
| Any SonarSource rspec pattern text | licence | SONAR Source-Available License v1.0, non-OSI. Six rules cite an S-number as a concept reference only; every query and message under those ids is written here. The upstream repository is now private, so the licence could only be confirmed from a fork snapshot — treat it as strictly concept-only. |
| Any SpotBugs, Checkstyle, Pylint, cppcheck or golangci-lint text | licence | LGPL / GPL. Two rules cite SpotBugs and PMD detector names as concept references; no text is taken from either. |
| nvim-treesitter query text | licence (usable, not used) | Apache-2.0 and therefore permissible, but individual query files carry their own upstream MIT notices, and copying one would mean carrying that notice into `NOTICE` for no benefit — the queries here are highlight queries, not analysis queries. Written from `node-types.json` instead. |

## Tree-sitter grammar versions consulted

Pins are from `crates/siloscan-core/Cargo.toml` and `Cargo.lock` at v2.0.0.
Sources were read from the local cargo registry after `cargo fetch`:
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/<crate>-<version>/`.

| Language key | Crate | Version | node-types.json path |
| --- | --- | --- | --- |
| `c` | `tree-sitter-c` | 0.24.2 | `src/node-types.json` |
| `cpp` | `tree-sitter-cpp` | 0.23.4 | `src/node-types.json` |
| `csharp` | `tree-sitter-c-sharp` | 0.23.5 | `src/node-types.json` |
| `go` | `tree-sitter-go` | 0.25.0 | `src/node-types.json` |
| `java` | `tree-sitter-java` | 0.23.5 | `src/node-types.json` |
| `javascript` | `tree-sitter-javascript` | 0.25.0 | `src/node-types.json` |
| `python` | `tree-sitter-python` | 0.25.0 | `src/node-types.json` |
| `ruby` | `tree-sitter-ruby` | 0.23.1 | `src/node-types.json` |
| `rust` | `tree-sitter-rust` | 0.24.2 | `src/node-types.json` |
| `typescript` | `tree-sitter-typescript` | 0.23.2 | `typescript/src/node-types.json` |

`tree-sitter` itself is pinned at 0.26.11. Two details of that version matter to
this matrix and were confirmed in its source rather than assumed:

- `QueryCursor::matches` applies text predicates itself
  (`QueryMatch::satisfies_text_predicates`, `binding_rust/lib.rs`), so `#eq?`,
  `#match?` and `#any-of?` filter matches before siloscan's engine sees them.
  Nothing in `engines/ast.rs` has to do it.
- `#eq?` supports capture-to-capture comparison (`TextPredicateCapture::EqCapture`),
  not only capture-to-string. Eleven rules in this matrix — every self-comparison,
  self-assignment and identical-branch rule — depend on that.

`tree-sitter-typescript` exposes two grammars; siloscan binds
`LANGUAGE_TYPESCRIPT`, so TSX-only node names were not used and the `tsx/`
node-types.json was not consulted.

## Verification

Three checks were run, all against the pinned grammars listed above. The
harnesses are throwaway and live outside the repository; they are described here
so the checks can be reproduced.

**1. Every query compiles, defines `@report`, and separates its own examples.**
A small Rust binary linking the same ten grammar crates at the same pinned
versions reads `rule-matrix.json`, calls `Query::new` for each query, asserts a
`report` capture index exists, parses the rule's `positive_example` and
`negative_example`, and counts matches with `QueryCursor::matches` and the
source bytes as the text provider — the same call `engines/ast.rs` makes.

```
checked=96 failures=0 rules=100
```

93 queries and 3 regex patterns: every one matched its
positive example at least once and its negative example zero times. `metric`
rules are skipped, since they have no pattern.

This check found three real defects in the first draft, which is the argument
for running it rather than eyeballing the queries:

- A predicate written after a top-level pattern — `(node ...) @report (#eq? @l @r)` —
  does not bind to that pattern. It parses, and then matches every node in the
  file. The correct form wraps the pattern and its predicate together:
  `((node ...) @report (#eq? @l @r))`. Twenty-two queries had the broken form and
  would have shipped as "report everything".
- `(binary_expression operator: "==" left: (string_literal))` is an *impossible
  pattern* and fails to compile: query children must be written in the grammar's
  child order, so `left:` has to precede `operator:`.
- The `commented-out-code` regex did not match its own positive example, because
  the terminator class omitted `}`.

**2. Every node name, field name and anonymous token appears in the grammar.**
A Python script extracts every `(name` occurrence, every `field:` occurrence and
every quoted token from each query, strips predicates first, and checks each
against that grammar's `node-types.json` (named types and fields) and its
`grammar.json` string terminals (anonymous tokens).

```
node names checked=254 field names checked=131 anonymous tokens checked=55 missing=0
```

The tree-sitter wildcard `(_)` is excluded from the node-name check; it is query
syntax, not a node type.

**3. The matrix satisfies siloscan's loader constraints.** Checked statically
against `rules.rs`: every id matches `^[a-z0-9-]+(\.[a-z0-9-]+)+$`, no id is
duplicated, no id is `metrics.duplicate-block`, every `ast` query-map key is one
of the ten known language names, no `ast` rule carries a `languages` envelope,
every severity is one of `info`/`warning`/`error`, and every `default: yes` rule
is rated low noise.

### Not verified

- **No corpus run.** Every `expected_noise` rating is an argument from the query
  shape, not a measurement. The false-positive limits and removal criteria issue
  #78 asks for need a corpus, and that is phase 2 work.
- **No load through siloscan's own YAML loader.** No rule YAML was written, per
  the scope of this phase, so the loader constraints were checked against the
  code rather than by loading a document.
- **No performance measurement.** 93 AST rules over ten languages adds
  per-file query execution that the 5% time and RSS gates have not been run
  against. Note that the AST engine runs every applicable rule's query
  separately per file; there is no query batching today.
- **Two concept citations were not re-verified** in the licence pass:
  `rustc`'s `unreachable_code` lint (rust-lang/rust) and `VSTHRD100`
  (microsoft/vs-threading). Both are believed permissive, both are concept-only,
  and neither contributes text.

## Licensing disposition

Every project below was checked against its actual LICENSE file. **No pattern
text, query text or message text was copied from any of them.** Every query in
this matrix was written from the grammar's `node-types.json`; every message and
noise rationale is original. The permissive column therefore records what
*would* have been allowed, not what was taken.

| Source | Repo | Licence | Class | Used for |
| --- | --- | --- | --- | --- |
| ESLint | `eslint/eslint` | MIT | permissive | concept |
| typescript-eslint | `typescript-eslint/typescript-eslint` | MIT | permissive | concept |
| Ruff | `astral-sh/ruff` | MIT | permissive | concept |
| Clippy | `rust-lang/rust-clippy` | Apache-2.0 OR MIT | permissive | concept |
| staticcheck | `dominikh/go-tools` | MIT | permissive | concept |
| go vet | `golang/go, golang/tools` | BSD-3-Clause | permissive | concept |
| errcheck | `kisielk/errcheck` | MIT | permissive | concept |
| RuboCop | `rubocop/rubocop` | MIT (code); docs are CC BY-SA 4.0 | permissive | concept |
| Roslyn | `dotnet/roslyn` | MIT | permissive | concept |
| Roslyn analyzers | `dotnet/roslyn-analyzers` | MIT | permissive | concept |
| clang / clang-tidy | `llvm/llvm-project` | Apache-2.0 WITH LLVM-exception | permissive | concept |
| Error Prone | `google/error-prone` | Apache-2.0 | permissive | concept |
| PMD | `pmd/pmd` | BSD-style with a DARPA acknowledgement clause; not SPDX BSD-3-Clause | permissive with attribution | concept |
| nvim-treesitter | `nvim-treesitter/nvim-treesitter` | Apache-2.0 (per-query files carry upstream MIT notices) | permissive | not used |
| SpotBugs | `spotbugs/spotbugs` | LGPL-2.1-or-later | copyleft | concept |
| Checkstyle | `checkstyle/checkstyle` | LGPL-2.1-or-later | copyleft | not used |
| Pylint | `pylint-dev/pylint` | GPL-2.0-or-later | copyleft | not used |
| cppcheck | `danmar/cppcheck` | GPL-3.0-or-later | copyleft | not used |
| golangci-lint | `golangci/golangci-lint` | GPL-3.0 (own code) | copyleft | not used |
| Semgrep rules | `semgrep/semgrep-rules` | Semgrep Rules License v1.0 (non-OSI) | restricted | not used |
| SonarSource rspec | `SonarSource/rspec (repo now private)` | SONAR Source-Available License v1.0 (non-OSI) | restricted | concept |
| C++ Core Guidelines | `isocpp/CppCoreGuidelines` | CC BY 4.0 (prose) | restricted for prose | concept |

Notes that matter if this ever moves from concept to text:

- **PMD is not BSD-3-Clause.** Its LICENSE is BSD-3 clauses plus a mandatory
  DARPA acknowledgement in end-user documentation, and part of the tree
  (`net.sourceforge.pmd.lang.vm`) is Apache-2.0. Do not label it BSD-3-Clause in
  an SBOM.
- **RuboCop's cop descriptions exist under two licences.** The source tree is
  MIT; the documentation site is CC BY-SA 4.0. If wording is ever taken, take it
  from `lib/rubocop/cop/**`, not from the docs.
- **SonarSource rspec is unverifiable upstream.** The repository is private. The
  licence was read from a fork snapshot and is a non-OSI source-available
  licence. Six rules cite an S-number as a concept; that is the ceiling.
- **Semgrep's rules licence forbids redistribution outright.** Nothing from it,
  including concept citations, is used.
- **NOTICE does not need a new entry.** `NOTICE` records gitleaks because
  `secrets.yaml` is a translation of gitleaks patterns. Nothing in this matrix is
  a translation of anything, so a profiles pack adds no attribution obligation.
  If that changes — if any upstream pattern text is copied during
  implementation — `NOTICE` gains an entry in the same shape, naming the project,
  the file, the tag and the licence text.

