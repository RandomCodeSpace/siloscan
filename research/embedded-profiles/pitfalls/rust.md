# Rust pitfall list

Ticket #104, under the v2.2 map #103. Twenty pitfalls a reviewer flags on sight
in Rust, each dispositioned against the engine boundary the map fixes: **a
single-file tree-sitter query or a single-file metric rule, nothing else**.

**Grammar**: `tree-sitter-rust` 0.24.2, `tree-sitter` 0.26.11, the versions
pinned in `crates/siloscan-core/Cargo.toml`. Node names, field names and
anonymous tokens were read from
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tree-sitter-rust-0.24.2/src/node-types.json`
and `grammar.json`.

**How every query here was verified.** Not by hand and not against a private
harness: each query was loaded through `siloscan_core::rules::load_str` under a
one-rule document and run over a two-file temporary tree through
`siloscan_core::scan::scan`, the same pair of calls `plan::resolve` and
`profile_corpus.rs` make. Each row records findings on the positive file and on
the negative file. A rule that separates its examples reports `pos>=1 neg=0`;
the four `needs primitive` rows and the two `inexpressible` rows record the
measurement that proves they do not. The harness was a throwaway test under
`crates/siloscan-core/tests/`, deleted after the run and not committed; every
query, positive and negative below is the literal text that was measured, so
the run reproduces by pasting them back into the same shape.

**Concept-only citations.** Every source below was checked for its licence and
cited as a concept. No pattern text, query text, message text or documentation
text is taken from any upstream project. Every query here was written from
`node-types.json`.

## Boundaries this list respects

- Single-file queries and metric rules. No cross-file, type-aware or dataflow
  analysis; one bounded engine primitive is allowed under #103 and only if at
  least three candidates across two languages need the same one.
- Noise policy is removal, not tuning: `warning` at or below 0.25 findings per
  kLOC, `info` at or below 1.0, on any pinned repository, with zero corpus false
  positives. One `paths` exclusion per rule before removal.
- Skipped: everything `crates/siloscan-core/rules/profiles/*-rust.yaml` already
  ships, and the one rule 2.1 removed — both listed under
  [Already dispositioned in 2.1](#already-dispositioned-in-21).

**Every `expected noise` rating below is an argument from the query's shape
plus, where the row says so, a measured hit on the idiom that causes it. None of
them is a per-kLOC measurement against the pinned noise set (ripgrep 15.2.0,
tokio 1.40.0, serde 1.0.229). That measurement is the implementation package's
job, and it is the gate that decides which of these actually ship.**

## The list

| id | severity | disposition | expected noise |
| --- | --- | --- | --- |
| `reliability.rust.static-mut` | warning | expressible | low |
| `reliability.rust.transmute-call` | warning | expressible | low |
| `reliability.rust.uninitialized-memory` | warning | expressible | low |
| `reliability.rust.unsafe-send-sync-impl` | warning | expressible | low |
| `reliability.rust.unchecked-access` | warning | expressible | medium |
| `reliability.rust.self-comparison-ordering` | warning | expressible | low |
| `reliability.rust.match-same-arms` | info | expressible | medium |
| `maintainability.rust.len-zero-comparison` | info | expressible | low |
| `maintainability.rust.bool-literal-comparison` | info | expressible | low |
| `maintainability.rust.needless-bool` | info | expressible | low |
| `maintainability.rust.needless-return` | info | expressible | low |
| `maintainability.rust.let-and-return` | info | expressible | medium |
| `maintainability.rust.wildcard-import` | info | expressible | low |
| `maintainability.rust.blanket-lint-allow` | info | expressible | low |
| `reliability.rust.undocumented-unsafe-block` | warning | needs primitive (P2) | unbounded without it |
| `reliability.rust.blocking-call-in-async` | warning | needs primitive (P1) | low, but recall near zero without it |
| `reliability.rust.unnecessary-unwrap` | info | needs primitive (P1) | low, but recall near zero without it |
| `maintainability.rust.empty-if-body` | info | needs primitive (P2) | medium without it |
| `reliability.rust.guard-held-across-await` | warning | inexpressible | unbounded |
| `reliability.rust.discarded-result` | warning | inexpressible | unbounded |

---

## Expressible

### 1. `reliability.rust.static-mut`

A `static mut` item is shared mutable state with no synchronisation, and taking
a reference to one is a hard error in edition 2024.

- **Concept source**: rustc — `static_mut_refs` (Apache-2.0 OR MIT). Concept
  only; no text taken.
- **Severity**: `warning`.
- **Verified query** — `pos=1 neg=0`:

```scheme
(static_item (mutable_specifier)) @report
```

```rust
// fires
static mut COUNTER: u32 = 0;
fn f() { unsafe { COUNTER += 1; } }

// does not fire
use std::sync::atomic::AtomicU32;
static COUNTER: AtomicU32 = AtomicU32::new(0);
fn f() -> &'static AtomicU32 { &COUNTER }
```

- **Expected noise**: low. The idiom that would produce it is a `static mut`
  inside a bindgen-generated FFI module or a `#[no_mangle]` interop shim, where
  the item is required by the C side. Those modules are usually a handful of
  files, and a `paths` exclusion is available before removal.
- **Disposition**: **expressible**. `mutable_specifier` is a named child of
  `static_item`, so the shape needs no predicate at all.

### 2. `reliability.rust.transmute-call`

`transmute` reinterprets a value's bytes with no check that the target type
admits them, and a reviewer stops on every call.

- **Concept source**: rust-clippy — `useless_transmute` / `wrong_transmute` /
  `transmute_undefined_repr` (Apache-2.0 OR MIT). Concept only; no text taken.
  The rule here is broader than any one of them: it reports the call, not a
  judgement about the types, because the types are outside the boundary.
- **Severity**: `warning`.
- **Verified query** — `pos=1 neg=0`, on both the plain and the turbofish
  spelling:

```scheme
((call_expression function: (scoped_identifier name: (identifier) @f)) @report (#eq? @f "transmute")) ((call_expression function: (generic_function function: (scoped_identifier name: (identifier) @g))) @report (#eq? @g "transmute"))
```

```rust
// fires
use std::mem;
fn f(x: u32) -> i32 { unsafe { mem::transmute::<u32, i32>(x) } }

// fires
fn f(x: u32) -> i32 { unsafe { std::mem::transmute(x) } }

// does not fire
fn f() { let _ = std::mem::size_of::<u32>(); }
```

- **Expected noise**: low. The idiom that would produce it is a crate whose
  whole job is byte reinterpretation — a zerocopy-style core, a serialiser's
  unsafe layer — where every call is deliberate and documented. Those are few,
  and the finding is still true there.
- **Disposition**: **expressible**. Two patterns are needed because
  `transmute::<A, B>(x)` puts a `generic_function` between the
  `call_expression` and the `scoped_identifier`; a single pattern misses it.
  Both patterns share the one `@report` capture, which `engines/ast.rs`
  resolves per pattern.

### 3. `reliability.rust.uninitialized-memory`

`mem::uninitialized` and `mem::zeroed` fabricate a value of a type that may have
no valid all-zero or all-garbage representation, which is instant undefined
behaviour.

- **Concept source**: rustc — `invalid_value` (Apache-2.0 OR MIT); rust-clippy —
  `uninit_assumed_init` (Apache-2.0 OR MIT). Concept only; no text taken.
- **Severity**: `warning`.
- **Verified query** — `pos=1 neg=0`:

```scheme
((call_expression function: (scoped_identifier path: (identifier) @p name: (identifier) @f)) @report (#eq? @p "mem") (#match? @f "^(uninitialized|zeroed)$")) ((call_expression function: (generic_function function: (scoped_identifier path: (identifier) @p2 name: (identifier) @f2))) @report (#eq? @p2 "mem") (#match? @f2 "^(uninitialized|zeroed)$"))
```

```rust
// fires
use std::mem;
fn f() -> u8 { unsafe { mem::uninitialized() } }

// does not fire
use std::mem;
fn f(a: &mut u8, b: &mut u8) { mem::swap(a, b); }
```

- **Expected noise**: low. The idiom that would produce it is `mem::zeroed()`
  for a `#[repr(C)]` FFI struct whose C counterpart is documented to accept an
  all-zero value; on an FFI-heavy crate that shape is the whole noise budget.
  Requiring the `mem::` path segment keeps a local helper named `zeroed` out.
- **Disposition**: **expressible**, with the same two-pattern turbofish caveat
  as item 2.

### 4. `reliability.rust.unsafe-send-sync-impl`

`unsafe impl Send` and `unsafe impl Sync` are a hand-written soundness claim
that the compiler cannot check, and they belong in a review, not a diff skim.

- **Concept source**: rust-clippy — `non_send_fields_in_send_ty` (Apache-2.0 OR
  MIT). Concept only; no text taken.
- **Severity**: `warning`.
- **Verified query** — `pos=1 neg=0`:

```scheme
((impl_item "unsafe" trait: (type_identifier) @t) @report (#match? @t "^(Send|Sync)$"))
```

```rust
// fires
struct W(*mut u8);
unsafe impl Send for W {}

// does not fire
struct W(u8);
unsafe trait T {}
unsafe impl T for W {}
```

- **Expected noise**: low. The idiom that would produce it is a wrapper around a
  raw pointer whose safety argument is written in a comment above the impl —
  correct code that a reviewer still wants surfaced. `unsafe` is an anonymous
  token on `impl_item` and must be written before the `trait:` field, because
  query children follow grammar child order.
- **Disposition**: **expressible**.

### 5. `reliability.rust.unchecked-access`

The `_unchecked` accessors and `set_len` move a bounds or initialisation check
from the compiler to the author, and a wrong one is memory corruption.

- **Concept source**: rustc — `unsafe_code` (Apache-2.0 OR MIT), narrowed here
  from "any unsafe" to a named set of accessors. Concept only; no text taken.
- **Severity**: `warning`.
- **Verified query** — `pos=1 neg=0`:

```scheme
((call_expression function: (field_expression field: (field_identifier) @m)) @report (#match? @m "^(get_unchecked|get_unchecked_mut|unwrap_unchecked|assume_init|set_len)$"))
```

```rust
// fires
fn f(v: &[u8]) -> u8 { unsafe { *v.get_unchecked(0) } }

// does not fire
fn f(v: &[u8]) -> Option<&u8> { v.first() }
```

- **Expected noise**: medium, **measured**. `assume_init()` on a `MaybeUninit`
  that was fully written a line earlier is correct code and fires: the probe
  reported it. So does `get_unchecked` inside a hot loop whose bounds were
  proven above. Both are the idiom, and both are exactly what a reviewer wants
  to see. Ships at `warning` only if the pinned set puts it under 0.25 per kLOC;
  otherwise it drops `assume_init` from the alternation and re-measures, and
  failing that it is removed.
- **Disposition**: **expressible**.

### 6. `reliability.rust.self-comparison-ordering`

Comparing an identifier with itself under an ordering or inequality operator has
a fixed result, so the comparison decides nothing.

- **Concept source**: rust-clippy — `eq_op` (Apache-2.0 OR MIT). Concept only;
  no text taken.
- **Severity**: `warning`.
- **Verified query** — `pos=1 neg=0` for both `!=` and `<`:

```scheme
((binary_expression left: (identifier) @l operator: ["!=" "<" ">" "<=" ">="] right: (identifier) @r) @report (#eq? @l @r))
```

```rust
// fires
fn f(a: i32) -> bool { a != a }

// fires
fn f(a: i32) -> bool { a < a }

// does not fire
fn f(a: f64) -> bool { a.is_nan() }
```

- **Expected noise**: low. The idiom that would produce it is a hand-rolled NaN
  check written `x != x` instead of `x.is_nan()`, which turns up in numeric
  crates that predate `is_nan` being obvious. That is the only shape where the
  self-comparison is deliberate.
- **Disposition**: **expressible**. This is new coverage, not a widening: the
  shipped `reliability.rust.self-comparison` constrains `operator: "=="` and
  sees none of these five. The anonymous-token alternation `["!=" "<" ...]`
  compiles under the pinned `tree-sitter` and was measured separately.

### 7. `reliability.rust.match-same-arms`

Two arms of one `match` with byte-identical bodies are either a copy-paste
mistake or two patterns that should have been one.

- **Concept source**: rust-clippy — `match_same_arms` (Apache-2.0 OR MIT).
  Concept only; no text taken.
- **Severity**: `info`.
- **Verified query** — `pos=1 neg=0`:

```scheme
((match_block (match_arm value: (_) @a) (match_arm value: (_) @b)) @report (#eq? @a @b))
```

```rust
// fires
fn compute(x: u8) -> u8 { x }
fn f(x: u8) -> u8 { match x { 1 => compute(x), 2 => compute(x), _ => 0 } }

// does not fire
fn f(r: Result<u8, u8>) -> u8 { match r { Ok(v) => v, Err(e) => e } }
```

- **Expected noise**: medium, **measured**. The idiom is two arms that map to
  the same trivial value — `Ok(_) => 0, Err(_) => 0`, or a pair of `_ => {}`
  arms in a state machine that is deliberately exhaustive. The probe confirmed
  the `Ok(_) => 0, Err(_) => 0` shape fires. That is why this is `info` and not
  `warning`; the trivial-body case cannot be excluded without a body-size test
  the query language does not have.
- **Disposition**: **expressible**. Two unanchored sibling patterns bind to two
  distinct `match_arm` nodes in source order, so an arm is never compared with
  itself.

### 8. `maintainability.rust.len-zero-comparison`

`x.len() == 0` is the long spelling of `x.is_empty()`, which is both clearer and
cheaper on types where length is not O(1).

- **Concept source**: rust-clippy — `len_zero` (Apache-2.0 OR MIT). Concept
  only; no text taken.
- **Severity**: `info`.
- **Verified query** — `pos=1 neg=0`:

```scheme
((binary_expression left: (call_expression function: (field_expression field: (field_identifier) @m)) operator: "==" right: (integer_literal) @z) @report (#eq? @m "len") (#eq? @z "0"))
```

```rust
// fires
fn f(v: &[u8]) -> bool { v.len() == 0 }

// does not fire
fn f(v: &[u8]) -> bool { v.len() == 1 }
```

- **Expected noise**: low. The idiom that would produce it is a type that
  exposes `len()` but no `is_empty()`, where the comparison is the only
  spelling available. Rare, and upstream flags it too.
- **Disposition**: **expressible**. `left:` must precede `operator:` in the
  pattern; the reverse order is an impossible pattern and fails to compile.

### 9. `maintainability.rust.bool-literal-comparison`

Comparing a boolean against a boolean literal adds an operator and removes
nothing.

- **Concept source**: rust-clippy — `bool_comparison` (Apache-2.0 OR MIT).
  Concept only; no text taken.
- **Severity**: `info`.
- **Verified query** — `pos=1 neg=0`, both operand positions:

```scheme
((binary_expression left: (_) operator: ["==" "!="] right: (boolean_literal)) @report) ((binary_expression left: (boolean_literal) operator: ["==" "!="] right: (_)) @report)
```

```rust
// fires
fn f(x: bool) -> bool { x == true }

// fires
fn f(x: bool) -> bool { x != false }

// does not fire
fn f(x: bool) -> bool { !x }
```

- **Expected noise**: low. The idiom that would produce it is a macro that
  expands to a comparison against a `bool` constant; the query never sees macro
  expansion, so it reports the written form only, which is the form under
  review.
- **Disposition**: **expressible**.

### 10. `maintainability.rust.needless-bool`

`if c { true } else { false }` is `c`, and the inverted form is `!c`.

- **Concept source**: rust-clippy — `needless_bool` (Apache-2.0 OR MIT). Concept
  only; no text taken.
- **Severity**: `info`.
- **Verified query** — `pos=1 neg=0`:

```scheme
((if_expression consequence: (block (boolean_literal) @a) alternative: (else_clause (block (boolean_literal) @b))) @report (#not-eq? @a @b))
```

```rust
// fires
fn f(c: bool) -> bool { if c { true } else { false } }

// does not fire
fn f(c: bool) -> i32 { if c { 1 } else { 0 } }

// does not fire: shipped identical-if-branches owns this shape
fn f(c: bool) -> bool { if c { true } else { true } }
```

- **Expected noise**: low. No idiom writes this deliberately. The `#not-eq?`
  keeps the rule off the shape the shipped
  `reliability.rust.identical-if-branches` already owns, so the two never
  double-report one line.
- **Disposition**: **expressible**.

### 11. `maintainability.rust.needless-return`

A `return` in the tail position of a function body is the one place Rust does
not need the keyword.

- **Concept source**: rust-clippy — `needless_return` (Apache-2.0 OR MIT).
  Concept only; no text taken.
- **Severity**: `info`.
- **Verified query** — `pos=1 neg=0`:

```scheme
(function_item body: (block (expression_statement (return_expression)) @report . "}"))
```

```rust
// fires
fn f() -> i32 { let x = 1; return x; }

// does not fire: the return is an early return, not the tail
fn f(c: bool) -> i32 {
    if c { return 1; }
    let x = 2;
    x
}
```

- **Expected noise**: low. The idiom that would produce it is a long function
  whose author keeps a trailing `return` for symmetry with several early
  returns above it — a style choice, which is why this is `info`. Anchoring the
  block to the `body:` field of `function_item` and the statement to the
  position immediately before the closing brace is what keeps every early
  return out; the anchor counts anonymous tokens, so `"}"` is a legal anchor
  target.
- **Disposition**: **expressible**.

### 12. `maintainability.rust.let-and-return`

Binding a value and immediately returning that binding is a step with no
purpose.

- **Concept source**: rust-clippy — `let_and_return` (Apache-2.0 OR MIT).
  Concept only; no text taken.
- **Severity**: `info`.
- **Verified query** — `pos=1 neg=0`:

```scheme
((block (let_declaration pattern: (identifier) @n) . (identifier) @tail) @report (#eq? @n @tail))
```

```rust
// fires
fn f() -> i32 { let x = 1; x }

// does not fire
fn f() -> i32 { let x = 1; x + 1 }

// does not fire
fn f(y: i32) -> i32 { let x = 1; y }
```

- **Expected noise**: medium, **measured**. The idiom is a binding kept for its
  type annotation, where the annotation drives a coercion the tail expression
  could not state on its own:

```rust
// fires, and should not
fn f() -> Box<dyn std::fmt::Debug> {
    let x: Box<dyn std::fmt::Debug> = Box::new(1);
    x
}
```

  The probe confirmed this fires. Excluding it means asserting that the
  `type:` field is *absent* on the `let_declaration`, which is primitive **P2**
  below; that is a one-predicate fix, not a redesign, and it is the same
  primitive two other items need. Until P2 exists the rule ships at `info` with
  this shape counted against its limit, or it does not ship.
- **Disposition**: **expressible**, at medium noise. P2 would move it to low.

### 13. `maintainability.rust.wildcard-import`

A glob import outside a test module or a prelude makes the origin of every name
it brings in unreadable.

- **Concept source**: rust-clippy — `wildcard_imports` (Apache-2.0 OR MIT).
  Concept only; no text taken.
- **Severity**: `info`.
- **Verified query** — `pos=1 neg=0`, with the negative carrying all three
  excluded idioms in one file:

```scheme
((use_declaration argument: (use_wildcard) @w) @report (#not-match? @w "^(super|self|crate)::|prelude::"))
```

```rust
// fires
use std::collections::*;

// does not fire
fn g() {}
#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;
    use crate::*;
    #[test]
    fn t() { g(); }
}
```

- **Expected noise**: low. The idiom is `use super::*;` in a
  `#[cfg(test)] mod tests` block, which is how essentially every Rust test
  module is written, and a prelude glob, which is the one glob the ecosystem
  endorses. Both are excluded by the predicate and the exclusion was measured.
  The cost is recall: `use crate::inner::*;` as a deliberate glob re-export is
  excluded too, measured at `pos=0`. That trade is the right one — a
  crate-rooted glob is usually the re-export idiom, and a rule that fires on
  every test module would breach its limit on the first repository.
- **Disposition**: **expressible**.

### 14. `maintainability.rust.blanket-lint-allow`

Switching off a whole lint group turns the compiler and clippy off for that
scope, and it is almost never what the author meant to do for the whole crate.

- **Concept source**: rust-clippy — `blanket_clippy_restriction_lints` /
  `allow_attributes_without_reason` (Apache-2.0 OR MIT). Concept only; no text
  taken.
- **Severity**: `info`.
- **Verified query** — `pos=1 neg=0`, on both the outer and the inner attribute
  spelling:

```scheme
((attribute_item (attribute (identifier) @n arguments: (token_tree) @args)) @report (#eq? @n "allow") (#match? @args "warnings|clippy::all|clippy::pedantic|clippy::restriction|clippy::complexity|clippy::correctness")) ((inner_attribute_item (attribute (identifier) @n2 arguments: (token_tree) @args2)) @report (#eq? @n2 "allow") (#match? @args2 "warnings|clippy::all|clippy::pedantic|clippy::restriction|clippy::complexity|clippy::correctness"))
```

```rust
// fires
#![allow(warnings)]

// fires
#[allow(clippy::all)]
fn f() {}

// does not fire
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn f() {}
```

- **Expected noise**: low. The idiom is a crate root that deliberately opts out
  of `clippy::pedantic` as a project policy. That is at most one hit per crate
  root, so the per-kLOC rate stays near zero on any repository large enough to
  measure. Matching the `token_tree` text rather than its children is what makes
  the rule read `#![allow(a, b, c)]` at all: the group name is one identifier
  among several inside an unstructured token stream.
- **Disposition**: **expressible**.

---

## Needs primitive

Each of these was measured in the same harness. The query shown is the best one
the current boundary admits, and the row records the measurement that shows why
it cannot ship.

### 15. `reliability.rust.undocumented-unsafe-block`

An `unsafe` block with no safety comment above it asserts an invariant nobody
wrote down.

- **Concept source**: rust-clippy — `undocumented_unsafe_blocks` (Apache-2.0 OR
  MIT). Concept only; no text taken.
- **Severity**: `warning`.
- **Query, measured `pos=1 neg=1`** — it cannot tell the two apart:

```scheme
(unsafe_block) @report
```

```rust
// fires
fn f(v: &[u8]) -> u8 { unsafe { *v.get_unchecked(0) } }

// also fires, and must not
fn f(v: &[u8]) -> u8 {
    // SAFETY: the caller guarantees v is non-empty.
    unsafe { *v.get_unchecked(0) }
}
```

- **Expected noise**: unbounded without the primitive. The idiom is the
  documented `unsafe` block — the correct, reviewed, safety-commented form,
  which is the *majority* of unsafe blocks in a well-maintained crate. A rule
  that reports every `unsafe` block reports the good ones and the bad ones at
  the same rate.
- **Disposition**: **needs primitive P2** — a negated-sibling predicate,
  `(#not-preceded-by? @report line_comment)`: assert that the captured node has
  no immediately preceding sibling of a given node type, comments included.
  Tree-sitter's anchor operator can require a preceding sibling; it has no form
  that requires one to be absent, and comments are extras that the anchor skips
  by default.

### 16. `reliability.rust.blocking-call-in-async`

A blocking `thread::sleep` inside an `async fn` stalls the executor thread and
every other task scheduled on it.

- **Concept source**: original to this repository. The nearest upstream concept
  is rust-clippy's `await_holding_lock` (Apache-2.0 OR MIT) — the same class of
  mistake, a synchronous operation inside an asynchronous scope — but no
  upstream lint covers this shape from syntax alone.
- **Severity**: `warning`.
- **Query, measured**: separates the shallow case (`pos=1 neg=0`) and **misses
  the real one** (`pos=0`):

```scheme
((function_item (function_modifiers "async") body: (block (expression_statement (call_expression function: (scoped_identifier name: (identifier) @f))))) @report (#eq? @f "sleep"))
```

```rust
// fires: the call is a direct child of the body block
use std::thread;
async fn f() { thread::sleep(std::time::Duration::from_secs(1)); }

// does not fire, and must: one level of nesting is enough to hide it
use std::thread;
async fn f(c: bool) { if c { thread::sleep(std::time::Duration::from_secs(1)); } }

// does not fire, correctly
async fn f() { tokio::time::sleep(std::time::Duration::from_secs(1)).await; }
```

- **Expected noise**: low — the false positives are not the problem. The problem
  is recall: a blocking call in real async code sits inside an `if`, a `match`
  arm or a `for` body, and the query reaches none of them.
- **Disposition**: **needs primitive P1** — descendant binding. A query child
  pattern matches an *immediate* child only; this was measured directly, see
  [Primitives](#primitives). Without a way to say "anywhere beneath this node",
  the rule ships with recall close to zero, which is worse than not shipping.

### 17. `reliability.rust.unnecessary-unwrap`

`if x.is_some() { ... x.unwrap() ... }` re-checks what the condition already
proved, and the compiler cannot collapse it for you.

- **Concept source**: rust-clippy — `unnecessary_unwrap` (Apache-2.0 OR MIT).
  Concept only; no text taken.
- **Severity**: `info`.
- **Query, measured**: separates the shallow case (`pos=1 neg=0`) and **misses
  the realistic one** (`pos=0`):

```scheme
((if_expression condition: (call_expression function: (field_expression value: (identifier) @v field: (field_identifier) @c)) consequence: (block (expression_statement (call_expression function: (field_expression value: (identifier) @u field: (field_identifier) @m))))) @report (#eq? @c "is_some") (#eq? @m "unwrap") (#eq? @v @u))
```

```rust
// fires: the unwrap is a bare statement in the block
fn f(x: Option<i32>) { if x.is_some() { x.unwrap(); } }

// does not fire, and must: the unwrap is inside a let, one level down
fn f(x: Option<i32>) -> i32 { if x.is_some() { let y = x.unwrap() + 1; y } else { 0 } }
```

- **Expected noise**: low. A discarded bare `x.unwrap();` is not how anyone
  writes this; the value is always bound or used, which is exactly the shape
  the query cannot reach.
- **Disposition**: **needs primitive P1**. The capture-to-capture `#eq?` that
  ties the condition's receiver to the unwrap's receiver already works — it is
  the same mechanism five shipped rules use. Only the depth is missing.

### 18. `maintainability.rust.empty-if-body`

An `if` with an empty body and no `else` evaluates a condition and throws the
answer away.

- **Concept source**: rust-clippy — `needless_ifs` (Apache-2.0 OR MIT), whose
  scope is "empty `if` branches with no else branch". Concept only; no text
  taken.
- **Severity**: `info`.
- **Query, measured `pos=1 neg=1`**:

```scheme
(if_expression consequence: (block "{" . "}")) @report
```

```rust
// fires
fn f(c: bool) { if c {} }

// also fires, and must not: the empty arm is the point
fn g() {}
fn f(c: bool) { if c {} else { g(); } }
```

- **Expected noise**: medium without the primitive. The idiom is the empty
  then-branch with a real `else`, written to avoid negating a long or awkward
  condition. Upstream's own lint carves it out by name, and this query cannot.
- **Disposition**: **needs primitive P2** — an absent-field predicate,
  `(#absent-field? @report alternative)`: assert that a named field is not
  present on a captured node. Tree-sitter can require a field and can match a
  wildcard in one, but has no negation over fields.

---

## Inexpressible

### 19. `reliability.rust.guard-held-across-await`

Holding a `std::sync::Mutex` guard across an `.await` blocks the executor thread
and, in a multi-task runtime, deadlocks.

- **Concept source**: rust-clippy — `await_holding_lock` (Apache-2.0 OR MIT).
  Concept only; no text taken.
- **Severity**: `warning` if it existed.
- **No query exists.** The closest shape — report every `.lock()` call — was
  measured at `pos=1 neg=1`:

```scheme
((call_expression function: (field_expression field: (field_identifier) @m)) @report (#eq? @m "lock"))
```

```rust
// fires
async fn f(m: &std::sync::Mutex<i32>) { let g = m.lock().unwrap(); other().await; drop(g); }
async fn other() {}

// also fires, and must not
fn f(m: &std::sync::Mutex<i32>) -> i32 { *m.lock().unwrap() }
```

- **Expected noise**: unbounded. The idiom that produces it is the ordinary
  synchronous `lock()`, which is every correct use of a mutex in the crate.
- **Disposition**: **inexpressible**. Deciding it needs three things at once:
  the guard's *lifetime* (does the binding live past the `.await`, or was it
  dropped), the receiver's *type* (a `std::sync::Mutex` guard, not a
  `tokio::sync::Mutex` guard, which is fine to hold), and the enclosing async
  scope. The first is flow-sensitive and the second is type-sensitive; both are
  outside the boundary #103 fixes, and no single bounded primitive brings them
  in. P1 would supply only the third.

### 20. `reliability.rust.discarded-result`

`let _ = f();` where `f` returns a `Result` throws away an error the type system
asked you to handle.

- **Concept source**: rustc — `unused_must_use` (Apache-2.0 OR MIT);
  rust-clippy — `let_underscore_must_use` (Apache-2.0 OR MIT). Concept only; no
  text taken.
- **Severity**: `warning` if it existed.
- **No query exists.** The syntactic shape *is* matchable — the wildcard pattern
  is a node whose type is the literal string `_`, so it must be written as an
  anonymous token, `pattern: "_"`, since `(_)` is the query language's own
  wildcard. The shape was measured at `pos=1 neg=1`:

```scheme
((let_declaration pattern: "_" value: (call_expression)) @report)
```

```rust
// fires
fn g() -> Result<(), ()> { Ok(()) }
fn f() { let _ = g(); }

// also fires, and must not: nothing is being discarded
fn g() -> i32 { 0 }
fn f() { let _ = g(); }
```

- **Expected noise**: unbounded. `let _ = ...` is also the idiomatic way to
  silence an unused-variable warning, to drop a value early, and to discard a
  return the author has decided is irrelevant.
- **Disposition**: **inexpressible**. Separating the two requires the callee's
  return type, which is symbol resolution across items and, for anything from a
  dependency, across crates. This is the same wall the matrix already recorded
  for errcheck-style rules in Go.

---

## Primitives

Two primitives would move four items, and one further candidate is named for the
record. The bar #103 sets is three candidates across two languages for one
primitive; the counts below are the Rust half only, so neither clears the bar on
this document alone.

### P1 — descendant binding

**Precisely**: an AST-query form that binds a child pattern to any node *beneath*
the anchor node rather than to an immediate child. Two shapes would do:
a predicate, `(#descendant? @outer @inner)`, or an engine-side execution where a
nested pattern marked as descendant is run as a second query over the byte range
of the outer match. `engines/ast.rs` already runs one combined query per
language per file and already resolves `@report` per pattern, so the second
shape is a scoped re-run inside `report_node`'s neighbourhood rather than a new
engine.

**Why it is needed**: tree-sitter query children are immediate children. This was
measured, not assumed — the query

```scheme
(function_item body: (block (integer_literal) @report))
```

reported **zero** matches on `fn f(c: bool) -> i32 { if c { 1 } else { 2 } }`,
where the literals sit three levels below the body block.

**Rust items that need it**: 16 (`blocking-call-in-async`), 17
(`unnecessary-unwrap`). Two.

### P2 — negation over fields and siblings

**Precisely**: two text-independent predicates added to the set a profile query
may use, which today is the ten text predicates the query compiler the loader
calls will accept — `eq?`, `not-eq?`, `any-eq?`, `any-not-eq?`, `match?`,
`not-match?`, `any-match?`, `any-not-match?`, `any-of?`, `not-any-of?` — and
nothing else, since anything outside that set fails `Query::new` and surfaces
as an `invalid ast query` load error:

- `(#absent-field? @node <field-name>)` — the captured node does not carry that
  field.
- `(#not-preceded-by? @node <node-type>)` — the captured node has no immediately
  preceding sibling of that type, counting extras such as comments, which the
  anchor operator skips.

Both are decidable from the match alone with no extra tree walk, which keeps
them inside the single-file boundary.

**Why it is needed**: tree-sitter can require a field or a preceding sibling and
has no form that requires either to be absent.

**Rust items that need it**: 15 (`undocumented-unsafe-block`, the sibling half),
18 (`empty-if-body`, the field half), and 12 (`let-and-return`) would move from
medium noise to low. Two blocked plus one improved.

### P3 — numeric comparison predicate (named, below the bar)

**Precisely**: `(#lt? @a @b)` / `(#gt? @a @b)` comparing two captures parsed as
integers rather than as text.

**The one Rust candidate**: a reversed empty range, `for i in 10..0`, which
clippy covers as `reversed_empty_ranges` (Apache-2.0 OR MIT; concept only). The
shape is matchable and the *decision* is not — measured at `pos=1 neg=1`:

```scheme
((for_expression value: (range_expression (integer_literal) @a (integer_literal) @b)) @report)
```

fires on both `for i in 10..0` and `for i in 0..10`, because the existing
predicates compare text and `"10"` versus `"0"` says nothing about order.

One candidate in one language. **Recorded, not proposed.** It should be
reconsidered only if the other language lists supply two more.

---

## Already dispositioned in 2.1

Skipped by ticket scope, listed so the next reader does not re-derive them.

**Shipped in `rules/profiles/reliability-rust.yaml`**: `self-comparison`,
`self-assignment`, `identical-if-branches`, `unimplemented-marker`,
`mem-forget`. **Shipped in `maintainability-rust.yaml`**: `dbg-macro`, and the
four metric rules `function-length`, `parameter-count`, `nesting-depth`,
`cyclomatic-complexity`.

**Held out of the 2.1 launch set on noise, still unmeasured**:
`reliability.rust.unwrap-in-library`, `maintainability.rust.empty-function-body`,
`maintainability.rust.print-in-library`. No primitive on this page changes any of
their failure modes — all three are separable only by a path convention, which
the `paths` envelope already provides — so they stay where 2.1 left them.

**Removed during 2.1 measurement**: `reliability.rust.unreachable-after-return`.
The removal record (commit `51bd561`) names the failure mode: 9 findings on
tokio, 7 of them the `return expr;`-followed-by-an-item-declaration idiom, where
the item is reachable and rustc does not warn. **No primitive is needed to fix
it, and that is worth saying plainly.** The removed query anchored the next
sibling as a wildcard:

```scheme
(block (expression_statement (return_expression)) . (_) @report)
```

which is why an item declaration satisfied it. Constraining the sibling's node
type instead reproduces the fix inside the current boundary — measured
`pos=1 neg=0` against the exact idiom that caused the removal, including the
`#[cfg]`-attributed form:

```scheme
(block (expression_statement (return_expression)) . [(expression_statement) (let_declaration)] @report)
```

```rust
// fires
fn f() -> i32 {
    return 1;
    let x = 2;
}

// does not fire: the item is reachable
fn f() -> u32 {
    return g();
    struct S;
}
fn g() -> u32 { 0 }

// does not fire
fn f() -> u32 {
    return g();
    #[cfg(test)]
    struct S;
}
fn g() -> u32 { 0 }
```

Per #104 this is not proposed as an item on this list, because the ticket admits
a 2.1 removal only when a primitive fixes it. It is recorded here as a finding
for whoever owns the removal's second look: the rule failed on its query, not on
the engine.

---

## Verification

**What was run.** A throwaway integration test under
`crates/siloscan-core/tests/`, four rounds, deleted after the last one and not
committed. Each row: build a one-rule YAML document, `rules::load_str(&doc,
"probe")`, wrap the compiled rules in a `RuleSet`, write `pos.rs` and `neg.rs`
into a `tempfile::tempdir()`, and call `scan::scan(dir, &set, None)`. Findings
are attributed to the file they land in. Nothing bypasses the loader, so a query
the loader would reject fails the row rather than passing on a hand-run
`Query::new`.

**Results.**

- Round 1, 23 rows: the 14 expressible queries all reported `pos>=1 neg=0`.
  Descendant binding measured absent. `wildcard_pattern` rejected as an invalid
  node type, which is what sent item 20 to the `"_"` anonymous-token spelling.
- Round 2, 21 rows: harder negatives — the named noise idiom for each
  expressible rule — all `neg=0` except `wildcard-import`, which fired on
  `use std::prelude::v1::*` under a first-draft predicate anchored to
  `prelude::\*$`.
- Round 3, 3 rows: the retuned `wildcard-import` predicate separates; the
  crate-rooted glob's lost recall measured; `let-and-return`'s typed-binding
  noise idiom measured firing.
- Round 4, 5 rows: the 2.1 removal's failure mode reproduced and the narrowed
  query measured against it; `match-same-arms` and `unchecked-access` noise
  idioms measured firing.

**Loader constraints checked by construction**, since every query above was
loaded rather than eyeballed: every id matches
`^[a-z0-9-]+(\.[a-z0-9-]+)+$`, no id is `metrics.duplicate-block`, `rust` is a
known language key, no `ast` rule carries a `languages` envelope, and every
predicate is inside the accepted text-predicate set. The two predicates proposed
in P2 are outside that set, which is the whole reason they are a primitive
package and not a query.

**Query gotchas confirmed in this pass**, each of which cost a row before it was
fixed:

- A predicate binds only within an enclosing parenthesis pair that also encloses
  the pattern. `(node ...) @report (#eq? @a @b)` parses and then matches
  everything.
- Query children follow the grammar's child order. `binary_expression` must be
  written `left:` then `operator:` then `right:`.
- Anonymous tokens are anchor targets and alternation members: `. "}"` and
  `["==" "!="]` both compile and both were measured.
- `(_)` is the query wildcard and cannot name the Rust `_` pattern node; that
  node is reached as the anonymous token `"_"`.

**Not verified.** No per-kLOC measurement against the pinned noise set. Every
`expected noise` rating here is an argument from query shape, sharpened by a
measured hit on the named idiom where the row says "measured". Corpus rows,
`noise/limits.tsv` entries and the removal decisions are the implementation
package's work.

## Licensing

Every concept source cited above, with the licence read at its own repository.
**No pattern text, query text, message text or documentation text was copied
from any of them.** Every query on this page was written from
`tree-sitter-rust`'s `node-types.json`.

| Source | Repo | Licence | Verified how | Used for |
| --- | --- | --- | --- | --- |
| Clippy | `rust-lang/rust-clippy` | Apache-2.0 OR MIT | `LICENSE-APACHE` and `LICENSE-MIT` both present at the repository root | concept |
| rustc | `rust-lang/rust` | Apache-2.0 OR MIT | `COPYRIGHT` at the repository root: "The Rust Project is dual-licensed under Apache 2.0 and MIT terms" | concept |

Clippy lint names were checked against the primary list,
`clippy_lints/src/declared_lints.rs` on `master`, which is generated by
`cargo dev update_lints` and is the authoritative enumeration. Every lint cited
here appears in it. One name did not and was corrected: the empty-`if` lint is
`needless_ifs`, not `needless_if`; its scope was read from the
`declare_clippy_lint!` block in `clippy_lints/src/needless_ifs.rs`.

rustc lint names were checked against the rustc book's lint listings:
`static_mut_refs`, `unused_must_use`, `invalid_value` and `unreachable_code` are
warn-by-default; `unsafe_code` is allow-by-default. This also closes one of the
two citations the 2.1 matrix recorded as "not re-verified": `unreachable_code`
is a rust-lang/rust lint under Apache-2.0 OR MIT, confirmed above.
