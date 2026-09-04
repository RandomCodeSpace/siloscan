# C++ pitfall list

**Ticket**: #111 (map #103). **Date**: 2026-09-04.
**Grammar**: `tree-sitter-cpp` 0.23.4, the pin in `crates/siloscan-core/Cargo.toml`; `tree-sitter`
0.26.11. Node names and fields were read from
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tree-sitter-cpp-0.23.4/src/node-types.json`
and from parse-tree dumps of the snippets below.

## How every query here was verified

Not by hand. A throwaway integration test (`crates/siloscan-core/tests/cpp_probe.rs`, deleted
before this commit) loaded each candidate as a one-rule profile document through
`rules::load_str` under the identity `reliability-cpp@1` — the same call `plan::resolve` makes in
a real scan — and ran `scan::scan` over a temporary directory holding the positive and the
negative snippet as `.cpp` files. The pattern is the one
`crates/siloscan-core/tests/profile_corpus.rs` uses in
`the_harness_measures_an_in_test_document`. A candidate is recorded as verified only when the
loader accepted it, the positive reported, and the negative reported nothing. The two negative
controls in items 15 and 17 are recorded as *failing* on purpose: their failure is the evidence
that no query expresses them.

What this document does **not** contain is a noise measurement. The environment has no network,
so the pinned C++ noise repositories (fmt 10.2.1, nlohmann/json v3.12.0, abseil-cpp 20240722.2)
could not be cloned. Every noise column is a judgement naming the idiom that would produce the
findings, not a per-kLOC number. Each one has to be measured by `scripts/profile_noise.py` before
the rule ships, under the map's policy: removal, not tuning, at 0.25 per kLOC for `warning` and
1.0 for `info`.

Three grammar facts the round already knew were re-checked here, because they decide several
judgements:

- **Macro-shaped namespaces.** A query does still match inside `ABSL_NAMESPACE_BEGIN` /
  `ABSL_NAMESPACE_END`. Verified: `catch-by-value` fires on a `catch` clause nested inside a
  macro-opened namespace and stays silent on the reference-catching version of the same file. The
  mis-parse widens `function_definition`, which is why `function-length` is absent from
  `maintainability-cpp.yaml`; it does not blind an expression-level query.
- **Template `<`/`>` ambiguity.** It is the named noise source for item 7 and nothing else here.
  The chained-comparison query stayed silent on `Set::template EqualElement<K, Eq>(k) < x` and on
  `std::less<K>()(k, k) < x`, but that is two snippets, not abseil.
- **Text predicates are the only predicates.** The loader rejects anything outside `eq?`,
  `not-eq?`, `any-eq?`, `any-not-eq?`, `match?`, `not-match?`, `any-match?`, `any-not-match?`,
  `any-of?`, `not-any-of?`. Every "needs primitive" verdict below is a consequence of that plus
  the query language's lack of negation and lack of a descendant axis.

One technique carried the hardest item and is worth recording: **an anchor before the first named
child expresses "this optional child is absent"**. `(declaration . declarator: (function_declarator …))`
matches a constructor declaration only when the `function_declarator` is its first named child,
which is exactly the case where no `explicit_function_specifier` precedes it. That is how item 11
detects a missing keyword without negation.

## Summary

| # | id | severity | disposition | expected noise |
| --- | --- | --- | --- | --- |
| 1 | `reliability.cpp.catch-by-value` | warning | expressible | low — catching a handle type (`std::exception_ptr`, `std::error_code`) by value |
| 2 | `reliability.cpp.throw-pointer` | warning | expressible | low — none found; `throw new` is extinct in modern code |
| 3 | `reliability.cpp.assignment-in-loop-condition` | warning | expressible | low — the deliberate `while (p = p->next)` list walk |
| 4 | `reliability.cpp.assert-with-side-effect` | warning | expressible | low — bare `assert` only; project assert macros are invisible to it |
| 5 | `reliability.cpp.duplicate-else-if-condition` | warning | expressible | low — a chain whose repeated condition calls a stateful function |
| 6 | `reliability.cpp.identical-logical-operands` | warning | expressible | low — none found |
| 7 | `reliability.cpp.chained-relational-comparison` | warning | expressible | **moderate** — a template-id the parser resolves as `a < b > c` |
| 8 | `reliability.cpp.bitwise-comparison-precedence` | warning | expressible | low — a deliberate `(a == b) & mask` |
| 9 | `reliability.cpp.unsafe-c-string-call` | warning | expressible | low–moderate — `alloca` in an intentional stack-allocation helper |
| 10 | `reliability.cpp.size-comparison-always-true` | warning | expressible | very low, and very low yield |
| 11 | `maintainability.cpp.implicit-converting-constructor` | info | expressible | **moderate–high** — a deliberately implicit value type (`nlohmann::json`, `string_view`) |
| 12 | `maintainability.cpp.redundant-virtual-with-override` | info | expressible | low — none found |
| 13 | `maintainability.cpp.named-unsafe-cast` | info | expressible | **high for `reinterpret_cast`** — bit-level container and formatter code |
| 14 | `maintainability.cpp.container-size-zero-comparison` | info | expressible | low–moderate — a type that exposes `size()` and no `empty()` |
| 15 | `reliability.cpp.non-virtual-destructor-in-polymorphic-class` | warning | **needs primitive**: negated-child predicate | n/a |
| 16 | `maintainability.cpp.incomplete-special-members` | info | **needs primitive**: negated-child predicate | n/a |
| 17 | `reliability.cpp.throw-escaping-destructor` | warning | **needs primitive**: descendant-pattern match | n/a |
| 18 | `maintainability.cpp.shadowed-local` | info | **needs primitive**: function-scope symbol tracking | n/a |
| 19 | `reliability.cpp.cstring-pointer-comparison` | warning | **inexpressible**: needs operand types | n/a |
| 20 | `reliability.cpp.mismatched-array-delete` | warning | **inexpressible**: needs allocation-site dataflow | n/a |

Twelve rules also carry a *yield* risk rather than a noise risk: items 2, 6, 10 and 12 describe
mistakes that competent C++ code does not make, so they may report nothing on all three pinned
repositories. That is not a reason to drop them — a silent reliability rule costs one query
pattern — but each still needs a corpus positive under
`crates/siloscan-core/tests/profiles-corpus/tree/cpp/`, or
`profile_recall_meets_its_floor_per_language` will never see them.

---

## 1. `reliability.cpp.catch-by-value`

**Pitfall.** An exception caught by value slices a derived exception down to its base and copies
it at the point of failure.

**Concept source.** clang-tidy `misc-throw-by-value-catch-by-reference` — "Finds violations of the
rule 'Throw by value, catch by reference'". Apache-2.0 WITH LLVM-exception. Concept only; the
query and message below are written here from `node-types.json`.

**Severity.** `warning`.

**Query** (verified: loads, fires on the positive, silent on the negative).

```scheme
(catch_clause
  parameters: (parameter_list
    (parameter_declaration
      type: [(type_identifier) (qualified_identifier) (template_type)]
      declarator: (identifier)) @report))
```

The `declarator: (identifier)` field is what makes it precise: catching by reference produces a
`reference_declarator`, and `catch (...)` produces no `parameter_declaration` at all. Restricting
`type:` to the three class-shaped nodes excludes `catch (int e)`, where a copy is free and
slicing is impossible.

```cpp
// fires
void f() {
  try { g(); } catch (std::runtime_error e) { h(); }
}

// does not fire
void f() {
  try { g(); } catch (const std::runtime_error& e) { h(); }
  try { g(); } catch (std::runtime_error& e) { h(); }
  try { g(); } catch (...) { h(); }
  try { g(); } catch (int e) { h(); }
}
```

**Expected noise.** Low. The idiom that would produce it is catching a cheap handle type by value
on purpose — `catch (std::exception_ptr p)` or `catch (std::error_code e)` — where no slicing can
occur. Neither appears often; if the measurement finds them, the fix is a `#not-any-of?` on the
type text, not a threshold.

**Disposition.** Expressible.

## 2. `reliability.cpp.throw-pointer`

**Pitfall.** `throw new E(...)` throws a pointer, so every handler has to catch `E*` and delete
it, and any handler catching `E` or `const E&` misses it entirely.

**Concept source.** clang-tidy `misc-throw-by-value-catch-by-reference` (same check, other half).
Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `warning`.

**Query** (verified).

```scheme
(throw_statement (new_expression)) @report
```

```cpp
// fires
void f() {
  throw new MyError("x");
}

// does not fire
void f() {
  throw MyError("x");
  auto* p = new MyError("x");
}
```

**Expected noise.** Low; no idiom produces it. `new` outside a `throw` is a different node parent
and was verified silent. The realistic outcome is zero findings on all three repositories, which
makes this a corpus-only rule.

**Disposition.** Expressible.

## 3. `reliability.cpp.assignment-in-loop-condition`

**Pitfall.** `while (n = g())` assigns where the reader expects a comparison. The shipped
`reliability.cpp.assignment-in-condition` covers `if_statement` only; `while`, `for` and
`do` conditions are three different node shapes and none of them match it.

**Concept source.** GCC `-Wparentheses` — "Warn if parentheses are omitted in certain contexts,
such as when there is an assignment in a context where a truth value is expected". GPL-3.0-or-later
documentation; concept only, no text taken.

**Severity.** `warning`.

**Query** (verified; all three patterns fire).

```scheme
(while_statement
  condition: (condition_clause value: (assignment_expression) @report))
(for_statement
  condition: (assignment_expression) @report)
(do_statement
  condition: (parenthesized_expression (assignment_expression) @report))
```

`while` wraps its condition in a `condition_clause`; `for` carries the condition as a bare
`condition:` field with no clause node; `do` uses a `parenthesized_expression`. Three patterns, not
one.

```cpp
// fires (three findings)
void f(int n) {
  while (n = g()) { h(); }
  for (int i = 0; i = n; ++i) { h(); }
  do { h(); } while (n = g());
}

// does not fire
void f(int n) {
  while ((n = g()) != 0) { h(); }
  for (int i = 0; i < n; ++i) { h(); }
  do { h(); } while ((n = g()) != 0);
}
```

The escape hatch is free: the conventional second pair of parentheses turns the condition into a
`binary_expression` over a `parenthesized_expression`, which no pattern matches.

**Expected noise.** Low. The idiom that would produce it is the deliberate unparenthesised list
walk, `while (p = p->next)`. It is rarer in C++ than in C, and the fix a reviewer would ask for is
the same parentheses the query already treats as an opt-out.

**Disposition.** Expressible. Ships as an extension of the shipped `assignment-in-condition` rule
or as its own id; the shipped rule's query is unchanged either way.

## 4. `reliability.cpp.assert-with-side-effect`

**Pitfall.** `assert(n = 1)` — an assertion whose condition mutates state disappears in a release
build, and the program behaves differently with `NDEBUG`.

**Concept source.** clang-tidy `bugprone-assert-side-effect` — "Finds `assert()` with side
effect". Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `warning`.

**Query** (verified).

```scheme
((call_expression
   function: (identifier) @f
   arguments: (argument_list
     [(assignment_expression) (update_expression)])) @report
 (#eq? @f "assert"))
```

```cpp
// fires (two findings)
void f(int n) {
  assert(n = 1);
  assert(n++);
}

// does not fire
void f(int n) {
  assert(n == 1);
  check(n = 1);
}
```

**Expected noise.** Low, because the name is pinned to bare `assert`. That also caps the yield:
`ABSL_HARDENING_ASSERT`, `FMT_ASSERT` and `JSON_ASSERT` are different identifiers and are not
matched. Widening the `#any-of?` list to project macro names would raise both numbers; do not do
it without a measurement.

**Disposition.** Expressible.

## 5. `reliability.cpp.duplicate-else-if-condition`

**Pitfall.** `if (a > 0) … else if (a > 0) …` — the second branch is unreachable, and the
condition the author meant to write is missing.

**Concept source.** clang-tidy `bugprone-branch-clone` — "Checks for repeated branches in
`if/else if/else` chains, consecutive repeated branches in `switch` statements and identical true
and false branches in conditional operators". Apache-2.0 WITH LLVM-exception. Concept only. The
shipped `reliability.cpp.identical-if-branches` covers the identical-*bodies* half; this is the
identical-*conditions* half, and neither query matches the other's shape.

**Severity.** `warning`.

**Query** (verified).

```scheme
((if_statement
   condition: (condition_clause value: (_) @c1)
   alternative: (else_clause
     (if_statement
       condition: (condition_clause value: (_) @c2)))) @report
 (#eq? @c1 @c2))
```

```cpp
// fires
int f(int a) {
  if (a > 0) { return 1; } else if (a > 0) { return 2; }
  return 0;
}

// does not fire
int f(int a) {
  if (a > 0) { return 1; } else if (a < 0) { return 2; }
  return 0;
}
```

**Expected noise.** Low. The idiom that would produce it is a chain whose repeated condition is a
call with state — `if (next()) … else if (next()) …` — where evaluating the same text twice is the
point. `#eq?` compares source text, so it also treats two textually identical conditions separated
by a preprocessor branch as duplicates; that is the shape to look for in the measurement.

**Disposition.** Expressible.

## 6. `reliability.cpp.identical-logical-operands`

**Pitfall.** `a && a` — one of the two operands is the wrong variable.

**Concept source.** clang-tidy `misc-redundant-expression` — "Detect redundant expressions which
are typically errors due to copy-paste". Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `warning`.

**Query** (verified).

```scheme
((binary_expression
   left: (identifier) @l
   operator: ["&&" "||"]
   right: (identifier) @r) @report
 (#eq? @l @r))
```

Identifier operands only, deliberately. This is the same decidable subset the shipped
`self-assignment` rule uses, and it is what keeps the rule away from the overloaded-`operator==`
failure that removed `self-comparison` in 2.1: `&&` and `||` on a class type are almost never
overloaded, and a reflexivity assertion is written over `==`, not `&&`.

```cpp
// fires
bool f(bool a) {
  return a && a;
}

// does not fire
bool f(bool a, bool b) {
  return a && b;
  return a || b;
}
```

**Expected noise.** Low; no idiom writes `a && a` on purpose. Expect a low yield to match.

**Disposition.** Expressible.

## 7. `reliability.cpp.chained-relational-comparison`

**Pitfall.** `a < b < c` compiles and means `(a < b) < c` — a bool compared against `c` — which is
never the mathematical reading the author intended.

**Concept source.** GCC `-Wparentheses` — "Also warn if a comparison like `x<=y<=z` appears; this
is equivalent to `(x<=y ? 1 : 0) <= z`, which is a different interpretation from that of ordinary
mathematical notation". GPL-3.0-or-later documentation; concept only.

**Severity.** `warning`.

**Query** (verified).

```scheme
(binary_expression
  left: (binary_expression operator: ["<" ">" "<=" ">="])
  operator: ["<" ">" "<=" ">="]) @report
```

```cpp
// fires
bool f(int a, int b, int c) {
  return a < b < c;
}

// does not fire
template <typename K, typename Eq>
bool f(const Set<K>& s, K k, int x, int a, int b, int c) {
  if (Set::template EqualElement<K, Eq>(k) < x) { return true; }
  return a < b && b < c;
}
```

**Expected noise.** Moderate, and this is the one item on the list whose risk is the grammar
rather than the language. The idiom that would produce it is a template-id that tree-sitter-cpp
resolves as arithmetic: any `f<T>(x) < y` the parser reads as `(f < T) > (x) < y`. The 2.1 round
already hit this exact ambiguity on abseil's `raw_hash_set.h`, where a condition containing
`Set::template EqualElement<...>` moved an `empty-if-body` report onto the wrong line. Two
hand-written negatives parsed correctly here, which is evidence that the common shapes are safe
and no evidence at all about abseil. Measure this one first; if it breaches, the failure will be
concentrated in template-dense headers and a `paths` exclusion will not save it, because those
headers are the library.

**Disposition.** Expressible, contingent on the measurement.

## 8. `reliability.cpp.bitwise-comparison-precedence`

**Pitfall.** `a & b == 0` parses as `a & (b == 0)`, because `==` binds tighter than `&`. The author
meant `(a & b) == 0`.

**Concept source.** Clang `-Wbitwise-op-parentheses`, a diagnostic flag in the Clang diagnostics
reference. Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `warning`.

**Query** (verified).

```scheme
(binary_expression
  operator: ["&" "|" "^"]
  right: (binary_expression operator: ["==" "!="])) @report
(binary_expression
  left: (binary_expression operator: ["==" "!="])
  operator: ["&" "|" "^"]) @report
```

Two patterns because both associations are suspicious: `a & b == c` puts the comparison on the
right, and `a == b & c` puts it on the left.

```cpp
// fires
bool f(int a, int b) {
  return a & b == 0;
}

// does not fire
bool f(int a, int b) {
  return (a & b) == 0;
  return a & (b | 1);
}
```

**Expected noise.** Low. The idiom that would produce it is a deliberate branchless
`(a == b) & mask`, written by someone avoiding a short-circuit; it exists in hash and SIMD code
and is exactly the shape the second pattern matches. If the measurement finds those in abseil,
drop the second pattern rather than the rule.

**Disposition.** Expressible.

## 9. `reliability.cpp.unsafe-c-string-call`

**Pitfall.** `strcpy`, `strcat`, `sprintf` and `gets` write without a destination bound.

**Concept source.** clang-tidy `bugprone-unsafe-functions`, which flags "functions that have
safer, more secure replacements available, or are considered deprecated due to design flaws" and
names `strcpy`, `strcat`, `gets` and `sprintf` among them. Apache-2.0 WITH LLVM-exception.
Concept only.

**Severity.** `warning`.

**Query** (verified).

```scheme
((call_expression function: (identifier) @f) @report
 (#any-of? @f "strcpy" "strcat" "sprintf" "gets" "alloca" "strtok"))
```

```cpp
// fires
void f(char* d, const char* s) {
  strcpy(d, s);
}

// does not fire
void f(Buf& b, char* d, const char* s, unsigned n) {
  b.strcpy(s);
  snprintf(d, n, "%s", s);
  std::strncpy(d, s, n);
}
```

A member call is a `field_expression`, not an `identifier`, and `std::strncpy` is a
`qualified_identifier`; both were verified silent. That also means a deliberately qualified
`std::strcpy` escapes the rule — a recall gap, taken knowingly, because widening the pattern to
`qualified_identifier` is what would start matching unrelated `foo::gets`.

**Expected noise.** Low to moderate. The idiom is `alloca` used on purpose as a stack-allocation
primitive, and `strtok` in a self-contained parser where the caller owns the state. If either
shows up, remove those two names from the `#any-of?` list; the four write-without-a-bound names
carry the rule.

**Disposition.** Expressible.

## 10. `reliability.cpp.size-comparison-always-true`

**Pitfall.** `v.size() >= 0` is always true — the author meant `> 0` or `!empty()`.

**Concept source.** Clang `-Wtautological-unsigned-zero-compare`, a diagnostic flag in the Clang
diagnostics reference. Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `warning`.

**Query** (verified).

```scheme
((binary_expression
   left: (call_expression
     function: (field_expression field: (field_identifier) @m))
   operator: ">="
   right: (number_literal) @z) @report
 (#eq? @m "size")
 (#eq? @z "0"))
```

```cpp
// fires
bool f(const std::vector<int>& v) {
  return v.size() >= 0;
}

// does not fire
bool f(const std::vector<int>& v) {
  return v.size() >= 1;
}
```

**Expected noise.** Very low — the shape is pinned to a method named `size` compared with the
literal `0` under `>=`. The real risk is the opposite one: this rule may report nothing on all
three repositories, which makes it a corpus-only rule the way `throw-pointer` is. Decide whether a
zero-yield reliability rule earns its pattern before shipping it.

**Disposition.** Expressible.

## 11. `maintainability.cpp.implicit-converting-constructor`

**Pitfall.** A single-argument constructor without `explicit` makes the type an implicit
conversion target, so an unrelated value silently becomes one at any call site.

**Concept source.** clang-tidy `google-explicit-constructor`. Apache-2.0 WITH LLVM-exception.
Concept only.

**Severity.** `info`.

**Query** (verified; all four patterns fire, and the six negatives are silent).

```scheme
((class_specifier
   name: (type_identifier) @cls
   body: (field_declaration_list
     (declaration
       .
       declarator: (function_declarator
         declarator: (identifier) @ctor
         parameters: (parameter_list . (parameter_declaration type: (_) @ptype) .))) @report))
 (#eq? @ctor @cls)
 (#not-eq? @ptype @cls)
 (#not-match? @ptype "initializer_list"))
```

plus the same pattern three more times, for `(function_definition …)` in a `class_specifier` (an
in-class definition is not a `declaration`) and for both again under `struct_specifier`.

Three details carry it:

- The anchor before `declarator:` means the `function_declarator` is the declaration's **first**
  named child. `explicit Foo(int)` puts an `explicit_function_specifier` first, so the anchor is
  what expresses "no `explicit`" in a language with no negation.
- The anchors around the single `parameter_declaration` bound the parameter list to exactly one
  parameter.
- `(#not-eq? @ptype @cls)` drops the copy and move constructors, whose parameter type is the class
  itself; `(#not-match? @ptype "initializer_list")` drops the one constructor that is
  conventionally implicit on purpose. Both exclusions were verified against
  `Bar(const Bar&)`, `Bar(Bar&&)` and `Bar(std::initializer_list<int>)`.

```cpp
// fires (four findings)
struct Bar { Bar(int a); };
struct Qux { Qux(int a) : a_(a) {} int a_; };
class Foo { public: Foo(int a); };
class Baz { public: Baz(int a) : a_(a) {} int a_; };

// does not fire
struct Bar {
  explicit Bar(int a);
  Bar(const Bar& o);
  Bar(Bar&& o);
  Bar(int a, int b);
  Bar();
  Bar(std::initializer_list<int> l);
};
```

A constructor whose single parameter has a default (`Foo(int a = 0)`) is an
`optional_parameter_declaration` and is not matched — a known recall gap, kept because closing it
would also match multi-parameter constructors with defaults.

**Expected noise.** Moderate to high, and repository-dependent. The idiom that produces it is a
value type that is *meant* to be implicitly constructible: `nlohmann::json` is built on exactly
that (its whole assignment API depends on implicit construction from anything), and
`absl::string_view` from `const char*` is the same design. abseil should be close to clean,
because the Google style it follows mandates `explicit`; nlohmann/json will not be, and no `paths`
exclusion helps there because the offending header is the library. Measure before shipping and
expect this to be the removal candidate of the set.

**Disposition.** Expressible.

## 12. `maintainability.cpp.redundant-virtual-with-override`

**Pitfall.** `virtual void f() override;` — `override` already implies `virtual`, and writing both
suggests the author was unsure which one does the work.

**Concept source.** clang-tidy `modernize-use-override` — "Adds `override` … to overridden virtual
functions and removes `virtual` from those functions as it is not required". Apache-2.0 WITH
LLVM-exception. Concept only.

**Severity.** `info`.

**Query** (verified).

```scheme
((field_declaration
   "virtual"
   declarator: (function_declarator (virtual_specifier) @v)) @report
 (#eq? @v "override"))
```

`virtual` is an anonymous token child of `field_declaration` and precedes the `type:` field, so it
is written before `declarator:` — query children must follow grammar child order. `virtual_specifier`
covers both `override` and `final`, which is why the `#eq?` is there: `virtual void h() final` is
not the same mistake.

```cpp
// fires
struct D : B {
  virtual void f() override;
};

// does not fire
struct D : B {
  void f() override;
  virtual void g();
  void h() final;
  virtual void i() = 0;
};
```

**Expected noise.** Low; the pattern is a tautology in the language, so there is no idiom that
produces it deliberately. Yield depends on the age of the codebase.

**Disposition.** Expressible.

## 13. `maintainability.cpp.named-unsafe-cast`

**Pitfall.** `const_cast` discards a promise the type system made; `reinterpret_cast` discards the
type system.

**Concept source.** clang-tidy `cppcoreguidelines-pro-type-const-cast` ("Imposes limitations on the
use of `const_cast` within C++ code") and `cppcoreguidelines-pro-type-reinterpret-cast` ("This
check flags all uses of `reinterpret_cast` in C++ code"). Apache-2.0 WITH LLVM-exception. Concept
only.

**Severity.** `info`.

**Query** (verified).

```scheme
((call_expression
   function: (template_function name: (identifier) @f)) @report
 (#any-of? @f "const_cast" "reinterpret_cast"))
```

The named casts have no dedicated node in this grammar: `const_cast<int*>(p)` parses as a
`call_expression` whose function is a `template_function`. `static_cast` and `dynamic_cast` share
the shape and are excluded by name.

```cpp
// fires
int* f(const int* p) {
  return const_cast<int*>(p);
}

// does not fire
long f(int p) {
  return static_cast<long>(p);
}
```

**Expected noise.** High for `reinterpret_cast`, low for `const_cast`. The idiom is bit-level
container and formatting code: abseil's hash tables and fmt's argument packing both reinterpret
storage as a matter of design, and neither is a defect. Ship `const_cast` alone unless the
measurement says otherwise; a rule that fires on every line of `raw_hash_set.h` teaches the reader
to ignore the profile.

**Disposition.** Expressible, with `reinterpret_cast` expected to be dropped from the
`#any-of?` list on measurement.

## 14. `maintainability.cpp.container-size-zero-comparison`

**Pitfall.** `v.size() == 0` asks for a count to answer a yes-or-no question; `empty()` is
constant-time on every container and `size()` is not.

**Concept source.** clang-tidy `readability-container-size-empty` — "Checks whether a call to the
`size()`/`length()` method or the `std::size()` free function can be replaced with a call to
`empty()`". Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `info`.

**Query** (verified).

```scheme
((binary_expression
   left: (call_expression
     function: (field_expression field: (field_identifier) @m))
   operator: ["==" "!="]
   right: (number_literal) @z) @report
 (#any-of? @m "size" "length")
 (#eq? @z "0"))
```

`field_expression` covers both `.` and `->`; the arrow form was verified.

```cpp
// fires (two findings)
bool f(const std::vector<int>& v, const std::string* s) {
  if (v.size() == 0) { return true; }
  return s->length() != 0;
}

// does not fire
bool f(const std::vector<int>& v) {
  if (v.empty()) { return true; }
  return v.size() == 1;
}
```

**Expected noise.** Low to moderate. The idiom is a type that exposes `size()` and no `empty()` —
a C-array wrapper, a generated protobuf message, a handle with a `size()` accessor that is not a
container at all — where the advice is wrong. The method name is the only evidence a query has;
`foo_size() == 0`, the protobuf shape, does not match, because the field identifier is `foo_size`.

**Disposition.** Expressible.

---

## 15. `reliability.cpp.non-virtual-destructor-in-polymorphic-class`

**Pitfall.** A class with a virtual function and a public non-virtual destructor: deleting a
derived object through a base pointer is undefined behaviour.

**Concept source.** clang-tidy `cppcoreguidelines-virtual-class-destructor` — "Finds virtual
classes whose destructor is neither public and virtual nor protected and non-virtual".
Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `warning`.

**No query exists.** The rule is a negation over siblings — *a `field_declaration_list` that
contains a `virtual` member function and does **not** contain a virtual destructor* — and the query
language has no negation over children. The closest expressible pattern is the positive half
alone, and it was run as a negative control:

```scheme
((class_specifier
   body: (field_declaration_list
     (field_declaration "virtual"))) @report)
```

It reported both snippets, including the one that declares `virtual ~Base();`. Verified failure,
not an assumption.

**Primitive needed.** A **negated-child predicate**: a way to assert that no child of a captured
node matches a given sub-pattern — spelled, for instance, `(#not-has-child? @body (declaration "virtual" declarator: (function_declarator declarator: (destructor_name))))`.
Text predicates cannot stand in: `#not-match?` over the class body would compare the whole body's
source text, so any `virtual` anywhere in the class would suppress the finding.

**Expected noise.** Not assessable until the primitive exists. The idiom to watch is the
protected-non-virtual-destructor form, which is correct and which the primitive's sub-pattern
would have to recognise.

**Disposition.** Needs primitive: negated-child predicate.

## 16. `maintainability.cpp.incomplete-special-members`

**Pitfall.** A class that defines a destructor but neither defines nor deletes its copy
constructor and copy assignment operator — the rule of three — copies itself with a
compiler-generated shallow copy over an owned resource.

**Concept source.** clang-tidy `cppcoreguidelines-special-member-functions` — "The check finds
classes where some but not all of the special member functions are defined". Apache-2.0 WITH
LLVM-exception. Concept only.

**Severity.** `info`.

**No query exists.** Same shape as item 15 and the same reason: "declares a destructor" is
expressible, "does not declare a copy constructor" is not. This is the second C++ candidate
blocked on the identical primitive, which is what makes the primitive worth costing.

**Primitive needed.** The same **negated-child predicate**. Two candidates in this language need
it; the map's bar is three candidates across two languages, and the equivalent shapes in other
languages — a Java class that overrides `equals` without `hashCode`, a C# type implementing
`IDisposable` with no `Dispose`, a Rust `impl PartialEq` with no `Eq` — are the same negation over
siblings. Those were not investigated here and should be confirmed on their own tickets before the
primitive is scheduled.

**Expected noise.** Not assessable. The idiom to watch is the deliberately move-only type, which
declares the destructor and `= delete`s the copies; the `delete_method_clause` node makes that
distinguishable, so the primitive's sub-pattern can exclude it.

**Disposition.** Needs primitive: negated-child predicate.

## 17. `reliability.cpp.throw-escaping-destructor`

**Pitfall.** A `throw` reachable from a destructor terminates the process when the destructor runs
during stack unwinding.

**Concept source.** clang-tidy `bugprone-exception-escape` — "Finds functions which may throw an
exception directly or indirectly, but they should not", naming destructors first among them.
Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `warning`.

**No sound query exists.** tree-sitter queries have no descendant axis: a pattern can name a
child, not "a `throw_statement` anywhere inside this body". The available approximation is a text
predicate over the captured body, and it was verified — including its failure:

```scheme
((function_definition
   declarator: (function_declarator declarator: (destructor_name))
   body: (compound_statement) @b) @report
 (#match? @b "throw"))
```

It fires correctly on a destructor containing `throw std::runtime_error("x")`. It also fires on

```cpp
struct U {
  ~U() {
    log("never throw here");
  }
};
```

because `#match?` matches the body's **source text**, so the word inside a string literal or a
comment counts. A `noexcept(false)` specifier or a `// may throw` comment produces the same false
positive. Verified failure.

**Primitive needed.** A **descendant-pattern match**: a way to require that a captured node's
subtree contains a node matching a sub-pattern, at any depth. The same primitive would also
express "a `switch` case that falls through into a non-empty case" and "a lambda that captures
`this` and is stored", neither of which was assessed here.

**Expected noise.** The regex approximation's noise is the word `throw` in prose, which is common
in destructor comments. Do not ship the approximation.

**Disposition.** Needs primitive: descendant-pattern match.

## 18. `maintainability.cpp.shadowed-local`

**Pitfall.** A local declaration that reuses the name of a parameter or an enclosing local, so an
assignment intended for the outer variable is silently discarded at the end of the inner scope.

**Concept source.** Clang `-Wshadow`, a diagnostic flag group in the Clang diagnostics reference.
Apache-2.0 WITH LLVM-exception. Concept only.

**Severity.** `info`.

**No query exists.** Two declarations in a nesting relationship, compared by name, with the
comparison conditioned on one being an ancestor scope of the other. A query can match a fixed
nesting depth — a `compound_statement` directly inside a `function_definition` — but not "any
enclosing scope", and the number of intervening blocks is unbounded.

**Primitive needed.** **Function-scope symbol tracking**: for each function body, the set of names
declared in each enclosing scope, exposed to a rule as a predicate over a captured identifier. This
is the "scope tracking within a function" option the map already names as an open question, and it
is a substantially larger addition than the two predicates above — it is a symbol table, not a
matcher.

**Expected noise.** Not assessable. The idiom to watch is the deliberate shadow in a short lambda
body or a nested `for` index, which many C++ codebases accept.

**Disposition.** Needs primitive: function-scope symbol tracking. Weakest of the four: the
primitive is the most expensive and the pitfall is the least severe.

---

## 19. `reliability.cpp.cstring-pointer-comparison`

**Pitfall.** `s == "x"` where `s` is a `const char*` compares addresses, not contents.

**Concept source.** Clang `-Wstring-compare`, a diagnostic flag in the Clang diagnostics reference
(listed under `-Waddress`). Apache-2.0 WITH LLVM-exception. Concept only. clang-tidy's
`bugprone-suspicious-string-compare` is the adjacent check and covers misuse of the `strcmp`
family, not this shape.

**Severity.** `warning`.

**Inexpressible.** The C profile ships this rule as `reliability.c.string-literal-comparison`, and
the identical query is wrong in C++: `operator==` is overloaded for `std::string`,
`std::string_view` and every string-like type in every library, so `s == "x"` is correct far more
often than it is wrong. Deciding which is which needs the static type of the left operand, which a
single-file query cannot have. No primitive short of type resolution fixes it, and type resolution
is outside the map's engine boundary.

**Disposition.** Inexpressible. Ships in C, cannot ship in C++.

## 20. `reliability.cpp.mismatched-array-delete`

**Pitfall.** Memory from `new[]` released with `delete`, or from `new` released with `delete[]`.

**Concept source.** cppcheck `mismatchAllocDealloc` ("Mismatching allocation and deallocation").
GPL-3.0-or-later — concept only, no text or pattern taken. clang-tidy's equivalent is the analyser
check `clang-analyzer-cplusplus.NewDelete`, which is path-sensitive by construction.

**Severity.** `warning`.

**Inexpressible.** `delete p` and `new T[n]` are two statements that share nothing but a variable
name, usually in different functions and often in different files. Matching them requires
following the pointer from its allocation to its release — dataflow, explicitly out of scope on
#103. The degenerate single-expression case, `delete new T[1]`, is expressible and worthless.

**Disposition.** Inexpressible: needs allocation-site dataflow.

---

## Primitives, and who needs them

| Primitive | Items | What it would have to do |
| --- | --- | --- |
| Negated-child predicate | 15 (`non-virtual-destructor-in-polymorphic-class`), 16 (`incomplete-special-members`) | Assert that no child of a captured node matches a sub-pattern. Two C++ candidates; the map's bar is three across two languages, so Java `equals`/`hashCode`, C# `IDisposable` and Rust `PartialEq`/`Eq` should be checked on their own tickets before this is scheduled. Cheapest of the three — it is a matcher, evaluated on a node siloscan already holds. |
| Descendant-pattern match | 17 (`throw-escaping-destructor`) | Require a captured node's subtree to contain a node matching a sub-pattern at any depth. One C++ candidate. The `#match?` text approximation exists today and is unsound; item 17 records the verified false positive. |
| Function-scope symbol tracking | 18 (`shadowed-local`) | Maintain, per function body, the names declared in each enclosing scope and expose them as a predicate over a captured identifier. One C++ candidate, and the most expensive of the three: a symbol table rather than a matcher. Weakest case of the three. |

## Considered and set aside

Each of these has a verified query — the loader accepted it, the positive fired, the negative was
silent — and is set aside on noise or on value, not on expressibility. They are recorded so the
next round does not re-derive them.

| Candidate | Verified query | Why set aside |
| --- | --- | --- |
| C-style cast | `((cast_expression type: (type_descriptor) @t) @report (#not-eq? @t "void"))` | The `(void)x` unused-parameter idiom is excluded by the predicate and was verified silent, but every remaining C-interop cast in fmt and abseil is deliberate. Concept: clang-tidy `cppcoreguidelines-pro-type-cstyle-cast`, Apache-2.0 WITH LLVM-exception. |
| `malloc` family in C++ | `((call_expression function: (identifier) @f) @report (#any-of? @f "malloc" "calloc" "realloc"))` | Allocator implementations and C-compatibility layers are the reason abseil calls these, and they are the correct code there. Concept: clang-tidy `cppcoreguidelines-no-malloc`, Apache-2.0 WITH LLVM-exception. |
| `NULL` instead of `nullptr` | `((null) @report (#eq? @report "NULL"))` | `NULL` and `nullptr` share the `null` node, so the `#eq?` is needed and works; `NULL` inside a `#define` body is `preproc_arg` text and is invisible, which was verified. Set aside because C-compatibility headers use `NULL` correctly and the finding is a style preference. Concept: clang-tidy `modernize-use-nullptr`, Apache-2.0 WITH LLVM-exception. |
| Range-for by value | `(for_range_loop type: (placeholder_type_specifier) declarator: (identifier)) @report` | Cannot distinguish `for (auto i : indices)` over `int` — correct and common — from `for (auto s : strings)`, which copies. That distinction is the whole rule and it needs types. Concept: clang-tidy `performance-for-range-copy`, Apache-2.0 WITH LLVM-exception. |
| `return std::move(x)` | `((return_statement (call_expression function: (qualified_identifier scope: (namespace_identifier) @s name: (identifier) @n))) @report (#eq? @s "std") (#eq? @n "move"))` | Pessimises the return of a local, but is required when returning a member or a by-value parameter as an rvalue, and syntax cannot tell those apart. |
| `goto` | `(goto_statement) @report` | Precise and near-silent in modern C++, which is also why it says nothing a reviewer does not already see. Low value per pattern. |

## The 2.1 removals

#111 excludes rules the 2.1 matrix removed unless a named primitive fixes the failure mode. None of
the four does, and the reasons are worth stating so the question is closed rather than re-opened:

- **`self-comparison`** was removed because every finding on nlohmann/json and abseil is a
  reflexivity assertion over an overloaded `operator==` — `CHECK(it1 == it1)`,
  `static_assert(t1 == t1, "")`. No primitive on this list fixes that; what would fix it is an
  **ancestor-pattern predicate** ("this match is not inside a call whose callee matches
  `CHECK|EXPECT|ASSERT|static_assert`"), which no other candidate here needs. A cheaper structural
  narrowing exists — restricting the rule to a `condition_clause` or `return_statement` operand, so
  a comparison inside an `argument_list` never matches — but that is a different rule with a
  different id, not the removed one returning, and it is not proposed here.
- **`unreachable-after-return`** was removed because every finding was a trailing comment on the
  return line. That is a span-reporting artefact, not a missing primitive.
- **`empty-catch`** was removed because every finding is the `try { f(); FAIL(); } catch (const E&) {}`
  assertion idiom or a fuzz entry point. A text predicate over the try block
  (`#not-match? @try "ASSERT|EXPECT|FAIL"`) is already expressible today with no new primitive, so
  the rule's return is a measurement question, not an engine question — and on the pinned set it
  would trade the noise for near-zero yield.
- **`empty-if-body`** was removed because the whole noise set yields two findings, both parse
  artefacts. A primitive cannot fix a grammar.

## Sources

| Source | Licence | Use |
| --- | --- | --- |
| clang-tidy checks (`clang.llvm.org/extra/clang-tidy/checks/…`) | Apache-2.0 WITH LLVM-exception | Concept only. Check names and one-line purposes were read from each check's own page; no pattern, matcher, diagnostic text or message was taken. Items 1, 2, 4, 5, 6, 9, 11, 12, 13, 14, 15, 16, 17, 19, 20 and four rows of the set-aside table. |
| Clang diagnostics reference (`clang.llvm.org/docs/DiagnosticsReference.html`) | Apache-2.0 WITH LLVM-exception | Concept only. Flag names `-Wbitwise-op-parentheses`, `-Wtautological-unsigned-zero-compare`, `-Wstring-compare`, `-Wshadow`. Items 8, 10, 18, 19. |
| GCC warning options (`gcc.gnu.org/onlinedocs/gcc/Warning-Options.html`) | GPL-3.0-or-later (documentation) | Concept only. `-Wparentheses`, for the assignment-as-truth-value and `x<=y<=z` concepts. Items 3 and 7. Two short phrases are quoted as attributed citations; nothing is reused as rule text. |
| cppcheck (`mismatchAllocDealloc`) | GPL-3.0-or-later | Concept only, as an error-id name. Item 20. No text or pattern taken. |
| `tree-sitter-cpp` 0.23.4 `src/node-types.json` | MIT | Every query above was written from it. |

No rule text, pattern, message or query was copied from any of them. Every query in this document
was written against `node-types.json` and parse-tree dumps, and verified through siloscan's own
loader and scanner.
