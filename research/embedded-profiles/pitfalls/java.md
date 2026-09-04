# Java pitfall list

Research for issue #109, under the 2.2 wayfinder map #103. This document decides
*what the Java rules would be*; it writes no rule YAML and no engine code.

**Grammar pin.** `tree-sitter-java` 0.23.5 on `tree-sitter` 0.26.11, from
`crates/siloscan-core/Cargo.toml`. Node names, field names and anonymous tokens
below were read from
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tree-sitter-java-0.23.5/src/node-types.json`
and `grammar.js` at that version.

**Engine boundary.** Single-file tree-sitter queries and single-file metric
rules, per #103. No cross-file, type-aware or dataflow analysis.

**Licensing.** Every citation is concept-only: a linter's *name for the idea*,
never its pattern text, query text or message text. PMD carries a BSD-style
licence with a DARPA acknowledgement clause (not SPDX BSD-3-Clause);
error-prone is Apache-2.0; Checkstyle is LGPL-2.1-or-later; SonarSource RSPEC
is the SONAR Source-Available License v1.0, non-OSI, cited by S-number only.
Nothing here is derived from any of their sources.

**What is excluded.** The three rules the shipped documents already carry —
`reliability.java.self-comparison`, `reliability.java.string-literal-identity`,
`reliability.java.identical-if-branches` — and the four metric rules in
`maintainability-java.yaml`. Three rules the 2.1 round *removed* are back, and
say so per item: in each case the removal was a defect in the query, not a limit
of the engine, and the fix is verified below.

## How each query was verified

Not by hand. `crates/siloscan-core/tests/pitfalls_java_probe.rs` (throwaway, not
committed) builds a one-rule document per candidate, loads it through
`rules::load_str` under the same call `plan::resolve` makes, writes the positive
and negative snippets into a temporary directory, and runs `scan::scan` over it —
the product's own path, not a re-implementation. A second test asserts the
shapes each query must *miss*, so the "needs primitive" dispositions rest on a
measured result rather than on reading the query.

```
17 candidates: every positive fired, every negative reported nothing,
5 miss-cases reported nothing.
```

Three query gotchas cost time and are recorded so the next language does not pay
them again:

- A predicate binds only inside an outer parenthesis pair wrapping the pattern.
  `(node ...) @report (#eq? @l @r)` parses and then matches everything.
- Query children must be written in the grammar's child order. `left:` precedes
  `operator:` precedes `right:` in `binary_expression`; the reverse is an
  impossible pattern and fails to compile.
- The loader accepts only the text-predicate set (`eq?`, `not-eq?`, `any-eq?`,
  `any-not-eq?`, `match?`, `not-match?`, `any-match?`, `any-not-match?`,
  `any-of?`, `not-any-of?`). Everything below stays inside it.

## Summary

| # | id | severity | disposition | noise |
| --- | --- | --- | --- | --- |
| 1 | `reliability.java.self-assignment` | warning | expressible | low |
| 2 | `reliability.java.unreachable-after-return` | warning | expressible | low |
| 3 | `reliability.java.empty-catch` | warning | expressible | medium — re-measure |
| 4 | `reliability.java.self-comparison-ordering` | warning | expressible | low |
| 5 | `reliability.java.self-equals` | warning | expressible | low |
| 6 | `reliability.java.identical-logical-operands` | warning | expressible | low |
| 7 | `reliability.java.duplicate-branch-condition` | warning | expressible | low |
| 8 | `reliability.java.assignment-in-condition` | warning | expressible | low |
| 9 | `reliability.java.control-flow-in-finally` | warning | expressible | low |
| 10 | `reliability.java.equals-wrong-parameter` | warning | expressible | low |
| 11 | `reliability.java.catch-jvm-throwable` | warning | expressible | medium |
| 12 | `reliability.java.finalize-override` | warning | expressible | low |
| 13 | `reliability.java.empty-control-body` | warning | expressible | low |
| 14 | `maintainability.java.redundant-wrapper-instantiation` | info | expressible | low |
| 15 | `maintainability.java.boolean-literal-redundancy` | info | expressible | low |
| 16 | `maintainability.java.catch-rethrow` | info | expressible | low |
| 17 | `maintainability.java.parameter-reassigned` | info | needs primitive | medium |
| 18 | `reliability.java.equals-without-hashcode` | warning | needs primitive | — |
| 19 | `maintainability.java.switch-without-default` | info | needs primitive | — |
| 20 | `reliability.java.reference-equality` | warning | inexpressible | — |

Sixteen expressible, three blocked on a primitive, one out of reach entirely.

---

## 1. `reliability.java.self-assignment`

**Pitfall.** A variable is assigned to itself, which does nothing.

**Concept source.** error-prone — `SelfAssignment` (Apache-2.0). Concept only.

**Severity.** `warning`

**2.1 relation.** Removed in 2.1 at 22 findings on guava, every one a compound
assignment: the query left the `operator` field unconstrained, so `b *= b` and
`n += n` matched. `assignment_expression` *has* an `operator` field
(`node-types.json`), so the fix is one line and needs no primitive.

```scheme
((assignment_expression
   left: (identifier) @l
   operator: "="
   right: (identifier) @r) @report
 (#eq? @l @r))
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
  int f;
  void m(int b) {
    b *= b;
    b += b;
    this.f = b;
  }
}
```

**Expected noise.** Low. The idiom that produced the 2.1 removal — a compound
assignment such as `b *= b` in a numeric accumulator — is now excluded by the
`operator: "="` constraint, verified above. `this.f = this.f` is a
`field_access` on both sides and is deliberately not matched; that is lost
recall, not noise.

**Disposition.** Expressible.

---

## 2. `reliability.java.unreachable-after-return`

**Pitfall.** A statement follows `return` in the same block and can never run.

**Concept source.** SonarSource S1763 — `unreachable code` (SONAR
Source-Available License v1.0, non-OSI; upstream repo private). Concept only.
javac rejects the shape outright under JLS §14.21, which is why the base rate is
near zero.

**Severity.** `warning`

**2.1 relation.** Removed in 2.1 because every finding on gson, commons-lang and
guava was a *trailing comment* on the return line, not code: `(_)` matches named
nodes and `line_comment`/`block_comment` are named. A text predicate excludes
them, and needs no primitive.

```scheme
((block (return_statement) . (_) @report)
 (#not-match? @report "^/"))
```

```java
// fires
class C {
  int m(int a) {
    return 1;
    a = 2;
  }
}

// does not fire
class C {
  int m() {
    return 1;
    // trailing note
  }
  int n() {
    /* block */
    return 2;
    /* after */
  }
}
```

**Expected noise.** Low. The idiom that produced the 2.1 removal — a comment
written after the `return` to explain it — is excluded, verified above. No Java
statement can begin with `/`, so the predicate discards nothing real.

**Disposition.** Expressible. Recall stays direct-sibling only: unreachable code
one block deeper is missed (verified). Item 17's primitive would lift that.

---

## 3. `reliability.java.empty-catch`

**Pitfall.** A `catch` block with no body silently discards the exception.

**Concept source.** PMD — `EmptyCatchBlock` (PMD BSD-style with acknowledgement
clause); SpotBugs — `DE_MIGHT_IGNORE` (LGPL-2.1-or-later). Concept only.

**Severity.** `warning`

**2.1 relation.** Removed in 2.1 at 4.67 per kLOC on guava, and the finding
*was* the pre-JUnit5 assertion idiom `catch (X expected) {}`. The exception
variable's name is the signal, and it is reachable from the same pattern.

```scheme
((catch_clause
   (catch_formal_parameter name: (identifier) @n)
   body: (block "{" . "}") @report)
 (#not-match? @n "(?i)^(expected|ignore|ignored|unused|e_)$"))
```

```java
// fires
class C {
  void m() {
    try { g(); } catch (Exception e) {}
  }
  void g() {}
}

// does not fire
class C {
  void m() {
    try { g(); } catch (Exception expected) {}
    try { g(); } catch (Exception ignored) {}
    try { g(); } catch (Exception e) { log(e); }
  }
  void g() {}
  void log(Exception e) {}
}
```

**Expected noise.** Medium until re-measured. The named idiom — pre-JUnit5
`try { failingCall(); fail(); } catch (X expected) {}` — is excluded, verified
above, and so is `catch (X ignored) {}`. What remains is a best-effort
`close()` swallowing `IOException` under a parameter still called `e`, which the
name predicate cannot see. This rule must not ship on the strength of this
document: it must be re-run against guava under `scripts/profile_noise.py` and
removed again if it clears 0.25 per kLOC. A block holding only a comment keeps a
comment node and is not reported, which stays the documented opt-out.

**Disposition.** Expressible; readmission is conditional on the measurement, not
on a primitive.

---

## 4. `reliability.java.self-comparison-ordering`

**Pitfall.** Both operands of an ordering comparison are the same identifier, so
the result is a constant.

**Concept source.** error-prone — `SelfComparison`, `IdentityBinaryExpression`
(Apache-2.0). Concept only.

**Severity.** `warning`

**Relation to shipped.** `reliability.java.self-comparison` covers `==` only.
This is its ordering sibling and does not overlap it.

```scheme
((binary_expression
   left: (identifier) @l
   operator: ["<" "<=" ">" ">="]
   right: (identifier) @r) @report
 (#eq? @l @r))
```

```java
// fires
class C {
  boolean m(int a) {
    return a < a;
  }
  boolean n(int a) {
    return a >= a;
  }
}

// does not fire
class C {
  boolean m(int a, int b) {
    return a < b;
  }
  boolean nan(double d) {
    return d != d;
  }
  boolean n(double d) {
    return Double.isNaN(d);
  }
}
```

**Expected noise.** Low. The idiom that *would* produce noise is `d != d` as a
hand-rolled NaN test, which numeric code does write; `!=` is therefore
deliberately left out of the operator set, verified above. No ordering operator
has a NaN idiom — the Java spelling is `Double.isNaN` — so what is left has no
correct reading.

**Disposition.** Expressible.

---

## 5. `reliability.java.self-equals`

**Pitfall.** An object is compared for equality with itself, which is always
true.

**Concept source.** error-prone — `SelfEquals` (Apache-2.0). Concept only.

**Severity.** `warning`

```scheme
((method_invocation
   object: (identifier) @o
   name: (identifier) @m
   arguments: (argument_list . (identifier) @a .)) @report
 (#eq? @m "equals")
 (#eq? @o @a))
```

```java
// fires
class C {
  boolean m(String a) {
    return a.equals(a);
  }
}

// does not fire
class C {
  boolean m(String a, String b) {
    return a.equals(b);
  }
  boolean n(String a) {
    return a.equals(a.trim());
  }
}
```

**Expected noise.** Low. The idiom that would produce noise is an equals-contract
test asserting reflexivity — `assertTrue(a.equals(a))` in an `EqualsTester`-style
suite — which is correct code and would report. The anchors `. (identifier) @a .`
hold the call to exactly one bare-identifier argument, so `a.equals(a.trim())`
does not match; a `paths` exclusion for the test tree is the one allowance #103
permits if the measurement needs it.

**Disposition.** Expressible.

---

## 6. `reliability.java.identical-logical-operands`

**Pitfall.** Both operands of a binary logical or bitwise operator are the same
identifier, so one of them is dead.

**Concept source.** error-prone — `IdentityBinaryExpression` (Apache-2.0).
Concept only.

**Severity.** `warning`

```scheme
((binary_expression
   left: (identifier) @l
   operator: ["&&" "||" "&" "|"]
   right: (identifier) @r) @report
 (#eq? @l @r))
```

```java
// fires
class C {
  boolean m(boolean a) {
    return a && a;
  }
}

// does not fire
class C {
  boolean m(boolean a, boolean b) {
    return a && b;
  }
}
```

**Expected noise.** Low. There is no idiom that writes `a && a` on purpose; the
usual cause is a copy-paste in a longer condition where the second operand was
never renamed. `a | a` on integers is equally a no-op. Restricting both sides to
bare identifiers keeps side-effecting calls (`f() && f()`) out, which is the one
shape where repetition can be deliberate.

**Disposition.** Expressible.

---

## 7. `reliability.java.duplicate-branch-condition`

**Pitfall.** An `else if` repeats the condition of the `if` above it, so its body
is unreachable.

**Concept source.** SonarSource S1862 — `related if/else if statements should
not have the same condition`, listed for Java (SONAR Source-Available License
v1.0, non-OSI). Concept only.

**Severity.** `warning`

**Relation to shipped.** `reliability.java.identical-if-branches` compares the
two *bodies*. This compares the two *conditions* down an else-if chain. Distinct
shapes, no overlap.

```scheme
((if_statement
   condition: (parenthesized_expression) @a
   alternative: (if_statement condition: (parenthesized_expression) @b)) @report
 (#eq? @a @b))
```

```java
// fires
class C {
  int m(int x) {
    if (x > 0) {
      return 1;
    } else if (x > 0) {
      return 2;
    }
    return 0;
  }
}

// does not fire
class C {
  int m(int x) {
    if (x > 0) {
      return 1;
    } else if (x < 0) {
      return 2;
    }
    return 0;
  }
}
```

**Expected noise.** Low. The comparison is byte-identical condition text
including the parentheses, so there is no idiom that reaches it by accident. The
cost is recall, not precision: `x > 0` against `x>0` is missed (verified), and so
is a condition repeated two links further down the chain.

**Disposition.** Expressible.

---

## 8. `reliability.java.assignment-in-condition`

**Pitfall.** A condition assigns instead of comparing — `if (a = b)` where
`if (a == b)` was meant.

**Concept source.** PMD — `AssignmentInOperand` (PMD BSD-style with
acknowledgement clause); Checkstyle — `InnerAssignment` (LGPL-2.1-or-later).
Concept only.

**Severity.** `warning`

```scheme
(if_statement condition: (parenthesized_expression (assignment_expression) @report))
(while_statement condition: (parenthesized_expression (assignment_expression) @report))
(do_statement condition: (parenthesized_expression (assignment_expression) @report))
```

```java
// fires
class C {
  void m(boolean a, boolean b) {
    if (a = b) { g(); }
  }
  void g() {}
}

// does not fire
import java.io.BufferedReader;
class C {
  void m(BufferedReader r) throws Exception {
    String line;
    while ((line = r.readLine()) != null) { g(line); }
  }
  void n(boolean a, boolean b) {
    if (a == b) { }
  }
  void g(String s) {}
}
```

**Expected noise.** Low, and this is the whole design of the rule. The idiom that
would produce noise is the read-loop `while ((line = reader.readLine()) != null)`,
which is deliberate and ubiquitous. There the assignment is a *grandchild* of the
condition — it sits under a `binary_expression` — so constraining the
`assignment_expression` to a direct child of `parenthesized_expression` excludes
it structurally rather than by a heuristic. Verified above. Java also requires the
condition to be `boolean`, so `if (i = 0)` does not even compile, which drives the
base rate lower than in C.

**Disposition.** Expressible.

---

## 9. `reliability.java.control-flow-in-finally`

**Pitfall.** A `finally` block returns, throws, breaks or continues, discarding
whatever the `try` or `catch` was returning or throwing.

**Concept source.** error-prone — `Finally` (Apache-2.0). Concept only.

**Severity.** `warning`

```scheme
(finally_clause
  (block [(return_statement) (break_statement) (continue_statement) (throw_statement)] @report))
```

```java
// fires
class C {
  int m() {
    try { return 1; } finally { return 2; }
  }
}

// does not fire
class C {
  int m() {
    try { return 1; } finally { close(); }
  }
  void close() {}
}
```

**Expected noise.** Low. There is no idiom that abandons a pending exception on
purpose; the shape is a bug in every codebase that has it. The direct-child
constraint means a nested `finally { if (c) { return 2; } }` is missed (verified)
and a `return` inside a lambda declared in the `finally` is correctly not
reported — the first is lost recall, the second is the reason the constraint is
there.

**Disposition.** Expressible.

---

## 10. `reliability.java.equals-wrong-parameter`

**Pitfall.** A method named `equals` takes something other than `Object`, so it
overloads rather than overrides `Object.equals` and collections never call it.

**Concept source.** error-prone — `NonOverridingEquals` (Apache-2.0). Concept
only.

**Severity.** `warning`

```scheme
((method_declaration
   name: (identifier) @n
   parameters: (formal_parameters . (formal_parameter type: (_) @t) .)) @report
 (#eq? @n "equals")
 (#not-match? @t "Object$"))
```

```java
// fires
class C {
  public boolean equals(C other) {
    return true;
  }
}

// does not fire
class C {
  @Override
  public boolean equals(Object other) {
    return true;
  }
}
class D {
  public boolean equals(java.lang.Object other) {
    return true;
  }
}
```

**Expected noise.** Low. The idiom that would produce noise is a fully qualified
`equals(java.lang.Object o)`, which parses as `scoped_type_identifier` and whose
text is not `Object`; the `Object$` suffix match covers both spellings, verified
above. The remaining legitimate shape is a value class shipping a typed
`equals(MyType)` *alongside* a correct `equals(Object)` as a fast path — rare, and
still worth a reviewer's eye. Anchors hold the rule to single-parameter methods,
so a two-argument static comparator helper named `equals` is not matched.

**Disposition.** Expressible.

---

## 11. `reliability.java.catch-jvm-throwable`

**Pitfall.** A `catch` clause names `Throwable`, `Error` or
`NullPointerException`, catching failures the program cannot handle or masking a
bug that should have surfaced.

**Concept source.** Checkstyle — `IllegalCatch` (LGPL-2.1-or-later); PMD —
`AvoidCatchingThrowable` and `AvoidCatchingNPE`, both deprecated in PMD 7.18.0 in
favour of the configurable `AvoidCatchingGenericException` (PMD BSD-style with
acknowledgement clause). Concept only.

**Severity.** `warning`

```scheme
((catch_formal_parameter (catch_type (type_identifier) @report))
 (#any-of? @report "Throwable" "Error" "NullPointerException"))
```

```java
// fires
class C {
  void m() {
    try { g(); } catch (Throwable t) { h(t); }
    try { g(); } catch (NullPointerException e) { }
  }
  void g() {}
  void h(Throwable t) {}
}

// does not fire
class C {
  void m() {
    try { g(); } catch (IllegalStateException e) { h(e); }
  }
  void g() {}
  void h(Exception e) {}
}
```

**Expected noise.** Medium, and this is the item most likely to be removed on
measurement. The idiom that produces noise is the top-of-loop guard: a thread
`run()`, an executor task wrapper or a plugin host that catches `Throwable`
precisely so one bad task cannot kill the pool. That is deliberate and correct,
and the query cannot distinguish it from a swallowed `OutOfMemoryError`. Test
code has a second one — a JUnit helper catching `Throwable` around an assertion,
error-prone's own `TryFailThrowable` shape. `Exception` and `RuntimeException`
are deliberately *not* in the set: catching `Exception` at a service boundary is
normal Java and would put this rule far over budget.

**Disposition.** Expressible. Ship behind the noise measurement, not on this
document.

---

## 12. `reliability.java.finalize-override`

**Pitfall.** A class overrides `finalize()`, which has been deprecated for
removal since Java 9 and whose execution the JVM never promises.

**Concept source.** Checkstyle — `NoFinalizer` (LGPL-2.1-or-later); PMD —
`EmptyFinalizer`, `FinalizeOnlyCallsSuperFinalize` (PMD BSD-style with
acknowledgement clause). Concept only.

**Severity.** `warning`

```scheme
((method_declaration
   name: (identifier) @report
   parameters: (formal_parameters "(" . ")"))
 (#eq? @report "finalize"))
```

```java
// fires
class C {
  protected void finalize() throws Throwable {
    super.finalize();
  }
}

// does not fire
class C {
  void finalizeAll() {}
  void finalize(int n) {}
}
```

**Expected noise.** Low. The `"(" . ")"` anchor holds it to a zero-parameter
method, so an unrelated domain method `finalize(Order o)` — the plausible
false-positive idiom, since `finalize` is an ordinary English verb in
order-processing and transaction code — is excluded, verified above. What is
left is a legacy resource class that really does override the JVM hook, which is
exactly the finding.

**Disposition.** Expressible.

---

## 13. `reliability.java.empty-control-body`

**Pitfall.** A stray semicolon becomes the entire body of an `if`, `while` or
`for`, so the block that follows is unconditional.

**Concept source.** PMD — `EmptyControlStatement` (PMD BSD-style with
acknowledgement clause); Checkstyle — `EmptyStatement` (LGPL-2.1-or-later).
Concept only.

**Severity.** `warning`

```scheme
(if_statement consequence: ";" @report)
(while_statement body: ";" @report)
(for_statement body: ";" @report)
(enhanced_for_statement body: ";" @report)
```

```java
// fires
class C {
  void m(boolean c) {
    if (c);
    while (c);
  }
}

// does not fire
class C {
  void m(boolean c) {
    if (c) { g(); }
    for (int i = 0; i < 3; i++) { g(); }
  }
  void g() {}
}
```

**Expected noise.** Low. `;` is an anonymous token in the grammar's `statement`
choice and is capturable directly, so the rule matches the exact typo and
nothing near it. The one idiom that would report is a deliberate spin-wait —
`while (!done);` in lock-free code — which is rare in Java and is itself worth a
comment. An empty *block* body `if (c) {}` is a different node and is not
matched here; that shape is `maintainability.java.empty-method-body`'s
neighbourhood and was already rejected on noise in 2.1.

**Disposition.** Expressible.

---

## 14. `maintainability.java.redundant-wrapper-instantiation`

**Pitfall.** `new String("literal")` allocates a second copy of an interned
constant, and `new Integer(3)` and its siblings call constructors deprecated for
removal since Java 9.

**Concept source.** PMD — `UnnecessaryBoxing` (PMD BSD-style with
acknowledgement clause); Checkstyle — `IllegalInstantiation`
(LGPL-2.1-or-later). Concept only.

**Severity.** `info`

```scheme
((object_creation_expression
   type: (type_identifier) @t
   arguments: (argument_list . (string_literal) .)) @report
 (#eq? @t "String"))
((object_creation_expression type: (type_identifier) @t) @report
 (#any-of? @t "Integer" "Long" "Short" "Byte" "Character" "Boolean" "Double" "Float"))
```

```java
// fires
class C {
  Object a = new String("x");
  Object b = new Integer(3);
  Object c = new Boolean(true);
}

// does not fire
import java.nio.charset.StandardCharsets;
class C {
  Object a = new String(bytes(), StandardCharsets.UTF_8);
  Object b = Integer.valueOf(3);
  Object c = new StringBuilder("x");
  byte[] bytes() { return new byte[0]; }
}
```

**Expected noise.** Low. The idiom that would produce noise is
`new String(bytes, charset)` — the standard, correct way to decode bytes — and
the single-`string_literal` anchor excludes it, verified above; the same anchor
excludes `new String(charArray)`. The boxed-constructor half fires on pre-Java-9
code that predates `valueOf`, which is a real cost signal and the reason the
severity is `info` rather than `warning`. The engine de-duplicates on
`(rule id, start, end)`, so the two patterns cannot double-report the same node.

**Disposition.** Expressible.

---

## 15. `maintainability.java.boolean-literal-redundancy`

**Pitfall.** A boolean is compared to a boolean literal, or a ternary yields
`true` and `false`, restating a value that already is the answer.

**Concept source.** Checkstyle — `SimplifyBooleanExpression`
(LGPL-2.1-or-later); error-prone — `BooleanLiteral` (Apache-2.0). Concept only.

**Severity.** `info`

```scheme
(binary_expression operator: ["==" "!="] right: [(true) (false)]) @report
(binary_expression left: [(true) (false)] operator: ["==" "!="]) @report
(ternary_expression
  consequence: [(true) (false)]
  alternative: [(true) (false)]) @report
```

```java
// fires
class C {
  boolean a(boolean x) { return x == true; }
  boolean b(boolean x) { return false != x; }
  boolean c(boolean x) { return x ? true : false; }
}

// does not fire
class C {
  boolean a(boolean x) { return x; }
  boolean b(boolean x) { return !x; }
  int c(boolean x) { return x ? 1 : 0; }
  boolean d(Boolean x) { return Boolean.TRUE.equals(x); }
}
```

**Expected noise.** Low. The idiom that would produce noise is the null-safe
`Boolean.TRUE.equals(x)` and its `x == Boolean.TRUE` cousin; both are
`field_access`, not the `(true)` literal node, so neither is matched, verified
above. Note the child-order requirement: the second pattern must write `left:`
before `operator:` or it is an impossible pattern and fails to compile.

**Disposition.** Expressible.

---

## 16. `maintainability.java.catch-rethrow`

**Pitfall.** A `catch` block does nothing but rethrow the exception it caught,
so the whole clause is dead weight.

**Concept source.** PMD — `AvoidRethrowingException` (PMD BSD-style with
acknowledgement clause). Concept only.

**Severity.** `info`

```scheme
((catch_clause
   (catch_formal_parameter name: (identifier) @n)
   body: (block . (throw_statement (identifier) @t) .)) @report
 (#eq? @n @t))
```

```java
// fires
class C {
  void m() throws Exception {
    try { g(); } catch (Exception e) { throw e; }
  }
  void g() throws Exception {}
}

// does not fire
class C {
  void m() {
    try { g(); } catch (Exception e) { throw new RuntimeException(e); }
  }
  void n() throws Exception {
    try { g(); } catch (Exception e) { log(e); throw e; }
  }
  void g() throws Exception {}
  void log(Exception e) {}
}
```

**Expected noise.** Low, and `info` for the residue. The idiom that would produce
noise is Java 7 *precise rethrow*: `catch (Exception e) { throw e; }` where the
enclosing `throws` clause lists the narrower checked types the compiler inferred,
which is a deliberate and correct way to narrow a signature. Nothing in a query
can see that inference, so those hits are real noise — hence `info` and not
`warning`. Log-then-rethrow is excluded by the anchors holding the body to a
single statement, verified above.

**Disposition.** Expressible.

---

## 17. `maintainability.java.parameter-reassigned`

**Pitfall.** A method assigns to its own formal parameter, so the name no longer
means what the signature says.

**Concept source.** PMD — `AvoidReassigningParameters` (PMD BSD-style with
acknowledgement clause); Checkstyle — `ParameterAssignment` (LGPL-2.1-or-later).
Concept only.

**Severity.** `info`

```scheme
((method_declaration
   parameters: (formal_parameters (formal_parameter name: (identifier) @p))
   body: (block (expression_statement (assignment_expression left: (identifier) @l)))) @report
 (#eq? @p @l))
```

```java
// fires
class C {
  int m(int a) {
    a = a + 1;
    return a;
  }
}

// does not fire
class C {
  int m(int a) {
    int b = a;
    b = b + 1;
    return b;
  }
}
```

**Expected noise.** Medium. The idiom is parameter normalisation at the top of a
method — `s = s.trim();`, `if (x == null) x = DEFAULT;` — which is common,
intentional and indistinguishable from an accidental clobber. The first form
reports; the second does not, only because it is nested one block deeper.

**Disposition.** **Needs primitive.** The query above matches only when the
assignment is a *direct child* of the method body block; an assignment inside an
`if` or a `for` is missed, verified. tree-sitter's query language has no
descendant operator, so "an assignment to `@p` anywhere under this method" cannot
be written. It needs **P2 — descendant matching within a bound ancestor**: the
ability to match a subpattern at arbitrary depth inside the ancestor that bound
the comparison capture. Note that the primitive raises recall and therefore
raises noise: the full-recall version would catch every normalisation idiom, so
this rule should be measured *after* the primitive lands, not before.

---

## 18. `reliability.java.equals-without-hashcode`

**Pitfall.** A class overrides `equals` but not `hashCode` (or the reverse), so
its instances misbehave in every hash-based collection.

**Concept source.** error-prone — `EqualsHashCode` (Apache-2.0); Checkstyle —
`EqualsHashCode` (LGPL-2.1-or-later). Concept only.

**Severity.** `warning`

**Query.** None exists. The rule is a statement about what a class body *lacks*,
and the query language has no negation: there is no way to write "a
`class_body` containing a `method_declaration` named `equals` and no
`method_declaration` named `hashCode`". Matching the positive half alone would
report every correctly written value class in the repository.

```java
// would fire
class C {
  @Override public boolean equals(Object o) { return o == this; }
}

// would not fire
class C {
  @Override public boolean equals(Object o) { return o == this; }
  @Override public int hashCode() { return 1; }
}
```

**Expected noise.** Not measurable without the query. The idiom that would make
a naive positive-only query useless is the ordinary value class that overrides
both methods correctly — the overwhelming majority of every `equals` in any real
tree.

**Disposition.** **Needs primitive.** **P1 — sibling-absence predicate**: a
negated subpattern scoped to one node's children, so a pattern can assert that a
named node's direct children contain *no* match for a given subpattern. Single
file, bounded to one node's child list, no dataflow — inside the #103 boundary.

---

## 19. `maintainability.java.switch-without-default`

**Pitfall.** A `switch` statement has no `default` label, so an unhandled value
falls through silently.

**Concept source.** Checkstyle — `MissingSwitchDefault` (LGPL-2.1-or-later).
Concept only.

**Severity.** `info`

**Query.** None exists, for the same reason as item 18: `switch_block` would
have to be asserted to contain no `switch_label` spelling `default`, and the
query language cannot express absence.

```java
// would fire
class C {
  int m(int x) {
    switch (x) {
      case 1: return 1;
      case 2: return 2;
    }
    return 0;
  }
}

// would not fire
class C {
  int m(int x) {
    switch (x) {
      case 1: return 1;
      default: return 0;
    }
  }
}
```

**Expected noise.** The idiom that would produce noise once the primitive exists
is the exhaustive `switch` over an `enum` or a sealed hierarchy, where javac
itself proves every case is covered and a `default` would be dead code. Java 21
pattern switches make that shape common. `info` at most, and it may still fail
the 1.0 per kLOC budget.

**Disposition.** **Needs primitive.** The same **P1 — sibling-absence
predicate** as item 18.

---

## 20. `reliability.java.reference-equality`

**Pitfall.** `==` compares two object references where `equals` was meant —
boxed `Integer` above the cache range, an enum-adjacent wrapper, a `BigDecimal`.

**Concept source.** PMD — `CompareObjectsWithEquals` (PMD BSD-style with
acknowledgement clause); error-prone — `ReferenceEquality` (Apache-2.0). Concept
only.

**Severity.** `warning`

**Query.** None is possible. `a == b` is correct for primitives, for enum
constants and for deliberate identity checks, and wrong for boxed types and most
objects. Nothing in the syntax says which `a` is: it needs the declared type of
both operands, which means resolving imports and the classpath. That is
type-aware analysis, explicitly out of scope in #103.

```java
// would need to fire
class C {
  boolean m(Integer a, Integer b) { return a == b; }
}

// would need to stay silent
class C {
  boolean m(int a, int b) { return a == b; }
}
```

The decidable subsets are already shipped:
`reliability.java.string-literal-identity` catches `==` against a string literal,
and `reliability.java.self-comparison` catches `a == a`. No further subset is
decidable from one file's syntax.

**Expected noise.** Any type-free approximation — flagging `==` where either
operand is a capitalised identifier, say — reports every `x == null`, every enum
comparison and every intentional identity check. That idiom set is most of the
`==` in any Java tree.

**Disposition.** **Inexpressible.**

---

## Primitives

Two, both single-file and both bounded. #103 allows one engine addition when at
least three candidates across two languages need the same primitive; Java alone
does not reach that bar for either, so both need corroboration from the sibling
pitfall lists before either becomes a package.

### P1 — sibling-absence predicate

*A negated subpattern scoped to one node's direct children:* a pattern may assert
that a matched node has **no** child matching a given subpattern. No dataflow, no
second file, no type information; the match is decided from one node's child
list.

| Item | Rule |
| --- | --- |
| 18 | `reliability.java.equals-without-hashcode` |
| 19 | `maintainability.java.switch-without-default` |

Two Java candidates. Every language with a `switch` has item 19's shape, and the
"declares X but not the required companion Y" family is not Java-specific, so
corroboration is likely; it is not established here.

### P2 — descendant matching within a bound ancestor

*A subpattern matched at arbitrary depth inside the ancestor that bound the
comparison capture*, rather than at a fixed child depth. tree-sitter's query
language has no descendant operator, which is what forces items 2, 9 and 17 to be
direct-child rules.

| Item | Rule | What it buys |
| --- | --- | --- |
| 17 | `maintainability.java.parameter-reassigned` | the rule at all, rather than the direct-body slice |
| 2 | `reliability.java.unreachable-after-return` | unreachable code one block deeper |
| 9 | `reliability.java.control-flow-in-finally` | `finally { if (c) return; }` |

Three Java candidates, but only item 17 is *blocked*: items 2 and 9 ship without
it at reduced recall. P2 also raises noise wherever it raises recall, so a rule
that needs it must be measured after it lands, not before.

## Rules deliberately not proposed

| Shape | Why not |
| --- | --- |
| `hashCode` / `compareTo` / `clone` contract violations beyond item 18 | Same absence problem as P1, and most also need the supertype. |
| String concatenation in a loop | Requires knowing the `+` operand is a `String` and that the statement is loop-carried. Types plus dataflow. |
| `Optional.get()` without `isPresent()` | Flow-sensitive across statements. |
| Ignored return value of a pure method (`s.trim();` as a statement) | Approximable only with a hardcoded method-name list, which fires on every user-defined `replace` or `trim` that does mutate. Fails the near-zero-false-positive bar by construction. |
| Missing `@Override` | Requires the supertype's method set. |
| Unused private field or method | Requires counting references across the whole file with scope awareness; beyond both primitives. |
| Switch fallthrough | Already ruled out for C/C++/C# in the 2.1 matrix on the same grounds: intentional fallthrough is marked by a comment the query cannot read, and grouped empty cases are the common legitimate form. |
| `synchronized` on a non-final field | Needs the field's declaration and its modifiers from elsewhere in the file, with scope resolution. |
| Raw exception types in `throw` (PMD `AvoidThrowingRawExceptionTypes`) | `throw new RuntimeException(e)` wrapping a checked exception is the standard Java idiom and would dominate the findings. |
| `System.out.println`, `printStackTrace`, empty method body | Already in the 2.1 matrix, already rejected on noise. Nothing here changes their failure mode. |
| Magic numbers, duplicate code | Ruled out in the 2.1 matrix; unchanged. |

## Sources

- [PMD Java rules — Error Prone](https://pmd.github.io/pmd/pmd_rules_java_errorprone.html)
- [PMD Java rules — Design](https://pmd.github.io/pmd/pmd_rules_java_design.html)
- [PMD Java rules — Code Style](https://pmd.github.io/pmd/pmd_rules_java_codestyle.html)
- [PMD Java rules — Best Practices](https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html)
- [error-prone bug patterns](https://errorprone.info/bugpatterns)
- [Checkstyle coding checks](https://checkstyle.org/checks/coding/index.html)
- [SonarSource RSPEC-1862](https://rules.sonarsource.com/csharp/RSPEC-1862/)
- `tree-sitter-java` 0.23.5 `src/node-types.json` and `grammar.js`, read from the
  local cargo registry.
