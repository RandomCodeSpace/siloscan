# Go pitfall list

Research for issue #105, under the map #103. This document decides *what the Go
pitfalls are* and whether each one fits the engine boundary. It writes no rule
YAML and no engine code.

Every `concept_source` below is concept-only. No pattern text, query text or
message text was taken from any upstream project; each entry names a rule so a
reader can find the idea, and nothing else was carried across.

## What was verified, and how

Grammar: `tree-sitter-go` 0.25.0, the version pinned in
`crates/siloscan-core/Cargo.toml`, under `tree-sitter` 0.26.11.

Every query below was loaded as a one-rule profile document through
`rules::load_str` and run over positive and negative snippets through
`scan::scan` — the product's own path, the same one `plan::resolve` takes — using
a throwaway test modelled on the in-test document pattern in
`crates/siloscan-core/tests/profile_corpus.rs`. The test is not committed. A
query that "compiles" is one the loader accepted; a query that "fires" reported a
finding on the positive snippet and none on the negative.

Noise was then measured for real, not estimated, by scanning three Go
repositories at pinned tags with the whole candidate set at once:

| Repository | Tag | Commit | Licence | Go lines |
| --- | --- | --- | --- | --- |
| spf13/cobra | v1.10.2 | 88b30ab89da2d0d0abb153818746c5a2d30eccec | Apache-2.0 | 12551 |
| gin-gonic/gin | v1.12.0 | 73726dc606796a025971fe451f0aa6f1b9b847f6 | MIT | 18076 |
| prometheus/client_golang | v1.23.2 | 8179a560819f2c64ef6ade70e6ae4c73aecaca3c | Apache-2.0 | 30968 |

The first two are the pinned Go noise set from `research/embedded-profiles/noise-set.md`.
The third is not pinned; it was added here because the map flags that "a Go
error-handling rule needs repositories heavy in error handling" and the pinned
set has only two Go rows. Go lines are non-blank, non-comment-only lines counted
by the harness, which is close to but not identical with the code-line
denominator `scripts/profile_noise.py` uses — treat the per-kLOC figures below as
indicative, and re-measure through the shipped script at implementation time.

Gates, from the map: `warning` at or below 0.25 findings per kLOC, `info` at or
below 1.0, on any pinned repository; zero corpus false positives; removal, not
tuning.

## Item table

| # | id | severity | disposition | measured noise (cobra / gin / client_golang, per kLOC) |
| --- | --- | --- | --- | --- |
| 1 | `reliability.go.unreachable-after-return` | warning | expressible | 0 / 0 / 0 |
| 2 | `reliability.go.self-comparison-ordering` | warning | expressible | 0 / 0 / 0 |
| 3 | `reliability.go.self-boolean-operand` | warning | expressible | 0 / 0 / 0 |
| 4 | `reliability.go.self-assignment-field` | warning | expressible | 0 / 0 / 0 |
| 5 | `reliability.go.duplicate-switch-case` | warning | expressible | 0 / 0 / 0 |
| 6 | `reliability.go.duplicate-else-if-condition` | warning | expressible | 0 / 0 / 0 |
| 7 | `reliability.go.error-string-comparison` | warning | expressible | 0 / 0 / 0.0646 |
| 8 | `reliability.go.empty-error-branch` | warning | expressible | 0 / 0 / 0 |
| 9 | `reliability.go.redundant-boolean-comparison` | info | expressible | 0.0797 / 0.0553 / 0 |
| 10 | `reliability.go.errors-new-sprintf` | info | expressible | 0 / 0 / 0 |
| 11 | `maintainability.go.struct-tag-malformed` | info | expressible | 0 / 0 / 0 |
| 12 | `maintainability.go.naked-return` | info | expressible, noise-rejected | 0.1593 / **1.4937** / 0.1937 |
| 13 | `maintainability.go.empty-interface-type` | info | expressible, noise-rejected | **1.5935** / 0 / **4.2302** |
| 14 | `reliability.go.unchecked-type-assertion` | warning | needs primitive (enclosing-node predicate) | **0.2390** / 0.2213 / **1.0979** |
| 15 | `reliability.go.defer-in-nested-block` | warning | needs primitive (descendant-scope constraint) | no query |
| 16 | `reliability.go.testing-goroutine-fatal` | warning | needs primitive (descendant-scope constraint) | 0 / 0 / 0, at one nesting level only |
| 17 | `reliability.go.math-rand-for-token` | warning | needs primitive (file-scoped import binding) | 0 / 0.1660 / **0.3229** |
| 18 | `reliability.go.printf-verb-arity` | warning | needs primitive (format-arity predicate) | no query |
| 19 | `reliability.go.loop-var-capture` | warning | inexpressible | no query |
| 20 | `reliability.go.mutex-value-copy` | warning | inexpressible | no query |

Bold marks a figure over that severity's gate. Items 1–11 are the ship list:
eleven rules, all measured at zero or near zero over 61595 lines of Go.

---

## 1. `reliability.go.unreachable-after-return`

**Pitfall.** A statement follows a `return` in the same block, so it can never
run.

**Concept source.** golang/go `cmd/vet` — `unreachable`, "check for unreachable
code" (BSD-3-Clause). Concept only; no text taken.

**Severity.** `warning`.

**Status.** This is a 2.1 removal returning. #89 records it as "gone from every
language (trailing comments, not dead code)", and the failure mode reproduces
exactly: the 2.1 query anchored a bare wildcard after the return, and a Go
comment is a named sibling inside `statement_list`, so a trailing line comment
matched. On client_golang the wildcard form reports five findings, every one of
them a comment — `return // No limit configured.` in `prometheus/histogram.go`
is the shape — and one more in cobra's `command.go`, also a comment.

**Query.** The fix is not a primitive. `tree-sitter-go` declares `_statement` as
a supertype (`grammar.json` `supertypes`: `_expression`, `_type`,
`_simple_type`, `_statement`, `_simple_statement`), so the pattern can demand a
statement instead of any node:

```scheme
(statement_list (return_statement) . (_statement) @report)
```

Verified: fires on the positive, silent on the negative, and **zero findings
across all three repositories** where the wildcard form produced six, all false.

**Examples.**

```go
// fires
package p

func f(c bool) int {
	if c {
		return 1
		println(2)
	}
	return 0
}

// does not fire
package p

func f(c bool) int {
	if c {
		return 1
		// the branch above is the fast path
	}
	return 0
}
```

**Expected noise.** The idiom that produced the 2.1 removal is the trailing
comment — a `return` with an explanatory `//` comment after it, either on the
same line or on the next. The supertype form cannot match a comment at all, so
the idiom is gone by construction rather than by tuning.

**Disposition: expressible.** One caveat, measured: the anchor `.` does not skip
comments, so dead code *separated from the return by a comment* is missed. A
comment-skipping anchor primitive would recover it; that is one candidate in one
language, well under the map's three-across-two bar, and not worth building. The
recall loss is the right trade for six fewer false positives.

---

## 2. `reliability.go.self-comparison-ordering`

**Pitfall.** Both operands of an ordering or inequality comparison are the same
identifier, so the result is a constant.

**Concept source.** go-tools (staticcheck) — `SA4000`, "Binary operator has
identical expressions on both sides" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query.**

```scheme
((binary_expression left: (identifier) @l operator: "<" right: (identifier) @r) @report (#eq? @l @r))
((binary_expression left: (identifier) @l operator: ">" right: (identifier) @r) @report (#eq? @l @r))
((binary_expression left: (identifier) @l operator: "<=" right: (identifier) @r) @report (#eq? @l @r))
((binary_expression left: (identifier) @l operator: ">=" right: (identifier) @r) @report (#eq? @l @r))
((binary_expression left: (identifier) @l operator: "!=" right: (identifier) @r) @report (#eq? @l @r))
```

**Examples.**

```go
// fires
package p

func f(a int) bool {
	return a < a
}

// does not fire
package p

func f(a, b int) bool {
	return a < b
}
```

**Expected noise.** None found. The one Go idiom that would justify comparing a
value with itself is the NaN check, and Go spells that `math.IsNaN`, not
`x != x`. Zero findings on 61595 lines.

**Disposition: expressible.** This widens the shipped
`reliability.go.self-comparison`, which pins `operator: "=="`, to the other five
comparison operators. It is a separate id so it can be measured and retired on
its own; folding the operators into the shipped rule would change nothing about
the queries but would move an already-measured rule's noise number.

---

## 3. `reliability.go.self-boolean-operand`

**Pitfall.** Both operands of `&&` or `||` are the same identifier, so the
operator decides nothing.

**Concept source.** go-critic — `dupSubExpr`, "Detects suspicious duplicated
sub-expressions" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query.**

```scheme
((binary_expression left: (identifier) @l operator: "&&" right: (identifier) @r) @report (#eq? @l @r))
((binary_expression left: (identifier) @l operator: "||" right: (identifier) @r) @report (#eq? @l @r))
```

**Examples.**

```go
// fires
package p

func f(a bool) bool {
	return a && a
}

// does not fire
package p

func f(a, b bool) bool {
	return a && b
}
```

**Expected noise.** None found. Restricting both sides to bare identifiers keeps
out the one shape that could be deliberate — a repeated call with side effects,
which is a `call_expression` and not matched. Zero findings on 61595 lines.

**Disposition: expressible.**

---

## 4. `reliability.go.self-assignment-field`

**Pitfall.** A struct field or package-qualified variable is assigned to itself.

**Concept source.** go-tools (staticcheck) — `SA4018`, "Self-assignment of
variables" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query.**

```scheme
((assignment_statement left: (expression_list . (selector_expression) @l .) operator: "=" right: (expression_list . (selector_expression) @r .)) @report (#eq? @l @r))
```

**Examples.**

```go
// fires
package p

type T struct{ a int }

func f(t *T) {
	t.a = t.a
}

// does not fire
package p

type T struct{ a, b int }

func f(t *T) {
	t.a = t.b
}
```

**Expected noise.** None found. The idiom that would produce noise is a
self-assignment used to force a copy or to silence an unused-variable warning;
Go has neither — the compiler's unused check is on declarations, and a struct
copy is written `*dst = *src`, which is a `unary_expression` and not matched.
Zero findings on 61595 lines.

**Disposition: expressible.** This extends the shipped
`reliability.go.self-assignment`, which matches bare identifiers only, to
selector targets. Separate id, same argument as item 2.

---

## 5. `reliability.go.duplicate-switch-case`

**Pitfall.** Two `case` clauses in one expression switch list the same values, so
the second is dead.

**Concept source.** go-critic — `dupCase`, "Detects duplicated case clauses
inside switch or select statements" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query.** Two unanchored sibling `expression_case` children of one switch, with
the text predicate over their value lists:

```scheme
((expression_switch_statement (expression_case value: (expression_list) @a) (expression_case value: (expression_list) @b)) @report (#eq? @a @b))
```

The two child slots bind distinct siblings — verified against a switch with
three distinct cases, which does not fire, so the pattern does not pair a case
with itself. Duplicates that are not adjacent are caught, and `case 1, 2:`
duplicated as a whole list is caught, because the comparison is over the whole
`expression_list`.

**Examples.**

```go
// fires
package p

func f(n int) int {
	switch n {
	case 1, 2:
		return 10
	case 3:
		return 20
	case 1, 2:
		return 30
	}
	return 0
}

// does not fire
package p

func f(n int) int {
	switch n {
	case 1, 2:
		return 10
	case 3:
		return 20
	case 4:
		return 30
	}
	return 0
}
```

**Expected noise.** None found. The near-miss idiom is a switch on a value whose
cases are named constants from different packages that happen to share a
spelling — `a.Open` and `b.Open` — but those are `selector_expression` texts and
differ. A partially overlapping list, `case 1, 2:` then `case 2, 3:`, is a real
bug this rule misses; it is not a false positive. Zero findings on 61595 lines.

**Disposition: expressible.**

---

## 6. `reliability.go.duplicate-else-if-condition`

**Pitfall.** An `if` and the `else if` directly after it test the same condition,
so the second branch is unreachable.

**Concept source.** SonarSource — `S1862`, "Related 'if/else-if' statements
should not have the same condition" (SONAR Source-Available License v1.0;
non-OSI). Concept only; no text taken. Cited the same way the 2.1 matrix cites
`S1871`.

**Severity.** `warning`.

**Query.**

```scheme
((if_statement !initializer condition: (_) @c1 alternative: (if_statement !initializer condition: (_) @c2)) @report (#eq? @c1 @c2))
```

The `!initializer` negations are load-bearing and were added on measurement. Without
them the rule reported four false positives in gin's `binding/form_mapping.go`
(0.2213 per kLOC, under the gate but wrong), on this shape:

```go
if ok, err = trySetUsingParser(vs[0], value, opt.parser); ok {
	return ok, err
} else if ok, err = trySetCustom(vs[0], value); ok {
	return ok, err
}
```

Both conditions are the bare identifier `ok`; the initializers differ, and they
are what decides the branch. Requiring both `if`s to have no initializer removes
the shape. With the negations the rule reports **zero** on all three
repositories.

**Examples.**

```go
// fires
package p

func f(n int) int {
	if n > 0 {
		return 1
	} else if n > 0 {
		return 2
	}
	return 0
}

// does not fire
package p

func try(a int) (bool, error) { return a > 0, nil }

func f(a int) (bool, error) {
	var ok bool
	var err error
	if ok, err = try(a); ok {
		return ok, err
	} else if ok, err = try(a + 1); ok {
		return ok, err
	}
	return false, nil
}
```

**Expected noise.** The idiom is exactly the one above: `if init; cond` chains
where the condition is a reused result variable. Excluded structurally.

**Disposition: expressible.** One recall limit, measured: the pattern compares
adjacent links only, so `if A / else if B / else if A` is missed. A second
pattern with an extra `alternative:` level catches distance two, and so on; each
extra rung is a fixed-depth pattern, not a general solution. Ship the adjacent
form — a duplicated condition two rungs apart is rare, and the alternative is an
unbounded pattern list.

---

## 7. `reliability.go.error-string-comparison`

**Pitfall.** An error is classified by comparing `err.Error()` with a string
literal, which breaks the moment the message is reworded.

**Concept source.** golang/go — the `errors` package's `Is`/`As` contract and the
Go 1.13 error-values guidance (BSD-3-Clause); go-err113 as a second reference
(MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query.**

```scheme
((binary_expression left: (call_expression function: (selector_expression field: (field_identifier) @m) arguments: (argument_list)) operator: "==" right: (interpreted_string_literal)) @report (#eq? @m "Error"))
((binary_expression left: (call_expression function: (selector_expression field: (field_identifier) @m) arguments: (argument_list)) operator: "!=" right: (interpreted_string_literal)) @report (#eq? @m "Error"))
```

**Examples.**

```go
// fires
package p

func f(err error) bool {
	return err.Error() == "not found"
}

// does not fire
package p

import "strings"

func f(err, other error) bool {
	return err.Error() == other.Error() || strings.Contains(err.Error(), "not found")
}
```

**Expected noise.** The idiom is the assertion in a test — "this call returned
exactly this message" — and that is where both client_golang findings are
(`prometheus/vec_test.go`, 0.0646 per kLOC). Both are true positives of the
pitfall: they are brittle in the way the rule says. Comparing two `Error()`
calls, and `strings.Contains` over a message, are both excluded by requiring a
string literal on the right.

**Disposition: expressible.** If the test idiom pushes a repository over 0.25,
the map allows one `paths` exclusion before removal, and `_test.go` is the
obvious one — but it was not needed on any of the three.

---

## 8. `reliability.go.empty-error-branch`

**Pitfall.** `if err != nil` guards an empty block, so the error is detected and
then dropped.

**Concept source.** go-tools (staticcheck) — `SA9003`, "Empty body in an if or
else branch" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query.**

```scheme
((if_statement condition: (binary_expression left: (identifier) @e operator: "!=" right: (nil)) consequence: (block "{" . "}")) @report (#eq? @e "err"))
```

Narrowing to the conventional name `err` is deliberate: `SA9003` on all empty
branches is the general rule, and the general rule is the noisy one. This is the
half that is always a mistake.

**Examples.**

```go
// fires
package p

func f(err error) {
	if err != nil {
	}
}

// does not fire
package p

func f(err error) {
	if err != nil {
		// best effort: the caller cannot act on this
	}
}
```

**Expected noise.** The idiom is the deliberate swallow with a comment saying
why — "best effort", "already logged upstream". A comment is a child of the
block, so `"{" . "}"` does not match and the documented swallow is silent while
the undocumented one reports. That is the right split. Zero findings on 61595
lines.

**Disposition: expressible.**

---

## 9. `reliability.go.redundant-boolean-comparison`

**Pitfall.** A boolean expression is compared with `true` or `false` instead of
being used directly.

**Concept source.** go-tools (staticcheck) — `S1002`, "Omit comparison with
boolean constant" (MIT). Concept only; no text taken.

**Severity.** `info`.

**Query.** `true` and `false` are named nodes in this grammar, not identifiers,
so the operand can be matched by kind:

```scheme
((binary_expression operator: "==" right: (true)) @report)
((binary_expression operator: "==" right: (false)) @report)
((binary_expression operator: "!=" right: (true)) @report)
((binary_expression operator: "!=" right: (false)) @report)
```

**Examples.**

```go
// fires
package p

func f(m map[string]bool) bool {
	return m["k"] == true
}

// does not fire
package p

func f(ok bool, m map[string]bool) bool {
	if v, found := m["k"]; found {
		return v
	}
	return ok
}
```

**Expected noise.** The idiom that looks like noise is the map-membership test
`if m[k] == true`, where the author means "present and true" — but in Go that is
what `m[k]` alone already means, and the two-value form is the correct spelling,
so the finding is right. Both real-world hits (cobra `completions_test.go`,
`compCmd.Hidden == false`; gin `tree_test.go`, `value.tsr != true`) are true
positives. 0.0797 and 0.0553 per kLOC, far under the 1.0 info gate.

**Disposition: expressible.**

---

## 10. `reliability.go.errors-new-sprintf`

**Pitfall.** `errors.New(fmt.Sprintf(...))` where `fmt.Errorf` is the one call
that does the job.

**Concept source.** go-tools (staticcheck) — `S1028`, "Simplify error
construction with `fmt.Errorf`" (MIT). Concept only; no text taken.

**Severity.** `info`.

**Query.**

```scheme
((call_expression function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn) arguments: (argument_list . (call_expression function: (selector_expression operand: (identifier) @p2 field: (field_identifier) @f2)) .)) @report (#eq? @pkg "errors") (#eq? @fn "New") (#eq? @p2 "fmt") (#eq? @f2 "Sprintf"))
```

**Examples.**

```go
// fires
package p

import (
	"errors"
	"fmt"
)

func f(n int) error {
	return errors.New(fmt.Sprintf("bad %d", n))
}

// does not fire
package p

import "fmt"

func f(n int) error {
	return fmt.Errorf("bad %d", n)
}
```

**Expected noise.** The idiom that could produce a wrong reading is a local
package aliased to the name `errors` or `fmt` whose `New`/`Sprintf` mean
something else. That is the general weakness the import-binding primitive
(item 17) exists for; here it is harmless, because a package that shadows
`errors.New` and takes a `fmt.Sprintf` result still reads better as
`fmt.Errorf`. Zero findings on 61595 lines.

**Disposition: expressible.**

---

## 11. `maintainability.go.struct-tag-malformed`

**Pitfall.** A struct tag is not in `key:"value"` form, so `reflect.StructTag.Get`
silently returns nothing and the encoder ignores the field.

**Concept source.** golang/go `cmd/vet` — `structtag`, "check that struct field
tags conform to reflect.StructTag.Get" (BSD-3-Clause). Concept only; no text
taken.

**Severity.** `info`.

**Query.** The reliable form is a whole-tag shape check with `#not-match?`, not a
search for a broken key:

```scheme
((field_declaration tag: (raw_string_literal) @report) (#not-match? @report "^`(\\s*[A-Za-z0-9_.-]+:\"[^\"]*\")*\\s*`$"))
```

The obvious first attempt — `#match?` for `key:` followed by a non-quote — was
written, measured, and thrown away: it reported four false positives in gin's
`context_test.go` because a *value* can contain a colon, and
`time_format:"02/01/2006 15:04"` contains ` 15:04`. Anchoring the key to a
preceding space does not help, since the value contains a space too. Matching
the whole tag against the well-formed shape and reporting the complement has no
such hole, and reports **zero** on all three repositories.

**Examples.**

```go
// fires
package p

type T struct {
	Name string `json:"name" xml:name`
}

// does not fire
package p

import "time"

type T struct {
	Bar          string    `form:"bar"`
	TimeUTC      time.Time `form:"time_utc" time_format:"02/01/2006 15:04" time_utc:"1"`
	Opt          string    `json:"opt,omitempty" validate:"required,min=1"`
	Dashed       string    `protobuf:"bytes,1,opt,name=a,json=b,proto3" json:"a,omitempty"`
	Plain        string
	Empty        string ``
}
```

**Expected noise.** The idiom is the multi-key tag with punctuation-heavy values
— protobuf tags, time layouts, validator expressions — which is exactly what the
first query broke on and what the shape check handles. Space after the colon
(`json: "name"`) is reported, and correctly: `reflect.StructTag.Get` does not
accept it.

**Disposition: expressible.**

---

## 12. `maintainability.go.naked-return`

**Pitfall.** A function with named results returns without naming them, so the
reader has to scan the body to learn what is returned.

**Concept source.** nakedret (alexkohler/nakedret) — MIT; and the Go project's
Code Review Comments, "Naked Returns" (BSD-3-Clause). Concept only; no text
taken.

**Severity.** `info`.

**Query.** Verified and clean. `return_statement` carries the `return` keyword as
its only token when there is no value, so anchoring after it is the "empty
return" test:

```scheme
((function_declaration result: (parameter_list (parameter_declaration name: (identifier))) body: (block (statement_list (return_statement "return" .) @report))))
((method_declaration result: (parameter_list (parameter_declaration name: (identifier))) body: (block (statement_list (return_statement "return" .) @report))))
```

Requiring a named result excludes the bare `return` in a `func()` with no
results, which is not the pitfall.

**Examples.**

```go
// fires
package p

func f(a int) (n int, err error) {
	n = a
	return
}

// does not fire
package p

func f(a int) (int, error) {
	return a, nil
}

func g(a int) {
	if a < 0 {
		return
	}
	println(a)
}
```

**Expected noise.** The idiom is the short helper with named results used as
documentation — `func (c *Context) Get(key string) (value any, exists bool)` —
where the naked return is idiomatic and the function is four lines long. gin
writes its whole `context.go` this way: 27 findings, **1.4937 per kLOC**, over
the 1.0 info gate, and reading them shows every one is deliberate and correct.
The gate cannot be met by a `paths` exclusion, because the findings are in the
package's core file, not in tests.

**Disposition: expressible, do not ship.** The query is correct; the pitfall is
not one a Go reviewer flags on sight, and the measurement says so. Naked returns
only become a problem in long functions, and "long" is
`maintainability.go.function-length`, which already ships. Removal, not tuning,
per the map.

---

## 13. `maintainability.go.empty-interface-type`

**Pitfall.** `interface{}` is written where `any` — its alias since Go 1.18 — is
the current spelling.

**Concept source.** golang/go — the Go 1.18 release notes' `any` alias
(BSD-3-Clause); revive `use-any` as a second reference (MIT). Concept only; no
text taken.

**Severity.** `info`.

**Query.** Restricting to the empty interface is necessary; `(interface_type)`
alone matches every named interface declaration in the file:

```scheme
((interface_type "{" . "}") @report)
```

**Examples.**

```go
// fires
package p

func f(x interface{}) {}

// does not fire
package p

type Reader interface {
	Read(p []byte) (int, error)
}

func f(r Reader, x any) {}
```

**Expected noise.** The idiom is a codebase that predates Go 1.18 or that
supports an older toolchain, where `interface{}` is the only spelling available
— and a generated file, which nobody rewrites. cobra reports 1.5935 per kLOC and
client_golang 4.2302, the latter concentrated in `api_test.go` and generated
`.pb.go` files. gin, which migrated to `any`, reports zero. Both breaching
figures are over the 1.0 info gate.

**Disposition: expressible, do not ship.** A `paths` exclusion for generated
files would not save cobra, whose findings are in `cobra.go` and `command.go`.
The rule is a migration aid with a deadline, not a pitfall: it says the code is
old, not that it is wrong.

---

## 14. `reliability.go.unchecked-type-assertion`

**Pitfall.** A single-value type assertion `v := x.(T)` panics when the dynamic
type is not `T`, where the two-value form returns a flag.

**Concept source.** go-tools (staticcheck) and errcheck — unchecked type
assertion (MIT). Concept only; no text taken. This is the 2.1 matrix candidate
rejected for the launch set on noise; it is revisited here because a named
primitive changes the answer.

**Severity.** `warning`.

**Query.** Compiles and discriminates:

```scheme
(short_var_declaration left: (expression_list . (identifier) .) right: (expression_list . (type_assertion_expression) @report .))
```

**Examples.**

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

**Expected noise.** The idiom is the assertion whose type was already established
by an enclosing `type switch` or by a `_, ok :=` guard a few lines above — the
matrix predicted this and the measurement confirms it: 0.2390 in cobra
(`command.go`, production code), 0.2213 in gin, **1.0979** in client_golang. The
warning gate is 0.25, so cobra alone fails it.

**Disposition: needs primitive — an enclosing-node predicate.** Precisely: a
clause that constrains a match by an ancestor of the matched node, so the rule
can say "a single-value type assertion that is **not** inside a
`type_switch_statement` whose value is the same expression". Two spellings would
do: a rule-level `not_inside: (type_switch_statement)` field on the `ast`
payload, or a predicate `#not-within? @report "(type_switch_statement)"`. Either
is a bounded, single-file addition; neither needs dataflow. Without it, the rule
is the same medium-noise candidate 2.1 already rejected, and it should stay
rejected.

---

## 15. `reliability.go.defer-in-nested-block`

**Pitfall.** A `defer` inside a loop, but nested inside an `if` or a `switch`
within the loop body, still runs only when the enclosing function returns.

**Concept source.** go-tools (staticcheck) — `SA9001`, "Defers in range loops may
not run when you expect them to" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query.** None exists. The shipped `reliability.go.defer-in-loop` matches a
`defer_statement` that is a *direct* child of the loop body's `statement_list`:

```scheme
(for_statement body: (block (statement_list (defer_statement) @report)))
```

Verified: given a `defer` one level deeper, inside an `if` inside the loop, this
reports nothing. The tree-sitter query language has no descendant axis — a
pattern names an exact parent-child path — so covering depth two means writing
the depth-two pattern, depth three means writing that one too, and the set of
intervening constructs (`if`, `else`, `switch` case, `select` case, labelled
statement, inner block) makes the enumeration combinatorial rather than long.

**Examples.**

```go
// should fire, does not
package p

func f(paths []string, ok bool) {
	for _, p := range paths {
		if ok {
			defer close(p)
		}
	}
}

// must not fire
package p

func f(paths []string) {
	for _, p := range paths {
		func() {
			defer close(p)
		}()
	}
}
```

**Expected noise.** The idiom the rule must not flag is the deliberate
per-iteration cleanup written as an immediately-invoked closure, as in the
second snippet. A descendant-scope primitive must therefore stop at a
`func_literal` boundary, which is what makes it a scope constraint and not a
plain subtree search.

**Disposition: needs primitive — a descendant-scope constraint.** Precisely: a
clause binding an inner pattern to match anywhere within an outer captured node,
with a stop set of node kinds it will not descend through. Spelled as a
predicate: `#within? @outer @inner` over two captures of one match, plus a
per-language stop set (`func_literal` for Go). This is the primitive with the
strongest case — see the summary below.

---

## 16. `reliability.go.testing-goroutine-fatal`

**Pitfall.** `t.Fatal` is called from a goroutine started by a test. It calls
`runtime.Goexit` on the wrong goroutine, so the test does not fail the way the
author expects.

**Concept source.** golang/go `cmd/vet` — `testinggoroutine`, "report calls to
(*testing.T).Fatal from goroutines started by a test" (BSD-3-Clause). Concept
only; no text taken.

**Severity.** `warning`.

**Query.** A depth-one form compiles and discriminates:

```scheme
((go_statement (call_expression function: (func_literal body: (block (statement_list (expression_statement (call_expression function: (selector_expression operand: (identifier) @t field: (field_identifier) @m) @report))))))) (#eq? @t "t") (#any-of? @m "Fatal" "Fatalf" "FailNow" "Fatalln"))
```

It fires on `go func() { t.Fatal(...) }()` and is silent on `t.Error`. It is also
useless in practice: verified against the same call wrapped in a single `if`, it
reports nothing, and a `t.Fatal` that is not inside a conditional is not a test
anyone writes. Zero findings on all three repositories, which here means no
recall rather than no noise.

**Examples.**

```go
// should fire, does not
package p

import "testing"

func TestX(t *testing.T, bad bool) {
	go func() {
		if bad {
			t.Fatal("boom")
		}
	}()
}

// must not fire
package p

import "testing"

func TestX(t *testing.T) {
	go func() {
		t.Error("boom")
	}()
}
```

**Expected noise.** The idiom that would produce noise if the rule descended
without a stop set is a nested helper closure that legitimately owns its own
`t` — the descendant primitive's `func_literal` stop set handles it, in the
opposite direction from item 15: here the search must stop at the *first*
`func_literal` boundary going in.

**Disposition: needs primitive — the same descendant-scope constraint as item
15.** With it, the rule is "a `t.Fatal`-family call anywhere inside the
`func_literal` of a `go_statement`", which is one pattern.

---

## 17. `reliability.go.math-rand-for-token`

**Pitfall.** `math/rand` is used where the value has to be unpredictable.

**Concept source.** gosec — `G404`, "Insecure random number source (`rand`)"
(Apache-2.0). Concept only; no text taken.

**Severity.** `warning`.

**Query.** A query over the call site alone compiles and fires, but cannot
discriminate:

```scheme
((call_expression function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn) @report) (#eq? @pkg "rand") (#any-of? @fn "Intn" "Int63" "Float64" "Read" "Int31" "Int"))
```

Verified failing: it fires identically on `math/rand`'s `rand.Read` and
`crypto/rand`'s `rand.Read`, because both bind the local name `rand` and a
tree-sitter query cannot see the file's import block from the call site — they
are separate subtrees under `source_file`, and there is no cross-subtree
correlation in the query language.

**Examples.**

```go
// fires, correctly
package p

import "math/rand"

func token() int {
	return rand.Intn(1000000)
}

// fires, wrongly
package p

import "crypto/rand"

func token(b []byte) error {
	_, err := rand.Read(b)
	return err
}
```

**Expected noise.** Two idioms. The first is `crypto/rand` under the same local
name, above — a straight false positive. The second is the legitimate use of
`math/rand`: jitter, sampling, load generation, and test fixtures.
client_golang reports **0.3229** per kLOC over the warning gate, all of it in
`examples/` and `_test.go`; gin's three are in a test.

**Disposition: needs primitive — file-scoped import binding.** Precisely: bind
each `package_identifier` used as a qualifier to the import path it resolves to
in the same file (the `name:` alias when present, otherwise the last path
segment), and expose it as a text predicate — `#import-path? @pkg "math/rand"`.
The data is already half-collected: `graph.rs` extracts Go import facts through
`GO_IMPORTS` for the boundary engine, and `scan.rs` gates that extraction on a
boundary rule being present. What is missing is the local binding name — the
current query captures `path:` only, not `name:` — and the hand-off to the AST
engine. Even with it, the second idiom stays, so this rule would still need a
`paths` exclusion for tests and examples before it could ship.

---

## 18. `reliability.go.printf-verb-arity`

**Pitfall.** A `Printf`-family format string has a different number of verbs than
the call has arguments, so the output carries `%!d(MISSING)` or `%!(EXTRA ...)`.

**Concept source.** golang/go `cmd/vet` — `printf`, "check consistency of Printf
format strings and arguments" (BSD-3-Clause). Concept only; no text taken.

**Severity.** `warning`.

**Query.** None exists, and none can. The check is arithmetic: count the verbs
in one captured string, count the sibling arguments, compare. The loader accepts
only the text-predicate set — `eq?`, `not-eq?`, `any-eq?`, `any-not-eq?`,
`match?`, `not-match?`, `any-match?`, `any-not-match?`, `any-of?`, `not-any-of?`
— every one of which tests a capture's text against a literal or a regex. None
counts anything, and a fixed-arity pattern per verb count would need one pattern
per (verb count, argument count) pair.

**Examples.**

```go
// should fire
package p

import "fmt"

func f(a, b int) string {
	return fmt.Sprintf("%d and %d", a)
}

// must not fire
package p

import "fmt"

func f(a, b int) string {
	return fmt.Sprintf("%d and %d", a, b)
}
```

**Expected noise.** The idiom that would break a naive count is `%%`, the escaped
percent, and the indexed verb `%[2]d`, which reuses an argument — both change the
arithmetic without changing the number of `%` characters.

**Disposition: needs primitive — a format-arity predicate.** Precisely: a
predicate `#verb-arity? @format @args` that parses Go's `fmt` verb grammar,
including `%%` and `%[n]`, and compares the count with the number of named
children of a captured argument list. It is a single-file check and would fit
the engine, but it serves one Go rule and one C rule at best, below the map's
three-candidates-across-two-languages bar. **Do not build it.** `go vet` runs
this check by default in every Go toolchain, so the pitfall is already covered
where it matters.

---

## 19. `reliability.go.loop-var-capture`

**Pitfall.** A closure or goroutine started inside a loop captures the loop
variable and sees its later value.

**Concept source.** golang/go `cmd/vet` — `loopclosure`, "check references to
loop variables from within nested functions" (BSD-3-Clause). Concept only; no
text taken.

**Severity.** `warning`.

**Query.** None. Deciding it needs three things a single-file query cannot do:
find the closure anywhere inside the loop body (item 15's primitive), resolve the
identifiers it reads to the loop's own declarations rather than to a shadowing
declaration inside the closure, and know whether the closure outlives the
iteration. The second is name resolution with scope, which the map puts out of
scope.

**Examples.**

```go
// the shape, pre-Go 1.22
package p

func f(xs []int) {
	for _, x := range xs {
		go func() {
			println(x)
		}()
	}
}

// the rewrite that was the fix
package p

func f(xs []int) {
	for _, x := range xs {
		go func(x int) {
			println(x)
		}(x)
	}
}
```

**Expected noise.** Moot, and this is the more important finding: Go 1.22 changed
the language. "Previously, the variables declared by a 'for' loop were created
once and updated by each iteration. In Go 1.22, each iteration of the loop
creates new variables, to avoid accidental sharing bugs." On any module
declaring `go 1.22` or later the first snippet is correct code, so a rule
reporting it would be a false positive on every modern repository, and telling
the two apart means reading `go.mod` — another file.

**Disposition: inexpressible.** Not merely out of reach of the engine but
obsolete: the language fixed it. Do not revisit.

---

## 20. `reliability.go.mutex-value-copy`

**Pitfall.** A value containing a `sync.Mutex` is copied — passed by value,
ranged over, or assigned — so the copy locks a different mutex than the original.

**Concept source.** golang/go `cmd/vet` — `copylocks`, "check for locks
erroneously passed by value" (BSD-3-Clause). Concept only; no text taken.

**Severity.** `warning`.

**Query.** None. The decision is "does the static type of this expression
contain a `sync.Locker` anywhere in its field graph", which needs the type of a
name defined in another file of the same package, and often in another module.
Nothing about the syntax distinguishes `func f(c Config)` from `func f(c
Counter)`; the difference is entirely in the declarations.

**Examples.**

```go
// the shape
package p

import "sync"

type Counter struct {
	mu sync.Mutex
	n  int
}

func bump(c Counter) { c.n++ }

// indistinguishable syntactically
package p

type Config struct {
	name string
	n    int
}

func bump(c Config) { c.n++ }
```

**Expected noise.** A syntactic approximation — "a parameter whose type is a
`type_identifier` and whose name suggests a lock" — would fire on every
by-value struct parameter in the file. There is no idiom to name because there
is no signal.

**Disposition: inexpressible.** Type-aware analysis, which the map puts out of
scope. `go vet` covers it.

---

## Primitives, and which items need them

| Primitive | Items in this list | Verdict |
| --- | --- | --- |
| **Descendant-scope constraint** — bind an inner pattern to match anywhere within an outer captured node, with a per-language stop set of kinds it will not descend through (`func_literal` for Go). Spelled `#within?` / `#not-within?` over two captures of one match. | 15 `defer-in-nested-block`, 16 `testing-goroutine-fatal`; and `regexp-compile-in-loop` and `time-after-in-loop`, both written off during this round for the same reason | **Strongest candidate.** Two dispositioned items plus two more here, and the shape recurs outside Go — "`await` inside a loop" in JavaScript and TypeScript, "a bare `open` inside a function that has no `with`" in Python are the same clause. It also lifts the ceiling on the shipped `reliability.go.defer-in-loop`, which today sees only depth one. Needs the cross-language count confirmed by the other pitfall tickets before it clears the map's three-across-two bar. |
| **Enclosing-node predicate** — constrain a match by an ancestor's kind, without the two-capture binding above. | 14 `unchecked-type-assertion` | A degenerate case of the descendant-scope constraint: `#not-within? @report "(type_switch_statement)"` is the same clause read from the inside out. Build one primitive, not two. |
| **File-scoped import binding** — resolve a qualifier `package_identifier` to its import path within the file, exposed as `#import-path? @pkg "math/rand"`. | 17 `math-rand-for-token`; and, as a precision floor, every rule that matches `errors.`, `fmt.`, `strings.` by bare package name — items 7, 10 and the shipped `append-result-discarded` | **Second candidate, and cheaper than it looks.** `graph.rs` already runs `GO_IMPORTS` over Go files and `scan.rs` already gates that extraction on a boundary rule. The missing pieces are the `name:` alias in the captured fact and the hand-off to `engines/ast.rs`. It does not by itself make item 17 shippable. |
| **Format-arity predicate** — `#verb-arity? @format @args`. | 18 `printf-verb-arity` | **Do not build.** One Go candidate, and `go vet` already runs the check in every toolchain. |
| **Comment-skipping anchor** — make `.` step over `extra` nodes. | 1 `unreachable-after-return`, recall only | **Do not build.** The `_statement` supertype form solves the correctness problem; this would only recover a rare recall case. |
| **Intra-function scope tracking** — resolve identifiers to their declarations within a function. | 19 `loop-var-capture`, and `shadowed-err`, written off during this round | Out of scope per the map, and item 19 is obsolete anyway. |

## Notes for the implementation package

- **The Go noise set needs a third repository.** The map lists this as unspecified.
  cobra and gin between them are 30627 lines and produced one finding each across
  the eleven-rule ship list. client_golang, measured here, is where the
  error-handling and type-assertion shapes actually appear, and it is Apache-2.0.
  It is the natural third row.
- **Two queries were fixed by measurement, not by review.** Items 6 and 11 both
  passed their positive and negative snippets in the first draft and both
  reported false positives on gin. Snippet verification is necessary and not
  sufficient; the noise run has to come before the disposition, not after.
- **The `_statement` supertype is worth trying in the other languages.** Item 1's
  fix is generic: if a grammar declares a statement supertype, the 2.1
  trailing-comment removal may be reversible there too, with no engine change.
  Worth one line in each of the other nine pitfall tickets.
- **Eleven rules would roughly double the Go reliability profile**, which ships
  five today. Items 2 and 4 widen shipped rules rather than adding new shapes,
  so the honest count of new pitfalls covered is nine.
