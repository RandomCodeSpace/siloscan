# C pitfall list

Research for issue #110, under the wayfinder map #103. This document decides
*what the C rules would be* for 2.2. It writes no rule YAML and no engine code.

- **Language:** `c`. `lang.rs` classifies a `.h` file as C unless its content
  reads as C++ (`is_cpp_header`), so every rule below runs over C headers too.
  Each query was verified in a `.h` file as well as a `.c` file.
- **Grammar:** `tree-sitter-c` 0.24.2 on `tree-sitter` 0.26.11, the versions
  pinned in `crates/siloscan-core/Cargo.toml`.
- **Engine boundary:** single-file tree-sitter queries and single-file metric
  rules, per #103. The only predicates the loader accepts are the text
  predicates — `eq?`, `not-eq?`, `any-eq?`, `any-not-eq?`, `match?`,
  `not-match?`, `any-match?`, `any-not-match?`, `any-of?`, `not-any-of?`.
- **Citations are concept-only.** Every entry names the linter and rule that
  owns the *idea*. No pattern text, query text, message text or test fixture
  was taken from any of them, and none of them was read to write the queries
  below; the queries were written against `tree-sitter-c`'s own
  `node-types.json`.

## Scope: what this document does not repeat

Already shipped in `crates/siloscan-core/rules/profiles/reliability-c.yaml`
and excluded here: `self-comparison`, `self-assignment`,
`assignment-in-condition` (the `if` form), `identical-if-branches`,
`string-literal-comparison`. Already shipped in `maintainability-c.yaml`:
`function-length`, `parameter-count`, `nesting-depth`,
`cyclomatic-complexity` — all four metric measures the engine has, so the
maintainability metric surface for C is closed.

Removed in 2.1 and excluded unless a named primitive fixes the failure mode:
`unreachable-after-return`, `empty-if-body`. See
[2.1 removals reconsidered](#21-removals-reconsidered) at the end; neither
returns as a numbered item, and one of them turns out not to need a primitive
at all.

## How each query was verified

Not by hand. A throwaway integration test (not committed) built a one-rule
document per candidate, loaded it through `rules::load_str` under the identity
`reliability-c@1` — the same call `plan::resolve` makes in a real scan — and
scanned a temporary directory holding that candidate's positive snippet, its
negative snippet, and the positive snippet again as a `.h` file, through
`scan::scan`. A candidate passes only if it reports on the positive `.c` file,
reports on the `.h` file, and reports nothing on the negative.

A second pass ran all fifteen expressible candidates over one 78-line block of
ordinary `#ifdef`-heavy C — a hand-rolled `strcpy`/`strlen` pair with empty
loop bodies, a `while ((c = fgetc(f)) != EOF)` drain loop, an
`#ifdef HAVE_SNPRINTF` / `#else` config path using `sizeof(buf)` on a local
array, an `#ifdef _WIN32` / `#else` pair of `if` statements, a
`strcmp(k, "a") == 0` else-if chain, a variadic logging macro, and
`return &g_state;`. That block is the *noise probe*, and where an entry below
says "measured on the noise probe" it means that run. It is not a substitute
for the pinned noise set in `noise-set.md`; it is the cheap filter that comes
first.

## Summary

| # | id | severity | disposition | expected noise |
| --- | --- | --- | --- | --- |
| 1 | `reliability.c.comparison-as-statement` | warning | expressible | near-zero |
| 2 | `reliability.c.bitwise-comparison-precedence` | warning | expressible | near-zero |
| 3 | `reliability.c.chained-comparison` | warning | expressible | near-zero |
| 4 | `reliability.c.contradictory-equality` | warning | expressible | near-zero |
| 5 | `reliability.c.tautological-inequality` | warning | expressible | near-zero |
| 6 | `reliability.c.duplicate-else-if-condition` | warning | expressible | low |
| 7 | `reliability.c.identical-logical-operands` | warning | expressible | near-zero |
| 8 | `reliability.c.self-relational-comparison` | warning | expressible | near-zero |
| 9 | `reliability.c.assignment-in-loop-condition` | warning | expressible | near-zero |
| 10 | `reliability.c.gets-call` | warning | expressible | near-zero |
| 11 | `reliability.c.unbounded-scanf-conversion` | warning | expressible | low |
| 12 | `reliability.c.non-literal-format-string` | warning | expressible | low |
| 13 | `reliability.c.strcmp-nonzero-comparison` | warning | expressible | near-zero |
| 14 | `reliability.c.strncat-destination-sizeof` | warning | expressible | near-zero |
| 15 | `reliability.c.empty-loop-body` | info | expressible, reject on noise | **measured 2 hits / 78 lines** |
| 16 | `reliability.c.sizeof-pointer-argument` | warning | needs primitive **P1** | naive form measured false-positive |
| 17 | `reliability.c.address-of-local-returned` | warning | needs primitive **P1** | naive form measured false-positive |
| 18 | `reliability.c.switch-case-fallthrough` | info | needs primitive **P2** | naive form measured false-positive |
| 19 | `reliability.c.null-check-wrong-operator` | warning | needs primitive **P3** | naive form measured under-match |
| 20 | `maintainability.c.macro-parameter-unparenthesised` | info | inexpressible | n/a |

Fourteen candidates are recommended for the launch set: 1–14. Item 15 is
expressible and measured too noisy, and is written down so the next round does
not rediscover it. Items 16–19 name the primitives they need. Item 20 is an
engine-boundary statement.

---

## 1. `reliability.c.comparison-as-statement`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** A comparison written where an assignment was meant — `a == b;` as
a statement — computes a value and throws it away.

**Concept source.** clang — `-Wunused-comparison` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
(expression_statement (binary_expression operator: ["==" "!=" "<" ">" "<=" ">="]) @report)
```

```c
// fires
void f(int a, int b) {
  a == b;
}

// does not fire
void f(int a, int b) {
  a = b;
}
```

**Expected noise: near-zero.** The idiom that would produce noise is the
cast-to-void suppression `(void)(a == b);`, and it was measured not to fire:
the cast puts a `cast_expression` and a `parenthesized_expression` between the
statement and the comparison, and the query requires the comparison to be a
direct child. A comparison in a `for` update slot is a field of `for_statement`,
not an `expression_statement`, so it does not fire either. Silent on the noise
probe.

---

## 2. `reliability.c.bitwise-comparison-precedence`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `&`, `|` and `^` bind *looser* than `==` in C, so `a & b == c`
means `a & (b == c)` — almost never what the author wrote it for.

**Concept source.** clang — `-Wparentheses` (Apache-2.0 WITH LLVM-exception).
Concept only; no text taken.

**Query** (verified; two patterns, and the engine de-duplicates on
`(rule id, start, end)`):

```scheme
(binary_expression left: (_) operator: ["&" "|" "^"] right: (binary_expression operator: ["==" "!="])) @report
(binary_expression left: (binary_expression operator: ["==" "!="]) operator: ["&" "|" "^"]) @report
```

```c
// fires
int f(int a, int b, int c) {
  return a & b == c;
}

// does not fire
int f(int a, int b, int c) {
  return (a & b) == c;
}
```

**Expected noise: near-zero.** The idiom that would produce noise is a
deliberate mask-of-a-predicate, `flags & (x == y)`, and writing it requires the
parentheses, which turn the operand into a `parenthesized_expression` the query
does not match. That is the same escape hatch the compiler diagnostic uses.
Silent on the noise probe, whose `if ((c & MASK) == 0)` is the parenthesised
form.

---

## 3. `reliability.c.chained-comparison`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `a < b < c` parses as `(a < b) < c`, comparing a 0-or-1 result
against `c`; it never has its mathematical meaning.

**Concept source.** clang — `-Wparentheses` (Apache-2.0 WITH LLVM-exception).
Concept only; no text taken.

**Query** (verified):

```scheme
(binary_expression left: (binary_expression operator: ["<" ">" "<=" ">="]) operator: ["<" ">" "<=" ">="]) @report
```

```c
// fires
int f(int a, int b, int c) {
  return a < b < c;
}

// does not fire
int f(int a, int b, int c) {
  return a < b && b < c;
}
```

**Expected noise: near-zero.** The idiom that would produce noise is a
deliberate comparison of a boolean result, `(a < b) < flag`; the parentheses
make the left operand a `parenthesized_expression`. The outer operator is
restricted to the four relational operators — extending it to `==`/`!=` would
catch `a < b == c`, but it would also catch the deliberate
`(a < b) == expected` shape used in test code, so it is left out. Silent on the
noise probe, whose `a < b && b < 10` is the correct spelling.

---

## 4. `reliability.c.contradictory-equality`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `x == 1 && x == 2` is always false; the author meant `||`.

**Concept source.** clang-tidy — `misc-redundant-expression` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
((binary_expression
   left: (binary_expression left: (identifier) @x operator: "==" right: (number_literal) @a)
   operator: "&&"
   right: (binary_expression left: (identifier) @y operator: "==" right: (number_literal) @b)) @report
 (#eq? @x @y)
 (#not-eq? @a @b))
```

```c
// fires
int f(int x) {
  return x == 1 && x == 2;
}

// does not fire
int f(int x, int y) {
  return x == 1 && y == 2;
}
```

**Expected noise: near-zero.** The idiom that would produce noise is a chain
over *named constants* whose values differ — `x == E_A && x == E_B` — where the
author is guarding against a macro that may expand to the same value under a
different `#ifdef`. Restricting both right operands to `number_literal` keeps
identifier and macro operands out entirely, which is also why recall is narrow:
this fires only on literal-versus-literal. `&&` is left-associative, so a
three-term chain still contains a two-term `binary_expression` node and is
matched. Silent on the noise probe.

---

## 5. `reliability.c.tautological-inequality`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `x != 1 || x != 2` is always true; the author meant `&&`.

**Concept source.** clang-tidy — `misc-redundant-expression` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
((binary_expression
   left: (binary_expression left: (identifier) @x operator: "!=" right: (number_literal) @a)
   operator: "||"
   right: (binary_expression left: (identifier) @y operator: "!=" right: (number_literal) @b)) @report
 (#eq? @x @y)
 (#not-eq? @a @b))
```

```c
// fires
int f(int x) {
  return x != 1 || x != 2;
}

// does not fire
int f(int x) {
  return x != 1 && x != 2;
}
```

**Expected noise: near-zero**, and for the same reason as item 4. The idiom
that would produce noise is the errno test `err != EAGAIN || err != EWOULDBLOCK`,
which is genuinely a bug when the two macros differ and correct-by-accident when
they are the same value — and it does not fire, because both operands are
`identifier` and the query requires `number_literal`. That is a deliberate
recall sacrifice: the engine cannot evaluate a macro. Silent on the noise probe.

---

## 6. `reliability.c.duplicate-else-if-condition`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `if (a) { … } else if (a) { … }` — the second arm is unreachable
because its condition is byte-identical to the first.

**Concept source.** clang-tidy — `bugprone-branch-clone` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken. Distinct from the shipped
`reliability.c.identical-if-branches`, which compares *bodies*, not conditions.

**Query** (verified):

```scheme
((if_statement
   condition: (parenthesized_expression) @a
   alternative: (else_clause (if_statement condition: (parenthesized_expression) @b))) @report
 (#eq? @a @b))
```

```c
// fires
int f(int a, int b) {
  if (a) {
    return 1;
  } else if (a) {
    return 2;
  }
  return 0;
}

// does not fire
int f(int a, int b) {
  if (a) {
    return 1;
  } else if (b) {
    return 2;
  }
  return 0;
}
```

**Expected noise: low.** The idiom that would produce noise is a
side-effecting condition repeated on purpose — `if (getc(f) == 'a') … else if
(getc(f) == 'a') …` — where the second call reads the next byte and the
duplication is deliberate. That is rare and, when it happens, it is worth a
reader's attention anyway. `#eq?` compares node text, so whitespace differences
already break the match; that costs recall, not precision. The `#ifdef` hazard
does not apply here: on the noise probe the `#ifdef _WIN32` / `#else` pair
parses as two *separate* `if` statements rather than an else-if chain, so it
did not fire.

---

## 7. `reliability.c.identical-logical-operands`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `a && a` and `a || a` evaluate one operand for nothing; one of the
two names is almost always a typo for a sibling.

**Concept source.** clang-tidy — `misc-redundant-expression` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
((binary_expression left: (identifier) @l operator: ["&&" "||"] right: (identifier) @r) @report
 (#eq? @l @r))
```

```c
// fires
int f(int a) {
  return a && a;
}

// does not fire
int f(int a, int b) {
  return a && b;
}
```

**Expected noise: near-zero.** The idiom that would produce noise is a macro
argument used twice inside a function-like macro body — but a macro body is a
single opaque `preproc_arg` token in this grammar (see item 20), so it is never
parsed as a `binary_expression` and never fires. Restricting both operands to
bare `identifier` keeps call operands, which may have side effects, out. Silent
on the noise probe.

---

## 8. `reliability.c.self-relational-comparison`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `a < a`, `a > a`, `a <= a`, `a >= a` are constants; the shipped
`reliability.c.self-comparison` covers only `==`.

**Concept source.** clang — `-Wtautological-compare` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
((binary_expression left: (identifier) @l operator: ["<" ">" "<=" ">="] right: (identifier) @r) @report
 (#eq? @l @r))
```

```c
// fires
int f(int a) {
  return a < a;
}

// does not fire
int f(int a, int b) {
  return a < b;
}
```

**Expected noise: near-zero.** The idiom that would produce noise is the
pre-C99 NaN test `x != x`, and `!=` is deliberately **not** in the operator
set for exactly that reason — which is also why `!=` is left out of the shipped
`self-comparison` rule. The four relational operators have no such idiom.
Silent on the noise probe.

---

## 9. `reliability.c.assignment-in-loop-condition`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `while (a = b)` assigns where it looks like it compares. The
shipped `reliability.c.assignment-in-condition` covers `if_statement` only, so
`while` and `do … while` are uncovered.

**Concept source.** clang — `-Wparentheses` (Apache-2.0 WITH LLVM-exception).
Concept only; no text taken.

**Query** (verified):

```scheme
(while_statement condition: (parenthesized_expression (assignment_expression) @report))
(do_statement condition: (parenthesized_expression (assignment_expression) @report))
```

```c
// fires
int f(int a, int b) {
  while (a = b) {
    return 1;
  }
  return 0;
}

// does not fire
int f(int a, int b) {
  while ((a = b)) {
    return 1;
  }
  return 0;
}
```

**Expected noise: near-zero.** The two idioms that would produce noise are the
read loop `while ((c = fgetc(f)) != EOF)` — where the condition is a
`binary_expression` and the assignment is nested one level down, so it does not
match — and the deliberately-doubled `while ((*d++ = *s++))`, where the inner
parentheses are the author's own "yes, I meant it" marker. The noise probe
contains both and the rule was silent on it. `for_statement` is deliberately
excluded: its `condition` field is a bare expression with no
`parenthesized_expression` wrapper, so there is no way for an author to spell
the escape hatch, and `for (; p = next(); )` would have no way out.

---

## 10. `reliability.c.gets-call`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `gets()` cannot be called safely — it has no way to bound the
write — and was removed from the language in C11.

**Concept source.** clang-tidy — `bugprone-unsafe-functions` / `cert-msc24-c`
(Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
((call_expression function: (identifier) @f) @report (#eq? @f "gets"))
```

```c
// fires
void f(char *b) {
  gets(b);
}

// does not fire
void f(char *b) {
  fgets(b, 10, stdin);
}
```

**Expected noise: near-zero.** The idiom that would produce noise is a
project-local function or member also called `gets`; `function: (identifier)`
excludes `obj->gets(…)` and `obj.gets(…)`, which are `field_expression`, so
only a free function of that exact name fires. Recall on a modern tree is close
to zero for the same reason the rule is safe — the function no longer exists.
The rule earns its place on legacy and vendored C, which is exactly where a
first scan finds it. Silent on the noise probe. Extending the `#any-of?` set to
`strcpy`/`strcat`/`sprintf` was considered and rejected: those have bounded,
correct uses everywhere and would breach the warning budget on any real tree.

---

## 11. `reliability.c.unbounded-scanf-conversion`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** A `%s` conversion with no field width in a `scanf` family format
string writes an unbounded amount into the destination.

**Concept source.** Cppcheck — `invalidscanf` (GPL-3.0-or-later). Concept only;
no text, pattern or fixture taken.

**Query** (verified):

```scheme
((call_expression function: (identifier) @f arguments: (argument_list (string_literal) @fmt)) @report
 (#any-of? @f "scanf" "fscanf" "sscanf" "vscanf" "vsscanf" "vfscanf")
 (#match? @fmt "%s"))
```

```c
// fires
void f(char *b) {
  scanf("%s", b);
}

// does not fire
void f(char *b) {
  scanf("%31s", b);
}
```

**Expected noise: low.** Two idioms could produce noise. First, a format string
containing a literal percent before an `s`, `"100%% saturated"` — `%%s` would
match the regex; it is rare enough to accept and could be excluded by
tightening the pattern to `%[^0-9*]*s` if the noise set says otherwise. Second,
the query does not anchor the format string to its argument position, so for
`sscanf` any *other* string-literal argument containing `%s` would fire; in
practice `sscanf`'s source buffer is a variable, not a literal. Anchoring
would need one pattern per function because the format position differs
(`scanf` first, `fscanf`/`sscanf` second), which is the trade this entry
records. Silent on the noise probe.

---

## 12. `reliability.c.non-literal-format-string`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `printf(msg)` treats attacker-influenced text as a format string;
the correct spellings are `fputs(msg, stdout)` or `printf("%s", msg)`.

**Concept source.** clang — `-Wformat-security` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
((call_expression function: (identifier) @f arguments: (argument_list . (identifier) @arg .)) @report
 (#any-of? @f "printf" "vprintf"))
```

```c
// fires
void f(char *b) {
  printf(b);
}

// does not fire
void f(char *b) {
  printf("%s", b);
}
```

**Expected noise: low.** The idiom that would produce noise is
`printf(banner)` where `banner` is a file-scope `static const char[]` the
author controls — which is the same shape the compiler diagnostic flags, so it
is a true positive under this rule's definition rather than noise. The two
anchors restrict the match to a call with exactly one argument, which keeps
every wrapper of the form `printf(fmt, …)` out. On the noise probe it fired
once, on the planted `printf(msg)`, and on nothing else — including the
variadic `LOG` macro, whose body is opaque. Extending the function set to
`fprintf`/`sprintf`/`snprintf` needs a per-function argument index and is left
out for the same reason as item 11.

---

## 13. `reliability.c.strcmp-nonzero-comparison`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `strcmp` is specified to return a value whose *sign* is
meaningful, not its magnitude; `strcmp(a, b) == 1` is only accidentally true.

**Concept source.** clang-tidy — `bugprone-suspicious-string-compare`
(Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
((binary_expression
   left: (call_expression function: (identifier) @f)
   operator: ["==" "!="]
   right: (number_literal) @n) @report
 (#any-of? @f "strcmp" "strncmp" "memcmp" "strcasecmp" "strncasecmp" "wcscmp")
 (#not-eq? @n "0"))
```

```c
// fires
#include <string.h>
int f(const char *a, const char *b) {
  return strcmp(a, b) == 1;
}

// does not fire
#include <string.h>
int f(const char *a, const char *b) {
  return strcmp(a, b) == 0;
}
```

**Expected noise: near-zero.** The idiom that would produce noise is an
alternative spelling of zero — `== 0L`, `== 0x0` — which `#not-eq? @n "0"` does
not recognise and which nobody writes. The `strcmp(a, b) == 0` equality test,
which is the overwhelmingly common form, is excluded by construction. Silent on
the noise probe, which contains two `strcmp(…) == 0` calls.

---

## 14. `reliability.c.strncat-destination-sizeof`

reliability · ast · severity `warning` · **expressible**

**Pitfall.** `strncat`'s third argument is the number of bytes to *append*, not
the size of the destination; `strncat(d, s, sizeof(d))` can write
`sizeof(d) + strlen(d) + 1` bytes.

**Concept source.** clang-tidy — `bugprone-not-null-terminated-result`
(Apache-2.0 WITH LLVM-exception). Concept only; no text taken.

**Query** (verified):

```scheme
((call_expression
   function: (identifier) @f
   arguments: (argument_list
     . (identifier) @dst
     (_)
     (sizeof_expression value: (parenthesized_expression (identifier) @sz)) .)) @report
 (#eq? @f "strncat")
 (#eq? @dst @sz))
```

```c
// fires
#include <string.h>
void f(char *d, const char *s) {
  strncat(d, s, sizeof(d));
}

// does not fire
#include <string.h>
void f(char *d, const char *s, unsigned n) {
  strncat(d, s, n);
}
```

**Expected noise: near-zero.** There is no idiom under which the third
argument is the whole destination size, so the shape has no correct reading.
Note the grammar detail the query depends on and that had to be measured rather
than assumed: `sizeof(d)` where `d` is a variable parses as
`sizeof_expression value: (parenthesized_expression (identifier))`, not as the
`type: (type_descriptor)` alternative. Recall is deliberately narrow: the
correct form `sizeof(d) - strlen(d) - 1` is a `binary_expression` and is
excluded, and a destination that is a struct field or an array element is not
an `identifier` and is missed. Silent on the noise probe.

---

## 15. `reliability.c.empty-loop-body`

reliability · ast · severity `info` · **expressible, reject on measured noise**

**Pitfall.** A stray semicolon after a loop head — `while (a);` — silently
detaches the intended body.

**Concept source.** clang — `-Wempty-body` (Apache-2.0 WITH LLVM-exception).
Concept only; no text taken.

**Query** (verified to compile, fire on its positive and stay off its
negative):

```scheme
(while_statement body: (expression_statement . ";" .) @report)
(for_statement body: (expression_statement . ";" .) @report)
```

```c
// fires
int f(int a) {
  while (a);
  return a;
}

// does not fire
int f(int a) {
  while (a) {}
  return a;
}
```

**Expected noise: rejected, and measured.** The idioms that produce the noise
are the two oldest loops in C: the hand-rolled copy `while (*d++ = *s++) ;` and
the hand-rolled length `for (i = 0; s[i]; i++) ;`. Both are correct, both put
the whole loop in the head on purpose, and both fired on the noise probe — two
findings in 78 lines, which extrapolates to roughly 26 per kLOC against an
`info` budget of 1.0. That is the same failure mode that removed
`reliability.c.empty-if-body` in 2.1, arrived at independently, and it is the
reason this entry is written down as rejected rather than shipped: #103's noise
policy is removal, not tuning, and there is no `paths` exclusion that would
help because the idiom lives in ordinary source. **Disposition: expressible,
do not ship.** No primitive rescues it — the shape is genuinely ambiguous in
the source text, not merely unparsed.

---

## 16. `reliability.c.sizeof-pointer-argument`

reliability · ast · severity `warning` · **needs primitive P1**

**Pitfall.** `sizeof` applied to a pointer yields the pointer's width, not the
size of what it points at; `memset(p, 0, sizeof(p))` clears eight bytes.

**Concept source.** clang — `-Wsizeof-pointer-memaccess`, and clang-tidy —
`bugprone-sizeof-expression` (Apache-2.0 WITH LLVM-exception). Concept only; no
text taken.

**Why no query exists.** The distinction is entirely in the *declaration* of
the identifier, which is elsewhere in the file. The naive query

```scheme
(sizeof_expression value: (parenthesized_expression (identifier))) @report
```

was run through the loader and the scanner and it fires on both of these:

```c
// true positive: p is a pointer parameter
#include <string.h>
void f(char *p) {
  memset(p, 0, sizeof(p));
}

// FALSE POSITIVE, measured: buf is a local array and sizeof(buf) is correct
#include <string.h>
void f(void) {
  char buf[32];
  memset(buf, 0, sizeof(buf));
}
```

**Expected noise: unshippable as written.** The idiom that produces the noise
is `sizeof(buf)` on a local fixed-size array — the single most common correct
use of `sizeof` in C. On the noise probe the naive query fired four times, all
four inside one function and all four correct.

**Primitive needed — P1, a function-local declarator index.** A predicate that
resolves a captured `identifier` to the declaration binding it in the nearest
enclosing scope within the same file — function parameter list, block-scope
`declaration`, or file-scope `declaration` — and exposes that declarator's
shape, so a rule can ask "is this a `pointer_declarator`?". Concretely a text
predicate spelled like `(#declared-as? @id pointer)`. Single-file and
non-type-aware: it reads declarators, not types, so `typedef char *str;` still
defeats it. That limit is acceptable; the array-versus-pointer distinction is
syntactic in the overwhelming majority of C.

---

## 17. `reliability.c.address-of-local-returned`

reliability · ast · severity `warning` · **needs primitive P1**

**Pitfall.** Returning the address of an automatic variable returns a pointer
into a frame that no longer exists.

**Concept source.** clang — `-Wreturn-stack-address` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken.

**Why no query exists.** The naive query

```scheme
(return_statement (pointer_expression operator: "&" argument: (identifier))) @report
```

cannot tell an automatic from a static. Measured through the loader and the
scanner, it fires on both:

```c
// true positive: x has automatic storage duration
int *f(void) {
  int x = 1;
  return &x;
}

// FALSE POSITIVE, measured: g has static storage duration
static int g = 1;
int *f(void) {
  return &g;
}
```

**Expected noise: unshippable as written.** The idiom that produces the noise
is the file-scope singleton — `return &g_state;` — which is how a C module
hands out a handle to its own state. It is the naive query's only hit on the
noise probe, and it is a false positive.

**Primitive needed — P1**, the same function-local declarator index as item 16,
asking a different question of it: whether the binding declaration is inside
the enclosing `function_definition` and carries no `static` storage-class
specifier. One primitive, two candidates; that is the argument for building it
rather than either rule alone.

---

## 18. `reliability.c.switch-case-fallthrough`

reliability · ast · severity `info` · **needs primitive P2**

**Pitfall.** A non-empty `case` arm with no `break`, `return`, `goto` or
`continue` falls into the next arm.

**Concept source.** clang — `-Wimplicit-fallthrough` (Apache-2.0 WITH
LLVM-exception). Concept only; no text taken.

**Why no query exists.** The rule is an assertion about what a `case_statement`
does *not* contain, and a tree-sitter query has no negation over subtrees: there
is no way to write "this node has no `break_statement` child". Every query that
can be written matches the presence of something. Measured: the only query that
covers the positive,

```scheme
(case_statement) @report
```

fires twice on a switch in which every arm is correctly terminated.

```c
// true positive: case 1 falls into case 2
int f(int a) {
  int r = 0;
  switch (a) {
  case 1:
    r = 1;
  case 2:
    r = 2;
    break;
  }
  return r;
}

// FALSE POSITIVE, measured: both arms break, both still report
int f(int a) {
  int r = 0;
  switch (a) {
  case 1:
    r = 1;
    break;
  case 2:
    r = 2;
    break;
  }
  return r;
}
```

**Expected noise: unshippable as written**, and noisy even with the primitive.
The idiom that would produce noise on the fixed rule is *deliberate*
fallthrough, which C has no syntax for and which authors mark with a comment or
`__attribute__((fallthrough))`. A shipped rule would need to exempt an arm whose
last child is a `comment` or an `attributed_statement`, which the primitive
below can express. Severity `info` reflects that residual.

**Primitive needed — P2, an absent-child assertion.** A predicate over a
capture asserting that its subtree contains no node of a given kind — spelled
like `(#lacks-child? @arm break_statement return_statement goto_statement)` —
optionally restricted to the capture's direct children. This is a query-engine
feature, not a C feature: it is what would also make a `missing-switch-default`
rule, a Go `missing-error-check` rule and a Java `empty-finally` rule
expressible, so it is the primitive most likely to clear #103's "three
candidates across two languages" bar. Only C evidence is in hand here; the
other languages' lists have to confirm it.

---

## 19. `reliability.c.null-check-wrong-operator`

reliability · ast · severity `warning` · **needs primitive P3**

**Pitfall.** `p != NULL || p->x` dereferences `p` exactly when `p` is null; the
guard operator should be `&&`, or the test should be `p == NULL ||`.

**Concept source.** Cppcheck — `nullPointerRedundantCheck` (GPL-3.0-or-later).
Concept only; no text, pattern or fixture taken.

**Why no query exists.** A tree-sitter query has only child and sibling
relations; there is no descendant operator, so the dereference has to be
written at one exact depth. This query is verified — it loads, and it fires on
its positive:

```scheme
((binary_expression
   left: (binary_expression left: (identifier) @p operator: "!=" right: (null))
   operator: "||"
   right: (field_expression argument: (identifier) @q)) @report
 (#eq? @p @q))
```

```c
// fires
struct s { int x; };
int f(struct s *p) {
  return p != NULL || p->x;
}

// DOES NOT FIRE — measured — and it is the same bug
struct s { int x; };
int f(struct s *p) {
  return p != NULL || p->x > 0;
}
```

The failure here is recall, not precision: one extra node between the `||` and
the dereference and the pattern misses. Enumerating every wrapper shape is not
a fix, it is an unbounded pattern list.

**Expected noise: near-zero precision, unusable recall.** There is no idiom
that produces a false positive at this exact shape — `p != NULL || p->x` has no
correct reading. The rule is not shippable because it would silently catch a
small, arbitrary fraction of real instances, which is worse than not shipping
it: a rule that fires on one spelling of a bug and not the next teaches readers
the wrong thing about what the scanner covers.

**Primitive needed — P3, descendant-scoped matching.** Allow a sub-pattern to
match anywhere beneath a captured node rather than only as its direct child —
in query syntax, some spelling of "`(field_expression …)` somewhere inside
`@rhs`". Like P2 this is a query-engine capability rather than a C one, and it
would also serve P2's exemption cases, so the two should be scoped together if
either is built.

---

## 20. `maintainability.c.macro-parameter-unparenthesised`

maintainability · ast · severity `info` · **inexpressible**

**Pitfall.** `#define SQ(x) x * x` breaks at every call site that passes an
expression: `SQ(a + 1)` expands to `a + 1 * a + 1`.

**Concept source.** Cppcheck — MISRA addon, directive 4.9 on function-like
macros (GPL-3.0-or-later). Concept only; no text taken.

**Why it is inexpressible.** `tree-sitter-c` 0.24.2 gives
`preproc_function_def` three fields — `name: (identifier)`,
`parameters: (preproc_params)` and `value: (preproc_arg)` — and `preproc_arg`
is a single opaque token holding the entire replacement list as text. There is
no sub-tree to query, so no tree-sitter query can see whether a parameter is
parenthesised inside the body. `#match?` over the `preproc_arg` text would be a
regex rule wearing an AST rule's clothes, and it would misread every macro whose
body contains a string literal, a comment, or a token that merely looks like a
parameter name.

**Disposition: inexpressible under #103's engine boundary.** Fixing it needs
the grammar to parse macro bodies, which no tree-sitter C grammar does and
which is not a bounded engine primitive. Recorded so it is not re-proposed.

---

## Primitives, and which items need them

| Primitive | What it is | Items | Note |
| --- | --- | --- | --- |
| **P1** function-local declarator index | Resolve a captured identifier to the declaration binding it in the nearest enclosing scope in the same file, and expose that declarator's shape and storage class to a text predicate. | 16, 17 | Per-grammar: needs a scope model per language, so it is the *least* likely of the three to be shared across languages. |
| **P2** absent-child assertion | A predicate asserting a captured node's subtree contains no node of a named kind. | 18 | Query-engine feature, language-independent. Would also unlock a C `missing-switch-default`, which is otherwise unwritable. |
| **P3** descendant-scoped matching | Let a sub-pattern match anywhere beneath a captured node, not only as a direct child. | 19 | Query-engine feature, language-independent, and it subsumes part of P2's exemption handling. P2 and P3 should be scoped as one decision. |

Against #103's bar — one bounded engine addition, allowed when at least three
candidates across two languages need the same primitive — C alone supplies two
candidates for P1 and one each for P2 and P3. None clears the bar on C
evidence. P2 and P3 are the ones to watch as the other nine lists land, because
they are properties of the query engine rather than of C.

## 2.1 removals reconsidered

`reliability-c.yaml` records two removals. #110 admits them back only if a named
primitive fixes the failure mode. Neither returns as a numbered item, but the
diagnosis differs and the map should know which is which.

**`reliability.c.empty-if-body`** — removed because every finding on curl was
the deliberate `if (cond) ; else if (…)` exclusion idiom and jq's were `#ifdef`
bodies the C parser cannot see. **Stays removed. No primitive helps.** The
`#ifdef` half needs preprocessor evaluation, which #103 puts out of scope, and
the idiom half is genuinely ambiguous source. Item 15 above reaches the same
verdict for loops, independently and with its own measurement.

**`reliability.c.unreachable-after-return`** — removed at 1.21 per kLOC on
curl, 1.84 on jq and 1.49 on redis, with the note that *every finding read is a
trailing comment on the return line, not code*. That is a defect in the query,
not in the engine. The shipped query was
`(compound_statement (return_statement) . (_) @report)`, and `(_)` matches a
`comment` node, which tree-sitter keeps in the tree as an extra. Replacing the
wildcard with an explicit alternation of statement kinds was measured through
the loader and the scanner:

```scheme
(compound_statement (return_statement) . [
  (expression_statement) (if_statement) (return_statement)
  (while_statement) (for_statement) (do_statement) (switch_statement)
  (compound_statement) (break_statement) (continue_statement)
  (goto_statement) (declaration)
] @report)
```

It fires on `return 1;` followed by `g();`, and does not fire on
`return 1; /* done */`. The alternation also excludes `labeled_statement`,
which is a legal `goto` target and which the 2.1 matrix already flagged.

**This is not a primitive**, so under #110's rule the item is excluded from the
numbered list. It is recorded here because the 2.1 measurement was read as an
engine-boundary result and it was a one-line query bug; whether the rewrite is
worth re-measuring on the pinned noise set is a decision for #103, not this
document. The claim proved here is narrow: the rewritten query keeps the
positive and drops the trailing-comment negative. It has **not** been measured
on curl, jq or redis.

## What was not measured

- No candidate here has been run against the pinned noise set
  (`research/embedded-profiles/noise-set.md`). The noise column above is a
  judgement plus one 78-line probe, not the 0.25/1.0-per-kLOC gate.
- No corpus rows were written. Where the fixtures come from — hand-written, or
  permissive linter-suite code with a NOTICE stanza — is still open on #103.
- Item 11's `%%s` case and item 12's `fprintf`-family extension are both noted
  as open trades rather than resolved.
