# TypeScript Pitfall List

**Ticket**: #108 · **Map**: #103 · **Date**: 2026-09-04 · **Branch**: `research/pitfalls-typescript`

Twenty pitfalls a reviewer would flag on sight in TypeScript, each dispositioned
against the engine boundary #103 fixes: a single-file tree-sitter query or a
single-file metric rule, nothing else.

Every concept citation is a linter rule **name and idea only**. No pattern text,
no message text and no rule text is taken from any upstream project.

## What was pinned, and how each claim was checked

| | |
| --- | --- |
| Grammar | `tree-sitter-typescript` **0.23.2**, the `typescript` grammar |
| Binding | `parsers.rs:41` maps the language key `typescript` to `LANGUAGE_TYPESCRIPT`. `tsx` is not bound and is not a separate language key, so TSX-only node names were not used and `tsx/node-types.json` was not consulted. `lang.rs:115` routes both `.ts` and `.tsx` to `typescript`, so a `.tsx` file is parsed by the non-TSX grammar. |
| Node names | `typescript/src/node-types.json` at that version |
| Engine | `tree-sitter` 0.26.11 applies the text predicates itself before `engines/ast.rs` sees a match |

**Query verification.** Every query below was loaded as a one-rule profile
document through `rules::load_str` under a profile identity and run over a
temporary directory of `.ts` files through `scan::scan` — the product's own
path, the same two calls `plan::resolve` and `tests/profile_corpus.rs` make. A
query is recorded as verified only when it reported on its positive example and
reported nothing on **every** negative example listed for it. The harness was a
throwaway integration test in `crates/siloscan-core/tests/`, modelled on the
in-test document pattern in `tests/profile_corpus.rs`; it is not committed. The
run that produced this file checked 33 cases.

**Noise measurement.** Not a judgement call: every candidate was scanned against
all three pinned TypeScript noise repositories at their pinned tags from
`research/embedded-profiles/noise-set.md` — zod `v3.23.8`, rxjs `7.8.1`,
nest `v12.0.1` — with `target/release/siloscan REPO --rules <dir>
--no-default-rules --no-cache --format json`. The denominator is the repository's
own TypeScript code lines summed out of `metrics.files` (`.ts` and `.tsx`, the
`lang.rs` mapping), matching `scripts/profile_noise.py`. Totals: zod 24,499,
rxjs 73,201, nest 105,989 — **203,689 TypeScript code lines**. No rule below
declares a `paths` exclusion, so the rates are whole-repository rates.

Budgets from #103: `warning` ≤ 0.25 per kLOC, `info` ≤ 1.0 per kLOC, on **any**
single pinned repository; zero corpus false positives.

## Items

| # | id | severity | disposition | max per kLOC (repo) |
| --- | --- | --- | --- | --- |
| 1 | `reliability.typescript.throw-non-error-literal` | warning | expressible | 0.0000 |
| 2 | `reliability.typescript.async-promise-executor` | warning | expressible | 0.0000 |
| 3 | `reliability.typescript.typeof-invalid-string` | warning | expressible | 0.0000 |
| 4 | `reliability.typescript.nan-comparison` | warning | expressible | 0.0000 |
| 5 | `reliability.typescript.unsafe-finally` | warning | expressible | 0.0000 |
| 6 | `reliability.typescript.assignment-in-condition` | warning | expressible | 0.0000 |
| 7 | `reliability.typescript.extra-non-null-assertion` | warning | expressible | 0.0000 |
| 8 | `reliability.typescript.non-null-after-optional-chain` | warning | expressible | 0.0094 (nest) |
| 9 | `reliability.typescript.duplicate-object-key` | warning | expressible | 0.0000 |
| 10 | `maintainability.typescript.var-declaration` | info | expressible | 0.0273 (rxjs) |
| 11 | `maintainability.typescript.namespace-declaration` | info | expressible | 0.4082 (zod) |
| 12 | `maintainability.typescript.require-import` | info | expressible | 0.0410 (rxjs) |
| 13 | `maintainability.typescript.empty-interface-body` | info | expressible | 0.0000 |
| 14 | `maintainability.typescript.unnecessary-type-constraint` | info | expressible | 0.0000 |
| 15 | `maintainability.typescript.literal-type-assertion` | info | expressible | 0.0000 |
| 16 | `maintainability.typescript.triple-slash-reference` | info | expressible | 0.0546 (rxjs) |
| 17 | `reliability.typescript.async-without-await` | warning | needs primitive — negated-descendant predicate | not measurable |
| 18 | `reliability.typescript.switch-case-fallthrough` | warning | needs primitive — terminal-child anchor | not measurable |
| 19 | `reliability.typescript.array-constructor-arity` | warning | needs primitive — named-child-count predicate | not measurable |
| 20 | `reliability.typescript.floating-promise` | warning | inexpressible | — |

Sixteen of twenty are expressible today and every one of them is inside its
budget on all three pinned repositories.

---

### 1. `reliability.typescript.throw-non-error-literal`

**Pitfall.** Throwing an object literal, a number or a template string instead
of an `Error` produces a value with no stack trace, which every `catch` in the
program then has to special-case.

**Concept source.** typescript-eslint — `only-throw-error` (MIT). ESLint —
`no-throw-literal` (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query** (verified):

```scheme
((throw_statement [(number) (object) (template_string)]) @report)
```

```typescript
// fires
function f(): void {
  throw { code: 500 };
}

// does not fire
function f(err: Error): void {
  throw err;
}
```

**Expected noise: 0.0000 on all three (measured).** The idiom that produces
noise is `throw 'sentinel string'` inside test doubles, and it is why the string
arm is not in the query. The full ESLint concept — a `(string)` alternative
alongside the others — was measured first and reported **111 findings on rxjs,
1.5164 per kLOC**, more than six times the `warning` budget. All 111 are under
rxjs's `spec/` tree (`throw 'bad'`, `throw 'should not be called'`,
`throw 'tried to use cold() in async test'`; 16 distinct strings). The
test-tree exclusion the shipped JavaScript and TypeScript documents already use
(`**/test/**`, `**/tests/**`, `**/__tests__/**`, `**/*.test.*`, `**/*.spec.*`,
`**/*_test.*`) does not reach `spec/Notification-spec.ts`, and applying it
*raises* the rate to 1.6918 because it shrinks the denominator without removing
a single finding. Widening the exclusion until rxjs's naming fits is tuning a
rule to its corpus, which the shipped maintainability document already refused
once for function-length. Dropping the string arm is a narrowing of the shape,
not of the corpus: the non-string arms report **zero** across all 203,689 lines.

**Disposition.** **Expressible**, with the string arm removed by shape.

---

### 2. `reliability.typescript.async-promise-executor`

**Pitfall.** An `async` executor passed to `new Promise` swallows every
rejection thrown inside it — the returned promise never settles and the error
disappears.

**Concept source.** ESLint — `no-async-promise-executor` (MIT). Concept only;
no text taken.

**Severity.** `warning`.

**Query** (verified):

```scheme
((new_expression
   constructor: (identifier) @c
   arguments: (arguments [(arrow_function "async") (function_expression "async")])) @report
 (#eq? @c "Promise"))
```

```typescript
// fires
const p = new Promise(async (resolve) => {
  resolve(1);
});

// does not fire
const p = new Promise<number>((resolve) => {
  resolve(1);
});
```

The `#eq?` sits inside the outer parenthesis pair, so it binds to the pattern;
without that pair it would not constrain anything. `new Promise<number>(...)`
still matches because `type_arguments` is a separate field.

**Expected noise: 0.0000 on all three (measured).** The idiom that would produce
noise is a deliberately-async executor wrapping a single `await` and calling
`resolve` in a `try`, which is rare and is itself the shape the rule is arguing
against. A plain `async function` anywhere else in the file does not match.

**Disposition.** **Expressible.**

---

### 3. `reliability.typescript.typeof-invalid-string`

**Pitfall.** Comparing `typeof x` against a string that is not one of the eight
values `typeof` can return — a typo like `'strng'`, or `'array'` — is a branch
that can never be taken.

**Concept source.** ESLint — `valid-typeof` (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query** (verified):

```scheme
((binary_expression
   left: (unary_expression operator: "typeof")
   operator: ["===" "!==" "==" "!="]
   right: (string (string_fragment) @s)) @report
 (#not-any-of? @s "string" "number" "bigint" "boolean" "symbol" "undefined" "object" "function"))
```

```typescript
// fires
function f(x: unknown): boolean {
  return typeof x === 'strng';
}

// does not fire
function f(x: unknown): boolean {
  return typeof x === 'undefined';
}
```

`#not-any-of?` is inside the loader's text-predicate set, so the whole
enumeration runs in tree-sitter before `engines/ast.rs` sees the match.

**Expected noise: 0.0000 on all three (measured).** The idiom that would produce
noise is a `typeof` compared against a constant rather than a literal
(`typeof x === KIND`), which does not match the `right:` field at all, so it is
a recall gap rather than noise.

**Disposition.** **Expressible.**

---

### 4. `reliability.typescript.nan-comparison`

**Pitfall.** `x === NaN` is always false — `NaN` is the one value not equal to
itself — so the branch is dead. It is the sincere version of the mistake that
`x !== x` makes on purpose.

**Concept source.** ESLint — `use-isnan` (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query** (verified, two patterns):

```scheme
((binary_expression operator: ["===" "!==" "==" "!="] right: (identifier) @r) @report
 (#eq? @r "NaN"))
((binary_expression left: (identifier) @l operator: ["===" "!==" "==" "!="]) @report
 (#eq? @l "NaN"))
```

```typescript
// fires
function f(x: number): boolean {
  return x === NaN;
}

// does not fire
function f(x: number): boolean {
  return x !== x;
}
```

The `#eq?` against the literal text `"NaN"` is what keeps a local variable named
`nan` out; the grammar has no distinct node for the global.

**Expected noise: 0.0000 on all three (measured).** The idiom that would produce
noise is a user-defined identifier spelled exactly `NaN` shadowing the global,
which is itself worth a finding. Note the deliberate asymmetry with the shipped
document: `x === x` is not reported in TypeScript because it is the canonical
NaN test, and this rule is the other half of that decision — it catches the
version that does not work.

**Disposition.** **Expressible.**

---

### 5. `reliability.typescript.unsafe-finally`

**Pitfall.** A `return`, `throw`, `break` or `continue` directly inside a
`finally` block overrides whatever the `try` or `catch` was returning or
throwing, silently discarding the original exception.

**Concept source.** ESLint — `no-unsafe-finally` (MIT). Concept only; no text
taken.

**Severity.** `warning`.

**Query** (verified):

```scheme
((finally_clause
   body: (statement_block
           [(return_statement) (throw_statement) (break_statement) (continue_statement)])) @report)
```

```typescript
// fires
function f(): number {
  try {
    return 1;
  } finally {
    return 2;
  }
}

// does not fire
function f(): number {
  try {
    return 1;
  } finally {
    cleanup();
  }
}
```

**Expected noise: 0.0000 on all three (measured).** There is no legitimate
idiom here; the shape has no correct reading. The cost is recall, not noise: a
`return` nested inside an `if` inside the `finally` is a direct child of the
`if`, not of the `statement_block`, so it is missed. Closing that gap is the
descendant half of the primitive item 17 needs.

**Disposition.** **Expressible**, at reduced recall.

---

### 6. `reliability.typescript.assignment-in-condition`

**Pitfall.** `if (x = f())` assigns and tests the assigned value. It is a
one-character slip from `===` and reads identically at a glance.

**Concept source.** ESLint — `no-cond-assign` (MIT). Concept only; no text
taken.

**Severity.** `warning`.

**Query** (verified, two patterns):

```scheme
((if_statement condition: (parenthesized_expression (assignment_expression))) @report)
((while_statement condition: (parenthesized_expression (assignment_expression))) @report)
```

```typescript
// fires
function f(x: number): void {
  if (x = compute()) {
    use(x);
  }
}

// does not fire — the deliberate form, wrapped in its own parentheses
function f(x: number): void {
  while ((x = next()) !== 0) {
    use(x);
  }
}
```

**Expected noise: 0.0000 on all three (measured).** The idiom that would produce
noise is the deliberate `while ((m = re.exec(s)) !== null)` matcher loop — and
it does not, because the extra parentheses the convention already requires
produce a nested `parenthesized_expression`, which is not an
`assignment_expression` and does not match. The convention that documents intent
is the same convention that suppresses the finding, which is why this rule can
ship in TypeScript where the Ruby twin was removed in 2.1: Ruby has no
equivalent parenthesisation habit.

**Disposition.** **Expressible.**

---

### 7. `reliability.typescript.extra-non-null-assertion`

**Pitfall.** A doubled non-null assertion (`x!!`) is always a typo or a leftover
from an edit; the second `!` asserts nothing the first did not.

**Concept source.** typescript-eslint — `no-extra-non-null-assertion` (MIT).
Concept only; no text taken.

**Severity.** `warning`.

**Query** (verified):

```scheme
((non_null_expression (non_null_expression)) @report)
```

```typescript
// fires
function f(x?: string): number {
  return x!!.length;
}

// does not fire
function f(a?: { b?: string }): number {
  return a!.b!.length;
}
```

The negative matters: chained assertions on *different* subexpressions are
common and legitimate, and they do not nest — `a!.b!` is a `non_null_expression`
wrapping a `member_expression`, not another `non_null_expression`.

**Expected noise: 0.0000 on all three (measured).** No idiom produces `x!!`.
This is the narrow, shippable neighbour of `non-null-assertion`, which 2.1 held
out at medium noise because `!` on its own is the TypeScript analogue of
`unwrap()`.

**Disposition.** **Expressible.**

---

### 8. `reliability.typescript.non-null-after-optional-chain`

**Pitfall.** `a?.b!` asserts non-null on the result of an expression written
specifically to be nullable. The two operators contradict each other, and the
`!` defeats exactly the check `?.` was added to make.

**Concept source.** typescript-eslint — `no-non-null-asserted-optional-chain`
(MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query** (verified, two patterns):

```scheme
((non_null_expression (member_expression optional_chain: (optional_chain))) @report)
((non_null_expression (subscript_expression optional_chain: (optional_chain))) @report)
```

```typescript
// fires
function f(a?: { b?: string }): number {
  return a?.b!.length;
}

// does not fire
function f(a?: { b?: string }): number {
  return a?.b?.length ?? 0;
}
```

A third arm for optional *calls* (`a?.()!`) is not available: `call_expression`
carries no `optional_chain` field in this grammar, and writing one produces the
compile error `Impossible pattern` from `Query::new`, which the loader surfaces
as `invalid ast query`. That was caught by the harness, not by reading the
grammar.

**Expected noise: 0.0094 per kLOC on nest, 0.0000 on zod and rxjs (measured).**
The single nest finding is at `packages/websockets/socket-module.ts:60`. The
idiom that would produce noise is a chain narrowed by an earlier guard the query
cannot see, where the author knows the value is present; it is rare because
authors reaching for `!` normally drop the `?.` in the same edit.

**Disposition.** **Expressible.**

---

### 9. `reliability.typescript.duplicate-object-key`

**Pitfall.** Two properties with the same key in one object literal: the second
silently wins and the first is dead, which in a config or options object is a
setting that appears to be set and is not.

**Concept source.** ESLint — `no-dupe-keys` (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query** (verified, two patterns):

```scheme
((object (pair key: (property_identifier) @a) (pair key: (property_identifier) @b)) @report
 (#eq? @a @b))
((object (pair key: (string (string_fragment) @a)) (pair key: (string (string_fragment) @b))) @report
 (#eq? @a @b))
```

```typescript
// fires
const o = { a: 1, b: 2, a: 3 };

// does not fire
const o = { a: 1, b: { b: 2 }, c: 3 };
```

**This one was expected to need a primitive and does not.** The worry was that
two unanchored sibling captures could bind the *same* `pair`, making `#eq?`
trivially true and reporting every object with one property. Measured: they
cannot. tree-sitter enumerates ordered pairs of *distinct* siblings, so the
pattern reports nothing on `{ a: 1 }`, `{ a: 1, b: 2 }`, `{ a: 1, b: 2, c: 3 }`,
`{ a: { a: 1 } }` or `{ a: 1, b: { b: 2 }, c: 3 }`, and still reports on the
non-adjacent `{ a: 1, b: 2, a: 3 }`. Five negatives, all clean. **The
"sibling-aware matching" primitive #103 lists as a candidate is not needed for
duplicate-key rules in any language** — this is the single most transferable
finding in this document.

**Expected noise: 0.0000 on all three (measured).** The idiom that would produce
noise is a deliberate override-then-default spread pattern, which uses `...` and
so produces `spread_element` nodes, not `pair` nodes, and does not match. Recall
gap: computed keys and shorthand properties (`{ a, a }`) are separate node types
and are not covered.

**Disposition.** **Expressible.**

---

### 10. `maintainability.typescript.var-declaration`

**Pitfall.** `var` in TypeScript is function-scoped and hoisted, which is a
scoping model the rest of the file does not use; the reviewer's question is
always whether it was deliberate.

**Concept source.** ESLint — `no-var` (MIT). Concept only; no text taken.

**Severity.** `info`.

**Query** (verified):

```scheme
(variable_declaration) @report
```

```typescript
// fires
var x = 1;

// does not fire
let x = 1;
const y = 2;
for (let i = 0; i < 3; i++) {
  use(i);
}
```

The grammar draws the line for free: `var` is `variable_declaration`, `let` and
`const` are `lexical_declaration`. No predicate is needed and there is no way
for the query to be wrong about which keyword it saw.

**Expected noise: 0.0273 per kLOC on rxjs, 0.0000 on zod and nest (measured).**
Two findings on rxjs, one of them in `docs_app/src/typings.d.ts`. The idiom that
would produce noise is a `.d.ts` ambient declaration file, where `var` is the
conventional spelling for a global — that is the shape to watch if the rule ever
approaches its budget, and a `**/*.d.ts` exclusion is the one allowed `paths`
entry. At 0.0273 against a 1.0 budget it does not need one.

**Disposition.** **Expressible.**

---

### 11. `maintainability.typescript.namespace-declaration`

**Pitfall.** `namespace Foo { }` is TypeScript's pre-ES-modules module system.
In a codebase that imports and exports, a namespace is a second, parallel
organisation scheme, and it does not tree-shake.

**Concept source.** typescript-eslint — `no-namespace` (MIT). Concept only; no
text taken.

**Severity.** `info`.

**Query** (verified):

```scheme
((internal_module name: (identifier)) @report)
```

```typescript
// fires
namespace Foo {
  export const a = 1;
}

// does not fire
declare module 'x' {
  export const a: number;
}
```

Constraining `name:` to `(identifier)` is what excludes `declare module 'x'`,
whose name is a `(string)` — module augmentation of a package is a different
thing from a namespace and is not the pitfall.

**Expected noise: 0.4082 per kLOC on zod (10 findings), 0.0094 on nest, 0.0000
on rxjs (measured).** This is the highest rate in the shippable set, and it is
inside the `info` budget of 1.0 with room, but it is the item to watch. The
idiom is `export namespace enumUtil { ... }` as a **type-utility container** —
zod uses it to group conditional-type helpers where a module would work but a
namespace reads better (`zod/deno/lib/helpers/enumUtil.ts:1` and eight more,
mostly the vendored `deno/` build of the same sources). nest's single finding is
`declare namespace fastifyMiddie` for a third-party type augmentation. Both are
deliberate. The rule is honest as an `info` — it flags a real architectural
choice — but a reader should expect it to report intent, not mistakes, in
library code.

**Disposition.** **Expressible.**

---

### 12. `maintainability.typescript.require-import`

**Pitfall.** `const x = require('y')` in a `.ts` file opts that import out of
the module graph the compiler checks: no type is inferred, nothing is
tree-shaken, and the file becomes CommonJS-shaped in an ESM build.

**Concept source.** typescript-eslint — `no-require-imports` (MIT). Concept
only; no text taken.

**Severity.** `info`.

**Query** (verified, two patterns):

```scheme
((lexical_declaration (variable_declarator value: (call_expression function: (identifier) @f))) @report
 (#eq? @f "require"))
((variable_declaration (variable_declarator value: (call_expression function: (identifier) @f))) @report
 (#eq? @f "require"))
```

```typescript
// fires
const fs = require('fs');

// does not fire
import fs = require('fs');
```

The negative is the point: TypeScript's own `import x = require(...)` form is an
`import_alias`, a different node, and it is the sanctioned spelling — so the
rule flags the untyped form and leaves the typed one alone. `#eq?` on the callee
text keeps `requireResolve(...)` out.

**Expected noise: 0.0410 per kLOC on rxjs (3 findings), 0.0000 on zod and nest
(measured).** The idiom that would produce noise is a build or integration
script written in TypeScript but executed by Node without a bundler — rxjs's
three are exactly that (`integration/import/runner.ts`,
`spec/helpers/testScheduler-ui.ts`). Well inside budget.

**Disposition.** **Expressible.**

---

### 13. `maintainability.typescript.empty-interface-body`

**Pitfall.** `interface Foo {}` with no members and no `extends` is a type that
accepts every non-nullish value. It reads as a constraint and enforces nothing.

**Concept source.** typescript-eslint — `no-empty-object-type` (MIT), the rule
that replaced `no-empty-interface`. Concept only; no text taken.

**Severity.** `info`.

**Query** (verified, two patterns):

```scheme
((interface_declaration name: (type_identifier) . body: (interface_body "{" . "}")) @report)
((interface_declaration
   name: (type_identifier) . type_parameters: (type_parameters) . body: (interface_body "{" . "}")) @report)
```

```typescript
// fires
interface Props {}

// does not fire
interface Props extends Base {}
```

Two anchors do the work. `"{" . "}"` asserts the braces are adjacent, which is
how a query says "empty" without arithmetic. The anchor between `name:` and
`body:` asserts nothing sits between them — which is how it excludes an
`extends_type_clause` without a negation predicate. The second pattern re-admits
the generic case, where `type_parameters` legitimately sits in that gap.

**Expected noise: 0.0000 on all three (measured), down from 0.1229 on rxjs for
the unanchored form.** This is the second case where the shape, not the corpus,
was narrowed. The naive query — any interface with an empty body — reported 9
findings on rxjs, **every one of them the same deliberate idiom**: naming a
specialised generic so type errors print the short name
(`interface OperatorFunction<T, R> extends UnaryFunction<Observable<T>, Observable<R>> {}`,
`src/internal/types.ts:30`; `interface AjaxTimeoutError extends AjaxError {}`,
`src/internal/ajax/errors.ts:78`). 0.1229 is inside the `info` budget, so the
naive rule would have *passed the gate while reporting nothing but noise* —
which is the argument for reading the findings and not only the rate. The
anchored form is also what upstream settled on: `no-empty-object-type` permits
the `extends` case by default.

**Disposition.** **Expressible.**

---

### 14. `maintainability.typescript.unnecessary-type-constraint`

**Pitfall.** `<T extends any>` and `<T extends unknown>` constrain nothing —
every type already satisfies them — so the constraint is decoration that reads
as a restriction.

**Concept source.** typescript-eslint — `no-unnecessary-type-constraint` (MIT).
Concept only; no text taken.

**Severity.** `info`.

**Query** (verified):

```scheme
((type_parameter constraint: (constraint (predefined_type) @t)) @report
 (#any-of? @t "any" "unknown"))
```

```typescript
// fires
function f<T extends any>(x: T): T {
  return x;
}

// does not fire
function f<T extends string>(x: T): T {
  return x;
}
```

**Expected noise: 0.0000 on all three (measured).** The one idiom with a real
motive is `<T extends unknown>` written in a `.tsx` file to stop the parser
reading `<T>` as a JSX tag. That motive does not exist in `.ts`, and this
document is bound to the non-TSX grammar — but `lang.rs` routes `.tsx` here too,
so a repository with `.tsx` sources is where this rule would first report
something deliberate. None of the three pinned repositories has meaningful
`.tsx`, so that arm of the noise judgement is **unverified**.

**Disposition.** **Expressible.**

---

### 15. `maintainability.typescript.literal-type-assertion`

**Pitfall.** `'x' as 'x'` asserts a literal to its own literal type. It is the
long way round to `as const`, and it stops being correct the moment the literal
is edited and the assertion is not.

**Concept source.** typescript-eslint — `prefer-as-const` (MIT). Concept only;
no text taken.

**Severity.** `info`.

**Query** (verified):

```scheme
((as_expression [(string) (number) (true) (false)] @v (literal_type [(string) (number) (true) (false)] @t)) @report
 (#eq? @v @t))
```

```typescript
// fires
const a = 'x' as 'x';

// does not fire
const a = 'x' as const;
const b = 1 as 2;
```

This uses capture-to-capture `#eq?` (`TextPredicateCapture::EqCapture`), the
same facility the shipped self-assignment and identical-branch rules depend on,
here comparing an expression's text against a type's text across the `as`.
`1 as 2` is the near-miss the comparison has to reject, and does.

**Expected noise: 0.0000 on all three (measured).** No idiom produces it
deliberately; `as const` is strictly better and is what every style guide asks
for. Rate is zero because the mistake is genuinely uncommon, not because the
query is narrow.

**Disposition.** **Expressible.**

---

### 16. `maintainability.typescript.triple-slash-reference`

**Pitfall.** `/// <reference path="..." />` is the pre-modules way to pull in a
declaration file. It is invisible to the module graph, and in a codebase with
`import` it is a second dependency mechanism nobody greps for.

**Concept source.** typescript-eslint — `triple-slash-reference` (MIT). Concept
only; no text taken.

**Severity.** `info`.

**Query** (verified):

```scheme
((comment) @report (#match? @report "^///[ ]*<reference"))
```

```typescript
// fires
/// <reference path="./x.d.ts" />

// does not fire
// see /// <reference in the docs
```

**This item settles a question the 2.1 matrix left as an assumption.** The
matrix routed `ts-suppression-comment` to a `regex` payload on the reasoning
that "tree-sitter keeps comments as opaque tokens, so a query cannot inspect
their text without a `#match?` on a comment node". That is true of the mechanism
and wrong about the conclusion: `#match?` **is** in the loader's text-predicate
set, the pattern compiles, and it is anchored to a comment node — which is
strictly more precise than a bare regex over the file, because it cannot match
inside a string literal. The negative above proves the anchoring earns its keep:
a prose comment quoting the directive does not match, and the `^` anchor is
evaluated against the comment's own text, not the line's. **Any comment-shaped
rule in any language can be an `ast` rule.** Regex remains right only where the
signal must reach files that have no grammar, which is the actual argument for
`maintainability.todo-marker`.

**Expected noise: 0.0546 per kLOC on rxjs (4 findings), 0.0094 on nest, 0.0000
on zod (measured).** The idiom that produces noise is `/// <reference types="..." />`
at the top of a package entry point, where it is the sanctioned way to declare
an ambient dependency — rxjs's `src/index.ts:11` and `:12` are exactly that. If
the rate ever mattered, the narrowing is by shape (`path=` only, not `types=`),
not by path exclusion. At 0.0546 against a 1.0 budget it does not.

---

### 17. `reliability.typescript.async-without-await` — needs primitive

**Pitfall.** An `async` function with no `await` anywhere in its body wraps its
return value in a promise for no reason, and usually means an `await` was
deleted or never added.

**Concept source.** ESLint — `require-await` (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Why no query exists.** The evidence is an **absence**, and a tree-sitter
pattern can only assert presence. The nearest expressible pattern,
`((function_declaration "async") @report)`, matches every async function:
verified reporting on both the positive and the negative, one false positive out
of one negative. There is no arrangement of anchors, alternations or text
predicates that says "no descendant of this node is an `await_expression`" —
text predicates compare captured *text*, and every capture must first have
matched a node that exists.

**Primitive needed: a negated-descendant predicate.** Precisely: a query
predicate of the form `(#not-contains? @capture "node_type" ...)` that succeeds
when no node in the subtree rooted at `@capture` has any of the named types,
evaluated in `engines/ast.rs` after tree-sitter hands over the match. Node types
only — not a nested pattern — which keeps it a subtree walk with a type-set
membership test and no second query compilation. It must run after
`satisfies_text_predicates`, so it needs the same "reject this match" hook the
text predicates already use.

**Expected noise, were the primitive to land.** The idiom that would produce
noise is an `async` method that exists only to satisfy an interface whose other
implementations are asynchronous — common in nest-style dependency injection,
and a plausible source of findings the author would call intentional. This one
should be measured before it is trusted; it is not obviously cheap.

**Disposition.** **Needs primitive** — negated-descendant predicate.

---

### 18. `reliability.typescript.switch-case-fallthrough` — needs primitive

**Pitfall.** A `switch` case with statements that does not end in `break`,
`return`, `throw` or `continue` falls into the next case. Deliberate fallthrough
exists; unmarked fallthrough is the classic switch bug.

**Concept source.** ESLint — `no-fallthrough` (MIT). Concept only; no text
taken.

**Severity.** `warning`.

**Why no query exists.** The evidence is "the **last** child of this case is
**not** one of these node types" — a negation applied at a position. A query can
anchor a node as the last child (`(switch_case body: (_) . )` style), but it
cannot then assert the anchored node is *not* a `break_statement`; alternation
`[...]` is a positive union, and there is no complement operator. The nearest
expressible pattern, `((switch_case body: (expression_statement)) @report)`,
reported 2 findings on the correct negative as well as 2 on the positive —
verified false positives, because a case that ends in `break` still *contains*
an `expression_statement`.

**Primitive needed: a terminal-child anchor with a negated type set.**
Precisely: the ability to name the last named child of a captured node and
assert its type is outside a listed set — spelled, for example,
`(#last-child-not? @case "break_statement" "return_statement" "throw_statement" "continue_statement")`.
Like item 17 it is a post-match check in `engines/ast.rs` over the captured
node's own children, and it needs no new query syntax, only a new predicate name
in the allowlist and an evaluator.

**Cross-language weight.** This is the primitive with the strongest case under
#103's "three candidates across two languages" rule: switch fallthrough is the
same shape in C, C++, C#, Java and JavaScript, and Go's missing-final-return
uses the same terminal-child test on a function body. It clears the bar on this
item alone.

**Expected noise, were the primitive to land.** The idiom that would produce
noise is deliberate grouped fallthrough marked by a comment
(`// falls through`) — comments are not statements, so a comment-marked case
would still report, and the rule would need a comment-aware last-child rule or
a documented acceptance of that class.

**Disposition.** **Needs primitive** — terminal-child anchor with a negated type
set.

---

### 19. `reliability.typescript.array-constructor-arity` — needs primitive

**Pitfall.** `new Array(1, 2, 3)` builds `[1, 2, 3]`; `new Array(3)` builds a
sparse array of length three. One argument means something entirely different
from two, and the reader has to count to know which.

**Concept source.** ESLint — `no-array-constructor` (MIT). Concept only; no text
taken.

**Severity.** `warning`.

**Why no query exists.** The rule is only correct for an argument count other
than one, and a query has no arithmetic. The nearest expressible pattern,
`((new_expression constructor: (identifier) @c) @report (#eq? @c "Array"))`,
reports on the legitimate `new Array(10)` preallocation: verified, one false
positive out of one negative. Enumerating counts by hand-writing patterns for
zero, two, three, four arguments is the same trap `maintainability.nesting-depth`
was moved to the metric engine to escape.

**Primitive needed: a named-child-count predicate.** Precisely:
`(#child-count? @capture <op> N)` over the named children of the captured node,
with `<op>` one of the comparison operators. Evaluated in `engines/ast.rs`
against `Node::named_child_count()`, so it is O(1) per match.

**Cross-language weight.** Weakest of the three. The counting the profiles
actually need is already served by the `metric` engine at function granularity,
and arity rules in the other languages (`assertEquals` misuse in Java and C#)
are a thinner seam than switch fallthrough. Named here for completeness; it
should not carry the bounded engine addition on its own.

**Expected noise, were the primitive to land.** The idiom that would produce
noise is `new Array(n)` preallocation, and the count predicate is precisely what
removes it.

**Disposition.** **Needs primitive** — named-child-count predicate.

---

### 20. `reliability.typescript.floating-promise` — inexpressible

**Pitfall.** Calling an async function and discarding the promise means a
rejection becomes an unhandled rejection and the sequencing the author intended
does not happen. It is the single most-flagged TypeScript mistake in review.

**Concept source.** typescript-eslint — `no-floating-promises` (MIT). Concept
only; no text taken.

**Severity.** `warning`, if it could ship.

**Why it is inexpressible.** The finding requires knowing that the *call's
return type* is a promise. That is not in the syntax: `doThing();` as a bare
expression statement is the same tree whether `doThing` returns `void`, a
number, or `Promise<void>`, and the declaration that would say which is usually
in another file. This is the boundary #103 draws — type-aware and cross-file
analysis — and no single-file primitive moves it. Restricting the rule to calls
syntactically marked async (`(await_expression)` absent from a statement whose
callee name matches `/^(fetch|load|save|.*Async)$/`) trades a type check for a
naming convention and would report on every synchronous function whose name
happens to end in `Async`.

The same verdict covers the rest of typescript-eslint's type-aware set —
`no-unnecessary-type-assertion`, `no-misused-promises`,
`no-unsafe-enum-comparison`, `no-unnecessary-condition` — and it is the honest
answer for all of them: **inexpressible under the engine boundary**, not
"pending a primitive".

**Disposition.** **Inexpressible** — requires type information.

---

## Primitives, and which items need them

| Primitive | Precise shape | Items here | Recommendation |
| --- | --- | --- | --- |
| Negated-descendant predicate | `(#not-contains? @cap "type" ...)` — no node of these types anywhere under `@cap`, checked in `engines/ast.rs` after `satisfies_text_predicates` | 17 | Wait for the other #103 language tickets. Empty-catch-with-no-comment (Java, C#, C++, Python) and require-await (JavaScript) plausibly clear the three-across-two bar with it, but none of those is mine to count. |
| Terminal-child anchor with a negated type set | `(#last-child-not? @cap "type" ...)` — the last **named** child's type is outside the set | 18 | **The strongest candidate.** Switch fallthrough is the same shape in C, C++, C#, Java and JavaScript, and Go's missing-final-return reuses it. It clears #103's bar on this item alone. |
| Named-child-count predicate | `(#child-count? @cap <op> N)` over `Node::named_child_count()` | 19 | Named for completeness. Do not spend the bounded engine addition here; the `metric` engine already covers the counting the profiles need. |

**Not needed, contrary to #103's guess.** The map lists "sibling-aware matching"
as a candidate primitive. Item 9 shows tree-sitter already binds unanchored
sibling captures to *distinct* nodes, so duplicate-key, duplicate-case and
duplicate-member rules need nothing new — in any language. Anchors also cover
"nothing between these two children" (item 13) and "these two tokens are
adjacent", which between them replace most of what sibling-awareness was wanted
for.

**Also not needed.** "Scope tracking within a function", the map's other guess,
is not requested by anything in this list. The rules that would use it —
`no-unused-vars`, `prefer-const`, `no-shadow` — are compiler and language-server
territory in TypeScript, reported by `tsc` itself, and duplicating them in a
profile is not worth an engine.

## 2.1 removals and held-out candidates, revisited

#108 asks that a 2.1 removal return only if a named primitive fixes its failure
mode. Two of them are fixed by **shape**, not by a primitive, so they are
recorded here rather than as numbered items — the decision is the ticket
owner's.

| 2.1 rule | 2.1 failure mode | Status now |
| --- | --- | --- |
| `reliability.typescript.any-assertion` | 10 per kLOC on zod | **Stays out.** No primitive helps. `as any` is frequent in a type-library's own internals by construction, and narrowing the shape cannot separate a library's deliberate escape hatch from an application's. |
| `reliability.typescript.ts-suppression-comment` | 5 per kLOC on test files | **Stays out** on noise. But its stated *reason* for being a `regex` rule is wrong — see item 16: `#match?` on a `(comment)` node compiles, is in the text-predicate set, and is more precise than a file-wide regex. Worth correcting in the matrix whatever happens to the rule. |
| `reliability.typescript.loose-equality` | "the query cannot separate `x == null` from an accidental coercion" | **Fixed by shape, no primitive.** `#not-eq?` on both operands against `"null"` and `"undefined"` does exactly that separation. Verified against four negatives. **Measured: 0.1093 per kLOC on rxjs, 0.0189 on nest, 0.0000 on zod** — inside the 0.25 `warning` budget on all three. Query: `((binary_expression left: (_) @l operator: ["==" "!="] right: (_) @r) @report (#not-eq? @l "null") (#not-eq? @r "null") (#not-eq? @l "undefined") (#not-eq? @r "undefined"))`. |
| `reliability.typescript.unreachable-after-return` | "a hoisted `function` declaration after `return` is legal and idiomatic" | **Fixed by shape, no primitive.** Anchor a positive alternation of non-hoisted statement types immediately after the `return`, and hoisted declarations simply do not match. Verified against three negatives including the hoisted-helper case. **Measured: 0.0000 on all three.** Query: `((statement_block (return_statement) . [(expression_statement) (if_statement) (for_statement) (while_statement) (switch_statement) (try_statement) (return_statement) (throw_statement) (lexical_declaration) (variable_declaration)]) @report)`. |
| `reliability.typescript.empty-catch` | intentional empty catches | **Stays out.** The narrowing that would help — "empty and not commented" — is the negated-descendant primitive of item 17, and even then an empty catch with a comment is the majority case, so the rule would report mostly intent. |
| `maintainability.typescript.empty-function-body` | idiomatic no-op callbacks | **Stays out.** Same reasoning; no primitive changes that empty callbacks are deliberate. |
| `reliability.typescript.non-null-assertion` | `!` is TypeScript's `unwrap()` | **Superseded.** Items 7 and 8 ship the two narrow, unambiguous slices of it — doubled assertions and assertion-on-optional-chain — at 0.0000 and 0.0094. The broad rule stays out. |

## Candidates measured and not proposed

Verified as queries and measured, but left off the list — recorded so the
decision is not re-litigated.

| candidate | max per kLOC | why not |
| --- | --- | --- |
| `this-alias` (typescript-eslint `no-this-alias`, MIT) | 0.1633 (zod) | Inside `info` budget, but all 12 findings across the three repos are deliberate closure captures in class methods. Reports intent, not mistakes. |
| `useless-constructor` (ESLint `no-useless-constructor`, MIT) | 0.0660 (nest) | Value depends on framework: nest's DI makes parameterless constructors meaningful in ways the query cannot see. |
| `new-wrapper-object` (ESLint `no-new-wrappers`, MIT) | 0.0189 (nest) | Clean rule, but both nest findings are tests asserting the behaviour, and the mistake is near-extinct in TypeScript. |
| `empty-destructuring-pattern` (ESLint `no-empty-pattern`, MIT) | 0.0000 | Correct and cheap; cut only to hold the list at twenty. Worth reconsidering. |
| `return-assignment` (ESLint `no-return-assign`, MIT) | 0.0137 (rxjs) | Overlaps item 6 conceptually; the parenthesised form that documents intent already escapes, so what remains is thin. |
| `compare-neg-zero` (ESLint `no-compare-neg-zero`, MIT) | 0.0000 | Correct, but the mistake is vanishingly rare and item 4 covers the comparison family. |
| `dynamic-code-eval` (ESLint `no-eval`, `no-new-func`, MIT) | 0.0000 | Correct, but overlaps the secrets/security remit rather than reliability, and `eval` is near-absent from typed codebases. |

## Reproducing this

1. Write each query into a one-rule document under a directory, `version: 1`,
   `severity`, `message`, and the query under `ast: { typescript: | }`.
2. Load it with `rules::load_str(src, "profile:probe")` and scan a temporary
   directory of `.ts` files with `scan::scan(dir, &RuleSet { rules, sources },
   None)`. A `LOAD-ERROR` is the loader rejecting the query — an unsupported
   predicate or a `Query error` such as `Impossible pattern` from a field the
   grammar does not have on that node.
3. Assert at least one finding on the positive file and zero on every negative.
4. For noise, shallow-clone the three pinned TypeScript rows from
   `noise-set.md` and run
   `target/release/siloscan REPO --rules <dir> --no-default-rules --no-cache
   --format json`, dividing each rule's finding count by the repository's
   `.ts`/`.tsx` `code_lines` summed from `metrics.files`.

Use `CARGO_TARGET_DIR=/home/dev/projects/siloscan/target` so the grammars are
not rebuilt.

## Boundary notes for the map

- **`.tsx` is scanned by the non-TSX grammar.** `lang.rs:115` routes `.tsx` to
  `typescript` and `parsers.rs:41` binds `LANGUAGE_TYPESCRIPT`. Every rate above
  comes from repositories with no meaningful `.tsx`, so the noise numbers say
  nothing about a React codebase — which is where a TypeScript profile will most
  often be pointed. **A fourth pinned repository with real `.tsx` is the gap
  #103 asks about for TypeScript.** Item 14's noise judgement is explicitly
  unverified without one.
- **A rate inside budget is not a clean rule.** Item 13 would have passed the
  gate at 0.1229 while reporting nine deliberate uses and zero mistakes. The
  per-rule measurement discipline should read the findings, not only divide
  them.
