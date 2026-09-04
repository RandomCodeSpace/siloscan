# JavaScript pitfall list

Research for issue #107, under the wayfinder map #103. This document decides
*what the javascript rules would be* for 2.2. It writes no rule YAML and no
engine code.

Grammar: `tree-sitter-javascript` 0.25.0, the version pinned in
`crates/siloscan-core/Cargo.toml`, read from
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tree-sitter-javascript-0.25.0/src/node-types.json`.
Query engine: `tree-sitter` 0.26.11.

Every query below was verified through the product's own loader and scanner —
`rules::load_str` under a profile identity, then `scan::scan` over a temporary
directory holding the snippet — using a throwaway test modelled on the in-test
document pattern in `crates/siloscan-core/tests/profile_corpus.rs`. The harness
was not committed. See [Verification](#verification) for the run.

Every concept source is a concept-only citation. No pattern text, query text or
message text is taken from any upstream project.

## What this list excludes

- **Already shipped.** `reliability.javascript.self-assignment`,
  `reliability.javascript.identical-if-branches`,
  `reliability.javascript.debugger-statement`,
  `reliability.javascript.constant-condition`, and the four
  `maintainability.javascript.*` metric rules. Item 15 below extends the
  shipped self-assignment rule to a node shape it does not reach; it is a new
  id, not a change to the shipped one.
- **2.1 removals.** `self-comparison`, `empty-catch`, `unreachable-after-return`
  and `loose-equality` are handled in
  [2.1 removals re-examined](#21-removals-re-examined), not in the twenty.

## Summary

18 of the 20 items are expressible today with a single-file query and no engine
change. Two need one primitive, and that primitive has a third and fourth
candidate behind it.

| # | id | severity | disposition | expected noise |
| --- | --- | --- | --- | --- |
| 1 | `reliability.javascript.async-promise-executor` | warning | expressible | none expected |
| 2 | `reliability.javascript.assignment-in-condition` | warning | expressible | **at risk**: the `while (m = re.exec(s))` scan loop |
| 3 | `reliability.javascript.duplicate-object-key` | warning | expressible | none expected |
| 4 | `reliability.javascript.duplicate-else-if-condition` | warning | expressible | none expected |
| 5 | `reliability.javascript.duplicate-switch-case` | warning | expressible | none expected |
| 6 | `reliability.javascript.compare-neg-zero` | warning | expressible | none expected |
| 7 | `reliability.javascript.invalid-typeof-comparison` | warning | expressible | low: the legacy `typeof x === "unknown"` ActiveX guard |
| 8 | `reliability.javascript.sparse-array-hole` | warning | expressible | low: sparse-array fixtures in a library's own test tree |
| 9 | `reliability.javascript.empty-destructuring-pattern` | warning | expressible | low: `function f({} = {})` as an ignore-the-argument placeholder |
| 10 | `reliability.javascript.throw-literal` | warning | expressible | low: sentinel-string throws used as early-exit control flow |
| 11 | `reliability.javascript.return-in-finally` | warning | expressible | none expected |
| 12 | `reliability.javascript.unsafe-negation` | warning | expressible | none expected |
| 13 | `reliability.javascript.dynamic-code-execution` | warning | expressible | low: a REPL or sandbox whose job is evaluating source |
| 14 | `reliability.javascript.prototype-builtin-call` | warning | expressible | **at risk**: pre-`Object.hasOwn` code calling `o.hasOwnProperty(k)` directly |
| 15 | `reliability.javascript.self-assignment-member` | warning | expressible | none expected |
| 16 | `reliability.javascript.new-wrapper-object` | warning | expressible | none expected |
| 17 | `reliability.javascript.setter-returns-value` | warning | expressible | none expected |
| 18 | `maintainability.javascript.nested-ternary-in-consequence` | info | expressible | low: dense formatting-and-units expressions |
| 19 | `reliability.javascript.async-function-without-await` | warning | needs primitive **P1** | unbounded without P1 |
| 20 | `reliability.javascript.getter-without-return` | warning | needs primitive **P1** | unbounded without P1 |

Noise column is a judgement, not a measurement: the pinned noise set in
`research/embedded-profiles/noise-set.md` was not cloned for this ticket, and
`scripts/profile_noise.py` is the thing that settles it at implementation time.
Two items are marked **at risk** because a named idiom puts them near or over
the 0.25 per kLOC `warning` gate on a real tree; those two want their
measurement before anything else in the list.

---

## 1. `reliability.javascript.async-promise-executor`

An `async` function passed as the `Promise` executor swallows its own
rejections: a throw inside it rejects the executor's invisible promise, not the
one being constructed.

- Concept source: eslint — `no-async-promise-executor` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((new_expression constructor: (identifier) @c arguments: (arguments [(arrow_function) (function_expression)] @f)) @report (#eq? @c "Promise") (#match? @f "^async[ (]"))
```

The grammar exposes `async` only as an anonymous token inside the function
node, and an anonymous token cannot be required from outside the node it
belongs to, so the `async` prefix is read off the executor's own text with
`#match?`. The `[ (]` tail is what stops it matching an identifier named
`asyncHandler` passed by reference.

```javascript
// fires
const p = new Promise(async (res) => { await g(); res(1); });
const p = new Promise(async function (res) { await g(); res(1); });

// does not fire
const p = new Promise((res) => { res(1); });
const p = new Promise(asyncHelper);
const p = new Deferred(async (res) => { await g(); });
```

Expected noise: none. There is no idiom that wants an async executor; the shape
is the bug. Disposition: **expressible**.

## 2. `reliability.javascript.assignment-in-condition`

An assignment used where a comparison was meant: `if (a = b)` always takes the
branch when `b` is truthy.

- Concept source: eslint — `no-cond-assign` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
([(if_statement condition: (parenthesized_expression (assignment_expression))) (while_statement condition: (parenthesized_expression (assignment_expression)))] @report)
```

Wrapping the assignment in a second pair of parentheses is the opt-out, and it
works structurally rather than by convention: `if ((a = b))` puts an inner
`parenthesized_expression` between the condition and the assignment, so the
pattern no longer matches.

```javascript
// fires
if (a = b) { return 1; }
while (m = re.exec(s)) { g(m); }

// does not fire
if (a === b) { return 1; }
if ((a = b)) { return 1; }
while ((m = re.exec(s))) { g(m); }
```

Expected noise: **at risk**. The idiom is the regex scan loop,
`while (m = re.exec(s))`, written without the extra parentheses — the single
place in JavaScript where an assignment in a condition is deliberate. A
template compiler or tokeniser writes several of them in one file. This wants
the measurement before it ships. Disposition: **expressible**.

## 3. `reliability.javascript.duplicate-object-key`

The same key written twice in one object literal: the later value silently wins
and the earlier one is dead.

- Concept source: eslint — `no-dupe-keys` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((object (pair key: (property_identifier) @a) (pair key: (property_identifier) @b)) @report (#eq? @a @b))
```

Two unanchored sibling patterns bind two *distinct* nodes — verified, not
assumed: `{ a: 1, b: 2 }` does not match, which it would if a single pair could
satisfy both `@a` and `@b`. A nested object with a repeated key across the
nesting boundary does not match either, because both pairs must be children of
the same `object`.

```javascript
// fires
const o = { a: 1, b: 2, a: 3 };
const o = { a: 1, a: 2 };

// does not fire
const o = { a: 1, b: 2 };
const o = { a: 1, n: { a: 2 } };
const o = { [k]: 1, [k]: 2 };
const o = { a, a };
```

Expected noise: none. The last two negatives are undercoverage rather than
noise: computed keys and shorthand properties are different node shapes and
this query does not reach them. Disposition: **expressible**.

## 4. `reliability.javascript.duplicate-else-if-condition`

An `else if` repeating the condition of the `if` above it: the second branch is
unreachable.

- Concept source: eslint — `no-dupe-else-if` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((if_statement condition: (parenthesized_expression) @c alternative: (else_clause (if_statement condition: (parenthesized_expression) @d))) @report (#eq? @c @d))
```

```javascript
// fires
if (a === 1) { return 1; } else if (a === 1) { return 2; }

// does not fire
if (a === 1) { return 1; } else if (a === 2) { return 2; }
```

Expected noise: none. `#eq?` on two captures compares source text, so the match
is byte-identical condition text, which is a copy-paste error and not a style.
Disposition: **expressible**.

## 5. `reliability.javascript.duplicate-switch-case`

Two `case` labels with the same value in one `switch`: the second is dead.

- Concept source: eslint — `no-duplicate-case` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((switch_body (switch_case value: (_) @a) (switch_case value: (_) @b)) @report (#eq? @a @b))
```

```javascript
// fires
switch (x) { case 1: return 1; case 1: return 2; }

// does not fire
switch (x) { case 1: return 1; case 2: return 2; }
switch (x) { case 1: case 2: return 1; }
switch (x) { case 1: return 1; } switch (y) { case 1: return 2; }
```

Expected noise: none. Grouped labels — the one legitimate shape that looks like
a duplicate — carry different values and do not match; the last two negatives
prove the same-value-different-switch case is scoped out by the shared
`switch_body` parent. Disposition: **expressible**.

## 6. `reliability.javascript.compare-neg-zero`

Comparing against `-0` with `===`: the comparison is true for `+0` too, so the
sign the author cared about is exactly what the operator throws away.

- Concept source: eslint — `no-compare-neg-zero` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((binary_expression operator: ["===" "==" "!==" "!=" ">=" "<="] right: (unary_expression operator: "-" argument: (number) @n)) @report (#eq? @n "0"))
```

```javascript
// fires
return x === -0;

// does not fire
return Object.is(x, -0);
return x === -1;
return x === 0;
return x < -0;
```

Expected noise: none. `Object.is(x, -0)` is the correct spelling and is a call,
not a comparison. Ordering operators other than `>=`/`<=` are left out because
`x < -0` is just `x < 0` and carries no mistake. Disposition: **expressible**.

## 7. `reliability.javascript.invalid-typeof-comparison`

`typeof x` compared against a string that `typeof` can never return: a typo
that makes the branch permanently dead.

- Concept source: eslint — `valid-typeof` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((binary_expression left: (unary_expression operator: "typeof") operator: ["===" "==" "!==" "!="] right: (string (string_fragment) @s)) @report (#not-any-of? @s "undefined" "object" "boolean" "number" "string" "function" "symbol" "bigint"))
```

`#not-any-of?` is in the loader's accepted predicate set, and the eight values
are the complete `typeof` result set for the language.

```javascript
// fires
return typeof x === "strnig";
return typeof x !== "Function";

// does not fire
return typeof x === "string";
return typeof x === "bigint";
return typeof x === t;
return x.kind === "strnig";
```

Expected noise: low. The idiom is the legacy Internet Explorer host-object
guard `typeof x === "unknown"`, which was a real `typeof` result in JScript and
still appears in shims kept for old browsers. A tree carrying one of those
carries a handful. Disposition: **expressible**.

## 8. `reliability.javascript.sparse-array-hole`

An elision in an array literal — `[1, , 2]` — which produces a hole rather than
`undefined`, and holes and `undefined` behave differently under `map`, `forEach`
and spread.

- Concept source: eslint — `no-sparse-arrays` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
[(array "," . ",") (array "[" . ",")] @report
```

Two patterns, because the leading hole `[, 1]` has only one comma and is
detected against the opening bracket instead. The engine de-duplicates on
`(rule id, start, end)`, so a literal that satisfies both reports once —
confirmed with a two-pattern probe that reports one finding, not two.

```javascript
// fires
const a = [1, , 2];
const a = [, 1];

// does not fire
const a = [1, 2];
const a = [1, 2, ];
const a = [];
const a = [...b, 1];
```

Expected noise: low. The idiom is a library's own test fixtures for sparse-array
handling, which contain holes deliberately and in bulk. If it breaches, the
document header's one allowed `paths` exclusion for test trees is the answer —
the same exclusion `maintainability.javascript.function-length` already carries.
Disposition: **expressible**.

## 9. `reliability.javascript.empty-destructuring-pattern`

`const {} = o` or `function f({})`: destructuring that binds nothing, which is
almost always a default value that was meant to be a pattern.

- Concept source: eslint — `no-empty-pattern` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
(object_pattern "{" . "}") @report
```

The `"{" . "}"` anchor is the same construction the profile's empty-body rules
use across the other nine languages.

```javascript
// fires
function f({}) { return 1; }
const {} = o;

// does not fire
function f({ a }) { return a; }
const o = {};
const { a = {} } = o;
function f({ a } = {}) { return a; }
```

Expected noise: low. The idiom is `function f({} = {})` written as an
accept-an-object-and-ignore-it placeholder, which is rare but real in adapter
code. `const o = {}` and a `= {}` default are different node shapes and do not
match. Disposition: **expressible**.

## 10. `reliability.javascript.throw-literal`

Throwing a string, number or template literal instead of an `Error`: the value
carries no stack, and every `catch` that reads `e.message` gets `undefined`.

- Concept source: eslint — `no-throw-literal` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
(throw_statement [(string) (number) (template_string)] @report)
```

```javascript
// fires
throw "bad";
throw `bad ${x}`;

// does not fire
throw new Error("bad");
throw e;
throw makeError("bad");
```

Expected noise: low. The idiom is the sentinel throw used as early-exit control
flow — a parser or a tree walker that throws a fixed string to unwind, catches
it one frame up and compares it by identity. Disposition: **expressible**.

## 11. `reliability.javascript.return-in-finally`

A `return`, `break` or `continue` directly inside `finally`: it discards the
pending return value, and it discards a pending exception silently.

- Concept source: eslint — `no-unsafe-finally` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
(finally_clause body: (statement_block [(return_statement) (break_statement) (continue_statement)] @report))
```

Direct children of the `finally` block only. A `return` inside a callback
defined in the block belongs to that callback and does not match — verified.

```javascript
// fires
try { return g(); } finally { return 1; }

// does not fire
try { return g(); } finally { cleanup(); }
try { return g(); } finally { if (x) { h(); } }
try { return g(); } finally { const done = () => { return 1; }; done(); }
```

Expected noise: none. Being restricted to direct children costs recall — a
`return` nested one `if` deep in the `finally` is the same bug and is missed —
which is under-reporting, not noise, and is one of the cases behind primitive
**P2** below. Disposition: **expressible**.

## 12. `reliability.javascript.unsafe-negation`

`!k in o` and `!o instanceof C`: `!` binds tighter than `in` and `instanceof`,
so the left operand is a boolean and the test is always false.

- Concept source: eslint — `no-unsafe-negation` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
(binary_expression left: (unary_expression operator: "!") operator: ["in" "instanceof"]) @report
```

```javascript
// fires
return !k in o;
return !o instanceof C;

// does not fire
return !(k in o);
return !(o instanceof C);
return k in o;
return !a === b;
```

Expected noise: none. There is no reading of `!k in o` that anyone wants.
Disposition: **expressible**.

## 13. `reliability.javascript.dynamic-code-execution`

`eval(...)`, `new Function(...)`, and `setTimeout`/`setInterval` given a string
first argument: source text compiled at runtime, which defeats every static
check the file otherwise gets.

- Concept source: eslint — `no-eval`, `no-implied-eval`, `no-new-func` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
[((call_expression function: (identifier) @f) @report (#eq? @f "eval")) ((call_expression function: (identifier) @g arguments: (arguments . [(string) (template_string)])) @report (#any-of? @g "setTimeout" "setInterval")) ((new_expression constructor: (identifier) @h) @report (#eq? @h "Function"))]
```

Three concepts in one id because they are one review comment. Each predicate
sits inside its own outer parenthesis pair, which is what binds it to its own
pattern rather than to the alternation. The `.` anchor on `arguments` is what
restricts the string test to the *first* argument, so `setTimeout(g, 10, "arg")`
does not match.

```javascript
// fires
return eval(s);
setTimeout("g()", 10);
setInterval(`g()`, 10);
const f = new Function("a", "return a;");

// does not fire
return evaluate(s);
return o.eval(s);
setTimeout(() => g(), 10);
setTimeout(g, 10, "arg");
const f = new FunctionCache();
```

Expected noise: low. The idiom is a REPL, a sandbox or a template compiler
whose job is evaluating source. Deliberately *not* covered is the bare
`Function("return this")()` global-object shim that older libraries carry: it
is a call rather than a `new`, so it does not match, and that shim is the single
most common benign hit this rule could otherwise take.
Disposition: **expressible**.

## 14. `reliability.javascript.prototype-builtin-call`

Calling `hasOwnProperty`, `isPrototypeOf` or `propertyIsEnumerable` directly on
an object: it throws on a null-prototype object and it is shadowable by a
property of the same name, which is exactly the untrusted-input case the call
is usually guarding.

- Concept source: eslint — `no-prototype-builtins` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((call_expression function: (member_expression object: (_) property: (property_identifier) @p)) @report (#any-of? @p "hasOwnProperty" "isPrototypeOf" "propertyIsEnumerable"))
```

```javascript
// fires
return o.hasOwnProperty(k);

// does not fire
return Object.prototype.hasOwnProperty.call(o, k);
return Object.hasOwn(o, k);
const has = Object.prototype.hasOwnProperty;
```

The safe spellings are structurally different: the `.call` form makes `call` the
called property, and an uncalled reference is not a `call_expression` at all.

Expected noise: **at risk**. The idiom is direct `o.hasOwnProperty(k)` in any
library written before `Object.hasOwn`, on an object the author knows is a plain
literal. A utility library of that vintage will carry many. This one wants the
measurement. Disposition: **expressible**.

## 15. `reliability.javascript.self-assignment-member`

`this.a = this.a`: the property-assignment form of a self-assignment, which the
shipped `reliability.javascript.self-assignment` rule does not reach because it
requires an `identifier` on both sides.

- Concept source: eslint — `no-self-assign` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((assignment_expression left: (member_expression) @l right: (member_expression) @r) @report (#eq? @l @r))
```

```javascript
// fires
this.a = this.a;
o.x.y = o.x.y;

// does not fire
this.a = b.a;
o.a = o.b;
o[i] = o[i];
```

Expected noise: none. `o[i] = o[i]` is deliberately out of scope: a
`subscript_expression` with a variable index is an in-place array copy whose two
sides can denote different elements over time, so including it would be wrong
rather than merely noisy. Disposition: **expressible**.

## 16. `reliability.javascript.new-wrapper-object`

`new String(...)`, `new Number(...)`, `new Boolean(...)`: an object wrapper
rather than a primitive, so `typeof` reports `"object"` and `new Boolean(false)`
is truthy. `new Symbol()` and `new BigInt()` throw outright.

- Concept source: eslint — `no-new-wrappers`, `no-new-native-nonconstructor` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
((new_expression constructor: (identifier) @c) @report (#any-of? @c "String" "Number" "Boolean" "Symbol" "BigInt"))
```

```javascript
// fires
const s = new String("x");
const n = new Number(1);

// does not fire
const s = String(1);
const s = Symbol("x");
const s = new Set();
```

Expected noise: none. The conversion spellings are bare calls and do not match.
Disposition: **expressible**.

## 17. `reliability.javascript.setter-returns-value`

`return v` inside a setter: the value is discarded, and writing it says the
author expected the assignment expression to yield it.

- Concept source: eslint — `no-setter-return` (MIT). Concept only; no text taken.
- Severity: `warning`.

```scheme
(method_definition "set" body: (statement_block (return_statement (_)) @report))
```

Requiring a child of the `return_statement` is what keeps the bare early-exit
`return;` — which is legal and common in a validating setter — out.

```javascript
// fires
class C { set x(v) { return v; } }

// does not fire
class C { set x(v) { this._x = v; } }
class C { set x(v) { if (!v) { return; } this._x = v; } }
class C { get x() { return this._x; } }
```

Expected noise: none. Disposition: **expressible**.

## 18. `maintainability.javascript.nested-ternary-in-consequence`

A ternary nested in the *consequence* of another ternary: the reader has to
track two conditions to know which of four values they are looking at.

- Concept source: eslint — `no-nested-ternary` (MIT). Concept only; no text taken.
- Severity: `info`.

```scheme
(ternary_expression consequence: [(ternary_expression) (parenthesized_expression (ternary_expression))]) @report
```

This deliberately narrows the upstream concept. Nesting in the *alternative* —
`a ? 1 : b ? 2 : 3` — is the chained-ternary idiom, reads top to bottom like a
`switch`, and is the overwhelming majority of nested ternaries in modern
JavaScript; flagging it is what makes the general rule unusable. Only the
consequence form fires.

```javascript
// fires
const x = a ? (b ? 1 : 2) : 3;
const x = a ? b ? 1 : 2 : 3;

// does not fire
const x = a ? 1 : b ? 2 : 3;
const x = a ? 1 : 2;
```

Expected noise: low. The idiom that could still produce some is the dense
formatting-and-units expression — a size or duration formatter that genuinely
branches two deep in the consequence. `info`, so the budget is 1.0 per kLOC.
Disposition: **expressible**.

## 19. `reliability.javascript.async-function-without-await`

An `async` function with no `await` in it: it returns a promise for no reason,
and it usually means an `await` was dropped during an edit.

- Concept source: eslint — `require-await` (MIT). Concept only; no text taken.
- Severity: `warning`.

**No query exists.** The rule is the *absence* of a node kind beneath another
node, and the query language has no negation. The closest expressible query
matches every `async` function, correct ones included:

```scheme
(function_declaration "async" body: (statement_block) @report)
```

```javascript
// fires (correctly)
async function f() { return 1; }

// also fires (wrongly) — this function is right
async function f() { await g(); return 1; }
```

Verified: the second snippet reports, which is the failure. Expected noise:
unbounded — every correct `async` function in the tree, which in a promise-heavy
library is most of them.

Disposition: **needs primitive P1** (`#lacks-descendant?`, defined below).

## 20. `reliability.javascript.getter-without-return`

A getter with no `return` in it: reading the property yields `undefined`, which
is never what a getter is for.

- Concept source: eslint — `getter-return` (MIT). Concept only; no text taken.
- Severity: `warning`.

**No query exists**, for the same reason as item 19. The closest expressible
query matches every getter:

```scheme
(method_definition "get" body: (statement_block) @report)
```

```javascript
// fires (correctly)
class C { get x() { this.touch(); } }

// also fires (wrongly) — this getter is right
class C { get x() { return this._x; } }
```

Verified: the second snippet reports. Expected noise: unbounded — every correct
getter.

Disposition: **needs primitive P1**.

---

## Primitives

### P1 — `#lacks-descendant?`, an absence predicate

A predicate the AST engine evaluates after tree-sitter's own text predicates,
failing the match when the node bound to a capture contains a descendant of any
of the named kinds:

```
(#lacks-descendant? @capture "await_expression")
```

Shape and bounds, so it stays inside the engine boundary #103 sets:

- One subtree walk per candidate match, over one file. No symbol table, no
  cross-file state, no type information.
- It is not one of tree-sitter's text predicates, so it cannot go through
  `QueryMatch::satisfies_text_predicates`. `rules.rs` rejects any predicate
  outside the text-predicate set at load, so admitting it is a change to the
  loader's accepted set as well as to `engines/ast.rs`.
- **The walk must stop at nested function boundaries.** `async function f() { g(async () => { await h(); }); }`
  has an `await_expression` descendant that belongs to the inner arrow function,
  not to `f`. Without a boundary set the primitive silently under-reports; with
  one it is correct. The boundary set is per-call, alongside the kind list.

Candidates behind it — three in JavaScript, and the same three again in
TypeScript, which clears the "three candidates across two languages" bar #103
sets for an engine addition:

| candidate | capture | absent kind | boundary |
| --- | --- | --- | --- |
| item 19, `async-function-without-await` | function body | `await_expression` | nested function nodes |
| item 20, `getter-without-return` | getter body | `return_statement` | nested function nodes |
| `constructor-missing-super` in a derived class (eslint `constructor-super`, MIT, concept only) | constructor body | `super` | nested function nodes |

The same primitive would also let the 2.1 `empty-catch` rule be rewritten as
"catch body with no statement and no comment", though as
[the removals section](#21-removals-re-examined) records, that is not what made
`empty-catch` unshippable.

### P2 — descendant matching for one pattern node

A pattern node that matches at any depth beneath its parent rather than as an
immediate child. Not required by any item in the twenty, and named here only
because it is the recurring cost behind their recall rather than their noise:

- item 11, `return-in-finally`, misses a `return` nested one `if` deep;
- `catch-parameter-reassigned` (eslint `no-ex-assign`, MIT, concept only) is
  expressible today *only* for an assignment that is a direct child of the catch
  block, which is verified and is the uncommon spelling —
  `catch (e) { if (x) { e = 1; } }` is missed;
- item 3, `duplicate-object-key`, is unaffected, because both pairs really are
  siblings.

Every one of these under-reports rather than over-reports, so none of them
breaches a noise gate. P2 buys recall, not shippability, and on that basis it
should lose to P1 if only one bounded addition is allowed.

---

## 2.1 removals re-examined

Issue #103 asks whether any 2.1 removal returns under a primitive that fixes
its failure mode. Two of the four JavaScript removals turn out to need no
primitive at all — the failure mode each removal note named is fixed by
enumerating node kinds in the query. Two are not fixable by any engine addition
inside the boundary.

### `reliability.javascript.unreachable-after-return` — fixed, no primitive

The 2.1 note: *"A hoisted `function` declaration written after `return` is still
reachable... the candidate query does not exclude it."* Naming the statement
kinds that are *not* hoisted does exclude it:

```scheme
(statement_block (return_statement) . [(expression_statement) (lexical_declaration) (variable_declaration) (return_statement) (if_statement) (for_statement) (for_in_statement) (while_statement) (do_statement) (switch_statement) (try_statement) (throw_statement) (break_statement) (continue_statement) (class_declaration) (statement_block) (empty_statement) (labeled_statement) (with_statement) (debugger_statement)] @report)
```

```javascript
// fires
function f() { return 1; const x = 2; }

// does not fire
function f() { const x = 2; return x; }
function f() { return g(); function g() { return 1; } }
function f() { return g(); function* g() { yield 1; } }
```

Both `function_declaration` and `generator_function_declaration` are outside the
alternation, and both negatives are verified.

One residual gap, also verified: a comment between the `return` and the dead
statement is a named sibling, so the `.` anchor no longer holds and
`function f() { return 1; /* why */ const x = 2; }` is missed. That is
under-reporting, not noise, and it does not breach the gate. A
comment-transparent anchor would close it, but it would have to be opt-in per
anchor — the empty-body rules across all ten shipped languages depend on the
current behaviour, where a comment in a `"{" . "}"` block is content and
suppresses the finding.

Recommendation: re-propose for 2.2 as `warning`, with a measurement.

### `reliability.javascript.loose-equality` — fixed, no primitive

The 2.1 note: *"`x == null` as a combined null/undefined check is deliberate...
the query cannot separate it from an accidental coercion."* Enumerating the
operand kinds on both sides separates them, because `null` and `undefined` are
their own node kinds in this grammar:

```scheme
((binary_expression left: [(identifier) (member_expression) (call_expression) (subscript_expression) (string) (number) (template_string) (true) (false) (this)] operator: ["==" "!="] right: [(identifier) (member_expression) (call_expression) (subscript_expression) (string) (number) (template_string) (true) (false) (this)]) @report)
```

```javascript
// fires
return a == b;

// does not fire
return a == null;
return a == undefined;
return null == a;
return a === b;
```

Expected noise: still the highest-count item in this document, because a
pre-`===` codebase writes `==` everywhere and the rule cannot tell a deliberate
coercion from an accidental one once `null` is out of the picture. The failure
mode the removal named is gone; whether the remainder fits 0.25 per kLOC is a
measurement, and on a library of that vintage it very likely does not.
Recommendation: re-measure, expect it to stay out.

### `reliability.javascript.self-comparison` — no primitive fixes it

Removed at 2.1.0 after 215 findings on lodash, 2.1939 per kLOC, all of them
`value === value` — the NaN test. This is a semantic distinction between two
byte-identical shapes, so no structural primitive reaches it. `#lacks-descendant?`
does not help; neither does scope tracking. It would need to know that the
author meant `Number.isNaN`, which is a mind-reading problem, not an engine one.
Recommendation: stays out permanently for JavaScript and TypeScript. The
matching note already in `reliability-typescript.yaml` should be copied into
`reliability-javascript.yaml`, which currently carries no removal record at all.

### `reliability.javascript.empty-catch` — no primitive fixes it

Removed at 2.1.0 after 454 findings on lodash, 4.6327 per kLOC. The removal note
is explicit that *"the findings are the shape the rule claims"* — the query was
correct and the shape is simply too common. A primitive changes what a query can
match, not how often a correct match occurs. Recommendation: stays out.

---

## Verified but not carried into the twenty

Four more queries were written and verified. Each is recorded so the
disposition is complete, and each is left out for the reason given.

| candidate | query | verified | left out because |
| --- | --- | --- | --- |
| `reliability.javascript.with-statement` (eslint `no-with`, MIT) | `(with_statement) @report` | fires / does not fire | `with` is a syntax error in strict mode and in every ES module, so on a modern tree the rule can never fire. Zero noise and zero value. |
| `reliability.javascript.comma-in-subscript` (eslint `no-sequences`, MIT) | `(subscript_expression index: (sequence_expression)) @report` | fires / does not fire | Correct and zero-noise, but `a[i, j]` is rare enough that it would never be exercised by the noise set or by a corpus row taken from real code. |
| `maintainability.javascript.var-declaration` (eslint `no-var`, MIT) | `(variable_declaration) @report` | fires / does not fire | Not a mistake, a vintage. It fires on every line of a pre-ES6 file and would breach the `info` gate by an order of magnitude on any library old enough to have `var` at all. |
| `maintainability.javascript.template-placeholder-in-plain-string` (eslint `no-template-curly-in-string`, MIT) | `((string (string_fragment) @s) @report (#match? @s "\\$\\{[A-Za-z_$][A-Za-z0-9_$.]*\\}"))` | fires / does not fire | The idiom that defeats it is the message catalogue: an i18n or logging-template file is *made* of `"${name}"` strings that are interpolated later and deliberately. |

## Rejected outright

Not expressible with a single-file query, with or without either primitive.

| Candidate | Reason |
| --- | --- |
| Unhandled promise / floating `await` (typescript-eslint `no-floating-promises`, MIT, concept only) | Requires knowing that the call's return value is a thenable, which is the callee's type. No type engine. |
| Unused variable, unused import (eslint `no-unused-vars`, MIT) | Requires a scope-resolved binding table plus reachability. Beyond one bounded primitive; it is a resolver. |
| Shadowed binding (eslint `no-shadow`, MIT) | Same: needs the enclosing scope chain, not a subtree walk. |
| Reassigned `const`, reassigned import (eslint `no-const-assign`, `no-import-assign`, MIT) | Same. |
| Array callback with no return on some path (eslint `array-callback-return`, MIT) | Reachability across every path in the callback, not the presence or absence of a node. |
| `this` in a static or detached context | Requires knowing how the function is called. |

---

## Verification

One run of the throwaway harness, over every query in this document plus the
four probes that establish the failure modes. `PASS` means every positive
snippet reported and every negative snippet did not; the four `FAIL` rows are
the deliberate probes, and their numbers are the evidence cited above.

```
cargo test -p siloscan-core --test pitfall_scratch --features tree-sitter-javascript -- --nocapture

[PASS] reliability.javascript.async-promise-executor pos=[1, 1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.assignment-in-condition pos=[1, 1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.duplicate-object-key pos=[1, 1] neg=[0, 0, 0, 0, 0, 0]
[PASS] reliability.javascript.duplicate-else-if-condition pos=[1] neg=[0, 0]
[PASS] reliability.javascript.compare-neg-zero pos=[1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.invalid-typeof-comparison pos=[1, 1] neg=[0, 0, 0, 0, 0]
[PASS] reliability.javascript.sparse-array-hole pos=[1, 1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.empty-destructuring-pattern pos=[1, 1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.throw-literal pos=[1, 1] neg=[0, 0, 0]
[PASS] reliability.javascript.return-in-finally pos=[1] neg=[0, 0, 0]
[PASS] reliability.javascript.unsafe-negation pos=[1, 1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.prototype-builtin-call pos=[1] neg=[0, 0, 0]
[PASS] reliability.javascript.self-assignment-member pos=[1, 1] neg=[0, 0, 0]
[PASS] maintainability.javascript.nested-ternary-in-consequence pos=[1, 1] neg=[0, 0]
[PASS] reliability.javascript.duplicate-switch-case pos=[1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.setter-returns-value pos=[1] neg=[0, 0, 0]
[PASS] reliability.javascript.new-wrapper-object pos=[1, 1] neg=[0, 0, 0]
[PASS] reliability.javascript.dynamic-code-execution pos=[1, 1, 1, 1] neg=[0, 0, 0, 0, 0, 0, 0]
[PASS] reliability.javascript.dedup-probe pos=[1]
[PASS] reliability.javascript.unreachable-after-return pos=[1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.loose-equality-nonnull pos=[1] neg=[0, 0, 0, 0]
[PASS] reliability.javascript.with-statement pos=[1] neg=[0]
[PASS] reliability.javascript.comma-in-subscript pos=[1] neg=[0, 0, 0]
[PASS] maintainability.javascript.var-declaration pos=[1] neg=[0]
[PASS] maintainability.javascript.template-placeholder-in-plain-string pos=[1] neg=[0, 0, 0]
[FAIL] showstopper.unreachable-comment-gap pos=[0]
[FAIL] showstopper.async-function-without-await pos=[1] neg=[1]
[FAIL] showstopper.catch-parameter-nested pos=[0] neg=[0]
[FAIL] showstopper.getter-without-return pos=[1] neg=[1]
```

What each probe establishes:

- `showstopper.unreachable-comment-gap` — `pos=[0]`: dead code separated from
  the `return` by a comment is missed, because the comment is a named sibling
  and breaks the `.` anchor.
- `showstopper.async-function-without-await` — `neg=[1]`: an async function that
  does `await` reports. Item 19's failure mode, and P1's reason to exist.
- `showstopper.catch-parameter-nested` — `pos=[0]`: a catch-parameter
  reassignment one `if` deep is missed. P2's reason to exist.
- `showstopper.getter-without-return` — `neg=[1]`: a getter that does return
  reports. Item 20's failure mode.
- `reliability.javascript.dedup-probe` — `pos=[1]`: two patterns in one query
  that hit the same node report one finding, not two, which is what makes the
  multi-pattern form in items 8 and 13 safe.

Three engine facts were confirmed by running rather than assumed:

1. **A predicate binds to the pattern inside its own outer parenthesis pair.**
   Item 13's three-pattern alternation works only because each pattern carries
   its own parentheses around pattern and predicate together.
2. **Two unanchored sibling patterns bind two distinct nodes.** Item 3's
   negative `{ a: 1, b: 2 }` does not report, which it would if one pair could
   satisfy both captures.
3. **`#not-any-of?` and `#any-of?` load.** Both are in the loader's accepted
   text-predicate set; item 7 and item 13 depend on them.

## Licensing disposition

Every concept source in this document is ESLint core or typescript-eslint, both
MIT. No pattern text, query text or message text was taken from either: the
queries were written against `node-types.json` for the pinned grammar, and the
rule names appear only as concept references. No SonarSource rule is cited here,
and no Semgrep rule is cited or consulted.

Fixture code: every positive and negative snippet in this document was written
for it. None is taken from an upstream test suite, so no `NOTICE` stanza is owed
if these snippets become corpus rows.
