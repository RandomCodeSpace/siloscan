# C# pitfall list

Research for issue #112, under the v2.2 map #103. This document decides *what
the C# rules would be*; it writes no rule YAML and no engine code.

Grammar: `tree-sitter-c-sharp` **0.23.5**, the version pinned in
`crates/siloscan-core/Cargo.toml`, read at
`~/.cargo/registry/src/*/tree-sitter-c-sharp-0.23.5/src/node-types.json` and
`grammar.json`. Query host: `tree-sitter` 0.26.11.

## Method

Every query below was written from the grammar's own `node-types.json` and then
**run through the product**, not eyeballed: a throwaway integration test built
each candidate into a one-rule YAML document, loaded it with
`siloscan_core::rules::load_str` — the same call `plan::resolve` makes — wrapped
the result in a `RuleSet`, wrote the positive and the negative snippet into
temporary directories and scanned each with `siloscan_core::scan::scan`. A
candidate passes only when the positive reports at least once and the negative
reports zero times. The harness also parses both snippets with
`parsers::language("csharp")` and rejects any snippet containing an `ERROR` or
missing node, so a negative cannot pass because it failed to parse.

Two rounds were run against the final text of every query:

```
round 1 (positives and negatives):   checked=18 ok=18 failures=0
round 2 (adversarial idioms):        checked=16 ok=16 failures=0
```

Round 2 exists because "does not fire on my negative" is a weak claim. It
re-ran each query against the idiom named in that item's noise judgement, and
against the shape the item claims it deliberately misses. Every expectation
held.

The harness is not committed, per the ticket. It is reproducible from the
description above; `CARGO_TARGET_DIR=/home/dev/projects/siloscan/target` was set
for every cargo invocation so the grammars were not rebuilt.

### Three engine facts this round established

These were measured, not assumed, and they set the boundary for every
disposition below.

1. **Query nesting is direct-child, not descendant.**
   `(class_declaration (method_declaration) @report)` does not merely fail to
   match — it is rejected at load with `Query error … Impossible pattern`,
   because a `method_declaration` is a child of `declaration_list`, not of
   `class_declaration`. `(method_declaration body: (block (throw_statement) @report))`
   compiles but reports nothing when the `throw` sits inside a nested `try`.
   So "X anywhere inside an async method" is **not** expressible; every query
   here spells out the full parent chain.
2. **`statement` is a query-usable supertype.** `grammar.json` lists
   `declaration`, `expression`, `non_lvalue_expression`, `lvalue_expression`,
   `literal`, `statement`, `type`, `type_declaration` and `pattern` as
   supertypes, and `(block (return_statement) . (statement) @report)` compiles
   and matches. That, plus alternation, is what rescues
   `unreachable-after-return` below.
3. **`comment` and every `preproc_*` directive are grammar `extras`.**
   `comment`, `preproc_region`, `preproc_endregion`, `preproc_line`,
   `preproc_pragma`, `preproc_nullable`, `preproc_error`, `preproc_warning`,
   `preproc_define` and `preproc_undef` can appear between any two siblings.
   They are named nodes, so `(_)` matches them and the `.` anchor counts them —
   which is exactly how the 2.1 `unreachable-after-return` query came to report
   `#pragma warning restore` lines and trailing comments.

## Summary

20 items: 16 **expressible**, 2 **needs primitive**, 2 **inexpressible**.

Of the 16 expressible, 13 are recommended for measurement against the pinned
noise set (Newtonsoft.Json 13.0.4, Dapper 2.1.79, AutoMapper v12.0.1) and 3 are
recorded as expressible-but-do-not-ship: their query is correct and their
findings are true, and they will still breach the per-kLOC budget because the
shape they name is ordinary in real C#.

| # | Proposed id | Severity | Disposition | Expected noise |
| --- | --- | --- | --- | --- |
| 1 | `reliability.csharp.lock-on-weak-identity` | warning | expressible | very low — `lock (this)` in a sealed internal type is the only defensible form |
| 2 | `reliability.csharp.throw-in-finally` | warning | expressible | very low — a deliberate `throw` in `finally` is vanishingly rare |
| 3 | `reliability.csharp.throw-reserved-exception` | warning | expressible | low — `throw new Exception(...)` in sample, test and scaffold code |
| 4 | `reliability.csharp.rethrow-only-catch` | info | expressible | low — `catch (X) when (filter) { throw; }`, where the filter is the point |
| 5 | `reliability.csharp.mistaken-empty-statement` | warning | expressible | very low — the deliberate spin `while (Poll());` |
| 6 | `reliability.csharp.recursive-property` | warning | expressible | none found — the shape is a bug |
| 7 | `reliability.csharp.gc-collect` | info | expressible | low — benchmark harnesses and finaliser tests call it on purpose |
| 8 | `reliability.csharp.sync-over-async-getresult` | warning | expressible | low — `Main` in a pre-C#-7.1 entry point, and test setup |
| 9 | `reliability.csharp.blocking-on-async-call` | warning | expressible | low — same two, plus already-completed tasks |
| 10 | `reliability.csharp.case-insensitive-tolower-comparison` | info | expressible | medium — **EF Core LINQ predicates**, where `StringComparison` does not translate to SQL |
| 11 | `reliability.csharp.task-returns-null` | warning | expressible | low — a `Task`-typed method that legitimately returns a null *task* does not exist |
| 12 | `maintainability.csharp.null-forgiving-operator` | info | expressible — **do not ship** | high — `!` is the ordinary spelling in test assertions and EF model classes |
| 13 | `reliability.csharp.catch-general-exception` | info | expressible — **do not ship** | high — top-level handlers, `Main`, retry loops, background-service loops |
| 14 | `maintainability.csharp.log-interpolated-message` | info | expressible — **do not ship** | high on service code — every `_logger.LogX($"…")` call fires |
| 15 | `reliability.csharp.self-assignment` (2.1 re-entry) | warning | expressible | none found — the 2.1 failure was the query, not the engine |
| 16 | `reliability.csharp.unreachable-after-return` (2.1 re-entry) | warning | expressible | none found — the 2.1 failure was the query, not the engine |
| 17 | `reliability.csharp.thread-sleep-in-async` | warning | **needs primitive** (P1) | unscoped form is medium: retry loops and test code sleep on purpose |
| 18 | `reliability.csharp.async-without-await` | warning | **needs primitive** (P2) | unconstrained form reports every `async` method |
| 19 | `reliability.csharp.dispose-before-losing-scope` | warning | **inexpressible** | — |
| 20 | `reliability.csharp.virtual-call-in-constructor` | warning | **inexpressible** | — |

Two idioms named in the ticket were held against every judgement above. **C#
local functions are hoisted**: a `local_function_statement` after a `return` is
reachable, so item 16 excludes that node type by name rather than by anchor.
**Object initialisers look like self-assignment**: `new Source { Id = Id }`
parses as `initializer_expression → assignment_expression`, which is why item 15
requires an `expression_statement` parent and pins `operator: "="`.

---

## 1. `reliability.csharp.lock-on-weak-identity`

**Pitfall.** The code takes a monitor on `this`, on a `typeof(...)` expression
or on a string literal — objects any other code can also reach and lock, so the
lock does not protect what the author thinks it protects.

**Concept source.** roslyn-analyzers / .NET code analysis — CA2002, "Do not lock
on objects with weak identity". The analyser now lives in `dotnet/sdk` (MIT);
the rule documentation is in `dotnet/docs` (CC-BY-4.0). Concept only; no text
taken. The rule's own type list includes `String`, `MarshalByRefObject`,
`MemberInfo`, `Thread` and `this`; only the three forms visible without type
information are taken here.

**Severity.** `warning`.

**Query** — verified.

```scheme
((lock_statement "this") @report)
((lock_statement (typeof_expression)) @report)
((lock_statement (string_literal)) @report)
```

`this` is an *unnamed* node type in this grammar (it appears in the
`lvalue_expression` supertype list but carries `named: false`), so it is written
as an anonymous token.

```csharp
// fires
class C { void M() { lock (this) { G(); } } }
class D { void M() { lock (typeof(D)) { G(); } } }
class E { void M() { lock ("gate") { G(); } } }

// does not fire
class C { private readonly object _gate = new object(); void M() { lock (_gate) { G(); } } }
```

**Expected noise.** Very low. The one defensible idiom is `lock (this)` inside a
sealed or internal type whose instances never escape, which CA2002 itself calls
out as safe to suppress. The three pinned repositories are libraries with
private sync roots; `lock (_lock)` on a private field is the dominant form and
does not match.

**Disposition.** **Expressible.** The weak-identity cases that need a type
(`MemberInfo`, `Thread`, a `MemoryStream` local) are out of reach and are simply
not claimed.

---

## 2. `reliability.csharp.throw-in-finally`

**Pitfall.** A `throw` directly inside a `finally` block replaces the exception
that is already unwinding, and the original failure is lost.

**Concept source.** roslyn-analyzers / .NET code analysis — CA2219, "Do not
raise exceptions in exception clauses" (analyser in `dotnet/sdk`, MIT;
documentation in `dotnet/docs`, CC-BY-4.0). Also Meziantou.Analyzer MA0072, "Do
not throw from a finally block" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query** — verified.

```scheme
(finally_clause (block (throw_statement) @report))
```

```csharp
// fires
class C { void M() { try { G(); } finally { throw new System.InvalidOperationException(); } } }

// does not fire
class C { void M() { try { G(); } finally { Cleanup(); } } }
```

**Expected noise.** Very low; CA2219's own guidance is that there is no scenario
in which this is right. What the query gives up is coverage, not precision: a
`throw` nested inside an `if` in the `finally` is not a direct child of the
block and is missed. Verified: `finally { if (c) { throw new …; } }` reports
nothing. Catching that needs primitive P1.

**Disposition.** **Expressible.**

---

## 3. `reliability.csharp.throw-reserved-exception`

**Pitfall.** The code throws `Exception`, `ApplicationException`,
`SystemException` or a runtime-reserved type, forcing every caller to catch
everything to catch anything.

**Concept source.** roslyn-analyzers / .NET code analysis — CA2201, "Do not
raise reserved exception types" (`dotnet/sdk`, MIT; docs `dotnet/docs`,
CC-BY-4.0). Concept only; no text taken. The name list is CA2201's own
published list of general and reserved types, used as a concept, not copied as
rule text.

**Severity.** `warning`.

**Query** — verified.

```scheme
((throw_statement (object_creation_expression type: (identifier) @t)) @report
 (#any-of? @t "Exception" "ApplicationException" "SystemException"
             "AccessViolationException" "ExecutionEngineException"
             "IndexOutOfRangeException" "NullReferenceException"
             "OutOfMemoryException" "StackOverflowException"
             "COMException" "ExternalException" "SEHException"))
((throw_statement (object_creation_expression type: (qualified_name name: (identifier) @q))) @report
 (#any-of? @q "Exception" "ApplicationException" "SystemException"
             "AccessViolationException" "ExecutionEngineException"
             "IndexOutOfRangeException" "NullReferenceException"
             "OutOfMemoryException" "StackOverflowException"
             "COMException" "ExternalException" "SEHException"))
```

Two patterns because `throw new Exception()` gives `type: (identifier)` and
`throw new System.Exception()` gives `type: (qualified_name name: (identifier))`.

```csharp
// fires
class C { void M() { throw new Exception("boom"); } void N() { throw new System.ApplicationException("boom"); } }

// does not fire
class C { void M(string x) { throw new System.ArgumentNullException(nameof(x)); } void N() { throw new OrderNotFoundException(42); } }
```

**Expected noise.** Low, and every finding is true by construction — the name is
matched, not inferred. The idiom that produces volume is scaffold code:
`throw new Exception("not implemented")` in samples, spikes and test doubles.
A user type genuinely named `Exception` would be a false positive; none exists
in the pinned set.

**Disposition.** **Expressible.**

---

## 4. `reliability.csharp.rethrow-only-catch`

**Pitfall.** A `catch` block whose only statement is a bare `throw;` changes
nothing but costs a two-pass stack walk and hides the fact that nothing is
handled.

**Concept source.** SonarSource sonar-dotnet — S2737, `"catch" clauses should do
more than rethrow` (verified from `analyzers/rspec/cs/S2737.json` in
`SonarSource/sonar-dotnet`). Licence: SONAR Source-Available License v1.0, **not
OSI**. Concept only; no text, no pattern and no message taken. Nothing from this
project may be copied — the citation records where the idea is catalogued.

**Severity.** `info`.

**Query** — verified.

```scheme
((catch_clause body: (block "{" . (throw_statement) @t . "}")) @report
 (#match? @t "^throw[ \t\r\n]*;$"))
```

The anchors pin the `throw` as the block's only statement. A bare `throw;` and a
`throw e;` are the same node type, and there is no way to require the absence of
a child; the `#match?` on the node's own text is what separates them, and it
also keeps this rule from overlapping the shipped
`reliability.csharp.rethrow-loses-stack`.

```csharp
// fires
class C { void M() { try { G(); } catch (System.Exception) { throw; } } }

// does not fire
class C { void M() { try { G(); } catch (System.Exception e) { Log(e); throw; } } }
```

**Expected noise.** Low, with one named idiom: `catch (X) when (Filter(e)) { throw; }`,
where the work happens in the exception filter and the body is deliberately
empty of everything but the rethrow. Verified — that form **does** fire. If the
measured rate is driven by filters, the fix is a second pattern requiring the
`catch_clause` to have no `catch_filter_clause` sibling, which needs primitive
P2; until then this is `info`.

**Disposition.** **Expressible.**

---

## 5. `reliability.csharp.mistaken-empty-statement`

**Pitfall.** A stray semicolon terminates an `if`, `while`, `for` or `foreach`,
so the block that follows runs unconditionally or the loop spins with no body.

**Concept source.** Roslyn compiler warning CS0642, "Possible mistaken empty
statement" (`dotnet/roslyn`, MIT; docs `dotnet/docs`, CC-BY-4.0). Also
Meziantou.Analyzer MA0037, "Remove empty statement" (MIT). Concept only; no text
taken.

**Severity.** `warning`.

**Query** — verified.

```scheme
(if_statement consequence: (empty_statement) @report)
(while_statement body: (empty_statement) @report)
(for_statement body: (empty_statement) @report)
(foreach_statement body: (empty_statement) @report)
```

```csharp
// fires
class C { void M(int n) { while (Step(n)); Done(); } void N(int n) { for (int i = 0; i < n; i++); Done(); } }

// does not fire
class C { void M(int n) { while (Step(n)) { } Done(); } void N() { for (;;) { break; } } }
```

**Expected noise.** Very low. The one idiom that is intentional is the spin
`while (Interlocked.CompareExchange(…) != 0);`, which a reviewer wants to see
anyway. An empty *block* body — `while (c) { }` — is a different node and does
not match, which is deliberate: that form is written on purpose far more often.

**Disposition.** **Expressible.**

---

## 6. `reliability.csharp.recursive-property`

**Pitfall.** A property getter returns the property itself, so reading it
recurses until the stack overflows. It is the classic consequence of renaming a
backing field.

**Concept source.** SonarSource sonar-dotnet — S2190, "Loops and recursions
should not be infinite" (verified from `analyzers/rspec/cs/S2190.json`). SONAR
Source-Available License v1.0, **not OSI**. Concept only; nothing taken. The
narrowing to the self-returning property is this repository's.

**Severity.** `warning`.

**Query** — verified.

```scheme
((property_declaration name: (identifier) @n
   value: (arrow_expression_clause (identifier) @v)) @report (#eq? @n @v))
((property_declaration name: (identifier) @n
   accessors: (accessor_list (accessor_declaration body: (arrow_expression_clause (identifier) @v)))) @report (#eq? @n @v))
((property_declaration name: (identifier) @n
   accessors: (accessor_list (accessor_declaration body: (block (return_statement (identifier) @v))))) @report (#eq? @n @v))
```

Three patterns for the three spellings: `int X => X;` (the arrow is the
property's `value` field), `{ get => X; }` and `{ get { return X; } }`.

```csharp
// fires
class C { public int Count => Count; }
class D { public int Count { get { return Count; } } }
class E { public int Count { get => Count; } }

// does not fire
class C { private int _c; public int Count => _c; }
class D { private int _c; public int Count { get { return _c; } set { _c = value; } } }
```

**Expected noise.** None found. `#eq?` compares the two identifiers' text, and
there is no idiom in which a property returning its own name is intended.
Verified as deliberately out of scope: the setter form `set { Count = value; }`
is not covered, because it is an `assignment_expression` inside the accessor's
block and would need a fourth pattern; the getter forms are the ones that
overflow on read.

**Disposition.** **Expressible.**

---

## 7. `reliability.csharp.gc-collect`

**Pitfall.** An explicit `GC.Collect()` forces a full collection, usually to
paper over a leak, and usually makes throughput worse.

**Concept source.** SonarSource sonar-dotnet — S1215, `"GC.Collect" should not
be called` (verified from `analyzers/rspec/cs/S1215.json`). SONAR
Source-Available License v1.0, **not OSI**. Concept only; nothing taken.

**Severity.** `info`.

**Query** — verified.

```scheme
((invocation_expression function: (member_access_expression expression: (_) @o name: (identifier) @m)) @report
 (#eq? @m "Collect")
 (#match? @o "(^|\\.)GC$"))
```

The `(_) @o` with a `#match?` anchored on `GC$` handles `GC.Collect()` and
`System.GC.Collect()` in one pattern instead of enumerating receiver shapes.

```csharp
// fires
class C { void M() { System.GC.Collect(); } void N() { GC.Collect(); } }

// does not fire
class C { void M(object GCManager, object gc) { GCManager.Collect(); gc.Collect(); } }
```

**Expected noise.** Low. The named idiom is deliberate: benchmark harnesses and
finaliser or weak-reference tests call `GC.Collect()` on purpose, and a memory
profiler's own code will too. Verified that a receiver merely *containing* `GC`
(`GCManager`) and a lowercase `gc` do not match — the regex is anchored.

**Disposition.** **Expressible.** `info` rather than `warning` because the
legitimate uses cluster in test projects, which the noise set does not exclude.

---

## 8. `reliability.csharp.sync-over-async-getresult`

**Pitfall.** `something.GetAwaiter().GetResult()` blocks a thread on a task. On
a context with a single-threaded synchronisation context it deadlocks; on a
thread pool it burns a worker.

**Concept source.** microsoft/vs-threading — VSTHRD002, "Avoid problematic
synchronous waits". Licence **MIT** — verified this round by reading
`LICENSE` in `microsoft/vs-threading`, which the 2.1 matrix listed as "not
re-verified". Also Meziantou.Analyzer MA0045 (MIT), "Do not use blocking calls,
even when the calling method must become async". Concept only; no text taken.

**Severity.** `warning`.

**Query** — verified.

```scheme
((invocation_expression
   function: (member_access_expression
     expression: (invocation_expression function: (member_access_expression name: (identifier) @a))
     name: (identifier) @g)) @report
 (#eq? @a "GetAwaiter") (#eq? @g "GetResult"))
((invocation_expression
   function: (member_access_expression
     expression: (invocation_expression function: (identifier) @a2)
     name: (identifier) @g2)) @report
 (#eq? @a2 "GetAwaiter") (#eq? @g2 "GetResult"))
```

Two patterns because the receiver of `.GetAwaiter()` may be `x.FooAsync()`
(member access) or `FooAsync()` (bare identifier).

```csharp
// fires
class C { void M() { FetchAsync().GetAwaiter().GetResult(); } void N() { _client.FetchAsync().GetAwaiter().GetResult(); } }

// does not fire
class C { async System.Threading.Tasks.Task M() { await FetchAsync(); } void N() { _query.Build().GetResult(); } }
```

**Expected noise.** Low. The `.GetAwaiter().GetResult()` pair has essentially
one meaning in C#, and the query requires the two calls adjacent, so a
`GetResult()` on an unrelated builder does not match (verified). The named
legitimate idiom is a synchronous `Main` on a target framework without
`async Main`, plus one-off test setup — both small and both worth seeing.

**Disposition.** **Expressible.**

---

## 9. `reliability.csharp.blocking-on-async-call`

**Pitfall.** `FooAsync().Result` or `FooAsync().Wait()` blocks on a task that
has just been started, the same deadlock as item 8 in its two commoner
spellings.

**Concept source.** microsoft/vs-threading — VSTHRD002 (MIT, verified above).
The `Async` suffix this rule keys on is itself a catalogued convention:
Meziantou.Analyzer MA0137, "Use 'Async' suffix when a method returns an
awaitable type" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query** — verified.

```scheme
((member_access_expression
   expression: (invocation_expression function: (member_access_expression name: (identifier) @f))
   name: (identifier) @p) @report (#match? @f "Async$") (#eq? @p "Result"))
((member_access_expression
   expression: (invocation_expression function: (identifier) @f2)
   name: (identifier) @p2) @report (#match? @f2 "Async$") (#eq? @p2 "Result"))
((invocation_expression
   function: (member_access_expression
     expression: (invocation_expression function: (member_access_expression name: (identifier) @w))
     name: (identifier) @wt)) @report (#match? @w "Async$") (#eq? @wt "Wait"))
((invocation_expression
   function: (member_access_expression
     expression: (invocation_expression function: (identifier) @w2)
     name: (identifier) @wt2)) @report (#match? @w2 "Async$") (#eq? @wt2 "Wait"))
```

A bare `.Result` is not usable as a rule: `Result` is an ordinary property name
on result types, option types and generated clients, and without type
information there is no way to tell `parseResult.Result` from
`task.Result`. Requiring the receiver to be a **call whose name ends in
`Async`** is what buys near-zero false positives, at the cost of missing every
call that does not follow the convention.

```csharp
// fires
class C { int M() { return _client.LoadAsync().Result; } void N() { SaveAsync().Wait(); } }

// does not fire
class C { async System.Threading.Tasks.Task M() { var x = await LoadAsync(); Use(x); }
          int N() { var t = LoadAsync(); return t.Result; } }
```

**Expected noise.** Low. The named idiom that could produce a false positive is
a synchronous method named `…Async` that returns a plain object with a `Result`
property — MA0138 exists precisely because people do that — but it is rare.
Verified as a deliberate miss: `var t = LoadAsync(); t.Result;` does not fire,
because binding `t` to its initialiser is a symbol-table job (see item 19's
primitive discussion).

**Disposition.** **Expressible.**

---

## 10. `reliability.csharp.case-insensitive-tolower-comparison`

**Pitfall.** Comparing `a.ToLower() == b.ToLower()` allocates two strings to
answer a question `string.Equals(a, b, StringComparison.OrdinalIgnoreCase)`
answers without allocating — and gets a different answer under some cultures.

**Concept source.** roslyn-analyzers / .NET code analysis — CA1862, "Use the
'StringComparison' method overloads to perform case-insensitive string
comparisons" (`dotnet/sdk`, MIT; docs `dotnet/docs`, CC-BY-4.0). Concept only;
no text taken.

**Severity.** `info`.

**Query** — verified.

```scheme
((binary_expression
   left: (invocation_expression function: (member_access_expression name: (identifier) @m))
   operator: "==") @report
 (#any-of? @m "ToLower" "ToUpper" "ToLowerInvariant" "ToUpperInvariant"))
((binary_expression
   operator: "=="
   right: (invocation_expression function: (member_access_expression name: (identifier) @m2))) @report
 (#any-of? @m2 "ToLower" "ToUpper" "ToLowerInvariant" "ToUpperInvariant"))
```

Note the field order: `left` must precede `operator`, and `operator` must
precede `right`. Writing `operator:` before `left:` is an impossible pattern and
fails to compile — the same trap the 2.1 matrix hit.

```csharp
// fires
class C { bool M(string a, string b) { return a.ToLower() == b.ToLower(); }
          bool N(string a, string b) { return a == b.ToUpperInvariant(); } }

// does not fire
class C { bool M(string a, string b) { return string.Equals(a, b, System.StringComparison.OrdinalIgnoreCase); }
          bool N(string a, string b) { return a.ToLower().Equals(b.ToLower()); } }
```

**Expected noise.** Medium, and the idiom has a name: **EF Core LINQ
predicates**. CA1862's own guidance is to suppress it when querying a database,
because EF Core throws on `string.Equals(…, StringComparison)` — it cannot
translate it to SQL — so `x.Name.ToLower() == term` is the *correct* spelling
inside a query. Dapper and AutoMapper are in the pinned set and are not EF Core,
so the measured rate will understate the rate on application code. `info`, and
the `paths` exclusion allowed by the noise policy would go on a repository's
data-access directory.

**Disposition.** **Expressible.**

---

## 11. `reliability.csharp.task-returns-null`

**Pitfall.** A method declared to return `Task` or `Task<T>` returns `null`. The
caller's `await` dereferences it and throws `NullReferenceException` at a place
that has nothing to do with the bug.

**Concept source.** Meziantou.Analyzer — MA0022, "Return Task.FromResult instead
of returning null" (MIT). Concept only; no text taken.

**Severity.** `warning`.

**Query** — verified.

```scheme
((method_declaration
   returns: (generic_name (identifier) @t)
   body: (block (return_statement (null_literal)))) @report
 (#any-of? @t "Task" "ValueTask"))
((method_declaration
   returns: (qualified_name name: (generic_name (identifier) @t2))
   body: (block (return_statement (null_literal)))) @report
 (#any-of? @t2 "Task" "ValueTask"))
```

```csharp
// fires
class C { System.Threading.Tasks.Task<string> M() { return null; } ValueTask<int> N() { return null; } }

// does not fire
class C { System.Threading.Tasks.Task<string> M() { return System.Threading.Tasks.Task.FromResult<string>(null); }
          System.Threading.Tasks.Task<string> N(bool c) { if (c) { return null; } return System.Threading.Tasks.Task.FromResult(""); } }
```

**Expected noise.** Low; there is no idiom in which returning a null *task* is
intended. Verified as a deliberate miss: `if (c) { return null; }` nested one
block deep does not fire, because the `return_statement` must be a direct child
of the method's block. That is the common real shape, so recall here is poor and
precision is high — P1 would fix the recall.

**Disposition.** **Expressible.**

---

## 12. `maintainability.csharp.null-forgiving-operator`

**Pitfall.** `x!` tells the compiler to stop checking. Every one is an assertion
the author could not prove, and the `NullReferenceException` it permits arrives
later and elsewhere.

**Concept source.** Meziantou.Analyzer — MA0191, "Do not use the null-forgiving
operator" (MIT). Concept only; no text taken.

**Severity.** `info`.

**Query** — verified.

```scheme
((postfix_unary_expression "!") @report)
```

```csharp
// fires
class C { int M(string s) { return s!.Length; } }

// does not fire
class C { int M(int i) { i++; i--; return i; } }
```

`postfix_unary_expression` also spells `++` and `--`; naming the `"!"` token
separates them, verified.

**Expected noise.** High, and this is the C# analogue of the TypeScript
`any-assertion` rule the 2.1 matrix removed. The named idioms are test
assertions (`result!.Value.Should()…`) and EF Core / serialisation model classes,
where `public string Name { get; set; } = null!;` is the standard way to
initialise a non-nullable navigation property. Both are dense, so the per-kLOC
count is driven by a convention rather than by defects.

**Disposition.** **Expressible — do not ship.** The query is correct and cheap;
it fails the noise policy on shape, not on precision, and the policy is removal
rather than tuning. Recorded here so the next round does not re-derive it. No
primitive changes this: distinguishing "asserted because the author checked" from
"asserted because the author gave up" is not syntax.

---

## 13. `reliability.csharp.catch-general-exception`

**Pitfall.** `catch (Exception)` swallows everything, including the failures the
author never considered.

**Concept source.** roslyn-analyzers / .NET code analysis — CA1031, "Do not
catch general exception types" (`dotnet/sdk`, MIT; docs `dotnet/docs`,
CC-BY-4.0). Concept only; no text taken.

**Severity.** `info`.

**Query** — verified.

```scheme
((catch_clause (catch_declaration type: (identifier) @t)) @report
 (#any-of? @t "Exception" "SystemException"))
((catch_clause (catch_declaration type: (qualified_name name: (identifier) @q))) @report
 (#any-of? @q "Exception" "SystemException"))
```

```csharp
// fires
class C { void M() { try { G(); } catch (System.Exception e) { Log(e); } } }

// does not fire
class C { void M() { try { G(); } catch (System.IO.IOException e) { Log(e); } }
          void N() { try { G(); } catch (System.AggregateException e) { Log(e); } } }
```

**Expected noise.** High. The named idioms are all legitimate and all common:
the top-level handler in `Main`, an ASP.NET Core exception middleware, a
`BackgroundService` loop that must not die, and a retry policy. CA1031 is
disabled by default in .NET 10 for exactly this reason. It fires roughly once
per error-handling boundary, which on a library like Newtonsoft.Json is
frequent.

**Disposition.** **Expressible — do not ship.** Would breach even the `info`
budget of 1.0 per kLOC on ordinary service code. Note that this rule does *not*
subsume the shipped `reliability.csharp.empty-catch`, which fires on the
*emptiness* of the body and is far narrower.

---

## 14. `maintainability.csharp.log-interpolated-message`

**Pitfall.** `_logger.LogInformation($"loaded {id}")` bakes the value into the
template, so the log aggregator sees a distinct message for every call and the
placeholder name is lost.

**Concept source.** roslyn-analyzers / .NET code analysis — CA2254, "Template
should be a static expression" (`dotnet/sdk`, MIT; docs `dotnet/docs`,
CC-BY-4.0). Concept only; no text taken.

**Severity.** `info`.

**Query** — verified.

```scheme
((invocation_expression
   function: (member_access_expression name: (identifier) @m)
   arguments: (argument_list (argument (interpolated_string_expression)))) @report
 (#match? @m "^Log[A-Z]"))
```

```csharp
// fires
class C { void M(object log, int id) { log.LogInformation($"loaded {id}"); } }

// does not fire
class C { void M(object log, int id) { log.LogInformation("loaded {Id}", id); log.Debug($"x {id}"); } }
```

The `^Log[A-Z]` anchor is what keeps this from firing on every method taking an
interpolated string; it keys on the `Microsoft.Extensions.Logging` naming
convention (`LogInformation`, `LogWarning`, `LogError`, `LogDebug`), and a
`log.Debug($"…")` from another logging library does not match (verified).

**Expected noise.** High on any service codebase — every interpolated log call
fires, and the finding is *true* each time. It would measure near zero on the
current pinned set, because Newtonsoft.Json, Dapper and AutoMapper are libraries
that barely log. That mismatch is itself a finding for the map's open question
about whether the noise set exercises the new pitfalls: this rule cannot be
honestly measured without a fourth, service-shaped repository.

**Disposition.** **Expressible — do not ship** on the current noise set. Revisit
only if the set gains a repository that logs.

---

## 15. `reliability.csharp.self-assignment` — 2.1 removal, re-entry

**Pitfall.** `a = a;` does nothing; it is almost always a mistyped field or
parameter name.

**Concept source.** Roslyn compiler warning CS1717, assignment made to same
variable (`dotnet/roslyn`, MIT). Concept only; no text taken.

**Severity.** `warning`.

**Why it was removed in 2.1.** From `reliability-csharp.yaml`'s own header: the
query did not constrain the `operator` field and could not tell an object
initialiser from an assignment, so all four findings across the three pinned
repositories were `new Source { Id = Id }` or `s += s`, and none was a
self-assignment.

**What actually fixes it — and it is not a primitive.** Both failure modes are
query defects:

- `new Source { Id = Id }` parses as `initializer_expression → assignment_expression`,
  **not** as `expression_statement → assignment_expression`. Requiring the
  `expression_statement` parent excludes every object and collection initialiser
  by construction. Verified against `initializer_expression` directly.
- `s += s` is an `assignment_expression` whose `operator` field is `"+="`.
  Pinning `operator: "="` excludes it.

**Query** — verified.

```scheme
((expression_statement
   (assignment_expression left: (identifier) @l operator: "=" right: (identifier) @r)) @report
 (#eq? @l @r))
```

```csharp
// fires
class C { void M(int a) { a = a; } }

// does not fire
class C { int Id; int a; C M(C s, int a) { s += s; this.a = a; return new C { Id = Id }; } }
```

The negative holds all three 2.1 failure shapes at once — compound assignment,
`this`-qualified assignment, and the object initialiser — and reports zero.

**Expected noise.** None found. The remaining theoretical false positive is the
deliberate `x = x;` written to silence an unused-variable warning, which C#
does not need because it has `_`.

**Disposition.** **Expressible.** This answers one of #103's open questions
directly: `self-assignment` returns to C# **without** any engine primitive. The
2.1 removal was correct as a removal; the query was the defect. The same
correction is worth checking for the other languages that shipped a
`self-assignment` rule, since the object-initialiser trap is C#-specific but the
`operator` field is not.

---

## 16. `reliability.csharp.unreachable-after-return` — 2.1 removal, re-entry

**Pitfall.** A statement directly after `return` in the same block never runs.

**Concept source.** Roslyn compiler warning CS0162, unreachable code detected
(`dotnet/roslyn`, MIT). Concept only; no text taken.

**Severity.** `warning`.

**Why it was removed in 2.1.** From the shipped header: every finding read was a
comment, a `#pragma warning restore` line, or a **C# local function declared
after the return — and a local function is hoisted, so it is reachable.** The
2.1 query was `(block (return_statement) . (_) @report)`, and `(_)` matches
every named node, including `extras`.

**What actually fixes it — and it is not a primitive either.** The `statement`
supertype is usable in a query (established above), and tree-sitter supports
alternation. Enumerating the statement kinds that are genuinely dead, and
leaving out `local_function_statement` and `preproc_if`, is verbose but exact.
`comment` and `preproc_pragma` are not statements at all and drop out for free.

**Query** — verified.

```scheme
(block (return_statement) .
  [(expression_statement) (if_statement) (return_statement) (for_statement)
   (foreach_statement) (while_statement) (do_statement) (switch_statement)
   (try_statement) (throw_statement) (using_statement) (lock_statement)
   (break_statement) (continue_statement) (yield_statement)
   (local_declaration_statement) (block) (goto_statement) (unsafe_statement)
   (checked_statement) (fixed_statement) (labeled_statement)] @report)
```

That is the `statement` supertype's full subtype list minus
`local_function_statement`, `preproc_if` and `empty_statement`.

```csharp
// fires
class C { int M() { return 1; G(); } }

// does not fire
class C { int M() { return 1; int Helper() { return 2; } }
  int N() { return 1;
#pragma warning restore CS0162
  }
  int O() { return 1; /* trailing note */ } }
```

The negative reproduces all three 2.1 failure modes in one file and reports
zero. Both snippets were checked for `ERROR` nodes, so the zero is not a parse
failure.

**Expected noise.** None found on the three shapes that sank it in 2.1. What
remains is recall: because `.` is a strict-adjacency anchor over named nodes, a
comment sitting between the `return` and the dead statement suppresses the
match. Verified — `return 1; /* dead on purpose */ G();` reports nothing. That
is a false negative, and it is the right trade.

**Disposition.** **Expressible.** Second answer to #103's open question: this
rule can return **without** a primitive. A *negated node-type* pattern
(`(block (return_statement) . (statement !local_function_statement) @report)`)
would express the same thing in one line instead of twenty-two, but it is a
convenience, not an enabler, and does not justify an engine change on its own.

---

## 17. `reliability.csharp.thread-sleep-in-async`

**Pitfall.** `Thread.Sleep` inside an `async` method blocks a pool thread for
the duration instead of yielding it; `await Task.Delay` is the spelling that
does not.

**Concept source.** Meziantou.Analyzer — MA0042, "Do not use blocking calls when
the calling method is async" (MIT). Concept only; no text taken. Note that
vs-threading's VSTHRD103 covers `Wait`/`Result`/`GetAwaiter().GetResult()` in an
async method but does not name `Thread.Sleep`; MA0042 is the closer concept.

**Severity.** `warning`.

**Query.** The scoped rule — "a `Thread.Sleep` call *anywhere inside* a method
carrying the `async` modifier" — **cannot be written**, because query nesting is
direct-child only (fact 1 above). Writing out every intermediate node chain is
not a workaround: the call may sit under any depth of `if`, `try`, `foreach`,
`switch_section` or lambda.

What *is* expressible is the unscoped form, verified:

```scheme
((invocation_expression function: (member_access_expression expression: (_) @o name: (identifier) @m)) @report
 (#eq? @m "Sleep")
 (#match? @o "(^|\\.)Thread$"))
```

```csharp
// fires
class C { async System.Threading.Tasks.Task M() { System.Threading.Thread.Sleep(100); await G(); } }

// does not fire
class C { void M(object timer) { timer.Pause(100); } }
```

**Expected noise.** The scoped rule would be near-zero. The unscoped rule is
medium: the named idioms are a synchronous retry or poll loop, a console tool
pacing output, and integration tests waiting for a service — all correct uses of
`Thread.Sleep` in code that is not async at all. Shipping the unscoped form
would report those, and the 2.2 policy is removal rather than tuning.

**Disposition.** **Needs primitive — P1, descendant-scoped child pattern.** See
the primitives section.

---

## 18. `reliability.csharp.async-without-await`

**Pitfall.** A method marked `async` with no `await` in it runs synchronously
while paying for a state machine, and its exceptions surface as a faulted task
rather than at the call.

**Concept source.** Roslyn compiler warning CS1998, "This async method lacks
'await' operators and will run synchronously" (`dotnet/roslyn`, MIT; docs
`dotnet/docs`, CC-BY-4.0). Concept only; no text taken.

**Severity.** `warning`.

**Query.** None exists. The rule is a statement about the **absence** of a node
in a subtree, and a tree-sitter query has no way to say "this subtree contains
no `await_expression`". Negation exists only in the text predicates
(`#not-eq?`, `#not-match?`, `#not-any-of?`), which act on a captured node's
text, not on tree structure.

Verified, to make the gap concrete rather than asserted: the positive half
compiles and matches every `async` method —

```scheme
((method_declaration (modifier) @m) @report (#eq? @m "async"))
```

```csharp
// fires (and would fire equally on an async method that does await)
class C { async System.Threading.Tasks.Task M() { Work(); } }

// does not fire
class C { void M() { Work(); } }
```

There is no second clause that can subtract the ones containing `await`.

A text-predicate hack — `(#not-match? @report "await")` over the method's own
source — is not proposed: it would be defeated by the word `await` in a comment,
a string literal or an identifier, and the noise policy has no room for a rule
whose correctness depends on the absence of a substring.

**Expected noise.** Not measurable; there is nothing to measure.

**Disposition.** **Needs primitive — P2, negative descendant assertion.** See
the primitives section.

---

## 19. `reliability.csharp.dispose-before-losing-scope`

**Pitfall.** An `IDisposable` is constructed into a local and never disposed —
no `using`, no `try/finally`, no ownership transfer — so the handle survives
until a finaliser that may never run.

**Concept source.** roslyn-analyzers / .NET code analysis — CA2000, "Dispose
objects before losing scope" (`dotnet/sdk`, MIT; docs `dotnet/docs`,
CC-BY-4.0). Concept only; no text taken.

**Severity.** `warning`, if it existed.

**Query.** None, and no primitive within the map's boundary produces one. Three
independent things are missing at once:

1. **Type knowledge.** Deciding that `new SqlConnection(...)` is disposable and
   `new StringBuilder(...)` is not requires resolving the type to its
   interfaces. That is not in the file.
2. **Flow.** CA2000 is a dataflow rule — its documented options include
   `interprocedural_analysis_kind` and `points_to_analysis_kind` — and the map
   puts cross-file, type-aware and dataflow analysis explicitly out of scope.
3. **Ownership.** Even with the first two, "returned to the caller", "assigned
   to a field" and "handed to a constructor that takes ownership" are all
   correct and all look the same syntactically.

A syntactic approximation — "an `object_creation_expression` whose type name
ends in `Connection`, `Stream`, `Reader` or `Writer`, in a
`local_declaration_statement` that is not a `using`" — was considered and is
rejected: it is a guess dressed as a rule, and the ownership cases above make it
wrong far more often than right.

**Disposition.** **Inexpressible** under the single-file query boundary. Record
it so the next round does not spend the time.

---

## 20. `reliability.csharp.virtual-call-in-constructor`

**Pitfall.** A constructor calls a `virtual` method on itself; the override runs
against a derived instance whose own constructor has not executed yet.

**Concept source.** roslyn-analyzers / .NET code analysis — CA2214, "Do not call
overridable methods in constructors" (`dotnet/sdk`, MIT; docs `dotnet/docs`,
CC-BY-4.0). Concept only; no text taken.

**Severity.** `warning`, if it existed.

**Query.** None. Finding the unqualified call inside a `constructor_declaration`
is easy; deciding whether the *called member* is `virtual` or `abstract` is a
lookup by name into the enclosing type's member list — and into its base types,
which are usually in another file. Even restricted to the same file, that is a
symbol table, which is a different kind of engine than a query.

This is the boundary case worth naming precisely, because it is the one that
would tempt a third primitive. **P3 — same-file symbol resolution** (bind an
identifier to the declaration of the same name in the enclosing type, and read
its modifiers) would enable this item, would let item 9 follow
`var t = LoadAsync(); t.Result;` through a local, and would let item 19 read a
local's declared type. It is deliberately **not** proposed: it is a scope
tracker plus a member table, it is not "one bounded engine addition", and the
map draws the line at exactly this point. Naming it here is the argument for
where the line sits, not a request to move it.

**Disposition.** **Inexpressible** under the single-file query boundary.

---

## Primitives

Two are named. Both are query-language capabilities, not analysis engines, and
both are bounded.

### P1 — descendant-scoped child pattern

**What it is.** A way to write "a node matching B appearing anywhere in the
subtree of a node matching A", as opposed to today's "B is a direct child of A".
Concretely, a descendant axis in the pattern language, so that a pattern can
bind an outer node and an arbitrarily deep inner node in one match and share
predicates between them.

**Why it is needed.** Today the query must spell out every intermediate node,
and the intermediate nodes are unbounded: a statement inside a method may be
under any nesting of `if`, `try`, `foreach`, `switch_section`, `block` or
lambda.

**C# items that need it.**

| Item | What P1 buys |
| --- | --- |
| 17 `thread-sleep-in-async` | The whole rule. Without scoping to an `async` method the finding is not a defect. |
| 2 `throw-in-finally` | Recall. `finally { if (c) { throw …; } }` is missed today. |
| 11 `task-returns-null` | Recall. `if (c) { return null; }` is missed today, and it is the common shape. |
| 8, 9 blocking calls | An optional `async`-method scope, which would let 9 drop the `Async$` name heuristic. |

That is one rule that cannot exist without it and three that are materially
weaker. The map's bar is three candidates across two languages; the
cross-language half of that test is not this document's to run, but a
descendant axis is language-neutral by construction, and the same "X anywhere
inside an async function" shape exists in JavaScript, TypeScript and Python.

### P2 — negative descendant assertion

**What it is.** A structural negation: "the subtree rooted here contains no node
matching this pattern". Today negation exists only over a captured node's
*text*.

**Why it is needed.** Several real pitfalls are defined by an absence, and an
absence is not expressible by adding patterns.

**C# items that need it.**

| Item | What P2 buys |
| --- | --- |
| 18 `async-without-await` | The whole rule. There is no other way to say "no `await` inside". |
| 4 `rethrow-only-catch` | Precision. Excluding a `catch_clause` that has a `catch_filter_clause` would remove the one named noise idiom. |
| 16 `unreachable-after-return` | Brevity only — a twenty-two-way alternation becomes one negated node type. Not an enabler. |

One rule that cannot exist without it, one that would move from `info` to
`warning`, and one cosmetic. Weaker than P1 on this language alone. If the
cross-language sweep finds the same absence-shaped rule elsewhere — "an `async`
function with no `await`" exists verbatim in JavaScript and TypeScript, and
"a `catch` that does not use the caught binding" is near-universal — P2 clears
the bar; on C# alone it does not.

**Not proposed: P3, same-file symbol resolution.** See item 20. It would unlock
items 19 and 20 and improve 9, and it is out of scope by the map's own wording.
It is recorded so that a later round can see it was considered and refused.

## Concept sources and licensing

Every query in this document was written from `tree-sitter-c-sharp`'s
`node-types.json` and `grammar.json`. **No pattern text, query text, rule text
or message text was taken from any project below.** Every citation is
concept-only. Licences were verified this round from each project's own
repository, not from a secondary index.

| Source | Repo | Licence | Class | How verified |
| --- | --- | --- | --- | --- |
| .NET code analysis (CA rules) | `dotnet/sdk` (the analysers moved there from `dotnet/roslyn-analyzers`) | MIT | permissive | GitHub licence API on `dotnet/sdk`; `dotnet/roslyn-analyzers` README records the move |
| .NET rule documentation | `dotnet/docs` | CC-BY-4.0 | permissive, docs | GitHub licence API |
| Roslyn compiler warnings (CS0162, CS1717, CS1998, CS0642) | `dotnet/roslyn` | MIT | permissive | GitHub licence API |
| vs-threading analyzers (VSTHRD002) | `microsoft/vs-threading` | MIT | permissive | `LICENSE` read directly — the GitHub API reports `NOASSERTION` only because the file opens with a copyright preamble before the MIT text. **This closes the 2.1 matrix's "not re-verified" note on VSTHRD100.** |
| Meziantou.Analyzer (MA0022, MA0037, MA0042, MA0045, MA0072, MA0137, MA0191) | `meziantou/Meziantou.Analyzer` | MIT | permissive | GitHub licence API; rule titles from `docs/README.md` |
| Roslynator | `dotnet/roslynator` | Apache-2.0 | permissive | `LICENSE.txt` read directly (API reports `NOASSERTION`) — checked as an alternative concept source, not cited by any item |
| SonarSource C# rules (S1215, S2190, S2737) | `SonarSource/sonar-dotnet` | SONAR Source-Available License v1.0 | **not OSI** | `LICENSE.txt` read directly; rule titles from `analyzers/rspec/cs/S*.json` |

The three SonarSource citations are the only non-permissive ones. They are
concept-only, as the map's sourcing decision requires, and nothing from that
project may become fixture code or rule text.

## What this document excludes, and why

- **Already shipped in `rules/profiles/reliability-csharp.yaml`:**
  `empty-catch`, `self-comparison`, `rethrow-loses-stack`, `async-void`,
  `identical-if-branches`. Not repeated.
- **Already shipped in `rules/profiles/maintainability-csharp.yaml`:** the four
  metric rules (`function-length`, `parameter-count`, `nesting-depth`,
  `cyclomatic-complexity`). No new metric measure is proposed for C#; the four
  the engine has cover what a single file can say about size and shape.
- **Rejected by the 2.1 matrix on noise and not revived:**
  `maintainability.csharp.empty-method-body` (empty bodies are how a virtual
  hook and an interface no-op are spelled) and
  `maintainability.csharp.console-write` (fires on every console application's
  own output). Nothing learned this round changes either judgement.
- **Removed in 2.1 and revived here:** `self-assignment` (item 15) and
  `unreachable-after-return` (item 16). Both are included because the ticket
  asks whether a primitive would fix the failure mode, and the verified answer
  is that **neither needs one** — both failures were query defects, and the
  corrected queries are proved against the exact idioms that sank them.

## Not verified

- **No noise measurement.** Every "expected noise" line is an argument from the
  query's shape plus knowledge of the idiom, not a count. The per-kLOC rates the
  policy gates on need a run of `scripts/profile_noise.py` against
  Newtonsoft.Json, Dapper and AutoMapper, and that is implementation work.
- **No corpus rows.** The positive and negative snippets here separate cleanly
  through the product loader and scanner, but they are not corpus fixtures and
  carry no `NOTICE` stanza.
- **The three "do not ship" items were not measured.** Items 12, 13 and 14 are
  predicted to breach on shape. If the next round wants to overturn one, it must
  measure it rather than re-argue it.
- **No cross-language check on P1 and P2.** This document establishes what C#
  needs. Whether either primitive clears the map's "three candidates across two
  languages" bar depends on the other nine lists.
- **`log-interpolated-message` cannot be measured on the current noise set.**
  All three pinned C# repositories are libraries that barely log; the rule's
  real rate lives in service code that the set does not contain. This is
  evidence for the map's open question about whether the pinned set exercises
  the 2.2 pitfalls.
