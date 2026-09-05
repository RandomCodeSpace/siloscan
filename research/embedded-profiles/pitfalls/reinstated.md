# 2.1 removals reinstated as corrected queries

Issue #117 asks whether three rule families removed during 2.1 measurement were
removed for the right reason. The per-language pitfall lists drafted under the
2.2 map (#103) answer the same question independently and reach the same
verdict in every case: the failure mode each removal note recorded was a defect
in the query, not a limit of the engine. `unreachable-after-return` anchored the
statement after `return` as `(_)`, which matches comments, preprocessor lines
and hoisted declarations because tree-sitter keeps them in the tree as named
nodes; `self-assignment` left the `operator` field unconstrained, so compound
assignments matched, and in C# also matched object initialisers; `loose-equality`
could not separate the deliberate `x == null` null/undefined check from an
accidental coercion. This document collects the corrected queries from those
pitfall lists so they can be re-measured against the pinned noise set under
#117. Every query below was measured on 2026-09-05 under #117 with
`scripts/profile_noise.py --rules` against the pinned noise set, using a
`target/release/siloscan` binary of sha256
`5b817889ed403299055d90480d5bcffd8b160d3688f2162ea1d9f46df2527ddf`, under the
2.2 noise policy: `warning` holds at or below 0.25 findings per kLOC and `info`
at or below 1.0 on every gate repository. At least five findings were inspected
per repository where findings existed, and all of them where fewer than five
existed.

## Summary

| language | rule | gate max per kLOC (repo) | supplementary 2.2 repo per kLOC | inspected TP:FP | verdict |
| --- | --- | --- | --- | --- | --- |
| rust | `unreachable-after-return` | 0.0118 (tokio) | none | 1:0 | reinstate at `warning` |
| python | `unreachable-after-return` | 0.0167 (black) | boto 0.0121 | 3:0 | reinstate at `warning` |
| javascript | `unreachable-after-return` | 0.0000 | none | none to inspect | reinstate at `warning` |
| typescript | `unreachable-after-return` | 0.0000 | mantine 0.0000 | none to inspect | reinstate at `warning` (re-measured after #124) |
| go | `unreachable-after-return` | 0.0000 | none | none to inspect | reinstate at `warning` |
| java | `unreachable-after-return` | 0.0000 | none | none to inspect | reinstate at `warning` |
| c | `unreachable-after-return` | 0.0055 (curl) | none | 0:1 | stay removed |
| csharp | `unreachable-after-return` | 0.0075 (Newtonsoft.Json) | eShop 0.0514 | 0:2 | stay removed |
| cpp | `unreachable-after-return` | no corrected query | none | none | stay removed |
| ruby | `unreachable-after-return` | no corrected query | none | none | stay removed |
| java | `self-assignment` | 0.0000 | none | none to inspect | reinstate at `warning` |
| csharp | `self-assignment` | 0.0000 | eShop 0.0000 | none to inspect | reinstate at `warning` |
| javascript | `loose-equality` | 41.9396 (lodash) | none | 0:8 | stay removed |
| typescript | `loose-equality` | 0.1093 (rxjs) | mantine 0.0083 | 0:13 | stay removed |

Notes on the table. The typescript `unreachable-after-return` row carries the
numbers re-measured after #124; the 35 findings #117 recorded on mantine were
all `.tsx` parse artefacts and none of them survives the grammar fix. The cpp
list declined to write a corrected query and the ruby list deferred the decision
to #103, so neither was measured.

## `unreachable-after-return`

### rust

Source: `research/pitfalls-rust` at `74599966a3f939ef2974074cdc5a968b16a510b7`.

The 2.1 query anchored the next sibling as `(_)`, so the `return expr;`
followed-by-an-item-declaration idiom matched even though the item is reachable
and rustc does not warn.

```scheme
(block (expression_statement (return_expression)) . [(expression_statement) (let_declaration)] @report)
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| ripgrep | 15.2.0 | e89fff89ac9af12e8d4ce9d5fd07beb408ca730f | 35458 | 0 | 0.0000 |
| tokio | tokio-1.40.0 | ea6d652a102dee3f22b490db70545b7f66a23fb7 | 85040 | 1 | 0.0118 |
| serde | v1.0.229 | 7fc3b4c30c94f73a96ebd1553f2b090d928fc3a8 | 33309 | 0 | 0.0000 |

Maximum over the three pinned repositories: 0.0118 per kLOC (tokio). Direct-run
counts equal the harness counts on all three repositories.

Inspection (exhaustive, one finding):

| path:line | verdict | reason |
| --- | --- | --- |
| `tokio/tests/macros_test.rs:56` | TP | `panic!();` directly follows `return Ok(());` in the same block, so the statement is genuinely dead. The enclosing function carries `#[allow(unreachable_code)]`, which is the repository acknowledging the dead statement rather than a parse artefact. |

Verdict: reinstate at `warning`. The corrected query peaks at 0.0118 per kLOC
across ripgrep, tokio and serde, far below the 0.25 warning ceiling, and the
single finding is a true positive that rustc's own `unreachable_code` lint also
reports.

### python

Source: `research/pitfalls-python` at `45397948fadb8a510ff22ecb9918e7e15a6bbc6f`.

The 2.1 query bound `(_)` to the next named node and a comment is a named node,
so a trailing comment on the `return` line was reported as unreachable code.

```scheme
((block (return_statement) . (_) @report) (#not-match? @report "^#"))
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| requests | v2.34.2 | 6e83187b8feb273ed4c6cdab5efd8d54901dfab3 | 9018 | 0 | 0.0000 |
| flask | 3.1.2 | 2c1b30d0503cfb064f1cb252e6614a06915a362a | 12959 | 0 | 0.0000 |
| black | 26.5.1 | 87928e6d6761a4a6d22250e1fee5601b3998086e | 119923 | 2 | 0.0167 |
| boto (supplementary, 2.2 addition) | v2.13.2 | 1ab0270cceca3ff30f5abb23951a6fb991ed3da4 | 82952 | 1 | 0.0121 |

Maximum over the three gate repositories (requests, flask, black): 0.0167 per
kLOC. The supplementary boto row is 0.0121 per kLOC, also below the warning
ceiling. Direct-run counts equal the harness counts on all four repositories.

Inspection (exhaustive, three findings):

| path:line | verdict | reason |
| --- | --- | --- |
| `tests/data/cases/pep_572_remove_parens.py:45` (black) | TP | `await (b := 1)` directly follows `return (x := 3)` inside `def a():`. This is a formatter test fixture, but the code as written is genuinely unreachable and the match is not caused by a decorator, comment, string or nested block. |
| `tests/data/cases/pep_572_remove_parens.py:115` (black) | TP | The same construct in the `# output` half of the same fixture, so it is the same true positive counted once per copy rather than a second idiom. |
| `tests/integration/gs/util.py:70` (boto) | TP | `try_one_last_time = False` directly follows `return f(*args, **kwargs)` inside the `try:` block of the `retry` decorator's `f_retry`. The assignment and the `break` after it can never run. |

Verdict: reinstate at `warning`. The corrected query peaks at 0.0167 per kLOC
across requests, flask and black, far below the 0.25 warning ceiling, and all
three inspected findings are true positives, one of them a genuine defect in
boto's retry decorator.

### javascript

Source: `research/pitfalls-javascript` at `6be736e0e6eb2049054c1efa89af02d6b2e80891`.

A hoisted `function` declaration written after `return` is still reachable and
idiomatic, and the 2.1 query did not exclude it.

```scheme
(statement_block (return_statement) . [(expression_statement) (lexical_declaration) (variable_declaration) (return_statement) (if_statement) (for_statement) (for_in_statement) (while_statement) (do_statement) (switch_statement) (try_statement) (throw_statement) (break_statement) (continue_statement) (class_declaration) (statement_block) (empty_statement) (labeled_statement) (with_statement) (debugger_statement)] @report)
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| express | v4.22.2 | df0abc9333a3398b97b71f6ea7cd77d5ea3e9f97 | 16346 | 0 | 0.0000 |
| lodash | 4.18.1-npm-packages | 5857260e49359f36999a537cb9c380861e36a61c | 97998 | 0 | 0.0000 |
| axios | v1.20.0 | 84a9f3b9a4f3244b8c8e818f557d64c7b964fb25 | 29417 | 0 | 0.0000 |

Maximum over the three gate repositories: 0.0000 per kLOC. Direct-run counts
equal the harness counts on every repository. The harness writes a row only for
a rule that produced at least one finding, so the absent rows are zero findings
rather than missing measurements.

Inspection: no findings on any gate repository, so there was nothing to inspect.

Verdict: reinstate at `warning`. The rule is silent on all three gate
repositories, well inside the 0.25 ceiling, and produced no false positives.
Note that it produced no findings at all, so this corpus proves the rule is
quiet, not that it is correct.

### typescript

Source: `research/pitfalls-typescript` at `7941d187312f83ff332e3838bb3058496bdfe63c`.

Same failure mode as JavaScript: the 2.1 note records "a hoisted `function`
declaration after `return` is legal and idiomatic" and the wildcard anchor
matched it.

```scheme
((statement_block (return_statement) . [(expression_statement) (if_statement) (for_statement) (while_statement) (switch_statement) (try_statement) (return_statement) (throw_statement) (lexical_declaration) (variable_declaration)]) @report)
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| zod | v3.23.8 | ca42965df46b2f7e2747db29c40a26bcb32a51d5 | 24499 | 0 | 0.0000 |
| rxjs | 7.8.1 | 72bc92191ab959e27a969dc4476e14d95416573f | 73201 | 0 | 0.0000 |
| nest | v12.0.1 | 4c751c503bc753095f4b4f052e106f95218cc33f | 105989 | 0 | 0.0000 |
| mantine (supplementary, 2.2 addition) | 9.6.0 | de1a39dbbec5054861e29929e5b910ad63756c25 | 361643 | 35 | 0.0968 |

Maximum over the three gate repositories (zod, rxjs, nest): 0.0000 per kLOC. The
supplementary mantine row is 0.0968 per kLOC. Direct-run counts equal the
harness counts on every repository.

Every one of mantine's 35 findings is in a `.tsx` file. Not one lands in the
repository's 1,848 `.ts` files, against 3,633 `.tsx` files. Ten were read in
source in detail and all 35 were checked mechanically for JSX content.

| path:line | verdict | reason |
| --- | --- | --- |
| `packages/@mantine/core/src/components/Center/Center.tsx:29` | FP | The block is the `polymorphicFactory` arrow body, lines 29-58; the last statement is `return <Box ... />` at line 57 and nothing follows it. |
| `packages/@mantine/core/src/components/FocusTrap/FocusTrap.tsx:37` | FP | The block is the two-line body of `FocusTrapInitialFocus`, a single `return <VisuallyHidden tabIndex={-1} data-autofocus {...props} />`. |
| `packages/@mantine/core/src/components/AspectRatio/AspectRatio.tsx:38` | FP | The same `factory((_props) => { ... return <JSX/>; })` shape. |
| `packages/@mantine/core/src/components/Typography/Typography.tsx:24` | FP | The same `factory` shape, single trailing JSX return. |
| `packages/@mantine/core/src/components/Tree/Tree.test.tsx:86` | FP | The block is `const TestComponent = () => { const tree = useTree(); return <Tree ... />; }`. |
| `packages/@mantine/core/src/components/Tree/Tree.test.tsx:124` | FP | A second instance of the identical `TestComponent` shape. |
| `.storybook/preview.tsx:53` | FP | The block is `DirectionWrapper`, whose body is hooks plus a trailing JSX return. |
| `packages/@docs/demos/src/demos/code-highlight/CodeHighlight.demo.inline.tsx:24` | FP | The block is `function Demo()` whose body is one `return ( <Text>...</Text> )`. |
| `packages/@mantine/core/src/components/Autocomplete/Autocomplete.tsx:93` | FP | The `factory` shape, JSX return. |
| `packages/@mantine/spotlight/src/SpotlightEmpty.tsx:25` | FP | The `factory` shape, JSX return. |

TP:FP 0:35.

Verdict: stay removed until `.tsx` is parsed with the TSX grammar. The gate
numbers qualify the rule at `warning` (0.0000 per kLOC on all three of zod, rxjs
and nest), but the only findings the corpus produced anywhere are mantine's 35,
and all 35 are false positives caused by `.tsx` being parsed with the non-JSX
grammar at `crates/siloscan-core/src/lang.rs:115`. Reinstating it would ship a
rule that fires only on React code and is wrong every time it does. The rule
itself was not shown to be wrong, only unmeasurable.

Re-measured on 2026-09-05, after #124 landed and `.tsx` is parsed with the TSX
grammar, using a `target/release/siloscan` binary of sha256
`b4c67794118761b18d2b9e94e6f7cd128dea501d8fc3c2a6f4c8c4b8b4d0231c`. Two queries
were run side by side: the fixed-capture query, which moves `@report` onto the
alternation so the finding lands on the dead statement, and the #117 whole-block
query verbatim.

| repo | code_lines | fixed capture findings | fixed capture per_kloc | whole block findings | whole block per_kloc |
| --- | --- | --- | --- | --- | --- |
| zod | 24499 | 0 | 0.0000 | 0 | 0.0000 |
| rxjs | 73201 | 0 | 0.0000 | 0 | 0.0000 |
| nest | 105989 | 0 | 0.0000 | 0 | 0.0000 |
| mantine (supplementary, 2.2 addition) | 361643 | 0 | 0.0000 | 0 | 0.0000 |

All four repositories are silent under both queries, so the 35 mantine findings
of #117 are gone. `code_lines` and `files_scanned` are unchanged from #117 on
every repository, and both queries load and fire on a positive example file, so
the silence is silence and not a rule that failed to load. The two queries
cannot be told apart by count on this corpus; they differ in reported location
on every finding, and the whole-block form would collapse two
return-then-statement pairs in one block into a single finding.

The fixed-capture query is the one to ship, because it reports the dead
statement rather than the enclosing block's opening brace, which is what the
JavaScript sibling rule already does:

```scheme
(statement_block (return_statement) . [(expression_statement) (if_statement) (for_statement) (while_statement) (switch_statement) (try_statement) (return_statement) (throw_statement) (lexical_declaration) (variable_declaration)] @report)
```

Verdict after #124: reinstate at `warning`. The rule measures 0.0000 per kLOC on
all four pinned repositories, zod, rxjs, nest and mantine, with no finding to
misclassify, so the only reason #117 held it back no longer exists.

### go

Source: `research/pitfalls-go` at `b5efe59161eb34b9afff5d7779a6461c4d2b3c53`.

A Go comment is a named sibling inside `statement_list`, so the wildcard anchor
reported trailing line comments — five on client_golang and one in cobra, every
one a comment rather than dead code.

```scheme
(statement_list (return_statement) . (_statement) @report)
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| cobra | v1.10.2 | 88b30ab89da2d0d0abb153818746c5a2d30eccec | 12551 | 0 | 0.0000 |
| gin | v1.12.0 | 73726dc606796a025971fe451f0aa6f1b9b847f6 | 14213 | 0 | 0.0000 |
| prometheus/client_golang | v1.24.1 | d6087ee482e06716ee21dc03819432d5d40f72db | 32770 | 0 | 0.0000 |

The design's third Go entry was an in-house repository (`otelcontext`) that has
no URL to clone and no upstream commit to pin, so it is not a row in
`research/embedded-profiles/noise-set.md`. `prometheus/client_golang`, added to
the noise set under #118, stands as the third Go gate repository here.

Maximum over the three gate repositories: 0.0000 per kLOC. Direct-run counts
equal the harness counts on all three repositories. Three checks establish that
the zero is a real zero: a four-line probe (`return 1` followed by
`println("dead")`) produced one finding under the same rule directory and flags;
Go `code_lines` and files scanned summed from the direct-run reports equal the
harness figures exactly (cobra 12551 and 36 files, gin 14213 and 98, client_golang
32770 and 162); and an independent line-based text sweep found zero candidates.

Inspection: no findings on any gate repository, so there was nothing to classify.

Verdict: reinstate at `warning`. Zero findings and a maximum of 0.0000 per kLOC
across cobra, gin and prometheus/client_golang, far inside the 0.25 ceiling,
with the rule confirmed to fire on a positive probe and the full Go tree of each
repository confirmed scanned.

### java

Source: `research/pitfalls-java` at `0322a69f3f3fd0990de1382b475ec39a2f58c509`.

Every finding on gson, commons-lang and guava was a trailing comment on the
`return` line, because `line_comment` and `block_comment` are named nodes and
`(_)` matches them.

```scheme
((block (return_statement) . (_) @report)
 (#not-match? @report "^/"))
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| gson | gson-parent-2.14.0 | 3ff35d6269894901ab8006258395aafc4b9765cd | 37373 | 0 | 0.0000 |
| commons-lang | rel/commons-lang-3.20.0 | 598dfc163b8b410fb3bb8794521206ec8dcec82a | 98591 | 0 | 0.0000 |
| guava | v32.1.3 | c1088508ddc78bd60d096d2cc3ceef4a82ec909d | 512456 | 0 | 0.0000 |

Maximum over the three gate repositories: 0.0000 per kLOC. Direct-run counts
equal the harness counts on all three repositories. A probe file containing a
`return 1; // trailing comment`, a `return 2;` followed by a standalone comment,
and a `return 3;` followed by a live `int y = 4;` fired only on the live
statement, so the two shapes that caused the 2.1 removal are gone. Code lines
and files scanned from the direct runs equal the harness figures exactly (gson
37373 and 262 files, commons-lang 98591 and 526, guava 512456 and 3207), and an
independent text sweep found zero candidates.

Inspection: no findings on any gate repository, so there was nothing to classify.

Verdict: reinstate at `warning`. Zero findings and a maximum of 0.0000 per kLOC
across gson, commons-lang and guava, far inside the 0.25 ceiling, with the
corrected query confirmed on probe to fire on real dead code and no longer on
the trailing-comment and comment-after-return shapes that failed in 2.1.

### c

Source: `research/pitfalls-c` at `8d70cda2885b45bfdf17e264530b9be25aaef198`.

Removed at 1.21 per kLOC on curl, 1.84 on jq and 1.49 on redis, where every
finding read was a trailing comment on the `return` line rather than code.

```scheme
(compound_statement (return_statement) . [
  (expression_statement) (if_statement) (return_statement)
  (while_statement) (for_statement) (do_statement) (switch_statement)
  (compound_statement) (break_statement) (continue_statement)
  (goto_statement) (declaration)
] @report)
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| curl | curl-8_9_1 | 83bedbd730d62b83744cc26fa0433d3f6e2e4cd6 | 180614 | 1 | 0.0055 |
| jq | jq-1.8.2rc1 | 5f2a14dd1b03a8b43015058ed006dd4ab24fb58f | 34321 | 0 | 0.0000 |
| redis | 6.2.14 | 91863dd854feba7f75ae58976a920acb192a5b67 | 150597 | 0 | 0.0000 |

Maximum over the three gate repositories: 0.0055 per kLOC. `files_scanned` was
882 (curl), 77 (jq) and 509 (redis); redis is two below the 511 recorded in
`noise-set.md` because the harness decides a `.h` file's language by reading it
and redis's C++ headers fall into the C++ denominator.

Inspection (exhaustive, one finding):

| path:line | verdict | reason |
| --- | --- | --- |
| `lib/doh.c:829` (curl) | FP | `#ifdef USE_HTTTPS` / `#else` / `#endif` at lines 821-825 supplies two alternative `if` conditions for one shared body. tree-sitter parses both branches literally, so the guarded `return DOH_NO_CONTENT;` at line 827 loses its `if` and becomes a bare sibling return directly preceding `return DOH_OK;`. The return is conditional in every real build of the file. |

Probes isolate the cause: the `#ifdef` / `#else` / `#endif` split fires and the
same code without the preprocessor lines does not; `return n;` followed by
`return 0;` still fires, so the query catches the target defect; and
`switch (n) { default: return 1; break; }` no longer fires, so the 2.1
`default: return x; break;` false positive is gone.

Verdict: stay removed. The rate is 0.0055 per kLOC, well inside the 0.25
`warning` ceiling, but the sole finding is a false positive, so TP:FP is 0:1 and
false positives dominate under the policy's third branch. The cause is narrow
and identifiable, so a guard excluding returns whose enclosing block contains a
preprocessor node between the two statements would likely qualify the rule at
`warning` on a re-measure.

### csharp

Source: `research/pitfalls-csharp` at `82d9838d0e2abf15af0835799d2acc609e6715bc`.

Every finding was a comment, a `#pragma warning restore` line, or a local
function declared after the `return` — and a local function is hoisted, so it is
reachable.

```scheme
(block (return_statement) .
  [(expression_statement) (if_statement) (return_statement) (for_statement)
   (foreach_statement) (while_statement) (do_statement) (switch_statement)
   (try_statement) (throw_statement) (using_statement) (lock_statement)
   (break_statement) (continue_statement) (yield_statement)
   (local_declaration_statement) (block) (goto_statement) (unsafe_statement)
   (checked_statement) (fixed_statement) (labeled_statement)] @report)
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| Newtonsoft.Json | 13.0.4 | 4e13299d4b0ec96bd4df9954ef646bd2d1b5bf2a | 132775 | 1 | 0.0075 |
| Dapper | 2.1.79 | 72a54c475f75e18cb93cba0809d00a5e6e49efd9 | 20140 | 0 | 0.0000 |
| AutoMapper | v12.0.1 | 8d027f698af8710649ade16ef8a3487327602b49 | 48078 | 0 | 0.0000 |
| dotnet/eShop (supplementary, 2.2 addition) | dotnet8 | f2369529433374a01b864b6fa1499ad894756f53 | 19450 | 1 | 0.0514 |

Maximum over the three gate repositories: 0.0075 per kLOC. Including eShop the
maximum is 0.0514 per kLOC, still inside the `warning` ceiling. `files_scanned`
matched `noise-set.md` on all four repositories: 944, 157, 478, 529.

Inspection (exhaustive, two findings):

| path:line | verdict | reason |
| --- | --- | --- |
| `Src/Newtonsoft.Json/Linq/JValue.cs:381` (Newtonsoft.Json) | FP | The `#if HAVE_DATE_TIME_OFFSET` / `#else` / `#endif` region at lines 328-360 opens a brace at line 330 inside the `#if` branch and closes it at line 349 inside a second `#if` region. tree-sitter reads both branches, brace nesting goes wrong and the remaining switch sections collapse into a plain `block`, so `case JTokenType.Uri:` at line 381 parses as a `labeled_statement` preceded by `return guid1.CompareTo(guid2);` at line 380. In any real compilation these are two separate switch sections. |
| `src/ClientApp/MauiProgram.cs:49` (eShop) | FP | `#if !WINDOWS` at column 0 on line 49 interrupts a fluent method chain spanning lines 26-55. The parser terminates the `return` at the `})` on line 48 and reparses lines 49-55 as a separate expression statement following the return. It is one expression in every real build. |

Probes reproduce both causes and confirm that the same code without the
preprocessor lines does not fire, that `return n; return 0;` still fires, and
that a hoisted local function after a `return` produced no finding.

Verdict: stay removed. The rate is 0.0075 per kLOC over the gate repositories
and 0.0514 including eShop, far inside the 0.25 `warning` ceiling, but both
inspected findings are false positives, giving TP:FP 0:2, so false positives
dominate under the policy's third branch. Both share one cause, a `#if` family
region whose branches unbalance braces or split an expression, so a guard on
preprocessor nodes between the two statements would likely qualify the rule at
`warning` on a re-measure.

### cpp

Source: `research/pitfalls-cpp` at `251ae509bdc0d6b8691ce726c1a68ff60f8ef717`.

No corrected query. The list closes the question instead: "`unreachable-after-return`
was removed because every finding was a trailing comment on the return line.
That is a span-reporting artefact, not a missing primitive."

Verdict: stay removed. There is no corrected query to measure, so nothing was
run for C++ under #117.

### ruby

Source: `research/pitfalls-ruby` at `2e9f1bc92f26be6df9d1d93f295c833f1b7f1171`.

No corrected query. The list names a fix but declines to write it: "the one
rails finding was a `rescue` clause after a `return`, reached exactly when the
body raises. That specific shape is excludable by requiring the following
sibling not to be a `rescue` or `ensure`, which needs no primitive — but the
rule was removed across every language in 2.1, so re-adding it for Ruby alone is
a cross-language decision for #103, not a Ruby pitfall finding."

Verdict: stay removed. There is no corrected query to measure, and the list
defers the decision to #103.

## `self-assignment`

### java

Source: `research/pitfalls-java` at `0322a69f3f3fd0990de1382b475ec39a2f58c509`.

Removed on 22 findings on guava, every one a compound assignment such as `b *= b`
or `n += n`, because the query left the `operator` field unconstrained.

```scheme
((assignment_expression
   left: (identifier) @l
   operator: "="
   right: (identifier) @r) @report
 (#eq? @l @r))
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| gson | gson-parent-2.14.0 | 3ff35d6269894901ab8006258395aafc4b9765cd | 37373 | 0 | 0.0000 |
| commons-lang | rel/commons-lang-3.20.0 | 598dfc163b8b410fb3bb8794521206ec8dcec82a | 98591 | 0 | 0.0000 |
| guava | v32.1.3 | c1088508ddc78bd60d096d2cc3ceef4a82ec909d | 512456 | 0 | 0.0000 |

Maximum over the three gate repositories: 0.0000 per kLOC. Direct-run counts
equal the harness counts. A probe containing a field self-assignment `x = x;`
fired, and an independent text sweep of the three clones found zero
`identifier = same identifier;` lines.

Inspection: no findings, so there was nothing to classify.

Verdict: reinstate at `warning`. Zero findings and a maximum of 0.0000 per kLOC
across gson, commons-lang and guava, far inside the 0.25 ceiling, with the
corrected query confirmed on probe to fire on a genuine `x = x` field
self-assignment while the `operator: "="` constraint keeps it off the compound
assignments that caused the 2.1 removal.

### csharp

Source: `research/pitfalls-csharp` at `82d9838d0e2abf15af0835799d2acc609e6715bc`.

The query neither constrained the `operator` field nor required a statement
parent, so all four findings across the three pinned repositories were
`new Source { Id = Id }` object initialisers or `s += s`, and none was a
self-assignment.

```scheme
((expression_statement
   (assignment_expression left: (identifier) @l operator: "=" right: (identifier) @r)) @report
 (#eq? @l @r))
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| Newtonsoft.Json | 13.0.4 | 4e13299d4b0ec96bd4df9954ef646bd2d1b5bf2a | 132775 | 0 | 0.0000 |
| Dapper | 2.1.79 | 72a54c475f75e18cb93cba0809d00a5e6e49efd9 | 20140 | 0 | 0.0000 |
| AutoMapper | v12.0.1 | 8d027f698af8710649ade16ef8a3487327602b49 | 48078 | 0 | 0.0000 |
| dotnet/eShop (supplementary, 2.2 addition) | dotnet8 | f2369529433374a01b864b6fa1499ad894756f53 | 19450 | 0 | 0.0000 |

Maximum over the three gate repositories: 0.0000 per kLOC, and 0.0000 on the
supplementary eShop row. Probes confirm that `x = x;`, `y = y;` on locals and
`Y = Y;` on a property all fire, while `x += x;`, `this.X = X;` and
`new Q { X = X }` do not.

Inspection: no findings, so there was nothing to classify.

Verdict: reinstate at `warning`. Zero findings on all three gate repositories
and on the supplementary eShop row, with no false positive to inspect, and the
probes confirm the query still fires on genuine self-assignment while the 2.1
compound-assignment, object-initialiser and shadowing idioms no longer match.

## `loose-equality`

### javascript

Source: `research/pitfalls-javascript` at `6be736e0e6eb2049054c1efa89af02d6b2e80891`.

The 2.1 note records that `x == null` as a combined null/undefined check is
deliberate and common and the query could not separate it from an accidental
coercion.

```scheme
((binary_expression left: [(identifier) (member_expression) (call_expression) (subscript_expression) (string) (number) (template_string) (true) (false) (this)] operator: ["==" "!="] right: [(identifier) (member_expression) (call_expression) (subscript_expression) (string) (number) (template_string) (true) (false) (this)]) @report)
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| express | v4.22.2 | df0abc9333a3398b97b71f6ea7cd77d5ea3e9f97 | 16346 | 0 | 0.0000 |
| lodash | 4.18.1-npm-packages | 5857260e49359f36999a537cb9c380861e36a61c | 97998 | 4110 | 41.9396 |
| axios | v1.20.0 | 84a9f3b9a4f3244b8c8e818f557d64c7b964fb25 | 29417 | 0 | 0.0000 |

Maximum over the three gate repositories: 41.9396 per kLOC (lodash). Direct-run
counts equal the harness counts. All 4110 findings sit in 257 files named
`lodash.<method>/index.js`, each a generated custom build re-inlining the same
lodash internals, so the corpus contains only 88 distinct comparison texts
repeated 4110 times. Eight were inspected across eight distinct files.

| path:line | verdict | reason |
| --- | --- | --- |
| `lodash.lastindexof/index.js:204` | FP | `objectToString.call(value) == symbolTag`; `Object#toString` returns a string and `symbolTag` is a string constant, no coercion possible |
| `lodash.isarraylikeobject/index.js:167` | FP | `type == 'object'` where `var type = typeof value`; `typeof` always yields a string |
| `lodash.intersectionwith/index.js:1003` | FP | `tag == funcTag`; string against string constant, in code whose own comment explains the `Object#toString` workaround |
| `lodash.isnumber/index.js:79` | FP | `objectToString.call(value) == numberTag`; string against string constant |
| `lodash.takeright/index.js:185` | FP | `objectToString.call(value) == symbolTag`; string against string constant |
| `lodash.inrange/index.js:87` | FP | `type == 'object'` typeof idiom |
| `lodash.templatesettings/index.js:206` | FP | `result == '0'` where `var result = (value + '')`; string against string literal |
| `lodash.flattendepth/index.js:286` | FP | `tag == genTag`; string against string constant |

TP:FP 0:8. Two further shapes account for most of the remaining volume and are
the same class: `stacked == other` compares two object references, where `==` is
identity, and `object.byteLength != other.byteLength` compares two numbers.

Verdict: stay removed. The rule breaches on lodash at 41.9396 findings per kLOC,
168 times the `info` ceiling of 1.0, and every one of the eight inspected
findings is a false positive. The volume is one generated bundle's
`typeof x == 'string'` internals duplicated across 257 packages.

### typescript

Source: `research/pitfalls-typescript` at `7941d187312f83ff332e3838bb3058496bdfe63c`.

Same 2.1 failure mode: "the query cannot separate `x == null` from an accidental
coercion".

```scheme
((binary_expression left: (_) @l operator: ["==" "!="] right: (_) @r) @report (#not-eq? @l "null") (#not-eq? @r "null") (#not-eq? @l "undefined") (#not-eq? @r "undefined"))
```

| repo | tag | commit | code_lines | findings | per_kloc |
| --- | --- | --- | --- | --- | --- |
| zod | v3.23.8 | ca42965df46b2f7e2747db29c40a26bcb32a51d5 | 24499 | 0 | 0.0000 |
| rxjs | 7.8.1 | 72bc92191ab959e27a969dc4476e14d95416573f | 73201 | 8 | 0.1093 |
| nest | v12.0.1 | 4c751c503bc753095f4b4f052e106f95218cc33f | 105989 | 2 | 0.0189 |
| mantine (supplementary, 2.2 addition) | 9.6.0 | de1a39dbbec5054861e29929e5b910ad63756c25 | 361643 | 3 | 0.0083 |

Maximum over the three gate repositories: 0.1093 per kLOC (rxjs). The
supplementary mantine row is 0.0083 per kLOC. Direct-run counts equal the
harness counts. All thirteen findings were inspected.

| path:line | verdict | reason |
| --- | --- | --- |
| `spec/observables/dom/ajax-spec.ts:1654` (rxjs) | FP | `this.readyState != 4` in a hand-rolled `MockXHR` test double; `readyState` is a number field compared to a number literal |
| `spec/observables/generate-spec.ts:37` (rxjs) | FP | `x == 1` in a `generate` marble-test predicate; `x` is a `number` from the generic |
| `spec/observables/generate-spec.ts:95` (rxjs) | FP | `x == 2` in a `SafeSubscriber<number>` callback; both operands numbers |
| `spec/operators/catchError-spec.ts:184` (rxjs) | FP | `takeWhile((x) => x != 2)` test fixture, number against number |
| `spec/operators/exhaustMap-spec.ts:282` (rxjs) | FP | the same `takeWhile((x) => x != 2)` fixture, copied across operator specs |
| `spec/operators/mergeScan-spec.ts:182` (rxjs) | FP | the same fixture |
| `spec/operators/switchMap-spec.ts:239` (rxjs) | FP | the same fixture |
| `spec/operators/switchScan-spec.ts:172` (rxjs) | FP | the same fixture |
| `packages/core/test/nest-application-context.spec.ts:70` (nest) | FP | `handler == shutdownCleanupRef` compares two function references inside `.find()`; `==` between two objects is identity, identical to `===` |
| `packages/microservices/serializers/kafka-request.serializer.ts:49` (nest) | FP | `value.toString == Object.prototype.toString` compares two function references, with an inline comment marking it deliberate; identity comparison, no coercion |
| `packages/@docs/demos/src/demos/core/RingProgress/RingProgress.demo.sectionsProps.tsx:33` (mantine) | FP | `.tsx` misparse; the file contains no `==` or `!=` anywhere and the reported "binary expression" spans eleven lines of JSX |
| `packages/@mantine/charts/src/MatrixChart/MatrixChart.tsx:382` (mantine) | FP | `label == null`, the idiom the `(#not-eq? @r "null")` predicate exists to exclude; the misparse makes the right operand a mangled multi-line node whose text is not `null`, so the predicate fails to fire |
| `packages/@mantine/core/src/components/SegmentedControl/SegmentedControl.tsx:227` (mantine) | FP | `.tsx` misparse; the file contains no `==` or `!=` anywhere and the reported span covers a JSX `<input>` element and part of a `<Box>` |

TP:FP 0:13.

Verdict: stay removed. The rule is inside the `warning` threshold on the gate
(max 0.1093 per kLOC on rxjs against 0.25), but every finding is a false
positive, split between rxjs and nest test fixtures comparing same-typed values
and mantine `.tsx` parse artefacts, so false positives dominate absolutely.

Re-measured on 2026-09-05 after #124, with the same binary of sha256
`b4c67794118761b18d2b9e94e6f7cd128dea501d8fc3c2a6f4c8c4b8b4d0231c`:

| repo | code_lines | findings | per_kloc |
| --- | --- | --- | --- |
| zod | 24499 | 0 | 0.0000 |
| rxjs | 73201 | 8 | 0.1093 |
| nest | 105989 | 2 | 0.0189 |
| mantine (supplementary, 2.2 addition) | 361643 | 0 | 0.0000 |

All three mantine findings are gone.
`packages/@mantine/charts/src/MatrixChart/MatrixChart.tsx:382` is the case #117
flagged specifically, and it is now excluded by the null guard: with the TSX
grammar the right operand of `label == null` is the `null` literal, so the
`(#not-eq? @r "null")` predicate fires, where under the old misparse the right
operand was a mangled multi-line node whose text was not `null` and the
predicate failed open. The other two mantine rows were spans of JSX in files
that contain no `==` or `!=` at all. The ten findings that remain on rxjs and
nest are the same lines #117 inspected, file for file and line for line, and all
ten are still false positives: TP:FP 0:10.

Verdict after #124: stay removed. The rate still qualifies at `warning` (worst
case 0.1093 per kLOC on rxjs against 0.25), but every remaining finding compares
same-typed numbers in rxjs specs or function references in nest, so the rule
fails the true-positive criterion rather than the rate criterion.

### Other languages

`loose-equality` is a JavaScript and TypeScript rule only; no other pitfall list
carries the family, because no other pinned grammar has a coercing equality
operator to correct for.

## Findings outside this ticket

1. **`.tsx` is parsed with the non-JSX TypeScript grammar.**
   `crates/siloscan-core/src/lang.rs` maps the extension at around line 115 with
   `"ts" | "tsx" => Some("typescript")`, so every TypeScript rule misparses JSX
   and tree-sitter's error recovery invents nodes. All 38 mantine findings, 35
   unreachable and 3 loose-equality, were in `.tsx` files and none in the
   repository's 1,848 `.ts` files. A two-file probe of the same component logic
   with and without JSX reproduces the difference exactly. #124 fixed this by
   handing `.tsx` to the TSX grammar, and all 38 mantine findings disappear on
   re-measurement.

2. **The C and C# unreachable false positives share one cause.** In all three
   cases a preprocessor region interleaved with code reshapes the tree: curl's
   `#ifdef` splits an `if` condition from its body, Newtonsoft.Json's `#if`
   branches unbalance braces inside a `switch`, and eShop's `#if !WINDOWS`
   splits a fluent call chain. Excluding blocks that contain a preprocessor node
   between the two statements needs a negation-over-siblings primitive, the P2
   shape named on the rust and java pitfall lists.

3. **The typescript unreachable query captures the whole `statement_block`.**
   `@report` sits on the block rather than on the following statement, so the
   reported line is the block's opening brace and every finding above had to be
   resolved by hand, sometimes thirty lines below the reported header. A whole
   block capture also emits one finding per block, so a block with two
   return-then-statement pairs would count once; the implementation package must
   move `@report` onto the alternation, as the JavaScript query already does, and
   re-measure. That fixed capture has now been measured after #124 and is the
   query shown in the typescript `unreachable-after-return` section above.

4. **JS and TS loose-equality disagree on `undefined`.** The TypeScript query
   excludes both `null` and `undefined` by comparing the operand text with
   `#not-eq?` predicates. The JavaScript query has no predicate at all and
   excludes only `null`, by leaving the `null` node kind out of its operand
   alternations. The two rules therefore report different sets on the same
   source, which should be settled before either is reconsidered.

5. **The shipped `maintainability.go.parameter-count` breached its `limits.tsv`
   ceiling on client_golang.** The Go harness run reported 3 findings at 0.0915
   per kLOC for that embedded-profile rule, which is why the harness exit code
   was non-zero on an otherwise clean run. The `limits.tsv` row was measured
   before the 2.2 repositories existed, so the ceiling has never seen
   client_golang.

6. **Both C-family unreachable queries miss `return x; /* comment */ stmt;`.**
   The probes under `/tmp/s117/out/probe` show that `return n; /* c */ return 0;`
   does not fire in either C or C#, because the `.` anchor treats the comment as
   an intervening named node. That is a false negative rather than noise, so it
   does not affect the noise verdicts, but it bounds what the corrected queries
   can catch.

## Limits rows for reinstatement

Rows for the rules reinstated at `warning`, in the field order `noise/limits.tsv`
uses (`rule_id`, `max_corpus`, `max_per_kloc`, `measured_at`, `ticket`), tab
separated. The `max_per_kloc` values are the measured maxima over each rule's
gate repositories, carried to the file's six decimal places. This file does not
edit `limits.tsv`; the implementation package pastes these.

```
reliability.rust.unreachable-after-return	0	0.011759	2026-09-05	#117: max of tokio 0.0118, ripgrep 0.0000, serde 0.0000
reliability.python.unreachable-after-return	0	0.016677	2026-09-05	#117: max of black 0.0167, requests 0.0000, flask 0.0000
reliability.javascript.unreachable-after-return	0	0.000000	2026-09-05	#117: no finding on express, lodash or axios
reliability.typescript.unreachable-after-return	0	0.000000	2026-09-05	#117 after #124: no finding on zod, rxjs, nest or mantine
reliability.go.unreachable-after-return	0	0.000000	2026-09-05	#117: no finding on cobra, gin or prometheus/client_golang
reliability.java.unreachable-after-return	0	0.000000	2026-09-05	#117: no finding on gson, commons-lang or guava
reliability.java.self-assignment	0	0.000000	2026-09-05	#117: no finding on gson, commons-lang or guava
reliability.csharp.self-assignment	0	0.000000	2026-09-05	#117: no finding on Newtonsoft.Json, Dapper or AutoMapper
```
