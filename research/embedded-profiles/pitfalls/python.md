# Python pitfall list

Research for issue #106 under the 2.2 map #103. This document decides *what the
Python rules would be*; it writes no rule YAML and no engine code.

Twenty pitfalls, each dispositioned. Sixteen are **expressible** as a single-file
tree-sitter query over the pinned grammar, three **need a primitive** the engine
does not have, one is **inexpressible** under the single-file boundary.

Every rule id here is new. The four reliability rules and four metric rules the
2.1 documents already ship (`crates/siloscan-core/rules/profiles/reliability-python.yaml`,
`maintainability-python.yaml`) are out of scope, and so is every candidate the
2.1 matrix removed — those are handled separately in
[2.1 removals revisited](#21-removals-revisited).

## Boundaries this list was drawn inside

- **Single file.** One tree-sitter query per rule over one file, or a metric
  rule. No cross-file resolution, no types, no dataflow (#103 Notes).
- **Concept-only citations.** Every `Concept source` below names an upstream
  linter's rule as a *concept*. No pattern text, query text, message text or
  test fixture was taken from any upstream project. Every query and every
  example in this document was written here.
- **Noise policy.** `warning` at or below 0.25 findings per kLOC and `info` at
  or below 1.0 on any pinned repository; removal, not tuning; one `paths`
  exclusion per rule is allowed before removal (#103 Notes).
- **Predicates.** The loader accepts only the text-predicate set — `eq?`,
  `not-eq?`, `any-eq?`, `any-not-eq?`, `match?`, `not-match?`, `any-match?`,
  `any-not-match?`, `any-of?`, `not-any-of?` — and
  `every_shipped_document_loads_strictly` fails a document that uses anything
  else. Nothing below uses anything else.

## How each query was verified

Grammar: `tree-sitter-python` **0.25.0**, the version pinned in
`crates/siloscan-core/Cargo.toml`, read as
`~/.cargo/registry/src/*/tree-sitter-python-0.25.0/grammar.js` for every node
name, field name and token alias used below.

Each query was run through the product's own path, not by hand: a throwaway
integration test built a one-rule document around the query, loaded it with
`siloscan_core::rules::load_str` under the identity `reliability-python@1` —
the same call `plan::resolve` makes — assembled a `RuleSet`, and scanned a
two-file temporary corpus with `siloscan_core::scan::scan`, exactly as
`tests/profile_corpus.rs` does for its in-test document. A query passes when it
loads, reports every positive line and reports nothing in the negative file.
The test is not committed; it was a measuring instrument, not a deliverable.

Two grammar facts cost a first attempt each and are worth recording:

- `is not` and `not in` are **single aliased tokens**, not two. A query written
  `(comparison_operator "is" …)` silently misses `x is not 3`. Both spellings
  must be listed: `["is" "is not"]`.
- `boolean_operator` names its operator with the field `operator`. Without
  `operator: "or"` a rule about `x == 1 or 2` also matches the pre-ternary idiom
  `cond and a or b`, which is where its false positives came from.

### The indicative survey, and what it is not

Each query was also run over the CPython 3.12 standard library at
`/usr/lib/python3.12` — 574 files, ~227 kLOC of code lines — to find the idioms
that produce noise. **This is not the pinned noise set** and its numbers are not
gate numbers: the gate is `scripts/profile_noise.py` against
`research/embedded-profiles/noise-set.md`, whose Python entries are `requests`
2.34.2, `flask` 3.1.2 and `black` 26.5.1. The stdlib was used precisely because
those three are not representative for this purpose — see
[What this means for the pinned noise set](#what-this-means-for-the-pinned-noise-set).

Where a `findings/kLOC` figure appears below it is this survey, labelled
`stdlib`, and it is a signal about which idiom fires, not a measurement of the
gate.

## Summary

| # | id | severity | disposition | expected noise (idiom) |
| --- | --- | --- | --- | --- |
| 1 | `reliability.python.is-literal-comparison` | warning | expressible | none; interned-literal identity tests are written `==` |
| 2 | `reliability.python.singleton-equality-comparison` | warning | expressible | numpy/pandas elementwise `series == None` masks |
| 3 | `reliability.python.self-assignment` | warning | expressible | none once scoped to a function body; module- and class-scope rebinding is excluded by construction |
| 4 | `reliability.python.duplicate-dict-key` | warning | expressible | none; only byte-identical string keys |
| 5 | `reliability.python.implicit-string-concat-in-collection` | warning | expressible | wrapped long messages inside a collection, excluded by the single-line predicate |
| 6 | `reliability.python.raise-not-implemented` | warning | expressible | none |
| 7 | `reliability.python.return-in-finally` | warning | expressible | deliberate exception suppression in cleanup wrappers |
| 8 | `reliability.python.duplicate-definition` | warning | expressible | version-gated and `try/except ImportError` redefinition, excluded by construction |
| 9 | `reliability.python.missing-self-parameter` | warning | expressible | class-body functions deliberately written without `self` — symmetric operator implementations, class-body factories |
| 10 | `reliability.python.comparison-against-bare-literal` | warning | expressible | none once the operator is pinned to `or` |
| 11 | `reliability.python.subprocess-shell-true` | warning | expressible | deliberate shell invocation in tooling and process wrappers |
| 12 | `reliability.python.yaml-load-without-loader` | warning | expressible | none |
| 13 | `reliability.python.open-without-encoding` | info | expressible | a module-local `open` that is not the builtin (`os.open`, `gzip.open`) |
| 14 | `maintainability.python.lambda-assignment` | info | expressible | dispatch tables and small key functions bound to a name |
| 15 | `maintainability.python.star-import` | info | expressible (one `paths` exclusion) | package `__init__.py` re-export |
| 16 | `maintainability.python.f-string-without-placeholder` | info | needs primitive (P3) | the leading fragment of a multi-part implicitly concatenated f-string |
| 17 | `reliability.python.eq-without-hash` | warning | needs primitive (P1) | `__hash__` supplied by assignment rather than `def` |
| 18 | `reliability.python.loop-variable-in-closure` | warning | needs primitive (P2) | n/a — no query to be noisy |
| 19 | `maintainability.python.unused-import` | info | needs primitive (P2) | n/a — no query to be noisy |
| 20 | `reliability.python.unreachable-except-clause` | warning | inexpressible | n/a — no query to be noisy |

---

## 1. `reliability.python.is-literal-comparison`

**Pitfall.** `is` compares object identity, so comparing with a string or number
literal tests whether the interpreter happened to intern that value; CPython
raises a `SyntaxWarning` for it and the result is not portable.

**Concept source.** ruff — `F632 is-literal` (MIT), reimplementing Pyflakes.
Concept only; no text taken.

**Severity.** `warning`.

**Query.** Verified: loads, fires on both positives, silent on the negative.

```scheme
(comparison_operator ["is" "is not"] [(string) (integer) (float)] @report)
```

```python
# fires
def f(x):
    if x is "y":
        return 1
    if x is not 3:
        return 2
    return 0

# does not fire
def f(x):
    if x is None:
        return 1
    if x == "y":
        return 2
    return 0
```

**Expected noise.** None. `is None` / `is not None` is the only common identity
test and `none` is not in the literal set. stdlib: 0 findings.

**Disposition.** **Expressible.**

## 2. `reliability.python.singleton-equality-comparison`

**Pitfall.** `== None`, `== True` and `== False` invoke `__eq__` on the left
operand, so a class with a custom `__eq__` — or a NumPy array — answers
something other than the identity question the author meant to ask.

**Concept source.** ruff — `E711 comparison-to-none` and `E712
true-false-comparison` (MIT), reimplementing pycodestyle. Concept only; no text
taken.

**Severity.** `warning`.

**Query.**

```scheme
(comparison_operator ["==" "!="] [(none) (true) (false)] @report)
```

```python
# fires
def f(x):
    if x == None:
        return 1
    if x != True:
        return 2
    return 0

# does not fire
def f(x):
    if x is None:
        return 1
    if x is not True:
        return 2
    return 0
```

**Expected noise.** The idiom that produces it is the NumPy/pandas elementwise
mask — `series == None`, `frame == True` — where `==` is deliberate because `is`
would not broadcast. That is a data-science idiom, absent from the pinned Python
repositories and absent from the stdlib: 1 finding over ~227 kLOC (0.004 per
kLOC), and that one is a genuine `!= False` in `wsgiref/validate.py`.

**Disposition.** **Expressible.**

## 3. `reliability.python.self-assignment`

**Pitfall.** `x = x` inside a function body binds a local to itself; either it
is dead, or the author meant to assign something else, or — where `x` was meant
to be the enclosing scope's name — it raises `UnboundLocalError`.

**Concept source.** ruff — `PLW0127 self-assigning-variable` (MIT),
reimplementing pylint. Concept only; no text taken.

**Severity.** `warning`.

**Query.** Scoped to a function body on purpose; see the noise note.

```scheme
((function_definition body: (block (expression_statement (assignment left: (identifier) @l right: (identifier) @r) @report))) (#eq? @l @r))
```

```python
# fires
def f(x):
    x = x
    return x

# does not fire
def f(x, y):
    x = y
    return x
```

**Expected noise.** The unscoped form of this rule — the obvious
`((assignment left: (identifier) @l right: (identifier) @r) @report (#eq? @l @r))` —
measures **133 findings on the stdlib, 0.586 per kLOC**, more than twice the
`warning` budget, and every sample read is the same idiom: a name rebound onto
itself at module or class scope to pin it into a namespace. `_pyio.py` has
`BlockingIOError = BlockingIOError` under a "rebind for compatibility" comment;
`dbm/dumb.py` has `_os = _os` inside a class body so `_commit()` still has a
reference during interpreter shutdown. Restricting the pattern to a function
body removes the idiom by construction: stdlib drops to **0 findings**.

The cost is recall — the query reaches only statements that are direct children
of the function's own block, so `if c: x = x` is missed. That is the right
trade: the rule is about a shape that is always wrong where it fires.

**Disposition.** **Expressible.**

## 4. `reliability.python.duplicate-dict-key`

**Pitfall.** A dict literal with the same key twice silently keeps the last
value; the earlier entry, and whatever the author intended by it, is gone.

**Concept source.** ruff — `F601 multi-value-repeated-key-literal` (MIT),
reimplementing Pyflakes. Concept only; no text taken.

**Severity.** `warning`.

**Query.** Two `pair` children in document order with byte-identical key text;
`@report` is the second pair, which is the entry that wins.

```scheme
((dictionary (pair key: (string) @a) (pair key: (string) @b) @report) (#eq? @a @b))
```

```python
# fires
D = {
    "a": 1,
    "b": 2,
    "a": 3,
}

# does not fire
D = {
    "a": 1,
    "b": 2,
    "c": 3,
}
```

**Expected noise.** None: the comparison is on the key's source text, so
`{"a": 1, 'a': 2}` — same key, different quoting — is a miss rather than a false
positive, and nothing else collides. stdlib: 0 findings.

**Disposition.** **Expressible.**

## 5. `reliability.python.implicit-string-concat-in-collection`

**Pitfall.** Two string literals side by side inside a list, set or tuple
concatenate into one element. Inside a collection this is almost always a
missing comma, and the collection is one element shorter than it reads.

**Concept source.** ruff — `ISC001 single-line-implicit-string-concatenation`
(MIT), reimplementing flake8-implicit-str-concat. Concept only; no text taken.

**Severity.** `warning`.

**Query.** The `#not-match?` on a newline is what keeps the rule to the
missing-comma case.

```scheme
((list (concatenated_string) @report) (#not-match? @report "\n"))
((set (concatenated_string) @report) (#not-match? @report "\n"))
((tuple (concatenated_string) @report) (#not-match? @report "\n"))
```

```python
# fires
NAMES = [
    "alpha",
    "beta" "gamma",
]

# does not fire
NAMES = [
    "alpha",
    "beta",
]
TEXT = (
    "one long "
    "sentence"
)
```

**Expected noise.** Without the newline predicate the rule measures **13
findings on the stdlib** and every one is the same deliberate idiom: a long
message wrapped across lines inside a tuple or list, as in `http/__init__.py`'s
status-code table and `pydoc.py`'s `topics` dict. A wrapped concatenation always
contains a newline in its own source text and a missing comma on one line never
does, so one text predicate separates them exactly. With it, stdlib drops to
0 findings.

Note that a parenthesised multi-line concatenation is a
`parenthesized_expression`, not a `tuple`, so the legitimate long-string idiom
is outside the pattern anyway; the predicate covers the case where the wrapped
string really is an element of a collection.

**Disposition.** **Expressible.**

## 6. `reliability.python.raise-not-implemented`

**Pitfall.** `raise NotImplemented` raises the *sentinel value* the binary
operator protocol uses, not the exception; Python 3 rejects it with
`TypeError: exceptions must derive from BaseException`, so the abstract method
that was supposed to say "override me" says something else entirely.

**Concept source.** ruff — `F901 raise-notimplemented` (MIT), reimplementing
Pyflakes. Concept only; no text taken.

**Severity.** `warning`.

**Query.** Two patterns, bare and called; the engine de-duplicates on
`(rule id, start, end)`.

```scheme
((raise_statement (identifier) @report) (#eq? @report "NotImplemented"))
((raise_statement (call function: (identifier) @report)) (#eq? @report "NotImplemented"))
```

```python
# fires
def f():
    raise NotImplemented


def g():
    raise NotImplemented()

# does not fire
def f():
    raise NotImplementedError


def g():
    raise NotImplementedError("g")
```

**Expected noise.** None. `#eq?` is exact, so `NotImplementedError` never
matches, and there is no correct program that raises the sentinel. stdlib: 0
findings.

**Disposition.** **Expressible.**

## 7. `reliability.python.return-in-finally`

**Pitfall.** A `return`, `break` or `continue` in a `finally` block discards any
in-flight exception. The exception the `try` raised never reaches the caller and
the traceback is gone.

**Concept source.** ruff — `B012 jump-statement-in-finally` (MIT),
reimplementing flake8-bugbear. Concept only; no text taken.

**Severity.** `warning`.

**Query.** `finally_clause` has no field for its suite, so the `block` is
matched positionally.

```scheme
(finally_clause (block [(return_statement) (break_statement) (continue_statement)] @report))
```

```python
# fires
def f(g):
    try:
        return g()
    finally:
        return 0

# does not fire
def f(g):
    try:
        return g()
    finally:
        g.close()
```

**Expected noise.** The one idiom that would produce it is a cleanup wrapper
that swallows teardown failures on purpose — `finally: return default`. It is
rare and it is exactly the shape a reviewer wants shown. stdlib: 0 findings.

**Disposition.** **Expressible.**

## 8. `reliability.python.duplicate-definition`

**Pitfall.** Two `def`s with the same name in the same block: the second wins
silently and the first is dead code, usually a bad merge or a copy-paste.

**Concept source.** ruff — `F811 redefined-while-unused` (MIT), reimplementing
Pyflakes. Concept only; no text taken.

**Severity.** `warning`.

**Query.** Two patterns because the container is `module` at top level and
`block` inside a class or function. Sibling enumeration does the work: the two
`function_definition` children need not be adjacent, only in order.

```scheme
((module (function_definition name: (identifier) @a) (function_definition name: (identifier) @b) @report) (#eq? @a @b))
((block (function_definition name: (identifier) @a) (function_definition name: (identifier) @b) @report) (#eq? @a @b))
```

```python
# fires
def f():
    return 1


def f():
    return 2

# does not fire
import sys

if sys.version_info >= (3, 12):
    def f():
        return 1
else:
    def f():
        return 2

try:
    def g():
        return 1
except ImportError:
    def g():
        return 2


class C:
    @property
    def v(self):
        return self._v

    @v.setter
    def v(self, n):
        self._v = n
```

**Expected noise.** Two idioms would produce it and the grammar excludes both
for free. Conditional definition — version gates, `try/except ImportError`
fallbacks — puts the two `def`s in *different* blocks, so the pattern cannot
pair them. `@property`/`@x.setter` pairs and `@typing.overload` stubs are
`decorated_definition` nodes, and a bare `(function_definition)` child pattern
does not match through a decorator. stdlib: 0 findings.

**Disposition.** **Expressible.**

## 9. `reliability.python.missing-self-parameter`

**Pitfall.** An undecorated method in a class body whose first parameter is not
`self`: every call through an instance passes the instance into the wrong slot.

**Concept source.** ruff — `N805 invalid-first-argument-name-for-method` (MIT),
reimplementing pep8-naming. Concept only; no text taken.

**Severity.** `warning`.

**Query.** The leading `.` anchor pins the capture to the *first* parameter.

```scheme
((class_definition body: (block (function_definition parameters: (parameters . (identifier) @p)) @report)) (#not-any-of? @p "self" "cls" "mcs" "mcls" "metacls"))
```

```python
# fires
class C:
    def f(x):
        return x

# does not fire
class C:
    def f(self):
        return self

    @staticmethod
    def g(x):
        return x

    @classmethod
    def h(cls):
        return cls

    def i(self, *args):
        return args

    def j(self, x):
        def inner(y):
            return y
        return inner(x)


def outer():
    def helper(x):
        return x
    return helper
```

**Expected noise.** Three shapes were candidates and two are excluded by
construction: `@staticmethod` / `@classmethod` are `decorated_definition` nodes
the pattern does not reach, and a nested function is not a direct child of the
class body. What remains is the **class-body function deliberately written
without `self`**, and the stdlib has a concentrated example of it:
`fractions.py` defines `_operator_fallbacks(monomorphic_operator,
fallback_operator)` and calls it in the class body to build the real methods,
and it defines the operator implementations it feeds that factory as
`def _add(a, b)` — symmetric binary operators whose first parameter is
deliberately not `self`. An early run also flagged `abc.py`'s
`def __new__(mcls, …)`, a naming variant handled by widening the
`#not-any-of?` set rather than a distinct idiom.

Rate: 34 findings, 0.150 per kLOC — inside the `warning` budget, and most of it
is one file's house style.

**Disposition.** **Expressible.** The deliberate-non-`self` idiom is the
residual false positive; distinguishing it from a genuine mistake needs P2.

## 10. `reliability.python.comparison-against-bare-literal`

**Pitfall.** `if x == 1 or 2:` reads as "x is 1 or 2" and means "x == 1, or else
the truthy constant 2", so the branch is always taken.

**Concept source.** Original to this repository. No upstream linter concept was
used; pylint's `condition-evals-to-constant` and Sonar's constant-condition
checks are adjacent but describe a different shape.

**Severity.** `warning`.

**Query.** The `operator: "or"` field is load-bearing; see the noise note.

```scheme
(boolean_operator left: (comparison_operator) operator: "or" right: [(integer) (float) (string)] @report)
```

```python
# fires
def f(x):
    if x == 1 or 2:
        return 1
    return 0

# does not fire
def f(x):
    if x == 1 or x == 2:
        return 1
    if x == 1 or x in (2, 3):
        return 2
    return 0
```

**Expected noise.** Without `operator: "or"` the rule measures **8 findings on
the stdlib** and they are all one idiom: the pre-conditional-expression ternary
`cond and a or b`, which `locale.py` uses throughout
(`conv[val<0 and 'n_cs_precedes' or 'p_cs_precedes']`). Those match on the `and`
arm, whose right operand is a deliberate literal. Pinning the operator to `or`
excludes them; the outer `or` of that idiom has a `boolean_operator` on its left,
not a `comparison_operator`, so it does not match either.

Rate after the fix: 0 findings on the stdlib.

**Disposition.** **Expressible.**

## 11. `reliability.python.subprocess-shell-true`

**Pitfall.** `shell=True` hands the command line to a shell, so any interpolated
value is shell syntax and a value containing `;` or `$(…)` is arbitrary code.

**Concept source.** ruff — `S602 subprocess-popen-with-shell-equals-true` (MIT),
reimplementing Bandit. Concept only; no text taken.

**Severity.** `warning`.

**Query.** Keyed on the keyword argument rather than on the callee, because the
callee is spelled `subprocess.run`, `Popen`, `check_output` and several more.

```scheme
((call arguments: (argument_list (keyword_argument name: (identifier) @k value: (true)))) @report (#eq? @k "shell"))
```

```python
# fires
import subprocess


def f(cmd):
    return subprocess.run(cmd, shell=True)

# does not fire
import subprocess


def f(cmd):
    return subprocess.run(cmd, shell=False)
```

**Expected noise.** The idiom is deliberate shell invocation in tooling: process
wrappers and CLI plumbing that genuinely want a shell and control the command
string. stdlib measures 6 findings, 0.026 per kLOC — `os.popen`, `platform.py`'s
`uname` probe, `pydoc`'s pager — all deliberate, all the shape a reviewer wants
to see. Well inside the `warning` budget.

**Disposition.** **Expressible.**

## 12. `reliability.python.yaml-load-without-loader`

**Pitfall.** `yaml.load` without an explicit safe loader constructs arbitrary
Python objects from the document, so parsing untrusted YAML executes code.

**Concept source.** ruff — `S506 unsafe-yaml-load` (MIT), reimplementing Bandit.
Concept only; no text taken.

**Severity.** `warning`.

**Query.** The receiver is pinned to `yaml` so that `json.load`, `pickle.load`
and every other `.load` are outside the pattern; the argument list is checked as
text for a loader.

```scheme
((call function: (attribute object: (identifier) @o attribute: (identifier) @m) arguments: (argument_list) @args) @report (#eq? @o "yaml") (#eq? @m "load") (#not-match? @args "Loader"))
```

```python
# fires
import yaml


def f(text):
    return yaml.load(text)

# does not fire
import yaml
import json


def f(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def g(fh):
    return json.load(fh)
```

**Expected noise.** None found. `import yaml as y` aliasing is a miss, not a
false positive. stdlib: 0 findings, as expected — PyYAML is not in the standard
library, which also means the pinned Python noise set will not exercise this
rule at all.

**Disposition.** **Expressible.**

## 13. `reliability.python.open-without-encoding`

**Pitfall.** A text-mode `open` with no `encoding=` uses
`locale.getpreferredencoding()`, so the same code reads a different file on a
different machine, and CI passes while a user's run raises
`UnicodeDecodeError`.

**Concept source.** ruff — `PLW1514 unspecified-encoding` (MIT), reimplementing
pylint. Concept only; no text taken.

**Severity.** `info`.

**Query.** Two text predicates on the argument list: one for an explicit
encoding, one for a binary mode string, which has no encoding to specify.

```scheme
((call function: (identifier) @f arguments: (argument_list) @args) @report (#eq? @f "open") (#not-match? @args "encoding") (#not-match? @args "[\"'][rwxa+]*b[rwxa+]*[\"']"))
```

```python
# fires
def f(path):
    with open(path) as fh:
        return fh.read()


def g(path, text):
    with open(path, "w") as fh:
        fh.write(text)

# does not fire
from pathlib import Path


def f(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def g(path):
    with open(path, "rb") as fh:
        return fh.read()


def h(path):
    return Path(path).open()
```

**Expected noise.** stdlib measures 29 findings, 0.128 per kLOC — inside the
`info` budget and inside the `warning` budget too, but the samples name the
idiom that keeps it at `info`: **a module-local `open` that is not the
builtin.** `os.py` calls `open(top, O_RDONLY | O_NONBLOCK, dir_fd=dir_fd)`,
which is `os.open` and returns a file descriptor; `aifc.py` calls its own
module-level `open`. Deciding which `open` a call names is exactly P2.

**Disposition.** **Expressible** at `info`. Promotion to `warning` would need P2.

## 14. `maintainability.python.lambda-assignment`

**Pitfall.** `f = lambda x: …` produces a function whose `__name__` is
`<lambda>`, so every traceback, profile and repr through it is anonymous, and it
gains nothing over `def`.

**Concept source.** ruff — `E731 lambda-assignment` (MIT), reimplementing
pycodestyle. Concept only; no text taken.

**Severity.** `info`.

**Query.**

```scheme
(assignment left: (identifier) right: (lambda) @report)
```

```python
# fires
double = lambda x: x * 2

# does not fire
def double(x):
    return x * 2


SORTED = sorted([1], key=lambda x: -x)
```

**Expected noise.** The idiom is the small key function or dispatch-table entry
bound to a name for one local use — `configparser.py` and `_pydecimal.py` both
do it. stdlib measures 30 findings, 0.132 per kLOC, comfortably inside the
`info` budget of 1.0. A lambda passed as an argument is not an `assignment` and
never matches, which is what keeps the number this low.

**Disposition.** **Expressible.**

## 15. `maintainability.python.star-import`

**Pitfall.** `from x import *` makes the module's namespace depend on another
module's contents, so a name can appear, vanish or shadow a local without any
line in this file changing.

**Concept source.** ruff — `F403 undefined-local-with-import-star` (MIT),
reimplementing Pyflakes. Concept only; no text taken.

**Severity.** `info`.

**Query.**

```scheme
(import_from_statement (wildcard_import) @report)
```

```python
# fires
from os.path import *

# does not fire
from os.path import join
```

**Expected noise.** One idiom, and it dominates: the package `__init__.py` that
re-exports its submodules. stdlib measures 56 findings, 0.247 per kLOC, and the
sample is `asyncio/__init__.py` five times over. That is inside the `info`
budget as it stands, but the finding is not useful there, so this rule should
ship with the profile's one allowed `paths` exclusion set to `__init__.py`,
recorded in the document header per the #103 noise policy.

**Disposition.** **Expressible**, with one `paths` exclusion.

## 16. `maintainability.python.f-string-without-placeholder`

**Pitfall.** An `f` prefix on a string with no `{…}` in it is a placeholder that
was removed, or a prefix that was meant for the next line; either way the string
is not doing what its prefix says.

**Concept source.** ruff — `F541 f-string-missing-placeholders` (MIT),
reimplementing Pyflakes. Concept only; no text taken.

**Severity.** `info`.

**Query.** This one loads and passes its own examples, and is still the wrong
rule:

```scheme
((string) @report (#match? @report "^[rRbBuU]*[fF]") (#not-match? @report "[{]"))
```

```python
# fires
def f():
    return f"Node can't use cause without an exception."

# does not fire
"""Module docstring."""


def f(name):
    return f"hello {name}"


def g():
    return "hello"


def h(name):
    return rf"\\d{name}"
```

**Expected noise.** stdlib measures 88 findings, 0.388 per kLOC. The rate is
inside the `info` budget; the findings are not right. The dominant idiom is the
**leading fragment of a multi-part implicitly concatenated f-string**:

```python
raise TypeError(f"Expected a list of types, an ellipsis, "
                f"or None, got {value!r}")
```

The first fragment is a `(string)` node with an `f` prefix and no brace, so it
matches, even though the expression it belongs to has placeholders. The
expression-level node is `concatenated_string`; the fragment is its child. A
tree-sitter pattern can constrain a node's children and its fields, but it
cannot say "this node's parent is not a `concatenated_string`", and no text
predicate reaches outside the captured node.

Matching `(concatenated_string) @report` with the same two predicates handles
the concatenated case correctly. It is the *lone* string that cannot be
expressed without excluding one parent kind.

**Disposition.** **Needs primitive: P3, parent-kind exclusion.**

## 17. `reliability.python.eq-without-hash`

**Pitfall.** Defining `__eq__` without `__hash__` sets `__hash__` to `None`, so
instances of the class stop being usable in a set or as a dict key — a change
the author did not write and usually does not notice until runtime.

**Concept source.** ruff — `PLW1641 eq-without-hash` (MIT), reimplementing
pylint. Concept only; no text taken.

**Severity.** `warning`.

**Query.** The closest expressible approximation loads and passes its examples:

```scheme
((class_definition body: (block) @b) @report (#match? @b "def __eq__") (#not-match? @b "__hash__"))
```

```python
# fires
class C:
    def __eq__(self, other):
        return True

# does not fire
class C:
    def __eq__(self, other):
        return True

    def __hash__(self):
        return 0
```

It is a text search over the class body's source, and that is why it is not
shippable. It matches the words `def __eq__` inside a docstring, a comment or a
string constant in the class body; it is defeated by any mention of `__hash__`
anywhere in the body, including in prose; and it cannot see a `__hash__`
inherited from a base class in the same file. The narrow spelling of the
predicate, `#not-match? @b "def __hash__"`, measures 31 findings on the stdlib,
and the samples in `_collections_abc.py` are classes that supply `__hash__` by
assignment (`__hash__ = Set._hash`) rather than by `def`. Widening it to
`#not-match? @b "__hash__"`, as written above, is what excludes those; it
measures 28 findings, 0.123 per kLOC — and it now also excludes any class that
merely mentions `__hash__` in a docstring or a comment.

What the rule actually needs is a structural statement: *this class body has a
`function_definition` named `__eq__` and does not have one named `__hash__`, and
does not assign `__hash__`.* The first half is a pattern; the second is a
negation over the same node's children, which the query language does not have.

**Disposition.** **Needs primitive: P1, structural negation over a captured
node's subtree.**

## 18. `reliability.python.loop-variable-in-closure`

**Pitfall.** A function defined inside a loop that refers to the loop variable
captures the *variable*, not its value; by the time any of the functions runs,
every one of them sees the last iteration's value.

**Concept source.** ruff — `B023 function-uses-loop-variable` (MIT),
reimplementing flake8-bugbear. Concept only; no text taken.

**Severity.** `warning`.

**Query.** None exists.

```python
# would fire
def f(items):
    out = []
    for item in items:
        out.append(lambda: item)
    return out

# would not fire
def f(items):
    out = []
    for item in items:
        out.append(lambda item=item: item)
    return out
```

A pattern can find a `lambda` or a `function_definition` inside a
`for_statement`. It cannot answer the question the rule turns on: *does the body
of that inner function read a name that is bound by the enclosing loop, and is
that name not rebound as a default parameter or otherwise shadowed?* That is
resolving an identifier occurrence to its binding site through the scopes of one
file. The two examples above differ only in whether `item` inside the lambda
resolves to the loop's binding or to the lambda's own parameter — identical tree
shapes, opposite answers.

**Disposition.** **Needs primitive: P2, binding resolution within a file.**

## 19. `maintainability.python.unused-import`

**Pitfall.** An import nothing in the file uses: dead weight, a slower import
graph, and — when it was left behind by a deletion — a lie about what the module
depends on. This is the single most common thing a Python reviewer flags on
sight, which is why it is here despite the disposition.

**Concept source.** ruff — `F401 unused-import` (MIT), reimplementing Pyflakes.
Concept only; no text taken.

**Severity.** `info`.

**Query.** None exists.

```python
# would fire
import os


def f():
    return 1

# would not fire
import os


def f():
    return os.getcwd()
```

Finding the import is one pattern. Deciding it is unused requires enumerating
every identifier occurrence in the file, excluding the ones that are attribute
names, keyword-argument names, string contents or the import statement itself,
and confirming none of them binds to that import — plus honouring `__all__`, the
`# noqa` convention and the re-export idiom. A tree-sitter query yields matches,
not an absence over a whole file, and text predicates see only the captured
node's own bytes.

**Disposition.** **Needs primitive: P2, binding resolution within a file.**

## 20. `reliability.python.unreachable-except-clause`

**Pitfall.** `except Exception:` before `except ValueError:` makes the second
handler dead — the broad handler catches everything first, and the specific
recovery never runs.

**Concept source.** ruff — `B014 duplicate-handler-exception` (MIT) and pylint's
`bad-except-order` (GPL-2.0) describe adjacent shapes. Concept only; no text
taken. The GPL source informs a concept only, which is what #89's licensing
boundary permits.

**Severity.** `warning`.

**Query.** None, and none is possible under the boundary.

```python
# would fire
def f(g):
    try:
        return g()
    except Exception:
        return 1
    except ValueError:
        return 2
```

Ordering two `except_clause` siblings is trivially expressible. Deciding whether
the first handler's type is a *base class* of the second's is not: it needs the
exception class hierarchy, which for anything but the builtins lives in another
file, and for the builtins is knowledge the engine does not carry. A hard-coded
table of builtin exception ancestors would cover the textbook case
(`Exception` before `ValueError`) and answer nothing about the project's own
exception types, which is where the mistake is actually made.

Restricting the rule to a literal `except BaseException:`/`except Exception:`
followed by any other handler would be expressible, but it is a different, much
narrower rule than the pitfall, and the shipped `bare-except` already covers the
neighbouring shape.

**Disposition.** **Inexpressible** under single-file queries. Not recommended
for a primitive: the missing input is cross-file type information, which #103
puts out of scope.

---

## Primitives

Two primitives are named by the items above, plus one that does not yet clear
the #103 bar.

### P1 — structural negation over a captured node's subtree

*Shape.* A predicate that takes a capture and a sub-pattern and holds when the
sub-pattern has **no** match inside the captured node. Concretely: a `#not-has?`
form usable as `(#not-has? @body (function_definition name: (identifier) @n)
(#eq? @n "__hash__"))`, or an equivalent `!`-prefixed negative sub-pattern in
the query syntax itself.

*Why it cannot be faked.* Text predicates read only the captured node's bytes,
so every approximation is a substring search that a docstring, a comment or a
mention in prose defeats.

*Python candidates.* #17 `eq-without-hash`; #13 `open-without-encoding`
(no `keyword_argument` named `encoding`, replacing a fragile mode regex); #12
`yaml-load-without-loader` (no `keyword_argument` named `Loader`, replacing the
same); a class defining `__enter__` without `__exit__`. Four in Python alone —
the #103 bar of three candidates across two languages is met by Python plus the
obvious equivalents elsewhere (a Java class overriding `equals` without
`hashCode`, a C++ class with a destructor and no copy control).

### P2 — binding resolution within a file

*Shape.* For a file, a map from each identifier occurrence to the site that
binds it, and from each binding to its occurrences, respecting function, class,
comprehension and module scope. Single file, no imports resolved — an import
binds a name, and what that name refers to elsewhere stays unknown.

*Why it cannot be faked.* Queries produce matches, not absences over a file, and
the same tree shape has opposite answers depending on which binding a name
resolves to (#18's two examples are identical trees).

*Python candidates.* #18 `loop-variable-in-closure`; #19 `unused-import`;
#13 `open-without-encoding` (is this `open` the builtin?); #9
`missing-self-parameter` (is this class-body function used as a method or called
at class-definition time?); an unused local variable rule. Five in Python; the
same primitive is what an unused-import or unused-variable rule needs in every
other language on the list, so the bar is met comfortably.

*Cost warning.* This is the expensive one. It is a per-file symbol pass with a
per-language scope model, which is a real engine addition and, per #103, its own
measured package. P1 is a query-language feature; P2 is an analysis.

### P3 — parent-kind exclusion (below the bar on Python alone)

*Shape.* A constraint that the captured node's parent is not of a stated kind,
e.g. `(string) @report !parent: (concatenated_string)`.

*Python candidates.* #16 `f-string-without-placeholder` only. One candidate is
below the #103 threshold. The same shape recurs in JavaScript and TypeScript —
a template literal with no substitution, and the adjacent `no-useless-concat` —
so a second language exists, but a third Python candidate does not, and the
honest recommendation is to leave #16 unshipped rather than to build P3 for it.

---

## 2.1 removals revisited

#103 asks whether any rule 2.1 dropped comes back under a primitive. For Python
the answer is that **two of the three come back without one** — the failure mode
was the query, not the engine — and the third does not come back at all. All
three re-tests below were run through the same loader-and-scan path as the items
above.

### `reliability.python.unreachable-after-return` — returns, no primitive needed

Dropped at 2.8552 per kLOC on flask. The recorded cause: the query
`(block (return_statement) . (_) @report)` matches the next *named* node, and a
comment is a named node, so a trailing comment on the `return` line was reported
as unreachable code. A text predicate excludes comments:

```scheme
((block (return_statement) . (_) @report) (#not-match? @report "^#"))
```

```python
# fires
def f():
    return 1
    x = 2
    return x

# does not fire
def f():
    return 1  # trailing comment


def g():
    x = 2
    return x
```

stdlib: 0 findings. The residual cost is recall, not noise: a dead statement
separated from the `return` by a comment line is now missed, because the
anchored `(_)` binds to the comment and the predicate rejects it. Recommend
re-measuring this against the pinned set in the 2.2 package.

### `reliability.python.assert-on-tuple` — returns, no primitive needed

Dropped because all 37 findings on black were the *message* operand of
`assert cond, (lineno, line)`. The recorded cause: the grammar hangs both
operands off `assert_statement` as direct children, so `(assert_statement
(tuple))` cannot tell them apart. It can — with a leading anchor, which pins the
tuple to the first named child, which is the condition:

```scheme
(assert_statement . (tuple) @report)
```

```python
# fires
def f(x):
    assert (x, "must be set")

# does not fire
def f(x, lineno, line):
    assert x, (lineno, line)
```

stdlib: 0 findings. Recommend re-measuring against the pinned set in the 2.2
package.

### `reliability.python.swallowed-exception` — does not return

Dropped at 1.0257 per kLOC on black, over the `info` budget, with the note that
"the findings themselves are the shape the rule claims". That is a true-positive
rate, not a failure mode, so no primitive changes it: `except X: pass` is simply
common. Excluded.

### Matrix rejections that stay rejected

`reliability.python.type-equality` (exact-type dispatch is a real pattern),
`maintainability.python.empty-function-body` (indistinguishable from a Protocol
or ABC stub) and `maintainability.python.print-call` (fires on every CLI entry
point) were rejected on noise in the 2.1 matrix. None of P1, P2 or P3 changes
any of those judgements; all three are correct findings that are unwanted, not
wrong findings.

---

## What this means for the pinned noise set

#103 lists as unspecified "whether the pinned noise set exercises the new
pitfalls". For Python, it largely does not, and the reason is systematic.

`requests`, `flask` and `black` are modern, actively linted codebases — `black`
in particular is a formatter maintained by people who run ruff over it. Every
pitfall in this list that ruff implements is a pitfall those three repositories
have already had removed. A rule measured only against them will read 0, pass
its gate, and then meet its real false-positive idiom the first time a user
scans a decade-old service.

The survey behind this document is the evidence: the CPython 3.12 standard
library produced 133 findings for one candidate and 88 for another, and the
idioms behind those numbers — module-scope rebinding, implicitly concatenated
f-strings, `os.open` — are what determined four of the twenty dispositions
above. None of them would have surfaced against the pinned three.

Recommendation for the 2.2 measured package: add one legacy-heavy, permissively
licensed Python repository to the pinned set as a fourth entry, and choose it
for age and for the absence of a ruff configuration rather than for popularity.
Two of the shipped rules' limits in `noise/limits.tsv` were set against three
repositories that agree with each other; a fourth that disagrees is worth more
than a third that does not.

Note also that `yaml-load-without-loader` (#12) cannot be exercised by any of
the three, or by the stdlib, because none of them depends on PyYAML. A rule the
noise set structurally cannot measure should be recorded as such in the package
rather than shipped on a 0 that means "not tested".
