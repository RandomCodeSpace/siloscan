# Ruby pitfall list

Ticket #113, map #103. Drafted 2026-09-04.

Grammar: `tree-sitter-ruby` 0.23.1, the version pinned in `crates/siloscan-core/Cargo.toml`,
read through its own `src/node-types.json`. Engine boundary per #103: single-file tree-sitter
queries and single-file metric rules, nothing else.

**How every query below was verified.** Each one was put in a one-rule profile document and
loaded through `siloscan_core::rules::load_str`, then run over positive and negative `.rb`
snippets through `siloscan_core::scan::scan` — the same two calls `profile_corpus.rs` makes.
A throwaway integration test drove it (`crates/siloscan-core/tests/ruby_probe.rs`, deleted
after the run, not committed); it read case directories of `rule.yaml` plus `pos_*.rb` and
`neg_*.rb` and printed which rule fired on which line. "Verified" below means: the document
loaded, the rule fired on every positive at the expected line, and reported nothing on every
negative. Nothing here is a hand-read of a syntax tree.

**Noise judgements are judgements, not measurements.** The pinned Ruby noise set is sinatra
v3.2.0, puma v6.6.1 and rails v8.1.3.1 (`research/embedded-profiles/noise-set.md`); no rule
here has been run against it. Each item names the idiom that would produce noise so the
measurement package knows what it is looking at. The 2.1 round removed three Ruby rules on
exactly this kind of idiom — `if w = @workers.find { ... }` for `assignment-in-condition`,
`assert zone1 == zone1` over an overloaded `==` for `self-comparison`, a `rescue` clause after
a `return` for `unreachable-after-return` — and the RSpec `describe ... do` block counts as a
function for the metric engine, which is why the block-shaped judgements below are called out
separately.

**Sources.** Concept-only citations. RuboCop is MIT (source tree; its docs are CC BY-SA 4.0);
it is cited as a concept regardless. No pattern, message, or rule text is taken from it. Cop
names were checked against `rubocop/config/default.yml` and `docs.rubocop.org/rubocop/latest/`
at the time of writing.

**Excluded.** The five rules `reliability-ruby@1` already ships (`rescue-exception`,
`rescue-modifier`, `self-assignment`, `identical-if-branches`, `ensure-return`), the three
`maintainability-ruby@1` measures, and the three rules 2.1 removed. See "2.1 removals" at the
end for why none of the three returns.

---

## Summary

| # | id | severity | disposition | expected noise |
| --- | --- | --- | --- | --- |
| 1 | `reliability.ruby.nested-method-definition` | warning | expressible | none — blocks and conditionals are different nodes |
| 2 | `reliability.ruby.safe-navigation-chain` | warning | expressible | none — an all-`&.` chain is a different shape |
| 3 | `reliability.ruby.raise-exception` | warning | expressible | none |
| 4 | `reliability.ruby.inherit-exception` | warning | expressible | none |
| 5 | `reliability.ruby.duplicate-hash-key` | warning | expressible | none — call-site keyword arguments are not a `hash` |
| 6 | `reliability.ruby.duplicate-method` | warning | expressible | low — a helper `def` repeated inside one `describe` block |
| 7 | `reliability.ruby.duplicate-case-condition` | warning | expressible | none |
| 8 | `reliability.ruby.shadowed-rescue` | warning | expressible | low — a library error class that is not a `StandardError` |
| 9 | `reliability.ruby.debugger-call` | warning | expressible | none after narrowing to statement position |
| 10 | `reliability.ruby.unsafe-deserialization` | warning | expressible | **moderate** — framework code deserialising its own payloads |
| 11 | `reliability.ruby.literal-condition` | warning | expressible | none — `while true` is deliberately out of the query |
| 12 | `reliability.ruby.interpolation-in-single-quotes` | warning | expressible | low — generator templates that emit Ruby source |
| 13 | `reliability.ruby.implicit-string-concatenation` | warning | expressible | low after the single-line restriction |
| 14 | `reliability.ruby.deprecated-exists` | warning | expressible | none |
| 15 | `reliability.ruby.ineffective-access-modifier` | warning | expressible | none — anchored to the statement after `private` |
| 16 | `reliability.ruby.empty-ensure` | warning | expressible | none |
| 17 | `maintainability.ruby.redundant-string-coercion` | info | expressible | none after the trailing anchor drops `to_s(:db)` |
| 18 | `reliability.ruby.useless-assignment` | warning | needs primitive — method-local binding table | unmeasurable without it |
| 19 | `reliability.ruby.missing-respond-to-missing` | warning | needs primitive — absent-sibling assertion | unmeasurable without it |
| 20 | `reliability.ruby.shadowed-exception` (hierarchy-aware) | warning | inexpressible | — |

---

## 1. `reliability.ruby.nested-method-definition`

**Pitfall.** A `def` directly inside another `def` does not make a local helper: it defines the
inner method on the enclosing class the first time the outer method runs, so the method's
existence depends on call order.

**Concept source.** RuboCop — `Lint/NestedMethodDefinition` (MIT; concept only, no text taken).

**Severity** `warning` · **Disposition** expressible

```scheme
(method body: (body_statement (method) @report))
```

Positive (fires on line 3):

```ruby
class A
  def outer
    def inner
      1
    end
    inner
  end
end
```

Negatives (silent):

```ruby
class A
  def build
    self.class.define_method(:g) { 1 }
  end
end

class B
  def build
    Class.new do
      def g
        1
      end
    end
  end
end
```

**Expected noise.** None. The query requires the inner `method` to be a direct child of the
outer method's `body_statement`. A `def` inside a `do_block` belongs to the block's own
`body_statement` (verified silent above), which is the idiom that would otherwise dominate —
`Class.new do ... end` and `describe ... do ... end` both define methods this way and are
correct. A `def` inside an `if` sits in a `then` node and is also skipped, which costs recall
on version-guarded definitions and buys silence on them.

---

## 2. `reliability.ruby.safe-navigation-chain`

**Pitfall.** `x&.foo.bar` still raises `NoMethodError` when `x` is nil: the `&.` guards one
call and the `.` that follows it does not.

**Concept source.** RuboCop — `Lint/SafeNavigationChain` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
(call receiver: (call operator: "&.") operator: ".") @report
```

Positives (fire on line 2):

```ruby
def f(x)
  x&.foo.bar
end

def g(a)
  a&.b.c&.d
end
```

Negatives (silent):

```ruby
def f(x)
  x&.foo&.bar
end

def g(x)
  x.foo.bar
end
```

**Expected noise.** None. There is no idiom that writes `&.` and then `.` on the same chain
deliberately; the shape is the bug. rails uses `&.` heavily, and every use either continues
with `&.` or ends the chain — both verified silent.

---

## 3. `reliability.ruby.raise-exception`

**Pitfall.** `raise Exception` raises outside the `StandardError` hierarchy, so ordinary
`rescue` clauses do not catch it and the process dies where a caller expected to recover.

**Concept source.** RuboCop — `Lint/RaiseException` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
((call method: (identifier) @m arguments: (argument_list . (constant) @c)) @report
 (#eq? @m "raise")
 (#eq? @c "Exception"))
```

Positives (fire on line 2):

```ruby
def f
  raise Exception, 'boom'
end

def g
  raise(Exception, 'boom')
end
```

Negative (silent):

```ruby
def f
  raise ArgumentError, 'boom'
end
```

**Expected noise.** None. The anchor pins `Exception` as the first argument and `#eq?` pins it
exactly, so `MyGem::Exception` (a `scope_resolution`, not a `constant`) and every other class
are excluded. The rule misses `raise Exception.new('boom')`, whose first argument is a `call`
— a recall cost taken deliberately rather than widening the pattern to any first argument
whose text starts with `Exception`.

---

## 4. `reliability.ruby.inherit-exception`

**Pitfall.** `class MyError < Exception` puts a library's own error class outside
`StandardError`, so every caller's `rescue => e` misses it.

**Concept source.** RuboCop — `Lint/InheritException` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
((class superclass: (superclass (constant) @c)) @report (#eq? @c "Exception"))
```

Positive (fires on line 1) / negative (silent):

```ruby
class MyError < Exception
end

class MyOtherError < StandardError
end
```

**Expected noise.** None. Defining an error class off `Exception` is always a mistake in
application and library code; the only correct users of the shape are Ruby's own core classes,
which are not in the noise set.

---

## 5. `reliability.ruby.duplicate-hash-key`

**Pitfall.** A hash literal with the same symbol key twice silently keeps the last value; the
earlier entry is dropped without a warning at load time.

**Concept source.** RuboCop — `Lint/DuplicateHashKey` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
((hash (pair key: (hash_key_symbol) @a) (pair key: (hash_key_symbol) @b)) @report (#eq? @a @b))
```

Positive (fires on line 1):

```ruby
h = { a: 1, b: 2, a: 3 }
```

Negatives (silent):

```ruby
h = { a: 1, b: 2 }
h = { a: 1 }
h = {}
h = { a: { a: 1 } }
f(a: 1, b: 2, a: 3)
h = { 'a' => 1, 'a' => 2 }
```

**Expected noise.** None. Two `pair` children of one `hash` are matched in document order, so
a single-pair hash cannot match itself (verified), and the same key at two nesting levels is
two different `hash` nodes (verified). The last two negatives are recall costs, not noise:
call-site keyword arguments parse as `argument_list`, and `'a' => 1` keys are `string`, not
`hash_key_symbol`. Both could be added as extra patterns if the measurement shows the misses
matter.

---

## 6. `reliability.ruby.duplicate-method`

**Pitfall.** Two `def`s of the same name in one body: the second silently replaces the first,
usually because a rebase or a copy-paste left both.

**Concept source.** RuboCop — `Lint/DuplicateMethods` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
((body_statement (method name: (identifier) @a) (method name: (identifier) @b)) @report (#eq? @a @b))
```

Positives (fire on line 2) — note that `private` does not open a new body, so the second is a
real duplicate:

```ruby
class A
  def foo
    1
  end

  def foo
    2
  end
end

class B
  def foo
    1
  end

  private

  def foo
    2
  end
end
```

Negatives (silent):

```ruby
class A
  if RUBY_VERSION >= '3.0'
    def foo
      1
    end
  else
    def foo
      2
    end
  end
end

class B
  def foo
    1
  end

  class << self
    def foo
      2
    end
  end
end

RSpec.describe A do
  describe 'x' do
    def helper
      1
    end
  end

  describe 'y' do
    def helper
      2
    end
  end
end
```

**Expected noise.** Low. The idiom to watch is the RSpec `describe` block, because a
`do_block`'s body is also a `body_statement` — the same node the metric engine counts as a
function. Two `describe` blocks each defining `def helper` are two separate bodies and are
silent (verified), but two `def helper`s inside *one* `describe` block would fire, and that
finding is correct: the second one wins for every example in the block. The other two idioms
that could have produced noise are also silent: version-guarded alternative definitions live
in `then`/`else` nodes, and an instance method plus a same-named singleton inside
`class << self` are in different bodies.

---

## 7. `reliability.ruby.duplicate-case-condition`

**Pitfall.** A `case` with the same `when` value twice: the second branch is unreachable.

**Concept source.** RuboCop — `Lint/DuplicateCaseCondition` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
((case (when pattern: (pattern) @a) (when pattern: (pattern) @b)) @report (#eq? @a @b))
```

Positives (fire on line 2):

```ruby
def f(x)
  case x
  when 1 then a
  when 2 then b
  when 1 then c
  end
end

def g(x)
  case x
  when 1, 2 then a
  when 2 then b
  end
end
```

Negatives (silent):

```ruby
def f(x)
  case x
  when 1 then a
  when 2 then b
  end
end

def g(x)
  case x
  when 1 then a
  end
end
```

**Expected noise.** None. The two `pattern` captures come from two different `when` nodes, so
a single-branch `case` cannot match itself, and the comparison is over the pattern's own text.
A multi-value `when 1, 2` overlapping a later `when 2` is caught (verified), which is the
common form of the mistake.

---

## 8. `reliability.ruby.shadowed-rescue`

**Pitfall.** A `rescue StandardError` clause placed before a narrower one makes the narrower
clause unreachable — the first matching clause wins and almost every library error descends
from `StandardError`.

**Concept source.** RuboCop — `Lint/ShadowedException` (MIT; concept only). This is the
subset of that concept that a single-file query can decide; item 20 is the rest.

**Severity** `warning` · **Disposition** expressible (narrowed)

```scheme
((body_statement
   (rescue exceptions: (exceptions (constant) @first)) .
   (rescue exceptions: (exceptions (constant) @second)) @report)
 (#eq? @first "StandardError")
 (#not-any-of? @second "Exception" "SystemExit" "SignalException" "NoMemoryError"
                       "ScriptError" "LoadError" "NotImplementedError" "SyntaxError"
                       "SecurityError" "SystemStackError" "Interrupt"))
```

Positive (fires on line 5):

```ruby
def f
  g
rescue StandardError
  h
rescue ArgumentError
  i
end
```

Negatives (silent):

```ruby
def f
  g
rescue StandardError
  h
rescue Exception
  i
end

def g
  g
rescue ArgumentError
  i
rescue StandardError
  h
end

def h
  g
rescue ArgumentError
  i
end
```

**Expected noise.** Low. The `#not-any-of?` list is the set of core classes that do *not*
descend from `StandardError`, so a later `rescue Exception` — which is reachable, and is the
shape the shipped `rescue-exception` rule owns — stays silent (verified). The residual noise
idiom is a gem defining its own error class directly under `Exception` and rescuing it after
`StandardError`; that class name is not in the list and the finding would be wrong. It is
rare, because a gem that does it is committing the mistake item 4 reports.

---

## 9. `reliability.ruby.debugger-call`

**Pitfall.** A debugger breakpoint left in committed code: `binding.pry`, `binding.irb`,
`binding.break`, a bare `debugger`, a bare `byebug`. It halts a production process at the line
and waits for a terminal that is not there.

**Concept source.** RuboCop — `Lint/Debugger` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

The bare forms parse as a plain `identifier`, not a `call`, so each statement position needs
its own pattern. Restricting to statement position is what removes the false positives:

```scheme
((call receiver: (identifier) @recv method: (identifier) @m) @report
 (#eq? @recv "binding")
 (#any-of? @m "pry" "irb" "break"))
((body_statement (identifier) @report) (#any-of? @report "debugger" "byebug"))
((block_body (identifier) @report) (#any-of? @report "debugger" "byebug"))
((then (identifier) @report) (#any-of? @report "debugger" "byebug"))
((program (identifier) @report) (#any-of? @report "debugger" "byebug"))
```

Positives (all fire):

```ruby
def f
  binding.pry
end

def g
  debugger
  h
end

items.each do |i|
  byebug
  h(i)
end

def k(x)
  if x
    debugger
  end
end

debugger
```

Negatives (silent):

```ruby
def f(debugger)
  debugger.step
end

debugger = Debugger.new
debugger.start

def g
  logger.debug('x')
end

def h
  binding.local_variable_get(:x)
end
```

**Expected noise.** None after the narrowing. The idiom that produced noise in the first draft
was a parameter or local variable literally named `debugger`: the unrestricted
`((identifier) @report (#any-of? @report "debugger"))` fired on the parameter list and on the
left of `debugger = Debugger.new` (both verified as false positives before the fix, both
silent after). What remains would need a DSL exposing a no-argument `debugger` method with
real behaviour, which none of the three pinned repositories has. Any finding on released code
is a genuine one — this is a rule that should measure at zero.

---

## 10. `reliability.ruby.unsafe-deserialization`

**Pitfall.** `YAML.load` and `Marshal.load` instantiate arbitrary objects from their input; on
anything reachable from a user they are remote code execution.

**Concept source.** RuboCop — `Security/YAMLLoad` and `Security/MarshalLoad` (MIT; concept
only).

**Severity** `warning` · **Disposition** expressible

```scheme
((call receiver: (constant) @recv method: (identifier) @m) @report
 (#any-of? @recv "YAML" "Marshal")
 (#eq? @m "load"))
```

Positives (fire on line 2):

```ruby
def f(s)
  YAML.load(s)
end

def g(s)
  Marshal.load(s)
end
```

Negatives (silent):

```ruby
def f(s)
  YAML.safe_load(s)
end

def g(s)
  JSON.parse(s)
end
```

**Expected noise.** Moderate, and this is the item to measure first. The idiom is a framework
round-tripping its own payloads: rails serialises and deserialises attribute values and cache
entries through YAML and Marshal on purpose, and every one of those call sites is a finding
this rule cannot tell apart from a request-fed one — the single-file boundary means the
provenance of `s` is unknowable. `Psych 4` also made bare `YAML.load` safe by default, which
weakens the concept on modern Rubies without changing the syntax. If rails breaches 0.25 per
kLOC the honest response under the #103 policy is removal, not a threshold change; the one
permitted `paths` exclusion would have to cover the framework's own serialisation directories
and is unlikely to be worth spending.

---

## 11. `reliability.ruby.literal-condition`

**Pitfall.** `if true` / `unless false` around a block of code: the branch was disabled during
debugging and the disabling was committed.

**Concept source.** RuboCop — `Lint/LiteralAsCondition` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
(if condition: [(true) (false) (integer) (float) (string) (simple_symbol)] @report)
(unless condition: [(true) (false) (integer) (float) (string) (simple_symbol)] @report)
```

Positives (fire on line 2):

```ruby
def f
  if true
    1
  end
end

def g
  unless false
    1
  end
end
```

Negatives (silent):

```ruby
def f(x)
  if x
    1
  end
end

def g
  while true
    break
  end
end

def h
  if RUBY_VERSION >= '3.0'
    1
  end
end

def k
  g if true
end
```

**Expected noise.** None. `while true` is the idiom that would have produced it — a
`loop`-shaped infinite loop written with `while`, correct and common in puma's reactor code —
and the query covers only `if` and `unless`, so it is silent by construction (verified). The
modifier forms (`g if true`) are separate `if_modifier` nodes and are also out of scope; they
are the one place a literal condition is sometimes written on purpose, behind a feature-flag
constant. A constant condition such as `RUBY_VERSION >= '3.0'` is a `binary`, not a literal.

---

## 12. `reliability.ruby.interpolation-in-single-quotes`

**Pitfall.** `'value: #{x}'` does not interpolate — single quotes make it the literal seven
characters — and the mistake usually surfaces as a log line or an error message containing
`#{x}`.

**Concept source.** RuboCop — `Lint/InterpolationCheck` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

Written as it appears in a profile document, where the YAML block scalar passes `\\{` through
to the query's string literal, which unescapes it to the regex `#\{`:

```yaml
    ast:
      ruby: |
        ((string) @report (#match? @report "^'[^']*#\\{"))
```

Positive (fires on line 2):

```ruby
def f(x)
  'value: #{x}'
end
```

Negatives (silent):

```ruby
def f(x)
  "value: #{x}"
end

def g
  'plain text'
end

TEMPLATE = %q(value: #{x})
```

**Expected noise.** Low. The idiom is a code generator or template that emits Ruby source for
later evaluation and therefore wants the literal `#{}` — rails' generators and any
`class_eval` string builder do this. Most of them write the template in a heredoc or `%q(...)`
(both verified silent) rather than single quotes, which is what keeps the count low; the
residual is a generator that uses single quotes. If rails breaches, the generator template
directory is the natural single `paths` exclusion.

---

## 13. `reliability.ruby.implicit-string-concatenation`

**Pitfall.** Two adjacent string literals inside an array — `['alpha' 'beta', 'gamma']` — are
concatenated into one element. It is a missing comma, and the array is silently one element
short.

**Concept source.** RuboCop — `Lint/ImplicitStringConcatenation` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```yaml
    ast:
      ruby: |
        ((array (chained_string) @report) (#not-match? @report "\\n"))
```

Positive (fires on line 1):

```ruby
NAMES = ['alpha' 'beta', 'gamma']
```

Negatives (silent):

```ruby
NAMES = ['alpha', 'beta', 'gamma']

MSGS = [
  'first part ' \
  'second part',
  'other'
]
```

**Expected noise.** Low, and only because of the single-line restriction. The idiom is the
deliberate multi-line continuation of one long message inside an array of messages — a
backslash at the end of the line and the string continued on the next. Without the
`#not-match?` on a newline that form fires (verified as a false positive before the fix, silent
after), and message tables in rails and sinatra are exactly where it lives. Restricting to a
`chained_string` that occupies one line keeps the missing-comma case and drops the
continuation case.

---

## 14. `reliability.ruby.deprecated-exists`

**Pitfall.** `File.exists?` and `Dir.exists?` are deprecated aliases that emit a warning on
modern Rubies; the current spellings are `exist?`.

**Concept source.** RuboCop — `Lint/DeprecatedClassMethods` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
((call receiver: (constant) @recv method: (identifier) @m) @report
 (#any-of? @recv "File" "Dir")
 (#eq? @m "exists?"))
```

Positives (fire on line 2):

```ruby
def f(p)
  File.exists?(p)
end

def g(p)
  Dir.exists?(p)
end
```

Negatives (silent):

```ruby
def f(p)
  File.exist?(p)
end

def g(h, k)
  h.exists?(k)
end
```

**Expected noise.** None. The receiver is pinned to the two core constants, so an application
object with its own `exists?` predicate — the only plausible source of noise — is excluded
(verified). Expect a count near zero on maintained repositories, which makes this a low-value
but free rule.

---

## 15. `reliability.ruby.ineffective-access-modifier`

**Pitfall.** `private` does not apply to `def self.foo`. A singleton method written under a
`private` line is public, and the author believes otherwise.

**Concept source.** RuboCop — `Lint/IneffectiveAccessModifier` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

```scheme
((body_statement (identifier) @mod . (singleton_method) @report) (#eq? @mod "private"))
```

Positive (fires on line 4):

```ruby
class A
  private

  def self.helper
    1
  end
end
```

Negatives (silent):

```ruby
class B
  private

  def helper
    1
  end
end

class C
  def self.helper
    1
  end
end

class D
  private_class_method

  def self.helper
    1
  end
end

class E
  protected

  def self.helper
    1
  end
end

class F
  private

  def instance_helper
    1
  end

  def self.helper
    2
  end
end
```

**Expected noise.** None. The anchor means only the statement immediately after a bare
`private` is examined, so the correct forms — `private_class_method`, `private def self.x`
(a call with an argument, not a bare identifier), and a `private` section whose first entry is
an instance method — are all silent (verified). The last negative shows the recall cost: a
singleton method further down a private section is missed. That is the conservative half of
the trade and it is the right half here.

---

## 16. `reliability.ruby.empty-ensure`

**Pitfall.** An `ensure` clause with nothing in it. It is either a leftover from deleted
cleanup code or a misunderstanding that `ensure` alone swallows something.

**Concept source.** RuboCop — `Lint/EmptyEnsure` (MIT; concept only).

**Severity** `warning` · **Disposition** expressible

The grammar has no way to assert an absent body, so the constraint goes on the node's own
text. An `ensure` with no statements spans only the keyword, and a comment inside it is an
extra that does not extend the span — so a comment-only `ensure` is reported too, correctly:

```yaml
    ast:
      ruby: |
        ((ensure) @report (#match? @report "^ensure\\s*$"))
```

Positives (fire on line 3):

```ruby
def f
  g
ensure
end

def h
  g
ensure
  # nothing to clean up
end
```

Negatives (silent):

```ruby
def f
  g
ensure
  h
end

def k
  g
ensure
  # note
  h
end
```

**Expected noise.** None. There is no idiom that writes an empty `ensure` on purpose; the
`begin/ensure` pair with a body is a different node text and is silent (verified). The text
predicate is doing real work here rather than papering over a grammar gap — the `ensure` node
carries no `body` field at all, so there is nothing else to constrain.

---

## 17. `maintainability.ruby.redundant-string-coercion`

**Pitfall.** `"value: #{x.to_s}"` — interpolation already calls `to_s`, so the explicit call
is noise the reader has to check.

**Concept source.** RuboCop — `Lint/RedundantStringCoercion` (MIT; concept only).

**Severity** `info` · **Disposition** expressible

The trailing anchor after the `method:` field requires the `identifier` to be the call's last
named child, which is how a call with no argument list is distinguished from one with
arguments:

```scheme
(interpolation (call method: (identifier) @m .) @report (#eq? @m "to_s"))
```

Positive (fires on line 2):

```ruby
def f(x)
  "value: #{x.to_s}"
end
```

Negatives (silent):

```ruby
def f(x)
  "value: #{x.to_s(2)}"
end

def g(x)
  "value: #{x.to_s(:db)}"
end

def h(x)
  "value: #{x}"
end
```

**Expected noise.** None after the anchor. The idiom that produced it is `to_s` with an
argument, where the call is not redundant at all: `to_s(2)` for a base and, all over rails,
`to_s(:db)` and `to_s(:short)` for a format. Without the anchor both fire (verified as a false
positive before the fix, silent after), and rails alone would have carried the rule over the
`info` gate.

---

## 18. `reliability.ruby.useless-assignment`

**Pitfall.** A local variable assigned and never read afterwards — usually a rename that only
half landed, or a result the author meant to return.

**Concept source.** RuboCop — `Lint/UselessAssignment` (MIT; concept only).

**Severity** `warning` · **Disposition** **needs primitive**

**No query exists.** The decision is "is there a read of this name, after this write, before
the end of the binding's scope" — three facts a tree-sitter pattern cannot carry. A pattern
matches one subtree at a time and its predicates compare captured text; there is no way to
quantify over the remaining siblings of an enclosing body, and no way to express "no node
anywhere below this one reads `@name`". Text predicates do not help: `#not-eq?` compares two
captures, not a capture against the absence of a match. Attempting it with sibling anchors
would only cover a write immediately followed by an unrelated statement, which is neither the
common shape nor a safe one — Ruby's block scoping means a write inside a `do_block` can be
read after the block, and a write before a `binding`-using call may be read reflectively.

**Primitive needed.** A **method-local binding table**: for each `method`, `singleton_method`,
`do_block`, `block` and `lambda`, the set of local names written and read inside it and its
nested blocks, with byte offsets, exposed to a query as a predicate over a capture — a shape
such as `(#unread-after? @name)`. It stays inside one file and one function, so it does not
cross the #103 boundary into cross-file or dataflow analysis.

---

## 19. `reliability.ruby.missing-respond-to-missing`

**Pitfall.** A class that defines `method_missing` without `respond_to_missing?` lies to
`respond_to?`, to `Object#method`, and to every duck-typing check a caller makes.

**Concept source.** RuboCop — `Style/MissingRespondToMissing` (MIT; concept only).

**Severity** `warning` · **Disposition** **needs primitive**

**No query exists.** The finding is about a sibling that is *not* there. A tree-sitter pattern
can require a `method` named `method_missing` inside a class body, and can require a second
`method` alongside it, but it cannot require the absence of one: every operator in the query
language is positive, and the loader's predicate set (`eq?`, `not-eq?`, `any-eq?`,
`any-not-eq?`, `match?`, `not-match?`, `any-match?`, `any-not-match?`, `any-of?`,
`not-any-of?`) compares text of captures that matched. Inverting the pattern — report every
`respond_to_missing?` and subtract — is not something a single query can do either, because a
rule reports what it matches.

**Primitive needed.** An **absent-sibling assertion**: a predicate on a captured node
asserting that no sibling of its parent matches a named pattern, spelled as a second pattern
in the same rule and referenced by name — something like
`(#no-sibling-matching? @report "respond-to-missing")`. Ruby needs it once. Whether it clears
the #103 bar of three candidates across two languages depends on the Java and C# lists
(`equals` without `hashCode`, `IDisposable` without `Dispose` are the same shape); those
tickets have to count it, not this one.

---

## 20. `reliability.ruby.shadowed-exception` (hierarchy-aware)

**Pitfall.** Any `rescue` clause whose class is an ancestor of a later clause's class makes the
later clause unreachable. Item 8 covers the case where the ancestor is spelled `StandardError`;
this is the rest — `rescue IOError` before `rescue EOFError`, `rescue MyGem::Error` before
`rescue MyGem::Timeout`.

**Concept source.** RuboCop — `Lint/ShadowedException` (MIT; concept only).

**Severity** `warning` · **Disposition** **inexpressible**

**No query exists, and no single-file primitive fixes it.** Deciding whether `EOFError`
descends from `IOError` requires the class hierarchy, which lives in Ruby's core, in gems, and
in other files of the same project. Item 8 works only because the ancestor relation for
`StandardError` is a fixed fact that can be written into the query as a literal exclusion
list; there is no such list for user-defined and gem-defined classes, and building one is
cross-file analysis, which #103 puts out of scope. A name-shape heuristic — treat
`Foo::Error` as an ancestor of `Foo::Timeout` — would be guessing, and guessing is what the
noise gate exists to punish.

---

## Primitives named

| Primitive | Shape | Items here that need it |
| --- | --- | --- |
| Method-local binding table | Per-function map of local writes and reads with offsets, queryable as a predicate over a capture (`#unread-after?`) | 18 `useless-assignment`; also Ruby's `Lint/ShadowingOuterLocalVariable` (a block parameter reusing an outer local's name), which is the same table read differently |
| Absent-sibling assertion | Predicate asserting no sibling of the capture's parent matches a second named pattern in the same rule | 19 `missing-respond-to-missing` |

Two candidates in Ruby need the binding table and one needs the absent-sibling assertion.
Neither clears #103's "three candidates across two languages" bar on Ruby alone. The binding
table is the stronger of the two: Python's unused-local and JavaScript's unused-variable are
the same computation, so if those lists ask for it, it clears the bar with room. The
absent-sibling assertion should be decided by Java and C#, where "defines X without Y" is a
recurring shape; Ruby is one voice for it, not a case.

Three things that looked like they needed a primitive and did not:

- **Absent-field constraint** (a call with no `arguments`). The trailing anchor `.` after the
  last field does it — item 17.
- **Empty-body constraint** (an `ensure` with no statements). A `#match?` on the node's own
  text does it, because an empty clause's span is the keyword alone — item 16.
- **Same-line constraint** (a `chained_string` that does not span lines). A `#not-match?` on
  `\n` over the node text does it — item 13.

## 2.1 removals

None of the three rules removed in 2.1 returns. No named primitive fixes any of them:

- **`assignment-in-condition`** — 1.4678 per kLOC on puma. Every finding was
  `if w = @workers.find { ... }`, which is not a mistake in Ruby but the ordinary way to bind
  and test in one step. The failure mode is that the syntax the rule detects is the syntax the
  idiom uses; there is nothing for a primitive to separate. RuboCop's own cop is satisfied by
  wrapping the assignment in parentheses, a convention siloscan cannot assume of a repository
  it has never seen.
- **`self-comparison`** — both rails findings were reflexivity assertions over an overloaded
  `==` (`assert zone1 == zone1`), where the comparison is a real test of real behaviour. A
  primitive would have to know that `==` is overloaded for the operand's type, which is
  type-aware cross-file analysis and out of scope. A `paths` exclusion for test directories
  would suppress the findings, but that is the existing config axis rather than a primitive,
  and it would also suppress the true positives that live in tests.
- **`unreachable-after-return`** — the one rails finding was a `rescue` clause after a
  `return`, reached exactly when the body raises. That specific shape is excludable by
  requiring the following sibling not to be a `rescue` or `ensure`, which needs no primitive
  — but the rule was removed across every language in 2.1, so re-adding it for Ruby alone is a
  cross-language decision for #103, not a Ruby pitfall finding.

## Verified but not carried

These queries were written and verified through the same loader and scanner and are left out
of the twenty, with the reason. They are recorded so a later round does not re-derive them:

| Query | Why not carried |
| --- | --- |
| `((call method: (identifier) @m) @report (#eq? @m "eval"))` — `Security/Eval` | Fires on any bare `eval`; metaprogramming-heavy gems call it deliberately and the single-file boundary cannot tell a constant argument from a request-fed one. Same failure mode as item 10, with a worse ratio. |
| `((rescue) @report (#match? @report "^rescue[^\n]*$"))` — `Lint/SuppressedException` | Empty `rescue` bodies. 2.1 removed the analogous `empty-catch` in Java, C++, JavaScript and TypeScript on noise; the deliberate `rescue; end` in cleanup paths is the same idiom in Ruby. |
| `(body_statement [(integer) (float) (string) (simple_symbol) (true) (false) (nil)] @report . (_))` — `Lint/Void` | Works, near-zero noise, but the shape is vanishingly rare in real Ruby: bare literals in void context are what a linter catches in a tutorial, not in sinatra. Low value per rule slot. A version including `(identifier)` must not be used — a bare identifier is how Ruby calls a no-argument method. |
| `(binary left: (float) operator: ["==" "!="]) @report` — `Lint/FloatComparison` | Moderate noise from `x == 0.0` sentinel checks, which are common and usually correct. |
| `(class_variable) @report` — `Style/ClassVars` | Every `@@var`. Legacy Ruby uses them freely; this is a style position, not a pitfall, and it would run far over the `info` gate on any old tree. |
| `((string_array) @report (#match? @report "[,']"))` — `Lint/PercentStringArray` | Near-zero noise and a real bug (`%w('a', 'b')` yields the quotes and commas as characters), but too narrow to spend a slot on. |
| `(interpolation [(string) (integer) (float) (simple_symbol) (true) (false) (nil)] @report)` — `Lint/LiteralInInterpolation` | Style, not reliability, and overlaps item 17's slot in the maintainability document. |
| `((call method: (identifier) @m arguments: (argument_list . [(integer) (float) (simple_symbol) (true) (false) (nil)] .)) @report (#eq? @m "each_with_object"))` — `Lint/EachWithObjectArgument` | Correct and silent on the array and hash forms, but the mistake is rare enough that the rule would measure at zero on all three repositories. |

## Query mechanics confirmed against this grammar

Recorded because they cost time to establish and the other language tickets will hit them:

- A predicate binds to the pattern inside the parenthesis pair that encloses both, which is
  why every constrained pattern above is wrapped in an extra pair.
- `do_block` and `block` bodies are `block_body`, but a `do_block`'s body is a
  `body_statement` — so a rule written against `body_statement` sees `describe ... do` bodies
  as well as method bodies. Item 6 depends on knowing this.
- `rescue` carries its statements in a `then` node under a `body` field, so consecutive
  `rescue` clauses remain siblings of the enclosing `body_statement` and sibling anchors work
  between them (item 8).
- An `ensure` with no statements, or with only comments, spans the keyword alone; comments are
  extras and do not widen the span (item 16).
- A trailing anchor after a field constrains that child to be the node's last named child,
  which is the substitute for an absent-field assertion (item 17).
- Bare `debugger` is an `identifier`, not a `call`; Ruby's grammar gives a no-argument,
  no-receiver method call no call node at all (item 9).
