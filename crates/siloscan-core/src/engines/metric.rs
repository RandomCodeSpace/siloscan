//! Threshold rules over per-function measurements.
//!
//! A tree-sitter query matches shapes; it cannot count, and it cannot compare a
//! count to a threshold. The four measures a maintainability profile wants —
//! function length, parameter count, nesting depth, cyclomatic complexity — are
//! all "one number per function node, compared to a `max`", so they get an
//! engine of their own instead of a query plus a counter.
//!
//! # What is measured, and where it is reported
//!
//! The unit is a *function-like node*: whatever the language's [`FUNCTION`
//! column](Kinds::functions) lists, which includes closures, lambdas, arrow
//! functions and — in Ruby, where a block is where the code is — `do`/`{}`
//! blocks. **A nested function is its own unit and is never attributed to its
//! parent**: its branches do not inflate the enclosing function's complexity
//! and its nesting is measured from its own body. That is what keeps one edit
//! from moving two findings.
//!
//! A finding is reported on the function's **name node**, not its body, because
//! [`crate::findings::fingerprint`] is `(rule_id, path, matched, occurrence)`:
//! reporting the body would move the fingerprint on any edit inside the
//! function, and every baseline entry and `--fail-on` gate would churn on
//! unrelated changes. Anonymous functions have no name and fall back to the
//! function node's first token, with the occurrence index separating two of
//! them in one file — the same mechanism the ast engine already uses.
//!
//! The measured value cannot go in `matched` for the same reason, so it goes in
//! the message: a rule's `message` is emitted with `": <value> > <max>"`
//! appended.
//!
//! # The measures
//!
//! | Measure | Definition |
//! | --- | --- |
//! | `function-length` | `end_row - start_row + 1` of the function node, nested functions included: they are lines of this function's text. |
//! | `parameter-count` | Parameters in the function's parameter list, which is every named child that is not on the language's [`not_parameters`](Kinds::not_parameters) list. Go groups parameters sharing a type into one node with a `name` field each, so an entry counts once per name. |
//! | `nesting-depth` | Deepest run of [`NESTING`](Kinds::nesting) nodes inside the function's own subtree; the body itself is depth 0. |
//! | `cyclomatic-complexity` | `1 + ` the [`BRANCH`](Kinds::branches) nodes in the function's own subtree, where a [binary node](Kinds::binary) counts only when its `operator` field is one of the language's short-circuit operators. |
//!
//! # The tables
//!
//! Every kind below was read out of the pinned grammars' `node-types.json`. A
//! grammar bump that renames or drops one is a silent loss of a branch or a
//! whole function kind, so `every_named_kind_still_exists` asserts each is
//! still a named node of its grammar.
//!
//! Decisions that are not observations:
//!
//! - `else` is not a branch. An `else` adds no independent path.
//! - Python's `if_clause` is the comprehension guard (`[x for x in y if p(x)]`),
//!   which is a real branch; `elif_clause` is a node of its own and must be
//!   counted, or an `elif` chain reads as complexity 2.
//! - Rust counts every `match_arm`, wildcard included, which is the convention
//!   `switch_case` and `when` already set.
//! - NESTING is BRANCH minus the expression forms (`conditional_expression`,
//!   `ternary_expression`, the `*_modifier` forms, the short-circuit operators)
//!   and minus the `case`/`when`/`arm` *labels*, plus each language's block
//!   constructs. Counting the switch *statement* rather than each of its labels
//!   is what keeps a thirty-case dispatch from reading as depth thirty.
//! - Typescript's `function_signature`, `method_signature` and
//!   `abstract_method_signature` are absent on purpose: they have no body, so
//!   there is nothing to measure.
//! - An `elif` / `elsif` / `else if` chain is one nesting level deeper than the
//!   `if` it continues, uniformly: the clause is a node inside its `if`, and it
//!   is in NESTING for the languages that spell it as one. A ten-branch chain
//!   is depth 2, not depth 10.
//! - **The implicit receiver is not a parameter.** Rust's `self_parameter`, a
//!   Go method's `receiver` — a separate field from `parameters` — and Java's
//!   `receiver_parameter` are all excluded. Python's `self` *is* counted,
//!   because in Python it is syntactically an ordinary first parameter and
//!   nothing in the grammar distinguishes it; a Python threshold therefore has
//!   to be read as one higher for methods than for functions.
//! - Java counts `switch_label` and not `switch_rule`: an arrow switch's rule
//!   holds a label as its first child, so counting both would count every arm
//!   of an arrow switch twice and leave the two switch styles disagreeing about
//!   the same code.
//! - A function-like node that is another function-like node's `body` is not a
//!   unit of its own. That is Ruby's `->() { }`, whose body is itself a
//!   `block`; see [`measure_tree`].

use std::num::NonZeroU16;

use tree_sitter::{Language, Node, Tree};

use super::{LineIndex, Occurrences, applies};
use crate::findings::{Finding, fingerprint};
use crate::rules::{CompiledPayload, CompiledRule, Measure};

/// One language's node kinds. Static data only: no grammar is loaded to read
/// it, so the tables exist whatever grammar features this build enables.
pub struct Kinds {
    /// The units measured.
    pub functions: &'static [&'static str],
    /// Each occurrence adds one to cyclomatic complexity.
    pub branches: &'static [&'static str],
    /// The language's binary-operator node, whose `operator` field decides
    /// whether it is a branch.
    pub binary: &'static str,
    /// Operators on `binary` that short-circuit, and so branch.
    pub short_circuit: &'static [&'static str],
    /// Nodes that increase nesting depth.
    pub nesting: &'static [&'static str],
    /// Parameter-list nodes. Anything else found where one was expected is a
    /// single bare parameter and counts as one.
    pub parameter_lists: &'static [&'static str],
    /// Named children of a parameter list that are *not* parameters. Every
    /// other named child is one.
    ///
    /// An exclusion list and not an inclusion list, because two of the
    /// grammars hide their parameters behind a supertype: Rust's
    /// `closure_parameters` holds `_pattern`, which is every pattern kind the
    /// language has, and Python's `parameters` holds `_parameter`. Listing what
    /// is not a parameter is short, and it fails in the safe direction — a
    /// grammar that gains a parameter kind keeps counting rather than silently
    /// dropping it.
    pub not_parameters: &'static [&'static str],
}

/// Languages with a node-kind table, sorted. Every language the crate can parse
/// has one; the list is the engine's coverage, not the build's.
pub const LANGUAGES: [&str; 10] = [
    "c",
    "cpp",
    "csharp",
    "go",
    "java",
    "javascript",
    "python",
    "ruby",
    "rust",
    "typescript",
];

const C: Kinds = Kinds {
    functions: &["function_definition"],
    branches: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "case_statement",
        "conditional_expression",
    ],
    binary: "binary_expression",
    short_circuit: &["&&", "||"],
    nesting: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "switch_statement",
    ],
    parameter_lists: &["parameter_list"],
    not_parameters: &["comment", "compound_statement"],
};

const CPP: Kinds = Kinds {
    functions: &["function_definition", "lambda_expression"],
    branches: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "for_range_loop",
        "case_statement",
        "catch_clause",
        "conditional_expression",
    ],
    binary: "binary_expression",
    // C++ spells the short-circuit operators twice.
    short_circuit: &["&&", "||", "and", "or"],
    nesting: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "for_range_loop",
        "catch_clause",
        "try_statement",
        "switch_statement",
    ],
    parameter_lists: &["parameter_list"],
    not_parameters: &["comment"],
};

const CSHARP: Kinds = Kinds {
    functions: &[
        "method_declaration",
        "constructor_declaration",
        "destructor_declaration",
        "operator_declaration",
        "local_function_statement",
        "accessor_declaration",
        "lambda_expression",
        "anonymous_method_expression",
    ],
    branches: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "foreach_statement",
        "switch_section",
        "switch_expression_arm",
        "catch_clause",
        "when_clause",
        "conditional_expression",
        "conditional_access_expression",
    ],
    binary: "binary_expression",
    short_circuit: &["&&", "||", "??"],
    nesting: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "foreach_statement",
        "catch_clause",
        "try_statement",
        "switch_statement",
    ],
    parameter_lists: &["parameter_list"],
    not_parameters: &["comment", "attribute_list"],
};

const GO: Kinds = Kinds {
    functions: &["function_declaration", "method_declaration", "func_literal"],
    // Go's four case kinds cover `switch`, type switches and `select`; `for`
    // has no separate range form.
    branches: &[
        "if_statement",
        "for_statement",
        "expression_case",
        "type_case",
        "communication_case",
        "default_case",
    ],
    binary: "binary_expression",
    short_circuit: &["&&", "||"],
    nesting: &[
        "if_statement",
        "for_statement",
        "expression_switch_statement",
        "type_switch_statement",
        "select_statement",
    ],
    // A method's `receiver` is a separate field and is not a parameter.
    parameter_lists: &["parameter_list"],
    not_parameters: &["comment"],
};

const JAVA: Kinds = Kinds {
    functions: &[
        "method_declaration",
        "constructor_declaration",
        "compact_constructor_declaration",
        "lambda_expression",
    ],
    // `switch_label` is the arm, in both switch styles: an arrow `switch_rule`
    // holds one as its first child, so counting the rule as well would count
    // every arrow arm twice.
    branches: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "enhanced_for_statement",
        "switch_label",
        "catch_clause",
        "ternary_expression",
    ],
    binary: "binary_expression",
    short_circuit: &["&&", "||"],
    // Java's switch is an expression node even when written as a statement.
    nesting: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "enhanced_for_statement",
        "catch_clause",
        "try_statement",
        "switch_expression",
    ],
    // A lambda writes its parameters three ways: `formal_parameters`,
    // `inferred_parameters`, or one bare `identifier` that lands on the
    // single-parameter path below.
    parameter_lists: &["formal_parameters", "inferred_parameters"],
    not_parameters: &["line_comment", "block_comment", "receiver_parameter"],
};

const JAVASCRIPT: Kinds = Kinds {
    functions: &[
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "arrow_function",
        "method_definition",
    ],
    // `switch_default` is a node of its own, and counts like every other
    // language's wildcard arm.
    branches: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "for_in_statement",
        "switch_case",
        "switch_default",
        "catch_clause",
        "ternary_expression",
    ],
    binary: "binary_expression",
    short_circuit: &["&&", "||", "??"],
    nesting: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "for_in_statement",
        "catch_clause",
        "try_statement",
        "switch_statement",
    ],
    parameter_lists: &["formal_parameters"],
    not_parameters: &["comment"],
};

const PYTHON: Kinds = Kinds {
    functions: &["function_definition", "lambda"],
    branches: &[
        "if_statement",
        "elif_clause",
        "while_statement",
        "for_statement",
        "except_clause",
        "case_clause",
        "conditional_expression",
        "if_clause",
    ],
    binary: "boolean_operator",
    short_circuit: &["and", "or"],
    nesting: &[
        "if_statement",
        "elif_clause",
        "while_statement",
        "for_statement",
        "except_clause",
        "try_statement",
        "with_statement",
        "match_statement",
    ],
    parameter_lists: &["parameters", "lambda_parameters"],
    not_parameters: &["comment", "positional_separator", "keyword_separator"],
};

const RUBY: Kinds = Kinds {
    functions: &["method", "singleton_method", "lambda", "do_block", "block"],
    branches: &[
        "if",
        "elsif",
        "unless",
        "while",
        "until",
        "for",
        "when",
        "in_clause",
        "rescue",
        "conditional",
        "if_modifier",
        "unless_modifier",
        "while_modifier",
        "until_modifier",
    ],
    binary: "binary",
    short_circuit: &["&&", "||", "and", "or"],
    nesting: &[
        "if",
        "elsif",
        "unless",
        "while",
        "until",
        "for",
        "rescue",
        "case",
        "case_match",
    ],
    parameter_lists: &["method_parameters", "block_parameters", "lambda_parameters"],
    not_parameters: &["comment"],
};

const RUST: Kinds = Kinds {
    functions: &["function_item", "closure_expression"],
    branches: &[
        "if_expression",
        "while_expression",
        "loop_expression",
        "for_expression",
        "match_arm",
    ],
    binary: "binary_expression",
    short_circuit: &["&&", "||"],
    nesting: &[
        "if_expression",
        "while_expression",
        "loop_expression",
        "for_expression",
        "match_expression",
    ],
    parameter_lists: &["parameters", "closure_parameters"],
    // A typed closure parameter is a `parameter`; an untyped one is a bare
    // pattern, so both have to count.
    not_parameters: &[
        "line_comment",
        "block_comment",
        "self_parameter",
        "attribute_item",
    ],
};

const TYPESCRIPT: Kinds = Kinds {
    functions: JAVASCRIPT.functions,
    branches: JAVASCRIPT.branches,
    binary: JAVASCRIPT.binary,
    short_circuit: JAVASCRIPT.short_circuit,
    nesting: JAVASCRIPT.nesting,
    parameter_lists: JAVASCRIPT.parameter_lists,
    not_parameters: JAVASCRIPT.not_parameters,
};

/// The node-kind table for one language, or `None` when the engine has none.
pub fn kinds(language: &str) -> Option<&'static Kinds> {
    match language {
        "c" => Some(&C),
        "cpp" => Some(&CPP),
        "csharp" => Some(&CSHARP),
        "go" => Some(&GO),
        "java" => Some(&JAVA),
        "javascript" => Some(&JAVASCRIPT),
        "python" => Some(&PYTHON),
        "ruby" => Some(&RUBY),
        "rust" => Some(&RUST),
        "typescript" => Some(&TYPESCRIPT),
        _ => None,
    }
}

/// Whether a metric rule may name this language. Load-time check; the engine
/// silently measures nothing for a language it has no table for.
pub fn has_kinds(language: &str) -> bool {
    kinds(language).is_some()
}

/// One function-like node's four measures and the span a finding reports on.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct Measured {
    /// Byte range of the name node, or of the first token when there is none.
    start: usize,
    end: usize,
    length: u32,
    parameters: u32,
    depth: u32,
    complexity: u32,
}

impl Measured {
    fn value(&self, measure: Measure) -> u32 {
        match measure {
            Measure::FunctionLength => self.length,
            Measure::ParameterCount => self.parameters,
            Measure::NestingDepth => self.depth,
            Measure::CyclomaticComplexity => self.complexity,
        }
    }
}

/// Run every applicable metric rule over one file's pre-parsed tree. `tree` is
/// parsed once per file by the caller; `None` yields no findings. Findings are
/// returned in reported-offset order; the caller owns the global ordering.
pub fn scan_file(
    rules: &[CompiledRule],
    path_rel: &str,
    language: Option<&str>,
    content: &str,
    tree: Option<&Tree>,
) -> Vec<Finding> {
    let (Some(language), Some(tree)) = (language, tree) else {
        return Vec::new();
    };
    let Some(kinds) = kinds(language) else {
        return Vec::new();
    };

    let applicable: Vec<&CompiledRule> = rules
        .iter()
        .filter(|rule| matches!(rule.payload, CompiledPayload::Metric { .. }))
        .filter(|rule| applies(rule, path_rel, Some(language)))
        .collect();
    if applicable.is_empty() {
        return Vec::new();
    }

    let functions = measure_tree(tree, kinds);
    if functions.is_empty() {
        return Vec::new();
    }

    // Rules in load order on the outside, functions in tree order on the
    // inside: the occurrence counter is per rule and order-sensitive, so this
    // is the order it has to see the matches in.
    let mut occurrences = Occurrences::new();
    let mut lines = LineIndex::new(content);
    let mut hits: Vec<(usize, Finding)> = Vec::new();

    for rule in applicable {
        let CompiledPayload::Metric { measure, max } = &rule.payload else {
            continue;
        };
        for function in &functions {
            let value = function.value(*measure);
            if value <= *max {
                continue;
            }
            let Some(text) = content.get(function.start..function.end) else {
                continue;
            };
            let occurrence = occurrences.next(rule.id.as_str(), text);
            let at = lines.position(function.start);
            hits.push((
                function.start,
                Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    // The value cannot go in `matched` without moving the
                    // fingerprint every time the function is edited, so it goes
                    // here, in a shape a reader and a diff can both follow.
                    message: format!("{}: {value} > {max}", rule.message),
                    path: path_rel.to_string(),
                    line: at.line,
                    column: at.column,
                    column_utf16: at.column_utf16,
                    matched: text.to_string(),
                    fingerprint: fingerprint(&rule.id, path_rel, text, occurrence),
                },
            ));
        }
    }

    hits.sort_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, finding)| finding).collect()
}

/// What one node of the walk leaves behind for its children.
#[derive(Clone, Copy)]
struct Level {
    /// Nesting depth of this node, counted from the innermost open unit. A
    /// unit's own node is depth 0: its body is not nesting.
    nesting: u32,
    /// This node is function-like, so a `body` child of it is not a unit.
    function: bool,
    /// This node is the language's binary node inside an open unit, so its
    /// `operator` child decides whether it branches.
    binary: bool,
    /// This node opened a unit, which leaving it closes again.
    opened: bool,
}

/// Measure every function-like node in the tree, in start-offset order.
///
/// One [`TreeCursor`](tree_sitter::TreeCursor) makes one depth-first pass and
/// computes all four measures on the way down. A stack of open units carries
/// the counters, so every node is attributed to the innermost unit that
/// encloses it and a nested function never inflates its parent: the moment a
/// nested unit opens, the parent stops being credited, and it resumes when that
/// unit closes.
///
/// A function-like node is a unit of its own except when it is another
/// function-like node's `body`. That case is Ruby's, where a lambda's body is
/// itself a `block` or a `do_block`: measuring both would leave the `lambda`
/// unit trivial and report a long lambda twice, once on `->` and once on `{`.
/// Folding the body into the lambda puts one finding on the `lambda` node,
/// whose `lambda_parameters` are the parameters a reader would name. No other
/// grammar gives a function-like node for a body.
///
/// The walk is iterative rather than recursive for the reason it always was: a
/// source file's tree is as deep as its author made it, and a scanner must not
/// overflow on one.
fn measure_tree(tree: &Tree, kinds: &Kinds) -> Vec<Measured> {
    let ids = Ids::resolve(&tree.language(), kinds);

    let mut out: Vec<Measured> = Vec::new();
    let mut cursor = tree.walk();
    // One entry per ancestor of the node being visited, innermost last.
    let mut levels: Vec<Level> = Vec::new();
    // Slot in `out` of each open unit, innermost last.
    let mut open: Vec<usize> = Vec::new();

    loop {
        let node = cursor.node();
        let kind = node.kind_id();
        let named = node.is_named();
        let parent = levels.last().copied();
        let mut level = Level {
            nesting: parent.map_or(0, |above| above.nesting),
            function: ids.functions.contains(&kind),
            binary: false,
            opened: false,
        };

        if level.function
            // The cursor already knows which field it descended through, so
            // the body test asks it rather than asking the parent for its
            // `body` child.
            && !(parent.is_some_and(|above| above.function)
                && ids.body.is_some()
                && cursor.field_id() == ids.body)
        {
            out.push(open_unit(node, kinds));
            open.push(out.len() - 1);
            level.opened = true;
            level.nesting = 0;
        } else if let Some(&slot) = open.last() {
            if ids.nesting.contains(&kind) {
                level.nesting += 1;
                out[slot].depth = out[slot].depth.max(level.nesting);
            }
            if ids.branches.contains(&kind) {
                out[slot].complexity += 1;
            } else if kind == ids.binary {
                level.binary = true;
            } else if parent.is_some_and(|above| above.binary)
                && ids.short_circuit.contains(&kind)
                && ids.operator.is_some()
                && cursor.field_id() == ids.operator
            {
                // The operator is an anonymous node in all ten grammars, and
                // counting it here, on the way past, is what spares every
                // binary node a field lookup of its own.
                out[slot].complexity += 1;
            }
        }

        levels.push(level);
        // Into named nodes only: an anonymous node is a token, and the walk
        // this one replaced never looked inside one either.
        if named && cursor.goto_first_child() {
            continue;
        }
        loop {
            let left = levels.pop().expect("one level per visited node");
            if left.opened {
                open.pop();
            }
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                out.sort_by_key(|measured| measured.start);
                return out;
            }
        }
    }
}

/// The measures a unit gets on entry: the two that are a lookup on the function
/// node rather than a count over its subtree.
fn open_unit(node: Node<'_>, kinds: &Kinds) -> Measured {
    let report = name_node(node).unwrap_or_else(|| first_token(node));
    let range = report.byte_range();
    Measured {
        start: range.start,
        end: range.end,
        length: (node.end_position().row - node.start_position().row + 1) as u32,
        parameters: parameter_count(node, kinds),
        depth: 0,
        // Cyclomatic complexity is `1 + branches`; the walk adds the branches.
        complexity: 1,
    }
}

/// One language's [`Kinds`] table resolved against the grammar that parsed the
/// file: numeric node kinds rather than names.
///
/// Reading a node's kind as a string costs a scan of that string, and every
/// column below would then be a run of string comparisons on every node of the
/// tree. Resolving the tables costs a few dozen lookups per file, once, and
/// leaves the walk comparing integers. A kind the grammar does not have
/// resolves to `0`, which is no node's kind, so it never matches — the same as
/// a name no node carries.
struct Ids {
    functions: Vec<u16>,
    branches: Vec<u16>,
    nesting: Vec<u16>,
    short_circuit: Vec<u16>,
    binary: u16,
    body: Option<NonZeroU16>,
    operator: Option<NonZeroU16>,
}

impl Ids {
    fn resolve(language: &Language, kinds: &Kinds) -> Self {
        let named = |names: &[&str]| {
            names
                .iter()
                .map(|name| language.id_for_node_kind(name, true))
                .collect()
        };
        Self {
            functions: named(kinds.functions),
            branches: named(kinds.branches),
            nesting: named(kinds.nesting),
            short_circuit: kinds
                .short_circuit
                .iter()
                .map(|operator| language.id_for_node_kind(operator, false))
                .collect(),
            binary: language.id_for_node_kind(kinds.binary, true),
            body: language.field_id_for_name("body"),
            operator: language.field_id_for_name("operator"),
        }
    }
}

/// The function's name node.
///
/// Every grammar but c and c++ puts it under a `name` field. Those two hang the
/// name off a declarator chain (`function_definition` → `function_declarator` →
/// `identifier`), and the same chain on a c++ lambda ends at an
/// `abstract_function_declarator` that is a parameter list and not a name,
/// which is what the `parameters` check rejects.
fn name_node(node: Node<'_>) -> Option<Node<'_>> {
    if let Some(name) = node.child_by_field_name("name") {
        return Some(name);
    }

    let mut current = node;
    while let Some(declarator) = current.child_by_field_name("declarator") {
        current = declarator;
    }
    if current.id() != node.id() && current.child_by_field_name("parameters").is_none() {
        return Some(current);
    }
    None
}

/// The function node's first token, the span an anonymous function reports on.
fn first_token(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while let Some(child) = current.child(0) {
        current = child;
    }
    current
}

fn parameter_count(node: Node<'_>, kinds: &Kinds) -> u32 {
    let Some(list) = parameter_list(node) else {
        return 0;
    };
    if !kinds.parameter_lists.contains(&list.kind()) {
        // A bare parameter with no list around it: a javascript `x => x`, a
        // c# `x => x`.
        return 1;
    }
    let mut count = 0;
    let mut cursor = list.walk();
    // A cursor and not `named_children`, because a Ruby block writes its
    // block-local variables into the same list under a `locals` field, and a
    // local is not a parameter.
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.is_named()
                && cursor.field_name() != Some("locals")
                && !kinds.not_parameters.contains(&child.kind())
            {
                count += names(child);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    count
}

/// How many parameters one entry of a parameter list is.
///
/// One, everywhere but Go, which groups parameters sharing a type into a single
/// `parameter_declaration` carrying one `name` field per parameter:
/// `func f(a, b, c int)` is one declaration and three parameters. An entry with
/// no name at all — an unnamed parameter in a Go signature — is still one
/// parameter.
fn names(node: Node<'_>) -> u32 {
    let mut cursor = node.walk();
    let named = node.children_by_field_name("name", &mut cursor).count() as u32;
    named.max(1)
}

/// The node holding the function's parameters: a list, or the single bare
/// parameter some grammars allow in its place. c and c++ reach it through the
/// declarator chain, which is why this is a walk and not one field lookup.
fn parameter_list(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        if let Some(parameters) = current.child_by_field_name("parameters") {
            return Some(parameters);
        }
        if let Some(parameter) = current.child_by_field_name("parameter") {
            return Some(parameter);
        }
        current = current.child_by_field_name("declarator")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers;
    use crate::rules::load_str;

    /// One language's fixture: a function whose four measures are known, and
    /// the values the engine must report for it.
    struct Fixture {
        language: &'static str,
        path: &'static str,
        /// The function the assertions are about.
        name: &'static str,
        source: &'static str,
        length: u32,
        parameters: u32,
        depth: u32,
        complexity: u32,
    }

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    fn rule(id: &str, measure: &str, max: u32) -> String {
        format!(
            "version: 1\nrules:\n  - id: {id}\n    severity: info\n    message: over budget\n    \
             metric:\n      measure: {measure}\n      max: {max}\n"
        )
    }

    fn scan(compiled: &[CompiledRule], path: &str, lang: &str, content: &str) -> Vec<Finding> {
        let tree = parsers::parse(lang, content).expect("tree");
        scan_file(compiled, path, Some(lang), content, Some(&tree))
    }

    /// Measure `fixture`'s named function through a rule whose `max` is one
    /// below the expected value, which is the only threshold that proves the
    /// number rather than merely bounding it.
    fn assert_measure(fixture: &Fixture, measure: &str, expected: u32) {
        let id = format!("metric.{measure}");
        let compiled = rules(&rule(&id, measure, expected - 1));
        let found = scan(&compiled, fixture.path, fixture.language, fixture.source);
        let hit = found
            .iter()
            .find(|finding| finding.matched == fixture.name)
            .unwrap_or_else(|| {
                panic!(
                    "{}: {measure} did not report {}: {found:#?}",
                    fixture.language, fixture.name
                )
            });
        assert_eq!(
            hit.message,
            format!("over budget: {expected} > {}", expected - 1),
            "{}: {measure} measured the wrong value",
            fixture.language
        );

        // And exactly at the value, nothing reports: the comparison is strict.
        let compiled = rules(&rule(&id, measure, expected));
        let found = scan(&compiled, fixture.path, fixture.language, fixture.source);
        assert!(
            !found.iter().any(|finding| finding.matched == fixture.name),
            "{}: {measure} reported at exactly max: {found:#?}",
            fixture.language
        );
    }

    /// One fixture per language. Each holds a function of known length,
    /// parameter count, nesting depth and cyclomatic complexity, written so the
    /// four numbers are readable off the source.
    ///
    /// Complexity is `1 + branches`; the branches are marked `+1` in comments.
    fn fixtures() -> Vec<Fixture> {
        vec![
            Fixture {
                language: "c",
                path: "src/a.c",
                name: "handle",
                // 8 lines, 3 params, depth 2, complexity 1+if+for+&&+?: = 5
                source: "int handle(int a, char *b, void *c) {\n\
                         if (a > 0 && b) {\n\
                         for (int i = 0; i < a; i++) {\n\
                         b[i] = 0;\n\
                         }\n\
                         }\n\
                         return a ? 1 : 0;\n\
                         }\n",
                length: 8,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "cpp",
                path: "src/a.cpp",
                name: "handle",
                // 8 lines, 3 params, depth 2, complexity 1+if+for+&&+?: = 5
                source: "int handle(int a, char *b, void *c) {\n\
                         if (a > 0 && b) {\n\
                         for (int i = 0; i < a; i++) {\n\
                         b[i] = 0;\n\
                         }\n\
                         }\n\
                         return a ? 1 : 0;\n\
                         }\n",
                length: 8,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "csharp",
                path: "src/A.cs",
                name: "Handle",
                // 8 lines, 3 params, depth 2, complexity 1+if+foreach+&&+?: = 5
                source: "class A {\n\
                         int Handle(int a, string b, object c) {\n\
                         if (a > 0 && b != null) {\n\
                         foreach (var x in b) {\n\
                         a++;\n\
                         }\n\
                         }\n\
                         return a > 0 ? 1 : 0;\n\
                         }\n\
                         }\n",
                length: 8,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "go",
                path: "src/a.go",
                name: "Handle",
                // 12 lines, 3 params, depth 2, complexity 1+if+for+&&+case = 5
                source: "package main\n\n\
                         func Handle(a int, b string, c bool) int {\n\
                         if a > 0 && c {\n\
                         for i := 0; i < a; i++ {\n\
                         a++\n\
                         }\n\
                         }\n\
                         switch b {\n\
                         case \"x\":\n\
                         a = 1\n\
                         }\n\
                         return a\n\
                         }\n",
                length: 12,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "java",
                path: "src/A.java",
                name: "handle",
                // 8 lines, 3 params, depth 2, complexity 1+if+for+&&+?: = 5
                source: "class A {\n\
                         int handle(int a, String b, Object c) {\n\
                         if (a > 0 && b != null) {\n\
                         for (int i = 0; i < a; i++) {\n\
                         a++;\n\
                         }\n\
                         }\n\
                         return a > 0 ? 1 : 0;\n\
                         }\n\
                         }\n",
                length: 8,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "javascript",
                path: "src/a.js",
                name: "handle",
                // 8 lines, 3 params, depth 2, complexity 1+if+for+&&+?: = 5
                source: "function handle(a, b, c) {\n\
                         if (a > 0 && b) {\n\
                         for (let i = 0; i < a; i++) {\n\
                         a++;\n\
                         }\n\
                         }\n\
                         return a > 0 ? 1 : 0;\n\
                         }\n",
                length: 8,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "python",
                path: "src/a.py",
                name: "handle",
                // 5 lines, 3 params, depth 2, complexity 1+if+for+and+cond = 5
                source: "def handle(a, b, c):\n\
                         \x20   if a > 0 and b:\n\
                         \x20       for i in range(a):\n\
                         \x20           a += i\n\
                         \x20   return 1 if a else 0\n",
                length: 5,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "ruby",
                path: "src/a.rb",
                name: "handle",
                // 8 lines, 3 params, depth 2, complexity 1+if+while+&&+ternary = 5
                source: "def handle(a, b, c)\n\
                         \x20 if a > 0 && b\n\
                         \x20   while a > 0\n\
                         \x20     a -= 1\n\
                         \x20   end\n\
                         \x20 end\n\
                         \x20 a > 0 ? 1 : 0\n\
                         end\n",
                length: 8,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "rust",
                path: "src/a.rs",
                name: "handle",
                // 8 lines, 3 params, depth 2, complexity 1+if+for+&&+match_arm = 5
                source: "fn handle(a: i32, b: bool, c: u8) -> i32 {\n\
                         if a > 0 && b {\n\
                         for i in 0..a {\n\
                         let _ = i;\n\
                         }\n\
                         }\n\
                         match c { _ => a }\n\
                         }\n",
                length: 8,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
            Fixture {
                language: "typescript",
                path: "src/a.ts",
                name: "handle",
                // 8 lines, 3 params, depth 2, complexity 1+if+for+&&+?: = 5
                source: "function handle(a: number, b: string, c: boolean): number {\n\
                         if (a > 0 && c) {\n\
                         for (let i = 0; i < a; i++) {\n\
                         a++;\n\
                         }\n\
                         }\n\
                         return a > 0 ? 1 : 0;\n\
                         }\n",
                length: 8,
                parameters: 3,
                depth: 2,
                complexity: 5,
            },
        ]
    }

    /// A grammar bump that renames or drops a kind must fail here rather than
    /// silently stop counting a branch. Only the languages this build enables
    /// are checked; the tables themselves exist for all ten either way.
    #[test]
    fn every_named_kind_still_exists() {
        for language in parsers::supported_languages() {
            let grammar = parsers::language(language).expect("a supported language has a grammar");
            let kinds = kinds(language).unwrap_or_else(|| panic!("{language} has no kind table"));

            let named = kinds
                .functions
                .iter()
                .chain(kinds.branches)
                .chain(std::iter::once(&kinds.binary))
                .chain(kinds.nesting)
                .chain(kinds.parameter_lists)
                .chain(kinds.not_parameters);
            for kind in named {
                assert_ne!(
                    grammar.id_for_node_kind(kind, true),
                    0,
                    "{language}: {kind} is no longer a named node of the grammar"
                );
            }

            // The short-circuit operators are anonymous nodes, and the whole
            // binary check reads their kind, so they get the same guard.
            for operator in kinds.short_circuit {
                assert_ne!(
                    grammar.id_for_node_kind(operator, false),
                    0,
                    "{language}: {operator} is no longer a token of the grammar"
                );
            }
        }
    }

    #[test]
    fn every_language_has_a_table() {
        for language in parsers::supported_languages() {
            assert!(has_kinds(language), "{language} has no metric table");
        }
        assert!(!has_kinds("klingon"));
    }

    /// `LANGUAGES` is what `ParseNeeds` reads to decide which files an
    /// unfiltered metric rule wants parsed, so a language `kinds` answers for
    /// but the list omits would never be parsed, and one the list carries but
    /// `kinds` does not would parse files for nothing.
    #[test]
    fn languages_is_exactly_the_tabled_set() {
        let mut sorted = LANGUAGES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), LANGUAGES.as_slice());

        for language in LANGUAGES {
            assert!(kinds(language).is_some(), "{language} is listed untabled");
        }
        // The other direction, over every name that can reach the engine: a
        // file's language comes from `lang::detect`, whose whole output is the
        // set of grammars this crate can parse.
        for language in parsers::supported_languages() {
            assert_eq!(
                LANGUAGES.contains(&language),
                kinds(language).is_some(),
                "{language} disagrees between LANGUAGES and kinds()"
            );
        }
        for language in ["", "klingon", "yaml", "json", "markdown", "toml"] {
            assert!(kinds(language).is_none(), "{language} has a table");
            assert!(!LANGUAGES.contains(&language));
        }
    }

    #[test]
    fn each_language_measures_its_fixture() {
        let enabled = parsers::supported_languages();
        for fixture in fixtures() {
            if !enabled.contains(&fixture.language) {
                continue;
            }
            assert!(
                !parsers::parse(fixture.language, fixture.source)
                    .expect("tree")
                    .root_node()
                    .has_error(),
                "{}: fixture does not parse cleanly",
                fixture.language
            );
            assert_measure(&fixture, "function-length", fixture.length);
            assert_measure(&fixture, "parameter-count", fixture.parameters);
            assert_measure(&fixture, "nesting-depth", fixture.depth);
            assert_measure(&fixture, "cyclomatic-complexity", fixture.complexity);
        }
    }

    /// Every measured unit of `source` as `(length, parameters, depth,
    /// complexity)`, in source order, read straight off the engine. Panics
    /// unless the source parses cleanly, so a fixture cannot pass on a broken
    /// tree.
    fn measures(language: &str, source: &str) -> Vec<(u32, u32, u32, u32)> {
        let tree = parsers::parse(language, source).expect("tree");
        assert!(
            !tree.root_node().has_error(),
            "{language}: fixture does not parse cleanly:\n{source}"
        );
        let kinds = kinds(language).expect("table");
        measure_tree(&tree, kinds)
            .into_iter()
            .map(|one| (one.length, one.parameters, one.depth, one.complexity))
            .collect()
    }

    /// The four measures of the one unit in `source`. The unit count is part of
    /// the assertion: it is what makes the numbers unambiguous.
    fn only_measure(language: &str, source: &str) -> (u32, u32, u32, u32) {
        let mut all = measures(language, source);
        assert_eq!(all.len(), 1, "{language}: expected one unit\n{source}");
        all.remove(0)
    }

    /// The parameter count of the *inner* unit, for a closure or lambda that
    /// can only be written inside a function.
    fn inner_parameters(language: &str, source: &str) -> u32 {
        let all = measures(language, source);
        assert_eq!(all.len(), 2, "{language}: expected two units\n{source}");
        all[1].1
    }

    fn only_complexity(language: &str, source: &str) -> u32 {
        only_measure(language, source).3
    }

    fn only_parameters(language: &str, source: &str) -> u32 {
        only_measure(language, source).1
    }

    fn only_depth(language: &str, source: &str) -> u32 {
        only_measure(language, source).2
    }

    /// A `switch_rule` holds a `switch_label` as its first child, so counting
    /// both would count every arm of an arrow switch twice and leave the two
    /// switch styles disagreeing about the same code.
    #[cfg(feature = "tree-sitter-java")]
    #[test]
    fn java_switch_styles_agree() {
        let arrow = "class A {\n  int f(int a) {\n    switch (a) {\n      case 1 -> a = 1;\n      \
                     case 2 -> a = 2;\n      default -> a = 3;\n    }\n    return a;\n  }\n}\n";
        let colon = "class A {\n  int f(int a) {\n    switch (a) {\n      case 1: a = 1; break;\n  \
                     case 2: a = 2; break;\n      default: a = 3;\n    }\n    return a;\n  }\n}\n";

        assert_eq!(only_complexity("java", arrow), 4);
        assert_eq!(only_complexity("java", colon), 4);
    }

    /// A Ruby lambda's body is itself a `do_block`, so measuring both would
    /// leave the lambda trivial and report a branchy lambda on the `do` instead
    /// of on the `->` that names it.
    #[cfg(feature = "tree-sitter-ruby")]
    #[test]
    fn a_ruby_lambda_is_one_unit_on_its_arrow() {
        let source = "pick = ->(a, b) do\n  if a > b\n    a\n  else\n    b\n  end\nend\n";
        assert_eq!(only_measure("ruby", source), (7, 2, 1, 2));

        let compiled = rules(&rule("metric.complexity", "cyclomatic-complexity", 1));
        let found = scan(&compiled, "src/a.rb", "ruby", source);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].matched, "->");
    }

    /// Go groups parameters that share a type into one declaration carrying a
    /// `name` field each, so counting declarations undercounts a signature.
    #[cfg(feature = "tree-sitter-go")]
    #[test]
    fn go_counts_grouped_parameter_names() {
        let source = "package main\n\nfunc f(a, b, c int, ctx string) {\n}\n";
        assert_eq!(only_parameters("go", source), 4);
    }

    /// A typed closure parameter is a `parameter`; an untyped one is a bare
    /// pattern under the `_pattern` supertype, and both are parameters.
    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn rust_counts_typed_and_untyped_closure_parameters() {
        assert_eq!(
            inner_parameters("rust", "fn m() {\n    let f = |a, b, c| a;\n}\n"),
            3
        );
        assert_eq!(
            inner_parameters("rust", "fn m() {\n    let f = |a: i32, b| a;\n}\n"),
            2
        );
    }

    /// A java lambda writes its parameters three ways.
    #[cfg(feature = "tree-sitter-java")]
    #[test]
    fn java_lambda_parameters_are_counted_however_they_are_written() {
        let inferred = "class A {\n  void m() {\n    var f = (a, b, c) -> a;\n  }\n}\n";
        let bare = "class A {\n  void m() {\n    var f = x -> x;\n  }\n}\n";
        let formal = "class A {\n  void m() {\n    var f = (int a, int b) -> a;\n  }\n}\n";

        assert_eq!(inner_parameters("java", inferred), 3);
        assert_eq!(inner_parameters("java", bare), 1);
        assert_eq!(inner_parameters("java", formal), 2);
    }

    /// `switch_default` is a node of its own, and is an arm like any other.
    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn a_javascript_switch_default_is_a_branch() {
        let source = "function f(a) {\n  switch (a) {\n    case 1: return 1;\n    case 2: return \
                      2;\n    default: return 3;\n  }\n}\n";
        assert_eq!(only_complexity("javascript", source), 4);
    }

    /// The pattern-matching statement is a nesting level, the same way every
    /// other language's switch statement is; its arms are not.
    #[cfg(feature = "tree-sitter-python")]
    #[test]
    fn a_python_match_statement_is_a_nesting_level() {
        let source = "def f(a):\n    match a:\n        case 1:\n            if a:\n                return \
             1\n        case _:\n            return 0\n";
        assert_eq!(only_depth("python", source), 2);
    }

    #[cfg(feature = "tree-sitter-ruby")]
    #[test]
    fn a_ruby_case_in_is_a_nesting_level() {
        let source = "def f(a)\n  case a\n  in 1\n    if a\n      1\n    end\n  else\n    0\n  \
                      end\nend\n";
        assert_eq!(only_depth("ruby", source), 2);
    }

    /// A comment sits in the parameter list as a named child and is not a
    /// parameter.
    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn a_javascript_comment_is_not_a_parameter() {
        assert_eq!(
            only_parameters(
                "javascript",
                "function f(/* unused */ a) {\n  return a;\n}\n"
            ),
            1
        );
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn a_rust_comment_is_not_a_parameter() {
        assert_eq!(
            only_parameters("rust", "fn f(/* unused */ a: i32) -> i32 {\n    a\n}\n"),
            1
        );
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn the_finding_is_on_the_name_and_survives_a_body_edit() {
        let compiled = rules(&rule("metric.complexity", "cyclomatic-complexity", 1));
        let before = "fn wide(a: bool) -> i32 {\n    if a { 1 } else { 0 }\n}\n";
        let after = "fn wide(a: bool) -> i32 {\n    // a comment\n    if a { 2 } else { 7 }\n}\n";

        let first = scan(&compiled, "src/a.rs", "rust", before);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].matched, "wide");
        // The name, not the `fn`: line 1, column 4.
        assert_eq!(first[0].line, 1);
        assert_eq!(first[0].column, 4);

        let second = scan(&compiled, "src/a.rs", "rust", after);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].fingerprint, first[0].fingerprint);
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn a_nested_function_is_measured_on_its_own() {
        let compiled = rules(&rule("metric.complexity", "cyclomatic-complexity", 1));
        // The outer function's only branch is the closure's, which belongs to
        // the closure; the outer is complexity 1 and does not report.
        let content = "fn outer(a: bool) -> i32 {\n    let f = |b: bool| if b { 1 } else { 0 };\n    f(a)\n}\n";
        let found = scan(&compiled, "src/a.rs", "rust", content);

        assert_eq!(found.len(), 1, "{found:#?}");
        // A closure has no name, so the span is the function node's first
        // token.
        assert_eq!(found[0].matched, "|");
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn two_anonymous_functions_get_distinct_fingerprints() {
        let compiled = rules(&rule("metric.complexity", "cyclomatic-complexity", 1));
        let content = "fn outer() {\n    let f = |b: bool| if b { 1 } else { 0 };\n    let g = |b: bool| if b { 2 } else { 3 };\n    let _ = (f, g);\n}\n";
        let found = scan(&compiled, "src/a.rs", "rust", content);

        assert_eq!(found.len(), 2, "{found:#?}");
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn a_paths_envelope_is_respected() {
        let src = "version: 1\nrules:\n  - id: metric.complexity\n    severity: info\n    \
                   message: over budget\n    paths:\n      include: [\"src/**\"]\n      \
                   exclude: [\"src/generated/**\"]\n    metric:\n      measure: \
                   cyclomatic-complexity\n      max: 1\n";
        let compiled = rules(src);
        let content = "fn wide(a: bool) -> i32 {\n    if a { 1 } else { 0 }\n}\n";

        assert_eq!(scan(&compiled, "src/a.rs", "rust", content).len(), 1);
        assert!(scan(&compiled, "src/generated/a.rs", "rust", content).is_empty());
        assert!(scan(&compiled, "vendor/a.rs", "rust", content).is_empty());
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn a_languages_filter_is_respected() {
        let src = "version: 1\nrules:\n  - id: metric.complexity\n    severity: info\n    \
                   message: over budget\n    languages: [python]\n    metric:\n      measure: \
                   cyclomatic-complexity\n      max: 1\n";
        let compiled = rules(src);
        let content = "fn wide(a: bool) -> i32 {\n    if a { 1 } else { 0 }\n}\n";

        assert!(scan(&compiled, "src/a.rs", "rust", content).is_empty());
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn a_rule_of_another_kind_reports_nothing_here() {
        let src = "version: 1\nrules:\n  - id: rust.dbg\n    severity: warning\n    message: m\n    \
                   ast:\n      rust: '(macro_invocation) @m'\n";
        let compiled = rules(src);
        let content = "fn wide(a: bool) -> i32 {\n    if a { 1 } else { 0 }\n}\n";

        assert!(scan(&compiled, "src/a.rs", "rust", content).is_empty());
    }

    /// The traversal [`measure_tree`] replaced, kept as the oracle it is
    /// checked against: one explicit stack to find the units, and a second one
    /// per unit to count over its subtree, every child reached through a
    /// `named_children` iterator that resets a cursor and crosses the FFI
    /// boundary per child. Every measured number is defined by this code; the
    /// single-pass walk is only allowed to be faster.
    fn measure_tree_by_stacks(tree: &Tree, kinds: &Kinds) -> Vec<Measured> {
        let mut out = Vec::new();
        let mut stack = vec![tree.root_node()];
        let mut cursor = tree.walk();

        while let Some(node) = stack.pop() {
            if is_unit_by_lookup(node, kinds) {
                out.push(measure_function_by_stacks(node, kinds));
            }
            stack.extend(node.named_children(&mut cursor));
        }

        out.sort_by_key(|measured| measured.start);
        out
    }

    fn measure_function_by_stacks(node: Node<'_>, kinds: &Kinds) -> Measured {
        let report = name_node(node).unwrap_or_else(|| first_token(node));
        let range = report.byte_range();

        let mut branches = 0u32;
        let mut depth = 0u32;
        let mut stack = vec![(node, 0u32)];
        let mut cursor = node.walk();

        while let Some((current, current_depth)) = stack.pop() {
            for child in current.named_children(&mut cursor) {
                if is_unit_by_lookup(child, kinds) {
                    continue;
                }
                if is_branch_by_lookup(child, kinds) {
                    branches += 1;
                }
                let child_depth = match kinds.nesting.contains(&child.kind()) {
                    true => {
                        let deeper = current_depth + 1;
                        depth = depth.max(deeper);
                        deeper
                    }
                    false => current_depth,
                };
                stack.push((child, child_depth));
            }
        }

        Measured {
            start: range.start,
            end: range.end,
            length: (node.end_position().row - node.start_position().row + 1) as u32,
            parameters: parameter_count(node, kinds),
            depth,
            complexity: branches + 1,
        }
    }

    fn is_unit_by_lookup(node: Node<'_>, kinds: &Kinds) -> bool {
        if !kinds.functions.contains(&node.kind()) {
            return false;
        }
        let Some(parent) = node.parent() else {
            return true;
        };
        if !kinds.functions.contains(&parent.kind()) {
            return true;
        }
        parent
            .child_by_field_name("body")
            .is_none_or(|body| body.id() != node.id())
    }

    fn is_branch_by_lookup(node: Node<'_>, kinds: &Kinds) -> bool {
        if kinds.branches.contains(&node.kind()) {
            return true;
        }
        if node.kind() != kinds.binary {
            return false;
        }
        node.child_by_field_name("operator")
            .is_some_and(|op| kinds.short_circuit.contains(&op.kind()))
    }

    /// A file far larger than any fixture, holding the shapes the two walks
    /// could disagree about — a closure and a nested `fn` inside a function,
    /// three levels of nesting, match arms, `&&` and `||` — repeated until the
    /// tree is deep and wide enough for an attribution mistake to show.
    fn a_large_rust_source() -> String {
        let mut source = String::new();
        for i in 0..64 {
            source.push_str(&format!(
                "fn outer_{i}(a: bool, b: Option<u8>, c: &[u8]) -> u32 {{\n    \
                 let mut total = 0u32;\n    \
                 if a && b.is_some() || c.is_empty() {{\n        \
                 for byte in c {{\n            \
                 while total < 8 {{\n                \
                 match byte {{\n                    \
                 0 => total += 1,\n                    \
                 1 | 2 => total += 2,\n                    \
                 _ => total += 3,\n                \
                 }}\n            \
                 }}\n        \
                 }}\n    \
                 }} else if let Some(v) = b {{\n        \
                 total += u32::from(v);\n    \
                 }}\n    \
                 let inner = |x: u32, y: u32| -> u32 {{\n        \
                 if x > y && y > 0 {{ x - y }} else {{ y - x }}\n    \
                 }};\n    \
                 fn helper_{i}(n: u32) -> u32 {{\n        \
                 if n % 2 == 0 || n % 3 == 0 {{ n / 2 }} else {{ n * 3 + 1 }}\n    \
                 }}\n    \
                 total = inner(total, helper_{i}(total));\n    \
                 total\n\
                 }}\n"
            ));
        }
        source
    }

    /// The single-pass walk is a performance change and nothing else: over
    /// every fixture in this module and over a file far larger than any of
    /// them, it must produce the same units with the same spans and the same
    /// four numbers, in the same order, as the stack walk it replaced.
    #[test]
    fn the_single_pass_walk_measures_what_the_stack_walk_did() {
        let enabled = parsers::supported_languages();
        let mut sources: Vec<(&str, String)> = fixtures()
            .into_iter()
            .filter(|fixture| enabled.contains(&fixture.language))
            .map(|fixture| (fixture.language, fixture.source.to_string()))
            .collect();
        if enabled.contains(&"rust") {
            sources.push(("rust", a_large_rust_source()));
        }
        assert!(!sources.is_empty(), "no language of the engine is enabled");

        for (language, source) in sources {
            let tree = parsers::parse(language, &source).expect("tree");
            assert!(
                !tree.root_node().has_error(),
                "{language}: source does not parse cleanly:\n{source}"
            );
            let kinds = kinds(language).expect("table");
            let single = measure_tree(&tree, kinds);
            assert!(!single.is_empty(), "{language}: nothing measured");
            assert_eq!(
                single,
                measure_tree_by_stacks(&tree, kinds),
                "{language}: the two walks disagree"
            );
        }
    }
}
