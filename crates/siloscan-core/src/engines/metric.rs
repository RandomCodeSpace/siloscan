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
//! | `parameter-count` | Counted children of the function's parameter list. |
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

use tree_sitter::{Node, Tree};

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
    /// Child kinds of a parameter list that are parameters. Empty means every
    /// named child counts.
    pub parameters: &'static [&'static str],
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
    parameters: &["parameter_declaration", "variadic_parameter"],
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
    parameters: &[
        "parameter_declaration",
        "optional_parameter_declaration",
        "variadic_parameter_declaration",
    ],
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
    parameters: &["parameter"],
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
    parameters: &["parameter_declaration", "variadic_parameter_declaration"],
};

const JAVA: Kinds = Kinds {
    functions: &[
        "method_declaration",
        "constructor_declaration",
        "compact_constructor_declaration",
        "lambda_expression",
    ],
    // `switch_label` is the old style and `switch_rule` the arrow style; a file
    // uses one or the other.
    branches: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "enhanced_for_statement",
        "switch_label",
        "switch_rule",
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
    parameter_lists: &["formal_parameters"],
    // `receiver_parameter` is not a parameter.
    parameters: &["formal_parameter", "spread_parameter"],
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
    branches: &[
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "for_in_statement",
        "switch_case",
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
    parameters: &[],
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
    ],
    parameter_lists: &["parameters", "lambda_parameters"],
    // `positional_separator` and `keyword_separator` are not parameters.
    parameters: &[
        "identifier",
        "default_parameter",
        "typed_parameter",
        "typed_default_parameter",
        "list_splat_pattern",
        "dictionary_splat_pattern",
    ],
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
        "if", "elsif", "unless", "while", "until", "for", "rescue", "case",
    ],
    parameter_lists: &["method_parameters", "block_parameters", "lambda_parameters"],
    parameters: &[],
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
    // `self_parameter` is not counted.
    parameters: &["parameter", "variadic_parameter"],
};

const TYPESCRIPT: Kinds = Kinds {
    functions: JAVASCRIPT.functions,
    branches: JAVASCRIPT.branches,
    binary: JAVASCRIPT.binary,
    short_circuit: JAVASCRIPT.short_circuit,
    nesting: JAVASCRIPT.nesting,
    parameter_lists: JAVASCRIPT.parameter_lists,
    // Typescript wraps every parameter, bare identifiers included.
    parameters: &["required_parameter", "optional_parameter"],
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

/// Measure every function-like node in the tree, in start-offset order.
///
/// The walk is an explicit stack rather than recursion: a source file's tree is
/// as deep as its author made it, and a scanner must not overflow on one.
fn measure_tree(tree: &Tree, kinds: &Kinds) -> Vec<Measured> {
    let mut out = Vec::new();
    let mut stack = vec![tree.root_node()];
    let mut cursor = tree.walk();

    while let Some(node) = stack.pop() {
        if kinds.functions.contains(&node.kind()) {
            out.push(measure_function(node, kinds));
        }
        stack.extend(node.named_children(&mut cursor));
    }

    out.sort_by_key(|measured| measured.start);
    out
}

fn measure_function(node: Node<'_>, kinds: &Kinds) -> Measured {
    let report = name_node(node).unwrap_or_else(|| first_token(node));
    let range = report.byte_range();

    let mut branches = 0u32;
    let mut depth = 0u32;
    // Depth of the function node itself is 0: its body is not nesting.
    let mut stack = vec![(node, 0u32)];
    let mut cursor = node.walk();

    while let Some((current, current_depth)) = stack.pop() {
        for child in current.named_children(&mut cursor) {
            // A nested function is its own unit and is measured on its own.
            if kinds.functions.contains(&child.kind()) {
                continue;
            }
            if is_branch(child, kinds) {
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

fn is_branch(node: Node<'_>, kinds: &Kinds) -> bool {
    if kinds.branches.contains(&node.kind()) {
        return true;
    }
    if node.kind() != kinds.binary {
        return false;
    }
    // The operator is an anonymous node in all ten grammars, so its kind is the
    // operator's own text.
    node.child_by_field_name("operator")
        .is_some_and(|op| kinds.short_circuit.contains(&op.kind()))
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
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .filter(|child| kinds.parameters.is_empty() || kinds.parameters.contains(&child.kind()))
        .count() as u32
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
                // 9 lines, 3 params, depth 2, complexity 1+if+foreach+&&+?: = 5
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
                // 7 lines, 3 params, depth 2, complexity 1+if+for+and+cond = 5
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
                .chain(kinds.parameters);
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
}
