use std::collections::HashSet;
use std::path::Path;

use tree_sitter::{
    Language, Node, Query, QueryCursor, QueryMatch, QueryPredicate, QueryPredicateArg,
    StreamingIterator, Tree,
};

use super::{LineIndex, Occurrences, applies};
use crate::findings::{Finding, fingerprint};
use crate::rules::{CompiledPayload, CompiledRule};

/// Capture name that narrows the reported span; without it the whole first
/// capture of a match is reported.
const REPORT_CAPTURE: &str = "report";

/// `(#has-descendant? @node "<pattern>" ["<kind> <kind>"])`: keep the match
/// only if the sub-pattern matches inside `@node`'s subtree.
const HAS_DESCENDANT: &str = "has-descendant?";

/// `(#not-has-descendant? @node "<pattern>" ["<kind> <kind>"])`: the same
/// search, rejecting the match when it finds something.
const NOT_HAS_DESCENDANT: &str = "not-has-descendant?";

/// One combined tree-sitter query per grammar, carrying every ast rule's
/// patterns for that grammar's language.
///
/// One query per rule means one full tree traversal per rule; one query holding
/// every rule's patterns walks the tree once. `owners` maps a pattern index of
/// the combined query back to the rule that contributed it.
#[derive(Debug)]
pub struct AstQueries {
    grammars: Vec<CombinedQuery>,
    /// Length of the `rules` slice `build` was given. `scan_file` indexes that
    /// slice with the indices recorded here, so it must be handed the same one.
    rules_len: usize,
}

#[derive(Debug)]
struct CombinedQuery {
    /// The grammar this query is compiled against, which is the rule's language
    /// for every language but TypeScript. A typescript rule set yields two of
    /// these, `typescript` and `tsx`, and [`scan_file`] picks between them by
    /// the file's path. This field is the lookup key and nothing else reads it.
    grammar: String,
    query: Query,
    /// Rule indices into the `rules` slice `build` was given, in load order.
    rules: Vec<usize>,
    /// For each pattern index of `query`, the position in `rules` that owns it.
    owners: Vec<usize>,
    /// `@report` capture index of the combined query, shared by every pattern
    /// that names it. A pattern that does not name it carries no capture with
    /// this index, so such a match still falls back to its own first capture,
    /// exactly as it did when the rule owned the whole query.
    report: Option<u32>,
    /// One entry per pattern index of `query`, holding that pattern's subtree
    /// predicates in source order. Most patterns carry none.
    subtrees: Vec<Vec<Subtree>>,
}

/// One `#has-descendant?` or `#not-has-descendant?` predicate of one pattern,
/// compiled against one grammar.
///
/// The sub-pattern is a query in its own right, compiled once at load, and its
/// captures are private to it: it shares nothing with the pattern it qualifies
/// but the node the search starts from.
#[derive(Debug)]
struct Subtree {
    /// Index, in the combined query, of the capture whose subtree is searched.
    capture: u32,
    /// The sub-pattern. Its own `#eq?`, `#match?` and the rest are applied by
    /// tree-sitter when the sub-query runs.
    query: Query,
    /// Node kind ids the descent must not pass through. Empty means no stop.
    stops: Vec<u16>,
    /// `#not-has-descendant?`: a surviving sub-match rejects the match instead
    /// of keeping it.
    negated: bool,
}

/// A language's patterns as they are gathered, before the concatenation is
/// compiled. `rules` and `sources` are parallel, one entry per contributing
/// rule.
struct Pending {
    language: String,
    rules: Vec<usize>,
    sources: Vec<String>,
    owners: Vec<usize>,
}

impl AstQueries {
    /// Build the combined query of every ast rule in `rules`, per grammar.
    ///
    /// Compiling the concatenation is expected to succeed once each rule's own
    /// query has compiled: tree-sitter parses a query as a sequence of
    /// top-level patterns, predicates bind to the pattern they sit in, and
    /// capture names are resolved per query, so a name two rules share simply
    /// shares an index. The `Err` is the escape hatch for a rule pack that
    /// proves that wrong, and names the language and the rule it broke on.
    ///
    /// This is also where each pattern's subtree predicates are validated and
    /// their sub-patterns compiled, so a rule naming an unknown predicate, a
    /// sub-pattern that does not compile or an unknown stop kind fails here
    /// rather than matching nothing in silence.
    pub fn build(rules: &[CompiledRule]) -> Result<AstQueries, String> {
        let mut pending: Vec<Pending> = Vec::new();

        for (index, rule) in rules.iter().enumerate() {
            let CompiledPayload::Ast { queries } = &rule.payload else {
                continue;
            };

            for entry in queries {
                let slot = match pending.iter().position(|p| p.language == entry.language) {
                    Some(slot) => slot,
                    None => {
                        pending.push(Pending {
                            language: entry.language.clone(),
                            rules: Vec::new(),
                            sources: Vec::new(),
                            owners: Vec::new(),
                        });
                        pending.len() - 1
                    }
                };

                let slot = &mut pending[slot];
                let position = slot.rules.len();
                slot.rules.push(index);
                slot.sources.push(entry.source.clone());
                slot.owners
                    .extend(std::iter::repeat_n(position, entry.query.pattern_count()));
            }
        }

        let mut grammars = Vec::with_capacity(pending.len());
        for one in pending {
            // A typescript rule set is compiled twice, once per grammar: the
            // same sources and the same owners, so a `.tsx` file is measured by
            // exactly the rules a `.ts` file is. See `parsers::grammar_name`
            // for why the two grammars cannot be one.
            if one.language == "typescript" {
                grammars.push(compile_combined(&one, rules, "tsx")?);
            }
            grammars.push(compile_combined(&one, rules, &one.language)?);
        }

        Ok(AstQueries {
            grammars,
            rules_len: rules.len(),
        })
    }

    fn get(&self, grammar: &str) -> Option<&CombinedQuery> {
        self.grammars
            .iter()
            .find(|combined| combined.grammar == grammar)
    }
}

/// A query source may end in a line comment, so the separator between two
/// rules' patterns has to be a newline.
fn concatenate(sources: &[String]) -> String {
    sources.join("\n")
}

/// Compile `pending`'s patterns against `grammar`, which is the pending
/// language's own name except for the second, `tsx`, compilation of a
/// typescript rule set. A failure under either grammar fails the load and names
/// the grammar it failed under.
fn compile_combined(
    pending: &Pending,
    rules: &[CompiledRule],
    grammar: &str,
) -> Result<CombinedQuery, String> {
    let language = crate::parsers::language(grammar)
        .ok_or_else(|| format!("the ast grammar {grammar} no longer resolves to a parser"))?;

    let query = match Query::new(&language, &concatenate(&pending.sources)) {
        Ok(query) => query,
        Err(error) => {
            return Err(attribute(
                pending,
                rules,
                grammar,
                &language,
                &error.to_string(),
            ));
        }
    };
    if query.pattern_count() != pending.owners.len() {
        return Err(format!(
            "the combined {grammar} ast query holds {} patterns where its rules contribute {}",
            query.pattern_count(),
            pending.owners.len()
        ));
    }
    let report = query.capture_index_for_name(REPORT_CAPTURE);

    // Every predicate tree-sitter does not evaluate itself lands here, so this
    // is also the gate that rejects a predicate name the engine would
    // otherwise ignore in silence.
    let mut subtrees = Vec::with_capacity(query.pattern_count());
    for pattern in 0..query.pattern_count() {
        let rule = &rules[pending.rules[pending.owners[pattern]]].id;
        subtrees.push(
            query
                .general_predicates(pattern)
                .iter()
                .map(|predicate| compile_subtree(predicate, &language, grammar, rule))
                .collect::<Result<Vec<Subtree>, String>>()?,
        );
    }

    Ok(CombinedQuery {
        grammar: grammar.to_string(),
        query,
        rules: pending.rules.clone(),
        owners: pending.owners.clone(),
        report,
        subtrees,
    })
}

/// Validate one general predicate and compile its sub-pattern against the
/// grammar the enclosing query is being compiled for.
///
/// A typescript rule is compiled twice, so its sub-patterns and stop kinds have
/// to hold under both the `typescript` and the `tsx` grammar.
fn compile_subtree(
    predicate: &QueryPredicate,
    language: &Language,
    grammar: &str,
    rule: &str,
) -> Result<Subtree, String> {
    let operator = predicate.operator.as_ref();
    let negated = match operator {
        HAS_DESCENDANT => false,
        NOT_HAS_DESCENDANT => true,
        _ => {
            return Err(format!(
                "the {grammar} ast query of rule {rule} uses the unknown predicate #{operator}"
            ));
        }
    };
    let bad = |detail: String| {
        format!(
            "the {grammar} ast query of rule {rule} has an invalid #{operator} predicate: {detail}"
        )
    };

    if !(2..=3).contains(&predicate.args.len()) {
        return Err(bad(format!(
            "expected a capture, a sub-pattern and optionally a list of stop kinds, got {} argument(s)",
            predicate.args.len()
        )));
    }
    let QueryPredicateArg::Capture(capture) = predicate.args[0] else {
        return Err(bad("the first argument must be a capture".to_string()));
    };
    let QueryPredicateArg::String(source) = &predicate.args[1] else {
        return Err(bad(
            "the second argument must be a sub-pattern in quotes, not a capture".to_string(),
        ));
    };

    let query = Query::new(language, source)
        .map_err(|error| bad(format!("the sub-pattern does not compile: {error}")))?;
    // The engine evaluates these predicates for the patterns of the combined
    // query only. One nested inside a sub-pattern would be read by nobody, so
    // it is a load error rather than a silent no-op.
    if (0..query.pattern_count()).any(|pattern| !query.general_predicates(pattern).is_empty()) {
        return Err(bad(
            "the sub-pattern carries a predicate of its own that nothing evaluates".to_string(),
        ));
    }

    let stops = match predicate.args.get(2) {
        None => Vec::new(),
        Some(QueryPredicateArg::Capture(_)) => {
            return Err(bad(
                "the third argument must be node kinds in quotes, not a capture".to_string(),
            ));
        }
        Some(QueryPredicateArg::String(kinds)) => kinds
            .split_whitespace()
            .map(|kind| match language.id_for_node_kind(kind, true) {
                0 => Err(bad(format!(
                    "{kind} is not a node kind of the {grammar} grammar"
                ))),
                id => Ok(id),
            })
            .collect::<Result<Vec<u16>, String>>()?,
    };

    Ok(Subtree {
        capture,
        query,
        stops,
        negated,
    })
}

/// Name the rule the combined query broke on.
///
/// Tree-sitter reports a row and an offset into the concatenation, which is
/// source no user wrote and no message can usefully quote. Every rule compiled
/// alone, so the break is in the combination; recompiling growing prefixes
/// finds the first rule whose patterns the combination does not survive. This
/// runs on the error path only.
fn attribute(
    pending: &Pending,
    rules: &[CompiledRule],
    grammar: &str,
    language: &tree_sitter::Language,
    error: &str,
) -> String {
    for upto in 1..=pending.sources.len() {
        if Query::new(language, &concatenate(&pending.sources[..upto])).is_err() {
            return format!(
                "the combined {grammar} ast query failed to compile at rule {}: {error}",
                rules[pending.rules[upto - 1]].id
            );
        }
    }

    format!("the combined {grammar} ast query failed to compile: {error}")
}

/// Run every applicable ast rule over one file's pre-parsed tree, in a single
/// traversal. `tree` is parsed once per file by the caller; `None` yields no
/// findings. Findings are returned in node-start-offset order; the caller owns
/// the global ordering.
///
/// `queries` must have been built from `rules`: it holds indices into that
/// slice, so a different one would attribute findings to the wrong rules. Only
/// the length is checkable, and a mismatch yields no findings rather than
/// wrong ones.
pub fn scan_file(
    rules: &[CompiledRule],
    queries: &AstQueries,
    path_rel: &str,
    language: Option<&str>,
    content: &str,
    tree: Option<&Tree>,
) -> Vec<Finding> {
    debug_assert_eq!(
        rules.len(),
        queries.rules_len,
        "ast queries were built from a different rule set"
    );
    if rules.len() != queries.rules_len {
        return Vec::new();
    }

    let (Some(language), Some(tree)) = (language, tree) else {
        return Vec::new();
    };
    // The query is picked by grammar and the envelope by language: a `.tsx`
    // file is read by the tsx grammar and is still a typescript file to every
    // rule's `languages:` filter.
    let Some(combined) = queries.get(crate::parsers::grammar_name(language, Path::new(path_rel)))
    else {
        return Vec::new();
    };

    // The path envelope is per rule and the query is per language, so a match
    // of a rule this file lies outside of is dropped here rather than by not
    // running its patterns.
    let applicable: Vec<bool> = combined
        .rules
        .iter()
        .map(|&index| applies(&rules[index], path_rel, Some(language)))
        .collect();
    if !applicable.iter().any(|ok| *ok) {
        return Vec::new();
    }

    // Matches are collected before they become findings so they can be
    // replayed rule by rule in load order: the occurrence counter and the dedup
    // set are per rule, and both are order-sensitive.
    let mut matched: Vec<(usize, usize, usize)> = Vec::new();
    let mut cursor = QueryCursor::new();
    // One cursor for every subtree predicate of this file: the sub-queries run
    // one at a time, and the outer cursor is borrowed by the match iterator.
    let mut subtree_cursor = QueryCursor::new();
    let mut matches = cursor.matches(&combined.query, tree.root_node(), content.as_bytes());
    while let Some(pattern_match) = matches.next() {
        let owner = combined.owners[pattern_match.pattern_index];
        if !applicable[owner] {
            continue;
        }
        // Evaluated on matches of the enclosing pattern only, so the cost is
        // bounded by the subtree that already matched.
        if !subtrees_hold(
            &combined.subtrees[pattern_match.pattern_index],
            pattern_match,
            content,
            &mut subtree_cursor,
        ) {
            continue;
        }
        let Some(node) = report_node(pattern_match, combined.report) else {
            continue;
        };
        let range = node.byte_range();
        matched.push((owner, range.start, range.end));
    }
    // Stable, so every rule keeps the order tree-sitter produced its matches
    // in.
    matched.sort_by_key(|(owner, _, _)| *owner);

    let mut occurrences = Occurrences::new();
    let mut seen: HashSet<(&str, usize, usize)> = HashSet::new();
    let mut hits: Vec<(usize, Finding)> = Vec::new();
    // Positions come from the byte offset rather than from the node's own
    // `start_position`. Tree-sitter reports a column in bytes, which is the
    // right answer for one of the two columns a finding carries and silently
    // the wrong one for the other; measuring both from the same offset against
    // the same line is what keeps them consistent.
    let mut lines = LineIndex::new(content);

    for (owner, start, end) in matched {
        let rule = &rules[combined.rules[owner]];

        // The same node can be reported by several patterns of one rule.
        if !seen.insert((rule.id.as_str(), start, end)) {
            continue;
        }

        let Some(text) = content.get(start..end) else {
            continue;
        };

        let occurrence = occurrences.next(rule.id.as_str(), text);
        let at = lines.position(start);

        hits.push((
            start,
            Finding {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                message: rule.message.clone(),
                path: path_rel.to_string(),
                line: at.line,
                column: at.column,
                column_utf16: at.column_utf16,
                matched: text.to_string(),
                fingerprint: fingerprint(&rule.id, path_rel, text, occurrence),
            },
        ));
    }

    hits.sort_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, finding)| finding).collect()
}

/// The `@report` capture when the query defines one and this match carries it,
/// else the match's first capture.
fn report_node<'tree>(
    pattern_match: &QueryMatch<'_, 'tree>,
    report: Option<u32>,
) -> Option<Node<'tree>> {
    if let Some(index) = report
        && let Some(capture) = pattern_match
            .captures
            .iter()
            .find(|capture| capture.index == index)
    {
        return Some(capture.node);
    }

    pattern_match.captures.first().map(|capture| capture.node)
}

/// Whether every subtree predicate of the match's pattern holds, in source
/// order.
///
/// The capture a predicate names can be absent from a match when it sits in an
/// optional part of the pattern. There is then no subtree to search, which
/// counts as "nothing found": `#has-descendant?` fails and
/// `#not-has-descendant?` passes.
fn subtrees_hold(
    subtrees: &[Subtree],
    pattern_match: &QueryMatch<'_, '_>,
    content: &str,
    cursor: &mut QueryCursor,
) -> bool {
    subtrees.iter().all(|subtree| {
        let found = pattern_match
            .captures
            .iter()
            .find(|capture| capture.index == subtree.capture)
            .is_some_and(|capture| has_descendant(subtree, capture.node, content, cursor));
        found != subtree.negated
    })
}

/// Whether the sub-pattern matches inside `root`'s subtree without the descent
/// passing through a stop kind.
fn has_descendant(
    subtree: &Subtree,
    root: Node<'_>,
    content: &str,
    cursor: &mut QueryCursor,
) -> bool {
    let mut matches = cursor.matches(&subtree.query, root, content.as_bytes());
    while let Some(found) = matches.next() {
        // A sub-pattern with no capture gives tree-sitter's binding no node to
        // hand back, so such a sub-match is taken to sit on `root` itself:
        // nothing lies between the two, and the stop list cannot exclude it.
        let Some(capture) = found.captures.first() else {
            return true;
        };
        if !stopped(capture.node, root, &subtree.stops) {
            return true;
        }
    }
    false
}

/// Whether the walk from `node` up to `root` passes through a stop kind.
///
/// Only the nodes strictly between the two are stops: neither `root`, which is
/// the captured node the search started from, nor the sub-match itself.
fn stopped(node: Node<'_>, root: Node<'_>, stops: &[u16]) -> bool {
    if stops.is_empty() {
        return false;
    }

    let mut current = node;
    while current.id() != root.id() {
        let Some(parent) = current.parent() else {
            return false;
        };
        if parent.id() == root.id() {
            return false;
        }
        if stops.contains(&parent.kind_id()) {
            return true;
        }
        current = parent;
    }

    false
}

#[cfg(all(test, feature = "tree-sitter-rust", feature = "tree-sitter-python"))]
mod tests {
    use super::*;
    use crate::parsers;
    use crate::rules::{Severity, load_str};

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    fn scan(compiled: &[CompiledRule], path: &str, lang: &str, content: &str) -> Vec<Finding> {
        let tree = parsers::parse_file(lang, std::path::Path::new(path), content).expect("tree");
        let queries = AstQueries::build(compiled).expect("queries should combine");
        scan_file(compiled, &queries, path, Some(lang), content, Some(&tree))
    }

    const DBG_RULE: &str = r#"
version: 1
rules:
  - id: rust.dbg-macro
    severity: warning
    message: leftover dbg
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "dbg"))'
"#;

    #[test]
    fn rust_dbg_macro_reports_report_capture() {
        let compiled = rules(DBG_RULE);
        let content = "fn main() {\n    let x = 1;\n    dbg!(x);\n}\n";
        let found = scan(&compiled, "src/main.rs", "rust", content);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rust.dbg-macro");
        assert_eq!(found[0].severity, Severity::Warning);
        assert_eq!(found[0].message, "leftover dbg");
        assert_eq!(found[0].path, "src/main.rs");
        assert_eq!((found[0].line, found[0].column), (3, 5));
        assert_eq!(found[0].matched, "dbg");
        assert_eq!(
            found[0].fingerprint,
            fingerprint("rust.dbg-macro", "src/main.rs", "dbg", 0)
        );
    }

    #[test]
    fn whole_match_is_reported_without_a_report_capture() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: rust.dbg-whole
    severity: info
    message: m
    ast:
      rust: '(macro_invocation macro: (identifier) @name (#eq? @name "dbg")) @whole'
"#,
        );
        let content = "fn main() {\n    dbg!(x);\n}\n";
        let found = scan(&compiled, "src/main.rs", "rust", content);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "dbg!(x)");
        assert_eq!((found[0].line, found[0].column), (2, 5));
    }

    #[test]
    fn python_print_call_is_reported() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: python.print-call
    severity: info
    message: m
    ast:
      python: '(call function: (identifier) @report (#eq? @report "print"))'
"#,
        );
        let content = "def f():\n    print('hi')\n";
        let found = scan(&compiled, "app.py", "python", content);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "print");
        assert_eq!((found[0].line, found[0].column), (2, 5));
    }

    #[test]
    fn multi_language_rule_fires_per_file_language() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: any.calls
    severity: info
    message: m
    ast:
      python: '(call function: (identifier) @report)'
      rust: '(macro_invocation macro: (identifier) @report)'
"#,
        );

        let rust = scan(&compiled, "src/main.rs", "rust", "fn main() { dbg!(1); }\n");
        assert_eq!(rust.len(), 1);
        assert_eq!(rust[0].matched, "dbg");

        let python = scan(&compiled, "app.py", "python", "print('hi')\n");
        assert_eq!(python.len(), 1);
        assert_eq!(python[0].matched, "print");
    }

    #[test]
    fn rule_without_the_file_language_is_silent() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: python.only
    severity: info
    message: m
    ast:
      python: '(call function: (identifier) @report)'
"#,
        );
        assert!(scan(&compiled, "src/main.rs", "rust", "fn main() { dbg!(1); }\n").is_empty());
    }

    #[test]
    fn duplicate_node_matches_are_deduplicated() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: rust.dupe
    severity: info
    message: m
    ast:
      rust: |
        (macro_invocation) @a
        (macro_invocation) @b
"#,
        );
        let found = scan(&compiled, "src/main.rs", "rust", "fn main() { dbg!(1); }\n");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "dbg!(1)");
    }

    #[test]
    fn findings_are_ordered_by_node_offset_across_rules() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: rust.late
    severity: info
    message: m
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "todo"))'
  - id: rust.early
    severity: info
    message: m
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "dbg"))'
"#,
        );
        let content = "fn main() {\n    dbg!(1);\n    todo!();\n}\n";
        let found = scan(&compiled, "src/main.rs", "rust", content);

        assert_eq!(
            found.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
            vec!["rust.early", "rust.late"]
        );
    }

    #[test]
    fn missing_tree_or_language_yields_nothing() {
        let compiled = rules(DBG_RULE);
        let content = "fn main() { dbg!(1); }\n";
        let tree = parsers::parse("rust", content).expect("tree");

        let queries = AstQueries::build(&compiled).expect("queries should combine");
        assert!(
            scan_file(
                &compiled,
                &queries,
                "src/main.rs",
                Some("rust"),
                content,
                None
            )
            .is_empty()
        );
        assert!(
            scan_file(
                &compiled,
                &queries,
                "src/main.rs",
                None,
                content,
                Some(&tree)
            )
            .is_empty()
        );
    }

    #[test]
    fn repeated_identical_matches_get_increasing_occurrence_index() {
        let compiled = rules(DBG_RULE);
        let content = "fn main() {\n    dbg!(x);\n    dbg!(x);\n}\n";
        let found = scan(&compiled, "src/main.rs", "rust", content);

        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].fingerprint,
            fingerprint("rust.dbg-macro", "src/main.rs", "dbg", 0)
        );
        assert_eq!(
            found[1].fingerprint,
            fingerprint("rust.dbg-macro", "src/main.rs", "dbg", 1)
        );
    }

    #[test]
    fn path_filters_still_gate_the_rule() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: rust.scoped
    severity: info
    message: m
    paths:
      include: ["src/**/*.rs"]
      exclude: ["**/tests/**"]
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "dbg"))'
"#,
        );
        let content = "fn main() { dbg!(1); }\n";
        assert_eq!(scan(&compiled, "src/a.rs", "rust", content).len(), 1);
        assert!(scan(&compiled, "docs/a.rs", "rust", content).is_empty());
        assert!(scan(&compiled, "src/tests/a.rs", "rust", content).is_empty());
    }

    /// Four rules in one language: two patterns in one rule, a predicate, a
    /// path envelope that excludes the fixture, and a rule with no `@report`
    /// capture sharing a query with rules that have one.
    const PACK: &str = r#"
version: 1
rules:
  - id: rust.two-patterns
    severity: warning
    message: two patterns
    ast:
      rust: |
        (macro_invocation macro: (identifier) @report (#eq? @report "dbg"))
        (unsafe_block) @report
  - id: rust.predicate
    severity: info
    message: predicate
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "todo"))'
  - id: rust.elsewhere
    severity: error
    message: out of envelope
    paths:
      include: ["tests/**"]
    ast:
      rust: '(identifier) @report'
  - id: rust.no-report
    severity: info
    message: first capture
    ast:
      rust: '(let_declaration pattern: (identifier) @name)'
"#;

    const PACK_FIXTURE: &str =
        "fn main() {\n    let x = 1;\n    dbg!(x);\n    todo!();\n    unsafe { dbg!(x); }\n}\n";

    #[test]
    fn a_pack_matches_running_each_rule_alone() {
        let compiled = rules(PACK);
        let together = scan(&compiled, "src/main.rs", "rust", PACK_FIXTURE);

        let mut apart: Vec<Finding> = Vec::new();
        for index in 0..compiled.len() {
            apart.extend(scan(
                &compiled[index..=index],
                "src/main.rs",
                "rust",
                PACK_FIXTURE,
            ));
        }
        // Stable, so this is the per-rule loop followed by a sort on the node
        // offset that the engine used to run.
        apart.sort_by_key(|finding| (finding.line, finding.column));

        assert_eq!(together, apart);
        assert_eq!(
            together
                .iter()
                .map(|finding| (finding.rule_id.as_str(), finding.matched.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("rust.no-report", "x"),
                ("rust.two-patterns", "dbg"),
                ("rust.predicate", "todo"),
                ("rust.two-patterns", "unsafe { dbg!(x); }"),
                ("rust.two-patterns", "dbg"),
            ]
        );
        // The excluded rule's patterns are in the combined query and its
        // matches are dropped by the envelope.
        assert!(
            together
                .iter()
                .all(|finding| finding.rule_id != "rust.elsewhere")
        );
        assert_eq!(
            scan(&compiled, "tests/main.rs", "rust", PACK_FIXTURE)
                .iter()
                .filter(|finding| finding.rule_id == "rust.elsewhere")
                .count(),
            7
        );
    }

    #[test]
    fn pattern_indices_map_back_to_their_rule() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: rust.two
    severity: info
    message: m
    ast:
      rust: |
        (macro_invocation macro: (identifier) @report (#eq? @report "dbg"))
        (macro_invocation macro: (identifier) @report (#eq? @report "todo"))
  - id: rust.one
    severity: info
    message: m
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "unimplemented"))'
"#,
        );

        let queries = AstQueries::build(&compiled).expect("queries should combine");
        let combined = queries.get("rust").expect("a combined rust query");
        assert_eq!(combined.query.pattern_count(), 3);
        assert_eq!(combined.owners, vec![0, 0, 1]);
        assert_eq!(combined.rules, vec![0, 1]);

        let content = "fn main() {\n    unimplemented!();\n    todo!();\n    dbg!(1);\n}\n";
        let found = scan(&compiled, "src/main.rs", "rust", content);
        assert_eq!(
            found
                .iter()
                .map(|finding| (finding.rule_id.as_str(), finding.matched.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("rust.one", "unimplemented"),
                ("rust.two", "todo"),
                ("rust.two", "dbg"),
            ]
        );
    }

    /// A `.tsx` file is a typescript file whose grammar is `tsx`. The plain
    /// typescript grammar reads the JSX here as a broken type assertion and
    /// swallows the statement after it, so this rule reports nothing at all
    /// under the mapping that sent every `.tsx` file to that grammar.
    #[cfg(feature = "tree-sitter-typescript")]
    #[test]
    fn a_typescript_rule_fires_after_jsx_in_a_tsx_file() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: typescript.self-assignment
    severity: warning
    message: m
    ast:
      typescript: '((assignment_expression left: (identifier) @l right: (identifier) @r) @report (#eq? @l @r))'
"#,
        );
        let content = "export function Badge({ label }: { label: string }) {\n  const icon = <img src=\"/icon.png\" alt=\"\" />;\n  label = label;\n  return <span className=\"badge\">{icon}{label}</span>;\n}\n";

        let found = scan(&compiled, "src/Badge.tsx", "typescript", content);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "label = label");
        assert_eq!(found[0].line, 3);

        // The same rule set, one grammar per path: the `.ts` reading of the
        // same bytes is a misparse and reports nothing.
        assert!(scan(&compiled, "src/Badge.ts", "typescript", content).is_empty());
    }

    /// Two rules whose reported nodes tie on the start offset: `foo` is both
    /// an identifier and the function of a call. The engine used to run rule by
    /// rule and stable-sort on the offset, so a tie broke in load order. The
    /// combined query yields the call match first whatever the load order is,
    /// so only the sort on the owning rule puts the tie back; without it this
    /// reports `outer`/`foo` before `inner`/`foo`.
    #[test]
    fn a_tie_on_the_offset_breaks_in_load_order() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: rust.inner
    severity: info
    message: m
    ast:
      rust: '(identifier) @report'
  - id: rust.outer
    severity: info
    message: m
    ast:
      rust: '(call_expression function: (identifier) @report)'
"#,
        );
        let found = scan(&compiled, "src/main.rs", "rust", "fn main() { foo(); }\n");

        assert_eq!(
            found
                .iter()
                .map(|finding| (finding.rule_id.as_str(), finding.matched.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("rust.inner", "main"),
                ("rust.inner", "foo"),
                ("rust.outer", "foo"),
            ]
        );
    }

    /// A sub-pattern with its own `#eq?`, run over the body of every function.
    #[test]
    fn has_descendant_keeps_only_the_function_that_contains_the_call() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: rust.blocking-sleep
    severity: warning
    message: m
    ast:
      rust: |
        ((function_item name: (identifier) @report body: (block) @body)
          (#has-descendant? @body "(call_expression function: (scoped_identifier name: (identifier) @f) (#eq? @f \"sleep\"))"))
"#,
        );
        let content = "async fn naps() {\n    std::thread::sleep(d);\n}\nasync fn works() {\n    work();\n}\n";
        let found = scan(&compiled, "src/main.rs", "rust", content);

        assert_eq!(
            found
                .iter()
                .map(|finding| finding.matched.as_str())
                .collect::<Vec<_>>(),
            vec!["naps"]
        );
    }

    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn not_has_descendant_keeps_the_function_without_the_sub_match() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: javascript.async-without-await
    severity: info
    message: m
    ast:
      javascript: |
        ((function_declaration name: (identifier) @report) @fn
          (#not-has-descendant? @fn "(await_expression) @a"))
"#,
        );
        let content = "async function a() {\n  await f();\n}\nasync function b() {\n  g();\n}\n";
        let found = scan(&compiled, "app.js", "javascript", content);

        assert_eq!(
            found
                .iter()
                .map(|finding| finding.matched.as_str())
                .collect::<Vec<_>>(),
            vec!["b"]
        );
    }

    /// The await belongs to the nested arrow function, not to `outer`. With the
    /// two function kinds stopping the descent it does not rescue `outer`;
    /// without them it does.
    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn stop_kinds_cut_the_descent_at_a_nested_function() {
        const CONTENT: &str =
            "async function outer() {\n  const inner = async () => {\n    await g();\n  };\n}\n";

        let stopping = rules(
            r#"
version: 1
rules:
  - id: javascript.stopped
    severity: info
    message: m
    ast:
      javascript: |
        ((function_declaration name: (identifier) @report) @fn
          (#not-has-descendant? @fn "(await_expression) @a" "arrow_function function_expression"))
"#,
        );
        let found = scan(&stopping, "app.js", "javascript", CONTENT);
        assert_eq!(
            found
                .iter()
                .map(|finding| finding.matched.as_str())
                .collect::<Vec<_>>(),
            vec!["outer"]
        );

        let descending = rules(
            r#"
version: 1
rules:
  - id: javascript.descending
    severity: info
    message: m
    ast:
      javascript: |
        ((function_declaration name: (identifier) @report) @fn
          (#not-has-descendant? @fn "(await_expression) @a"))
"#,
        );
        assert!(scan(&descending, "app.js", "javascript", CONTENT).is_empty());
    }

    /// A sub-pattern that captures nothing leaves the binding no node to report,
    /// so its sub-match counts as sitting on the captured node itself and the
    /// stop list cannot exclude it.
    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn a_capture_less_sub_pattern_is_not_stopped() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: javascript.capture-less
    severity: info
    message: m
    ast:
      javascript: |
        ((function_declaration name: (identifier) @report) @fn
          (#has-descendant? @fn "(await_expression)" "arrow_function"))
"#,
        );
        let content =
            "async function outer() {\n  const inner = async () => {\n    await g();\n  };\n}\n";
        let found = scan(&compiled, "app.js", "javascript", content);

        assert_eq!(
            found
                .iter()
                .map(|finding| finding.matched.as_str())
                .collect::<Vec<_>>(),
            vec!["outer"]
        );
    }

    /// Two predicates on one pattern, both carrying a sub-pattern with its own
    /// `#eq?`: a class that defines `equals` and no `hashCode`.
    #[cfg(feature = "tree-sitter-java")]
    #[test]
    fn two_sub_patterns_with_their_own_predicates_agree_on_one_class() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: java.equals-without-hashcode
    severity: warning
    message: m
    ast:
      java: |
        ((class_declaration name: (identifier) @report body: (class_body) @body)
          (#has-descendant? @body "(method_declaration name: (identifier) @m (#eq? @m \"equals\"))")
          (#not-has-descendant? @body "(method_declaration name: (identifier) @m (#eq? @m \"hashCode\"))"))
"#,
        );
        let content = concat!(
            "class A {\n  public boolean equals(Object o) { return false; }\n}\n",
            "class B {\n  public boolean equals(Object o) { return false; }\n",
            "  public int hashCode() { return 0; }\n}\n",
            "class C {\n  public int size() { return 0; }\n}\n",
        );
        let found = scan(&compiled, "src/A.java", "java", content);

        assert_eq!(
            found
                .iter()
                .map(|finding| finding.matched.as_str())
                .collect::<Vec<_>>(),
            vec!["A"]
        );
    }

    /// The sub-pattern is compiled once per grammar, so a typescript rule that
    /// carries one still fires on a `.tsx` file.
    #[cfg(feature = "tree-sitter-typescript")]
    #[test]
    fn a_typescript_subtree_predicate_fires_under_both_grammars() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: typescript.eval-in-function
    severity: warning
    message: m
    ast:
      typescript: |
        ((function_declaration name: (identifier) @report) @fn
          (#has-descendant? @fn "(call_expression function: (identifier) @c (#eq? @c \"eval\"))"))
"#,
        );

        let tsx = "export function Widget() {\n  const value = eval(\"1\");\n  return <div>{value}</div>;\n}\nexport function Plain() {\n  return <div />;\n}\n";
        let found = scan(&compiled, "src/Widget.tsx", "typescript", tsx);
        assert_eq!(
            found
                .iter()
                .map(|finding| finding.matched.as_str())
                .collect::<Vec<_>>(),
            vec!["Widget"]
        );

        let ts = "export function widget(): number {\n  return eval(\"1\");\n}\n";
        let found = scan(&compiled, "src/widget.ts", "typescript", ts);
        assert_eq!(
            found
                .iter()
                .map(|finding| finding.matched.as_str())
                .collect::<Vec<_>>(),
            vec!["widget"]
        );
    }

    /// Every way a subtree predicate can be wrong is a load error that names
    /// the rule it came from.
    #[test]
    fn a_broken_subtree_predicate_names_its_rule() {
        fn build_error(query: &str) -> String {
            let src = format!(
                "version: 1\nrules:\n  - id: rust.broken\n    severity: info\n    message: m\n    ast:\n      rust: |\n        {query}\n"
            );
            let compiled = rules(&src);
            AstQueries::build(&compiled).expect_err("the predicate should be rejected")
        }

        let unknown = build_error(r#"((identifier) @x (#nonsense? @x "(identifier) @i"))"#);
        assert!(unknown.contains("rust.broken"), "{unknown}");
        assert!(
            unknown.contains("unknown predicate #nonsense?"),
            "{unknown}"
        );

        let arity = build_error("((identifier) @x (#has-descendant? @x))");
        assert!(arity.contains("rust.broken"), "{arity}");
        assert!(arity.contains("1 argument(s)"), "{arity}");

        let literal = build_error(r#"((identifier) @x (#has-descendant? "x" "(identifier) @i"))"#);
        assert!(literal.contains("rust.broken"), "{literal}");
        assert!(
            literal.contains("first argument must be a capture"),
            "{literal}"
        );

        let broken = build_error(r#"((identifier) @x (#has-descendant? @x "(call_expression"))"#);
        assert!(broken.contains("rust.broken"), "{broken}");
        assert!(broken.contains("does not compile"), "{broken}");

        let kind = build_error(
            r#"((identifier) @x (#has-descendant? @x "(identifier) @i" "no_such_kind"))"#,
        );
        assert!(kind.contains("rust.broken"), "{kind}");
        assert!(
            kind.contains("no_such_kind is not a node kind of the rust grammar"),
            "{kind}"
        );

        let nested = build_error(
            r#"((identifier) @x (#has-descendant? @x "((identifier) @i (#has-descendant? @i \"(identifier) @j\"))"))"#,
        );
        assert!(nested.contains("rust.broken"), "{nested}");
        assert!(nested.contains("nothing evaluates"), "{nested}");
    }
}
