use std::collections::HashSet;

use tree_sitter::{Node, Query, QueryCursor, QueryMatch, StreamingIterator, Tree};

use super::{LineIndex, Occurrences, applies};
use crate::findings::{Finding, fingerprint};
use crate::rules::{CompiledPayload, CompiledRule};

/// Capture name that narrows the reported span; without it the whole first
/// capture of a match is reported.
const REPORT_CAPTURE: &str = "report";

/// One combined tree-sitter query per language, carrying every ast rule's
/// patterns for that language.
///
/// One query per rule means one full tree traversal per rule; one query holding
/// every rule's patterns walks the tree once. `owners` maps a pattern index of
/// the combined query back to the rule that contributed it.
#[derive(Debug)]
pub struct AstQueries {
    languages: Vec<CombinedQuery>,
    /// Length of the `rules` slice `build` was given. `scan_file` indexes that
    /// slice with the indices recorded here, so it must be handed the same one.
    rules_len: usize,
}

#[derive(Debug)]
struct CombinedQuery {
    language: String,
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
    /// Build the combined query of every ast rule in `rules`, per language.
    ///
    /// Compiling the concatenation is expected to succeed once each rule's own
    /// query has compiled: tree-sitter parses a query as a sequence of
    /// top-level patterns, predicates bind to the pattern they sit in, and
    /// capture names are resolved per query, so a name two rules share simply
    /// shares an index. The `Err` is the escape hatch for a rule pack that
    /// proves that wrong, and names the language and the rule it broke on.
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

        let mut languages = Vec::with_capacity(pending.len());
        for one in pending {
            languages.push(compile_combined(one, rules)?);
        }

        Ok(AstQueries {
            languages,
            rules_len: rules.len(),
        })
    }

    fn get(&self, language: &str) -> Option<&CombinedQuery> {
        self.languages
            .iter()
            .find(|combined| combined.language == language)
    }
}

/// A query source may end in a line comment, so the separator between two
/// rules' patterns has to be a newline.
fn concatenate(sources: &[String]) -> String {
    sources.join("\n")
}

fn compile_combined(pending: Pending, rules: &[CompiledRule]) -> Result<CombinedQuery, String> {
    let language = crate::parsers::language(&pending.language).ok_or_else(|| {
        format!(
            "the ast language {} no longer resolves to a parser",
            pending.language
        )
    })?;

    let query = match Query::new(&language, &concatenate(&pending.sources)) {
        Ok(query) => query,
        Err(error) => return Err(attribute(&pending, rules, &language, &error.to_string())),
    };
    if query.pattern_count() != pending.owners.len() {
        return Err(format!(
            "the combined {} ast query holds {} patterns where its rules contribute {}",
            pending.language,
            query.pattern_count(),
            pending.owners.len()
        ));
    }
    let report = query.capture_index_for_name(REPORT_CAPTURE);

    Ok(CombinedQuery {
        language: pending.language,
        query,
        rules: pending.rules,
        owners: pending.owners,
        report,
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
    language: &tree_sitter::Language,
    error: &str,
) -> String {
    for upto in 1..=pending.sources.len() {
        if Query::new(language, &concatenate(&pending.sources[..upto])).is_err() {
            return format!(
                "the combined {} ast query failed to compile at rule {}: {error}",
                pending.language,
                rules[pending.rules[upto - 1]].id
            );
        }
    }

    format!(
        "the combined {} ast query failed to compile: {error}",
        pending.language
    )
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
    let Some(combined) = queries.get(language) else {
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
    let mut matches = cursor.matches(&combined.query, tree.root_node(), content.as_bytes());
    while let Some(pattern_match) = matches.next() {
        let owner = combined.owners[pattern_match.pattern_index];
        if !applicable[owner] {
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

#[cfg(all(test, feature = "tree-sitter-rust", feature = "tree-sitter-python"))]
mod tests {
    use super::*;
    use crate::parsers;
    use crate::rules::{Severity, load_str};

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    fn scan(compiled: &[CompiledRule], path: &str, lang: &str, content: &str) -> Vec<Finding> {
        let tree = parsers::parse(lang, content).expect("tree");
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
}
