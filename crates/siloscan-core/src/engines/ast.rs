use std::collections::HashSet;

use tree_sitter::{Node, QueryCursor, QueryMatch, StreamingIterator, Tree};

use super::{Occurrences, applies};
use crate::findings::{Finding, fingerprint};
use crate::rules::{CompiledPayload, CompiledRule};

/// Capture name that narrows the reported span; without it the whole first
/// capture of a match is reported.
const REPORT_CAPTURE: &str = "report";

/// Run every applicable ast rule over one file's pre-parsed tree. `tree` is
/// parsed once per file by the caller; `None` yields no findings. Findings are
/// returned in node-start-offset order; the caller owns the global ordering.
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

    let mut occurrences = Occurrences::new();
    let mut seen: HashSet<(&str, usize, usize)> = HashSet::new();
    let mut hits: Vec<(usize, Finding)> = Vec::new();
    let mut cursor = QueryCursor::new();

    for rule in rules {
        if !applies(rule, path_rel, Some(language)) {
            continue;
        }

        let CompiledPayload::Ast { queries } = &rule.payload else {
            continue;
        };

        // An ast rule covers exactly the languages in its query map.
        let Some((_, query)) = queries.iter().find(|(lang, _)| lang == language) else {
            continue;
        };

        let report = query.capture_index_for_name(REPORT_CAPTURE);
        let mut matches = cursor.matches(query.as_ref(), tree.root_node(), content.as_bytes());

        while let Some(pattern_match) = matches.next() {
            let Some(node) = report_node(pattern_match, report) else {
                continue;
            };

            let range = node.byte_range();
            // The same node can be reported by several patterns of one query.
            if !seen.insert((rule.id.as_str(), range.start, range.end)) {
                continue;
            }

            let Some(matched) = content.get(range.clone()) else {
                continue;
            };

            let occurrence = occurrences.next(rule.id.as_str(), matched);
            let start = node.start_position();

            hits.push((
                range.start,
                Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    message: rule.message.clone(),
                    path: path_rel.to_string(),
                    line: start.row as u64 + 1,
                    column: start.column as u64 + 1,
                    matched: matched.to_string(),
                    fingerprint: fingerprint(&rule.id, path_rel, matched, occurrence),
                },
            ));
        }
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
        scan_file(compiled, path, Some(lang), content, Some(&tree))
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

        assert!(scan_file(&compiled, "src/main.rs", Some("rust"), content, None).is_empty());
        assert!(scan_file(&compiled, "src/main.rs", None, content, Some(&tree)).is_empty());
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
}
