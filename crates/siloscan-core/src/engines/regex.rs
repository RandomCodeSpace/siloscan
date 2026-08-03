use super::{LineIndex, Occurrences, applies, capture_span};
use crate::findings::{Finding, fingerprint};
use crate::rules::{CompiledPayload, CompiledRule};

/// Run every applicable regex rule over one file's contents. Findings are
/// returned in match-offset order; the caller is responsible for the global
/// ordering across files.
pub fn scan_file(
    rules: &[CompiledRule],
    path_rel: &str,
    language: Option<&str>,
    content: &str,
) -> Vec<Finding> {
    let mut lines = LineIndex::new(content);
    let mut occurrences = Occurrences::new();
    let mut hits: Vec<(usize, Finding)> = Vec::new();

    for rule in rules {
        if !applies(rule, path_rel, language) {
            continue;
        }

        let CompiledPayload::Regex { regex, group } = &rule.payload else {
            continue;
        };

        for caps in regex.captures_iter(content) {
            // A `None` span means an optional capture did not participate.
            let Some(span) = capture_span(&caps, *group) else {
                continue;
            };

            let matched = span.as_str();
            let occurrence = occurrences.next(rule.id.as_str(), matched);
            let (line, column) = lines.position(span.start());

            hits.push((
                span.start(),
                Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    message: rule.message.clone(),
                    path: path_rel.to_string(),
                    line,
                    column,
                    matched: matched.to_string(),
                    fingerprint: fingerprint(&rule.id, path_rel, matched, occurrence),
                },
            ));
        }
    }

    hits.sort_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, finding)| finding).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Severity, load_str};

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    #[test]
    fn reports_line_and_column_across_lines() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.needle
    severity: warning
    message: found needle
    regex:
      pattern: 'needle'
"#,
        );
        let content = "alpha\nbeta needle\n  needle\n";
        let found = scan_file(&compiled, "src/main.rs", None, content);

        assert_eq!(found.len(), 2);
        assert_eq!((found[0].line, found[0].column), (2, 6));
        assert_eq!((found[1].line, found[1].column), (3, 3));
        assert_eq!(found[0].rule_id, "a.needle");
        assert_eq!(found[0].severity, Severity::Warning);
        assert_eq!(found[0].message, "found needle");
        assert_eq!(found[0].path, "src/main.rs");
        assert_eq!(found[0].matched, "needle");
    }

    #[test]
    fn first_line_column_is_one_based() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.head
    severity: info
    message: m
    regex:
      pattern: 'alpha'
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "alpha\n");
        assert_eq!((found[0].line, found[0].column), (1, 1));
    }

    #[test]
    fn group_narrows_the_reported_span() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.secret
    severity: error
    message: hardcoded secret
    regex:
      pattern: 'password\s*=\s*"([^"]*)"'
      group: 1
"#,
        );
        let content = "cfg = {}\npassword = \"hunter2\"\n";
        let found = scan_file(&compiled, "cfg.py", None, content);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "hunter2");
        // Line 2 starts at offset 9; the quoted value starts at offset 21.
        assert_eq!((found[0].line, found[0].column), (2, 13));
    }

    #[test]
    fn non_participating_group_is_skipped() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.optional
    severity: info
    message: m
    regex:
      pattern: 'key(=value)?'
      group: 1
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "key\nkey=value\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "=value");
        assert_eq!(found[0].line, 2);
    }

    #[test]
    fn identical_matches_get_increasing_occurrence_index() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.dupe
    severity: info
    message: m
    regex:
      pattern: 'x  =  1'
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "x  =  1\nx  =  1\n");

        assert_eq!(found.len(), 2);
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
        assert_eq!(
            found[0].fingerprint,
            fingerprint("a.dupe", "f.txt", "x  =  1", 0)
        );
        assert_eq!(
            found[1].fingerprint,
            fingerprint("a.dupe", "f.txt", "x  =  1", 1)
        );
    }

    #[test]
    fn occurrence_counter_is_keyed_by_normalized_text() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.spaced
    severity: info
    message: m
    regex:
      pattern: 'x\s+=\s+1'
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "x = 1\nx    =    1\n");

        assert_eq!(found.len(), 2);
        assert_eq!(
            found[1].fingerprint,
            fingerprint("a.spaced", "f.txt", "x = 1", 1)
        );
    }

    #[test]
    fn language_filter_gates_the_rule() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.rustonly
    severity: info
    message: m
    languages: ["rust"]
    regex:
      pattern: 'needle'
"#,
        );
        let content = "needle\n";
        assert!(scan_file(&compiled, "f.rs", None, content).is_empty());
        assert!(scan_file(&compiled, "f.py", Some("python"), content).is_empty());
        assert_eq!(scan_file(&compiled, "f.rs", Some("rust"), content).len(), 1);
    }

    #[test]
    fn include_and_exclude_filters_gate_the_rule() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.scoped
    severity: info
    message: m
    paths:
      include: ["src/**/*.rs"]
      exclude: ["**/tests/**"]
    regex:
      pattern: 'needle'
"#,
        );
        let content = "needle\n";
        assert_eq!(scan_file(&compiled, "src/a.rs", None, content).len(), 1);
        assert!(scan_file(&compiled, "docs/a.rs", None, content).is_empty());
        assert!(scan_file(&compiled, "src/tests/a.rs", None, content).is_empty());
    }

    #[test]
    fn findings_are_ordered_by_offset_across_rules() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.late
    severity: info
    message: m
    regex:
      pattern: 'gamma'
  - id: a.early
    severity: info
    message: m
    regex:
      pattern: 'alpha'
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "alpha\nbeta\ngamma\n");
        assert_eq!(
            found.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
            vec!["a.early", "a.late"]
        );
    }
}
