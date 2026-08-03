use std::collections::HashMap;

use crate::findings::{fingerprint, Finding};
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
    let mut occurrences: HashMap<(&str, String), u32> = HashMap::new();
    let mut hits: Vec<(usize, Finding)> = Vec::new();

    for rule in rules {
        if !applies(rule, path_rel, language) {
            continue;
        }

        let CompiledPayload::Regex { regex, group } = &rule.payload;

        for caps in regex.captures_iter(content) {
            let span = match group {
                Some(index) => match caps.get(*index) {
                    Some(span) => span,
                    // The capture is optional and did not participate.
                    None => continue,
                },
                None => match caps.get(0) {
                    Some(span) => span,
                    None => continue,
                },
            };

            let matched = span.as_str();
            let normalized = matched.split_whitespace().collect::<Vec<&str>>().join(" ");
            let counter = occurrences
                .entry((rule.id.as_str(), normalized))
                .or_insert(0);
            let occurrence = *counter;
            *counter += 1;

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

fn applies(rule: &CompiledRule, path_rel: &str, language: Option<&str>) -> bool {
    if let Some(languages) = &rule.languages {
        match language {
            Some(lang) => {
                if !languages.iter().any(|l| l == lang) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(include) = &rule.include {
        if !include.is_match(path_rel) {
            return false;
        }
    }

    if let Some(exclude) = &rule.exclude {
        if exclude.is_match(path_rel) {
            return false;
        }
    }

    true
}

/// Line-start byte offsets, built at most once per file and only when the file
/// produces at least one match.
struct LineIndex<'a> {
    content: &'a str,
    starts: Option<Vec<usize>>,
}

impl<'a> LineIndex<'a> {
    fn new(content: &'a str) -> Self {
        LineIndex {
            content,
            starts: None,
        }
    }

    /// Returns the 1-based line and 1-based byte column of `offset`.
    fn position(&mut self, offset: usize) -> (u64, u64) {
        let content = self.content;
        let starts = self.starts.get_or_insert_with(|| line_starts(content));
        // `starts` always begins with 0, so the partition point is at least 1.
        let index = starts.partition_point(|&start| start <= offset) - 1;
        ((index as u64) + 1, (offset - starts[index]) as u64 + 1)
    }
}

fn line_starts(content: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(16);
    starts.push(0);
    starts.extend(content.match_indices('\n').map(|(i, _)| i + 1));
    starts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{load_str, Severity};

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
