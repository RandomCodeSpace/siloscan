use std::collections::HashMap;

use crate::findings::Finding;

/// Common stem of both markers; the suffix decides the scope.
const MARKER: &str = "siloscan-ignore";

/// Split findings into (kept, suppressed) according to the inline ignore
/// markers in `content`. Input order is preserved in both halves, so a
/// canonically ordered input yields canonically ordered output.
///
/// A line containing `siloscan-ignore: <ids>` suppresses the listed rules on
/// the following line; `siloscan-ignore-line: <ids>` suppresses them on the
/// marker's own line. Rule ids are mandatory and matched exactly.
pub fn partition(content: &str, findings: Vec<Finding>) -> (Vec<Finding>, Vec<Finding>) {
    let scopes = collect(content);
    if scopes.is_empty() {
        return (findings, Vec::new());
    }

    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for finding in findings {
        let hit = scopes
            .get(&finding.line)
            .is_some_and(|ids| ids.contains(&finding.rule_id));
        if hit {
            suppressed.push(finding);
        } else {
            kept.push(finding);
        }
    }

    (kept, suppressed)
}

/// Map of 1-based line number to the rule ids suppressed on that line.
fn collect(content: &str) -> HashMap<u64, Vec<String>> {
    let mut scopes: HashMap<u64, Vec<String>> = HashMap::new();

    for (index, line) in content.lines().enumerate() {
        let number = index as u64 + 1;
        for (offset, _) in line.match_indices(MARKER) {
            let rest = &line[offset + MARKER.len()..];
            // `-line:` must be tested first: the same-line marker contains the
            // next-line marker's stem.
            let (target, tail) = if let Some(tail) = rest.strip_prefix("-line:") {
                (number, tail)
            } else if let Some(tail) = rest.strip_prefix(':') {
                (number + 1, tail)
            } else {
                continue;
            };

            let ids = parse_ids(tail);
            if ids.is_empty() {
                continue;
            }
            scopes.entry(target).or_default().extend(ids);
        }
    }

    scopes
}

/// Read the comma-separated id list following a marker. Parsing stops at the
/// first token that is not a bare rule id, so trailing prose or a comment
/// terminator does not become an id.
fn parse_ids(tail: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for token in tail.split(',') {
        let word = token.split_whitespace().next().unwrap_or("");
        if word.is_empty() || !word.chars().all(is_id_char) {
            break;
        }
        ids.push(word.to_string());
    }
    ids
}

fn is_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::findings::fingerprint;
    use crate::rules::Severity;

    fn finding(rule_id: &str, line: u64) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Warning,
            message: "found".to_string(),
            path: "src/a.rs".to_string(),
            line,
            column: 1,
            column_utf16: 1,
            matched: "needle".to_string(),
            fingerprint: fingerprint(rule_id, "src/a.rs", "needle", 0),
        }
    }

    fn ids(findings: &[Finding]) -> Vec<(&str, u64)> {
        findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.line))
            .collect()
    }

    #[test]
    fn next_line_marker_suppresses_the_following_line() {
        let content = "// siloscan-ignore: test.needle\nlet needle = 1;\n";

        let (kept, suppressed) = partition(content, vec![finding("test.needle", 2)]);

        assert!(kept.is_empty());
        assert_eq!(ids(&suppressed), vec![("test.needle", 2)]);
    }

    #[test]
    fn next_line_marker_does_not_suppress_its_own_line() {
        let content = "needle // siloscan-ignore: test.needle\nlet x = 1;\n";

        let (kept, suppressed) = partition(content, vec![finding("test.needle", 1)]);

        assert_eq!(ids(&kept), vec![("test.needle", 1)]);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn same_line_marker_suppresses_its_own_line() {
        let content = "let needle = 1; // siloscan-ignore-line: test.needle\n";

        let (kept, suppressed) = partition(content, vec![finding("test.needle", 1)]);

        assert!(kept.is_empty());
        assert_eq!(ids(&suppressed), vec![("test.needle", 1)]);
    }

    #[test]
    fn same_line_marker_is_not_read_as_a_next_line_marker() {
        let content = "let a = 1; # siloscan-ignore-line: test.needle\nlet needle = 2;\n";

        let (kept, suppressed) = partition(content, vec![finding("test.needle", 2)]);

        assert_eq!(ids(&kept), vec![("test.needle", 2)]);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn multiple_ids_are_suppressed() {
        let content = "/* siloscan-ignore: test.one ,test.two */\nneedle needle\n";

        let (kept, suppressed) = partition(
            content,
            vec![
                finding("test.one", 2),
                finding("test.two", 2),
                finding("test.three", 2),
            ],
        );

        assert_eq!(ids(&kept), vec![("test.three", 2)]);
        assert_eq!(ids(&suppressed), vec![("test.one", 2), ("test.two", 2)]);
    }

    #[test]
    fn id_mismatch_is_not_suppressed() {
        let content = "// siloscan-ignore: test.other\nlet needle = 1;\n";

        let (kept, suppressed) = partition(content, vec![finding("test.needle", 2)]);

        assert_eq!(ids(&kept), vec![("test.needle", 2)]);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn id_prefix_does_not_match() {
        let content = "// siloscan-ignore: test.need\nlet needle = 1;\n";

        let (kept, suppressed) = partition(content, vec![finding("test.needle", 2)]);

        assert_eq!(ids(&kept), vec![("test.needle", 2)]);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn marker_without_ids_suppresses_nothing() {
        let content = "// siloscan-ignore:\nlet needle = 1;\n// siloscan-ignore-line: \nneedle\n";

        let (kept, suppressed) = partition(
            content,
            vec![finding("test.needle", 2), finding("test.needle", 4)],
        );

        assert_eq!(ids(&kept), vec![("test.needle", 2), ("test.needle", 4)]);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn marker_on_the_last_line_is_harmless() {
        let content = "let needle = 1;\n// siloscan-ignore: test.needle\n";

        let (kept, suppressed) = partition(content, vec![finding("test.needle", 1)]);

        assert_eq!(ids(&kept), vec![("test.needle", 1)]);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn both_marker_forms_can_share_a_line() {
        let content =
            "needle // siloscan-ignore-line: test.one siloscan-ignore: test.two\nneedle\n";

        let (kept, suppressed) = partition(
            content,
            vec![
                finding("test.one", 1),
                finding("test.two", 1),
                finding("test.two", 2),
            ],
        );

        assert_eq!(ids(&kept), vec![("test.two", 1)]);
        assert_eq!(ids(&suppressed), vec![("test.one", 1), ("test.two", 2)]);
    }

    #[test]
    fn findings_without_markers_are_returned_unchanged() {
        let content = "let needle = 1;\nlet needle = 2;\n";

        let (kept, suppressed) = partition(
            content,
            vec![finding("test.needle", 1), finding("test.needle", 2)],
        );

        assert_eq!(ids(&kept), vec![("test.needle", 1), ("test.needle", 2)]);
        assert!(suppressed.is_empty());
    }
}
