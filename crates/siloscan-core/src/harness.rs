use std::collections::BTreeSet;
use std::path::Path;

use crate::rules::RuleSet;
use crate::walk::{self, FileKind};

/// Marker token. A line containing it declares the expectations for the line
/// that follows: comma-separated rule ids after the token.
const MARKER: &str = "siloscan-expect:";

/// Result of checking a fixture tree against its inline expectations.
/// `missing` and `unexpected` hold human-readable `path:line rule_id` lines,
/// sorted by path (bytewise), line, then rule id. `matched` counts the
/// expectations that were satisfied.
#[derive(Debug, Clone)]
pub struct HarnessReport {
    pub missing: Vec<String>,
    pub unexpected: Vec<String>,
    pub matched: usize,
}

type Key = (String, u64, String);

pub fn run(fixture_root: &Path, rules: &RuleSet) -> HarnessReport {
    let (expected, markers) = collect_expectations(fixture_root);

    let report = crate::scan::scan(fixture_root, rules, None);
    let actual: BTreeSet<Key> = report
        .findings
        .into_iter()
        // A rule may match the marker text itself; that is not a fixture failure.
        .filter(|f| !markers.contains(&(f.path.clone(), f.line)))
        .map(|f| (f.path, f.line, f.rule_id))
        .collect();

    HarnessReport {
        missing: expected.difference(&actual).map(render).collect(),
        unexpected: actual.difference(&expected).map(render).collect(),
        matched: expected.intersection(&actual).count(),
    }
}

fn collect_expectations(fixture_root: &Path) -> (BTreeSet<Key>, BTreeSet<(String, u64)>) {
    let mut expected: BTreeSet<Key> = BTreeSet::new();
    let mut markers: BTreeSet<(String, u64)> = BTreeSet::new();

    for path in walk::collect_files(fixture_root) {
        let FileKind::Text(content) = walk::read_text(&path) else {
            continue;
        };
        let path_rel = relative(fixture_root, &path);

        // Line numbering matches the engines: split on '\n', 1-based.
        for (index, line) in content.split('\n').enumerate() {
            let Some(offset) = line.find(MARKER) else {
                continue;
            };
            let marker_line = index as u64 + 1;
            markers.insert((path_rel.clone(), marker_line));
            for id in rule_ids(&line[offset + MARKER.len()..]) {
                expected.insert((path_rel.clone(), marker_line + 1, id));
            }
        }
    }

    (expected, markers)
}

/// Rule ids are whitespace-free, so the first token of each comma-separated
/// segment is the id; anything trailing (a comment terminator, say) is dropped.
fn rule_ids(rest: &str) -> Vec<String> {
    rest.split(',')
        .filter_map(|segment| segment.split_whitespace().next())
        .map(|id| id.to_string())
        .collect()
}

fn render(key: &Key) -> String {
    let (path, line, rule_id) = key;
    format!("{path}:{line} {rule_id}")
}

/// Mirrors the scan-root-relative, forward-slash path used for findings.
fn relative(root: &Path, path: &Path) -> String {
    let tail = path.strip_prefix(root).unwrap_or(path);
    let joined = join_slashes(tail);
    if joined.is_empty() {
        join_slashes(Path::new(path.file_name().unwrap_or(path.as_os_str())))
    } else {
        joined
    }
}

fn join_slashes(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<String>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use crate::rules::load_str;

    const RULES: &str = r#"
version: 1
rules:
  - id: fixture.alpha
    severity: warning
    message: "alpha found"
    regex:
      pattern: "ALPHA"
  - id: fixture.beta
    severity: error
    message: "beta found"
    regex:
      pattern: "BETA"
"#;

    const MARKER_RULES: &str = r#"
version: 1
rules:
  - id: fixture.alpha
    severity: warning
    message: "alpha found"
    regex:
      pattern: "ALPHA"
  - id: fixture.self
    severity: info
    message: "matches the marker itself"
    regex:
      pattern: "siloscan-expect"
"#;

    fn ruleset(src: &str) -> RuleSet {
        RuleSet {
            rules: load_str(src, "test").expect("rules should load"),
        }
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    #[test]
    fn all_expectations_matched() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "src/a.rs",
            "// siloscan-expect: fixture.alpha\nlet x = ALPHA;\n\
             // siloscan-expect: fixture.alpha, fixture.beta\nlet y = ALPHA + BETA;\n",
        );

        let report = run(dir.path(), &ruleset(RULES));

        assert!(report.missing.is_empty());
        assert!(report.unexpected.is_empty());
        assert_eq!(report.matched, 3);
    }

    #[test]
    fn missing_expectation_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.rs",
            "// siloscan-expect: fixture.alpha, fixture.beta\nlet x = ALPHA;\n",
        );

        let report = run(dir.path(), &ruleset(RULES));

        assert_eq!(report.missing, vec!["a.rs:2 fixture.beta"]);
        assert!(report.unexpected.is_empty());
        assert_eq!(report.matched, 1);
    }

    #[test]
    fn unexpected_finding_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.rs", "let x = BETA;\n");

        let report = run(dir.path(), &ruleset(RULES));

        assert!(report.missing.is_empty());
        assert_eq!(report.unexpected, vec!["a.rs:1 fixture.beta"]);
        assert_eq!(report.matched, 0);
    }

    #[test]
    fn marker_line_self_match_is_exempt() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.rs",
            "// siloscan-expect: fixture.alpha\nlet x = ALPHA;\n",
        );

        let report = run(dir.path(), &ruleset(MARKER_RULES));

        assert!(report.missing.is_empty());
        assert!(report.unexpected.is_empty());
        assert_eq!(report.matched, 1);
    }

    #[test]
    fn output_is_sorted_canonically() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "z.rs", "BETA\nALPHA\n");
        write(dir.path(), "a.rs", "BETA ALPHA\n");
        write(dir.path(), "src/m.rs", "ALPHA\n");

        let report = run(dir.path(), &ruleset(RULES));

        assert!(report.missing.is_empty());
        assert_eq!(
            report.unexpected,
            vec![
                "a.rs:1 fixture.alpha",
                "a.rs:1 fixture.beta",
                "src/m.rs:1 fixture.alpha",
                "z.rs:1 fixture.beta",
                "z.rs:2 fixture.alpha",
            ]
        );
        assert_eq!(report.matched, 0);
    }
}
