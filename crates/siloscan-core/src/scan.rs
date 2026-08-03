use std::path::Path;

use serde::Serialize;

use crate::findings::Finding;
use crate::rules::RuleSet;
use crate::walk::{self, FileKind};

#[derive(Debug, Clone, Serialize)]
pub struct SkippedFile {
    /// Repo-relative path using forward slashes.
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
}

pub fn scan(root: &Path, rules: &RuleSet) -> ScanReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut skipped: Vec<SkippedFile> = Vec::new();

    for path in walk::collect_files(root) {
        let path_rel = relative(root, &path);
        match walk::read_text(&path) {
            // Binary files are not scannable input, not a failure to report.
            FileKind::Binary => {}
            FileKind::Unreadable(reason) => skipped.push(SkippedFile {
                path: path_rel,
                reason,
            }),
            FileKind::Text(content) => {
                let language = crate::lang::detect(&path, &content);
                findings.extend(crate::engines::regex::scan_file(
                    &rules.rules,
                    &path_rel,
                    language,
                    &content,
                ));
            }
        }
    }

    // Canonical order: path (bytewise), line, column, rule id.
    findings.sort_by(|a, b| {
        a.path
            .as_bytes()
            .cmp(b.path.as_bytes())
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.rule_id.as_bytes().cmp(b.rule_id.as_bytes()))
    });
    skipped.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    ScanReport { findings, skipped }
}

/// Scan-root-relative, forward-slash path. Fingerprints incorporate this
/// value, so it must depend only on the scanned tree, never on anything
/// above the scan root. A file scan root reports its file name so the path
/// is never empty.
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
  - id: test.needle
    severity: warning
    message: "needle found"
    regex:
      pattern: "needle"
"#;

    fn ruleset() -> RuleSet {
        RuleSet {
            rules: load_str(RULES, "test").expect("rules should load"),
        }
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn write(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    #[test]
    fn scans_a_tree_end_to_end() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let x = 1;\nlet needle = 2;\n");
        write(dir.path(), "src/deep/b.rs", b"// nothing here\n");

        let report = scan(dir.path(), &ruleset());

        assert!(report.skipped.is_empty());
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "test.needle");
        assert_eq!(finding.path, "src/a.rs");
        assert_eq!(finding.line, 2);
        assert_eq!(finding.column, 5);
        assert_eq!(finding.matched, "needle");
        assert_eq!(finding.fingerprint.len(), 64);
    }

    #[test]
    fn findings_are_in_canonical_order() {
        let dir = tempdir();
        // Created in non-sorted order on purpose.
        write(dir.path(), "z.rs", b"needle\nfiller\nneedle\n");
        write(dir.path(), "src/m.rs", b"needle needle\n");
        write(dir.path(), "a.rs", b"filler\nneedle\n");

        let report = scan(dir.path(), &ruleset());

        let order: Vec<(&str, u64, u64)> = report
            .findings
            .iter()
            .map(|f| (f.path.as_str(), f.line, f.column))
            .collect();
        assert_eq!(
            order,
            vec![
                ("a.rs", 2, 1),
                ("src/m.rs", 1, 1),
                ("src/m.rs", 1, 8),
                ("z.rs", 1, 1),
                ("z.rs", 3, 1),
            ]
        );
    }

    #[test]
    fn file_scan_root_still_reports_a_path() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"needle\n");

        let report = scan(&dir.path().join("src/a.rs"), &ruleset());

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "a.rs");
    }

    #[test]
    fn paths_are_relative_to_the_scan_root() {
        let dir = tempdir();
        write(dir.path(), "sub/b.rs", b"needle\n");

        let from_root = scan(dir.path(), &ruleset());
        let from_sub = scan(&dir.path().join("sub"), &ruleset());

        assert_eq!(from_root.findings.len(), 1);
        assert_eq!(from_root.findings[0].path, "sub/b.rs");
        assert_eq!(from_sub.findings.len(), 1);
        assert_eq!(from_sub.findings[0].path, "b.rs");
        // Paths never reach above the scan root, wherever the tree lives.
        assert!(!from_root.findings[0].path.contains(".."));
    }

    #[test]
    fn binary_file_is_skipped_silently() {
        let dir = tempdir();
        write(dir.path(), "blob.bin", b"needle\0\0\0needle");
        write(dir.path(), "ok.txt", b"needle\n");

        let report = scan(dir.path(), &ruleset());

        assert!(report.skipped.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "ok.txt");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_is_counted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        write(dir.path(), "secret.txt", b"needle\n");
        write(dir.path(), "ok.txt", b"needle\n");

        let locked = dir.path().join("secret.txt");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&locked).is_ok() {
            // Privileged run: the mode bits are ignored, so there is nothing to assert.
            return;
        }

        let report = scan(dir.path(), &ruleset());

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, "secret.txt");
        assert!(!report.skipped[0].reason.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "ok.txt");

        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
    }
}
