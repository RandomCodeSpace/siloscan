use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use siloscan_core::serde_json::Value;
use tempfile::TempDir;

const MATCHING_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.needle\n",
    "    severity: error\n",
    "    message: needle found\n",
    "    regex:\n",
    "      pattern: 'needle'\n",
);

const NON_MATCHING_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.absent\n",
    "    severity: error\n",
    "    message: absent\n",
    "    regex:\n",
    "      pattern: 'zzz-not-present-zzz'\n",
);

const DUPLICATE_ID_RULES: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.dupe\n",
    "    severity: error\n",
    "    message: first\n",
    "    regex:\n",
    "      pattern: 'a'\n",
    "  - id: test.dupe\n",
    "    severity: error\n",
    "    message: second\n",
    "    regex:\n",
    "      pattern: 'b'\n",
);

fn write(dir: &Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

/// Rules live outside the scanned tree so rule files are never scan input.
fn fixture(rules_yaml: &str) -> (TempDir, TempDir) {
    let rules = tempfile::tempdir().unwrap();
    write(rules.path(), "rules.yaml", rules_yaml);

    let src = tempfile::tempdir().unwrap();
    // Marks the fixture as the repo root so reported paths cannot depend on
    // whatever lies above the system temp directory.
    fs::create_dir_all(src.path().join(".git")).unwrap();
    write(src.path(), "z.rs", "let a = 1;\nlet needle = 2;\n");
    write(src.path(), "a.rs", "needle\n");

    (rules, src)
}

fn run(rules: &Path, src: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_siloscan"))
        .arg(src)
        .arg("--rules")
        .arg(rules)
        .args(extra)
        .output()
        .expect("siloscan binary should run")
}

#[test]
fn findings_exit_one_in_canonical_order() {
    let (rules, src) = fixture(MATCHING_RULE);
    let output = run(rules.path(), src.path(), &[]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        vec![
            "a.rs:1:1 error test.needle needle found",
            "z.rs:2:5 error test.needle needle found",
        ]
    );
}

#[test]
fn json_format_parses_and_carries_fingerprints() {
    let (rules, src) = fixture(MATCHING_RULE);
    let output = run(rules.path(), src.path(), &["--format", "json"]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = siloscan_core::serde_json::from_str(&stdout).expect("stdout should be JSON");

    let findings = value["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 2);
    for finding in findings {
        let fingerprint = finding["fingerprint"].as_str().expect("fingerprint field");
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }
    assert_eq!(findings[0]["path"], "a.rs");
    assert_eq!(findings[1]["path"], "z.rs");
}

#[test]
fn no_findings_exits_zero() {
    let (rules, src) = fixture(NON_MATCHING_RULE);
    let output = run(rules.path(), src.path(), &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8(output.stdout).unwrap().is_empty());
}

#[test]
fn missing_scan_path_exits_two() {
    let (rules, src) = fixture(MATCHING_RULE);
    let missing = src.path().join("no-such-dir");
    let output = run(rules.path(), &missing, &[]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no-such-dir"), "stderr: {stderr}");
    assert!(String::from_utf8(output.stdout).unwrap().is_empty());
}

#[test]
fn invalid_rules_exit_two() {
    let (rules, src) = fixture(DUPLICATE_ID_RULES);
    let output = run(rules.path(), src.path(), &[]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("duplicate rule id"), "stderr: {stderr}");
}
