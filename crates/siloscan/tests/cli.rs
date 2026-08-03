use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

/// Entropy-gated secret rule: the capture group is the token, so the gate sees
/// the token alone rather than the surrounding assignment.
const SECRET_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.token\n",
    "    severity: error\n",
    "    message: token found\n",
    "    secret:\n",
    "      pattern: 'token = \"([A-Za-z0-9]{16})\"'\n",
    "      group: 1\n",
    "      entropy: 3.5\n",
    "      keywords:\n",
    "        - token\n",
);

/// The rule id deliberately avoids the pattern text, so an inline marker naming
/// the id does not itself become a match.
const SUPPRESSIBLE_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: sup.hit\n",
    "    severity: error\n",
    "    message: needle found\n",
    "    regex:\n",
    "      pattern: 'needle'\n",
);

/// Reports the macro name node, so the span is the `dbg` identifier rather than
/// the whole invocation.
const AST_DBG_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: ast.dbg\n",
    "    severity: error\n",
    "    message: leftover dbg\n",
    "    ast:\n",
    "      rust: '(macro_invocation macro: (identifier) @report (#eq? @report \"dbg\"))'\n",
);

const BOUNDARY_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: arch.api-db\n",
    "    severity: error\n",
    "    message: api must not import db\n",
    "    boundary:\n",
    "      from: api\n",
    "      deny: [\"db\"]\n",
);

const COVERAGE_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: cov.min\n",
    "    severity: error\n",
    "    message: line coverage below threshold\n",
    "    coverage:\n",
    "      min: 80\n",
);

const SILO_CONFIG: &str = concat!(
    "[silos]\n",
    "api = [\"src/api/**\"]\n",
    "db = [\"src/db/**\"]\n",
);

/// `src/low.rs` is 20% covered, `src/high.rs` exactly 80%, so a `min: 80` rule
/// reports the first and clears the second.
const LCOV: &str = concat!(
    "TN:\n",
    "SF:src/low.rs\n",
    "DA:1,1\n",
    "DA:2,0\n",
    "DA:3,0\n",
    "DA:4,0\n",
    "DA:5,0\n",
    "LF:5\n",
    "LH:1\n",
    "end_of_record\n",
    "TN:\n",
    "SF:src/high.rs\n",
    "DA:1,1\n",
    "DA:2,1\n",
    "DA:3,1\n",
    "DA:4,1\n",
    "DA:5,0\n",
    "LF:5\n",
    "LH:4\n",
    "end_of_record\n",
);

fn write(dir: &Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn rules_dir(rules_yaml: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "rules.yaml", rules_yaml);
    dir
}

/// A scan root holding `files`. The `.git` entry marks it as the repo root so
/// reported paths cannot depend on whatever lies above the system temp
/// directory.
fn src_dir(files: &[(&str, &str)]) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    write(dir.path(), ".git/HEAD", "ref: refs/heads/main\n");
    for (rel, body) in files {
        write(dir.path(), rel, body);
    }
    dir
}

/// Rules live outside the scanned tree so rule files are never scan input.
fn fixture(rules_yaml: &str) -> (TempDir, TempDir) {
    let src = src_dir(&[
        ("z.rs", "let a = 1;\nlet needle = 2;\n"),
        ("a.rs", "needle\n"),
    ]);
    (rules_dir(rules_yaml), src)
}

/// One file that trips the ast rule and one that does not, so a run exercises
/// both the hit and the miss path through the cache.
fn ast_src() -> TempDir {
    src_dir(&[
        (
            "src/main.rs",
            "fn main() {\n    let x = 1;\n    dbg!(x);\n}\n",
        ),
        ("src/clean.rs", "pub fn f() -> u32 {\n    1\n}\n"),
    ])
}

fn ast_fixture() -> (TempDir, TempDir) {
    (rules_dir(AST_DBG_RULE), ast_src())
}

/// Every file under the scan root's cache directory, sorted. Empty when the
/// directory does not exist.
fn cache_entries(src: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    let mut out = Vec::new();
    walk(&src.join(".siloscan/cache"), &mut out);
    out.sort();
    out
}

/// A two-silo repository: one cross-silo import that the rule denies, and one
/// same-silo import that it must leave alone.
fn boundary_src() -> TempDir {
    src_dir(&[
        ("siloscan.toml", SILO_CONFIG),
        ("src/api/handler.js", "import x from '../db/client';\n"),
        ("src/api/routes.js", "import u from './util';\n"),
        ("src/api/util.js", "export const u = 1;\n"),
        ("src/db/client.js", "export const x = 1;\n"),
    ])
}

fn coverage_src() -> TempDir {
    src_dir(&[
        ("src/low.rs", "let x = 1;\n"),
        ("src/high.rs", "let y = 2;\n"),
    ])
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

fn run_args(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_siloscan"))
        .args(args)
        .output()
        .expect("siloscan binary should run")
}

fn path_str(dir: &TempDir) -> &str {
    dir.path().to_str().expect("temp path should be UTF-8")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be UTF-8")
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

#[test]
fn secret_rule_reports_only_above_the_entropy_threshold() {
    let rules = rules_dir(SECRET_RULE);
    let src = src_dir(&[(
        "s.rs",
        "token = \"aaaaaaaaaaaaaaaa\"\ntoken = \"aG7xQ2vT9pL4zR1b\"\n",
    )]);

    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines, vec!["s.rs:2:10 error test.token token found"]);
}

#[test]
fn baseline_then_rescan_reports_baselined_and_exits_zero() {
    let (rules, src) = fixture(MATCHING_RULE);

    let baseline = run_args(&["baseline", path_str(&src), "--rules", path_str(&rules)]);
    assert_eq!(baseline.status.code(), Some(0), "{}", stderr(&baseline));
    assert_eq!(stdout(&baseline).trim(), "baseline written: 2 entries");
    assert!(src.path().join(".siloscan/baseline.json").is_file());

    let rescan = run(rules.path(), src.path(), &[]);

    assert_eq!(rescan.status.code(), Some(0));
    let text = stdout(&rescan);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines, vec!["0 findings (2 baselined, 0 suppressed)"]);
}

#[test]
fn inline_ignore_line_suppresses_and_is_counted() {
    let rules = rules_dir(SUPPRESSIBLE_RULE);
    let src = src_dir(&[(
        "s.rs",
        "let a = needle; // siloscan-ignore-line: sup.hit\nlet b = needle;\n",
    )]);

    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec![
            "s.rs:2:9 error sup.hit needle found",
            "1 findings (0 baselined, 1 suppressed)",
        ]
    );
}

#[test]
fn sarif_format_parses_with_schema_and_results() {
    let (rules, src) = fixture(MATCHING_RULE);
    let output = run(
        rules.path(),
        src.path(),
        &["--format", "sarif", "--no-default-rules"],
    );

    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    let value: Value = siloscan_core::serde_json::from_str(&text).expect("stdout should be JSON");

    assert_eq!(
        value["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(value["version"], "2.1.0");

    let run_value = &value["runs"][0];
    assert_eq!(run_value["tool"]["driver"]["name"], "siloscan");
    let driver_rules = run_value["tool"]["driver"]["rules"]
        .as_array()
        .expect("driver rules array");
    assert_eq!(driver_rules.len(), 1);
    assert_eq!(driver_rules[0]["id"], "test.needle");

    let results = run_value["results"].as_array().expect("results array");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["ruleId"], "test.needle");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "a.rs"
    );
    assert_eq!(
        results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "z.rs"
    );
}

#[test]
fn test_subcommand_passes_on_a_matching_fixture() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[("a.rs", "// siloscan-expect: test.needle\nlet x = needle;\n")]);

    let output = run_args(&[
        "test",
        path_str(&src),
        "--rules",
        path_str(&rules),
        "--no-default-rules",
    ]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "1 matched, 0 missing, 0 unexpected");
}

#[test]
fn test_subcommand_fails_on_a_missing_expectation() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[("a.rs", "// siloscan-expect: test.needle\nlet x = 1;\n")]);

    let output = run_args(&[
        "test",
        path_str(&src),
        "--rules",
        path_str(&rules),
        "--no-default-rules",
    ]);

    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec![
            "missing: a.rs:2 test.needle",
            "0 matched, 1 missing, 0 unexpected",
        ]
    );
}

#[test]
fn no_default_rules_without_rule_dirs_scans_with_zero_rules() {
    let src = src_dir(&[("a.rs", "needle\ntoken = \"aG7xQ2vT9pL4zR1b\"\n")]);

    let output = run_args(&[path_str(&src), "--no-default-rules"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).is_empty(), "stdout: {}", stdout(&output));
}

#[test]
fn ast_rule_reports_the_report_capture_position() {
    let (rules, src) = ast_fixture();
    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines, vec!["src/main.rs:3:5 error ast.dbg leftover dbg"]);
}

#[test]
fn warm_cache_reproduces_the_cold_output_byte_for_byte() {
    let (rules, src) = ast_fixture();
    assert!(cache_entries(src.path()).is_empty());

    let cold = run(rules.path(), src.path(), &["--no-default-rules"]);
    assert_eq!(cold.status.code(), Some(1), "{}", stderr(&cold));

    let entries = cache_entries(src.path());
    assert!(!entries.is_empty(), "cold run should populate the cache");
    assert!(
        entries
            .iter()
            .all(|path| path.extension().is_some_and(|ext| ext == "json")),
        "unexpected cache files: {entries:?}"
    );

    let warm = run(rules.path(), src.path(), &["--no-default-rules"]);
    assert_eq!(warm.status.code(), cold.status.code());
    assert_eq!(warm.stdout, cold.stdout);
    // A warm run reads what it already wrote, so the entry set is unchanged.
    assert_eq!(cache_entries(src.path()), entries);
}

#[test]
fn no_cache_produces_identical_output_and_writes_no_entries() {
    let rules = rules_dir(AST_DBG_RULE);
    let cached_src = ast_src();
    let uncached_src = ast_src();

    let cached = run(rules.path(), cached_src.path(), &["--no-default-rules"]);
    let uncached = run(
        rules.path(),
        uncached_src.path(),
        &["--no-default-rules", "--no-cache"],
    );

    assert_eq!(uncached.status.code(), cached.status.code());
    assert_eq!(uncached.stdout, cached.stdout);
    assert!(!cache_entries(cached_src.path()).is_empty());
    assert!(cache_entries(uncached_src.path()).is_empty());
    assert!(!uncached_src.path().join(".siloscan/cache").exists());
}

#[test]
fn editing_a_scanned_file_invalidates_its_cached_entry() {
    let (rules, src) = ast_fixture();

    let first = run(rules.path(), src.path(), &["--no-default-rules"]);
    assert_eq!(
        stdout(&first).lines().collect::<Vec<_>>(),
        vec!["src/main.rs:3:5 error ast.dbg leftover dbg"]
    );
    let before = cache_entries(src.path());

    write(
        src.path(),
        "src/main.rs",
        "fn main() {\n    let x = 1;\n    let y = 2;\n    dbg!(x + y);\n}\n",
    );

    let second = run(rules.path(), src.path(), &["--no-default-rules"]);
    assert_eq!(second.status.code(), Some(1), "{}", stderr(&second));
    assert_eq!(
        stdout(&second).lines().collect::<Vec<_>>(),
        vec!["src/main.rs:4:5 error ast.dbg leftover dbg"]
    );
    assert!(
        cache_entries(src.path()).len() > before.len(),
        "edited content should be a miss and add an entry"
    );
}

#[test]
fn boundary_rule_reports_the_denied_import_and_leaves_same_silo_imports_alone() {
    let rules = rules_dir(BOUNDARY_RULE);
    let src = boundary_src();

    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec!["src/api/handler.js:1:15 error arch.api-db api must not import db"]
    );
}

#[test]
fn a_boundary_rule_without_a_config_exits_two() {
    let rules = rules_dir(BOUNDARY_RULE);
    let src = src_dir(&[
        ("src/api/handler.js", "import x from '../db/client';\n"),
        ("src/db/client.js", "export const x = 1;\n"),
    ]);

    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(2));
    let text = stderr(&output);
    assert!(text.contains("arch.api-db"), "stderr: {text}");
    assert!(text.contains("siloscan.toml"), "stderr: {text}");
    assert!(stdout(&output).is_empty(), "stdout: {}", stdout(&output));
}

#[test]
fn coverage_rule_reports_a_file_below_the_threshold() {
    let rules = rules_dir(COVERAGE_RULE);
    let src = coverage_src();
    let report = tempfile::tempdir().unwrap();
    write(report.path(), "lcov.info", LCOV);

    let output = run(
        rules.path(),
        src.path(),
        &[
            "--no-default-rules",
            "--coverage-report",
            report
                .path()
                .join("lcov.info")
                .to_str()
                .expect("temp path should be UTF-8"),
        ],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec!["src/low.rs:1:1 error cov.min line coverage below threshold"]
    );
}

#[test]
fn coverage_rules_are_inert_without_a_report() {
    let rules = rules_dir(COVERAGE_RULE);
    let src = coverage_src();

    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).is_empty(), "stdout: {}", stdout(&output));
}

/// A consumer that exits early (`siloscan | head`) closes the read end of the
/// pipe. The output must exceed the pipe buffer so the write actually hits
/// EPIPE, which must not turn the exit code into a panic.
#[test]
fn closed_stdout_keeps_the_exit_code_contract() {
    let rules = rules_dir(MATCHING_RULE);
    let body = "needle\n".repeat(20_000);
    let src = src_dir(&[("big.rs", body.as_str())]);

    let mut child = Command::new(env!("CARGO_BIN_EXE_siloscan"))
        .arg(src.path())
        .arg("--rules")
        .arg(rules.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("siloscan binary should run");
    drop(child.stdout.take());

    let status = child.wait().expect("child should exit");
    assert_eq!(status.code(), Some(1));
}
