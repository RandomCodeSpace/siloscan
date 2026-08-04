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

/// A rule whose message is a terminal escape sequence: `ESC [ 2 K` erases the
/// line the cursor sits on and `\r` returns to its start, so a report line
/// written raw overwrites itself with whatever follows. A repository reaches
/// this by pointing `rules` in its own `siloscan.toml` at a rule file it ships.
const ESC_MESSAGE_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.needle\n",
    "    severity: error\n",
    "    message: \"\\e[2K\\rscan complete: 0 findings\"\n",
    "    regex:\n",
    "      pattern: 'needle'\n",
);

/// The second vector, and the one needing no config at all: a file name. Any
/// byte but `/` and NUL is legal in one, so the escape arrives through the
/// walker without the repository configuring anything.
const ESC_PATH: &str = "ev\u{1b}[2Kil.js";

/// The fingerprint `siloscan` 1.1.1 produced for the finding in [`ESC_PATH`],
/// recorded before the terminal escaping existed. Escaping is a rendering
/// concern, so this value may not move: a baseline written by an older release
/// has to keep covering the same finding.
const ESC_FINGERPRINT: &str = "a5421000a7dd76b51bd5b139caaf6746668891ada868f7b47d0437039dea245a";

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

/// Every cache entry under the scan root's cache directory, sorted. Empty when
/// the directory does not exist.
///
/// The prune stamp is not an entry and is filtered out: it is bookkeeping about
/// which build last swept the directory, and it appears or not depending on
/// whether the run had a directory to write it into. Tests that care about it
/// look for it by name.
fn cache_entries(src: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "json") {
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

/// [`run_args`] with the process started inside `cwd`, so a test can tell a scan
/// of the named tree from a scan of the working directory.
fn run_args_in(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_siloscan"))
        .current_dir(cwd)
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

/// Human stdout without the metrics summary every scan ends with, so the
/// assertions below pin the findings listing alone.
fn report_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| !line.starts_with("metrics: "))
        .collect()
}

#[test]
fn findings_exit_one_in_canonical_order() {
    let (rules, src) = fixture(MATCHING_RULE);
    let output = run(rules.path(), src.path(), &[]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines = report_lines(&stdout);
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
    // No findings, so the metrics summary is the whole of human output.
    let text = stdout(&output);
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        vec!["metrics: 3 lines, 3 code lines, 0 duplicated lines, 0.0% duplication"]
    );
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
    let lines = report_lines(&text);
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
    let lines = report_lines(&text);
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
    let lines = report_lines(&text);
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
    let lines = report_lines(&text);
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
    let text = stdout(&output);
    assert!(report_lines(&text).is_empty(), "stdout: {text}");
}

#[test]
fn ast_rule_reports_the_report_capture_position() {
    let (rules, src) = ast_fixture();
    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    let lines = report_lines(&text);
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
        report_lines(&stdout(&first)),
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
        report_lines(&stdout(&second)),
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
    let lines = report_lines(&text);
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
    let lines = report_lines(&text);
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
    let text = stdout(&output);
    assert!(report_lines(&text).is_empty(), "stdout: {text}");
}

/// A repository holding one matching file and one clean one, so a scan of
/// either file alone is the whole of the scan.
fn single_file_src() -> TempDir {
    src_dir(&[
        ("app.js", "const a = needle;\n"),
        ("clean.js", "const b = 1;\n"),
    ])
}

/// Same arguments as [`run`], with the process started inside `cwd` so the scan
/// path may be relative to it.
fn run_in(cwd: &Path, rules: &Path, scan_path: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_siloscan"))
        .current_dir(cwd)
        .arg(scan_path)
        .arg("--rules")
        .arg(rules)
        .args(extra)
        .output()
        .expect("siloscan binary should run")
}

#[test]
fn a_single_file_scan_root_reports_the_file_by_name() {
    let rules = rules_dir(MATCHING_RULE);
    let src = single_file_src();

    let absolute = run(
        rules.path(),
        &src.path().join("app.js"),
        &["--no-default-rules"],
    );

    assert_eq!(absolute.status.code(), Some(1), "{}", stderr(&absolute));
    assert_eq!(
        report_lines(&stdout(&absolute)),
        vec!["app.js:1:11 error test.needle needle found"]
    );

    // The same file named relative to the directory holding it: same report,
    // same exit code, and no `.siloscan` below the file.
    let relative = run_in(src.path(), rules.path(), "app.js", &["--no-default-rules"]);

    assert_eq!(relative.status.code(), Some(1), "{}", stderr(&relative));
    assert_eq!(stdout(&relative), stdout(&absolute));
    assert!(src.path().join(".siloscan/cache").is_dir());
}

#[test]
fn a_clean_single_file_scan_root_exits_zero() {
    let rules = rules_dir(MATCHING_RULE);
    let src = single_file_src();

    let output = run(
        rules.path(),
        &src.path().join("clean.js"),
        &["--no-default-rules"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(report_lines(&text).is_empty(), "stdout: {text}");

    // And with the cache off, which reaches the same state directory.
    let uncached = run(
        rules.path(),
        &src.path().join("clean.js"),
        &["--no-default-rules", "--no-cache"],
    );
    assert_eq!(uncached.status.code(), Some(0), "{}", stderr(&uncached));
    assert_eq!(uncached.stdout, output.stdout);
}

#[test]
fn a_baseline_taken_on_a_file_root_lands_beside_it_and_is_honoured() {
    let rules = rules_dir(MATCHING_RULE);
    let src = single_file_src();
    let file = src.path().join("app.js");
    let file_str = file.to_str().expect("temp path should be UTF-8");

    let baseline = run_args(&[
        "baseline",
        file_str,
        "--rules",
        path_str(&rules),
        "--no-default-rules",
    ]);

    assert_eq!(baseline.status.code(), Some(0), "{}", stderr(&baseline));
    assert_eq!(stdout(&baseline).trim(), "baseline written: 1 entries");
    assert!(src.path().join(".siloscan/baseline.json").is_file());

    let rescan = run(rules.path(), &file, &["--no-default-rules"]);

    assert_eq!(rescan.status.code(), Some(0), "{}", stderr(&rescan));
    assert_eq!(
        report_lines(&stdout(&rescan)),
        vec!["0 findings (1 baselined, 0 suppressed)"]
    );
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

/// Hidden files are scan input - `.env` and `.github/workflows/` are where
/// secrets live - while version-control internals are not. Asserted end to end
/// because the exclusion is by directory name at any depth, which a unit test
/// of the walker alone cannot show reaching a report.
#[test]
fn hidden_files_are_scanned_and_vcs_internals_are_not() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[
        (".env", "SECRET=needle\n"),
        (".github/workflows/ci.yml", "run: needle\n"),
        (".git/config", "needle\n"),
        ("src/a.rs", "let x = 1;\n"),
    ]);

    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(
        report_lines(&stdout(&output)),
        vec![
            ".env:1:8 error test.needle needle found",
            ".github/workflows/ci.yml:1:6 error test.needle needle found",
        ]
    );
}

/// The state directory the first run creates - `.siloscan/cache` and the
/// `.gitignore` beside it - is scan input to nobody, so a warm run reports
/// exactly what the cold one did. Hidden files are in the tree because they are
/// what made the state directory visible to the walker in the first place.
#[test]
fn a_warm_run_over_a_hidden_tree_is_byte_identical_to_the_cold_one() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[(".env", "SECRET=needle\n"), ("src/a.rs", "let x = 1;\n")]);

    let cold = run(
        rules.path(),
        src.path(),
        &["--no-default-rules", "--format", "json"],
    );
    assert!(src.path().join(".siloscan/cache").is_dir());

    let warm = run(
        rules.path(),
        src.path(),
        &["--no-default-rules", "--format", "json"],
    );

    assert_eq!(cold.status.code(), Some(1), "{}", stderr(&cold));
    assert_eq!(warm.status.code(), cold.status.code());
    assert_eq!(stdout(&warm), stdout(&cold));

    let report: Value = siloscan_core::serde_json::from_str(&stdout(&warm)).expect("json report");
    let files = report["metrics"]["files"]
        .as_object()
        .expect("metrics files");
    let mut keys: Vec<&str> = files.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec![".env", "src/a.rs"]);
}

/// One file whose name carries an escape sequence, matched by a rule whose
/// message carries another: the two ways a scanned repository reaches the
/// operator's terminal.
fn esc_fixture() -> (TempDir, TempDir) {
    (
        rules_dir(ESC_MESSAGE_RULE),
        src_dir(&[(ESC_PATH, "const a = needle;\n")]),
    )
}

/// Written raw, `ESC [ 2 K` followed by a carriage return erases the report
/// line and rewrites it, so a repository holding a live credential could render
/// as a clean scan. The bytes are rendered instead, and the finding still shows.
#[test]
fn no_escape_byte_from_a_scanned_repository_reaches_the_terminal() {
    let (rules, src) = esc_fixture();

    let output = run(rules.path(), src.path(), &["--no-default-rules"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        !output.stdout.contains(&0x1b),
        "stdout: {:?}",
        stdout(&output)
    );
    assert!(
        !output.stderr.contains(&0x1b),
        "stderr: {:?}",
        stderr(&output)
    );
    assert_eq!(
        report_lines(&stdout(&output)),
        vec![concat!(
            "ev\\x1b[2Kil.js:1:11 error test.needle ",
            "\\x1b[2K\\x0dscan complete: 0 findings"
        )]
    );
}

/// Escaping is a rendering concern and stops at the human format: the JSON
/// report still carries the bytes, and the fingerprint an older release wrote
/// into a baseline still identifies the same finding.
#[test]
fn escaping_leaves_the_json_report_and_its_fingerprints_where_they_were() {
    let (rules, src) = esc_fixture();

    let output = run(
        rules.path(),
        src.path(),
        &["--no-default-rules", "--format", "json"],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let value: Value =
        siloscan_core::serde_json::from_str(&stdout(&output)).expect("stdout should be JSON");

    let finding = &value["findings"][0];
    assert_eq!(finding["path"], ESC_PATH);
    assert_eq!(finding["message"], "\u{1b}[2K\rscan complete: 0 findings");
    assert_eq!(finding["fingerprint"], ESC_FINGERPRINT);

    // JSON escapes C0 controls per RFC 8259, so the structured report carries
    // the bytes without a terminal reading one.
    assert!(!output.stdout.contains(&0x1b));
}

#[test]
fn a_bare_invocation_scans_the_working_directory() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[("a.rs", "needle\n")]);

    let output = run_args_in(
        src.path(),
        &["--rules", path_str(&rules), "--no-default-rules"],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(
        report_lines(&stdout(&output)),
        vec!["a.rs:1:1 error test.needle needle found"]
    );
}

#[test]
fn a_scan_path_scans_that_tree_and_not_the_working_directory() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[("a.rs", "needle\n")]);
    let elsewhere = src_dir(&[("other.rs", "needle\n")]);

    let output = run_args_in(
        elsewhere.path(),
        &[
            path_str(&src),
            "--rules",
            path_str(&rules),
            "--no-default-rules",
        ],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(
        report_lines(&stdout(&output)),
        vec!["a.rs:1:1 error test.needle needle found"]
    );
}

#[test]
fn baseline_writes_into_the_tree_it_was_given_and_not_the_working_directory() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[("a.rs", "needle\n")]);
    let elsewhere = src_dir(&[("other.rs", "needle\n")]);

    let output = run_args_in(
        elsewhere.path(),
        &[
            "baseline",
            path_str(&src),
            "--rules",
            path_str(&rules),
            "--no-default-rules",
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "baseline written: 1 entries");
    assert!(src.path().join(".siloscan/baseline.json").is_file());
    assert!(!elsewhere.path().join(".siloscan/baseline.json").exists());
}

#[test]
fn test_checks_the_tree_it_was_given_and_not_the_working_directory() {
    let rules = rules_dir(MATCHING_RULE);
    let fixture = src_dir(&[("a.rs", "// siloscan-expect: test.needle\nlet x = needle;\n")]);
    let elsewhere = src_dir(&[("other.rs", "needle\n")]);

    let output = run_args_in(
        elsewhere.path(),
        &[
            "test",
            path_str(&fixture),
            "--rules",
            path_str(&rules),
            "--no-default-rules",
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "1 matched, 0 missing, 0 unexpected");
}

/// `siloscan <PATH> baseline` used to accept the working directory's findings
/// as debt: the top-level positional took PATH and `BaselineArgs::path` kept its
/// default of `.`. It is now refused, so no tree is baselined by accident.
#[test]
fn a_path_before_baseline_is_refused_and_baselines_nothing() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[("a.rs", "needle\n")]);
    let elsewhere = src_dir(&[("other.rs", "needle\n")]);

    let output = run_args_in(
        elsewhere.path(),
        &[
            path_str(&src),
            "baseline",
            "--rules",
            path_str(&rules),
            "--no-default-rules",
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    let text = stderr(&output);
    assert!(text.contains("siloscan baseline <PATH>"), "stderr: {text}");
    assert!(!src.path().join(".siloscan/baseline.json").exists());
    assert!(!elsewhere.path().join(".siloscan/baseline.json").exists());
    assert!(stdout(&output).is_empty(), "stdout: {}", stdout(&output));
}

#[test]
fn a_path_before_test_is_refused() {
    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[("a.rs", "needle\n")]);
    let fixture = src_dir(&[("a.rs", "// siloscan-expect: test.needle\nlet x = needle;\n")]);

    let output = run_args(&[
        path_str(&src),
        "test",
        path_str(&fixture),
        "--rules",
        path_str(&rules),
        "--no-default-rules",
    ]);

    assert_eq!(output.status.code(), Some(2));
    let text = stderr(&output);
    assert!(text.contains("siloscan test <PATH>"), "stderr: {text}");
    assert!(stdout(&output).is_empty(), "stdout: {}", stdout(&output));
}

/// The usage line used to read `siloscan [OPTIONS] [PATH] [COMMAND]`, which
/// documented the refused order as a supported one.
#[test]
fn help_documents_only_the_forms_that_work() {
    let output = run_args(&["--help"]);

    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("siloscan [OPTIONS] [PATH]"), "stdout: {text}");
    assert!(text.contains("siloscan <COMMAND>"), "stdout: {text}");
    assert!(!text.contains("[PATH] [COMMAND]"), "stdout: {text}");
}

/// An asset-heavy repository must not bury stderr under one warning per file.
///
/// The record is not dropped - every skipped file is still in the JSON report,
/// which is the point of reporting them at all - but the human channel names a
/// handful and counts the rest. 200 PNGs was 200 lines; it is now 11.
#[test]
fn a_binary_heavy_tree_summarises_its_skip_warnings() {
    const BINARIES: usize = 200;

    let rules = rules_dir(MATCHING_RULE);
    let src = src_dir(&[("a.rs", "needle\n")]);
    for index in 0..BINARIES {
        fs::write(
            src.path().join(format!("asset{index:03}.png")),
            b"\x89PNG\r\n\x1a\n\0binary",
        )
        .unwrap();
    }

    let output = run(rules.path(), src.path(), &["--no-default-rules"]);
    let text = stderr(&output);
    let warnings = text
        .lines()
        .filter(|line| line.starts_with("warning: skipped "))
        .count();

    assert!(
        warnings <= 10,
        "{warnings} individual warnings for {BINARIES} binaries:\n{text}"
    );
    assert!(
        text.contains(&format!("and {} more files skipped", BINARIES - warnings)),
        "the remainder must be counted, not dropped:\n{text}"
    );

    // The sample is the head of a path-sorted list, so it is the same on every
    // run of the same tree.
    let again = stderr(&run(rules.path(), src.path(), &["--no-default-rules"]));
    assert_eq!(again, text, "the summary must be deterministic");
    assert!(text.contains("asset000.png"), "{text}");

    // The full list is still machine-readable.
    let json = run(
        rules.path(),
        src.path(),
        &["--no-default-rules", "--format", "json"],
    );
    let report: Value = siloscan_core::serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(
        report["skipped"].as_array().unwrap().len(),
        BINARIES,
        "the JSON record is what the warnings summarise"
    );
}
