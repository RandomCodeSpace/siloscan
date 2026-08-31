use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};

use siloscan_tui::{ReviewSession, WalkPolicy};

fn normalize_line_endings(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .expect("session output should be UTF-8")
        .replace("\r\n", "\n")
}

fn standalone(args: Vec<OsString>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_siloscan-tui"))
        .args(args)
        .output()
        .expect("standalone TUI should run")
}

fn assert_same_setup_error(session: ReviewSession, args: Vec<OsString>) {
    let linked = siloscan_tui::run(session).expect_err("setup should fail before terminal access");
    let standalone = standalone(args);

    assert_eq!(standalone.status.code(), Some(2));
    assert!(standalone.stdout.is_empty());
    assert_eq!(
        normalize_line_endings(&standalone.stderr),
        format!("error: {linked}\n")
    );
}

fn assert_standalone_surface(arg: &str, expected: &str) {
    let output = standalone(vec![OsString::from(arg)]);

    assert!(output.status.success(), "{arg} should exit successfully");
    assert!(output.stderr.is_empty(), "{arg} should not write stderr");
    assert_eq!(normalize_line_endings(&output.stdout), expected);
}

#[test]
fn library_entry_matches_standalone_live_setup_errors() {
    let dir = tempfile::tempdir().expect("temporary directory should be available");
    let missing = dir.path().join("missing-project");

    assert_same_setup_error(
        ReviewSession::Live {
            path: missing.clone(),
            rules: Vec::new(),
            no_default_rules: false,
            config: None,
            walk: WalkPolicy::default(),
        },
        vec![missing.into_os_string()],
    );
}

#[test]
fn library_entry_matches_standalone_snapshot_setup_errors() {
    let dir = tempfile::tempdir().expect("temporary directory should be available");
    let missing = dir.path().join("missing-report.json");

    assert_same_setup_error(
        ReviewSession::SavedReport {
            report: missing.clone(),
            source_base: PathBuf::from("."),
            config: None,
        },
        vec![OsString::from("--report"), missing.into_os_string()],
    );
}

#[test]
fn standalone_surface_preserves_help() {
    assert_standalone_surface(
        "--help",
        include_str!("../../../research/oracle-v1.5.1/golden/siloscan-tui-help.stdout"),
    );
}

#[test]
fn standalone_surface_preserves_version() {
    assert_standalone_surface(
        "--version",
        include_str!("../../../research/oracle-v1.5.1/golden/siloscan-tui-version.stdout"),
    );
}
