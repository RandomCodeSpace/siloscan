//! The command surface both binaries present: which invocations are automatic,
//! what each persistence control does, where the notices go, and what `review`
//! opens.
//!
//! Every case runs through `siloscan` and `ss`, because the two are one
//! implementation under two names and a difference between them is a bug the
//! user meets rather than a detail.
//!
//! The successful TUI paths are deliberately absent. Opening a terminal session
//! from a test either fails for the wrong reason or blocks on a real terminal;
//! what belongs here is everything `review` decides before it hands over.
//!
//! A saved report is located by the `Report:` line the run printed, never by
//! searching the directory a test set `XDG_STATE_HOME` to: only Linux resolves
//! its state root from the environment, so that search would find nothing on
//! macOS and Windows whether or not a report was written. `v2_persistence` has
//! the long version of that argument, and `common::isolation` has the rule for
//! which directories a child is pointed at on which platform.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use siloscan_core::serde_json::Value;
use tempfile::TempDir;

#[path = "common/isolation.rs"]
mod isolation;

const BINARIES: [(&str, &str); 2] = [
    ("siloscan", env!("CARGO_BIN_EXE_siloscan")),
    ("ss", env!("CARGO_BIN_EXE_ss")),
];

const MATCHING_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.needle\n",
    "    severity: error\n",
    "    message: needle found\n",
    "    regex:\n",
    "      pattern: 'needle'\n",
);

/// A finding that `--fail-on warning` catches and `--min-severity error` hides:
/// the pair that separates the gate from the listing.
const WARNING_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.hay\n",
    "    severity: warning\n",
    "    message: hay found\n",
    "    regex:\n",
    "      pattern: 'hay'\n",
);

struct Host {
    _dir: TempDir,
    state: PathBuf,
    home: PathBuf,
    cache: PathBuf,
    tree: PathBuf,
    rules: PathBuf,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = dir.path().join("state");
        let home = dir.path().join("home");
        let cache = dir.path().join("cache");
        let tree = dir.path().join("tree");
        let rules = dir.path().join("rules");
        for path in [&state, &home, &cache, &tree, &rules] {
            fs::create_dir_all(path).expect("fixture directory");
        }
        fs::write(rules.join("needle.yaml"), MATCHING_RULE).expect("rule file");
        fs::write(tree.join("a.rs"), "let x = 1;\n").expect("source file");
        Self {
            _dir: dir,
            state,
            home,
            cache,
            tree,
            rules,
        }
    }

    fn run(&self, binary: &str, args: &[&str]) -> Output {
        self.run_in(binary, &self.tree, args)
    }

    fn run_in(&self, binary: &str, cwd: &Path, args: &[&str]) -> Output {
        let mut command = Command::new(binary);
        command.current_dir(cwd);
        isolation::isolate(&mut command, &self.cache, &self.state, &self.home)
            .args(args)
            .output()
            .expect("binary should run")
    }

    fn rules_arg(&self) -> String {
        self.rules.to_str().expect("utf-8 path").to_owned()
    }

    fn write_rule(&self, name: &str, body: &str) {
        fs::write(self.rules.join(name), body).expect("rule file");
    }
}

/// The report a run says it wrote: the `Report:` line, from stdout for human
/// output and from stderr for machine output.
fn saved_line(output: &Output) -> Option<PathBuf> {
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        if let Some(path) = text.lines().find_map(|line| line.strip_prefix("Report: ")) {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// The report this run wrote, asserted to be there.
fn saved(output: &Output) -> PathBuf {
    let report = saved_line(output).unwrap_or_else(|| {
        panic!(
            "the run reported no saved report\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert!(report.is_file(), "{}", report.display());
    report
}

/// Assert that this run saved nothing: no `Report:` line anywhere, and on the
/// one host whose state root the test chose, nothing in it.
fn assert_saved_nothing(case: &str, output: &Output, state: &Path) {
    assert_eq!(
        saved_line(output),
        None,
        "{case}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if cfg!(target_os = "linux") {
        let mut found = Vec::new();
        collect(state, &mut found);
        assert!(found.is_empty(), "{case}: {found:?}");
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be UTF-8")
}

// ---------------------------------------------------------------------------
// Automatic and explicit modes
// ---------------------------------------------------------------------------

/// A bare invocation is the new default journey: it saves, and it says so.
#[test]
fn a_bare_invocation_saves_and_names_its_own_review_command() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &[]);

        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        let report = saved(&output);
        let text = stdout(&output);
        assert!(
            text.contains(&format!("Report: {}", report.display())),
            "{name}: the path is on stdout for human output: {text}"
        );
        assert!(
            text.contains(&format!("Review: {name} review\n")),
            "{name}: the hint must name the binary that was invoked: {text}"
        );
        assert!(text.contains("setup: "), "{name}: {text}");
        assert!(text.contains("capabilities: "), "{name}: {text}");
    }
}

/// Any supplied `PATH` keeps the v1 meaning, including `.`, which names the
/// same directory a bare run scans and is a different invocation.
#[test]
fn an_explicit_dot_is_not_a_bare_invocation() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &["."]);

        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        assert_saved_nothing(name, &output, &host.state);
        assert!(!stdout(&output).contains("setup: "), "{name}");
    }
}

/// A supplied option whose value equals its default is still a supplied option.
/// Comparing values to defaults would make `--fail-on error` a bare run.
#[test]
fn an_option_set_to_its_own_default_is_still_an_explicit_scan() {
    for (name, binary) in BINARIES {
        for option in [
            vec!["--fail-on", "error"],
            vec!["--min-severity", "info"],
            vec!["--format", "human"],
        ] {
            let host = Host::new();

            let output = host.run(binary, &option);

            assert_eq!(
                output.status.code(),
                Some(0),
                "{name} {option:?}: {}",
                stderr(&output)
            );
            assert_saved_nothing(&format!("{name} {option:?}"), &output, &host.state);
            assert!(
                !stdout(&output).contains("setup: "),
                "{name} {option:?}: {}",
                stdout(&output)
            );
        }
    }
}

/// A persistence control is not a scan option, so it cannot turn a bare
/// invocation into an explicit one.
#[test]
fn a_persistence_control_does_not_leave_automatic_mode() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &["--no-save"]);

        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        assert_saved_nothing(name, &output, &host.state);
        // Still the automatic journey: the summary is there, the publication
        // lines are not.
        assert!(stdout(&output).contains("setup: "), "{name}");
    }
}

// ---------------------------------------------------------------------------
// Save controls
// ---------------------------------------------------------------------------

/// `--save` opts an explicit scan into the requested scope's slot, without
/// changing what the scan does.
#[test]
fn save_opts_an_explicit_scan_into_its_scopes_slot() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        let rules = host.rules_arg();

        let output = host.run(
            binary,
            &[".", "--rules", &rules, "--no-default-rules", "--save"],
        );

        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        let here = saved(&output);
        let text = stdout(&output);
        assert!(text.contains("Report: "), "{name}: {text}");
        // `.` is what `review` opens by default, so the hint stays short.
        assert!(
            text.contains(&format!("Review: {name} review\n")),
            "{name}: {text}"
        );
        // The scan itself is unchanged: no summary lines on an explicit run.
        assert!(!text.contains("setup: "), "{name}: {text}");

        // A scope that is not the working directory has to be named, or the
        // hint would open a different report than the one just written.
        let nested = host.tree.join("modules/api");
        fs::create_dir_all(&nested).expect("nested scope");
        fs::write(nested.join("b.rs"), "let y = 2;\n").expect("source file");
        let output = host.run(
            binary,
            &[
                "modules/api",
                "--rules",
                &rules,
                "--no-default-rules",
                "--save",
            ],
        );
        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        assert!(
            stdout(&output).contains(&format!("Review: {name} review modules/api")),
            "{name}: {}",
            stdout(&output)
        );
        assert_ne!(saved(&output), here, "{name}: two scopes, two slots");
    }
}

/// `--output` writes one named file and leaves the saved slot alone, so the
/// review hint points at the file rather than at a report nobody updated.
#[test]
fn output_writes_one_named_file_and_does_not_touch_the_saved_slot() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        let bare = host.run(binary, &[]);
        let slot = saved(&bare);
        let before = fs::read(&slot).expect("saved report");

        let destination = host.tree.join("report.json");
        let destination_arg = destination.to_str().expect("utf-8 path").to_owned();
        let output = host.run(binary, &["--output", &destination_arg]);

        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        assert_eq!(fs::read(&slot).expect("saved report"), before, "{name}");
        let document: Value =
            siloscan_core::serde_json::from_slice(&fs::read(&destination).expect("named report"))
                .expect("canonical JSON");
        assert_eq!(document["report_kind"], "scan", "{name}");
        assert!(
            stdout(&output).contains(&format!("Review: {name} review --report ")),
            "{name}: {}",
            stdout(&output)
        );
    }
}

/// `--output -` would give the flag a second, unrelated meaning; machine stdout
/// already has two formats of its own.
#[test]
fn output_does_not_accept_a_dash() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &["--output", "-"]);

        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(stdout(&output).is_empty(), "{name}: {}", stdout(&output));
        assert!(
            stderr(&output).contains("--format"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

// ---------------------------------------------------------------------------
// Stream routing
// ---------------------------------------------------------------------------

/// Machine stdout stays one parseable document. The publication notices go to
/// stderr, where a consumer is not reading a report.
#[test]
fn machine_stdout_carries_no_publication_lines() {
    for (name, binary) in BINARIES {
        for format in ["json", "sarif"] {
            let host = Host::new();

            let output = host.run(binary, &["--format", format, "--save"]);

            assert_eq!(
                output.status.code(),
                Some(0),
                "{name} {format}: {}",
                stderr(&output)
            );
            let text = stdout(&output);
            assert!(!text.contains("Report: "), "{name} {format}: {text}");
            assert!(!text.contains("setup: "), "{name} {format}: {text}");
            let parsed: Result<Value, _> = siloscan_core::serde_json::from_str(&text);
            assert!(parsed.is_ok(), "{name} {format}: {text}");

            let notices = stderr(&output);
            assert!(notices.contains("Report: "), "{name} {format}: {notices}");
            assert!(notices.contains("Review: "), "{name} {format}: {notices}");
        }
    }
}

/// A JSON scan carries the resolved metadata whether or not it is saved: the
/// stdout document and the saved one are the same document.
#[test]
fn json_stdout_carries_the_resolved_metadata_without_saving() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &[".", "--format", "json"]);

        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        assert_saved_nothing(name, &output, &host.state);
        let document: Value =
            siloscan_core::serde_json::from_str(&stdout(&output)).expect("JSON stdout");
        assert_eq!(document["report_kind"], "scan", "{name}");
        assert!(document["scope"]["identity"].is_string(), "{name}");
        assert_eq!(document["outcome"]["fail_on"], "error", "{name}");
        assert_eq!(document["outcome"]["threshold_reached"], false, "{name}");
        assert!(document["setup"]["capabilities"].is_array(), "{name}");
    }
}

/// A report holds what the output filter left, and an outcome decided before it.
///
/// The two together are what stops a filtered run reading as a clean one: the
/// only finding here is a warning, `--fail-on warning` fails on it, and
/// `--min-severity error` removes it from every list. The report that reaches
/// stdout and the file therefore has no findings at all and still says the
/// threshold was reached.
#[test]
fn a_filtered_report_keeps_the_outcome_that_was_decided_before_filtering() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        host.write_rule("hay.yaml", WARNING_RULE);
        fs::write(host.tree.join("a.rs"), "let hay = 1;\n").expect("source file");
        let rules = host.rules_arg();

        let output = host.run(
            binary,
            &[
                ".",
                "--rules",
                &rules,
                "--no-default-rules",
                "--format",
                "json",
                "--fail-on",
                "warning",
                "--min-severity",
                "error",
                "--save",
            ],
        );

        assert_eq!(output.status.code(), Some(1), "{name}: {}", stderr(&output));
        let report = saved(&output);
        let printed: Value =
            siloscan_core::serde_json::from_str(&stdout(&output)).expect("JSON stdout");
        let written: Value =
            siloscan_core::serde_json::from_slice(&fs::read(&report).expect("saved report"))
                .expect("saved JSON");

        for (stream, document) in [("stdout", &printed), ("saved", &written)] {
            assert_eq!(
                document["findings"].as_array().map(Vec::len),
                Some(0),
                "{name} {stream}: the filter took the only finding"
            );
            assert_eq!(document["outcome"]["fail_on"], "warning", "{name} {stream}");
            assert_eq!(
                document["outcome"]["threshold_reached"], true,
                "{name} {stream}: the gate is decided before the filter"
            );
            assert_eq!(
                document["min_severity"], "error",
                "{name} {stream}: the report records the filter it applied"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------

/// Implicit review looks in exactly one place and says so when it is empty. It
/// never falls back to another scope's report or starts a scan.
#[test]
fn review_without_a_saved_report_names_the_scope_and_the_ways_out() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &["review"]);

        assert_eq!(output.status.code(), Some(2), "{name}");
        assert_saved_nothing(
            &format!("{name}: review must not scan"),
            &output,
            &host.state,
        );
        let message = stderr(&output);
        assert!(message.contains("no saved report"), "{name}: {message}");
        assert!(message.contains(&format!("`{name}`")), "{name}: {message}");
        assert!(message.contains("--save"), "{name}: {message}");
        assert!(message.contains("--report"), "{name}: {message}");
    }
}

/// A scope that does not exist is a scope error, not a missing-report error.
#[test]
fn review_of_a_missing_scope_is_refused() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &["review", "absent"]);

        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(
            stderr(&output).contains("absent"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

/// An explicit report is opened as given: no scope is resolved, so the error
/// for an unreadable one comes from the loader.
#[test]
fn review_of_an_explicit_report_reports_the_loader_error() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        fs::write(host.tree.join("junk.json"), "not a report").expect("junk file");

        let missing = host.run(binary, &["review", "--report", "absent.json"]);
        assert_eq!(missing.status.code(), Some(2), "{name}");
        assert!(
            stderr(&missing).contains("absent.json"),
            "{name}: {}",
            stderr(&missing)
        );

        let junk = host.run(binary, &["review", "--report", "junk.json"]);
        assert_eq!(junk.status.code(), Some(2), "{name}");
        assert!(
            !stderr(&junk).contains("no saved report"),
            "{name}: an explicit report is never looked up by scope: {}",
            stderr(&junk)
        );
    }
}

/// Implicit review opens one scope's report and checks that it is that scope's.
/// A report for somewhere else in the slot is refused rather than shown, and the
/// refusal happens during setup, before the terminal is touched.
#[test]
fn implicit_review_refuses_another_scopes_report() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        let elsewhere = host.tree.join("modules/api");
        fs::create_dir_all(&elsewhere).expect("nested scope");
        fs::write(elsewhere.join("b.rs"), "let y = 2;\n").expect("source file");
        let rules = host.rules_arg();

        // The working directory's slot first, so the second one to appear is
        // the nested scope's and needs no key arithmetic to identify.
        let mine = saved(&host.run(binary, &[]));
        let theirs = saved(&host.run(
            binary,
            &[
                "modules/api",
                "--rules",
                &rules,
                "--no-default-rules",
                "--save",
            ],
        ));
        assert_ne!(mine, theirs, "{name}: two scopes, two slots");
        fs::copy(&theirs, &mine).expect("plant the other scope's report");

        let output = host.run(binary, &["review"]);

        assert_eq!(output.status.code(), Some(2), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("saved for a different scan scope"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

/// A report with no resolved metadata cannot say which scope it describes, so it
/// is never a scope's latest report however it got into the slot.
#[test]
fn implicit_review_refuses_a_marker_free_report() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let report = saved(&host.run(binary, &[]));
        let mut document: Value =
            siloscan_core::serde_json::from_slice(&fs::read(&report).expect("saved report"))
                .expect("canonical JSON");
        for marker in ["report_kind", "scope", "outcome", "setup"] {
            document
                .as_object_mut()
                .expect("object")
                .remove(marker)
                .unwrap_or_else(|| panic!("{name}: {marker} should be present"));
        }
        fs::write(
            &report,
            siloscan_core::serde_json::to_vec_pretty(&document).expect("re-serialize"),
        )
        .expect("plant the legacy report");

        let output = host.run(binary, &["review"]);

        assert_eq!(output.status.code(), Some(2), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("no resolved scan metadata"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

/// `--report` and `--live` ask for two different things, so asking for both is
/// a parse failure rather than a precedence rule.
#[test]
fn review_refuses_a_report_and_a_live_scan_together() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &["review", "--report", "r.json", "--live"]);

        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(stdout(&output).is_empty(), "{name}");
    }
}

/// A live session still validates its root before it opens anything.
#[test]
fn review_live_validates_its_root() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &["review", "--live", "absent"]);

        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(
            stderr(&output).contains("absent"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

// ---------------------------------------------------------------------------
// The ./review collision
// ---------------------------------------------------------------------------

/// `review` was a path before it was a subcommand. A repository that really has
/// one keeps being scannable.
#[test]
fn a_real_review_directory_is_scanned_rather_than_treated_as_a_subcommand() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        let review = host.tree.join("review");
        fs::create_dir(&review).expect("review directory");
        fs::write(review.join("a.rs"), "let needle = 1;\n").expect("source file");
        let rules = host.rules_arg();

        let output = host.run(binary, &["review", "--rules", &rules, "--no-default-rules"]);

        assert_eq!(output.status.code(), Some(1), "{name}: {}", stderr(&output));
        assert!(
            stdout(&output).contains("a.rs:1:5 error test.needle"),
            "{name}: {}",
            stdout(&output)
        );
    }
}

/// The collision is narrow on purpose: arguments the scan grammar cannot accept
/// mean the subcommand, whatever is on disk.
#[test]
fn review_arguments_the_scan_grammar_refuses_stay_the_subcommand() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        let review = host.tree.join("review");
        fs::create_dir(&review).expect("review directory");
        fs::write(review.join("a.rs"), "let needle = 1;\n").expect("source file");

        let output = host.run(binary, &["review", "--report", "absent.json"]);

        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(
            !stdout(&output).contains("test.needle"),
            "{name}: the subcommand must win: {}",
            stdout(&output)
        );
    }
}

/// With no such path there is nothing to collide with, and `review` is the
/// subcommand it looks like.
#[test]
fn review_is_the_subcommand_when_no_such_path_exists() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &["review"]);

        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(
            stderr(&output).contains("no saved report"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

// ---------------------------------------------------------------------------
// Embedded profiles
// ---------------------------------------------------------------------------

/// `--profiles auto` runs, and the setup report says what it found: nothing,
/// because no profile document ships yet.
///
/// The tree is Rust and the detector says so, so the empty answer is a fact
/// about the registry and not about the walk. The reason has to be the one that
/// says that; `not_configured` with no reason, or a reason blaming the request,
/// would send a reader looking in the wrong place.
#[test]
fn profiles_auto_reports_a_capability_with_nothing_available_to_select() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let output = host.run(binary, &[".", "--profiles", "auto", "--format", "json"]);

        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        let document: Value =
            siloscan_core::serde_json::from_str(&stdout(&output)).expect("JSON stdout");
        assert_eq!(document["setup"]["languages"][0], "rust", "{name}");
        let profiles = document["setup"]["capabilities"]
            .as_array()
            .expect("capabilities")
            .iter()
            .find(|capability| capability["id"] == "profiles")
            .unwrap_or_else(|| panic!("{name}: no profiles capability: {}", stdout(&output)));
        assert_eq!(profiles["status"], "not_configured", "{name}");
        assert_eq!(
            profiles["reason"], "no detected language has an embedded profile",
            "{name}"
        );
    }
}

/// `--profiles none` asks for what every scan already resolves, so it changes
/// no byte of the report.
///
/// It is still a supplied scan option: the run is explicit either way here, and
/// the setup report records `profiles` in `explicit_overrides`, which is what an
/// override list is for. What must not move is the scan.
#[test]
fn profiles_none_scans_exactly_as_the_run_without_the_flag() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let without = host.run(binary, &["."]);
        let with = host.run(binary, &[".", "--profiles", "none"]);

        assert_eq!(with.status.code(), Some(0), "{name}: {}", stderr(&with));
        assert_eq!(with.status.code(), without.status.code(), "{name}");
        assert_eq!(stdout(&with), stdout(&without), "{name}");
        assert_eq!(stderr(&with), stderr(&without), "{name}");
    }
}

/// A named profile with no document is a resolve error: exit 2, naming the
/// identity that was asked for and what was available instead.
///
/// The second run is the `--no-default-rules` interaction. That flag disables
/// every embedded document, profiles included, but the names are resolved
/// before it suppresses them, so a misspelling is refused whether or not the
/// documents were going to load. The alternative accepts it silently on one run
/// and refuses it on the next.
#[test]
fn an_unknown_profile_identity_is_refused_with_the_resolve_exit_code() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        let rules = host.rules_arg();

        for extra in [
            vec![".", "--profiles", "reliability-elixir@1"],
            vec![
                ".",
                "--profiles",
                "reliability-elixir@1",
                "--no-default-rules",
                "--rules",
                &rules,
            ],
        ] {
            let output = host.run(binary, &extra);

            assert_eq!(output.status.code(), Some(2), "{name} {extra:?}");
            let text = stderr(&output);
            assert!(
                text.contains("unknown profile: reliability-elixir@1"),
                "{name} {extra:?}: {text}"
            );
            assert!(text.contains("available: none"), "{name} {extra:?}: {text}");
        }
    }
}

/// A value that is neither word nor a usable list is refused by the parser, so
/// the scan never starts and the message says what the value should have been.
///
/// `auto,none` is the case worth pinning: passed through as identities it would
/// come back as "unknown profile: auto", which is true and sends the reader
/// looking for a document instead of at the comma they typed.
#[test]
fn a_malformed_profiles_value_is_a_usage_error() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        for value in ["", "auto,none", "reliability-rust@1,"] {
            let output = host.run(binary, &[".", "--profiles", value]);

            assert_eq!(output.status.code(), Some(2), "{name} {value:?}");
            let text = stderr(&output);
            assert!(
                text.contains(&format!("invalid value '{value}' for '--profiles")),
                "{name} {value:?}: {text}"
            );
            assert!(
                text.contains("comma-separated list of profile identities"),
                "{name} {value:?}: {text}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Help and subcommand conflicts
// ---------------------------------------------------------------------------

/// The new surface is documented under both names, and the subcommand advice
/// still names the binary that was invoked.
#[test]
fn help_documents_the_new_forms_under_both_names() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let help = host.run(binary, &["--help"]);
        assert_eq!(help.status.code(), Some(0), "{name}");
        let text = stdout(&help);
        for expected in [
            "review",
            "--save",
            "--no-save",
            "--output",
            "--profiles <auto|none|LIST>",
        ] {
            assert!(
                text.contains(expected),
                "{name}: {expected} missing:\n{text}"
            );
        }

        let review_help = host.run(binary, &["review", "--help"]);
        assert_eq!(review_help.status.code(), Some(0), "{name}");
        let text = stdout(&review_help);
        assert!(text.contains("--report"), "{name}: {text}");
        assert!(text.contains("--live"), "{name}: {text}");
    }
}

/// A scan option in front of a subcommand is still refused with the advice that
/// names the working forms; a persistence conflict is not about subcommands and
/// gets clap's own message.
#[test]
fn subcommand_advice_appears_only_for_a_subcommand_conflict() {
    for (name, binary) in BINARIES {
        let host = Host::new();

        let subcommand = host.run(binary, &["--format", "json", "baseline", "."]);
        assert_eq!(subcommand.status.code(), Some(2), "{name}");
        assert!(
            stderr(&subcommand).contains(&format!("{name} baseline <PATH>")),
            "{name}: {}",
            stderr(&subcommand)
        );

        let persistence = host.run(binary, &["--save", "--no-save"]);
        assert_eq!(persistence.status.code(), Some(2), "{name}");
        assert!(
            !stderr(&persistence).contains("A subcommand comes first"),
            "{name}: {}",
            stderr(&persistence)
        );
    }
}

/// The other subcommands never write a scan report.
#[test]
fn baseline_test_and_cache_prune_save_nothing() {
    for (name, binary) in BINARIES {
        let host = Host::new();
        let rules = host.rules_arg();

        let baseline = host.run(
            binary,
            &["baseline", ".", "--rules", &rules, "--no-default-rules"],
        );
        assert_eq!(
            baseline.status.code(),
            Some(0),
            "{name}: {}",
            stderr(&baseline)
        );

        let prune = host.run(binary, &["cache", "prune", "."]);
        assert_eq!(prune.status.code(), Some(0), "{name}: {}", stderr(&prune));

        assert_saved_nothing(&format!("{name}: baseline"), &baseline, &host.state);
        assert_saved_nothing(&format!("{name}: cache prune"), &prune, &host.state);
    }
}
