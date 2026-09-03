//! The saved report as a user meets it: where it lands, what replaces it, and
//! what happens when it cannot be written.
//!
//! Everything here runs the real binary, because the contract is about files on
//! disk and exit codes, not about the functions that produce them.
//!
//! # Finding the report
//!
//! The state root is a platform answer, and only one of the three platforms
//! reads an environment variable for it: Linux takes `XDG_STATE_HOME`, macOS
//! asks Foundation, Windows asks the shell. A test that went looking under a
//! directory it had set itself would therefore assert nothing on two hosts out
//! of three - every positive case failing to find a report it did find, every
//! "nothing was saved" case passing without looking anywhere real.
//!
//! So the report is located the way a user locates it: by the `Report:` line the
//! run printed. [`saved`] reads that line, and the assertions are about the
//! layout under whatever root it names. The cases that are about `XDG_STATE_HOME`
//! itself are marked `#[cfg(target_os = "linux")]`, because on the other two
//! hosts they would be asserting the behaviour of a variable nothing reads.
//!
//! # Staying out of the real state directory
//!
//! `HOME`, `XDG_STATE_HOME` and `LOCALAPPDATA` point into a temporary directory,
//! and on macOS `CFFIXED_USER_HOME` redirects Foundation's idea of the user's
//! home along with them. Windows has no equivalent - `SHGetKnownFolderPath`
//! reads no environment variable - so a saving case there does write under the
//! real local application data folder. That is safe rather than merely tolerated:
//! the scope key is the hash of a path inside this run's own temporary
//! directory, so it names a directory no other run and no real scan can collide
//! with.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use siloscan_core::serde_json::Value;
use tempfile::TempDir;

const SILOSCAN: &str = env!("CARGO_BIN_EXE_siloscan");

const MATCHING_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.needle\n",
    "    severity: error\n",
    "    message: needle found\n",
    "    regex:\n",
    "      pattern: 'needle'\n",
);

/// One isolated machine: its own state root, home, cache and scanned tree.
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

    /// Run in `cwd` with this host's environment. `state` may be overridden to
    /// exercise an invalid or hostile `XDG_STATE_HOME`.
    fn run_in(&self, cwd: &Path, state: Option<&str>, args: &[&str]) -> Output {
        let mut command = Command::new(SILOSCAN);
        command
            .current_dir(cwd)
            .env("XDG_CACHE_HOME", &self.cache)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            // Foundation's user home on macOS, so `URLForDirectory:inDomain:`
            // answers with a directory this run owns. Windows has no equivalent;
            // see the module note.
            .env("CFFIXED_USER_HOME", &self.home)
            .env("LOCALAPPDATA", &self.state);
        match state {
            Some(value) => command.env("XDG_STATE_HOME", value),
            None => command.env("XDG_STATE_HOME", &self.state),
        };
        command.args(args).output().expect("siloscan should run")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_in(&self.tree, None, args)
    }

    fn rules_arg(&self) -> String {
        self.rules.to_str().expect("utf-8 path").to_owned()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be UTF-8")
}

/// The report a run says it wrote, or `None` when it says it wrote none.
///
/// Human output puts the line on stdout and machine output on stderr, so both
/// are read. This is the only way a test learns where a report went; see the
/// module note for why.
fn saved_line(output: &Output) -> Option<PathBuf> {
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        if let Some(path) = text.lines().find_map(|line| line.strip_prefix("Report: ")) {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// The report this run wrote, asserted to exist and to sit where the contract
/// puts it: `<state>/siloscan/reports/<64 lowercase hex>/latest.json`.
fn saved(output: &Output) -> PathBuf {
    let report = saved_line(output).unwrap_or_else(|| {
        panic!(
            "the run reported no saved report\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert!(report.is_file(), "{}", report.display());
    assert_eq!(report.file_name().expect("file name"), "latest.json");

    let scope_dir = report.parent().expect("scope directory");
    let key = scope_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("scope key directory");
    assert_eq!(key.len(), 64, "the key is the full digest: {key}");
    assert!(
        key.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{key}"
    );

    let reports = scope_dir.parent().expect("reports directory");
    assert_eq!(reports.file_name().expect("file name"), "reports");
    assert_eq!(
        reports
            .parent()
            .and_then(Path::file_name)
            .expect("application directory"),
        "siloscan"
    );
    report
}

/// Assert that this run saved nothing.
///
/// The absence of the `Report:` line is the portable half. On Linux the state
/// root is also the one the run would have used, so it can be checked directly;
/// on the other two hosts there is no directory to check that the run did not
/// choose for itself.
fn assert_saved_nothing(output: &Output, state: &Path) {
    assert_eq!(
        saved_line(output),
        None,
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if cfg!(target_os = "linux") {
        assert!(files_under(state).is_empty(), "{}", state.display());
    }
}

/// Everything in the directory holding `report`, sorted. Scope-specific, so it
/// is the same question on every host: what else did this scan leave behind?
fn scope_files(report: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    collect(report.parent().expect("scope directory"), &mut found);
    found.sort();
    found
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    collect(dir, &mut found);
    found.sort();
    found
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

// ---------------------------------------------------------------------------
// Current-host state and identity
// ---------------------------------------------------------------------------

/// The platform adapter as this host implements it. `saved` asserts the layout
/// under whichever root the run chose - the `XDG_STATE_HOME` this test set on
/// Linux, Foundation's answer on macOS, the shell's on Windows - because the
/// layout is the part of the contract all three share.
#[test]
fn a_bare_scan_saves_one_report_under_the_platform_state_root() {
    let host = Host::new();

    let output = host.run(&[]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report = saved(&output);

    // The layout has no history, no index, no previous report and, after a
    // successful publication, no temporary.
    assert_eq!(scope_files(&report), vec![report.clone()]);

    // On the one host whose state root this test chose, that is the whole of it.
    if cfg!(target_os = "linux") {
        assert!(report.starts_with(host.state.join("siloscan/reports")));
        assert_eq!(files_under(&host.state), vec![report]);
    }
}

/// A relative `XDG_STATE_HOME` is not resolved against the working directory:
/// that would let the launch directory move siloscan's state into the tree it
/// is scanning. The documented `$HOME` fallback answers instead.
#[cfg(target_os = "linux")]
#[test]
fn a_relative_state_home_is_ignored_in_favour_of_the_home_fallback() {
    let host = Host::new();

    let output = host.run_in(&host.tree, Some("relative/state"), &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        !host.tree.join("relative").exists(),
        "a relative value must not be resolved against the scan"
    );
    let report = saved(&output);
    assert!(
        report.starts_with(host.home.join(".local/state/siloscan/reports")),
        "{}",
        report.display()
    );
}

/// No usable state root is a refusal, not a guess. Falling back to the cache,
/// the repository or a temporary directory would make review lookup depend on
/// where the scan happened to fail.
#[cfg(target_os = "linux")]
#[test]
fn no_state_root_at_all_is_status_two_with_no_scan_output() {
    let host = Host::new();

    let mut command = Command::new(SILOSCAN);
    command
        .current_dir(&host.tree)
        .env("XDG_CACHE_HOME", &host.cache)
        .env_remove("XDG_STATE_HOME")
        .env_remove("HOME");
    let output = command.output().expect("siloscan should run");

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    let message = stderr(&output);
    assert!(message.contains("--no-save"), "{message}");
    assert!(message.contains("--output"), "{message}");
}

/// Relative, absolute and symlinked spellings of one scope are one report.
#[test]
fn every_spelling_of_one_scope_updates_one_report() {
    let host = Host::new();
    let nested = host.tree.join("modules/api");
    fs::create_dir_all(&nested).expect("nested scope");
    fs::write(nested.join("b.rs"), "let y = 2;\n").expect("source file");
    let rules = host.rules_arg();

    let absolute = nested.to_str().expect("utf-8 path").to_owned();
    let mut written = Vec::new();
    for path in [
        &absolute,
        &"modules/api".to_owned(),
        &"./modules/api".to_owned(),
    ] {
        let output = host.run(&[path, "--rules", &rules, "--no-default-rules", "--save"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        written.push(saved(&output));
    }

    assert_eq!(written[0], written[1]);
    assert_eq!(written[1], written[2]);
}

/// A repository scan, a nested scan and a single-file scan are different
/// scopes, so they get different slots. Review of one must never find another.
#[test]
fn nested_and_single_file_scopes_get_their_own_slots() {
    let host = Host::new();
    let nested = host.tree.join("modules/api");
    fs::create_dir_all(&nested).expect("nested scope");
    fs::write(nested.join("b.rs"), "let y = 2;\n").expect("source file");
    let rules = host.rules_arg();

    let mut written = Vec::new();
    for path in [".", "modules/api", "modules/api/b.rs"] {
        let output = host.run(&[path, "--rules", &rules, "--no-default-rules", "--save"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        written.push(saved(&output));
    }

    written.sort();
    written.dedup();
    assert_eq!(written.len(), 3, "three scopes, three slots");
}

/// The report the scan produced identifies the scope the state directory is
/// named for, so implicit review can check that it opened the right one.
#[test]
fn the_saved_report_records_the_scope_it_is_filed_under() {
    let host = Host::new();

    let output = host.run(&[]);
    let report = saved(&output);
    let document: Value =
        siloscan_core::serde_json::from_slice(&fs::read(&report).expect("report")).expect("JSON");

    assert_eq!(document["report_kind"], "scan");
    assert_eq!(document["scope"]["kind"], "directory");
    assert_eq!(document["scope"]["path_base_ancestor_levels"], 0);
    let identity = document["scope"]["identity"]
        .as_str()
        .expect("identity string");
    let key = report
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .expect("scope key");
    assert_eq!(identity, format!("sha256-v1:{key}"));

    // Nothing that names the machine the scan ran on.
    let text = String::from_utf8(fs::read(&report).expect("report")).expect("UTF-8");
    assert!(!text.contains(host.tree.to_str().expect("utf-8")), "{text}");
}

/// A config-anchored module scan measures its paths from the config root, and
/// the report records how far above the scope that is - `modules/api` is two.
///
/// The number is the only way back to that directory: the report carries no
/// path text, so identity stays lossless for a path that is not valid Unicode.
/// The session that opens the report climbs it; this is the half that writes it.
#[test]
fn a_config_anchored_module_records_the_climb_back_to_its_config_root() {
    let host = Host::new();
    fs::create_dir_all(host.tree.join(".git")).expect(".git");
    fs::write(host.tree.join(".git/HEAD"), "ref: refs/heads/main\n").expect("HEAD");
    fs::write(
        host.tree.join("siloscan.toml"),
        "anchor = \"config\"\ninclude = [\"modules/api/siloscan.toml\"]\n\n[silos]\ncore = [\"crates/core/**\"]\n",
    )
    .expect("root config");
    let module = host.tree.join("modules/api");
    fs::create_dir_all(&module).expect("module");
    fs::write(
        module.join("siloscan.toml"),
        "[silos]\napi = [\"src/**\"]\n",
    )
    .expect("module config");
    fs::write(module.join("b.rs"), "let y = 2;\n").expect("source file");
    let rules = host.rules_arg();

    let output = host.run(&[
        "modules/api",
        "--rules",
        &rules,
        "--no-default-rules",
        "--save",
    ]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report = saved(&output);
    let document: Value =
        siloscan_core::serde_json::from_slice(&fs::read(&report).expect("report")).expect("JSON");
    assert_eq!(document["scope"]["kind"], "directory");
    assert_eq!(document["scope"]["path_base_ancestor_levels"], 2);

    // A scan-root-anchored run of the same directory has nothing to climb.
    fs::remove_file(host.tree.join("siloscan.toml")).expect("drop the root config");
    fs::remove_file(module.join("siloscan.toml")).expect("drop the module config");
    let output = host.run(&[
        "modules/api",
        "--rules",
        &rules,
        "--no-default-rules",
        "--no-cache",
        "--save",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let document: Value =
        siloscan_core::serde_json::from_slice(&fs::read(&report).expect("report")).expect("JSON");
    assert_eq!(document["scope"]["path_base_ancestor_levels"], 0);
}

// ---------------------------------------------------------------------------
// Publication and recovery
// ---------------------------------------------------------------------------

/// A second identical scan replaces the report with the same bytes and leaves
/// nothing else behind: one file, no temporary, no history.
#[test]
fn a_repeat_scan_replaces_the_report_with_identical_bytes() {
    let host = Host::new();

    let first_run = host.run(&[]);
    let report = saved(&first_run);
    let first = fs::read(&report).expect("first report");

    let second_run = host.run(&[]);

    assert_eq!(saved(&second_run), report, "the same slot, replaced");
    assert_eq!(fs::read(&report).expect("second report"), first);
    assert_eq!(scope_files(&report), vec![report]);
}

/// A changed tree replaces the report's content, through the same one file.
#[test]
fn a_changed_tree_replaces_the_reports_content() {
    let host = Host::new();
    let rules = host.rules_arg();

    let first_run = host.run(&[".", "--rules", &rules, "--no-default-rules", "--save"]);
    let report = saved(&first_run);
    let clean = fs::read_to_string(&report).expect("first report");
    assert!(!clean.contains("test.needle"), "{clean}");

    fs::write(host.tree.join("a.rs"), "let needle = 1;\n").expect("source file");
    let output = host.run(&[
        ".",
        "--rules",
        &rules,
        "--no-default-rules",
        "--no-cache",
        "--save",
    ]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(saved(&output), report, "the same slot, replaced");
    let dirty = fs::read_to_string(&report).expect("second report");
    assert!(dirty.contains("test.needle"), "{dirty}");
    assert_eq!(scope_files(&report), vec![report]);
}

/// JSON stdout and the saved file are the same document, produced once. The
/// observable consequence is byte equality, down to the single trailing
/// newline both end with.
#[test]
fn json_stdout_and_the_saved_report_are_the_same_bytes() {
    let host = Host::new();

    let output = host.run(&["--format", "json", "--save"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report = saved(&output);
    assert_eq!(fs::read(&report).expect("report"), output.stdout);
}

/// Human and SARIF stdout are a different document, so the saved report is
/// streamed on its own - and it is still the canonical JSON, not the format
/// that went to the terminal.
#[test]
fn human_and_sarif_runs_save_canonical_json() {
    for format in ["human", "sarif"] {
        let host = Host::new();

        let output = host.run(&["--format", format, "--save"]);

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let report = saved(&output);
        let document: Value =
            siloscan_core::serde_json::from_slice(&fs::read(&report).expect("report"))
                .unwrap_or_else(|e| panic!("{format}: saved report should be canonical JSON: {e}"));
        assert_eq!(document["report_kind"], "scan", "{format}");
        assert_eq!(document["schema_version"], "1.2", "{format}");
    }
}

/// A destination that cannot be published to costs the run an exit code, not
/// its report: the scan output is already correct and is not discarded because
/// its durable publication failed.
#[test]
fn a_post_scan_publication_failure_keeps_stdout_and_exits_two() {
    let host = Host::new();
    // A directory where the report file should be: the temporary is created
    // beside it and the replacement then has nowhere to land.
    let blocked = host.tree.join("blocked.json");
    fs::create_dir(&blocked).expect("blocking directory");
    let destination = blocked.to_str().expect("utf-8 path").to_owned();

    let output = host.run(&["--format", "json", "--output", &destination]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let document: Result<Value, _> = siloscan_core::serde_json::from_slice(&output.stdout);
    assert!(
        document.is_ok(),
        "machine stdout must stay one complete document: {}",
        stdout(&output)
    );
    let message = stderr(&output);
    assert!(message.contains("error: "), "{message}");
    assert!(
        !message.contains("Report: "),
        "a failed save must not claim a path: {message}"
    );
    // The temporary this run created is gone.
    let leftovers: Vec<_> = fs::read_dir(&host.tree)
        .expect("tree")
        .flatten()
        .map(|entry| entry.file_name())
        .filter(|name| name.to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// Status 2 wins over the finding status, because the command did not finish
/// what it was asked to do.
#[test]
fn a_save_failure_outranks_a_finding_status() {
    let host = Host::new();
    fs::write(host.tree.join("a.rs"), "let needle = 1;\n").expect("source file");
    let blocked = host.tree.join("blocked.json");
    fs::create_dir(&blocked).expect("blocking directory");
    let destination = blocked.to_str().expect("utf-8 path").to_owned();
    let rules = host.rules_arg();

    let output = host.run(&[
        ".",
        "--rules",
        &rules,
        "--no-default-rules",
        "--output",
        &destination,
    ]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("test.needle"),
        "the findings still printed: {}",
        stdout(&output)
    );
}

/// A destination that cannot be prepared is refused before the scan runs: the
/// answer would have been the same afterwards and the scan would have been
/// wasted.
#[test]
fn a_missing_output_parent_is_refused_before_the_scan() {
    let host = Host::new();
    let destination = host
        .tree
        .join("absent/report.json")
        .to_str()
        .expect("utf-8 path")
        .to_owned();

    let output = host.run(&["--output", &destination]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    assert_saved_nothing(&output, &host.state);
    assert!(stderr(&output).contains("--output"), "{}", stderr(&output));
}

/// Automatic state inside the tree being scanned would become an input the same
/// scan discovers. It is refused before anything is created.
///
/// Planting the state root is `XDG_STATE_HOME`, so this asks its question only
/// on Linux. The containment rule itself is not platform-specific and its unit
/// coverage is in `saved_report`.
#[cfg(target_os = "linux")]
#[test]
fn a_state_root_inside_the_scanned_tree_is_refused_before_the_scan() {
    let host = Host::new();
    let inside = host
        .tree
        .join("state")
        .to_str()
        .expect("utf-8 path")
        .to_owned();

    let output = host.run_in(&host.tree, Some(&inside), &[]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    assert_eq!(saved_line(&output), None);
    assert!(!host.tree.join("state").exists(), "nothing may be created");
    let message = stderr(&output);
    assert!(message.contains("--no-save"), "{message}");
}

/// The same protection one directory out: a scan of a module must not put state
/// anywhere in the repository around it.
#[cfg(target_os = "linux")]
#[test]
fn a_state_root_inside_the_repository_around_the_scope_is_refused() {
    let host = Host::new();
    fs::create_dir_all(host.tree.join(".git")).expect(".git");
    fs::write(host.tree.join(".git/HEAD"), "ref: refs/heads/main\n").expect("HEAD");
    let module = host.tree.join("modules/api");
    fs::create_dir_all(&module).expect("module");
    fs::write(module.join("b.rs"), "let y = 2;\n").expect("source file");
    let inside = host
        .tree
        .join("var/state")
        .to_str()
        .expect("utf-8 path")
        .to_owned();
    let rules = host.rules_arg();

    let output = host.run_in(
        &host.tree,
        Some(&inside),
        &[
            "modules/api",
            "--rules",
            &rules,
            "--no-default-rules",
            "--save",
        ],
    );

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(!host.tree.join("var").exists());
}

/// The normal Linux fallback when the user scans their own home directory: the
/// report would land under the scan, so the run fails early rather than
/// creating it.
#[cfg(target_os = "linux")]
#[test]
fn scanning_home_with_the_default_fallback_fails_early() {
    let host = Host::new();
    fs::write(host.home.join("a.rs"), "let x = 1;\n").expect("source file");

    let mut command = Command::new(SILOSCAN);
    command
        .current_dir(&host.home)
        .env("XDG_CACHE_HOME", &host.cache)
        .env("HOME", &host.home)
        .env_remove("XDG_STATE_HOME");
    let output = command.output().expect("siloscan should run");

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(!host.home.join(".local/state/siloscan").exists());
}

/// A stale temporary beside a valid report is not a review candidate and is not
/// swept: another scan may still be writing one.
#[test]
fn a_stale_temporary_is_left_alone_and_is_not_the_report() {
    let host = Host::new();

    let first_run = host.run(&[]);
    let report = saved(&first_run);
    let stale = report.with_file_name("latest.json.999999.0.tmp");
    fs::write(&stale, b"{\"partial\": ").expect("stale temporary");

    host.run(&[]);

    assert!(stale.is_file(), "another writer's temporary is not swept");
    let document: Result<Value, _> =
        siloscan_core::serde_json::from_slice(&fs::read(&report).expect("report"));
    assert!(document.is_ok(), "the committed report is unaffected");
}

/// The persistence controls are pairwise exclusive, so one scan writes at most
/// one report and the refusal happens in argument parsing, before any work.
#[test]
fn conflicting_persistence_controls_are_refused_with_no_scan_output() {
    let host = Host::new();

    for args in [
        vec!["--save", "--no-save"],
        vec!["--no-save", "--output", "report.json"],
        vec!["--save", "--output", "report.json"],
    ] {
        let output = host.run(&args);

        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(stdout(&output).is_empty(), "{args:?}: {}", stdout(&output));
        assert_saved_nothing(&output, &host.state);
    }
}
