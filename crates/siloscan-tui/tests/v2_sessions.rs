//! Live and saved review sessions, through both entry points.
//!
//! The standalone binary and the library entry are the same session: what one
//! refuses the other refuses, in the same words. The rejection cells of the
//! reader matrix are driven through the binary, because that also proves the
//! exit status and proves the terminal was never touched - a session that
//! refused before setup finished writes nothing to stdout, so there is no
//! alternate screen to restore. The acceptance cells are driven through
//! [`siloscan_tui::OpenSession`], which performs the same setup and stops
//! before the terminal, and are checked as semantic state on a fixed 120x40
//! test backend rather than through a pseudo-terminal.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use siloscan_core::plan::{
    OutcomeMetadata, ResolvedScanPlan, ScanRequest, ScopeKind, ScopeMetadata, to_resolved_json,
};
use siloscan_core::rules::Severity;
use siloscan_core::serde_json::{self, Value};
use siloscan_tui::{ExpectedScope, OpenSession, ReviewSession};

/// The terminal every semantic check is rendered at.
const SIZE: (u16, u16) = (120, 40);

/// A scan of a tree this size is a fraction of a second; the deadline is only
/// here so a wedged worker fails the test instead of hanging it.
const SCAN_DEADLINE: Duration = Duration::from_secs(60);

/// The scope identity the resolved fixtures are written under. The CLI derives
/// the real one; this reader only ever compares what it is handed.
const IDENTITY: &str = "sha256-v1:0f0e0d0c0b0a09080706050403020100f0e0d0c0b0a090807060504030201000";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A tree with one finding in it: a rule directory of its own, so the fixture
/// does not depend on the embedded pack, and no cache, so no session test reads
/// or writes the user's cache directory.
fn project(dir: &Path) -> ScanRequest {
    fs::create_dir_all(dir.join("src")).expect("the fixture tree is writable");
    fs::write(dir.join("src/leak.rs"), b"let key = \"needle-42\";\n").expect("writable");
    fs::write(dir.join("rules.yaml"), RULE).expect("writable");

    ScanRequest::explicit(dir)
        .with_rule_dirs(vec![dir.to_path_buf()])
        .without_embedded_rules()
        .without_cache()
}

/// The one rule the fixtures scan with. Its pattern does not match the file
/// that declares it, so the only finding in a fixture tree is the planted one.
const RULE: &str = "version: 1\nrules:\n  - id: test.needle\n    severity: error\n    message: \"needle\"\n    regex:\n      pattern: \"needle-[0-9]+\"\n";

/// A line that exists only in the module's source file, so finding it on screen
/// means the source pane read that file rather than matched on report text.
const SOURCE_MARKER: &str = "// anchored-source-marker";

/// A repository that anchors every reported path at its own root, with the
/// scanned module two directories below it.
///
/// The `.git` marker is what lets config discovery climb out of the module to
/// the repository config, which is the arrangement that makes the scan root and
/// the baseline root differ. Returns the module and the request that scans it;
/// the repository root is `dir`.
fn anchored_repo(dir: &Path) -> (PathBuf, ScanRequest) {
    let module = dir.join("modules/api");
    fs::create_dir_all(module.join("src")).expect("the fixture tree is writable");
    fs::create_dir_all(dir.join(".git")).expect("writable");
    fs::write(dir.join(".git/HEAD"), b"ref: refs/heads/main\n").expect("writable");
    fs::write(dir.join("siloscan.toml"), "anchor = \"config\"\n").expect("writable");
    fs::write(dir.join("rules.yaml"), RULE).expect("writable");
    fs::write(
        module.join("src/a.rs"),
        format!("{SOURCE_MARKER}\nlet key = \"needle-42\";\n").as_bytes(),
    )
    .expect("writable");

    let request = ScanRequest::explicit(&module)
        .with_rule_dirs(vec![dir.to_path_buf()])
        .without_embedded_rules()
        .without_cache();
    (module, request)
}

/// The complete resolved report a scan of `request` produces, with the four
/// markers the CLI appends. Written by the core writer itself, so the fixtures
/// are the bytes the product actually saves.
fn resolved_json(request: &ScanRequest, identity: &str, kind: ScopeKind, reached: bool) -> String {
    resolved_json_with_levels(request, identity, kind, reached, 0)
}

/// The same, for a scope whose reported paths are measured `levels` directories
/// above it - which is what config anchoring does.
fn resolved_json_with_levels(
    request: &ScanRequest,
    identity: &str,
    kind: ScopeKind,
    reached: bool,
    levels: u32,
) -> String {
    let plan = ResolvedScanPlan::resolve(request).expect("the fixture request resolves");
    let resolved = plan.execute(&mut |_| {}).expect("the fixture scan runs");
    let (report, setup, context) = resolved.into_parts();
    to_resolved_json(
        &report,
        &setup,
        &context,
        &ScopeMetadata::new(identity.to_string(), kind, levels),
        &OutcomeMetadata::new(Severity::Error, reached),
        None,
    )
}

/// The same document with `edit` applied to its top-level object.
fn edited(json: &str, edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> String {
    let mut value: Value = serde_json::from_str(json).expect("the fixture is JSON");
    edit(value.as_object_mut().expect("a JSON object"));
    serde_json::to_string_pretty(&value).expect("re-serializes")
}

/// A marker-free report of the shape the retained public core writer emits: a
/// current product version and no resolved metadata at all.
fn core_writer_json(json: &str) -> String {
    edited(json, |map| {
        for marker in ["report_kind", "scope", "outcome", "setup"] {
            map.remove(marker);
        }
    })
}

/// A marker-free report as v1.5.1 wrote it.
fn legacy_json(json: &str) -> String {
    edited(&core_writer_json(json), |map| {
        map.insert("version".to_string(), Value::String("1.5.1".to_string()));
    })
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, text).expect("the fixture file is writable");
    path
}

// ---------------------------------------------------------------------------
// Session drivers
// ---------------------------------------------------------------------------

fn saved(report: PathBuf, source_base: &Path, expect: Option<ExpectedScope>) -> ReviewSession {
    ReviewSession::SavedReport {
        report,
        source_base: source_base.to_path_buf(),
        config: None,
        expect,
    }
}

/// Open a saved session, or the refusal that stopped it.
fn open_saved(
    report: PathBuf,
    source_base: &Path,
    expect: Option<ExpectedScope>,
) -> Result<OpenSession, String> {
    OpenSession::open(saved(report, source_base, expect)).map_err(|error| error.to_string())
}

/// Run a live session's scan to completion.
fn settle(session: &mut OpenSession) {
    let deadline = Instant::now() + SCAN_DEADLINE;
    while session.is_scanning() {
        session.drain();
        assert!(Instant::now() < deadline, "the scan never finished");
        thread::sleep(Duration::from_millis(5));
    }
    session.drain();
}

/// Every cell of a 120x40 frame, one row per line.
fn render(session: &mut OpenSession) -> String {
    let (width, height) = SIZE;
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a test backend");
    session.draw(&mut terminal).expect("the frame draws");
    let buffer = terminal.backend().buffer().clone();

    let mut text = String::new();
    for y in 0..height {
        for x in 0..width {
            text.push_str(buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()));
        }
        text.push('\n');
    }
    text
}

fn standalone(args: Vec<OsString>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_siloscan-tui"))
        .args(args)
        .output()
        .expect("standalone TUI should run")
}

fn normalize_line_endings(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .expect("session output should be UTF-8")
        .replace("\r\n", "\n")
}

/// The standalone binary's refusal: status 2, the message on stderr, and an
/// untouched terminal. Nothing reaches stdout, so no alternate screen was
/// entered and there is nothing left to restore.
fn assert_standalone_refuses(args: Vec<OsString>, expected: &str) {
    let output = standalone(args);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "a refusal must leave the terminal as it was: {:?}",
        normalize_line_endings(&output.stdout)
    );
    assert_eq!(
        normalize_line_endings(&output.stderr),
        format!("error: {expected}\n")
    );
}

// ---------------------------------------------------------------------------
// The two entry points are one session
// ---------------------------------------------------------------------------

#[test]
fn library_entry_matches_standalone_live_setup_errors() {
    let dir = tempfile::tempdir().expect("temporary directory should be available");
    let missing = dir.path().join("missing-project");

    let linked = siloscan_tui::run(ReviewSession::Live {
        request: ScanRequest::explicit(&missing),
    })
    .expect_err("setup should fail before terminal access");

    assert_standalone_refuses(vec![missing.into_os_string()], &linked.to_string());
}

#[test]
fn library_entry_matches_standalone_snapshot_setup_errors() {
    let dir = tempfile::tempdir().expect("temporary directory should be available");
    let missing = dir.path().join("missing-report.json");

    let linked = siloscan_tui::run(saved(missing.clone(), Path::new("."), None))
        .expect_err("setup should fail before terminal access");

    assert_standalone_refuses(
        vec![OsString::from("--report"), missing.into_os_string()],
        &linked.to_string(),
    );
}

#[test]
fn standalone_surface_preserves_help() {
    let output = standalone(vec![OsString::from("--help")]);

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        normalize_line_endings(&output.stdout),
        include_str!("../../../research/oracle-v1.5.1/golden/siloscan-tui-help.stdout")
    );
}

#[test]
fn standalone_surface_preserves_version() {
    let output = standalone(vec![OsString::from("--version")]);

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        normalize_line_endings(&output.stdout),
        include_str!("../../../research/oracle-v1.5.1/golden/siloscan-tui-version.stdout")
    );
}

/// A live session's setup is the core's, so a refusal the CLI would print is
/// the refusal this session returns - word for word, and through both entries.
#[test]
fn a_live_session_refuses_what_core_setup_refuses() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = ScanRequest::explicit(dir.path()).without_embedded_rules();
    let refusal = ResolvedScanPlan::resolve(&request)
        .err()
        .expect("no rules means nothing would be checked");

    let linked = siloscan_tui::run(ReviewSession::Live { request })
        .expect_err("the session refuses the same request");
    assert_eq!(linked.to_string(), refusal.to_string());

    assert_standalone_refuses(
        vec![
            OsString::from(dir.path()),
            OsString::from("--no-default-rules"),
        ],
        &refusal.to_string(),
    );
}

// ---------------------------------------------------------------------------
// Live sessions
// ---------------------------------------------------------------------------

/// The first scan reports the tree, and the setup that produced it comes from
/// the plan rather than from anything the TUI resolved for itself.
#[test]
fn a_live_session_reports_its_first_scan() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());

    let mut session =
        OpenSession::open(ReviewSession::Live { request }).expect("the tree resolves");
    settle(&mut session);

    assert!(!session.is_read_only());
    assert_eq!(session.status(), "1 new, 0 baselined, 0 suppressed");

    let setup = session
        .setup()
        .expect("the plan's setup arrives with the report");
    assert!(
        setup.explicit_overrides.contains(&"path".to_string()),
        "the request's provenance is kept: {:?}",
        setup.explicit_overrides
    );
    assert!(
        setup
            .rule_sources
            .iter()
            .any(|source| source.origin == "directory"),
        "the rule directory is recorded: {:?}",
        setup.rule_sources
    );

    let text = render(&mut session);
    assert!(
        text.contains("1 new"),
        "the debt counts are on screen:\n{text}"
    );
    assert!(
        text.contains("src"),
        "the module card is on screen:\n{text}"
    );
    assert!(
        !text.contains("read-only"),
        "a live session is writable:\n{text}"
    );
}

/// Every scan resolves its own plan. A config written between two scans is
/// picked up by the second one, which is only possible if setup ran again.
#[test]
fn a_live_session_resolves_a_fresh_plan_for_every_scan() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());

    let mut session =
        OpenSession::open(ReviewSession::Live { request }).expect("the tree resolves");
    settle(&mut session);
    assert_eq!(capability(&session, "repository-config"), "not_configured");

    fs::write(
        dir.path().join("siloscan.toml"),
        "[silos]\nsource = [\"src/**\"]\n",
    )
    .expect("writable");

    session.rescan();
    settle(&mut session);

    assert_eq!(
        capability(&session, "repository-config"),
        "enabled",
        "the second scan discovered the config the first one could not have seen"
    );
    let text = render(&mut session);
    assert!(
        text.contains("source"),
        "the declared silo is on screen:\n{text}"
    );
}

/// A rescan re-walks the tree, so what it shows is the tree as it is now.
#[test]
fn a_rescan_reports_the_tree_as_it_is_now() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());

    let mut session =
        OpenSession::open(ReviewSession::Live { request }).expect("the tree resolves");
    settle(&mut session);
    assert_eq!(session.status(), "1 new, 0 baselined, 0 suppressed");

    fs::write(dir.path().join("src/leak.rs"), b"let key = \"fixed\";\n").expect("writable");
    session.rescan();
    settle(&mut session);

    assert_eq!(session.status(), "0 new, 0 baselined, 0 suppressed");
}

/// A config-anchored module scan has two roots, and they are not the same
/// directory. Sources are read from the module; fingerprints are measured from
/// the config root, so that is where the baseline the ratchet writes has to go.
/// Resolving both in the TUI is what produced the wrong one before this slice.
#[test]
fn a_config_anchored_live_session_separates_its_two_roots() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (module, request) = anchored_repo(dir.path());

    let mut session =
        OpenSession::open(ReviewSession::Live { request }).expect("the tree resolves");
    settle(&mut session);

    assert_eq!(session.status(), "1 new, 0 baselined, 0 suppressed");
    assert_eq!(
        session.source_base(),
        module,
        "sources are read from the module that was scanned"
    );
    assert_eq!(
        session.baseline_root(),
        dir.path(),
        "the baseline belongs where the fingerprints are measured from"
    );
}

/// The caller cannot know how far above the scope a report's paths are measured
/// from without reading the report, and it is forbidden a second parse of it. So
/// it passes the scope's own directory and the session climbs the levels the
/// report records.
#[test]
fn a_saved_session_climbs_to_the_base_its_report_records() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (module, request) = anchored_repo(dir.path());

    // Two directories from `modules/api` up to the config root, which is what
    // the CLI records for this scope.
    let report = write(
        dir.path(),
        "latest.json",
        &resolved_json_with_levels(&request, IDENTITY, ScopeKind::Directory, true, 2),
    );

    let mut session = open_saved(report, &module, None).expect("the report opens");

    assert_eq!(
        session.source_base(),
        dir.path(),
        "the base is the config root, not the module the scope names"
    );

    // And the source pane reads through it: this line is in the module's file
    // and nowhere in the report.
    session.key(KeyEvent::from(KeyCode::Char('2')));
    let text = render(&mut session);
    assert!(
        text.contains(SOURCE_MARKER),
        "the source pane did not resolve the report's path:\n{text}"
    );
}

/// A report measured from further up than the base can reach is refused. Any
/// directory the climb happened to stop at would show one file's contents under
/// another file's name.
#[test]
fn a_saved_session_refuses_a_base_it_cannot_climb() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (module, request) = anchored_repo(dir.path());
    let report = write(
        dir.path(),
        "deep.json",
        &resolved_json_with_levels(&request, IDENTITY, ScopeKind::Directory, true, 400),
    );

    let error = open_saved(report, &module, None)
        .err()
        .expect("400 parents is not a base");

    assert!(error.contains("400 directories above"), "{error}");
}

fn capability(session: &OpenSession, id: &str) -> String {
    let setup = session.setup().expect("a live session has setup");
    let state = setup
        .capabilities
        .iter()
        .find(|capability| capability.id() == id)
        .unwrap_or_else(|| panic!("no {id} capability in {:?}", setup.capabilities));
    serde_json::to_value(state.status())
        .expect("a capability status serializes")
        .as_str()
        .expect("as a string")
        .to_string()
}

// ---------------------------------------------------------------------------
// Saved sessions never scan
// ---------------------------------------------------------------------------

/// The tree under review would produce a finding if anything scanned it. The
/// session shows what the report says instead, because it never scans.
#[test]
fn a_saved_session_opens_the_report_and_not_the_tree() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let scanned = resolved_json(&request, IDENTITY, ScopeKind::Directory, true);
    assert!(
        scanned.contains("src/leak.rs"),
        "the fixture tree does produce a finding"
    );

    // The same scope, reported clean by a run that saw a different tree.
    let clean = edited(&scanned, |map| {
        map.insert("findings".to_string(), Value::Array(Vec::new()));
        map.insert(
            "outcome".to_string(),
            serde_json::json!({ "fail_on": "error", "threshold_reached": false }),
        );
    });
    let report = write(dir.path(), "latest.json", &clean);

    let mut session = open_saved(report, dir.path(), None).expect("the report opens");

    assert!(session.is_read_only());
    assert!(!session.is_scanning());
    assert!(
        session.setup().is_none(),
        "a saved session resolves no plan, so it has no setup of its own"
    );

    // `r` is the only way to start a scan, and this session refuses it.
    session.rescan();
    assert!(
        !session.is_scanning(),
        "a saved session has nothing to scan"
    );

    let text = render(&mut session);
    assert!(text.contains("read-only"), "the read-only banner:\n{text}");
    assert!(
        !text.contains("src/leak.rs"),
        "the tree was scanned after all:\n{text}"
    );
    assert!(
        session.status().starts_with("0 new, 0 baselined"),
        "{}",
        session.status()
    );
}

// ---------------------------------------------------------------------------
// The reader matrix
// ---------------------------------------------------------------------------

/// Explicit `--report FILE`, marker-free supported 1.x: accepted, with setup
/// and the saved outcome unavailable rather than clean.
#[test]
fn explicit_review_opens_a_marker_free_one_x_report() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let report = write(
        dir.path(),
        "old.json",
        &legacy_json(&resolved_json(
            &request,
            IDENTITY,
            ScopeKind::Directory,
            true,
        )),
    );

    let mut session = open_saved(report, dir.path(), None).expect("a 1.x report opens");

    assert!(session.is_read_only());
    assert_eq!(session.notes(), "saved outcome unavailable");
    let text = render(&mut session);
    assert!(text.contains("read-only"), "the read-only banner:\n{text}");
    assert!(text.contains("saved outcome unavailable"), "{text}");
}

/// Explicit `--report FILE`, complete four-marker v2: authoritative. The gate
/// the run was judged against is shown, not inferred from the rows.
#[test]
fn explicit_review_takes_a_complete_resolved_report_as_authoritative() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let report = write(
        dir.path(),
        "latest.json",
        &resolved_json(&request, IDENTITY, ScopeKind::Directory, true),
    );

    let mut session = open_saved(report, dir.path(), None).expect("a resolved report opens");

    assert_eq!(session.notes(), "saved outcome: fail-on error reached");
    let text = render(&mut session);
    assert!(text.contains("read-only"), "{text}");
    assert!(
        text.contains("saved outcome: fail-on error reached"),
        "{text}"
    );
}

/// Explicit `--report FILE`, marker-free output of the retained core writer:
/// accepted, and labelled the same way every other marker-free report is. Its
/// 2.x product version says nothing about its shape.
#[test]
fn explicit_review_opens_marker_free_core_writer_output() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let report = write(
        dir.path(),
        "core.json",
        &core_writer_json(&resolved_json(
            &request,
            IDENTITY,
            ScopeKind::Directory,
            true,
        )),
    );

    let mut session = open_saved(report, dir.path(), None).expect("core writer output opens");

    assert_eq!(session.notes(), "saved outcome unavailable");
    assert!(render(&mut session).contains("read-only"));
}

/// Explicit `--report FILE`, partial markers: refused, through the entry point
/// a user would hit it with.
#[test]
fn explicit_review_refuses_a_partial_marker_set() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let complete = resolved_json(&request, IDENTITY, ScopeKind::Directory, true);

    for dropped in ["report_kind", "scope", "outcome", "setup"] {
        let partial = edited(&complete, |map| {
            map.remove(dropped);
        });
        let path = write(dir.path(), &format!("{dropped}-missing.json"), &partial);

        let error = open_saved(path.clone(), dir.path(), None)
            .err()
            .unwrap_or_else(|| panic!("a report without {dropped} must be refused"));
        assert!(error.contains(dropped), "{dropped}: {error}");

        assert_standalone_refuses(
            vec![OsString::from("--report"), path.into_os_string()],
            &error,
        );
    }
}

/// Implicit latest: only a complete resolved report, and only for the scope it
/// was asked about.
#[test]
fn implicit_latest_takes_only_a_complete_report_for_its_scope() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let complete = resolved_json(&request, IDENTITY, ScopeKind::Directory, true);
    let expect = ExpectedScope {
        identity: IDENTITY.to_string(),
        kind: ScopeKind::Directory,
    };

    let path = write(dir.path(), "latest.json", &complete);
    let session =
        open_saved(path, dir.path(), Some(expect.clone())).expect("its own scope's report opens");
    assert!(session.is_read_only());

    // Every other shape, refused.
    let refused = [
        (
            "legacy.json",
            legacy_json(&complete),
            "no resolved scan metadata",
        ),
        (
            "core.json",
            core_writer_json(&complete),
            "no resolved scan metadata",
        ),
        (
            "partial.json",
            edited(&complete, |map| {
                map.remove("setup");
            }),
            "setup",
        ),
    ];
    for (name, text, expected) in refused {
        let path = write(dir.path(), name, &text);
        let error = open_saved(path, dir.path(), Some(expect.clone()))
            .err()
            .unwrap_or_else(|| panic!("{name} must not be this scope's latest report"));
        assert!(error.contains(expected), "{name}: {error}");
    }
}

/// Another scope's report is not this scope's latest, whichever half of the
/// identity differs. An explicitly named file is opened whatever scope it came
/// from.
#[test]
fn implicit_latest_refuses_another_scope() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let path = write(
        dir.path(),
        "latest.json",
        &resolved_json(&request, IDENTITY, ScopeKind::Directory, true),
    );

    let others = [
        ExpectedScope {
            identity: "sha256-v1:ff".to_string(),
            kind: ScopeKind::Directory,
        },
        ExpectedScope {
            identity: IDENTITY.to_string(),
            kind: ScopeKind::File,
        },
    ];
    for expect in others {
        let error = open_saved(path.clone(), dir.path(), Some(expect))
            .err()
            .expect("a different scope must be refused");
        assert!(error.contains("different scan scope"), "{error}");
    }

    assert!(
        open_saved(path, dir.path(), None).is_ok(),
        "an explicitly named report is opened whatever scope it came from"
    );
}

/// The documents that are not reports, refused by name through the standalone
/// entry point. Every one of these would have opened as an empty passing board
/// if the reader took its tolerance one step further.
#[test]
fn a_document_that_is_not_a_report_is_refused() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let complete = resolved_json(&request, IDENTITY, ScopeKind::Directory, true);

    let cases = [
        (
            "schema-only.json",
            r#"{ "schema_version": "1.2" }"#.to_string(),
        ),
        (
            "null-findings.json",
            r#"{ "schema_version": "1.2", "findings": null }"#.to_string(),
        ),
        (
            "sarif.json",
            r#"{ "version": "2.1.0", "runs": [{ "results": [] }] }"#.to_string(),
        ),
        (
            "package.json",
            r#"{ "name": "app", "scripts": {} }"#.to_string(),
        ),
        (
            "bad-version.json",
            edited(&complete, |map| {
                map.insert("version".to_string(), Value::String("two".to_string()));
            }),
        ),
        (
            "numeric-version.json",
            edited(&complete, |map| {
                map.insert("version".to_string(), Value::from(2));
            }),
        ),
    ];

    for (name, text) in cases {
        let path = write(dir.path(), name, &text);
        let error = open_saved(path.clone(), dir.path(), None)
            .err()
            .unwrap_or_else(|| panic!("{name} must be refused"));

        assert_standalone_refuses(
            vec![OsString::from("--report"), path.into_os_string()],
            &error,
        );
    }
}

/// A capability status a later build invented does not invalidate the report
/// that carries it: the document is still that scan's report, and the reader
/// keeps the value it could not interpret.
#[test]
fn an_unknown_setup_status_is_retained() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let future = edited(
        &resolved_json(&request, IDENTITY, ScopeKind::Directory, false),
        |map| {
            let setup = map.get_mut("setup").expect("the setup marker");
            let capabilities = setup
                .get_mut("capabilities")
                .and_then(Value::as_array_mut)
                .expect("the capability list");
            for capability in capabilities.iter_mut() {
                capability["status"] = Value::String("deferred".to_string());
            }
        },
    );
    let path = write(dir.path(), "future.json", &future);

    let session = open_saved(path, dir.path(), None).expect("a same-major addition still opens");

    assert_eq!(session.notes(), "saved outcome: fail-on error not reached");
}

/// The failure this distinction exists to prevent: a report that hid its
/// findings behind `--min-severity` and records no outcome must not read as a
/// run that passed.
#[test]
fn a_filtered_legacy_report_is_never_authoritatively_clean() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let filtered = edited(
        &legacy_json(&resolved_json(
            &request,
            IDENTITY,
            ScopeKind::Directory,
            true,
        )),
        |map| {
            map.insert("findings".to_string(), Value::Array(Vec::new()));
            map.insert(
                "min_severity".to_string(),
                Value::String("error".to_string()),
            );
        },
    );
    let path = write(dir.path(), "filtered.json", &filtered);

    let mut session = open_saved(path, dir.path(), None).expect("a filtered 1.x report opens");

    assert_eq!(session.status(), "0 new, 0 baselined, 0 suppressed");
    assert_eq!(
        session.notes(),
        "saved outcome unavailable | filtered report: findings below error hidden"
    );

    // On screen, at the size the status line would have clipped both notes:
    // the board reads 0 new, and nothing on it may leave that standing alone.
    let text = render(&mut session);
    assert!(text.contains("0 new"), "{text}");
    assert!(text.contains("saved outcome unavailable"), "{text}");
    assert!(
        text.contains("filtered report: findings below error hidden"),
        "{text}"
    );
}

/// The same report, saved by a v2 run whose gate was reached before filtering,
/// still reads as failed with nothing failing on screen.
#[test]
fn a_filtered_resolved_report_keeps_the_outcome_its_run_recorded() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let request = project(dir.path());
    let filtered = edited(
        &resolved_json(&request, IDENTITY, ScopeKind::Directory, true),
        |map| {
            map.insert("findings".to_string(), Value::Array(Vec::new()));
            map.insert(
                "min_severity".to_string(),
                Value::String("error".to_string()),
            );
        },
    );
    let path = write(dir.path(), "filtered.json", &filtered);

    let mut session = open_saved(path, dir.path(), None).expect("the report opens");

    assert_eq!(session.status(), "0 new, 0 baselined, 0 suppressed");

    // A board with nothing failing on it, drawn at 120x40, still says the run
    // it came from failed its gate and why the rows are missing.
    let text = render(&mut session);
    assert!(text.contains("0 new"), "{text}");
    assert!(
        text.contains("saved outcome: fail-on error reached"),
        "a report with nothing failing on screen still reports its gate:\n{text}"
    );
    assert!(
        text.contains("filtered report: findings below error hidden"),
        "{text}"
    );
}
