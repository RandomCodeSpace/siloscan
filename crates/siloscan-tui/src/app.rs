//! Scan lifecycle: run the core scanner off the UI thread and fold its result
//! back into `AppState`.

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::thread;

use siloscan_core::config::Config;
use siloscan_core::findings::Finding;
use siloscan_core::metrics::DUPLICATE_BLOCK_RULE_ID;
use siloscan_core::output::REDACTED_MATCH;
use siloscan_core::plan::{ResolvedScanPlan, ResolvedScanReport, ScanRequest};
use siloscan_core::rules::Severity;
use siloscan_core::scan::{Progress, ScanReport};

use crate::snapshot::{HIDDEN_MATCH_NOTE, SavedOutcome, SnapshotData};
use crate::state::{AppState, FindingRow, Scroll, Status};
use crate::ui::dashboard;

/// The report is boxed so a progress tick, which is the common event by far,
/// stays small.
pub enum AppEvent {
    Progress(Progress),
    ScanDone(Box<ResolvedScanReport>),
    /// The scan never produced a report: setup refused the request, or a
    /// boundary rule names a silo the config does not define. Reported in the
    /// status line rather than killing the session.
    Failed(String),
}

/// Run an already-resolved plan on a worker thread, streaming progress and then
/// the report.
///
/// This is the session's first scan, whose plan was resolved before the
/// terminal was taken so that a setup refusal reaches the caller instead of a
/// status line nobody asked for.
pub fn spawn_scan(plan: ResolvedScanPlan, tx: Sender<AppEvent>) {
    thread::spawn(move || execute(plan, &tx));
}

/// Resolve a fresh plan for `request` and run it, both on a worker thread.
///
/// Every rescan goes through here rather than reusing the plan the session
/// booted with. A plan is immutable and holds the config, rules, baseline,
/// coverage report, cache and admitted inventory as they were when it was
/// resolved; reusing one would show the same tree after the file that changed
/// is exactly what the reader pressed `r` to see.
pub fn spawn_fresh_scan(request: ScanRequest, tx: Sender<AppEvent>) {
    thread::spawn(move || match ResolvedScanPlan::resolve(&request) {
        Ok(plan) => execute(plan, &tx),
        Err(error) => {
            let _ = tx.send(AppEvent::Failed(error.to_string()));
        }
    });
}

/// Send failures mean the UI is gone, which is not an error worth reporting.
fn execute(plan: ResolvedScanPlan, tx: &Sender<AppEvent>) {
    let progress_tx = tx.clone();
    let mut on_progress = |progress: Progress| {
        let _ = progress_tx.send(AppEvent::Progress(progress));
    };
    let event = match plan.execute(&mut on_progress) {
        Ok(report) => AppEvent::ScanDone(Box::new(report)),
        Err(e) => AppEvent::Failed(e),
    };
    let _ = tx.send(event);
}

/// Report a scan that never produced findings. The rows already on screen are
/// left alone: a failed rescan should not wipe the triage list.
pub fn apply_failure(state: &mut AppState, message: String) {
    state.scan_running = false;
    state.status = message;
}

/// Replace the rows with the report's findings, merged back into canonical
/// order (path, line, column, rule id) across all three statuses. `config`
/// supplies the silo declarations the module cards are grouped by.
pub fn apply_report(state: &mut AppState, report: ScanReport, config: Option<&Config>) {
    let boundary_edges = report.boundary_edges;
    let rows = merge_rows(report.findings, report.baselined, report.suppressed);

    // The core reports each violating edge by fingerprint, since the silo pair
    // is not recoverable from the finding; the silo screen wants row indices.
    // A finding whose fingerprint is absent from the rows was never reported.
    let mut by_fingerprint: HashMap<&str, usize> = HashMap::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        by_fingerprint
            .entry(row.finding.fingerprint.as_str())
            .or_insert(index);
    }
    let edges: Vec<(String, String, usize)> = boundary_edges
        .into_iter()
        .filter_map(|(from, to, fingerprint)| {
            by_fingerprint
                .get(fingerprint.as_str())
                .map(|index| (from, to, *index))
        })
        .collect();

    state.rows = rows;
    state.boundary_edges = edges;
    state.metrics = report.metrics;
    reset_cursors(state);
    refresh_silos(state, config);
    report_debt(state);
}

/// Load a report file into the same shape a scan produces. A report carries no
/// boundary edges - the silo pair behind a violation is not recoverable from a
/// finding - so the silo matrix is empty in snapshot mode, by construction.
/// `snapshot` is set last: it is what every live-only action is gated on.
///
/// A report written under `--min-severity` carries the threshold it was
/// filtered at, and that is not a detail the UI may drop: every number on the
/// board is computed from the rows the file happens to contain. See
/// [`filtered_note`].
///
/// A pre-1.2 report predates redaction at the writer, so its `matched` fields
/// may be the credentials themselves, and snapshot mode has no rule set to tell
/// which ones are. Every match is therefore replaced by [`REDACTED_MATCH`]
/// here, in the data, rather than at each pane that draws it: the panes read
/// `matched` for several purposes beyond the match column, and a rule that only
/// covers the drawing code is a rule the next pane forgets.
///
/// One rule is exempt, and only one. [`DUPLICATE_BLOCK_RULE_ID`] is a reserved
/// id: `rules::load_str` refuses to compile a user rule that claims it, so a
/// finding carrying it cannot have come from anywhere but the duplication
/// engine, whose `matched` is the fixed `"N duplicated lines (block HHHH...)"`
/// and never a credential. Redacting it bought no secrecy and cost the whole
/// duplicate-set grouping, which parses the block key back out of that text.
///
/// The coverage tile is deliberately *not* exempted. In snapshot mode it
/// recognises its findings by the shape of `matched` itself
/// (`ui::dashboard::is_coverage_matched`), so exempting it would mean deciding
/// whether to reveal a string by looking at that same string - a secret that
/// happens to read as `12/40 lines (30.0%)` would exempt itself. A compile-time
/// reserved id is a safe signal; text from the report is not. The tile falls
/// back to "no coverage report" on a pre-1.2 snapshot, and the footer says why.
pub fn apply_snapshot(state: &mut AppState, data: SnapshotData, config: Option<&Config>) {
    let hidden = data.hides_match_text();
    let outcome = data.outcome();
    let mut rows = merge_rows(data.findings, data.baselined, data.suppressed);
    if hidden {
        for row in &mut rows {
            if row.finding.rule_id == DUPLICATE_BLOCK_RULE_ID {
                continue;
            }
            row.finding.matched = REDACTED_MATCH.to_string();
        }
    }

    state.rows = rows;
    state.boundary_edges = Vec::new();
    state.metrics = data.metrics;
    state.snapshot_anchor = data.anchor;
    state.saved_outcome = outcome;
    state.snapshot = Some(data.source);
    reset_cursors(state);
    refresh_silos(state, config);
    report_debt(state);

    // The gate first: it is the one claim about the run as a whole, and the two
    // notes after it are about what this screen is not showing. They go on
    // their own row rather than into the status line, which shares its width
    // with the tabs, the bindings and the read-only banner and would clip them.
    let mut notes = vec![outcome_note(state.saved_outcome)];
    if let Some(threshold) = data.min_severity {
        notes.push(filtered_note(threshold));
    }
    if hidden {
        notes.push(HIDDEN_MATCH_NOTE.to_string());
    }
    state.snapshot_notes = notes.join(" | ");
}

/// What the footer says about the gate the saved run was judged against.
///
/// A resolved report records the threshold and whether the unfiltered run
/// reached it, so a filtered report still reads as failed when every failing
/// finding was filtered out of it. A legacy or core-writer report records
/// neither, and saying so is the only honest answer: the rows on screen are not
/// evidence that the run passed, and a footer that stayed silent would let a
/// filtered legacy report read as authoritatively clean.
fn outcome_note(outcome: Option<SavedOutcome>) -> String {
    match outcome {
        None => "saved outcome unavailable".to_string(),
        Some(outcome) if outcome.threshold_reached => {
            format!("saved outcome: fail-on {} reached", outcome.fail_on)
        }
        Some(outcome) => format!("saved outcome: fail-on {} not reached", outcome.fail_on),
    }
}

/// What the footer says about a report that was written under
/// `--min-severity`.
///
/// The writer records the threshold in the report; until this, the UI read the
/// findings and ignored it, so a report that withheld half its findings opened
/// as the whole picture - the debt counts, the module cards and the dashboard
/// all computed off a filtered list and none of them saying so. The rows cannot
/// be recovered from the file, so the only honest thing the UI can do is name
/// the threshold and let the reader go and get an unfiltered report.
///
/// It lands in the footer beside the pre-1.2 match-text note, for the same
/// reason that one is there: this is a statement about what the screen is not
/// showing, and the footer is where the session says those.
fn filtered_note(min_severity: Severity) -> String {
    format!("filtered report: findings below {min_severity} hidden")
}

/// The three finding lists folded into one row list in canonical order (path,
/// line, column, rule id).
fn merge_rows(
    findings: Vec<Finding>,
    baselined: Vec<Finding>,
    suppressed: Vec<Finding>,
) -> Vec<FindingRow> {
    let mut rows: Vec<FindingRow> =
        Vec::with_capacity(findings.len() + baselined.len() + suppressed.len());
    for (findings, status) in [
        (findings, Status::New),
        (baselined, Status::Baselined),
        (suppressed, Status::Suppressed),
    ] {
        rows.extend(
            findings
                .into_iter()
                .map(|finding| FindingRow { finding, status }),
        );
    }

    // Stable: findings sharing a key keep New before Baselined before Suppressed.
    rows.sort_by(|a, b| {
        a.finding
            .path
            .as_bytes()
            .cmp(b.finding.path.as_bytes())
            .then(a.finding.line.cmp(&b.finding.line))
            .then(a.finding.column.cmp(&b.finding.column))
            .then(
                a.finding
                    .rule_id
                    .as_bytes()
                    .cmp(b.finding.rule_id.as_bytes()),
            )
    });
    rows
}

fn reset_cursors(state: &mut AppState) {
    state.selected = 0;
    state.ratchet_cursor = 0;
    state.scroll = Scroll::default();
    state.scan_running = false;
}

fn report_debt(state: &mut AppState) {
    let (new, baselined, suppressed) = state.debt_counts();
    state.status = format!("{new} new, {baselined} baselined, {suppressed} suppressed");
}

/// Rebuild the module cards from the rows and metrics now in `state`.
///
/// Silos come from the config when it declares any, in alphabetical name order
/// (`Config::silos` is a `BTreeMap`, so the file's own order is not kept);
/// otherwise - including a snapshot opened without a config - they fall back to
/// the top-level directories of the paths the report mentions. A config whose
/// silo globs do not compile falls back too rather than dropping the row: the
/// dashboard is not the place that error belongs to.
pub fn refresh_silos(state: &mut AppState, config: Option<&Config>) {
    let declared = config
        .filter(|config| !config.silos.is_empty())
        .and_then(|config| {
            let sets = config.silo_sets().ok()?;
            let order: Vec<String> = config.silos.keys().cloned().collect();
            Some(dashboard::declared_silo_groups(
                &state.metrics.files,
                &state.rows,
                &order,
                |path| config.silo_of(&sets, path).map(str::to_string),
            ))
        });

    let groups = declared
        .unwrap_or_else(|| dashboard::directory_silo_groups(&state.metrics.files, &state.rows));

    state.silo_cards = dashboard::silo_cards(&groups, &state.metrics.files, &state.rows);
    state.silo_groups = groups;
    state.silo_offset = 0;
    state.selected_silo = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::Arc;

    use siloscan_core::rules::{RuleSet, Severity};
    use siloscan_core::scan::SkippedFile;

    use crate::snapshot::{SavedCapability, SavedMarkers, SavedScope, SavedSetup};

    fn finding(rule_id: &str, path: &str, line: u64, column: u64) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: path.to_string(),
            line,
            column,
            column_utf16: column,
            matched: "needle".to_string(),
            fingerprint: format!("{rule_id}:{path}:{line}:{column}"),
        }
    }

    fn state() -> AppState {
        AppState::new(
            PathBuf::from("/repo"),
            Arc::new(RuleSet {
                rules: Vec::new(),
                ..Default::default()
            }),
        )
    }

    fn report() -> ScanReport {
        ScanReport {
            findings: vec![
                finding("z.rule", "src/b.rs", 1, 1),
                finding("a.rule", "src/b.rs", 1, 1),
            ],
            baselined: vec![finding("b.rule", "a.rs", 9, 2)],
            suppressed: vec![
                finding("c.rule", "src/b.rs", 1, 4),
                finding("d.rule", "a.rs", 2, 1),
            ],
            skipped: vec![SkippedFile {
                path: "blob.bin".to_string(),
                reason: "binary".to_string(),
            }],
            ignored: Default::default(),
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn apply_report_merges_into_canonical_order() {
        let mut state = state();
        apply_report(&mut state, report(), None);

        let keys: Vec<(&str, u64, u64, &str)> = state
            .rows
            .iter()
            .map(|row| {
                (
                    row.finding.path.as_str(),
                    row.finding.line,
                    row.finding.column,
                    row.finding.rule_id.as_str(),
                )
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                ("a.rs", 2, 1, "d.rule"),
                ("a.rs", 9, 2, "b.rule"),
                ("src/b.rs", 1, 1, "a.rule"),
                ("src/b.rs", 1, 1, "z.rule"),
                ("src/b.rs", 1, 4, "c.rule"),
            ]
        );
    }

    #[test]
    fn apply_report_maps_each_list_to_its_status() {
        let mut state = state();
        apply_report(&mut state, report(), None);

        let statuses: Vec<Status> = state.rows.iter().map(|row| row.status).collect();
        assert_eq!(
            statuses,
            vec![
                Status::Suppressed,
                Status::Baselined,
                Status::New,
                Status::New,
                Status::Suppressed,
            ]
        );
        assert_eq!(state.debt_counts(), (2, 1, 2));
    }

    #[test]
    fn apply_report_resets_cursors_and_clears_the_running_flag() {
        let mut state = state();
        state.scan_running = true;
        state.selected = 7;
        state.ratchet_cursor = 4;
        state.scroll.table = 12;

        apply_report(&mut state, report(), None);

        assert_eq!(state.selected, 0);
        assert_eq!(state.ratchet_cursor, 0);
        assert_eq!(state.scroll.table, 0);
        assert!(!state.scan_running);
    }

    #[test]
    fn apply_report_on_a_clean_scan_empties_the_rows() {
        let mut state = state();
        apply_report(&mut state, report(), None);
        apply_report(
            &mut state,
            ScanReport {
                findings: Vec::new(),
                baselined: Vec::new(),
                suppressed: Vec::new(),
                skipped: Vec::new(),
                ignored: Default::default(),
                graph: Default::default(),
                boundary_edges: Vec::new(),
                metrics: Default::default(),
                warnings: Vec::new(),
            },
            None,
        );

        assert!(state.rows.is_empty());
        assert!(state.visible_rows().is_empty());
        assert_eq!(state.debt_counts(), (0, 0, 0));
    }

    #[test]
    fn apply_report_maps_boundary_edges_onto_row_indices() {
        let mut state = state();
        let mut report = report();
        // src/b.rs:1:1 a.rule sorts to row 2, a.rs:9:2 b.rule to row 1.
        report.boundary_edges = vec![
            (
                "api".to_string(),
                "db".to_string(),
                report.findings[1].fingerprint.clone(),
            ),
            (
                "web".to_string(),
                "db".to_string(),
                report.baselined[0].fingerprint.clone(),
            ),
            // A fingerprint no row carries is dropped.
            ("web".to_string(), "api".to_string(), "absent".to_string()),
        ];

        apply_report(&mut state, report, None);

        assert_eq!(
            state.boundary_edges,
            vec![
                ("api".to_string(), "db".to_string(), 2),
                ("web".to_string(), "db".to_string(), 1),
            ]
        );
        let matrix = state.silo_matrix().expect("edges make a matrix");
        assert_eq!(matrix.names, vec!["api", "db", "web"]);
    }

    #[test]
    fn apply_report_clears_stale_boundary_edges() {
        let mut state = state();
        state.boundary_edges = vec![("api".to_string(), "db".to_string(), 0)];

        apply_report(&mut state, report(), None);

        assert!(state.boundary_edges.is_empty());
    }

    /// A report at the version this build's core writes, whose match text is
    /// already redacted at the source and is carried through untouched.
    fn snapshot_data() -> SnapshotData {
        snapshot_data_at(siloscan_core::output::SCHEMA_VERSION)
    }

    fn snapshot_data_at(schema_version: &str) -> SnapshotData {
        use siloscan_core::metrics::{FileMetrics, Metrics, MetricsTotals};

        SnapshotData {
            source: "report.json".to_string(),
            schema_version: schema_version.to_string(),
            anchor: Default::default(),
            min_severity: None,
            findings: vec![finding("z.rule", "api/b.rs", 1, 1)],
            baselined: vec![finding("b.rule", "core/a.rs", 9, 2)],
            suppressed: Vec::new(),
            markers: None,
            metrics: Metrics {
                files: std::collections::BTreeMap::from([
                    (
                        "api/b.rs".to_string(),
                        FileMetrics {
                            lines: 100,
                            code_lines: Some(80),
                            duplicated_lines: 20,
                        },
                    ),
                    (
                        "core/a.rs".to_string(),
                        FileMetrics {
                            lines: 60,
                            code_lines: Some(50),
                            duplicated_lines: 0,
                        },
                    ),
                ]),
                totals: MetricsTotals {
                    lines: 160,
                    code_lines: 130,
                    duplicated_lines: 20,
                    duplication_density: 12.5,
                },
            },
        }
    }

    #[test]
    fn apply_snapshot_loads_rows_metrics_and_the_read_only_flag() {
        let mut state = state();
        state.selected = 4;
        state.boundary_edges = vec![("api".to_string(), "db".to_string(), 0)];

        apply_snapshot(&mut state, snapshot_data(), None);

        assert_eq!(state.snapshot.as_deref(), Some("report.json"));
        assert!(state.is_snapshot());
        assert!(!state.scan_running);
        assert_eq!(state.selected, 0);
        assert!(
            state.boundary_edges.is_empty(),
            "a report carries no boundary edges"
        );
        assert_eq!(state.metrics.totals.lines, 160);
        assert_eq!(state.metrics.files["api/b.rs"].duplicated_lines, 20);
        assert_eq!(state.debt_counts(), (1, 1, 0));
        // Same canonical order as a live report.
        let paths: Vec<&str> = state
            .rows
            .iter()
            .map(|row| row.finding.path.as_str())
            .collect();
        assert_eq!(paths, vec!["api/b.rs", "core/a.rs"]);

        // The report's path convention is carried through for the banner.
        let mut anchored = snapshot_data();
        anchored.anchor = siloscan_core::config::Anchor::Config;
        apply_snapshot(&mut state, anchored, None);
        assert_eq!(state.snapshot_anchor, siloscan_core::config::Anchor::Config);
    }

    #[test]
    fn a_snapshot_without_a_config_falls_back_to_directory_silos() {
        let mut state = state();
        apply_snapshot(&mut state, snapshot_data(), None);

        let names: Vec<&str> = state
            .silo_cards
            .iter()
            .map(|card| card.name.as_str())
            .collect();
        assert_eq!(names, vec!["api", "core"]);
        assert_eq!(state.silo_cards[0].loc, 100);
        assert_eq!(state.silo_cards[0].duplication_percent, 20.0);
        assert_eq!(state.silo_groups.len(), state.silo_cards.len());
        assert!(state.silo_groups[0].paths.contains("api/b.rs"));
        assert_eq!(state.selected_silo, None);
        assert_eq!(state.silo_offset, 0);
    }

    #[test]
    fn declared_silos_win_over_the_directory_fallback() {
        let config = Config {
            silos: std::collections::BTreeMap::from([
                ("service".to_string(), vec!["api/**".to_string()]),
                ("engine".to_string(), vec!["core/**".to_string()]),
            ]),
            ..Config::default()
        };

        let mut state = state();
        apply_snapshot(&mut state, snapshot_data(), Some(&config));

        let names: Vec<&str> = state
            .silo_cards
            .iter()
            .map(|card| card.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["engine", "service"],
            "alphabetical name order, not the order the config lists them in"
        );
        assert_eq!(state.silo_cards[1].loc, 100, "service holds api/b.rs");
    }

    #[test]
    fn a_live_report_derives_silo_cards_too_and_stays_writable() {
        let mut state = state();
        let mut report = report();
        report.metrics.files.insert(
            "src/b.rs".to_string(),
            siloscan_core::metrics::FileMetrics {
                lines: 12,
                code_lines: None,
                duplicated_lines: 3,
            },
        );

        apply_report(&mut state, report, None);

        assert!(state.snapshot.is_none(), "a scan is never read-only");
        let names: Vec<&str> = state
            .silo_cards
            .iter()
            .map(|card| card.name.as_str())
            .collect();
        assert_eq!(names, vec![".", "src"]);
        assert_eq!(state.metrics.files["src/b.rs"].lines, 12);
    }

    // -- pre-1.2 reports -------------------------------------------------

    /// Stands in for the credential a 1.1 report carries in the clear.
    const RAW_MATCH: &str = "AKIAIOSFODNN7EXAMPLE";

    /// Every cell of the terminal, one row per line, for a state drawn at this
    /// size. The whole buffer, not one pane: the claim being tested is that no
    /// pane anywhere puts the text on screen.
    fn render_text(state: &AppState, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::ui::draw(frame, state))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();

        let mut out = String::new();
        for y in 0..height {
            for x in 0..width {
                out.push_str(buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()));
            }
            out.push('\n');
        }
        out
    }

    /// A pre-1.2 report with a credential in it, and the rule ids of the two
    /// findings that would otherwise be read out of their match text.
    fn pre_redaction_data() -> SnapshotData {
        let mut data = snapshot_data_at("1.1");
        data.findings[0].matched = RAW_MATCH.to_string();
        data.baselined[0].matched = "20 duplicated lines (block 0123456789ab)".to_string();
        data
    }

    /// The gate accepts a 1.1 report, and a 1.1 report predates redaction at
    /// the writer. With no rule set to say which finding came from a secret
    /// rule, every match goes.
    #[test]
    fn a_pre_one_two_report_renders_no_match_text_anywhere() {
        let mut state = state();
        apply_snapshot(&mut state, pre_redaction_data(), None);

        let matches: Vec<&str> = state
            .rows
            .iter()
            .map(|row| row.finding.matched.as_str())
            .collect();
        assert_eq!(
            matches,
            vec![REDACTED_MATCH, REDACTED_MATCH],
            "the credential survived into the rows"
        );

        // Nothing draws it either, on any screen, at any of the sizes the board
        // lays out for.
        for screen in [
            crate::state::Screen::Dashboard,
            crate::state::Screen::Triage,
            crate::state::Screen::Ratchet,
            crate::state::Screen::Silo,
        ] {
            state.screen = screen;
            for (width, height) in [(200, 50), (80, 24), (40, 12)] {
                let text = render_text(&state, width, height);
                assert!(
                    !text.contains(RAW_MATCH),
                    "{screen:?} at {width}x{height} drew the credential:\n{text}"
                );
                assert!(
                    !text.contains("0123456789ab"),
                    "{screen:?} at {width}x{height} drew match text:\n{text}"
                );
            }
        }
    }

    /// The reserved duplicate-block id is the one exemption, and it has to work
    /// alongside the redaction rather than instead of it: the same report
    /// carries a credential, and that still goes.
    ///
    /// Blanket redaction was correct about secrets and wrong about this: the
    /// block key lives in `matched`, so redacting it dissolved every duplicate
    /// set into ungrouped rows and cost the feature for no secrecy gained.
    #[test]
    fn a_pre_one_two_duplicate_block_survives_while_the_secret_is_redacted() {
        use crate::ui::triage::block_key;

        let mut data = snapshot_data_at("1.1");
        data.findings[0].matched = RAW_MATCH.to_string();
        data.baselined[0].rule_id = DUPLICATE_BLOCK_RULE_ID.to_string();
        data.baselined[0].matched = "20 duplicated lines (block 0123456789ab)".to_string();

        let mut state = state();
        apply_snapshot(&mut state, data, None);

        let secret = state
            .rows
            .iter()
            .find(|row| row.finding.rule_id == "z.rule")
            .expect("the secret finding");
        assert_eq!(
            secret.finding.matched, REDACTED_MATCH,
            "the credential survived the exemption"
        );

        let duplicate = state
            .rows
            .iter()
            .find(|row| row.finding.rule_id == DUPLICATE_BLOCK_RULE_ID)
            .expect("the duplicate-block finding");
        assert_eq!(
            duplicate.finding.matched, "20 duplicated lines (block 0123456789ab)",
            "a reserved-id finding must keep the text its grouping is built on"
        );
        assert_eq!(
            block_key(&duplicate.finding).as_deref(),
            Some("0123456789ab"),
            "the block key must still parse"
        );

        // The exemption is not a hole: nothing draws the credential.
        state.screen = crate::state::Screen::Triage;
        for (width, height) in [(200, 50), (80, 24)] {
            let text = render_text(&state, width, height);
            assert!(
                !text.contains(RAW_MATCH),
                "the credential reached the screen at {width}x{height}:\n{text}"
            );
        }
        // And the notes row still says match text is being withheld.
        assert!(
            state.snapshot_notes.contains(HIDDEN_MATCH_NOTE),
            "{}",
            state.snapshot_notes
        );
    }

    /// Redaction that is not announced is indistinguishable from a report that
    /// had nothing to show, which is the failure this whole fix is about.
    #[test]
    fn a_pre_one_two_report_says_why_the_match_column_is_empty() {
        let mut state = state();
        apply_snapshot(&mut state, pre_redaction_data(), None);

        assert!(
            state.snapshot_notes.contains(HIDDEN_MATCH_NOTE),
            "notes: {}",
            state.snapshot_notes
        );
        assert_eq!(
            state.status, "1 new, 1 baselined, 0 suppressed",
            "the debt counts keep the status line to themselves"
        );

        state.screen = crate::state::Screen::Triage;
        for (width, height) in [(200, 50), (120, 40), (80, 24)] {
            let text = render_text(&state, width, height);
            assert!(
                text.contains(HIDDEN_MATCH_NOTE),
                "not on screen at {width}x{height}:\n{text}"
            );
        }
    }

    /// A 1.2 report was redacted by the writer, so the UI has no reason to
    /// second-guess it and no reason to say anything.
    #[test]
    fn a_current_report_keeps_its_match_text_and_its_status() {
        let mut state = state();
        let mut data = snapshot_data();
        data.findings[0].matched = "20 duplicated lines (block 0123456789ab)".to_string();

        apply_snapshot(&mut state, data, None);

        let kept = state
            .rows
            .iter()
            .any(|row| row.finding.matched == "20 duplicated lines (block 0123456789ab)");
        assert!(kept, "a 1.2 report's match text must be left alone");
        assert_eq!(state.status, "1 new, 1 baselined, 0 suppressed");
        assert_eq!(state.snapshot_notes, "saved outcome unavailable");
    }

    // -- filtered reports ------------------------------------------------

    /// A report written under `--min-severity` is not the whole picture, and
    /// the board draws every number on it from the rows the file carries. Until
    /// the UI says so, a filtered report opened as a clean one - the exact
    /// confusion the writer records the threshold to prevent, reintroduced at
    /// the reader.
    #[test]
    fn a_filtered_snapshot_says_what_it_was_filtered_at() {
        let mut state = state();
        let mut data = snapshot_data();
        data.min_severity = Some(Severity::Error);

        apply_snapshot(&mut state, data, None);

        assert!(
            state
                .snapshot_notes
                .contains("filtered report: findings below error hidden"),
            "notes: {}",
            state.snapshot_notes
        );
        assert_eq!(
            state.status, "1 new, 1 baselined, 0 suppressed",
            "the debt counts are still reported"
        );

        // The notes row is where it has to land, at every size the board lays
        // out for - including the one the status line would clip it at.
        state.screen = crate::state::Screen::Triage;
        for (width, height) in [(200, 50), (120, 40), (80, 24)] {
            let text = render_text(&state, width, height);
            assert!(
                text.contains("filtered report"),
                "not on screen at {width}x{height}:\n{text}"
            );
        }
    }

    /// An unfiltered report says nothing about filtering. It still says its
    /// outcome is unavailable, because a report with no outcome recorded is not
    /// a report of a run that passed.
    #[test]
    fn an_unfiltered_snapshot_says_nothing_about_filtering() {
        let mut state = state();
        apply_snapshot(&mut state, snapshot_data(), None);

        assert_eq!(state.status, "1 new, 1 baselined, 0 suppressed");
        assert_eq!(state.snapshot_notes, "saved outcome unavailable");
    }

    /// Three notices about the same report, in a fixed order: the gate, then
    /// the numbers, then the column.
    #[test]
    fn a_filtered_pre_one_two_snapshot_says_both() {
        let mut state = state();
        let mut data = pre_redaction_data();
        data.min_severity = Some(Severity::Warning);

        apply_snapshot(&mut state, data, None);

        assert_eq!(
            state.snapshot_notes,
            format!(
                "saved outcome unavailable | filtered report: findings below \
                 warning hidden | {HIDDEN_MATCH_NOTE}"
            )
        );
    }

    // -- the saved outcome -----------------------------------------------

    /// The four markers of a resolved report, with the gate `reached` records.
    fn resolved_markers(reached: bool) -> SavedMarkers {
        SavedMarkers {
            scope: SavedScope {
                identity: "sha256-v1:aa".to_string(),
                kind: siloscan_core::plan::ScopeKind::Directory,
                path_base_ancestor_levels: 0,
            },
            outcome: SavedOutcome {
                fail_on: Severity::Error,
                threshold_reached: reached,
            },
            setup: SavedSetup {
                languages: vec!["rust".to_string()],
                capabilities: vec![SavedCapability {
                    id: "cache".to_string(),
                    status: "enabled".to_string(),
                    reason: None,
                }],
                explicit_overrides: Vec::new(),
            },
        }
    }

    /// A resolved report was judged before its findings were filtered, so the
    /// gate it records is the run's answer rather than a count of what is left
    /// on screen.
    #[test]
    fn a_resolved_snapshot_reports_the_gate_its_run_was_judged_against() {
        let mut state = state();
        let mut data = snapshot_data();
        data.findings.clear();
        data.baselined.clear();
        data.min_severity = Some(Severity::Error);
        data.markers = Some(resolved_markers(true));

        apply_snapshot(&mut state, data, None);

        assert_eq!(
            state.saved_outcome,
            Some(SavedOutcome {
                fail_on: Severity::Error,
                threshold_reached: true
            })
        );
        assert_eq!(state.status, "0 new, 0 baselined, 0 suppressed");
        assert_eq!(
            state.snapshot_notes,
            "saved outcome: fail-on error reached | filtered report: findings \
             below error hidden"
        );
    }

    /// A run that passed says so, in the same place and the same words.
    #[test]
    fn a_resolved_snapshot_reports_a_gate_that_was_not_reached() {
        let mut state = state();
        let mut data = snapshot_data();
        data.markers = Some(resolved_markers(false));

        apply_snapshot(&mut state, data, None);

        assert_eq!(state.status, "1 new, 1 baselined, 0 suppressed");
        assert_eq!(
            state.snapshot_notes,
            "saved outcome: fail-on error not reached"
        );
    }

    #[test]
    fn apply_failure_keeps_the_rows_and_reports_the_reason() {
        let mut state = state();
        apply_report(&mut state, report(), None);
        state.scan_running = true;

        apply_failure(&mut state, "rule a.b: unknown silo: db".to_string());

        assert!(!state.scan_running);
        assert_eq!(state.status, "rule a.b: unknown silo: db");
        assert_eq!(state.rows.len(), 5);
    }

    /// A tree with one finding in it, and the request that scans it.
    ///
    /// The cache is off: a session test must not read or write the user's own
    /// cache directory, and a warm entry from a previous run would decide what
    /// this one reports.
    fn needle_project(dir: &std::path::Path) -> ScanRequest {
        use std::fs;

        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/a.rs"), b"let x = \"needle-42\";\n").unwrap();
        // The pattern does not match the rule file that declares it, so the one
        // finding in this tree is the one the fixture put there.
        fs::write(
            dir.join("rules.yaml"),
            "version: 1\nrules:\n  - id: test.needle\n    severity: warning\n    message: \"needle\"\n    regex:\n      pattern: \"needle-[0-9]+\"\n",
        )
        .unwrap();

        ScanRequest::explicit(dir)
            .with_rule_dirs(vec![dir.to_path_buf()])
            .without_embedded_rules()
            .without_cache()
    }

    /// Fold every event of one scan into `state`, and count the progress ticks.
    fn drain(state: &mut AppState, rx: std::sync::mpsc::Receiver<AppEvent>) -> usize {
        let mut progress = 0usize;
        for event in rx {
            match event {
                AppEvent::Progress(p) => {
                    progress += 1;
                    state.progress = Some(p);
                }
                AppEvent::ScanDone(resolved) => {
                    let (report, setup, context) = resolved.into_parts();
                    state.setup = Some(setup);
                    state.rules = Arc::new(context.rules().clone());
                    apply_report(state, report, context.config());
                }
                AppEvent::Failed(e) => apply_failure(state, e),
            }
        }
        progress
    }

    #[test]
    fn spawn_scan_streams_progress_then_the_report() {
        use std::sync::mpsc;

        let dir = tempfile::tempdir().unwrap();
        let request = needle_project(dir.path());
        let plan = ResolvedScanPlan::resolve(&request).expect("the request resolves");

        let (tx, rx) = mpsc::channel();
        spawn_scan(plan, tx);

        let mut state = AppState::new(dir.path().to_path_buf(), Arc::new(RuleSet::default()));
        state.scan_running = true;
        let progress = drain(&mut state, rx);

        assert!(progress >= 2);
        assert!(!state.scan_running);
        assert_eq!(state.rows.len(), 1);
        assert_eq!(state.rows[0].finding.path, "src/a.rs");
        assert_eq!(state.debt_counts(), (1, 0, 0));
        assert!(state.setup.is_some(), "the plan's setup arrives with it");
    }

    /// A rescan resolves its own plan, so what it reports is the tree as it is
    /// now rather than the tree the session booted on.
    #[test]
    fn a_fresh_scan_resolves_the_request_again() {
        use std::fs;
        use std::sync::mpsc;

        let dir = tempfile::tempdir().unwrap();
        let request = needle_project(dir.path());
        let mut state = AppState::new(dir.path().to_path_buf(), Arc::new(RuleSet::default()));

        let (tx, rx) = mpsc::channel();
        spawn_fresh_scan(request.clone(), tx);
        drain(&mut state, rx);
        assert_eq!(state.rows.len(), 1);

        fs::write(dir.path().join("src/a.rs"), b"let x = \"clean\";\n").unwrap();
        let (tx, rx) = mpsc::channel();
        spawn_fresh_scan(request, tx);
        drain(&mut state, rx);

        assert!(state.rows.is_empty(), "the second scan re-walked the tree");
    }

    /// A request that setup refuses is a status line, not a dead session: the
    /// rows already on screen stay, and the reader can fix the config and press
    /// `r` again.
    #[test]
    fn a_fresh_scan_reports_a_setup_refusal_in_the_status_line() {
        use std::sync::mpsc;

        let dir = tempfile::tempdir().unwrap();
        let mut state = AppState::new(dir.path().to_path_buf(), Arc::new(RuleSet::default()));
        apply_report(&mut state, report(), None);

        let (tx, rx) = mpsc::channel();
        spawn_fresh_scan(
            ScanRequest::explicit(dir.path().join("gone")).without_cache(),
            tx,
        );
        drain(&mut state, rx);

        assert!(state.status.contains("gone"), "{}", state.status);
        assert_eq!(state.rows.len(), 5, "a refusal keeps the board");
    }
}
