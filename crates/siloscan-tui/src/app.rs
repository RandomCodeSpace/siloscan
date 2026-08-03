//! Scan lifecycle: run the core scanner off the UI thread and fold its result
//! back into `AppState`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread;

use siloscan_core::baseline::Baseline;
use siloscan_core::rules::RuleSet;
use siloscan_core::scan::{self, Progress, ScanReport};

use crate::state::{AppState, FindingRow, Scroll, Status};

/// The report is boxed so a progress tick, which is the common event by far,
/// stays small.
#[derive(Debug, Clone)]
pub enum AppEvent {
    Progress(Progress),
    ScanDone(Box<ScanReport>),
}

/// Run a scan on a worker thread, streaming progress and then the report.
/// Send failures mean the UI is gone, which is not an error worth reporting.
pub fn spawn_scan(
    root: PathBuf,
    rules: Arc<RuleSet>,
    baseline: Option<Arc<Baseline>>,
    tx: Sender<AppEvent>,
) {
    thread::spawn(move || {
        let progress_tx = tx.clone();
        let mut on_progress = |progress: Progress| {
            let _ = progress_tx.send(AppEvent::Progress(progress));
        };
        let report = scan::scan_with_progress(&root, &rules, baseline.as_deref(), &mut on_progress);
        let _ = tx.send(AppEvent::ScanDone(Box::new(report)));
    });
}

/// Replace the rows with the report's findings, merged back into canonical
/// order (path, line, column, rule id) across all three statuses.
pub fn apply_report(state: &mut AppState, report: ScanReport) {
    let mut rows: Vec<FindingRow> = Vec::with_capacity(
        report.findings.len() + report.baselined.len() + report.suppressed.len(),
    );
    for (findings, status) in [
        (report.findings, Status::New),
        (report.baselined, Status::Baselined),
        (report.suppressed, Status::Suppressed),
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

    state.rows = rows;
    state.selected = 0;
    state.ratchet_cursor = 0;
    state.scroll = Scroll::default();
    state.scan_running = false;
    let (new, baselined, suppressed) = state.debt_counts();
    state.status = format!("{new} new, {baselined} baselined, {suppressed} suppressed");
}

#[cfg(test)]
mod tests {
    use super::*;

    use siloscan_core::findings::Finding;
    use siloscan_core::rules::Severity;
    use siloscan_core::scan::SkippedFile;

    fn finding(rule_id: &str, path: &str, line: u64, column: u64) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: path.to_string(),
            line,
            column,
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
            None,
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
            graph: Default::default(),
        }
    }

    #[test]
    fn apply_report_merges_into_canonical_order() {
        let mut state = state();
        apply_report(&mut state, report());

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
        apply_report(&mut state, report());

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

        apply_report(&mut state, report());

        assert_eq!(state.selected, 0);
        assert_eq!(state.ratchet_cursor, 0);
        assert_eq!(state.scroll.table, 0);
        assert!(!state.scan_running);
    }

    #[test]
    fn apply_report_on_a_clean_scan_empties_the_rows() {
        let mut state = state();
        apply_report(&mut state, report());
        apply_report(
            &mut state,
            ScanReport {
                findings: Vec::new(),
                baselined: Vec::new(),
                suppressed: Vec::new(),
                skipped: Vec::new(),
                graph: Default::default(),
            },
        );

        assert!(state.rows.is_empty());
        assert!(state.visible_rows().is_empty());
        assert_eq!(state.debt_counts(), (0, 0, 0));
    }

    #[test]
    fn spawn_scan_streams_progress_then_the_report() {
        use siloscan_core::rules::load_str;
        use std::fs;
        use std::sync::mpsc;

        let dir = std::env::temp_dir().join(format!("siloscan-tui-app-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/a.rs"), b"let x = needle;\n").unwrap();

        let rules = Arc::new(RuleSet {
            rules: load_str(
                "version: 1\nrules:\n  - id: test.needle\n    severity: warning\n    message: \"needle\"\n    regex:\n      pattern: \"needle\"\n",
                "test",
            )
            .unwrap(), ..Default::default() });

        let (tx, rx) = mpsc::channel();
        spawn_scan(dir.clone(), Arc::clone(&rules), None, tx);

        let mut progress = 0usize;
        let mut state = AppState::new(dir.clone(), Arc::clone(&rules), None);
        state.scan_running = true;
        for event in rx {
            match event {
                AppEvent::Progress(p) => {
                    progress += 1;
                    state.progress = Some(p);
                }
                AppEvent::ScanDone(report) => apply_report(&mut state, *report),
            }
        }

        assert!(progress >= 2);
        assert!(!state.scan_running);
        assert_eq!(state.rows.len(), 1);
        assert_eq!(state.rows[0].finding.path, "src/a.rs");
        assert_eq!(state.debt_counts(), (1, 0, 0));

        let _ = fs::remove_dir_all(&dir);
    }
}
