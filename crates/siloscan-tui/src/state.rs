//! Terminal-free application state. Everything here is plain data plus pure
//! queries, so it can be unit-tested without a backend. The module card types
//! come from `ui::dashboard`, which derives them; they are plain data too, and
//! nothing here renders.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use siloscan_core::config::Anchor;
use siloscan_core::findings::Finding;
use siloscan_core::metrics::Metrics;
use siloscan_core::plan::ScanSetupReport;
use siloscan_core::rules::{RuleSet, Severity};
use siloscan_core::scan::Progress;

use crate::snapshot::SavedOutcome;
use crate::ui::dashboard::{SiloCard, SiloGroup};

/// Why a rescan is refused against a loaded report.
pub const READ_ONLY_RESCAN: &str = "snapshot is read-only: rescan needs a live scan";
/// Why the ratchet cannot accept a finding into the baseline from a snapshot.
pub const READ_ONLY_BASELINE: &str = "snapshot is read-only: the baseline needs a live scan";
/// Why an inline suppression cannot be written from a snapshot.
pub const READ_ONLY_SUPPRESS: &str =
    "snapshot is read-only: inline suppression needs the scanned files";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Screen {
    #[default]
    Dashboard,
    Triage,
    Ratchet,
    Silo,
}

impl Screen {
    pub fn as_str(self) -> &'static str {
        match self {
            Screen::Dashboard => "dashboard",
            Screen::Triage => "triage",
            Screen::Ratchet => "ratchet",
            Screen::Silo => "silo",
        }
    }

    pub const ALL: [Screen; 4] = [
        Screen::Dashboard,
        Screen::Triage,
        Screen::Ratchet,
        Screen::Silo,
    ];

    pub fn next(self) -> Screen {
        match self {
            Screen::Dashboard => Screen::Triage,
            Screen::Triage => Screen::Ratchet,
            Screen::Ratchet => Screen::Silo,
            Screen::Silo => Screen::Dashboard,
        }
    }

    pub fn prev(self) -> Screen {
        match self {
            Screen::Dashboard => Screen::Silo,
            Screen::Triage => Screen::Dashboard,
            Screen::Ratchet => Screen::Triage,
            Screen::Silo => Screen::Ratchet,
        }
    }
}

/// Boundary violations aggregated into a square silo-by-silo matrix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiloMatrix {
    /// Every silo taking part in a violation, ascending.
    pub names: Vec<String>,
    /// `cells[from][to]` is the number of violating findings on that edge.
    pub cells: Vec<Vec<usize>>,
    /// Row indices into `AppState::rows`, ascending, keyed by (from, to).
    pub edges: BTreeMap<(String, String), Vec<usize>>,
}

/// Where a finding sits relative to the baseline and inline suppressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    New,
    Baselined,
    Suppressed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::New => "new",
            Status::Baselined => "baselined",
            Status::Suppressed => "suppressed",
        }
    }

    pub const ALL: [Status; 3] = [Status::New, Status::Baselined, Status::Suppressed];
}

/// Triage filters. An empty set means "no constraint on that axis"; the axes
/// are combined with AND.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filters {
    pub rules: BTreeSet<String>,
    pub severities: BTreeSet<Severity>,
    pub statuses: BTreeSet<Status>,
    /// Report-relative paths a module card handed over. Empty means every path.
    pub paths: BTreeSet<String>,
    pub text: String,
}

impl Filters {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
            && self.severities.is_empty()
            && self.statuses.is_empty()
            && self.paths.is_empty()
            && self.text.is_empty()
    }

    pub fn clear(&mut self) {
        *self = Filters::default();
    }

    pub fn matches(&self, finding: &Finding, status: Status) -> bool {
        if !self.rules.is_empty() && !self.rules.contains(&finding.rule_id) {
            return false;
        }
        if !self.severities.is_empty() && !self.severities.contains(&finding.severity) {
            return false;
        }
        if !self.statuses.is_empty() && !self.statuses.contains(&status) {
            return false;
        }
        if !self.paths.is_empty() && !self.paths.contains(&finding.path) {
            return false;
        }
        if self.text.is_empty() {
            return true;
        }

        let needle = self.text.to_lowercase();
        contains_ignore_case(&finding.path, &needle)
            || contains_ignore_case(&finding.rule_id, &needle)
            || contains_ignore_case(&finding.message, &needle)
    }

    pub fn toggle_rule(&mut self, rule_id: &str) {
        toggle(&mut self.rules, rule_id.to_string());
    }

    pub fn toggle_severity(&mut self, severity: Severity) {
        toggle(&mut self.severities, severity);
    }

    pub fn toggle_status(&mut self, status: Status) {
        toggle(&mut self.statuses, status);
    }
}

fn toggle<T: Ord>(set: &mut BTreeSet<T>, value: T) {
    if !set.remove(&value) {
        set.insert(value);
    }
}

fn contains_ignore_case(haystack: &str, lowercase_needle: &str) -> bool {
    haystack.to_lowercase().contains(lowercase_needle)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    pub finding: Finding,
    pub status: Status,
}

/// Scrollable panes. Offsets are tracked per pane so the wheel affects only
/// the pane under the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pane {
    Sidebar,
    Table,
    Code,
    Dashboard,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Scroll {
    pub sidebar: usize,
    pub table: usize,
    pub code: usize,
    pub dashboard: usize,
}

impl Scroll {
    pub fn get_mut(&mut self, pane: Pane) -> &mut usize {
        match pane {
            Pane::Sidebar => &mut self.sidebar,
            Pane::Table => &mut self.table,
            Pane::Code => &mut self.code,
            Pane::Dashboard => &mut self.dashboard,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub screen: Screen,
    pub filters: Filters,
    /// All rows in canonical order: path, line, column, rule id.
    pub rows: Vec<FindingRow>,
    /// Index into `visible_rows()`, not into `rows`.
    pub selected: usize,
    pub scroll: Scroll,
    pub scan_running: bool,
    pub progress: Option<Progress>,
    /// Index into `new_rows()`.
    pub ratchet_cursor: usize,
    /// Directory the findings' paths are read from, for the source pane.
    pub root: PathBuf,
    /// Directory holding `.siloscan/baseline.json`, which is the scan root
    /// under scan-root anchoring and the config root under config anchoring.
    /// Distinct from `root`: a config-anchored scan of a module measures its
    /// fingerprints from the repository root, so that is where its baseline
    /// lives, and writing one beside the module would ratchet nothing.
    pub baseline_root: PathBuf,
    pub rules: Arc<RuleSet>,
    /// What resolution found for the last live scan. `None` in snapshot mode
    /// and before the first report arrives.
    pub setup: Option<ScanSetupReport>,
    /// Findings accepted in the ratchet console, pending a baseline write.
    pub dirty_baseline: Vec<Finding>,
    /// Boundary violations as (from silo, to silo, index into `rows`).
    pub boundary_edges: Vec<(String, String, usize)>,
    /// Size and duplication of the last report, live or loaded.
    pub metrics: Metrics,
    /// Silo membership behind the module cards. Same order and length as
    /// `silo_cards`: index `i` of one describes index `i` of the other.
    pub silo_groups: Vec<SiloGroup>,
    /// Module cards, derived from `metrics` and `rows`.
    pub silo_cards: Vec<SiloCard>,
    /// First module card shown; the row scrolls rather than shrinking cards.
    pub silo_offset: usize,
    /// Keyboard selection in the module card row, indexing `silo_cards`.
    pub selected_silo: Option<usize>,
    /// File name of the report this session was opened from. `None` in live
    /// mode, and the flag every live-only action is gated on.
    pub snapshot: Option<String>,
    /// Path convention the loaded report used. Config-anchored paths do not
    /// resolve against the working directory, so the banner says so; nothing
    /// else reads it. Meaningless while `snapshot` is `None`.
    pub snapshot_anchor: Anchor,
    /// The gate the loaded report's run was judged against. `None` for a live
    /// session and for a report that records no outcome, which is not the same
    /// as a run that passed. `snapshot_notes` says which of the two it is.
    pub saved_outcome: Option<SavedOutcome>,
    /// What this session is not showing about the report it loaded, drawn on a
    /// row of its own. Empty for a live session, which is not showing anything
    /// but the tree in front of it.
    pub snapshot_notes: String,
    /// True while the filter text box owns the keyboard.
    pub input_mode: bool,
    /// Status bar message.
    pub status: String,
    pub should_quit: bool,
}

impl AppState {
    /// A session over `root` with nothing loaded yet.
    ///
    /// The baseline root starts as the scan root, which is where it stays for
    /// every scan-root-anchored scan; a config-anchored plan replaces it when
    /// its first report arrives.
    pub fn new(root: PathBuf, rules: Arc<RuleSet>) -> Self {
        AppState {
            screen: Screen::default(),
            filters: Filters::default(),
            rows: Vec::new(),
            selected: 0,
            scroll: Scroll::default(),
            scan_running: false,
            progress: None,
            ratchet_cursor: 0,
            baseline_root: root.clone(),
            root,
            rules,
            setup: None,
            dirty_baseline: Vec::new(),
            boundary_edges: Vec::new(),
            metrics: Metrics::default(),
            silo_groups: Vec::new(),
            silo_cards: Vec::new(),
            silo_offset: 0,
            selected_silo: None,
            snapshot: None,
            snapshot_anchor: Anchor::default(),
            saved_outcome: None,
            snapshot_notes: String::new(),
            input_mode: false,
            status: String::new(),
            should_quit: false,
        }
    }

    /// Every key goes to the filter text box while this holds.
    pub fn captures_input(&self) -> bool {
        self.input_mode
    }

    /// True when the findings came from a report file rather than a scan. Every
    /// write the TUI can perform is refused in that mode.
    pub fn is_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }

    /// Gate for a live-only action: reports `reason` in the status line and
    /// returns true when the action must not run. Live sessions are untouched.
    pub fn refuse_if_snapshot(&mut self, reason: &str) -> bool {
        if self.is_snapshot() {
            self.status = reason.to_string();
            true
        } else {
            false
        }
    }

    /// Move the module card selection. The first move from nothing selects the
    /// first card; the selection is clamped to the cards that exist.
    pub fn select_silo(&mut self, delta: isize) {
        if self.silo_cards.is_empty() {
            self.selected_silo = None;
            return;
        }
        let last = self.silo_cards.len() - 1;
        let next = match self.selected_silo {
            None if delta < 0 => last,
            None => 0,
            Some(current) if delta >= 0 => current.saturating_add(delta as usize).min(last),
            Some(current) => current.saturating_sub(delta.unsigned_abs()),
        };
        self.selected_silo = Some(next);
    }

    /// Arm the state for a scan that is about to be spawned.
    pub fn begin_scan(&mut self) {
        self.scan_running = true;
        self.progress = None;
        self.status = "scanning".to_string();
    }

    /// Indices into `rows` that pass the current filters, in canonical order.
    pub fn visible_rows(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| self.filters.matches(&row.finding, row.status))
            .map(|(index, _)| index)
            .collect()
    }

    pub fn visible_len(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| self.filters.matches(&row.finding, row.status))
            .count()
    }

    /// Index into `rows` of the current selection, if anything is visible.
    pub fn selected_index(&self) -> Option<usize> {
        self.visible_rows().get(self.selected).copied()
    }

    pub fn selected_row(&self) -> Option<&FindingRow> {
        self.selected_index().map(|index| &self.rows[index])
    }

    pub fn select_next(&mut self) {
        let len = self.visible_len();
        self.selected = if len == 0 {
            0
        } else {
            (self.selected + 1).min(len - 1)
        };
    }

    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Select by position in the visible list (mouse click on a table row).
    pub fn select_visible(&mut self, position: usize) {
        let len = self.visible_len();
        self.selected = if len == 0 { 0 } else { position.min(len - 1) };
        self.scroll.code = 0;
    }

    /// Keep the selection in range after the filters or rows change.
    pub fn clamp_selection(&mut self) {
        let len = self.visible_len();
        self.selected = if len == 0 {
            0
        } else {
            self.selected.min(len - 1)
        };
    }

    pub fn scroll_by(&mut self, pane: Pane, delta: isize) {
        let offset = self.scroll.get_mut(pane);
        *offset = if delta >= 0 {
            offset.saturating_add(delta as usize)
        } else {
            offset.saturating_sub(delta.unsigned_abs())
        };
    }

    /// Indices into `rows` of findings still failing the scan.
    pub fn new_rows(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.status == Status::New)
            .map(|(index, _)| index)
            .collect()
    }

    pub fn ratchet_index(&self) -> Option<usize> {
        self.new_rows().get(self.ratchet_cursor).copied()
    }

    pub fn ratchet_finding(&self) -> Option<&Finding> {
        self.ratchet_index().map(|index| &self.rows[index].finding)
    }

    pub fn ratchet_next(&mut self) {
        let len = self.new_rows().len();
        self.ratchet_cursor = if len == 0 {
            0
        } else {
            (self.ratchet_cursor + 1).min(len - 1)
        };
    }

    pub fn ratchet_prev(&mut self) {
        self.ratchet_cursor = self.ratchet_cursor.saturating_sub(1);
    }

    /// Verdicts are applied by `actions`, which owns the filesystem writes and
    /// calls this to keep the cursor on the next NEW finding.
    pub fn clamp_ratchet(&mut self) {
        let len = self.new_rows().len();
        self.ratchet_cursor = if len == 0 {
            0
        } else {
            self.ratchet_cursor.min(len - 1)
        };
    }

    /// Severity totals over every row, most severe first. Zero counts are kept
    /// so the chart keeps a stable shape.
    pub fn counts_by_severity(&self) -> Vec<(Severity, usize)> {
        [Severity::Error, Severity::Warning, Severity::Info]
            .into_iter()
            .map(|severity| {
                let count = self
                    .rows
                    .iter()
                    .filter(|row| row.finding.severity == severity)
                    .count();
                (severity, count)
            })
            .collect()
    }

    /// The `n` busiest rules: count descending, then rule id ascending.
    pub fn top_rules(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for row in &self.rows {
            *counts.entry(row.finding.rule_id.as_str()).or_insert(0) += 1;
        }

        let mut ranked: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(id, count)| (id.to_string(), count))
            .collect();
        // BTreeMap already yields ids ascending; a stable sort by count keeps
        // that as the tie-break.
        ranked.sort_by_key(|(_, count)| Reverse(*count));
        ranked.truncate(n);
        ranked
    }

    /// Findings grouped by top-level directory. Files at the scan root are
    /// grouped under ".". Count descending, then name ascending.
    pub fn counts_by_dir(&self) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for row in &self.rows {
            *counts.entry(top_dir(&row.finding.path)).or_insert(0) += 1;
        }

        let mut ranked: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(dir, count)| (dir.to_string(), count))
            .collect();
        ranked.sort_by_key(|(_, count)| Reverse(*count));
        ranked
    }

    /// (new, baselined, suppressed)
    pub fn debt_counts(&self) -> (usize, usize, usize) {
        let mut counts = (0, 0, 0);
        for row in &self.rows {
            match row.status {
                Status::New => counts.0 += 1,
                Status::Baselined => counts.1 += 1,
                Status::Suppressed => counts.2 += 1,
            }
        }
        counts
    }

    /// Boundary violations folded into a square matrix over the silos that
    /// take part in one. `None` when nothing crossed a boundary.
    pub fn silo_matrix(&self) -> Option<SiloMatrix> {
        if self.boundary_edges.is_empty() {
            return None;
        }

        let mut edges: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        for (from, to, row) in &self.boundary_edges {
            edges
                .entry((from.clone(), to.clone()))
                .or_default()
                .push(*row);
        }
        for rows in edges.values_mut() {
            rows.sort_unstable();
            rows.dedup();
        }

        let mut set: BTreeSet<&str> = BTreeSet::new();
        for (from, to) in edges.keys() {
            set.insert(from.as_str());
            set.insert(to.as_str());
        }
        let names: Vec<String> = set.into_iter().map(str::to_string).collect();

        let mut cells = vec![vec![0usize; names.len()]; names.len()];
        for ((from, to), rows) in &edges {
            let (Ok(from), Ok(to)) = (
                names.binary_search_by(|name| name.as_str().cmp(from.as_str())),
                names.binary_search_by(|name| name.as_str().cmp(to.as_str())),
            ) else {
                continue;
            };
            cells[from][to] = rows.len();
        }

        Some(SiloMatrix {
            names,
            cells,
            edges,
        })
    }

    /// Fraction of the scan completed, 0.0 to 1.0.
    pub fn progress_ratio(&self) -> f64 {
        match self.progress {
            Some(progress) if progress.files_total > 0 => {
                (progress.files_done as f64 / progress.files_total as f64).clamp(0.0, 1.0)
            }
            Some(_) => 0.0,
            None => 0.0,
        }
    }
}

fn top_dir(path: &str) -> &str {
    match path.split_once('/') {
        Some((head, _)) if !head.is_empty() => head,
        _ => ".",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_id: &str, severity: Severity, path: &str, line: u64, message: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            message: message.to_string(),
            path: path.to_string(),
            line,
            column: 1,
            column_utf16: 1,
            matched: "needle".to_string(),
            fingerprint: format!("{rule_id}:{path}:{line}"),
        }
    }

    fn row(rule_id: &str, severity: Severity, path: &str, line: u64, status: Status) -> FindingRow {
        FindingRow {
            finding: finding(rule_id, severity, path, line, "hardcoded secret"),
            status,
        }
    }

    fn state(rows: Vec<FindingRow>) -> AppState {
        let mut state = AppState::new(
            PathBuf::from("/repo"),
            Arc::new(RuleSet {
                rules: Vec::new(),
                ..Default::default()
            }),
        );
        state.rows = rows;
        state
    }

    fn sample() -> AppState {
        state(vec![
            row("a.one", Severity::Error, "src/a.rs", 1, Status::New),
            row("b.two", Severity::Warning, "src/b.rs", 2, Status::Baselined),
            row("a.one", Severity::Info, "tests/c.rs", 3, Status::Suppressed),
            row("c.three", Severity::Error, "main.rs", 4, Status::New),
        ])
    }

    #[test]
    fn empty_filters_match_everything() {
        let filters = Filters::default();
        let state = sample();
        for row in &state.rows {
            assert!(filters.matches(&row.finding, row.status));
        }
    }

    #[test]
    fn rule_axis_filters_alone() {
        let mut filters = Filters::default();
        filters.toggle_rule("a.one");

        let f = finding("a.one", Severity::Info, "src/a.rs", 1, "m");
        assert!(filters.matches(&f, Status::New));
        let other = finding("b.two", Severity::Info, "src/a.rs", 1, "m");
        assert!(!filters.matches(&other, Status::New));
    }

    #[test]
    fn severity_axis_filters_alone() {
        let mut filters = Filters::default();
        filters.toggle_severity(Severity::Error);

        assert!(filters.matches(&finding("r", Severity::Error, "a.rs", 1, "m"), Status::New));
        assert!(!filters.matches(&finding("r", Severity::Info, "a.rs", 1, "m"), Status::New));
    }

    #[test]
    fn status_axis_filters_alone() {
        let mut filters = Filters::default();
        filters.toggle_status(Status::New);

        let f = finding("r", Severity::Info, "a.rs", 1, "m");
        assert!(filters.matches(&f, Status::New));
        assert!(!filters.matches(&f, Status::Baselined));
        assert!(!filters.matches(&f, Status::Suppressed));
    }

    #[test]
    fn text_axis_is_case_insensitive_over_path_rule_and_message() {
        let f = finding(
            "secret.aws",
            Severity::Info,
            "src/Deep/Key.rs",
            1,
            "Hardcoded Token",
        );

        let mut filters = Filters::default();
        for needle in ["deep/key", "SECRET.AWS", "hardcoded token"] {
            filters.text = needle.to_string();
            assert!(filters.matches(&f, Status::New), "{needle}");
        }

        filters.text = "nowhere".to_string();
        assert!(!filters.matches(&f, Status::New));
    }

    #[test]
    fn axes_combine_with_and() {
        let mut filters = Filters::default();
        filters.toggle_severity(Severity::Error);
        filters.toggle_status(Status::New);
        filters.text = "src".to_string();

        let hit = finding("r", Severity::Error, "src/a.rs", 1, "m");
        assert!(filters.matches(&hit, Status::New));
        // Right severity and status, wrong path.
        let miss = finding("r", Severity::Error, "lib/a.rs", 1, "m");
        assert!(!filters.matches(&miss, Status::New));
        // Right path and severity, wrong status.
        assert!(!filters.matches(&hit, Status::Baselined));
    }

    #[test]
    fn path_axis_filters_alone() {
        let filters = Filters {
            paths: BTreeSet::from(["src/a.rs".to_string()]),
            ..Filters::default()
        };
        assert!(!filters.is_empty());

        let f = finding("r", Severity::Info, "src/a.rs", 1, "m");
        assert!(filters.matches(&f, Status::New));
        let other = finding("r", Severity::Info, "src/b.rs", 1, "m");
        assert!(!filters.matches(&other, Status::New));

        let mut cleared = filters;
        cleared.clear();
        assert!(cleared.paths.is_empty());
        assert!(cleared.matches(&other, Status::New));
    }

    #[test]
    fn a_snapshot_refuses_live_only_actions_with_a_reason() {
        let mut state = sample();
        assert!(!state.is_snapshot());
        assert!(!state.refuse_if_snapshot(READ_ONLY_RESCAN));
        assert!(state.status.is_empty());

        state.snapshot = Some("report.json".to_string());
        assert!(state.is_snapshot());
        assert!(state.refuse_if_snapshot(READ_ONLY_BASELINE));
        assert_eq!(state.status, READ_ONLY_BASELINE);
    }

    #[test]
    fn silo_selection_clamps_to_the_cards_that_exist() {
        let mut state = sample();
        state.select_silo(1);
        assert_eq!(state.selected_silo, None, "no cards, no selection");

        state.silo_cards = ["api", "core"]
            .into_iter()
            .map(|name| SiloCard {
                name: name.to_string(),
                error_count: 0,
                warning_count: 0,
                info_count: 0,
                loc: 0,
                duplication_percent: 0.0,
            })
            .collect();

        state.select_silo(1);
        assert_eq!(
            state.selected_silo,
            Some(0),
            "the first move lands on card 0"
        );
        state.select_silo(1);
        state.select_silo(1);
        assert_eq!(state.selected_silo, Some(1), "clamped to the last card");
        state.select_silo(-1);
        state.select_silo(-1);
        assert_eq!(state.selected_silo, Some(0), "clamped to the first card");
    }

    #[test]
    fn toggling_a_filter_twice_clears_it() {
        let mut filters = Filters::default();
        filters.toggle_rule("a.one");
        assert!(!filters.is_empty());
        filters.toggle_rule("a.one");
        assert!(filters.is_empty());
    }

    #[test]
    fn visible_rows_reports_indices_into_rows() {
        let mut state = sample();
        state.filters.toggle_rule("a.one");

        assert_eq!(state.visible_rows(), vec![0, 2]);
        assert_eq!(state.visible_len(), 2);

        state.filters.toggle_severity(Severity::Error);
        assert_eq!(state.visible_rows(), vec![0]);

        state.filters.clear();
        assert_eq!(state.visible_rows(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn selection_is_clamped_over_visible_rows() {
        let mut state = sample();
        assert_eq!(state.selected, 0);

        for _ in 0..10 {
            state.select_next();
        }
        assert_eq!(state.selected, 3);
        assert_eq!(state.selected_index(), Some(3));

        for _ in 0..10 {
            state.select_prev();
        }
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn selection_clamps_when_filters_shrink_the_list() {
        let mut state = sample();
        state.select_next();
        state.select_next();
        state.select_next();
        assert_eq!(state.selected, 3);

        state.filters.toggle_status(Status::New);
        state.clamp_selection();

        assert_eq!(state.selected, 1);
        assert_eq!(state.selected_index(), Some(3));
        assert_eq!(state.selected_row().unwrap().finding.rule_id, "c.three");
    }

    #[test]
    fn selection_stays_zero_with_nothing_visible() {
        let mut state = state(Vec::new());
        state.select_next();
        state.select_prev();
        assert_eq!(state.selected, 0);
        assert_eq!(state.selected_index(), None);
        assert!(state.selected_row().is_none());
    }

    #[test]
    fn select_visible_clamps_click_targets() {
        let mut state = sample();
        state.select_visible(99);
        assert_eq!(state.selected, 3);
        state.select_visible(1);
        assert_eq!(state.selected, 1);
    }

    #[test]
    fn scroll_offsets_are_per_pane_and_saturate() {
        let mut state = sample();
        state.scroll_by(Pane::Table, 3);
        state.scroll_by(Pane::Code, 1);
        assert_eq!(state.scroll.table, 3);
        assert_eq!(state.scroll.code, 1);
        assert_eq!(state.scroll.sidebar, 0);

        state.scroll_by(Pane::Table, -10);
        assert_eq!(state.scroll.table, 0);
    }

    #[test]
    fn counts_by_severity_keeps_all_three_buckets() {
        let state = sample();
        assert_eq!(
            state.counts_by_severity(),
            vec![
                (Severity::Error, 2),
                (Severity::Warning, 1),
                (Severity::Info, 1),
            ]
        );
    }

    #[test]
    fn top_rules_breaks_ties_by_rule_id() {
        let state = state(vec![
            row("z.rule", Severity::Info, "a.rs", 1, Status::New),
            row("a.rule", Severity::Info, "b.rs", 1, Status::New),
            row("m.rule", Severity::Info, "c.rs", 1, Status::New),
            row("m.rule", Severity::Info, "c.rs", 2, Status::New),
        ]);

        assert_eq!(
            state.top_rules(3),
            vec![
                ("m.rule".to_string(), 2),
                ("a.rule".to_string(), 1),
                ("z.rule".to_string(), 1),
            ]
        );
        assert_eq!(state.top_rules(1), vec![("m.rule".to_string(), 2)]);
        assert!(state.top_rules(0).is_empty());
    }

    #[test]
    fn top_rules_is_independent_of_row_order() {
        let mut forward = sample();
        forward
            .rows
            .push(row("b.two", Severity::Info, "x.rs", 9, Status::New));
        let mut reversed = forward.clone();
        reversed.rows.reverse();

        assert_eq!(forward.top_rules(5), reversed.top_rules(5));
    }

    #[test]
    fn counts_by_dir_groups_at_depth_one() {
        let state = sample();
        assert_eq!(
            state.counts_by_dir(),
            vec![
                ("src".to_string(), 2),
                (".".to_string(), 1),
                ("tests".to_string(), 1),
            ]
        );
    }

    #[test]
    fn debt_counts_partition_the_rows() {
        let state = sample();
        assert_eq!(state.debt_counts(), (2, 1, 1));
    }

    #[test]
    fn ratchet_walks_only_new_findings() {
        let mut state = sample();
        assert_eq!(state.new_rows(), vec![0, 3]);
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "a.one");

        state.ratchet_next();
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "c.three");
        state.ratchet_next();
        assert_eq!(state.ratchet_cursor, 1);

        state.ratchet_prev();
        state.ratchet_prev();
        assert_eq!(state.ratchet_cursor, 0);
    }

    #[test]
    fn clamping_keeps_the_cursor_on_the_next_new_finding() {
        let mut state = sample();

        // What `actions::accept_baseline` does to the row it accepts.
        state.rows[0].status = Status::Baselined;
        state.clamp_ratchet();
        assert_eq!(state.debt_counts(), (1, 2, 1));
        // Cursor kept, list shrank: it now points at the next NEW finding.
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "c.three");

        state.rows[3].status = Status::Suppressed;
        state.clamp_ratchet();
        assert_eq!(state.debt_counts(), (0, 2, 2));
        assert!(state.ratchet_finding().is_none());
        assert_eq!(state.ratchet_cursor, 0);
    }

    #[test]
    fn begin_scan_arms_the_state() {
        let mut state = sample();
        state.progress = Some(Progress {
            files_total: 9,
            files_done: 9,
            findings: 4,
        });

        state.begin_scan();

        assert!(state.scan_running);
        assert!(state.progress.is_none());
        assert!(!state.status.is_empty());
    }

    #[test]
    fn input_mode_gates_key_capture() {
        let mut state = sample();
        assert!(!state.captures_input());
        state.input_mode = true;
        assert!(state.captures_input());
    }

    #[test]
    fn progress_ratio_handles_missing_and_empty_scans() {
        let mut state = sample();
        assert_eq!(state.progress_ratio(), 0.0);

        state.progress = Some(Progress {
            files_total: 0,
            files_done: 0,
            findings: 0,
        });
        assert_eq!(state.progress_ratio(), 0.0);

        state.progress = Some(Progress {
            files_total: 4,
            files_done: 1,
            findings: 2,
        });
        assert_eq!(state.progress_ratio(), 0.25);
    }

    #[test]
    fn silo_matrix_is_none_without_boundary_edges() {
        assert!(sample().silo_matrix().is_none());
    }

    #[test]
    fn silo_matrix_counts_each_edge_and_keeps_names_sorted() {
        let mut state = sample();
        state.boundary_edges = vec![
            ("web".to_string(), "db".to_string(), 3),
            ("api".to_string(), "db".to_string(), 1),
            ("api".to_string(), "db".to_string(), 0),
            // A duplicate row on the same edge counts once.
            ("api".to_string(), "db".to_string(), 0),
        ];

        let matrix = state.silo_matrix().unwrap();
        assert_eq!(matrix.names, vec!["api", "db", "web"]);
        assert_eq!(
            matrix.cells,
            vec![vec![0, 2, 0], vec![0, 0, 0], vec![0, 1, 0]]
        );
        assert_eq!(
            matrix.edges[&("api".to_string(), "db".to_string())],
            vec![0, 1]
        );
        assert_eq!(
            matrix.edges[&("web".to_string(), "db".to_string())],
            vec![3]
        );
        assert_eq!(matrix.edges.len(), 2);
    }

    #[test]
    fn silo_matrix_is_independent_of_edge_order() {
        let mut forward = sample();
        forward.boundary_edges = vec![
            ("api".to_string(), "web".to_string(), 2),
            ("web".to_string(), "api".to_string(), 0),
            ("api".to_string(), "web".to_string(), 1),
        ];
        let mut reversed = forward.clone();
        reversed.boundary_edges.reverse();

        assert_eq!(forward.silo_matrix(), reversed.silo_matrix());
    }

    #[test]
    fn top_rules_lists_every_distinct_rule() {
        let ids: Vec<String> = sample()
            .top_rules(8)
            .into_iter()
            .map(|(rule, _)| rule)
            .collect();
        assert_eq!(ids, vec!["a.one", "b.two", "c.three"]);
    }
}
