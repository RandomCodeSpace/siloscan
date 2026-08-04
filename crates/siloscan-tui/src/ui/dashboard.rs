//! Dashboard screen: a stats board over the whole scan.
//!
//! Deliberately free of file-level detail, which belongs to the triage screen.
//! Rows are laid out top to bottom by importance - quality gate, KPI cards,
//! silo cards, charts, debt strip - and dropped bottom-up when the terminal is
//! short, so a nine-row strip still carries the gate and the KPI cards.
//!
//! Both card rows are clickable: each card records its rectangle in the
//! `LayoutMap`, `open_card` turns a click on a KPI into the equivalent triage
//! filter, and `open_silo_card` does the same for a module card.
//!
//! Silo cards are rendered from a prepared `Vec<SiloCard>`: the derivation
//! ([`declared_silo_groups`], [`directory_silo_groups`], [`silo_cards`]) is
//! pure, sorted, and independent of the terminal, so the row draws the same
//! numbers from a live scan and from a loaded snapshot.

use std::collections::{BTreeMap, BTreeSet};

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Bar, BarChart, Gauge, Paragraph};

use siloscan_core::findings::sanitize_for_terminal;
use siloscan_core::metrics::FileMetrics;
use siloscan_core::rules::{CompiledPayload, Severity};

use crate::state::{AppState, FindingRow, Screen, Status};
use crate::ui::LayoutMap;
use crate::ui::theme;

/// Below this width nothing on the dashboard is legible.
const MIN_COLS: u16 = 30;
/// Quality gate banner: border plus one line.
const GATE_ROWS: u16 = 3;
/// KPI card with block-glyph digits: border, three glyph rows, label.
const CARD_ROWS: u16 = 6;
/// KPI card with the plain number instead of glyphs.
const CARD_MIN_ROWS: u16 = 3;
/// Below this a chart is a border and a rumour.
const CHART_MIN_ROWS: u16 = 7;
/// Debt gauge and coverage tile.
const BOTTOM_ROWS: u16 = 3;
/// Narrowest a KPI card is allowed to be before one is dropped.
const CARD_MIN_COLS: u16 = 12;
/// Widths at which the charts row carries two and three columns.
const TWO_CHART_COLS: u16 = 48;
const THREE_CHART_COLS: u16 = 72;
/// Rows kept in the rules and hotspot lists at most.
const LIST_ROWS: usize = 8;

/// Silo card: border, severity mini-bar, size line.
const SILO_CARD_ROWS: u16 = 4;
/// Narrowest a silo card stays readable at: twelve columns inside the border,
/// which is what the size line needs.
const SILO_CARD_COLS: u16 = 16;
/// Wrapped rows of silo cards the board spends at most; past that the row
/// scrolls instead of eating the charts.
const SILO_MAX_ROWS: u16 = 2;
/// Columns reserved for the scroll indicator when the cards overflow.
const SILO_INDICATOR_COLS: u16 = 5;
/// Silo cards that can be hit-tested at once. The row never draws more than
/// this many, whatever the terminal width.
pub const MAX_SILO_HITS: usize = 24;
/// Widest the severity mini-bar is drawn, however wide the card is.
const SILO_BAR_MAX: usize = 24;
/// Card collecting the files no declared silo claims.
pub const UNASSIGNED_SILO: &str = "(unassigned)";

/// A KPI tile. The order is the render order, left to right, and the tail is
/// what gets dropped on a narrow terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Card {
    Errors,
    Warnings,
    Info,
    New,
    Debt,
    Rating,
    Duplication,
}

impl Card {
    pub const COUNT: usize = 7;
    pub const ALL: [Card; Card::COUNT] = [
        Card::Errors,
        Card::Warnings,
        Card::Info,
        Card::New,
        Card::Debt,
        Card::Rating,
        Card::Duplication,
    ];

    pub fn index(self) -> usize {
        match self {
            Card::Errors => 0,
            Card::Warnings => 1,
            Card::Info => 2,
            Card::New => 3,
            Card::Debt => 4,
            Card::Rating => 5,
            Card::Duplication => 6,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Card::Errors => "Errors",
            Card::Warnings => "Warnings",
            Card::Info => "Info",
            Card::New => "New",
            Card::Debt => "Debt",
            Card::Rating => "Rating",
            Card::Duplication => "Duplication",
        }
    }

    /// What the tile prints, big: a count, the rating letter, or the
    /// duplication density.
    pub fn value(self, state: &AppState) -> String {
        let (new, baselined, suppressed) = state.debt_counts();
        match self {
            Card::Errors => severity_total(state, Severity::Error).to_string(),
            Card::Warnings => severity_total(state, Severity::Warning).to_string(),
            Card::Info => severity_total(state, Severity::Info).to_string(),
            Card::New => new.to_string(),
            Card::Debt => (baselined + suppressed).to_string(),
            Card::Rating => rating(state).to_string(),
            Card::Duplication => {
                format!("{:.1}%", state.metrics.totals.duplication_density)
            }
        }
    }

    /// Second line of the tile, under the value. Only the duplication card has
    /// one: the density alone does not say how much code it stands for.
    pub fn detail(self, state: &AppState) -> Option<String> {
        match self {
            Card::Duplication => Some(format!(
                "{} dup lines",
                state.metrics.totals.duplicated_lines
            )),
            _ => None,
        }
    }

    /// Border and text color of the tile.
    pub fn color(self, state: &AppState) -> Color {
        match self {
            Card::Errors => theme::ERROR,
            Card::Warnings => theme::WARNING,
            Card::Info => theme::INFO,
            Card::New => theme::ACCENT,
            Card::Debt => theme::DIM,
            Card::Rating => rating_color(rating(state)),
            // Duplicate blocks are reported at info severity; the tile matches
            // the findings it opens rather than inventing a threshold.
            Card::Duplication => theme::INFO,
        }
    }
}

/// One module card: the severity split, the size and the duplication of one
/// silo. Derived from `metrics.files` and the findings - the report stores no
/// per-silo rollups, by design.
#[derive(Debug, Clone, PartialEq)]
pub struct SiloCard {
    pub name: String,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    /// Non-blank physical lines over the silo's files.
    pub loc: u64,
    /// `duplicated_lines / loc * 100`, zero when the silo has no lines.
    pub duplication_percent: f64,
}

impl SiloCard {
    pub fn findings(&self) -> usize {
        self.error_count + self.warning_count + self.info_count
    }

    /// Accent color of the card: the worst severity present, or `OK` for a
    /// silo with nothing to act on.
    pub fn accent(&self) -> Color {
        if self.error_count > 0 {
            theme::ERROR
        } else if self.warning_count > 0 {
            theme::WARNING
        } else if self.info_count > 0 {
            theme::INFO
        } else {
            theme::OK
        }
    }
}

/// The paths one silo owns. Kept beside the cards so a click can filter triage
/// by membership instead of guessing at a path prefix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiloGroup {
    pub name: String,
    /// Report-relative paths, ascending.
    pub paths: BTreeSet<String>,
}

/// Silo card rectangle recorded for hit-testing, with the index into the full
/// card list it stands for - the row scrolls, so the visible slot is not the
/// card index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiloHit {
    pub area: Rect,
    pub index: usize,
}

/// Groups for the silos declared in the config. `order` fixes the card order and
/// is used exactly as given - the caller passes the config's silo names, which
/// come out of a `BTreeMap` and are therefore in alphabetical order, not in the
/// order the config file lists them; `assign` maps a report path to the silo
/// owning it (`Config::silo_of` over `Config::silo_sets`). Every declared silo
/// gets a card even when it holds nothing, so the row does not change shape
/// between scans; paths no silo claims land in a trailing `(unassigned)` card,
/// which is emitted only when it is non-empty.
pub fn declared_silo_groups<F>(
    files: &BTreeMap<String, FileMetrics>,
    rows: &[FindingRow],
    order: &[String],
    assign: F,
) -> Vec<SiloGroup>
where
    F: Fn(&str) -> Option<String>,
{
    let mut groups: Vec<SiloGroup> = order
        .iter()
        .map(|name| SiloGroup {
            name: name.clone(),
            paths: BTreeSet::new(),
        })
        .collect();
    let mut unassigned = SiloGroup {
        name: UNASSIGNED_SILO.to_string(),
        paths: BTreeSet::new(),
    };

    for path in all_paths(files, rows) {
        match assign(&path) {
            Some(silo) => match groups.iter_mut().find(|group| group.name == silo) {
                Some(group) => {
                    group.paths.insert(path);
                }
                // A silo the assignment knows and the order does not: keep the
                // file rather than lose it.
                None => {
                    unassigned.paths.insert(path);
                }
            },
            None => {
                unassigned.paths.insert(path);
            }
        }
    }

    if !unassigned.paths.is_empty() {
        groups.push(unassigned);
    }
    groups
}

/// Fallback grouping when no silo is declared: top-level directory of every
/// path, ascending. Files at the report root group under ".". Nothing is
/// unassigned here - every path has a top-level segment.
pub fn directory_silo_groups(
    files: &BTreeMap<String, FileMetrics>,
    rows: &[FindingRow],
) -> Vec<SiloGroup> {
    let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in all_paths(files, rows) {
        groups
            .entry(top_dir(&path).to_string())
            .or_default()
            .insert(path);
    }
    groups
        .into_iter()
        .map(|(name, paths)| SiloGroup { name, paths })
        .collect()
}

/// Every path the report mentions, ascending and deduplicated: measured files
/// first, plus any path that only a finding names.
fn all_paths(files: &BTreeMap<String, FileMetrics>, rows: &[FindingRow]) -> BTreeSet<String> {
    let mut paths: BTreeSet<String> = files.keys().cloned().collect();
    paths.extend(rows.iter().map(|row| row.finding.path.clone()));
    paths
}

/// Roll the groups up into cards. Counts cover every finding, whatever its
/// status, to match the KPI row; lines and duplication come from
/// `metrics.files` and stay at zero for a silo no file was measured in.
pub fn silo_cards(
    groups: &[SiloGroup],
    files: &BTreeMap<String, FileMetrics>,
    rows: &[FindingRow],
) -> Vec<SiloCard> {
    groups
        .iter()
        .map(|group| {
            let mut card = SiloCard {
                name: group.name.clone(),
                error_count: 0,
                warning_count: 0,
                info_count: 0,
                loc: 0,
                duplication_percent: 0.0,
            };

            for row in rows {
                if !group.paths.contains(&row.finding.path) {
                    continue;
                }
                match row.finding.severity {
                    Severity::Error => card.error_count += 1,
                    Severity::Warning => card.warning_count += 1,
                    Severity::Info => card.info_count += 1,
                }
            }

            let mut duplicated: u64 = 0;
            for path in &group.paths {
                if let Some(metrics) = files.get(path) {
                    card.loc += metrics.lines;
                    duplicated += metrics.duplicated_lines;
                }
            }
            card.duplication_percent = if card.loc == 0 {
                0.0
            } else {
                duplicated as f64 / card.loc as f64 * 100.0
            };

            card
        })
        .collect()
}

/// Total findings of one severity, whatever their status.
fn severity_total(state: &AppState, severity: Severity) -> usize {
    state
        .counts_by_severity()
        .into_iter()
        .find(|(candidate, _)| *candidate == severity)
        .map_or(0, |(_, count)| count)
}

/// New findings of one severity: what the quality gate and the rating judge.
fn new_total(state: &AppState, severity: Severity) -> usize {
    state
        .rows
        .iter()
        .filter(|row| row.status == Status::New && row.finding.severity == severity)
        .count()
}

/// SonarQube-style letter over the new findings only: the baseline is by
/// definition already accepted debt.
pub fn rating(state: &AppState) -> char {
    let errors = new_total(state, Severity::Error);
    let warnings = new_total(state, Severity::Warning);
    match (errors, warnings) {
        (0, 0) => 'A',
        (0, _) => 'B',
        (1..=5, _) => 'C',
        (6..=20, _) => 'D',
        _ => 'E',
    }
}

fn rating_color(rating: char) -> Color {
    match rating {
        'A' => theme::OK,
        'B' => theme::WARNING,
        'C' => theme::ERROR_SOFT,
        _ => theme::ERROR,
    }
}

/// Clicking a card is the same as arriving at triage with that filter set. The
/// rating is a verdict, not an axis, so it is inert. The duplication card is
/// the drill-down entry point: it filters to the reserved duplicate-block rule
/// and turns block grouping on, so triage opens on the duplicate sets rather
/// than on a flat list of copies.
pub fn open_card(state: &mut AppState, card: Card) {
    let mut filters = crate::state::Filters::default();
    match card {
        Card::Errors => filters.toggle_severity(Severity::Error),
        Card::Warnings => filters.toggle_severity(Severity::Warning),
        Card::Info => filters.toggle_severity(Severity::Info),
        Card::New => filters.toggle_status(Status::New),
        Card::Debt => {
            filters.toggle_status(Status::Baselined);
            filters.toggle_status(Status::Suppressed);
        }
        // The duplicate sets are triage's grouped view, and triage owns that
        // transition: filter, screen, grouping and cursor in one call.
        Card::Duplication => return crate::ui::triage::open_duplication(state),
        Card::Rating => return,
    }

    open_triage(state, filters);
}

/// Clicking a module card filters triage to the paths that silo owns.
/// `index` indexes `state.silo_groups`, which is what the row hit-tests to.
/// A declared silo can own nothing - its globs matched no file in the report -
/// and an empty path set is "no constraint" to `Filters::matches`, so opening
/// triage on it would show the whole board as if it were that module. Say so in
/// the status bar and stay put instead.
pub fn open_silo_card(state: &mut AppState, index: usize) {
    let Some(group) = state.silo_groups.get(index) else {
        return;
    };
    if group.paths.is_empty() {
        state.status = format!("{}: no files in this report", group.name);
        return;
    }

    let filters = crate::state::Filters {
        paths: group.paths.clone(),
        ..crate::state::Filters::default()
    };
    open_triage(state, filters);
}

fn open_triage(state: &mut AppState, filters: crate::state::Filters) {
    state.filters = filters;
    state.screen = Screen::Triage;
    state.selected = 0;
    state.clamp_selection();
    state.scroll.table = 0;
    state.scroll.code = 0;
}

/// Which rows of the board fit. Sections are dropped from the bottom up; a
/// leftover too short for the charts still goes to the debt strip, which reads
/// fine in three rows. The silo row sits above the charts and outlives them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Plan {
    gate: Option<Rect>,
    cards: Option<Rect>,
    silos: Option<Rect>,
    charts: Option<Rect>,
    bottom: Option<Rect>,
}

fn plan(area: Rect, silo_count: usize) -> Plan {
    let mut rows = area.height;

    let gate = if rows >= GATE_ROWS { GATE_ROWS } else { 0 };
    rows -= gate;

    let cards = if rows >= CARD_ROWS {
        CARD_ROWS
    } else if rows >= CARD_MIN_ROWS {
        CARD_MIN_ROWS
    } else {
        0
    };
    rows -= cards;

    let wanted = silo_rows(area.width, silo_count) * SILO_CARD_ROWS;
    let silos = if rows >= wanted {
        wanted
    } else if rows >= SILO_CARD_ROWS && silo_count > 0 {
        SILO_CARD_ROWS
    } else {
        0
    };
    rows -= silos;

    let (charts, bottom) = if rows >= CHART_MIN_ROWS + BOTTOM_ROWS {
        (rows - BOTTOM_ROWS, BOTTOM_ROWS)
    } else if rows >= CHART_MIN_ROWS {
        (rows, 0)
    } else if rows >= BOTTOM_ROWS {
        (0, BOTTOM_ROWS)
    } else {
        (0, 0)
    };

    let areas: [Rect; 6] = Layout::vertical([
        Constraint::Length(gate),
        Constraint::Length(cards),
        Constraint::Length(silos),
        Constraint::Length(charts),
        Constraint::Length(bottom),
        Constraint::Min(0),
    ])
    .areas(area);

    Plan {
        gate: keep(areas[0]),
        cards: keep(areas[1]),
        silos: keep(areas[2]),
        charts: keep(areas[3]),
        bottom: keep(areas[4]),
    }
}

/// Wrapped rows the silo cards would like, capped at `SILO_MAX_ROWS`.
fn silo_rows(width: u16, count: usize) -> u16 {
    if count == 0 {
        return 0;
    }
    let per_row = silo_columns(width) as usize;
    let needed = count.div_ceil(per_row.max(1)) as u16;
    needed.clamp(1, SILO_MAX_ROWS)
}

/// Cards one row of `width` columns holds.
fn silo_columns(width: u16) -> u16 {
    (width / SILO_CARD_COLS).clamp(1, MAX_SILO_HITS as u16)
}

fn keep(area: Rect) -> Option<Rect> {
    (area.height > 0).then_some(area)
}

pub fn draw(frame: &mut Frame, area: Rect, state: &AppState, layout: &mut LayoutMap) {
    if area.width < MIN_COLS || area.height == 0 {
        return;
    }

    let plan = plan(area, state.silo_cards.len());
    if let Some(gate) = plan.gate {
        draw_gate(frame, gate, state);
    }

    // Nothing scanned yet, or nothing found: the gate says so, and empty chart
    // frames would only dress up the absence of data.
    if state.rows.is_empty() {
        let rest = Rect {
            y: area.y + plan.gate.map_or(0, |gate| gate.height),
            height: area
                .height
                .saturating_sub(plan.gate.map_or(0, |gate| gate.height)),
            ..area
        };
        draw_clean(frame, rest);
        return;
    }

    if let Some(cards) = plan.cards {
        draw_cards(frame, cards, state, layout);
    }
    if let Some(silos) = plan.silos {
        draw_silo_cards(
            frame,
            silos,
            &state.silo_cards,
            state.silo_offset,
            state.selected_silo,
            layout,
        );
    }
    if let Some(charts) = plan.charts {
        draw_charts(frame, charts, state);
    }
    if let Some(bottom) = plan.bottom {
        draw_bottom(frame, bottom, state);
    }
}

/// The verdict, first thing the eye hits.
fn draw_gate(frame: &mut Frame, area: Rect, state: &AppState) {
    let errors = new_total(state, Severity::Error);
    let passed = errors == 0;
    let color = if passed { theme::OK } else { theme::ERROR };

    let block = theme::colored_block("Quality Gate", color);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let badge = if passed { "  PASSED  " } else { "  FAILED  " };
    let reason = if passed {
        "no new errors".to_string()
    } else if errors == 1 {
        "1 new error above the gate".to_string()
    } else {
        format!("{errors} new errors above the gate")
    };

    let line = Line::from(vec![
        Span::styled(
            badge,
            Style::default()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(reason, Style::default().fg(color)),
    ]);
    frame.render_widget(Paragraph::new(line), inner);
}

/// Zero findings: one line, centered, no skeletons.
fn draw_clean(frame: &mut Frame, area: Rect) {
    if area.height == 0 {
        return;
    }
    let middle = Rect {
        y: area.y + area.height / 2,
        height: 1,
        ..area
    };
    frame.render_widget(
        Paragraph::new(Line::styled("clean - no findings", theme::dim()))
            .alignment(Alignment::Center),
        middle,
    );
}

fn draw_cards(frame: &mut Frame, area: Rect, state: &AppState, layout: &mut LayoutMap) {
    let shown = ((area.width / CARD_MIN_COLS) as usize).clamp(1, Card::COUNT);
    let rects = Layout::horizontal(vec![Constraint::Fill(1); shown]).split(area);

    for (card, rect) in Card::ALL.into_iter().take(shown).zip(rects.iter().copied()) {
        draw_card(frame, rect, card, state);
        layout.cards[card.index()] = Some(rect);
    }
}

/// Block glyphs for a card value: counts go through `big_digits`, the rating
/// letter through the same font by way of `big_text`.
fn big_value(value: &str) -> Vec<String> {
    match value.parse::<usize>() {
        Ok(number) => theme::big_digits(number),
        Err(_) => theme::big_text(value),
    }
}

fn draw_card(frame: &mut Frame, area: Rect, card: Card, state: &AppState) {
    let color = card.color(state);
    let block = theme::colored_block("", color);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let value = card.value(state);
    let mut lines: Vec<Line> = Vec::new();

    match card.detail(state) {
        // A decimal has no block glyph, so this tile prints plain: the value,
        // the count it stands for, and the label on the bottom row where the
        // glyph tiles keep theirs.
        Some(detail) => {
            if inner.height as usize > theme::GLYPH_ROWS {
                lines.push(Line::raw(""));
            }
            lines.push(Line::styled(
                value,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ));
            if lines.len() + 1 < inner.height as usize
                && detail.chars().count() <= inner.width as usize
            {
                lines.push(Line::styled(detail, theme::dim()));
            }
        }
        None => {
            // Glyphs need three rows plus one for the label, and the columns to
            // draw them in; anything less prints the number.
            let fits = inner.height as usize > theme::GLYPH_ROWS
                && theme::big_width(value.chars().count()) <= inner.width as usize;
            if fits {
                for row in big_value(&value) {
                    lines.push(Line::styled(row, Style::default().fg(color)));
                }
            } else {
                lines.push(Line::styled(
                    value,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ));
            }
        }
    }

    if lines.len() < inner.height as usize {
        lines.push(Line::styled(
            card.label(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
    }

    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
}

/// The module card row. `offset` is the first card shown - the row scrolls
/// horizontally rather than shrinking cards past legibility - and `selected`
/// indexes `cards`, not the visible window. Every drawn card records a
/// `SiloHit` carrying its own index, so a click resolves without the caller
/// redoing the scroll arithmetic.
pub fn draw_silo_cards(
    frame: &mut Frame,
    area: Rect,
    cards: &[SiloCard],
    offset: usize,
    selected: Option<usize>,
    layout: &mut LayoutMap,
) {
    layout.silo_cards = [None; MAX_SILO_HITS];
    if cards.is_empty() || area.width < SILO_CARD_COLS || area.height < SILO_CARD_ROWS {
        return;
    }

    // Two passes: the indicator only appears when the cards overflow, and it
    // takes columns that could otherwise have held one more card.
    let mut row_area = area;
    let mut capacity = silo_capacity(row_area);
    if cards.len() > capacity && row_area.width > SILO_INDICATOR_COLS + SILO_CARD_COLS {
        row_area.width -= SILO_INDICATOR_COLS;
        capacity = silo_capacity(row_area);
    }

    let start = offset.min(cards.len().saturating_sub(capacity));
    let visible = &cards[start..(start + capacity).min(cards.len())];

    let rows = (visible
        .len()
        .div_ceil(silo_columns(row_area.width) as usize) as u16)
        .clamp(1, row_area.height / SILO_CARD_ROWS);
    let columns = visible.len().div_ceil(rows as usize).max(1);

    let bands = Layout::vertical(vec![Constraint::Length(SILO_CARD_ROWS); rows as usize])
        .split(Rect {
            height: rows * SILO_CARD_ROWS,
            ..row_area
        })
        .to_vec();

    for (band_index, band) in bands.iter().enumerate() {
        let slots = Layout::horizontal(vec![Constraint::Fill(1); columns]).split(*band);
        for (column, slot) in slots.iter().enumerate() {
            let visible_index = band_index * columns + column;
            let Some(card) = visible.get(visible_index) else {
                break;
            };
            let index = start + visible_index;
            draw_silo_card(frame, *slot, card, selected == Some(index));
            if visible_index < MAX_SILO_HITS {
                layout.silo_cards[visible_index] = Some(SiloHit { area: *slot, index });
            }
        }
    }

    if cards.len() > visible.len() {
        draw_silo_scroll(
            frame,
            Rect {
                x: row_area.x + row_area.width,
                width: area.width - row_area.width,
                ..area
            },
            start,
            cards.len() - start - visible.len(),
        );
    }
}

/// Cards `area` holds at once, hit-testing cap included.
fn silo_capacity(area: Rect) -> usize {
    let columns = silo_columns(area.width) as usize;
    let rows = (area.height / SILO_CARD_ROWS).clamp(1, SILO_MAX_ROWS) as usize;
    (columns * rows).min(MAX_SILO_HITS)
}

/// How many cards sit off each end of the visible window.
fn draw_silo_scroll(frame: &mut Frame, area: Rect, before: usize, after: usize) {
    if area.width == 0 || area.height < 2 {
        return;
    }
    let lines = vec![
        Line::styled(
            if before > 0 {
                format!("<{before}")
            } else {
                String::new()
            },
            theme::dim(),
        ),
        Line::styled(
            if after > 0 {
                format!("{after}>")
            } else {
                String::new()
            },
            theme::dim(),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Right),
        Rect {
            y: area.y + 1,
            height: 2,
            ..area
        },
    );
}

/// One module card: the silo name in the border, colored by its worst
/// severity, over the severity mini-bar and the size line. The selected card
/// takes the shared selection background.
fn draw_silo_card(frame: &mut Frame, area: Rect, card: &SiloCard, selected: bool) {
    let name = head_truncate(&card.name, area.width.saturating_sub(4) as usize);
    let mut block = theme::colored_block(&name, card.accent());
    if selected {
        block = block.style(theme::selected());
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let mut lines = vec![severity_line(card, inner.width as usize)];
    if inner.height > 1 {
        lines.push(size_line(card, inner.width as usize));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Severity mini-bar plus the three counts, each in its own severity color.
fn severity_line(card: &SiloCard, width: usize) -> Line<'static> {
    let counts = [card.error_count, card.warning_count, card.info_count];
    let severities = [Severity::Error, Severity::Warning, Severity::Info];

    let mut tail: Vec<Span<'static>> = Vec::new();
    for (index, (count, severity)) in counts.iter().zip(severities).enumerate() {
        if index > 0 {
            tail.push(Span::styled("/", theme::dim()));
        }
        tail.push(Span::styled(
            count.to_string(),
            Style::default().fg(theme::severity_color(severity)),
        ));
    }
    let tail_width: usize = tail.iter().map(|span| span.content.chars().count()).sum();

    let bar = width.saturating_sub(tail_width + 1).min(SILO_BAR_MAX);
    let mut spans: Vec<Span<'static>> = Vec::new();
    if bar > 0 {
        let cells = bar_cells(counts, bar);
        for (count, severity) in cells.iter().zip(severities) {
            if *count > 0 {
                spans.push(Span::styled(
                    "\u{2588}".repeat(*count),
                    Style::default().fg(theme::severity_color(severity)),
                ));
            }
        }
        let filled: usize = cells.iter().sum();
        spans.push(Span::styled(
            "\u{2591}".repeat(bar - filled),
            Style::default().fg(theme::DIM),
        ));
        spans.push(Span::raw(" "));
    }
    spans.extend(tail);
    Line::from(spans)
}

/// Bar cells per severity: proportional, but any non-zero count keeps at least
/// one cell, and rounding never spills past `width`.
fn bar_cells(counts: [usize; 3], width: usize) -> [usize; 3] {
    let total: usize = counts.iter().sum();
    if total == 0 || width == 0 {
        return [0; 3];
    }

    let mut cells = [0usize; 3];
    for (index, count) in counts.iter().enumerate() {
        if *count > 0 {
            cells[index] = (count * width / total).max(1);
        }
    }

    // Trim the widest segment first, earliest on a tie, until the bar fits.
    while cells.iter().sum::<usize>() > width {
        let Some(index) = (0..cells.len()).max_by_key(|index| (cells[*index], usize::MAX - *index))
        else {
            break;
        };
        if cells[index] == 0 {
            break;
        }
        cells[index] -= 1;
    }
    cells
}

/// Lines and duplication, the size of the silo in one line. The percent is
/// what survives when the card is too narrow for both.
fn size_line(card: &SiloCard, width: usize) -> Line<'static> {
    let left = format!("{} loc", card.loc);
    let right = format!("{:.1}%", card.duplication_percent);
    let right_width = right.chars().count();

    if left.chars().count() + 1 + right_width <= width {
        let gap = width - left.chars().count() - right_width;
        return Line::from(vec![
            Span::styled(left, theme::dim()),
            Span::raw(" ".repeat(gap)),
            Span::styled(right, theme::accent()),
        ]);
    }
    if right_width <= width {
        return Line::from(vec![Span::styled(right, theme::accent())]);
    }
    Line::from(vec![Span::styled(
        head_truncate(&right, width),
        theme::accent(),
    )])
}

/// Silo names read from the front: the head is the informative half. Sanitized
/// before the cut, so an escape byte cannot ride through inside what survives.
fn head_truncate(text: &str, width: usize) -> String {
    sanitize_for_terminal(text).chars().take(width).collect()
}

fn draw_charts(frame: &mut Frame, area: Rect, state: &AppState) {
    let columns = if area.width >= THREE_CHART_COLS {
        3
    } else if area.width >= TWO_CHART_COLS {
        2
    } else {
        1
    };
    let rects = Layout::horizontal(vec![Constraint::Fill(1); columns]).split(area);

    draw_severity_chart(frame, rects[0], state);
    if columns > 1 {
        draw_top_rules(frame, rects[1], state);
    }
    if columns > 2 {
        draw_hotspots(frame, rects[2], state);
    }
}

fn draw_severity_chart(frame: &mut Frame, area: Rect, state: &AppState) {
    let counts = state.counts_by_severity();
    let max = counts
        .iter()
        .map(|(_, count)| *count as u64)
        .max()
        .unwrap_or(1)
        .max(1);

    let bars: Vec<Bar> = counts
        .iter()
        .map(|(severity, count)| {
            let color = theme::severity_color(*severity);
            Bar::default()
                .value(*count as u64)
                .label(Line::from(theme::severity_name_span(*severity)))
                .style(Style::default().fg(color))
                .value_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(color)
                        .add_modifier(Modifier::BOLD),
                )
        })
        .collect();

    // Three bars, two gaps, and a column of breathing room either side.
    let width = (area.width.saturating_sub(4) / 3).clamp(1, 9);
    let chart = BarChart::new(bars)
        .block(theme::pane_block("Severity", false))
        .bar_width(width)
        .bar_gap(1)
        .max(max);
    frame.render_widget(chart, area);
}

/// A row of "name, proportional bar, count". Shared by the rules and hotspot
/// panes so they line up with each other.
fn bar_line(name: &str, count: usize, max: usize, color: Color, width: u16) -> Line<'static> {
    let count_text = count.to_string();
    let name_width = ((width as usize) * 2 / 5).clamp(4, 24);
    let bar_width = (width as usize)
        .saturating_sub(name_width + count_text.chars().count() + 2)
        .max(1);

    let name = tail_truncate(name, name_width);
    let pad = name_width.saturating_sub(name.chars().count());
    let filled = if max == 0 {
        0
    } else {
        (count * bar_width).div_ceil(max).min(bar_width)
    };

    Line::from(vec![
        Span::styled(name, Style::default().fg(color)),
        Span::raw(" ".repeat(pad + 1)),
        Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
        Span::styled(
            "\u{2591}".repeat(bar_width - filled),
            Style::default().fg(theme::DIM),
        ),
        Span::raw(" "),
        Span::styled(count_text, theme::dim()),
    ])
}

/// Rule ids are dotted and the tail is the informative half. Sanitized before
/// the cut, for the reason [`head_truncate`] gives.
fn tail_truncate(text: &str, width: usize) -> String {
    let text = &*sanitize_for_terminal(text);
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    chars[chars.len().saturating_sub(width)..].iter().collect()
}

fn draw_top_rules(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = theme::pane_block("Top rules", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width < 8 {
        return;
    }

    let rows = (inner.height as usize).min(LIST_ROWS);
    let rules = state.top_rules(rows);
    let max = rules.iter().map(|(_, count)| *count).max().unwrap_or(0);

    let lines: Vec<Line> = rules
        .iter()
        .map(|(rule, count)| bar_line(rule, *count, max, theme::ACCENT, inner.width))
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Worst severity seen in each top-level directory, so a hotspot is colored by
/// how bad it is, not just how busy.
fn worst_by_dir(state: &AppState) -> BTreeMap<String, Severity> {
    let mut worst: BTreeMap<String, Severity> = BTreeMap::new();
    for row in &state.rows {
        let dir = top_dir(&row.finding.path).to_string();
        let severity = row.finding.severity;
        worst
            .entry(dir)
            .and_modify(|current| {
                if severity > *current {
                    *current = severity;
                }
            })
            .or_insert(severity);
    }
    worst
}

fn top_dir(path: &str) -> &str {
    match path.split_once('/') {
        Some((head, _)) if !head.is_empty() => head,
        _ => ".",
    }
}

fn draw_hotspots(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = theme::pane_block("Hotspots", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width < 8 {
        return;
    }

    let worst = worst_by_dir(state);
    let dirs = state.counts_by_dir();
    let max = dirs.iter().map(|(_, count)| *count).max().unwrap_or(0);

    let lines: Vec<Line> = dirs
        .iter()
        .take((inner.height as usize).min(LIST_ROWS))
        .map(|(dir, count)| {
            let color = worst
                .get(dir)
                .copied()
                .map_or(theme::DIM, theme::severity_color);
            bar_line(dir, *count, max, color, inner.width)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_bottom(frame: &mut Frame, area: Rect, state: &AppState) {
    let [debt, coverage] =
        Layout::horizontal([Constraint::Fill(2), Constraint::Fill(1)]).areas(area);
    draw_debt(frame, debt, state);
    draw_coverage(frame, coverage, state);
}

fn draw_debt(frame: &mut Frame, area: Rect, state: &AppState) {
    let (new, baselined, suppressed) = state.debt_counts();
    let total = new + baselined + suppressed;
    let ratio = if total == 0 {
        0.0
    } else {
        new as f64 / total as f64
    };

    let gauge = Gauge::default()
        .block(theme::pane_block("Debt", false))
        .ratio(ratio)
        .gauge_style(Style::default().fg(theme::ERROR).bg(theme::DIM))
        .label(Span::styled(
            format!("{new} new / {baselined} baselined / {suppressed} suppressed"),
            Style::default().add_modifier(Modifier::BOLD),
        ));
    frame.render_widget(gauge, area);
}

/// Findings from coverage rules. The scan carries no overall percentage, so the
/// tile counts files instead of inventing one.
///
/// Coverage rule ids are only knowable from a rule set. A snapshot boots without
/// one - the report carries findings, never the rules that produced them - so
/// there the findings are recognised by the text the coverage engine writes into
/// `matched` instead.
fn coverage_findings(state: &AppState) -> usize {
    if state.rules.rules.is_empty() {
        return state
            .rows
            .iter()
            .filter(|row| is_coverage_matched(&row.finding.matched))
            .count();
    }

    let ids: BTreeSet<&str> = state
        .rules
        .rules
        .iter()
        .filter(|rule| matches!(rule.payload, CompiledPayload::Coverage { .. }))
        .map(|rule| rule.id.as_str())
        .collect();
    if ids.is_empty() {
        return 0;
    }
    state
        .rows
        .iter()
        .filter(|row| ids.contains(row.finding.rule_id.as_str()))
        .count()
}

/// True for the `matched` text `coverage::scan_coverage` writes:
/// `<covered>/<total> lines (<percent>%)`. The duplicate-block wording
/// (`<n> duplicated lines (block <hash>)`) is the near miss this has to reject.
fn is_coverage_matched(matched: &str) -> bool {
    let Some((lines, percent)) = matched.split_once(" lines (") else {
        return false;
    };
    let Some((covered, total)) = lines.split_once('/') else {
        return false;
    };
    let Some(percent) = percent.strip_suffix("%)") else {
        return false;
    };
    covered.parse::<u64>().is_ok() && total.parse::<u64>().is_ok() && percent.parse::<f64>().is_ok()
}

fn draw_coverage(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = theme::pane_block("Coverage", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let count = coverage_findings(state);
    let line = if count == 0 {
        Line::styled("no coverage report", theme::dim())
    } else {
        Line::styled(
            format!("{count} files below threshold"),
            Style::default()
                .fg(theme::WARNING)
                .add_modifier(Modifier::BOLD),
        )
    };
    frame.render_widget(Paragraph::new(line).alignment(Alignment::Center), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;
    use siloscan_core::findings::Finding;
    use siloscan_core::metrics::DUPLICATE_BLOCK_RULE_ID;
    use siloscan_core::rules::{CompiledRule, RuleSet};
    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::state::FindingRow;

    fn finding(rule_id: &str, severity: Severity, path: &str, line: u64) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            message: "test".to_string(),
            path: path.to_string(),
            line,
            column: 1,
            matched: "match".to_string(),
            fingerprint: format!("{rule_id}:{path}:{line}"),
        }
    }

    fn row(rule_id: &str, severity: Severity, path: &str, line: u64, status: Status) -> FindingRow {
        FindingRow {
            finding: finding(rule_id, severity, path, line),
            status,
        }
    }

    fn empty(rules: RuleSet) -> AppState {
        AppState::new(PathBuf::from("."), Arc::new(rules), None)
    }

    fn state() -> AppState {
        let mut state = empty(RuleSet::default());
        for index in 0..20 {
            let severity = match index % 3 {
                0 => Severity::Error,
                1 => Severity::Warning,
                _ => Severity::Info,
            };
            let status = if index % 4 == 0 {
                Status::Baselined
            } else {
                Status::New
            };
            state.rows.push(row(
                &format!("rule.{}", index % 5),
                severity,
                &format!("src/deep/file_{index}.rs"),
                index as u64,
                status,
            ));
        }
        state
    }

    fn render(state: &AppState, width: u16, height: u16) -> (Buffer, LayoutMap) {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        let mut layout = LayoutMap::default();
        terminal
            .draw(|frame| draw(frame, frame.area(), state, &mut layout))
            .unwrap();
        (terminal.backend().buffer().clone(), layout)
    }

    fn dump(buffer: &Buffer) -> String {
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()));
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn renders_the_whole_board_at_200x50() {
        let (buffer, layout) = render(&state(), 200, 50);
        let text = dump(&buffer);

        assert!(text.contains("FAILED"), "{text}");
        assert!(text.contains("new errors above the gate"), "{text}");
        assert!(text.contains("Errors"), "{text}");
        assert!(text.contains("Rating"), "{text}");
        assert!(text.contains("Severity"), "{text}");
        assert!(text.contains("Top rules"), "{text}");
        assert!(text.contains("Hotspots"), "{text}");
        assert!(text.contains("baselined"), "{text}");
        assert!(text.contains("no coverage report"), "{text}");
        assert!(
            layout.cards.iter().all(Option::is_some),
            "every card is clickable at 200 columns"
        );
    }

    #[test]
    fn renders_at_80x24_with_the_cards_that_fit() {
        let (buffer, layout) = render(&state(), 80, 24);
        let text = dump(&buffer);

        assert!(text.contains("FAILED"), "{text}");
        assert!(text.contains("Warnings"), "{text}");
        // Eighty columns hold six of the seven; the tail is dropped, as ever.
        assert_eq!(
            layout.cards.iter().filter(|card| card.is_some()).count(),
            (80 / CARD_MIN_COLS as usize).min(Card::COUNT)
        );

        let (_, wide) = render(&state(), 120, 24);
        assert_eq!(
            wide.cards.iter().filter(|card| card.is_some()).count(),
            Card::COUNT
        );
    }

    #[test]
    fn short_terminals_drop_rows_from_the_bottom() {
        // A nine-row strip keeps the gate and the cards and nothing else.
        let strip = plan(Rect::new(0, 0, 200, 9), 3);
        assert_eq!(strip.gate.map(|area| area.height), Some(GATE_ROWS));
        assert_eq!(strip.cards.map(|area| area.height), Some(CARD_ROWS));
        assert!(strip.silos.is_none());
        assert!(strip.charts.is_none());
        assert!(strip.bottom.is_none());

        // Enough for everything: the charts take the slack left by the silo row.
        let full = plan(Rect::new(0, 0, 200, 30), 3);
        assert_eq!(full.silos.map(|area| area.height), Some(SILO_CARD_ROWS));
        assert_eq!(full.charts.map(|area| area.height), Some(14));
        assert_eq!(full.bottom.map(|area| area.height), Some(BOTTOM_ROWS));

        // No silos, no band: the charts get every row they used to.
        let bare = plan(Rect::new(0, 0, 200, 30), 0);
        assert!(bare.silos.is_none());
        assert_eq!(bare.charts.map(|area| area.height), Some(18));

        // Three rows: the gate alone.
        let gate_only = plan(Rect::new(0, 0, 200, 3), 3);
        assert!(gate_only.gate.is_some());
        assert!(gate_only.cards.is_none());
        assert!(gate_only.silos.is_none());
    }

    #[test]
    fn the_silo_band_outlives_the_charts_but_not_the_kpi_cards() {
        // Narrow and short: two wrapped rows of cards, no charts.
        let cramped = plan(Rect::new(0, 0, 40, 20), 5);
        assert_eq!(
            cramped.silos.map(|area| area.height),
            Some(SILO_MAX_ROWS * SILO_CARD_ROWS)
        );
        assert!(cramped.charts.is_none());

        // One band's worth left: the row scrolls instead of wrapping.
        let single = plan(Rect::new(0, 0, 40, 14), 5);
        assert_eq!(single.silos.map(|area| area.height), Some(SILO_CARD_ROWS));
        assert!(single.cards.is_some());
    }

    #[test]
    fn narrow_terminals_drop_cards_from_the_right() {
        let (_, layout) = render(&state(), 40, 24);
        assert_eq!(layout.cards.iter().filter(|card| card.is_some()).count(), 3);
        assert!(layout.cards[Card::Errors.index()].is_some());
        assert!(layout.cards[Card::Rating.index()].is_none());
    }

    #[test]
    fn a_clean_scan_passes_the_gate_and_says_so_once() {
        let (buffer, _) = render(&empty(RuleSet::default()), 80, 24);
        let text = dump(&buffer);

        assert!(text.contains("PASSED"), "{text}");
        assert!(text.contains("no new errors"), "{text}");
        assert!(text.contains("clean - no findings"), "{text}");
        assert!(!text.contains("Top rules"), "no chart skeletons: {text}");
    }

    #[test]
    fn a_baselined_scan_passes_the_gate() {
        let mut state = state();
        for row in &mut state.rows {
            row.status = Status::Baselined;
        }
        let (buffer, _) = render(&state, 120, 30);
        let text = dump(&buffer);

        assert!(text.contains("PASSED"), "{text}");
        assert_eq!(rating(&state), 'A');
    }

    #[test]
    fn the_rating_grades_new_findings_only() {
        let mut state = empty(RuleSet::default());
        assert_eq!(rating(&state), 'A');

        state
            .rows
            .push(row("r", Severity::Warning, "a.rs", 1, Status::New));
        assert_eq!(rating(&state), 'B');

        state
            .rows
            .push(row("r", Severity::Error, "a.rs", 2, Status::New));
        assert_eq!(rating(&state), 'C');
        assert_eq!(rating_color('C'), theme::ERROR_SOFT);

        for line in 3..10 {
            state
                .rows
                .push(row("r", Severity::Error, "a.rs", line, Status::New));
        }
        assert_eq!(rating(&state), 'D');

        // Baselined errors are accepted debt: they do not grade.
        for row in &mut state.rows {
            row.status = Status::Baselined;
        }
        assert_eq!(rating(&state), 'A');
    }

    #[test]
    fn clicking_a_card_opens_triage_with_that_filter() {
        let mut state = state();

        open_card(&mut state, Card::Errors);
        assert_eq!(state.screen, Screen::Triage);
        assert!(state.filters.severities.contains(&Severity::Error));
        assert!(state.filters.statuses.is_empty());

        open_card(&mut state, Card::New);
        assert!(state.filters.severities.is_empty());
        assert_eq!(state.filters.statuses.len(), 1);
        assert!(state.filters.statuses.contains(&Status::New));

        open_card(&mut state, Card::Debt);
        assert!(state.filters.statuses.contains(&Status::Baselined));
        assert!(state.filters.statuses.contains(&Status::Suppressed));
        assert!(!state.filters.statuses.contains(&Status::New));

        // The rating is a verdict, not a filter axis.
        state.screen = Screen::Dashboard;
        open_card(&mut state, Card::Rating);
        assert_eq!(state.screen, Screen::Dashboard);
    }

    #[test]
    fn the_coverage_tile_counts_coverage_rule_findings() {
        let rules = RuleSet {
            rules: vec![CompiledRule {
                id: "quality.line-coverage".to_string(),
                severity: Severity::Warning,
                message: "coverage below threshold".to_string(),
                languages: None,
                include: None,
                exclude: None,
                payload: CompiledPayload::Coverage { min: 80.0 },
            }],
            sources: Vec::new(),
        };

        let mut state = empty(rules);
        state.rows.push(row(
            "secret.aws",
            Severity::Error,
            "src/a.rs",
            1,
            Status::New,
        ));
        assert_eq!(coverage_findings(&state), 0);

        state.rows.push(row(
            "quality.line-coverage",
            Severity::Warning,
            "src/b.rs",
            1,
            Status::New,
        ));
        assert_eq!(coverage_findings(&state), 1);

        let (buffer, _) = render(&state, 120, 30);
        assert!(dump(&buffer).contains("1 files below threshold"));
    }

    /// A snapshot boots with no rules, so the tile has no coverage rule id to
    /// match on and has to read the finding's own shape. The duplicate-block
    /// wording is the near miss that must not be counted.
    ///
    /// Schema 1.2, because shape detection needs the match text and snapshot
    /// mode withholds it below that version. The duplicate-block rule is
    /// exempted from that redaction and this one deliberately is not: the
    /// exemption there is a reserved rule id, fixed at compile time, while the
    /// only signal here is the shape of `matched` itself. Keying an exemption
    /// on the text being protected would let a secret that reads as
    /// `12/40 lines (30.0%)` exempt itself. On a pre-1.2 snapshot the tile
    /// reads "no coverage report" instead, and the footer says why.
    #[test]
    fn a_snapshot_shows_coverage_findings_without_a_rule_set() {
        let mut coverage = finding("quality.line-coverage", Severity::Warning, "src/a.rs", 1);
        coverage.matched = "12/40 lines (30.0%)".to_string();
        let mut duplicate = finding(DUPLICATE_BLOCK_RULE_ID, Severity::Info, "src/b.rs", 3);
        duplicate.matched = "12 duplicated lines (block 0123456789ab)".to_string();

        let mut state = empty(RuleSet::default());
        crate::app::apply_snapshot(
            &mut state,
            crate::snapshot::SnapshotData {
                source: "report.json".to_string(),
                schema_version: "1.2".to_string(),
                anchor: Default::default(),
                findings: vec![coverage, duplicate],
                baselined: Vec::new(),
                suppressed: Vec::new(),
                metrics: siloscan_core::metrics::Metrics::default(),
            },
            None,
        );

        assert!(state.rules.rules.is_empty(), "snapshot boot loads no rules");
        assert_eq!(coverage_findings(&state), 1);

        let (buffer, _) = render(&state, 120, 30);
        assert!(dump(&buffer).contains("1 files below threshold"));
    }

    #[test]
    fn bars_stay_inside_their_width() {
        for width in [12u16, 20, 40, 80] {
            for count in [0usize, 1, 7] {
                let line = bar_line("silo.boundary.web", count, 7, theme::ACCENT, width);
                assert!(
                    line.width() <= width as usize,
                    "{width} cols, count {count}, got {}",
                    line.width()
                );
            }
        }
    }

    #[test]
    fn does_not_render_when_too_narrow() {
        let (buffer, layout) = render(&state(), 20, 24);
        assert!(dump(&buffer).trim().is_empty());
        assert!(layout.cards.iter().all(Option::is_none));
    }

    // -- silo cards ------------------------------------------------------

    fn measured(lines: u64, duplicated: u64) -> FileMetrics {
        FileMetrics {
            lines,
            code_lines: Some(lines),
            duplicated_lines: duplicated,
        }
    }

    /// Four measured files over three top-level directories, one of them at
    /// the report root, plus twenty duplicated lines in `api`.
    fn silo_files() -> BTreeMap<String, FileMetrics> {
        BTreeMap::from([
            ("api/handler.rs".to_string(), measured(100, 20)),
            ("api/util.rs".to_string(), measured(40, 0)),
            ("core/lib.rs".to_string(), measured(60, 0)),
            ("README.md".to_string(), measured(10, 0)),
        ])
    }

    fn silo_findings() -> Vec<FindingRow> {
        vec![
            row(
                "secrets.aws",
                Severity::Error,
                "api/handler.rs",
                3,
                Status::New,
            ),
            row(
                "style.todo",
                Severity::Warning,
                "api/util.rs",
                9,
                Status::New,
            ),
            row(
                DUPLICATE_BLOCK_RULE_ID,
                Severity::Info,
                "core/lib.rs",
                1,
                Status::New,
            ),
            row(
                DUPLICATE_BLOCK_RULE_ID,
                Severity::Info,
                "core/lib.rs",
                40,
                Status::Baselined,
            ),
        ]
    }

    fn derived_cards() -> Vec<SiloCard> {
        let files = silo_files();
        let rows = silo_findings();
        silo_cards(&directory_silo_groups(&files, &rows), &files, &rows)
    }

    fn render_silos(
        cards: &[SiloCard],
        width: u16,
        height: u16,
        offset: usize,
        selected: Option<usize>,
    ) -> (Buffer, LayoutMap) {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        let mut layout = LayoutMap::default();
        terminal
            .draw(|frame| {
                draw_silo_cards(frame, frame.area(), cards, offset, selected, &mut layout)
            })
            .unwrap();
        (terminal.backend().buffer().clone(), layout)
    }

    fn hits(layout: &LayoutMap) -> Vec<SiloHit> {
        layout.silo_cards.iter().flatten().copied().collect()
    }

    #[test]
    fn directory_fallback_groups_by_top_level_segment() {
        let files = silo_files();
        let rows = silo_findings();
        let groups = directory_silo_groups(&files, &rows);

        let names: Vec<&str> = groups.iter().map(|group| group.name.as_str()).collect();
        assert_eq!(names, vec![".", "api", "core"], "sorted, root under '.'");
        assert!(groups[1].paths.contains("api/handler.rs"));
        assert!(groups[1].paths.contains("api/util.rs"));

        // A finding in a file the metrics never measured still joins a group.
        let mut rows = rows;
        rows.push(row(
            "style.todo",
            Severity::Info,
            "web/app.ts",
            1,
            Status::New,
        ));
        let groups = directory_silo_groups(&files, &rows);
        let names: Vec<&str> = groups.iter().map(|group| group.name.as_str()).collect();
        assert_eq!(names, vec![".", "api", "core", "web"]);
    }

    #[test]
    fn cards_carry_the_numbers_from_metrics_and_findings() {
        let cards = derived_cards();
        assert_eq!(cards.len(), 3);

        let api = &cards[1];
        assert_eq!(api.name, "api");
        assert_eq!(
            (api.error_count, api.warning_count, api.info_count),
            (1, 1, 0)
        );
        assert_eq!(api.loc, 140);
        assert!(
            (api.duplication_percent - 20.0 / 140.0 * 100.0).abs() < 1e-9,
            "{}",
            api.duplication_percent
        );
        assert_eq!(api.accent(), theme::ERROR);

        // Baselined findings count towards the card, as they do on the KPI row.
        let core = &cards[2];
        assert_eq!(core.info_count, 2);
        assert_eq!(core.loc, 60);
        assert_eq!(core.duplication_percent, 0.0);
        assert_eq!(core.accent(), theme::INFO);

        // A silo with lines and no findings is clean, not dim.
        let root = &cards[0];
        assert_eq!(root.findings(), 0);
        assert_eq!(root.loc, 10);
        assert_eq!(root.accent(), theme::OK);
    }

    #[test]
    fn declared_silos_keep_the_order_given_and_collect_the_rest() {
        let files = silo_files();
        let rows = silo_findings();
        let order = vec!["web".to_string(), "api".to_string()];
        let groups = declared_silo_groups(&files, &rows, &order, |path| {
            path.split_once('/')
                .filter(|(head, _)| *head == "api" || *head == "web")
                .map(|(head, _)| head.to_string())
        });

        let names: Vec<&str> = groups.iter().map(|group| group.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["web", "api", UNASSIGNED_SILO],
            "the order given, leftovers last"
        );
        assert!(
            groups[0].paths.is_empty(),
            "an empty silo still gets a card"
        );
        assert_eq!(groups[1].paths.len(), 2);
        assert_eq!(
            groups[2]
                .paths
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["README.md", "core/lib.rs"]
        );

        // Everything claimed: no trailing card.
        let groups = declared_silo_groups(&files, &rows, &order, |_| Some("api".to_string()));
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|group| group.name != UNASSIGNED_SILO));

        let cards = silo_cards(&groups, &files, &rows);
        assert_eq!(cards[1].loc, 210, "every measured file landed in api");
    }

    #[test]
    fn the_card_row_prints_the_name_the_counts_and_the_size() {
        let cards = derived_cards();
        let (buffer, layout) = render_silos(&cards, 90, 4, 0, None);
        let text = dump(&buffer);

        assert!(text.contains("api"), "{text}");
        assert!(text.contains("core"), "{text}");
        assert!(text.contains("1/1/0"), "severity counts: {text}");
        assert!(text.contains("140 loc"), "{text}");
        assert!(text.contains("14.3%"), "one decimal: {text}");
        assert_eq!(hits(&layout).len(), 3, "every card is clickable");
    }

    #[test]
    fn the_worst_severity_colors_the_card_border() {
        let cards = derived_cards();
        let (buffer, layout) = render_silos(&cards, 90, 4, 0, None);
        let hits = hits(&layout);

        let border = |hit: &SiloHit| {
            buffer
                .cell((hit.area.x, hit.area.y))
                .expect("card corner is inside the buffer")
                .fg
        };
        assert_eq!(border(&hits[0]), theme::OK, "no findings");
        assert_eq!(
            border(&hits[1]),
            theme::ERROR,
            "an error outranks a warning"
        );
        assert_eq!(border(&hits[2]), theme::INFO, "info only");
    }

    #[test]
    fn the_row_wraps_when_the_terminal_is_narrow() {
        let mut cards = derived_cards();
        cards.push(SiloCard {
            name: "web".to_string(),
            error_count: 0,
            warning_count: 2,
            info_count: 0,
            loc: 500,
            duplication_percent: 1.0,
        });

        // Wide: one band, four cards side by side.
        let (_, wide) = render_silos(&cards, 200, 8, 0, None);
        let wide = hits(&wide);
        assert_eq!(wide.len(), 4);
        assert!(
            wide.iter().all(|hit| hit.area.y == wide[0].area.y),
            "one row at 200 columns: {wide:?}"
        );

        // Narrow: two cards per band, two bands, nothing dropped.
        let (_, narrow) = render_silos(&cards, 40, 8, 0, None);
        let narrow = hits(&narrow);
        assert_eq!(narrow.len(), 4);
        assert_eq!(narrow[0].area.y, narrow[1].area.y);
        assert_eq!(narrow[2].area.y, narrow[0].area.y + SILO_CARD_ROWS);
        assert_eq!(narrow[3].index, 3, "hits carry the card index");
    }

    #[test]
    fn the_row_scrolls_and_says_how_many_are_hidden() {
        let cards: Vec<SiloCard> = (0..5)
            .map(|index| SiloCard {
                name: format!("silo-{index}"),
                error_count: index,
                warning_count: 0,
                info_count: 0,
                loc: 10,
                duplication_percent: 0.0,
            })
            .collect();

        // One band, two cards wide: three cards sit off the right edge.
        let (buffer, layout) = render_silos(&cards, 40, 4, 0, None);
        let visible = hits(&layout);
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].index, 0);
        let text = dump(&buffer);
        assert!(text.contains("3>"), "hidden count on the right: {text}");
        assert!(!text.contains("<"), "nothing hidden on the left: {text}");

        // Scrolled past the end: the window clamps to the last two cards.
        let (buffer, layout) = render_silos(&cards, 40, 4, 9, None);
        let visible = hits(&layout);
        assert_eq!(
            visible.iter().map(|hit| hit.index).collect::<Vec<_>>(),
            vec![3, 4]
        );
        let text = dump(&buffer);
        assert!(text.contains("<3"), "hidden count on the left: {text}");
        assert!(text.contains("silo-4"), "{text}");
    }

    #[test]
    fn a_selected_card_is_drawn_selected() {
        let cards = derived_cards();
        let (plain, _) = render_silos(&cards, 90, 4, 0, None);
        let (selected, layout) = render_silos(&cards, 90, 4, 0, Some(1));
        let hit = hits(&layout)[1];

        let background = |buffer: &Buffer| {
            buffer
                .cell((hit.area.x + 1, hit.area.y + 1))
                .expect("card body is inside the buffer")
                .bg
        };
        assert_ne!(background(&plain), theme::SELECTED_BG);
        assert_eq!(background(&selected), theme::SELECTED_BG);
    }

    #[test]
    fn an_empty_card_list_draws_nothing() {
        let (buffer, layout) = render_silos(&[], 90, 4, 0, None);
        assert!(dump(&buffer).trim().is_empty());
        assert!(layout.silo_cards.iter().all(Option::is_none));

        // Too short for a card: the band is skipped rather than half-drawn.
        let (buffer, layout) = render_silos(&derived_cards(), 90, 2, 0, None);
        assert!(dump(&buffer).trim().is_empty());
        assert!(layout.silo_cards.iter().all(Option::is_none));
    }

    #[test]
    fn the_severity_bar_fits_and_keeps_every_present_severity() {
        for width in [1usize, 3, 7, 24] {
            let cells = bar_cells([97, 2, 1], width);
            assert!(cells.iter().sum::<usize>() <= width, "{width}: {cells:?}");
        }
        // Every non-zero severity keeps a cell once there is room for one each.
        assert_eq!(
            bar_cells([97, 2, 1], 10).iter().filter(|c| **c > 0).count(),
            3
        );
        assert_eq!(bar_cells([0, 0, 0], 10), [0, 0, 0]);

        for width in [12usize, 20, 40] {
            let line = severity_line(&derived_cards()[1], width);
            assert!(line.width() <= width, "{width}: got {}", line.width());
        }
    }

    #[test]
    fn the_size_line_drops_the_line_count_before_the_percentage() {
        let card = &derived_cards()[1];
        assert_eq!(size_line(card, 14).to_string(), "140 loc  14.3%");
        assert_eq!(size_line(card, 6).to_string(), "14.3%");
        assert_eq!(size_line(card, 3).to_string(), "14.");
    }

    #[test]
    fn the_duplication_card_prints_density_and_lines_and_opens_the_blocks() {
        let mut state = state();
        state.metrics.totals.lines = 320;
        state.metrics.totals.duplicated_lines = 40;
        state.metrics.totals.duplication_density = 12.5;

        let (buffer, layout) = render(&state, 120, 30);
        let text = dump(&buffer);
        assert!(text.contains("12.5%"), "{text}");
        assert!(text.contains("40 dup lines"), "{text}");
        assert!(text.contains("Duplication"), "{text}");
        assert!(
            layout.cards[Card::Duplication.index()].is_some(),
            "the duplication card records a hit box"
        );

        open_card(&mut state, Card::Duplication);
        assert_eq!(state.screen, Screen::Triage);
        assert!(state.filters.rules.contains(DUPLICATE_BLOCK_RULE_ID));
        assert!(
            crate::ui::triage::group().on,
            "the drill-down opens on the duplicate sets, grouped"
        );
    }

    #[test]
    fn clicking_a_silo_card_filters_triage_to_its_paths() {
        let mut state = state();
        let files = silo_files();
        state.rows = silo_findings();
        state.silo_groups = directory_silo_groups(&files, &state.rows);
        state.silo_cards = silo_cards(&state.silo_groups, &files, &state.rows);

        open_silo_card(&mut state, 1);
        assert_eq!(state.screen, Screen::Triage);
        assert_eq!(
            state
                .filters
                .paths
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["api/handler.rs", "api/util.rs"]
        );

        // A card index nobody drew leaves the state alone.
        state.screen = Screen::Dashboard;
        open_silo_card(&mut state, 99);
        assert_eq!(state.screen, Screen::Dashboard);
    }

    #[test]
    fn a_silo_card_that_owns_nothing_does_not_open_an_unfiltered_board() {
        let mut state = state();
        let files = silo_files();
        state.rows = silo_findings();
        state.silo_groups = declared_silo_groups(
            &files,
            &state.rows,
            &["empty".to_string(), "api".to_string()],
            |path| {
                path.starts_with("api/")
                    .then(|| "api".to_string())
                    .or_else(|| Some("core".to_string()))
            },
        );
        state.silo_cards = silo_cards(&state.silo_groups, &files, &state.rows);
        assert!(state.silo_groups[0].paths.is_empty());

        open_silo_card(&mut state, 0);
        assert_eq!(
            state.screen,
            Screen::Dashboard,
            "an empty silo must not open triage: empty paths mean no constraint"
        );
        assert!(state.filters.is_empty());
        assert!(state.status.contains("empty"), "{}", state.status);
    }

    #[test]
    fn the_board_draws_the_silo_row_under_the_kpi_row() {
        let mut state = state();
        let files = silo_files();
        state.rows = silo_findings();
        state.silo_groups = directory_silo_groups(&files, &state.rows);
        state.silo_cards = silo_cards(&state.silo_groups, &files, &state.rows);

        let (buffer, layout) = render(&state, 120, 40);
        let text = dump(&buffer);
        assert!(text.contains("api"), "{text}");
        assert!(text.contains("140 loc"), "{text}");

        let kpi = layout.cards[Card::Errors.index()].expect("KPI row drawn");
        let silo = hits(&layout);
        assert_eq!(silo.len(), 3);
        assert!(
            silo[0].area.y >= kpi.y + kpi.height,
            "the silo row sits under the KPI row"
        );
    }
}
