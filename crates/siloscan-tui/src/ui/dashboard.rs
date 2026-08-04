//! Dashboard screen: a stats board over the whole scan.
//!
//! Deliberately free of file-level detail, which belongs to the triage screen.
//! Rows are laid out top to bottom by importance - quality gate, KPI cards,
//! charts, debt strip - and dropped bottom-up when the terminal is short, so a
//! nine-row strip still carries the gate and the cards.
//!
//! The KPI cards are clickable: each one records its rectangle in the
//! `LayoutMap` and `open_card` turns a click into the equivalent triage filter.

use std::collections::{BTreeMap, BTreeSet};

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Bar, BarChart, Gauge, Paragraph};

use siloscan_core::rules::{CompiledPayload, Severity};

use crate::state::{AppState, Screen, Status};
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
}

impl Card {
    pub const COUNT: usize = 6;
    pub const ALL: [Card; Card::COUNT] = [
        Card::Errors,
        Card::Warnings,
        Card::Info,
        Card::New,
        Card::Debt,
        Card::Rating,
    ];

    pub fn index(self) -> usize {
        match self {
            Card::Errors => 0,
            Card::Warnings => 1,
            Card::Info => 2,
            Card::New => 3,
            Card::Debt => 4,
            Card::Rating => 5,
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
        }
    }

    /// What the tile prints, big: a count, or the rating letter.
    pub fn value(self, state: &AppState) -> String {
        let (new, baselined, suppressed) = state.debt_counts();
        match self {
            Card::Errors => severity_total(state, Severity::Error).to_string(),
            Card::Warnings => severity_total(state, Severity::Warning).to_string(),
            Card::Info => severity_total(state, Severity::Info).to_string(),
            Card::New => new.to_string(),
            Card::Debt => (baselined + suppressed).to_string(),
            Card::Rating => rating(state).to_string(),
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
        }
    }
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
/// rating is a verdict, not an axis, so it is inert.
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
        Card::Rating => return,
    }

    state.filters = filters;
    state.screen = Screen::Triage;
    state.selected = 0;
    state.clamp_selection();
    state.scroll.table = 0;
    state.scroll.code = 0;
}

/// Which rows of the board fit. Sections are dropped from the bottom up; a
/// leftover too short for the charts still goes to the debt strip, which reads
/// fine in three rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Plan {
    gate: Option<Rect>,
    cards: Option<Rect>,
    charts: Option<Rect>,
    bottom: Option<Rect>,
}

fn plan(area: Rect) -> Plan {
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

    let (charts, bottom) = if rows >= CHART_MIN_ROWS + BOTTOM_ROWS {
        (rows - BOTTOM_ROWS, BOTTOM_ROWS)
    } else if rows >= CHART_MIN_ROWS {
        (rows, 0)
    } else if rows >= BOTTOM_ROWS {
        (0, BOTTOM_ROWS)
    } else {
        (0, 0)
    };

    let areas: [Rect; 5] = Layout::vertical([
        Constraint::Length(gate),
        Constraint::Length(cards),
        Constraint::Length(charts),
        Constraint::Length(bottom),
        Constraint::Min(0),
    ])
    .areas(area);

    Plan {
        gate: keep(areas[0]),
        cards: keep(areas[1]),
        charts: keep(areas[2]),
        bottom: keep(areas[3]),
    }
}

fn keep(area: Rect) -> Option<Rect> {
    (area.height > 0).then_some(area)
}

pub fn draw(frame: &mut Frame, area: Rect, state: &AppState, layout: &mut LayoutMap) {
    if area.width < MIN_COLS || area.height == 0 {
        return;
    }

    let plan = plan(area);
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

    // Glyphs need three rows plus one for the label, and the columns to draw
    // them in; anything less prints the number.
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

    if lines.len() < inner.height as usize {
        lines.push(Line::styled(
            card.label(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
    }

    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
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

/// Rule ids are dotted and the tail is the informative half.
fn tail_truncate(text: &str, width: usize) -> String {
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
fn coverage_findings(state: &AppState) -> usize {
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
    fn renders_at_80x24_with_every_card() {
        let (buffer, layout) = render(&state(), 80, 24);
        let text = dump(&buffer);

        assert!(text.contains("FAILED"), "{text}");
        assert!(text.contains("Warnings"), "{text}");
        assert_eq!(
            layout.cards.iter().filter(|card| card.is_some()).count(),
            Card::COUNT
        );
    }

    #[test]
    fn short_terminals_drop_rows_from_the_bottom() {
        // A nine-row strip keeps the gate and the cards and nothing else.
        let strip = plan(Rect::new(0, 0, 200, 9));
        assert_eq!(strip.gate.map(|area| area.height), Some(GATE_ROWS));
        assert_eq!(strip.cards.map(|area| area.height), Some(CARD_ROWS));
        assert!(strip.charts.is_none());
        assert!(strip.bottom.is_none());

        // Enough for everything: the charts take the slack.
        let full = plan(Rect::new(0, 0, 200, 30));
        assert_eq!(full.charts.map(|area| area.height), Some(18));
        assert_eq!(full.bottom.map(|area| area.height), Some(BOTTOM_ROWS));

        // Three rows: the gate alone.
        let gate_only = plan(Rect::new(0, 0, 200, 3));
        assert!(gate_only.gate.is_some());
        assert!(gate_only.cards.is_none());
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
}
