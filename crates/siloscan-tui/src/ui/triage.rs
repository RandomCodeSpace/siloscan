//! Triage screen: filter sidebar, findings table, code context pane.
//!
//! Everything the screen needs beyond `AppState` (sort mode, sidebar focus,
//! clickable rectangles) lives in two thread-locals written by the last draw,
//! mirroring how `ui::LayoutMap` is handed to the mouse handler. `LayoutMap`
//! itself is a fixed `Copy` struct owned by `ui/mod.rs`, so the chip and header
//! rectangles are kept here in `Hits` instead.

use std::cell::{Cell as StdCell, RefCell};
use std::cmp::Reverse;
use std::fs;
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Row, Table};

use siloscan_core::findings::Finding;
use siloscan_core::rules::Severity;

use crate::state::{AppState, Pane, Status};
use crate::ui::LayoutMap;

const SIDEBAR_WIDTH: u16 = 24;
/// Below this width the sidebar is dropped whatever the collapse flag says.
const SIDEBAR_MIN_COLS: u16 = 90;
/// Below this width the code pane stacks under the table instead of beside it.
const STACK_COLS: u16 = 120;
const TOP_RULES: usize = 8;
const WHEEL_LINES: isize = 3;
const PAGE_ROWS: usize = 10;

/// View order of the findings table. Purely a permutation of the visible rows;
/// `AppState::rows` stays in canonical order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Sort {
    #[default]
    Canonical,
    Severity,
    Rule,
}

impl Sort {
    pub fn as_str(self) -> &'static str {
        match self {
            Sort::Canonical => "canonical",
            Sort::Severity => "severity",
            Sort::Rule => "rule",
        }
    }

    pub fn next(self) -> Sort {
        match self {
            Sort::Canonical => Sort::Severity,
            Sort::Severity => Sort::Rule,
            Sort::Rule => Sort::Canonical,
        }
    }
}

/// Sidebar section owning the keyboard cursor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Section {
    #[default]
    Severity,
    Status,
    Rules,
}

/// Screen-local view state: not part of the scan model, so it does not belong
/// in `AppState`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TriageView {
    pub sort: Sort,
    pub focus: Section,
    /// Index into `section_chips(state, focus)`.
    pub cursor: usize,
    pub collapsed: bool,
}

/// A clickable filter toggle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chip {
    Severity(Severity),
    Status(Status),
    Rule(String),
}

/// One rendered sidebar row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidebarLine {
    Header(&'static str),
    Chip {
        chip: Chip,
        label: String,
        active: bool,
    },
}

/// Clickable rectangles of the last rendered frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hits {
    pub chips: Vec<(Chip, Rect)>,
    /// Table header row: clicking it cycles the sort.
    pub header: Option<Rect>,
    /// Table data rows, excluding the header.
    pub rows: Option<Rect>,
}

thread_local! {
    static VIEW: StdCell<TriageView> = const { StdCell::new(TriageView {
        sort: Sort::Canonical,
        focus: Section::Severity,
        cursor: 0,
        collapsed: false,
    }) };
    static HITS: RefCell<Hits> = const { RefCell::new(Hits {
        chips: Vec::new(),
        header: None,
        rows: None,
    }) };
}

pub fn view() -> TriageView {
    VIEW.with(StdCell::get)
}

pub fn set_view(view: TriageView) {
    VIEW.with(|cell| cell.set(view));
}

pub fn hits() -> Hits {
    HITS.with(|cell| cell.borrow().clone())
}

pub fn set_hits(hits: Hits) {
    HITS.with(|cell| *cell.borrow_mut() = hits);
}

/// Display order as a permutation of visible positions: entry `d` holds the
/// index into `AppState::visible_rows()` shown on display row `d`.
pub fn view_order(state: &AppState, sort: Sort) -> Vec<usize> {
    let visible = state.visible_rows();
    let mut order: Vec<usize> = (0..visible.len()).collect();
    match sort {
        Sort::Canonical => {}
        Sort::Severity => {
            order.sort_by_key(|&position| Reverse(state.rows[visible[position]].finding.severity));
        }
        Sort::Rule => order.sort_by(|&a, &b| {
            state.rows[visible[a]]
                .finding
                .rule_id
                .cmp(&state.rows[visible[b]].finding.rule_id)
        }),
    }
    order
}

/// Display row currently holding the selection.
pub fn display_position(order: &[usize], selected: usize) -> usize {
    order
        .iter()
        .position(|&position| position == selected)
        .unwrap_or(0)
}

/// Chips of one sidebar section, in render order.
pub fn section_chips(state: &AppState, section: Section) -> Vec<Chip> {
    match section {
        Section::Severity => state
            .counts_by_severity()
            .into_iter()
            .map(|(severity, _)| Chip::Severity(severity))
            .collect(),
        Section::Status => Status::ALL.into_iter().map(Chip::Status).collect(),
        Section::Rules => state
            .top_rules(TOP_RULES)
            .into_iter()
            .map(|(rule, _)| Chip::Rule(rule))
            .collect(),
    }
}

/// Every sidebar row: section headers interleaved with their chips.
pub fn sidebar_lines(state: &AppState) -> Vec<SidebarLine> {
    let mut lines = vec![SidebarLine::Header("Severity")];
    for (severity, count) in state.counts_by_severity() {
        let active = state.filters.severities.contains(&severity);
        lines.push(SidebarLine::Chip {
            label: chip_label(active, severity.as_str(), count),
            chip: Chip::Severity(severity),
            active,
        });
    }

    lines.push(SidebarLine::Header("Status"));
    let (new, baselined, suppressed) = state.debt_counts();
    for (status, count) in [
        (Status::New, new),
        (Status::Baselined, baselined),
        (Status::Suppressed, suppressed),
    ] {
        let active = state.filters.statuses.contains(&status);
        lines.push(SidebarLine::Chip {
            label: chip_label(active, status.as_str(), count),
            chip: Chip::Status(status),
            active,
        });
    }

    lines.push(SidebarLine::Header("Top rules"));
    for (rule, count) in state.top_rules(TOP_RULES) {
        let active = state.filters.rules.contains(&rule);
        lines.push(SidebarLine::Chip {
            label: chip_label(active, &rule, count),
            chip: Chip::Rule(rule),
            active,
        });
    }

    lines
}

fn chip_label(active: bool, name: &str, count: usize) -> String {
    let marker = if active { 'x' } else { ' ' };
    format!("[{marker}] {name} {count}")
}

fn focused_chip(state: &AppState, view: TriageView) -> Option<Chip> {
    section_chips(state, view.focus)
        .into_iter()
        .nth(view.cursor)
}

/// Toggle one filter axis and re-anchor the selection.
pub fn apply_chip(state: &mut AppState, chip: &Chip) {
    match chip {
        Chip::Severity(severity) => state.filters.toggle_severity(*severity),
        Chip::Status(status) => state.filters.toggle_status(*status),
        Chip::Rule(rule) => state.filters.toggle_rule(rule),
    }
    state.clamp_selection();
    state.scroll.table = 0;
    state.scroll.code = 0;
}

pub fn draw_triage(frame: &mut Frame, area: Rect, state: &AppState, layout: &mut LayoutMap) {
    let view = view();
    let show_sidebar = !view.collapsed && area.width >= SIDEBAR_MIN_COLS;

    let (sidebar_area, main) = if show_sidebar {
        let [sidebar, main] =
            Layout::horizontal([Constraint::Length(SIDEBAR_WIDTH), Constraint::Min(20)])
                .areas(area);
        (Some(sidebar), main)
    } else {
        (None, area)
    };

    let [table_area, code_area] = if area.width < STACK_COLS {
        Layout::vertical([Constraint::Min(6), Constraint::Percentage(45)]).areas(main)
    } else {
        Layout::horizontal([Constraint::Min(40), Constraint::Percentage(45)]).areas(main)
    };

    let mut hits = Hits::default();
    if let Some(area) = sidebar_area {
        draw_sidebar(frame, state, area, view, &mut hits);
    }
    draw_table(frame, state, table_area, view, &mut hits);
    draw_code(frame, state, code_area);
    set_hits(hits);

    layout.sidebar = sidebar_area;
    layout.table = Some(table_area);
    layout.code = Some(code_area);
}

fn draw_sidebar(
    frame: &mut Frame,
    state: &AppState,
    area: Rect,
    view: TriageView,
    hits: &mut Hits,
) {
    let block = Block::bordered().title(" filters ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let lines = sidebar_lines(state);
    let focused = focused_chip(state, view);
    let start = state
        .scroll
        .sidebar
        .min(lines.len().saturating_sub(inner.height as usize));

    for (offset, line) in lines
        .iter()
        .skip(start)
        .take(inner.height as usize)
        .enumerate()
    {
        let rect = Rect::new(inner.x, inner.y + offset as u16, inner.width, 1);
        match line {
            SidebarLine::Header(name) => {
                let style = Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
                frame.render_widget(Paragraph::new(Line::styled(*name, style)), rect);
            }
            SidebarLine::Chip {
                chip,
                label,
                active,
            } => {
                let mut style = Style::default();
                if *active {
                    style = style.fg(Color::Green).add_modifier(Modifier::BOLD);
                }
                if focused.as_ref() == Some(chip) {
                    style = style.add_modifier(Modifier::REVERSED);
                }
                frame.render_widget(Paragraph::new(Line::styled(label.clone(), style)), rect);
                hits.chips.push((chip.clone(), rect));
            }
        }
    }
}

fn draw_table(frame: &mut Frame, state: &AppState, area: Rect, view: TriageView, hits: &mut Hits) {
    let show_input = state.input_mode || !state.filters.text.is_empty();
    let (list_area, input_area) = if show_input && area.height >= 4 {
        let [list, input] =
            Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(area);
        (list, Some(input))
    } else {
        (area, None)
    };

    if let Some(input_area) = input_area {
        let caret = if state.input_mode { "_" } else { "" };
        let spans = vec![
            Span::styled("/", Style::default().fg(Color::Cyan)),
            Span::raw(state.filters.text.clone()),
            Span::styled(caret, Style::default().add_modifier(Modifier::REVERSED)),
        ];
        frame.render_widget(Paragraph::new(Line::from(spans)), input_area);
    }

    let title = format!(
        " findings {}/{}  sort:{} ",
        state.visible_len(),
        state.rows.len(),
        view.sort.as_str()
    );
    let block = Block::bordered().title(title);
    let inner = block.inner(list_area);
    frame.render_widget(block, list_area);
    if inner.width == 0 || inner.height < 2 {
        return;
    }

    let header_rect = Rect::new(inner.x, inner.y, inner.width, 1);
    let rows_rect = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);
    hits.header = Some(header_rect);
    hits.rows = Some(rows_rect);

    let order = view_order(state, view.sort);
    let height = rows_rect.height as usize;
    let visible = state.visible_rows();
    let selected_display = display_position(&order, state.selected);
    // Draw does not mutate state; the handlers clamp with the same rule.
    let start = clamp_scroll(state.scroll.table, order.len(), height);

    let rows: Vec<Row> = order
        .iter()
        .skip(start)
        .take(height)
        .enumerate()
        .map(|(offset, &position)| {
            let row = &state.rows[visible[position]];
            let finding = &row.finding;
            let cells = vec![
                Span::raw(status_label(row.status).to_string()),
                Span::styled(
                    severity_label(finding.severity).to_string(),
                    Style::default().fg(severity_color(finding.severity)),
                ),
                Span::raw(format!("{}:{}", finding.path, finding.line)),
                Span::raw(finding.rule_id.clone()),
                Span::raw(finding.message.clone()),
            ];
            let table_row = Row::new(cells);
            if start + offset == selected_display {
                table_row.style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                table_row
            }
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(4),
        Constraint::Fill(3),
        Constraint::Fill(2),
        Constraint::Fill(5),
    ];
    let header = Row::new(vec!["St", "Sev", "Path:Line", "Rule", "Message"])
        .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED));
    let table = Table::new(rows, widths).header(header).column_spacing(1);
    frame.render_widget(table, inner);

    if order.is_empty() {
        frame.render_widget(Paragraph::new("no findings match the filters"), rows_rect);
    }
}

fn clamp_scroll(offset: usize, rows: usize, height: usize) -> usize {
    offset.min(rows.saturating_sub(height))
}

fn draw_code(frame: &mut Frame, state: &AppState, area: Rect) {
    let selected = state.selected_row();
    let title = match selected {
        Some(row) => format!(" {}:{} ", row.finding.path, row.finding.line),
        None => " code ".to_string(),
    };
    let block = Block::bordered().title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let Some(row) = selected else {
        frame.render_widget(Paragraph::new("no finding selected"), inner);
        return;
    };

    let lines = match read_source(&state.root, &row.finding.path) {
        Ok(source) => code_lines(
            &source,
            &row.finding,
            inner.height as usize,
            state.scroll.code,
        ),
        Err(reason) => vec![Line::from(format!("source unavailable: {reason}"))],
    };
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The scan root is usually a directory; when a single file was scanned the
/// finding path is that file, so fall back to the root itself.
fn read_source(root: &Path, path: &str) -> Result<String, String> {
    fs::read_to_string(root.join(path)).or_else(|error| {
        if root.is_file() {
            fs::read_to_string(root).map_err(|error| error.to_string())
        } else {
            Err(error.to_string())
        }
    })
}

/// A window of `height` source lines centred on the finding, offset by `scroll`.
fn code_lines(source: &str, finding: &Finding, height: usize, scroll: usize) -> Vec<Line<'static>> {
    let all: Vec<&str> = source.lines().collect();
    if all.is_empty() {
        return vec![Line::from("source unavailable: empty file".to_string())];
    }

    let height = height.max(1);
    let target = finding.line.max(1) as usize - 1;
    let max_start = all.len().saturating_sub(height);
    let start = target
        .saturating_sub(height / 2)
        .saturating_add(scroll)
        .min(max_start);

    let mut lines = Vec::new();
    let end = start.saturating_add(height).min(all.len());
    for (offset, text) in all[start..end].iter().enumerate() {
        let number = start + offset + 1;
        let text = *text;
        let gutter = Span::styled(
            format!("{number:>5} "),
            Style::default().fg(Color::DarkGray),
        );
        if number as u64 == finding.line {
            let (before, matched, after) = split_span(
                text,
                finding.column.max(1) as usize - 1,
                finding.matched.len(),
            );
            let highlight = Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD);
            lines.push(Line::from(vec![
                gutter,
                Span::styled(before.to_string(), highlight),
                Span::styled(
                    matched.to_string(),
                    Style::default().add_modifier(Modifier::REVERSED),
                ),
                Span::styled(after.to_string(), highlight),
            ]));
        } else {
            lines.push(Line::from(vec![gutter, Span::raw(text.to_string())]));
        }
    }
    lines
}

/// Split `text` at a byte offset and length, snapped to char boundaries.
fn split_span(text: &str, start: usize, len: usize) -> (&str, &str, &str) {
    let begin = floor_boundary(text, start.min(text.len()));
    let end = floor_boundary(text, begin.saturating_add(len).min(text.len())).max(begin);
    (&text[..begin], &text[begin..end], &text[end..])
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn status_label(status: Status) -> &'static str {
    match status {
        Status::New => "new",
        Status::Baselined => "base",
        Status::Suppressed => "supp",
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "err",
        Severity::Warning => "warn",
        Severity::Info => "info",
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Error => Color::Red,
        Severity::Warning => Color::Yellow,
        Severity::Info => Color::Cyan,
    }
}

pub fn handle_key_triage(state: &mut AppState, key: KeyEvent) {
    if state.input_mode {
        match key.code {
            KeyCode::Char(c) => state.filters.text.push(c),
            KeyCode::Backspace => {
                state.filters.text.pop();
            }
            KeyCode::Esc => {
                state.filters.text.clear();
                state.input_mode = false;
            }
            KeyCode::Enter => state.input_mode = false,
            _ => return,
        }
        state.clamp_selection();
        state.scroll.table = 0;
        state.scroll.code = 0;
        return;
    }

    let mut view = view();
    match key.code {
        KeyCode::Char('/') => state.input_mode = true,
        KeyCode::Tab => {
            view.collapsed = !view.collapsed;
            set_view(view);
        }
        KeyCode::Char('s') => focus_section(state, view, Section::Severity),
        KeyCode::Char('t') => focus_section(state, view, Section::Status),
        KeyCode::Char('f') => focus_section(state, view, Section::Rules),
        KeyCode::Char('o') => {
            view.sort = view.sort.next();
            set_view(view);
        }
        KeyCode::Enter => {
            if let Some(chip) = focused_chip(state, view) {
                apply_chip(state, &chip);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.select_next();
            follow_selection(state, view);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.select_prev();
            follow_selection(state, view);
        }
        KeyCode::PageDown => {
            for _ in 0..PAGE_ROWS {
                state.select_next();
            }
            follow_selection(state, view);
        }
        KeyCode::PageUp => {
            for _ in 0..PAGE_ROWS {
                state.select_prev();
            }
            follow_selection(state, view);
        }
        KeyCode::Esc => {
            state.filters.clear();
            state.clamp_selection();
            state.scroll.table = 0;
            state.scroll.code = 0;
        }
        _ => {}
    }
}

fn focus_section(state: &AppState, mut view: TriageView, section: Section) {
    let len = section_chips(state, section).len();
    if view.focus == section && len > 0 {
        view.cursor = (view.cursor + 1) % len;
    } else {
        view.focus = section;
        view.cursor = 0;
    }
    set_view(view);
}

/// Keep the selected display row inside the viewport of the last frame.
fn follow_selection(state: &mut AppState, view: TriageView) {
    state.scroll.code = 0;
    let height = hits().rows.map_or(0, |rect| rect.height as usize);
    if height == 0 {
        return;
    }

    let order = view_order(state, view.sort);
    let display = display_position(&order, state.selected);
    if display < state.scroll.table {
        state.scroll.table = display;
    } else if display >= state.scroll.table + height {
        state.scroll.table = display + 1 - height;
    }
}

pub fn handle_mouse_triage(state: &mut AppState, event: MouseEvent, layout: &LayoutMap) {
    handle_mouse_with(state, event, layout, &hits());
}

/// Mouse routing against explicit rectangles, so it is testable without a draw.
pub fn handle_mouse_with(state: &mut AppState, event: MouseEvent, layout: &LayoutMap, hits: &Hits) {
    let (column, row) = (event.column, event.row);
    match event.kind {
        MouseEventKind::ScrollUp => wheel(state, layout, hits, column, row, -WHEEL_LINES),
        MouseEventKind::ScrollDown => wheel(state, layout, hits, column, row, WHEEL_LINES),
        MouseEventKind::Down(MouseButton::Left) => {
            if hits.header.is_some_and(|rect| inside(rect, column, row)) {
                let mut view = view();
                view.sort = view.sort.next();
                set_view(view);
                return;
            }
            if let Some(rect) = hits.rows.filter(|rect| inside(*rect, column, row)) {
                let order = view_order(state, view().sort);
                let start = clamp_scroll(state.scroll.table, order.len(), rect.height as usize);
                let display = start + (row - rect.y) as usize;
                if let Some(&position) = order.get(display) {
                    state.select_visible(position);
                }
                return;
            }
            if let Some((chip, _)) = hits
                .chips
                .iter()
                .find(|(_, rect)| inside(*rect, column, row))
            {
                apply_chip(state, &chip.clone());
            }
        }
        _ => {}
    }
}

fn wheel(
    state: &mut AppState,
    layout: &LayoutMap,
    hits: &Hits,
    column: u16,
    row: u16,
    delta: isize,
) {
    let Some(pane) = layout.pane_at(column, row) else {
        return;
    };
    state.scroll_by(pane, delta);
    if pane == Pane::Table {
        let height = hits.rows.map_or(0, |rect| rect.height as usize);
        state.scroll.table = clamp_scroll(state.scroll.table, state.visible_len(), height);
    }
}

fn inside(rect: Rect, column: u16, row: u16) -> bool {
    column >= rect.x
        && column < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::Arc;

    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use siloscan_core::rules::RuleSet;

    use crate::state::FindingRow;

    const SOURCE: &str =
        "fn main() {\n    let token = \"needle\";\n    println!(\"{token}\");\n}\n";

    fn temp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("siloscan-tui-triage-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/a.rs"), SOURCE).unwrap();
        fs::write(dir.join("src/b.rs"), SOURCE).unwrap();
        dir
    }

    fn finding(rule_id: &str, severity: Severity, path: &str, line: u64, message: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            message: message.to_string(),
            path: path.to_string(),
            line,
            column: 17,
            matched: "needle".to_string(),
            fingerprint: format!("{rule_id}:{path}:{line}"),
        }
    }

    fn row(rule_id: &str, severity: Severity, path: &str, status: Status) -> FindingRow {
        FindingRow {
            finding: finding(rule_id, severity, path, 2, "hardcoded secret"),
            status,
        }
    }

    fn state(root: PathBuf) -> AppState {
        let mut state = AppState::new(root, Arc::new(RuleSet { rules: Vec::new() }), None);
        state.rows = vec![
            row("secret.token", Severity::Info, "src/a.rs", Status::New),
            row("regex.todo", Severity::Error, "src/a.rs", Status::Baselined),
            row("secret.token", Severity::Warning, "src/b.rs", Status::New),
            row(
                "alpha.rule",
                Severity::Error,
                "src/b.rs",
                Status::Suppressed,
            ),
        ];
        state
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn click(column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn render(state: &AppState, width: u16, height: u16) -> (Buffer, LayoutMap) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut map = LayoutMap::default();
        terminal
            .draw(|frame| {
                let area = frame.area();
                draw_triage(frame, area, state, &mut map);
            })
            .unwrap();
        (terminal.backend().buffer().clone(), map)
    }

    fn dump(buffer: &Buffer) -> String {
        dump_rect(buffer, buffer.area)
    }

    fn dump_rect(buffer: &Buffer, rect: Rect) -> String {
        let mut out = String::new();
        for y in rect.y..rect.y + rect.height {
            for x in rect.x..rect.x + rect.width {
                out.push_str(buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()));
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn renders_narrow_with_the_code_pane_stacked() {
        let root = temp_root("narrow");
        let state = state(root.clone());
        let (buffer, map) = render(&state, 80, 24);
        let text = dump(&buffer);

        assert!(map.sidebar.is_none(), "sidebar hidden below 90 cols");
        let table = map.table.unwrap();
        let code = map.code.unwrap();
        assert_eq!(table.x, code.x, "code stacks under the table");
        assert!(code.y >= table.y + table.height);

        assert!(text.contains("secret.token"), "{text}");
        assert!(text.contains("src/a.rs:2"), "{text}");
        // Code pane read the real file from disk.
        assert!(text.contains("let token"), "{text}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn renders_wide_with_sidebar_and_side_by_side_code() {
        let root = temp_root("wide");
        let state = state(root.clone());
        let (buffer, map) = render(&state, 160, 48);
        let text = dump(&buffer);

        let sidebar = map.sidebar.expect("sidebar shown at 160 cols");
        assert_eq!(sidebar.width, SIDEBAR_WIDTH);
        let table = map.table.unwrap();
        let code = map.code.unwrap();
        assert_eq!(table.y, code.y, "code sits beside the table");
        assert!(code.x >= table.x + table.width);

        assert!(text.contains("Severity"), "{text}");
        assert!(text.contains("Top rules"), "{text}");
        assert!(text.contains("[ ] error"), "{text}");
        assert!(text.contains("let token"), "{text}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_source_renders_a_placeholder() {
        let root = temp_root("missing");
        let mut state = state(root.clone());
        state.rows[0].finding.path = "src/gone.rs".to_string();
        state.selected = 0;
        let (buffer, _) = render(&state, 160, 48);

        assert!(dump(&buffer).contains("source unavailable:"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sort_is_a_deterministic_permutation_of_the_visible_rows() {
        let state = state(PathBuf::from("/nowhere"));

        assert_eq!(view_order(&state, Sort::Canonical), vec![0, 1, 2, 3]);
        // Error, Error, Warning, Info with canonical order as the tie-break.
        assert_eq!(view_order(&state, Sort::Severity), vec![1, 3, 2, 0]);
        // alpha.rule, regex.todo, secret.token, secret.token.
        assert_eq!(view_order(&state, Sort::Rule), vec![3, 1, 0, 2]);

        for sort in [Sort::Canonical, Sort::Severity, Sort::Rule] {
            let mut sorted = view_order(&state, sort);
            sorted.sort_unstable();
            assert_eq!(sorted, vec![0, 1, 2, 3], "{sort:?} is a permutation");
            assert_eq!(view_order(&state, sort), view_order(&state, sort));
        }
    }

    #[test]
    fn sorting_does_not_reorder_the_underlying_rows() {
        let state = state(PathBuf::from("/nowhere"));
        let before: Vec<String> = state
            .rows
            .iter()
            .map(|row| row.finding.rule_id.clone())
            .collect();

        set_view(TriageView {
            sort: Sort::Severity,
            ..TriageView::default()
        });
        let _ = render(&state, 160, 48);

        let after: Vec<String> = state
            .rows
            .iter()
            .map(|row| row.finding.rule_id.clone())
            .collect();
        assert_eq!(before, after);
    }

    #[test]
    fn text_filter_narrows_the_visible_rows() {
        let root = temp_root("filter");
        let mut state = state(root.clone());

        let (wide, map) = render(&state, 160, 48);
        let before = dump_rect(&wide, map.table.unwrap());
        assert!(before.contains("regex.todo"), "{before}");
        assert!(before.contains("secret.token"), "{before}");
        assert!(before.contains("findings 4/4"), "{before}");

        handle_key_triage(&mut state, key(KeyCode::Char('/')));
        assert!(state.input_mode);
        for c in "regex".chars() {
            handle_key_triage(&mut state, key(KeyCode::Char(c)));
        }
        handle_key_triage(&mut state, key(KeyCode::Backspace));
        assert_eq!(state.filters.text, "rege");
        assert_eq!(state.visible_len(), 1);

        let (narrow, map) = render(&state, 160, 48);
        let after = dump_rect(&narrow, map.table.unwrap());
        assert!(after.contains("findings 1/4"), "{after}");
        assert!(after.contains("regex.todo"), "{after}");
        // The sidebar still lists every rule chip; only the table narrows.
        assert!(!after.contains("secret.token"), "{after}");

        handle_key_triage(&mut state, key(KeyCode::Esc));
        assert!(!state.input_mode);
        assert!(state.filters.text.is_empty());
        assert_eq!(state.visible_len(), 4);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clicking_a_chip_toggles_that_filter() {
        let root = temp_root("chip");
        let mut state = state(root.clone());
        let (_, map) = render(&state, 160, 48);

        let hits = hits();
        let (chip, rect) = hits
            .chips
            .iter()
            .find(|(chip, _)| *chip == Chip::Severity(Severity::Error))
            .cloned()
            .unwrap();
        assert_eq!(chip, Chip::Severity(Severity::Error));

        handle_mouse_with(&mut state, click(rect.x + 1, rect.y), &map, &hits);
        assert!(state.filters.severities.contains(&Severity::Error));
        assert_eq!(state.visible_len(), 2);

        handle_mouse_with(&mut state, click(rect.x + 1, rect.y), &map, &hits);
        assert!(state.filters.is_empty());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clicking_the_header_cycles_the_sort() {
        let root = temp_root("header");
        let mut state = state(root.clone());
        set_view(TriageView::default());
        let (_, map) = render(&state, 160, 48);

        let hits = hits();
        let header = hits.header.unwrap();
        handle_mouse_with(&mut state, click(header.x + 2, header.y), &map, &hits);
        assert_eq!(view().sort, Sort::Severity);
        handle_mouse_with(&mut state, click(header.x + 2, header.y), &map, &hits);
        assert_eq!(view().sort, Sort::Rule);
        handle_mouse_with(&mut state, click(header.x + 2, header.y), &map, &hits);
        assert_eq!(view().sort, Sort::Canonical);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clicking_a_row_selects_through_the_sort_permutation() {
        let root = temp_root("select");
        let mut state = state(root.clone());
        set_view(TriageView {
            sort: Sort::Rule,
            ..TriageView::default()
        });
        let (_, map) = render(&state, 160, 48);

        let hits = hits();
        let rows = hits.rows.unwrap();
        // Rule order puts alpha.rule (canonical position 3) on display row 0.
        handle_mouse_with(&mut state, click(rows.x + 1, rows.y), &map, &hits);
        assert_eq!(state.selected, 3);
        assert_eq!(state.selected_row().unwrap().finding.rule_id, "alpha.rule");

        handle_mouse_with(&mut state, click(rows.x + 1, rows.y + 2), &map, &hits);
        assert_eq!(state.selected, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn keyboard_moves_the_selection_and_the_wheel_scrolls_panes() {
        let root = temp_root("keys");
        let mut state = state(root.clone());
        set_view(TriageView::default());
        let (_, map) = render(&state, 160, 48);

        handle_key_triage(&mut state, key(KeyCode::Char('j')));
        assert_eq!(state.selected, 1);
        handle_key_triage(&mut state, key(KeyCode::Down));
        assert_eq!(state.selected, 2);
        handle_key_triage(&mut state, key(KeyCode::Char('k')));
        assert_eq!(state.selected, 1);
        handle_key_triage(&mut state, key(KeyCode::PageDown));
        assert_eq!(state.selected, 3);
        handle_key_triage(&mut state, key(KeyCode::PageUp));
        assert_eq!(state.selected, 0);

        let code = map.code.unwrap();
        let wheel = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: code.x + 1,
            row: code.y + 1,
            modifiers: KeyModifiers::NONE,
        };
        handle_mouse_with(&mut state, wheel, &map, &hits());
        assert_eq!(state.scroll.code, WHEEL_LINES as usize);
        assert_eq!(state.scroll.table, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn section_keys_cycle_focus_and_enter_toggles() {
        let mut state = state(PathBuf::from("/nowhere"));
        set_view(TriageView::default());

        handle_key_triage(&mut state, key(KeyCode::Char('t')));
        assert_eq!(view().focus, Section::Status);
        assert_eq!(view().cursor, 0);
        handle_key_triage(&mut state, key(KeyCode::Char('t')));
        assert_eq!(view().cursor, 1);

        handle_key_triage(&mut state, key(KeyCode::Enter));
        assert!(state.filters.statuses.contains(&Status::Baselined));
        assert_eq!(state.visible_len(), 1);

        handle_key_triage(&mut state, key(KeyCode::Char('f')));
        assert_eq!(view().focus, Section::Rules);
        handle_key_triage(&mut state, key(KeyCode::Enter));
        assert!(!state.filters.rules.is_empty());

        handle_key_triage(&mut state, key(KeyCode::Esc));
        assert!(state.filters.is_empty());
    }

    #[test]
    fn tab_collapses_the_sidebar() {
        let root = temp_root("collapse");
        let mut state = state(root.clone());
        set_view(TriageView::default());

        let (_, map) = render(&state, 160, 48);
        assert!(map.sidebar.is_some());

        handle_key_triage(&mut state, key(KeyCode::Tab));
        let (_, map) = render(&state, 160, 48);
        assert!(map.sidebar.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn code_window_centres_on_the_finding_and_marks_the_match() {
        let source = (1..=40)
            .map(|n| format!("line {n}"))
            .collect::<Vec<String>>()
            .join("\n");
        let mut finding = finding("r", Severity::Info, "a.rs", 20, "m");
        finding.column = 6;
        finding.matched = "20".to_string();

        let lines = code_lines(&source, &finding, 11, 0);
        assert_eq!(lines.len(), 11);
        assert!(lines[0].to_string().contains("line 15"));
        assert!(lines[5].to_string().contains("line 20"));

        let scrolled = code_lines(&source, &finding, 11, 4);
        assert!(scrolled[0].to_string().contains("line 19"));

        // Gutter, before, matched, after.
        assert_eq!(lines[5].spans.len(), 4);
        assert_eq!(lines[5].spans[2].content, "20");
    }

    #[test]
    fn code_window_survives_short_lines_and_bad_columns() {
        let mut finding = finding("r", Severity::Info, "a.rs", 1, "m");
        finding.column = 99;
        finding.matched = "needle".to_string();
        let lines = code_lines("ab\n", &finding, 4, 0);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].spans[1].content, "ab");
        assert!(lines[0].spans[2].content.is_empty());

        assert_eq!(code_lines("", &finding, 4, 0).len(), 1);
    }

    #[test]
    fn split_span_snaps_to_char_boundaries() {
        let text = "let x = \"héllo\";";
        let (before, matched, after) = split_span(text, 9, 6);
        assert_eq!(before, "let x = \"");
        assert!(text.starts_with(before));
        assert_eq!(format!("{before}{matched}{after}"), text);
        assert!(matched.starts_with('h'));
    }

    #[test]
    fn sidebar_lines_cover_every_section() {
        let mut state = state(PathBuf::from("/nowhere"));
        state.filters.toggle_severity(Severity::Error);
        let lines = sidebar_lines(&state);

        let headers: Vec<&str> = lines
            .iter()
            .filter_map(|line| match line {
                SidebarLine::Header(name) => Some(*name),
                _ => None,
            })
            .collect();
        assert_eq!(headers, vec!["Severity", "Status", "Top rules"]);

        let active: Vec<&Chip> = lines
            .iter()
            .filter_map(|line| match line {
                SidebarLine::Chip { chip, active, .. } if *active => Some(chip),
                _ => None,
            })
            .collect();
        assert_eq!(active, vec![&Chip::Severity(Severity::Error)]);
        assert_eq!(
            section_chips(&state, Section::Status),
            vec![
                Chip::Status(Status::New),
                Chip::Status(Status::Baselined),
                Chip::Status(Status::Suppressed),
            ]
        );
    }

    #[test]
    fn scrolling_keeps_the_selection_visible() {
        let mut state = state(PathBuf::from("/nowhere"));
        for index in 0..60 {
            state.rows.push(row(
                "bulk.rule",
                Severity::Info,
                &format!("src/f{index}.rs"),
                Status::New,
            ));
        }
        set_view(TriageView::default());
        let _ = render(&state, 160, 20);

        for _ in 0..40 {
            handle_key_triage(&mut state, key(KeyCode::Char('j')));
        }
        let height = hits().rows.unwrap().height as usize;
        assert!(state.scroll.table > 0);
        assert!(state.selected >= state.scroll.table);
        assert!(state.selected < state.scroll.table + height);

        for _ in 0..40 {
            handle_key_triage(&mut state, key(KeyCode::Char('k')));
        }
        assert_eq!(state.scroll.table, 0);
    }
}
