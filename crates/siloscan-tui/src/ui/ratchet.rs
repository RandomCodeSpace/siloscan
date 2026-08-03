//! Ratchet console: step through the findings that are still NEW and give each
//! one a verdict. Accepting writes the baseline, ignoring edits the source
//! file; skipping leaves the finding failing.
//!
//! Layout, hit testing and verdict application are pure functions over `Rect`
//! and `AppState`, so they are unit-testable without a terminal.

use std::cell::RefCell;
use std::fs;

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Gauge, Paragraph, Wrap};

use siloscan_core::findings::Finding;
use siloscan_core::rules::Severity;

use crate::actions;
use crate::state::{AppState, Pane, Status};
use crate::ui::LayoutMap;

/// Below this width the code context and the finding details stack instead of
/// sitting side by side.
const WIDE: u16 = 90;

/// Lines of source shown around the finding when the pane is unconstrained.
const CONTEXT: usize = 40;

/// A verdict the user can give the current finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Baseline,
    Ignore,
    Next,
    Prev,
    Back,
}

impl Verdict {
    pub const ALL: [Verdict; 5] = [
        Verdict::Baseline,
        Verdict::Ignore,
        Verdict::Next,
        Verdict::Prev,
        Verdict::Back,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Verdict::Baseline => "[b]aseline",
            Verdict::Ignore => "[i]gnore-inline",
            Verdict::Next => "[n]ext/skip",
            Verdict::Prev => "[p]rev",
            Verdict::Back => "[esc] back",
        }
    }
}

thread_local! {
    /// Verdict buttons of the last rendered ratchet frame, for mouse hit
    /// testing. Draw and input handling both run on the main thread.
    static BUTTONS: RefCell<Vec<(Verdict, Rect)>> = const { RefCell::new(Vec::new()) };
}

fn set_buttons(buttons: Vec<(Verdict, Rect)>) {
    BUTTONS.with(|cell| *cell.borrow_mut() = buttons);
}

fn buttons() -> Vec<(Verdict, Rect)> {
    BUTTONS.with(|cell| cell.borrow().clone())
}

/// Render the console into `area` and return the pane rectangles of the frame.
pub fn draw_ratchet(frame: &mut Frame, state: &AppState, area: Rect) -> LayoutMap {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);
    let (header, body, footer) = (chunks[0], chunks[1], chunks[2]);

    draw_header(frame, state, header);

    let (code_area, details_area) = split_body(body);
    let map = LayoutMap {
        code: Some(code_area),
        dashboard: Some(details_area),
        ..LayoutMap::default()
    };

    match state.ratchet_finding() {
        Some(finding) => {
            draw_code(frame, state, finding, code_area);
            draw_details(frame, finding, details_area);
        }
        None => {
            let message = if state.scan_running {
                "scanning"
            } else {
                "no new findings: the ratchet is clean"
            };
            frame.render_widget(
                Paragraph::new(message).block(Block::bordered().title(" context ")),
                code_area,
            );
            frame.render_widget(
                Paragraph::new("").block(Block::bordered().title(" finding ")),
                details_area,
            );
        }
    }

    let footer_buttons = footer_buttons(footer);
    draw_footer(frame, state, footer, &footer_buttons);
    set_buttons(footer_buttons);

    map
}

/// Side by side on a wide terminal, stacked on a narrow one. The code pane
/// keeps the elastic share in both directions.
pub fn split_body(area: Rect) -> (Rect, Rect) {
    let layout = if area.width >= WIDE {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(20), Constraint::Percentage(35)])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Percentage(40)])
    };
    let chunks = layout.split(area);
    (chunks[0], chunks[1])
}

/// Equal-width verdict buttons across the footer, in `Verdict::ALL` order.
pub fn footer_buttons(footer: Rect) -> Vec<(Verdict, Rect)> {
    let inner = Rect {
        x: footer.x.saturating_add(1),
        y: footer.y.saturating_add(1),
        width: footer.width.saturating_sub(2),
        height: footer.height.saturating_sub(2),
    };
    if inner.width == 0 || inner.height == 0 {
        return Vec::new();
    }

    let count = Verdict::ALL.len() as u32;
    let cells = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            Verdict::ALL
                .iter()
                .map(|_| Constraint::Ratio(1, count))
                .collect::<Vec<Constraint>>(),
        )
        .split(inner);

    Verdict::ALL
        .into_iter()
        .zip(cells.iter().copied())
        .collect()
}

/// Verdict whose button covers the position, if any.
pub fn button_at(buttons: &[(Verdict, Rect)], column: u16, row: u16) -> Option<Verdict> {
    buttons
        .iter()
        .find(|(_, area)| contains(*area, column, row))
        .map(|(verdict, _)| *verdict)
}

fn contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x
        && column < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
}

fn draw_header(frame: &mut Frame, state: &AppState, area: Rect) {
    let total = state.new_rows().len();
    let position = if total == 0 {
        0
    } else {
        state.ratchet_cursor + 1
    };
    let title = format!(" Ratchet: {position} of {total} new findings ");

    let ratio = if state.scan_running {
        state.progress_ratio()
    } else if total == 0 {
        1.0
    } else {
        (state.ratchet_cursor as f64 / total as f64).clamp(0.0, 1.0)
    };
    let label = if state.scan_running {
        match state.progress {
            Some(progress) => format!(
                "scanning {}/{} files, {} findings",
                progress.files_done, progress.files_total, progress.findings
            ),
            None => "scanning".to_string(),
        }
    } else {
        let (_, baselined, suppressed) = state.debt_counts();
        format!("{baselined} baselined, {suppressed} suppressed")
    };

    frame.render_widget(
        Gauge::default()
            .block(Block::bordered().title(title))
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio(ratio)
            .label(label),
        area,
    );
}

fn draw_code(frame: &mut Frame, state: &AppState, finding: &Finding, area: Rect) {
    let path = state.root.join(&finding.path);
    let title = format!(" {}:{} ", finding.path, finding.line);
    let block = Block::bordered().title(title);

    let height = area.height.saturating_sub(2) as usize;
    let lines = match fs::read_to_string(&path) {
        Ok(content) => code_lines(&content, finding, state.scroll.code, height.max(1)),
        Err(e) => vec![Line::from(format!("{}: {e}", path.display()))],
    };

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// The window of source around the finding, gutter included, with the matched
/// span highlighted. `offset` scrolls the window down from that anchor.
pub fn code_lines(
    content: &str,
    finding: &Finding,
    offset: usize,
    height: usize,
) -> Vec<Line<'static>> {
    let all: Vec<&str> = content.lines().collect();
    if all.is_empty() {
        return Vec::new();
    }

    let target = finding.line.saturating_sub(1) as usize;
    let window = height.clamp(1, CONTEXT);
    let anchor = target.saturating_sub(window / 2);
    let start = anchor
        .saturating_add(offset)
        .min(all.len().saturating_sub(1));
    let end = start.saturating_add(window).min(all.len());

    let width = end.to_string().len();
    all[start..end]
        .iter()
        .enumerate()
        .map(|(index, text)| {
            let number = start + index;
            let gutter = Span::styled(
                format!("{:>width$} | ", number + 1, width = width),
                Style::default().fg(Color::DarkGray),
            );
            let mut spans = vec![gutter];
            if number == target {
                spans.extend(highlight(text, finding.column, &finding.matched));
            } else {
                spans.push(Span::raw((*text).to_string()));
            }
            Line::from(spans)
        })
        .collect()
}

/// Split a line around the matched span. The column is a 1-based byte offset;
/// anything that does not line up falls back to a plain line.
fn highlight(text: &str, column: u64, matched: &str) -> Vec<Span<'static>> {
    let style = Style::default()
        .fg(Color::Black)
        .bg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let start = (column.saturating_sub(1)) as usize;
    let start = if text.is_char_boundary(start) && text[start..].starts_with(matched) {
        start
    } else {
        match text.find(matched) {
            Some(found) => found,
            None => return vec![Span::raw(text.to_string())],
        }
    };
    let end = start + matched.len();

    vec![
        Span::raw(text[..start].to_string()),
        Span::styled(text[start..end].to_string(), style),
        Span::raw(text[end..].to_string()),
    ]
}

fn draw_details(frame: &mut Frame, finding: &Finding, area: Rect) {
    let lines = vec![
        detail("rule", &finding.rule_id),
        Line::from(vec![
            Span::styled("severity  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                finding.severity.as_str().to_string(),
                Style::default()
                    .fg(severity_color(finding.severity))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        detail("where", &format!("{}:{}", finding.path, finding.line)),
        detail("print", short(&finding.fingerprint)),
        Line::from(""),
        Line::from(finding.message.clone()),
        Line::from(""),
        Line::from(Span::styled(
            finding.matched.clone(),
            Style::default().fg(Color::Yellow),
        )),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(" finding "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn detail(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<10}"), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

/// First 12 hex characters of a fingerprint: enough to eyeball, short enough
/// to fit the pane.
pub fn short(fingerprint: &str) -> &str {
    let end = fingerprint
        .char_indices()
        .nth(12)
        .map(|(index, _)| index)
        .unwrap_or(fingerprint.len());
    &fingerprint[..end]
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Error => Color::Red,
        Severity::Warning => Color::Yellow,
        Severity::Info => Color::Blue,
    }
}

fn draw_footer(frame: &mut Frame, state: &AppState, area: Rect, buttons: &[(Verdict, Rect)]) {
    frame.render_widget(Block::bordered().title(" verdict "), area);

    let armed = state.ratchet_finding().is_some();
    for (verdict, cell) in buttons {
        let style = match verdict {
            Verdict::Baseline | Verdict::Ignore if !armed => Style::default().fg(Color::DarkGray),
            Verdict::Baseline => Style::default().fg(Color::Green),
            Verdict::Ignore => Style::default().fg(Color::Magenta),
            _ => Style::default().fg(Color::Gray),
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(verdict.label(), style))).centered(),
            *cell,
        );
    }
}

/// Apply a verdict to the finding under the cursor. Accepting and ignoring
/// take the row out of the NEW set, so the cursor lands on the next one.
pub fn apply_verdict(state: &mut AppState, verdict: Verdict) {
    match verdict {
        Verdict::Baseline => {
            let Some(index) = state.ratchet_index() else {
                return;
            };
            let rule_id = state.rows[index].finding.rule_id.clone();
            actions::accept_baseline(state, index);
            if state.rows[index].status == Status::Baselined
                && !state.status.starts_with("baseline:")
            {
                state.status = format!("baselined {rule_id}");
            }
        }
        Verdict::Ignore => {
            let Some(index) = state.ratchet_index() else {
                return;
            };
            let finding = state.rows[index].finding.clone();
            state.status = match actions::insert_suppression(state, index) {
                Ok(()) => format!(
                    "ignored {} at {}:{}",
                    finding.rule_id, finding.path, finding.line
                ),
                Err(e) => format!("ignore failed: {e}"),
            };
        }
        Verdict::Next => state.ratchet_next(),
        Verdict::Prev => state.ratchet_prev(),
        Verdict::Back => state.screen = state.screen.prev(),
    }
}

/// Keys the ratchet claims. Global bindings are consumed before this runs.
pub fn handle_key_ratchet(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Char('b') | KeyCode::Char('B') => apply_verdict(state, Verdict::Baseline),
        KeyCode::Char('i') | KeyCode::Char('I') => apply_verdict(state, Verdict::Ignore),
        KeyCode::Char('n') | KeyCode::Down | KeyCode::Right | KeyCode::Char(' ') => {
            apply_verdict(state, Verdict::Next)
        }
        KeyCode::Char('p') | KeyCode::Up | KeyCode::Left => apply_verdict(state, Verdict::Prev),
        KeyCode::Esc => apply_verdict(state, Verdict::Back),
        KeyCode::PageDown => state.scroll_by(Pane::Code, 1),
        KeyCode::PageUp => state.scroll_by(Pane::Code, -1),
        KeyCode::Home => state.scroll.code = 0,
        _ => {}
    }
}

/// Mouse events on the ratchet: verdict buttons take clicks, the code pane
/// takes the wheel.
pub fn handle_mouse_ratchet(state: &mut AppState, event: MouseEvent) {
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(verdict) = button_at(&buttons(), event.column, event.row) {
                apply_verdict(state, verdict);
            }
        }
        MouseEventKind::ScrollDown => state.scroll_by(Pane::Code, 1),
        MouseEventKind::ScrollUp => state.scroll_by(Pane::Code, -1),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::Arc;

    use crossterm::event::{KeyEventKind, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use siloscan_core::rules::RuleSet;

    use crate::state::FindingRow;

    fn finding(rule_id: &str, path: &str, line: u64) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Error,
            message: "hardcoded secret".to_string(),
            path: path.to_string(),
            line,
            column: 9,
            matched: "needle".to_string(),
            fingerprint: format!("{:0>64}", rule_id.len()),
        }
    }

    fn row(rule_id: &str, path: &str, line: u64, status: Status) -> FindingRow {
        FindingRow {
            finding: finding(rule_id, path, line),
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
            None,
        );
        state.rows = rows;
        state
    }

    fn sample() -> AppState {
        state(vec![
            row("a.one", "src/a.rs", 2, Status::New),
            row("b.two", "src/b.rs", 1, Status::Baselined),
            row("c.three", "src/c.rs", 3, Status::Suppressed),
            row("d.four", "src/d.rs", 4, Status::New),
        ])
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
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

    #[test]
    fn navigation_visits_only_new_rows() {
        let mut state = sample();
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "a.one");

        handle_key_ratchet(&mut state, key(KeyCode::Char('n')));
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "d.four");

        // Past the end the cursor holds instead of walking into other statuses.
        handle_key_ratchet(&mut state, key(KeyCode::Char('n')));
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "d.four");

        handle_key_ratchet(&mut state, key(KeyCode::Char('p')));
        handle_key_ratchet(&mut state, key(KeyCode::Char('p')));
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "a.one");
    }

    #[test]
    fn arrows_are_navigation_too() {
        let mut state = sample();
        handle_key_ratchet(&mut state, key(KeyCode::Down));
        assert_eq!(state.ratchet_cursor, 1);
        handle_key_ratchet(&mut state, key(KeyCode::Up));
        assert_eq!(state.ratchet_cursor, 0);
    }

    #[test]
    fn escape_leaves_the_console() {
        let mut state = sample();
        state.screen = crate::state::Screen::Ratchet;
        handle_key_ratchet(&mut state, key(KeyCode::Esc));
        assert_eq!(state.screen, crate::state::Screen::Triage);
    }

    #[test]
    fn page_keys_scroll_the_code_pane_only() {
        let mut state = sample();
        handle_key_ratchet(&mut state, key(KeyCode::PageDown));
        handle_key_ratchet(&mut state, key(KeyCode::PageDown));
        assert_eq!(state.scroll.code, 2);
        assert_eq!(state.scroll.table, 0);

        handle_key_ratchet(&mut state, key(KeyCode::Home));
        assert_eq!(state.scroll.code, 0);
    }

    #[test]
    fn verdicts_on_an_empty_ratchet_do_nothing() {
        let mut state = state(vec![row("b.two", "src/b.rs", 1, Status::Baselined)]);
        apply_verdict(&mut state, Verdict::Baseline);
        apply_verdict(&mut state, Verdict::Ignore);

        assert!(state.dirty_baseline.is_empty());
        assert_eq!(state.rows[0].status, Status::Baselined);
        assert!(state.status.is_empty());
    }

    #[test]
    fn accepting_advances_to_the_next_new_finding() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = sample();
        state.root = dir.path().to_path_buf();

        apply_verdict(&mut state, Verdict::Baseline);

        assert_eq!(state.rows[0].status, Status::Baselined);
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "d.four");
        assert!(state.status.contains("a.one"));
        assert_eq!(
            siloscan_core::baseline::load(dir.path())
                .unwrap()
                .unwrap()
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn ignoring_edits_the_file_and_advances() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a.rs"), "let x = 1;\nlet a = needle;\n").unwrap();

        let mut state = sample();
        state.root = dir.path().to_path_buf();

        apply_verdict(&mut state, Verdict::Ignore);

        let edited = fs::read_to_string(dir.path().join("src/a.rs")).unwrap();
        assert_eq!(
            edited,
            "let x = 1;\nlet a = needle;  // siloscan-ignore-line: a.one\n"
        );
        assert_eq!(state.rows[0].status, Status::Suppressed);
        assert_eq!(state.ratchet_finding().unwrap().rule_id, "d.four");
    }

    #[test]
    fn ignoring_reports_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = sample();
        state.root = dir.path().to_path_buf();

        apply_verdict(&mut state, Verdict::Ignore);

        assert!(state.status.starts_with("ignore failed:"));
        assert_eq!(state.rows[0].status, Status::New);
    }

    #[test]
    fn body_stacks_on_a_narrow_terminal() {
        let (code, details) = split_body(Rect::new(0, 0, 120, 20));
        assert_eq!(code.y, details.y);
        assert!(code.x < details.x);

        let (code, details) = split_body(Rect::new(0, 0, 60, 20));
        assert_eq!(code.x, details.x);
        assert!(code.y < details.y);
    }

    #[test]
    fn footer_buttons_tile_the_footer_in_order() {
        let footer = Rect::new(0, 20, 80, 3);
        let buttons = footer_buttons(footer);

        assert_eq!(buttons.len(), 5);
        let verdicts: Vec<Verdict> = buttons.iter().map(|(v, _)| *v).collect();
        assert_eq!(verdicts, Verdict::ALL.to_vec());

        let covered: u16 = buttons.iter().map(|(_, area)| area.width).sum();
        assert_eq!(covered, footer.width - 2);
        for (_, area) in &buttons {
            assert_eq!(area.y, footer.y + 1);
            assert_eq!(area.height, 1);
        }
    }

    #[test]
    fn footer_buttons_vanish_when_there_is_no_room() {
        assert!(footer_buttons(Rect::new(0, 0, 1, 3)).is_empty());
        assert!(footer_buttons(Rect::new(0, 0, 40, 2)).is_empty());
    }

    #[test]
    fn button_at_hit_tests_the_cells() {
        let buttons = footer_buttons(Rect::new(0, 20, 50, 3));
        let (verdict, area) = buttons[1];
        assert_eq!(button_at(&buttons, area.x, area.y), Some(verdict));
        assert_eq!(button_at(&buttons, area.x, area.y + 5), None);
        assert_eq!(button_at(&buttons, 0, 0), None);
    }

    #[test]
    fn code_lines_highlight_the_matched_span() {
        let content = "let x = 1;\nlet a = needle;\nlet y = 2;\n";
        let f = finding("a.one", "src/a.rs", 2);

        let lines = code_lines(content, &f, 0, 3);
        assert_eq!(lines.len(), 3);

        let target = &lines[1];
        let text: String = target.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.ends_with("let a = needle;"));
        assert!(text.starts_with("2 | "));
        assert!(
            target
                .spans
                .iter()
                .any(|s| s.content == "needle" && s.style.bg == Some(Color::Yellow))
        );
    }

    #[test]
    fn code_lines_survive_a_stale_column() {
        let content = "let a = needle;\n";
        let mut f = finding("a.one", "src/a.rs", 1);
        f.column = 900;

        let lines = code_lines(content, &f, 0, 1);
        let target = &lines[0];
        assert!(
            target
                .spans
                .iter()
                .any(|s| s.content == "needle" && s.style.bg == Some(Color::Yellow))
        );

        f.matched = "gone".to_string();
        let lines = code_lines(content, &f, 0, 1);
        let text: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.ends_with("let a = needle;"));
    }

    #[test]
    fn code_lines_clamp_the_scroll_and_the_file() {
        let content = "a\nb\nc\n";
        let f = finding("a.one", "src/a.rs", 1);

        assert!(code_lines("", &f, 0, 5).is_empty());
        assert_eq!(code_lines(content, &f, 99, 5).len(), 1);
        assert_eq!(code_lines(content, &f, 0, 99).len(), 3);
    }

    #[test]
    fn fingerprints_are_shortened_safely() {
        assert_eq!(short("0123456789abcdef"), "0123456789ab");
        assert_eq!(short("abc"), "abc");
        assert_eq!(short(""), "");
    }

    #[test]
    fn draw_records_buttons_that_take_clicks() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a.rs"), "let x = 1;\nlet a = needle;\n").unwrap();

        let mut state = sample();
        state.root = dir.path().to_path_buf();

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let mut map = LayoutMap::default();
        terminal
            .draw(|frame| map = draw_ratchet(frame, &state, frame.area()))
            .unwrap();

        let rendered = terminal.backend().to_string();
        assert!(rendered.contains("Ratchet: 1 of 2 new findings"));
        assert!(rendered.contains("let a = needle;"));
        assert!(rendered.contains("[b]aseline"));
        assert!(map.code.is_some());
        assert!(map.dashboard.is_some());

        let buttons = buttons();
        let (_, ignore) = buttons
            .iter()
            .find(|(verdict, _)| *verdict == Verdict::Ignore)
            .unwrap();
        handle_mouse_ratchet(&mut state, click(ignore.x, ignore.y));

        assert_eq!(state.rows[0].status, Status::Suppressed);
    }

    #[test]
    fn draw_handles_an_empty_ratchet_and_a_tiny_terminal() {
        let state = state(vec![row("b.two", "src/b.rs", 1, Status::Baselined)]);

        let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
        terminal
            .draw(|frame| {
                draw_ratchet(frame, &state, frame.area());
            })
            .unwrap();
        assert!(terminal.backend().to_string().contains("no new findings"));

        let mut tiny = Terminal::new(TestBackend::new(8, 4)).unwrap();
        tiny.draw(|frame| {
            draw_ratchet(frame, &state, frame.area());
        })
        .unwrap();
    }

    #[test]
    fn wheel_scrolls_the_code_pane() {
        let mut state = sample();
        let wheel = |kind| MouseEvent {
            kind,
            column: 1,
            row: 1,
            modifiers: KeyModifiers::NONE,
        };

        handle_mouse_ratchet(&mut state, wheel(MouseEventKind::ScrollDown));
        assert_eq!(state.scroll.code, 1);
        handle_mouse_ratchet(&mut state, wheel(MouseEventKind::ScrollUp));
        assert_eq!(state.scroll.code, 0);
    }
}
