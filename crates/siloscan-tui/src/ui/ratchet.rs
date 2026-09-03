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
use ratatui::widgets::{Gauge, Paragraph, Wrap};

use siloscan_core::findings::{Finding, sanitize_for_terminal};
use siloscan_core::output::{self, REDACTED_MATCH};

use crate::actions;
use crate::state::{AppState, Pane, Status};
use crate::ui::LayoutMap;
use crate::ui::theme;

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
            Verdict::Ignore => "[i]gnore",
            Verdict::Next => "[n]ext",
            Verdict::Prev => "[p]rev",
            Verdict::Back => "[esc]",
        }
    }

    /// The label split into its bracketed key and the rest of the word, so the
    /// key can be drawn like a keycap and the word plainly.
    pub fn parts(self) -> (&'static str, &'static str) {
        let label = self.label();
        match label.find(']') {
            Some(index) => label.split_at(index + 1),
            None => (label, ""),
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
            draw_details(frame, state, finding, details_area);
        }
        None => {
            let message: Vec<Line> = if state.scan_running {
                vec![Line::styled("scanning", theme::dim())]
            } else {
                vec![
                    Line::styled("no new findings: the ratchet is clean", theme::dim()),
                    Line::styled("press r to rescan, tab for the next screen", theme::dim()),
                ]
            };
            frame.render_widget(
                Paragraph::new(message).block(theme::pane_block(" context ", false)),
                code_area,
            );
            frame.render_widget(
                Paragraph::new(Line::styled("nothing to review", theme::dim()))
                    .block(theme::pane_block(" finding ", false)),
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
            .block(theme::pane_block(&title, true))
            .gauge_style(Style::default().fg(theme::WARNING).bg(theme::DIM))
            .ratio(ratio)
            .label(Span::styled(
                label,
                Style::default().add_modifier(Modifier::BOLD),
            )),
        area,
    );
}

fn draw_code(frame: &mut Frame, state: &AppState, finding: &Finding, area: Rect) {
    let path = state.root.join(&finding.path);
    let title = format!(" {}:{} ", finding.path, finding.line);
    let block = theme::pane_block(&title, true);

    let height = area.height.saturating_sub(2) as usize;
    // The pane draws the file, so the credential is in the bytes it read; the
    // detail pane's redaction would be pointless with the raw span next to it.
    let redact = output::redacts_match(&state.rules, &finding.rule_id);
    let lines = match fs::read_to_string(&path) {
        Ok(content) => code_lines(&content, finding, state.scroll.code, height.max(1), redact),
        // Unreadable source is a dead end for this finding, not a crash: say so
        // in the same dim guidance voice the other empty panes use.
        Err(e) => vec![
            Line::styled(
                format!(
                    "cannot read {}",
                    sanitize_for_terminal(&path.display().to_string())
                ),
                theme::dim(),
            ),
            Line::styled(
                sanitize_for_terminal(&e.to_string()).into_owned(),
                theme::dim(),
            ),
            Line::styled(
                "the file moved or was deleted since the scan; press r to rescan",
                theme::dim(),
            ),
        ],
    };

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// The window of source around the finding, gutter included, with the matched
/// span highlighted. `offset` scrolls the window down from that anchor.
///
/// `redact` stands for [`output::redacts_match`] on the finding's rule: with it
/// set the highlighted span renders as [`REDACTED_MATCH`] instead of the bytes
/// it covers, so a credential the report withholds does not reach the screen
/// through the file it was found in.
pub fn code_lines(
    content: &str,
    finding: &Finding,
    offset: usize,
    height: usize,
    redact: bool,
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
                theme::dim(),
            );
            let mut spans = vec![gutter];
            if number == target {
                spans.extend(highlight(text, finding.column, &finding.matched, redact));
            } else {
                spans.push(Span::raw(sanitize_for_terminal(text).into_owned()));
            }
            Line::from(spans)
        })
        .collect()
}

/// Split a line around the matched span. The column is a 1-based byte offset;
/// anything that does not line up falls back to a plain line.
///
/// That fallback is safe for a plain finding, since it is taken only when the
/// line does not contain the match. It is not safe for a redacting one: a
/// snapshot's `matched` is already the placeholder, so the span cannot be
/// located and the line drawn in its place would be the credential itself.
/// A redacting finding whose span is not found therefore renders as the
/// placeholder alone.
fn highlight(text: &str, column: u64, matched: &str, redact: bool) -> Vec<Span<'static>> {
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
            None if redact => return vec![Span::styled(REDACTED_MATCH.to_string(), style)],
            None => return vec![Span::raw(sanitize_for_terminal(text).into_owned())],
        }
    };
    let end = start + matched.len();

    // Sanitizing follows the slicing: `column` and `matched.len()` are byte
    // offsets into the file's own bytes, and escaping one byte to four
    // characters would move every offset behind it.
    let span = match redact {
        true => REDACTED_MATCH.to_string(),
        false => sanitize_for_terminal(&text[start..end]).into_owned(),
    };
    vec![
        Span::raw(sanitize_for_terminal(&text[..start]).into_owned()),
        Span::styled(span, style),
        Span::raw(sanitize_for_terminal(&text[end..]).into_owned()),
    ]
}

/// `state` is read for its rule set alone: the match text is the one field
/// here that may be a credential, and only the rules say which findings those
/// are.
fn draw_details(frame: &mut Frame, state: &AppState, finding: &Finding, area: Rect) {
    let lines = vec![
        detail_line(
            "rule",
            Span::styled(
                sanitize_for_terminal(&finding.rule_id).into_owned(),
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        ),
        detail_line(
            "severity",
            Span::styled(
                finding.severity.as_str().to_string(),
                Style::default()
                    .fg(theme::severity_color(finding.severity))
                    .add_modifier(Modifier::BOLD),
            ),
        ),
        detail(
            "where",
            &format!("{}:{}", sanitize_for_terminal(&finding.path), finding.line),
        ),
        detail_line(
            "print",
            Span::styled(short(&finding.fingerprint).to_string(), theme::dim()),
        ),
        Line::from(""),
        Line::from(sanitize_for_terminal(&finding.message).into_owned()),
        Line::from(""),
        Line::from(Span::styled(
            crate::ui::display_match(&state.rules, finding).to_string(),
            Style::default().fg(theme::WARNING),
        )),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .block(theme::pane_block(" finding ", true))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn detail(label: &str, value: &str) -> Line<'static> {
    detail_line(label, Span::raw(value.to_string()))
}

/// A dim label in a fixed gutter plus the value, however it is styled.
fn detail_line(label: &str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<10}"), theme::dim()),
        value,
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

fn draw_footer(frame: &mut Frame, state: &AppState, area: Rect, buttons: &[(Verdict, Rect)]) {
    frame.render_widget(theme::pane_block(" verdict ", true), area);

    let armed = state.ratchet_finding().is_some();
    for (verdict, cell) in buttons {
        // Disarmed verdicts recede; the rest keep the color of what they do.
        let style = match verdict {
            Verdict::Baseline | Verdict::Ignore if !armed => theme::dim(),
            Verdict::Baseline => Style::default().fg(Color::Green),
            Verdict::Ignore => Style::default().fg(Color::Magenta),
            _ => theme::accent(),
        };
        let (key, word) = verdict.parts();
        let line = Line::from(vec![
            Span::styled(key, style.add_modifier(Modifier::REVERSED | Modifier::BOLD)),
            Span::styled(word, style),
        ]);
        frame.render_widget(Paragraph::new(line).centered(), *cell);
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
    use siloscan_core::output::REDACTED_MATCH;
    use siloscan_core::rules::{RuleSet, Severity, load_str};

    use crate::state::FindingRow;

    fn finding(rule_id: &str, path: &str, line: u64) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Error,
            message: "hardcoded secret".to_string(),
            path: path.to_string(),
            line,
            column: 9,
            column_utf16: 9,
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
        // A scan-root-anchored session, so the baseline lives at the root too.
        state.baseline_root = dir.path().to_path_buf();

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

        let lines = code_lines(content, &f, 0, 3, false);
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

        let lines = code_lines(content, &f, 0, 1, false);
        let target = &lines[0];
        assert!(
            target
                .spans
                .iter()
                .any(|s| s.content == "needle" && s.style.bg == Some(Color::Yellow))
        );

        f.matched = "gone".to_string();
        let lines = code_lines(content, &f, 0, 1, false);
        let text: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.ends_with("let a = needle;"));
    }

    #[test]
    fn code_lines_clamp_the_scroll_and_the_file() {
        let content = "a\nb\nc\n";
        let f = finding("a.one", "src/a.rs", 1);

        assert!(code_lines("", &f, 0, 5, false).is_empty());
        assert_eq!(code_lines(content, &f, 99, 5, false).len(), 1);
        assert_eq!(code_lines(content, &f, 0, 99, false).len(), 3);
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

    /// One secret rule and one regex rule, so a single session can hold a
    /// finding that must be redacted next to one that must not.
    fn secret_rules() -> RuleSet {
        RuleSet {
            rules: load_str(
                "version: 1\nrules:\n  - id: secret.aws-key\n    severity: error\n    \
                 message: aws access key\n    secret:\n      pattern: 'AKIA[0-9A-Z]{16}'\n  \
                 - id: style.needle\n    severity: warning\n    message: needle found\n    \
                 regex:\n      pattern: 'needle'\n",
                "test",
            )
            .expect("rules load"),
            ..Default::default()
        }
    }

    /// A live scan hands the UI the engine's findings with the raw match text
    /// still in them - only the JSON writer redacts, and this path never goes
    /// through it. The detail pane has to redact for itself.
    ///
    /// The code pane has the same duty against the file it reads; that is
    /// `the_code_pane_redacts_a_live_secret_finding`.
    #[test]
    fn the_detail_pane_redacts_a_live_secret_finding() {
        const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

        let render = |rule_id: &str, matched: &str| {
            let mut row = row(rule_id, "src/a.rs", 1, Status::New);
            row.finding.matched = matched.to_string();
            let mut state = state(vec![row]);
            state.rules = Arc::new(secret_rules());
            // No such file, so the source pane cannot be what puts the text on
            // screen and the assertion is about the detail pane alone.
            state.root = PathBuf::from("/nonexistent-scan-root");

            let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
            terminal
                .draw(|frame| {
                    draw_ratchet(frame, &state, frame.area());
                })
                .unwrap();
            terminal.backend().to_string()
        };

        let secret = render("secret.aws-key", SECRET);
        assert!(
            !secret.contains(SECRET),
            "credential reached the screen: {secret}"
        );
        assert!(secret.contains(REDACTED_MATCH), "{secret}");

        // Every other payload keeps its match text: it is not a credential and
        // showing it is the reason the pane exists.
        let regex = render("style.needle", "plain-match-text");
        assert!(regex.contains("plain-match-text"), "{regex}");
        assert!(!regex.contains(REDACTED_MATCH), "{regex}");

        // A snapshot already carries the placeholder, so the pane redacts it a
        // second time; that has to be a no-op rather than a nested placeholder.
        let already = render("secret.aws-key", REDACTED_MATCH);
        assert!(already.contains(REDACTED_MATCH), "{already}");
        assert_eq!(
            already.matches(REDACTED_MATCH).count(),
            secret.matches(REDACTED_MATCH).count(),
            "redacting twice must render the same thing as redacting once"
        );
    }

    /// The code pane draws the file itself, so the credential is in the bytes
    /// it read even though the detail pane redacts. The highlighted span is the
    /// match, so it is the span that has to carry the placeholder.
    #[test]
    fn the_code_pane_redacts_a_live_secret_finding() {
        const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

        let render = |rule_id: &str, matched: &str, source: &str| {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir_all(dir.path().join("src")).unwrap();
            fs::write(dir.path().join("src/a.rs"), source).unwrap();

            let mut row = row(rule_id, "src/a.rs", 1, Status::New);
            row.finding.matched = matched.to_string();
            row.finding.column = 12;
            let mut state = state(vec![row]);
            state.rules = Arc::new(secret_rules());
            state.root = dir.path().to_path_buf();

            let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
            terminal
                .draw(|frame| {
                    draw_ratchet(frame, &state, frame.area());
                })
                .unwrap();
            terminal.backend().to_string()
        };

        let secret = render(
            "secret.aws-key",
            SECRET,
            &format!("let key = \"{SECRET}\";\n"),
        );
        assert!(!secret.contains(SECRET), "credential reached the screen");
        assert!(
            secret.contains(REDACTED_MATCH),
            "placeholder missing from the code pane"
        );
        // Only the match is withheld; the line it sits on is still readable.
        assert!(
            secret.contains("let key = "),
            "the rest of the line was withheld"
        );

        // Every other payload keeps its match text: it is not a credential and
        // showing it is the reason the pane exists.
        let regex = render(
            "style.needle",
            "plain-match-text",
            "let a = plain-match-text;\n",
        );
        assert!(regex.contains("plain-match-text"), "{regex}");
        assert!(!regex.contains(REDACTED_MATCH), "{regex}");
    }

    /// A snapshot carries the placeholder as the match, so the span covering
    /// the credential cannot be found in the file the pane read. The line is
    /// then not drawn at all: it is the credential.
    #[test]
    fn a_redacting_rule_whose_span_is_not_found_draws_the_placeholder_alone() {
        const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

        let content = format!("let key = \"{SECRET}\";\n");
        let mut f = finding("secret.aws-key", "src/a.rs", 1);
        f.column = 12;
        f.matched = REDACTED_MATCH.to_string();

        let lines = code_lines(&content, &f, 0, 1, true);
        let text = lines[0].to_string();
        assert!(
            !text.contains(SECRET),
            "credential reached the screen: {text}"
        );
        assert!(text.contains(REDACTED_MATCH), "{text}");
        // Gutter and placeholder, nothing of the line itself.
        assert_eq!(lines[0].spans.len(), 2);

        // The same finding against a rule set that does not redact keeps the
        // line, which is what a snapshot loaded against unrelated rules needs.
        let plain = code_lines(&content, &f, 0, 1, false);
        assert!(plain[0].to_string().contains(SECRET));
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
