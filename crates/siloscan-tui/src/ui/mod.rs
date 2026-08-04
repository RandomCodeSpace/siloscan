//! Rendering and input routing.
//!
//! Contract used by `main`:
//! - `draw(frame, state)` renders the whole UI and records the pane rectangles
//!   of the frame it just drew via `set_layout`.
//! - `handle_key(state, key)` receives every key the event loop did not claim
//!   as a global binding (`q`, `r`, `1`/`2`/`3`, Ctrl-C).
//! - `handle_mouse(state, event)` receives every mouse event. The `LayoutMap`
//!   is not passed in: it lives in a thread-local written by the last `draw`
//!   and is read back with `layout()`. Draw and input handling both run on the
//!   main thread, so the thread-local is always the map the user is looking at.

pub mod dashboard;
pub mod ratchet;
pub mod silo;
pub mod theme;
pub mod triage;

use std::cell::RefCell;

use crossterm::event::{KeyCode, KeyEvent, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Gauge, Paragraph};

use crate::state::{AppState, Pane, Screen};
use crate::ui::dashboard::Card;

/// Rows the dashboard strip keeps on non-dashboard screens. The strip is the
/// first thing dropped when the terminal is short: charts yield space first.
const STRIP_HEIGHT: u16 = 9;
/// Below this height no screen but the dashboard shows the strip.
const STRIP_MIN_ROWS: u16 = 40;
/// Below this width the charts are unreadable and the strip is dropped.
const STRIP_MIN_COLS: u16 = 60;

/// Pane rectangles of the last rendered frame. Panes absent from the current
/// screen stay `None`. Screen tabs record their rects for mouse-based switching,
/// and so do the dashboard KPI cards, indexed by `Card::index`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LayoutMap {
    pub sidebar: Option<Rect>,
    pub table: Option<Rect>,
    pub code: Option<Rect>,
    pub dashboard: Option<Rect>,
    pub status: Option<Rect>,
    pub dashboard_tab: Option<Rect>,
    pub triage_tab: Option<Rect>,
    pub ratchet_tab: Option<Rect>,
    pub silo_tab: Option<Rect>,
    pub cards: [Option<Rect>; Card::COUNT],
}

impl LayoutMap {
    /// Scrollable pane under a mouse position, if any.
    pub fn pane_at(&self, column: u16, row: u16) -> Option<Pane> {
        let hits = [
            (self.sidebar, Pane::Sidebar),
            (self.table, Pane::Table),
            (self.code, Pane::Code),
            (self.dashboard, Pane::Dashboard),
        ];
        hits.into_iter()
            .find(|(area, _)| area.is_some_and(|area| contains(area, column, row)))
            .map(|(_, pane)| pane)
    }

    /// Screen tab under a mouse position, if any.
    pub fn screen_at(&self, column: u16, row: u16) -> Option<Screen> {
        let hits = [
            (self.dashboard_tab, Screen::Dashboard),
            (self.triage_tab, Screen::Triage),
            (self.ratchet_tab, Screen::Ratchet),
            (self.silo_tab, Screen::Silo),
        ];
        hits.into_iter()
            .find(|(area, _)| area.is_some_and(|area| contains(area, column, row)))
            .map(|(_, screen)| screen)
    }

    /// Dashboard KPI card under a mouse position, if any.
    pub fn card_at(&self, column: u16, row: u16) -> Option<Card> {
        Card::ALL
            .into_iter()
            .find(|card| self.cards[card.index()].is_some_and(|area| contains(area, column, row)))
    }
}

fn contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x
        && column < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
}

thread_local! {
    static LAYOUT: RefCell<LayoutMap> = const { RefCell::new(LayoutMap {
        sidebar: None,
        table: None,
        code: None,
        dashboard: None,
        status: None,
        dashboard_tab: None,
        triage_tab: None,
        ratchet_tab: None,
        silo_tab: None,
        cards: [None; Card::COUNT],
    }) };
}

pub fn set_layout(map: LayoutMap) {
    LAYOUT.with(|cell| *cell.borrow_mut() = map);
}

pub fn layout() -> LayoutMap {
    LAYOUT.with(|cell| *cell.borrow())
}

pub fn draw(frame: &mut Frame, state: &AppState) {
    let area = frame.area();
    let strip_height = strip_height(state.screen, area);

    let [strip, content, status] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(strip_height),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(area);

    let mut layout_map = LayoutMap::default();

    if strip_height > 0 {
        dashboard::draw(frame, strip, state, &mut layout_map);
        layout_map.dashboard = Some(strip);
    }

    draw_content(frame, content, state, &mut layout_map);
    draw_status(frame, status, state, &mut layout_map);

    set_layout(layout_map);
}

/// The dashboard screen renders the charts as its content, so it needs no
/// strip. Every other screen gets one only when the terminal can spare it.
pub fn strip_height(screen: Screen, area: Rect) -> u16 {
    if screen == Screen::Dashboard || area.height < STRIP_MIN_ROWS || area.width < STRIP_MIN_COLS {
        0
    } else {
        STRIP_HEIGHT
    }
}

fn draw_content(frame: &mut Frame, area: Rect, state: &AppState, layout: &mut LayoutMap) {
    match state.screen {
        Screen::Dashboard => {
            dashboard::draw(frame, area, state, layout);
            layout.dashboard = Some(area);
        }
        Screen::Triage => triage::draw_triage(frame, area, state, layout),
        Screen::Ratchet => {
            let map = ratchet::draw_ratchet(frame, state, area);
            layout.code = map.code;
            // The strip, when present, keeps the dashboard pane; the ratchet
            // details pane takes it otherwise.
            layout.dashboard = layout.dashboard.or(map.dashboard);
        }
        Screen::Silo => silo::draw_silo(frame, area, state, layout),
    }
}

/// Keybindings advertised for a screen, right of the tabs.
pub fn keybindings(screen: Screen) -> &'static str {
    match screen {
        Screen::Dashboard => "q quit | r rescan | tab next screen",
        Screen::Triage => {
            "/ search | s/t/f section | enter toggle | o sort | tab sidebar | esc clear"
        }
        Screen::Ratchet => "b baseline | i ignore-inline | n/p step | esc back",
        Screen::Silo => "arrows move cell | enter open edge | esc close | tab next screen",
    }
}

/// Ticker text for the progress gauge: percent while scanning, the scan
/// summary once it is done.
pub fn ticker(state: &AppState) -> String {
    match state.progress {
        Some(progress) if state.scan_running => format!(
            "{}/{} files | {} findings",
            progress.files_done, progress.files_total, progress.findings
        ),
        _ if state.scan_running => "starting".to_string(),
        _ => {
            let (new, baselined, suppressed) = state.debt_counts();
            format!("{new} new | {baselined} base | {suppressed} supp")
        }
    }
}

/// Status message plus the current screen's keybindings. The triage screen
/// also advertises whether any filter is narrowing the table. The bar renders
/// `status_spans` instead; this is the plain-text form of the same line, kept
/// as the contract the styled version is pinned against.
#[cfg(test)]
pub fn status_line(state: &AppState) -> String {
    let mut line = String::new();
    if !state.status.is_empty() {
        line.push_str(&state.status);
        line.push_str(" | ");
    }
    if state.screen == Screen::Triage && !state.filters.is_empty() {
        line.push_str("filtered | ");
    }
    line.push_str(keybindings(state.screen));
    line
}

/// The status line as styled spans: the message in accent, the filter marker in
/// warning, and each binding as an accented key letter plus a dim description.
/// The text matches `status_line` exactly.
fn status_spans(state: &AppState) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();

    if !state.status.is_empty() {
        spans.push(Span::styled(state.status.clone(), theme::accent()));
        spans.push(Span::styled(" | ", theme::dim()));
    }
    if state.screen == Screen::Triage && !state.filters.is_empty() {
        spans.push(Span::styled(
            "filtered",
            Style::default().fg(theme::WARNING),
        ));
        spans.push(Span::styled(" | ", theme::dim()));
    }
    spans.extend(keybinding_spans(state.screen));

    Line::from(spans)
}

fn keybinding_spans(screen: Screen) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (index, binding) in keybindings(screen).split(" | ").enumerate() {
        if index > 0 {
            spans.push(Span::styled(" | ", theme::dim()));
        }
        match binding.split_once(' ') {
            Some((key, rest)) => {
                spans.push(Span::styled(key, theme::accent()));
                spans.push(Span::styled(format!(" {rest}"), theme::dim()));
            }
            None => spans.push(Span::styled(binding, theme::accent())),
        }
    }
    spans
}

/// The debt counts as styled spans. Same text as the idle branch of `ticker`.
fn counts_spans(state: &AppState) -> Line<'static> {
    let (new, baselined, suppressed) = state.debt_counts();
    let new_style = if new > 0 {
        Style::default()
            .fg(theme::ERROR)
            .add_modifier(Modifier::BOLD)
    } else {
        theme::dim()
    };

    Line::from(vec![
        Span::styled(format!("{new} new"), new_style),
        Span::styled(" | ", theme::dim()),
        Span::styled(format!("{baselined} base"), theme::dim()),
        Span::styled(" | ", theme::dim()),
        Span::styled(format!("{suppressed} supp"), theme::dim()),
    ])
}

fn draw_status(frame: &mut Frame, area: Rect, state: &AppState, layout: &mut LayoutMap) {
    let [tabs, keys, progress] = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(Screen::ALL.len() as u16 * TAB_WIDTH),
            Constraint::Min(0),
            Constraint::Length(28),
        ])
        .areas(area);

    draw_tabs(frame, tabs, state, layout);

    frame.render_widget(Paragraph::new(status_spans(state)), keys);

    // A scan in flight gets the gauge; an idle one gets the debt counts, which
    // carry more information per column than a full bar does.
    if state.scan_running {
        let gauge = Gauge::default()
            .ratio(state.progress_ratio())
            .gauge_style(Style::default().fg(theme::ACCENT).bg(theme::DIM))
            .label(Span::styled(
                ticker(state),
                Style::default().add_modifier(Modifier::BOLD),
            ));
        frame.render_widget(gauge, progress);
    } else {
        frame.render_widget(
            Paragraph::new(counts_spans(state)).alignment(Alignment::Right),
            progress,
        );
    }

    layout.status = Some(area);
}

const TAB_WIDTH: u16 = 11;

fn draw_tabs(frame: &mut Frame, area: Rect, state: &AppState, layout: &mut LayoutMap) {
    let cells = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(TAB_WIDTH); Screen::ALL.len()])
        .split(area);

    for (screen, rect) in Screen::ALL.into_iter().zip(cells.iter().copied()) {
        let selected = state.screen == screen;
        let text = if selected {
            format!("[{}]", screen.as_str())
        } else {
            format!(" {} ", screen.as_str())
        };
        let style = if selected {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            theme::dim()
        };
        frame.render_widget(Paragraph::new(text).style(style), rect);

        match screen {
            Screen::Dashboard => layout.dashboard_tab = Some(rect),
            Screen::Triage => layout.triage_tab = Some(rect),
            Screen::Ratchet => layout.ratchet_tab = Some(rect),
            Screen::Silo => layout.silo_tab = Some(rect),
        }
    }
}

pub fn handle_key(state: &mut AppState, key: KeyEvent) {
    match state.screen {
        Screen::Dashboard => handle_dashboard_key(state, key),
        Screen::Triage => triage::handle_key_triage(state, key),
        Screen::Ratchet => ratchet::handle_key_ratchet(state, key),
        Screen::Silo => silo::handle_key_silo(state, key),
    }
}

fn handle_dashboard_key(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Tab | KeyCode::Right => state.screen = state.screen.next(),
        KeyCode::BackTab | KeyCode::Left => state.screen = state.screen.prev(),
        KeyCode::Down | KeyCode::Char('j') => state.scroll_by(Pane::Dashboard, 1),
        KeyCode::Up | KeyCode::Char('k') => state.scroll_by(Pane::Dashboard, -1),
        _ => {}
    }
}

/// Clicks on a screen tab switch screens whatever the screen; clicks on a KPI
/// card open triage with that card's filter, from the dashboard screen or from
/// the strip above another one. Everything else goes to the current screen's
/// handler.
pub fn handle_mouse(state: &mut AppState, event: MouseEvent) {
    let layout = layout();

    if event.kind == MouseEventKind::Down(crossterm::event::MouseButton::Left) {
        if let Some(screen) = layout.screen_at(event.column, event.row) {
            state.screen = screen;
            return;
        }
        if let Some(card) = layout.card_at(event.column, event.row) {
            dashboard::open_card(state, card);
            return;
        }
    }

    match state.screen {
        Screen::Dashboard => handle_dashboard_mouse(state, event, &layout),
        Screen::Triage => triage::handle_mouse_triage(state, event, &layout),
        Screen::Ratchet => ratchet::handle_mouse_ratchet(state, event),
        Screen::Silo => silo::handle_mouse_silo(state, event),
    }
}

fn handle_dashboard_mouse(state: &mut AppState, event: MouseEvent, layout: &LayoutMap) {
    let delta = match event.kind {
        MouseEventKind::ScrollDown => 1,
        MouseEventKind::ScrollUp => -1,
        _ => return,
    };
    if let Some(pane) = layout.pane_at(event.column, event.row) {
        state.scroll_by(pane, delta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn pane_at_matches_the_recorded_rectangles() {
        let map = LayoutMap {
            table: Some(Rect::new(0, 0, 10, 5)),
            code: Some(Rect::new(10, 0, 10, 5)),
            ..LayoutMap::default()
        };
        assert_eq!(map.pane_at(3, 2), Some(Pane::Table));
        assert_eq!(map.pane_at(12, 4), Some(Pane::Code));
        assert_eq!(map.pane_at(3, 9), None);
    }

    #[test]
    fn screen_at_finds_tabs() {
        let map = LayoutMap {
            dashboard_tab: Some(Rect::new(0, 9, 10, 1)),
            triage_tab: Some(Rect::new(10, 9, 10, 1)),
            ratchet_tab: Some(Rect::new(20, 9, 10, 1)),
            ..LayoutMap::default()
        };
        assert_eq!(map.screen_at(5, 9), Some(Screen::Dashboard));
        assert_eq!(map.screen_at(15, 9), Some(Screen::Triage));
        assert_eq!(map.screen_at(25, 9), Some(Screen::Ratchet));
        assert_eq!(map.screen_at(30, 9), None);
    }

    #[test]
    fn layout_round_trips_through_the_thread_local() {
        let map = LayoutMap {
            status: Some(Rect::new(0, 9, 20, 1)),
            dashboard_tab: Some(Rect::new(0, 9, 10, 1)),
            ..LayoutMap::default()
        };
        set_layout(map);
        assert_eq!(layout(), map);
    }

    #[test]
    fn draw_dashboard_renders_at_80x24() {
        let state = AppState::new(
            PathBuf::from("."),
            Arc::new(siloscan_core::rules::RuleSet {
                rules: Vec::new(),
                ..Default::default()
            }),
            None,
        );

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                draw(frame, &state);
            })
            .unwrap();
    }

    #[test]
    fn draw_dashboard_renders_at_200x50() {
        let state = AppState::new(
            PathBuf::from("."),
            Arc::new(siloscan_core::rules::RuleSet {
                rules: Vec::new(),
                ..Default::default()
            }),
            None,
        );

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(200, 50)).unwrap();
        terminal
            .draw(|frame| {
                draw(frame, &state);
            })
            .unwrap();
    }

    use crossterm::event::{KeyEventKind, KeyModifiers, MouseButton};
    use siloscan_core::findings::Finding;
    use siloscan_core::rules::{RuleSet, Severity};
    use siloscan_core::scan::Progress;

    use crate::state::{FindingRow, Status};

    fn state() -> AppState {
        let mut state = AppState::new(
            PathBuf::from("/repo"),
            Arc::new(RuleSet {
                rules: Vec::new(),
                ..Default::default()
            }),
            None,
        );
        state.rows = ["src/a.rs", "src/b.rs", "tests/c.rs"]
            .into_iter()
            .enumerate()
            .map(|(index, path)| FindingRow {
                finding: Finding {
                    rule_id: format!("rule.{index}"),
                    severity: Severity::Error,
                    message: "hardcoded secret".to_string(),
                    path: path.to_string(),
                    line: index as u64 + 1,
                    column: 1,
                    matched: "needle".to_string(),
                    fingerprint: format!("{index:0>64}"),
                },
                status: if index == 0 {
                    Status::Baselined
                } else {
                    Status::New
                },
            })
            .collect();
        state
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn render(state: &AppState, width: u16, height: u16) -> LayoutMap {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, state)).unwrap();
        layout()
    }

    fn render_text(state: &AppState, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, state)).unwrap();
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

    #[test]
    fn the_dashboard_leads_with_the_quality_gate_banner() {
        let mut state = state();
        for (width, height) in [(80, 24), (200, 50)] {
            let text = render_text(&state, width, height);
            assert!(text.contains("Quality Gate"), "{width}x{height}: {text}");
            assert!(text.contains("FAILED"), "{width}x{height}: {text}");
            assert!(
                text.contains("new errors above the gate"),
                "{width}x{height}: {text}"
            );
        }

        for row in &mut state.rows {
            row.status = Status::Baselined;
        }
        let text = render_text(&state, 80, 24);
        assert!(text.contains("PASSED"), "{text}");
        assert!(text.contains("no new errors"), "{text}");
    }

    #[test]
    fn clicking_a_kpi_card_opens_triage_filtered() {
        let mut state = state();
        let map = render(&state, 200, 50);

        let card = map.cards[crate::ui::dashboard::Card::Errors.index()].unwrap();
        handle_mouse(
            &mut state,
            mouse(
                MouseEventKind::Down(MouseButton::Left),
                card.x + 1,
                card.y + 1,
            ),
        );

        assert_eq!(state.screen, Screen::Triage);
        assert!(state.filters.severities.contains(&Severity::Error));
    }

    #[test]
    fn every_screen_renders_wide_and_narrow() {
        let mut state = state();
        for screen in Screen::ALL {
            state.screen = screen;
            for (width, height) in [(200, 50), (80, 24), (40, 12)] {
                let map = render(&state, width, height);
                assert!(map.status.is_some(), "{screen:?} {width}x{height}");
                assert!(
                    map.dashboard_tab.is_some(),
                    "tabs missing on {screen:?} {width}x{height}"
                );
            }
        }
    }

    #[test]
    fn triage_and_ratchet_record_their_panes() {
        let mut state = state();

        state.screen = Screen::Triage;
        let map = render(&state, 200, 50);
        assert!(map.table.is_some());
        assert!(map.code.is_some());
        assert!(map.sidebar.is_some());

        state.screen = Screen::Ratchet;
        let map = render(&state, 200, 50);
        assert!(map.code.is_some());
    }

    #[test]
    fn the_strip_yields_space_before_the_screens_do() {
        // The dashboard screen is the charts, so it never doubles them up.
        assert_eq!(strip_height(Screen::Dashboard, Rect::new(0, 0, 200, 60)), 0);
        assert_eq!(strip_height(Screen::Triage, Rect::new(0, 0, 200, 60)), 9);
        // Short or narrow: the charts go first.
        assert_eq!(strip_height(Screen::Triage, Rect::new(0, 0, 200, 24)), 0);
        assert_eq!(strip_height(Screen::Ratchet, Rect::new(0, 0, 40, 60)), 0);
    }

    #[test]
    fn keys_route_to_the_current_screen() {
        let mut state = state();

        state.screen = Screen::Triage;
        handle_key(&mut state, key(KeyCode::Char('/')));
        assert!(state.captures_input(), "triage owns '/'");
        state.input_mode = false;

        state.screen = Screen::Ratchet;
        let before = state.ratchet_cursor;
        handle_key(&mut state, key(KeyCode::Char('n')));
        assert_eq!(state.ratchet_cursor, before + 1, "ratchet owns 'n'");

        state.screen = Screen::Dashboard;
        handle_key(&mut state, key(KeyCode::Tab));
        assert_eq!(state.screen, Screen::Triage);
    }

    #[test]
    fn a_click_on_a_tab_switches_screens_from_any_screen() {
        let mut state = state();
        for screen in Screen::ALL {
            state.screen = screen;
            let map = render(&state, 120, 40);
            let tab = map.ratchet_tab.unwrap();
            handle_mouse(
                &mut state,
                mouse(MouseEventKind::Down(MouseButton::Left), tab.x, tab.y),
            );
            assert_eq!(state.screen, Screen::Ratchet, "from {screen:?}");
        }
    }

    #[test]
    fn the_wheel_scrolls_the_pane_under_the_cursor() {
        let mut state = state();
        state.screen = Screen::Triage;
        let map = render(&state, 200, 50);

        let code = map.code.unwrap();
        handle_mouse(
            &mut state,
            mouse(MouseEventKind::ScrollDown, code.x, code.y),
        );
        assert!(state.scroll.code > 0);
        assert_eq!(state.scroll.sidebar, 0);
    }

    /// Six findings spread over every severity and every status, plus a
    /// boundary edge so the silo matrix has a violation to draw. Enough shape
    /// for every screen to have something worth styling.
    fn styled_state() -> AppState {
        let mut state = AppState::new(
            PathBuf::from("/repo"),
            Arc::new(RuleSet {
                rules: Vec::new(),
                ..Default::default()
            }),
            None,
        );

        let specs = [
            (
                "secrets.aws_key",
                Severity::Error,
                "src/api/auth.rs",
                Status::New,
            ),
            (
                "secrets.token",
                Severity::Error,
                "src/api/client.rs",
                Status::New,
            ),
            (
                "style.unwrap",
                Severity::Warning,
                "src/core/mod.rs",
                Status::New,
            ),
            (
                "style.todo",
                Severity::Warning,
                "src/core/parse.rs",
                Status::Baselined,
            ),
            (
                "docs.missing",
                Severity::Info,
                "src/ui/view.rs",
                Status::Baselined,
            ),
            (
                "docs.stale",
                Severity::Info,
                "tests/smoke.rs",
                Status::Suppressed,
            ),
        ];

        state.rows = specs
            .into_iter()
            .enumerate()
            .map(|(index, (rule, severity, path, status))| FindingRow {
                finding: Finding {
                    rule_id: rule.to_string(),
                    severity,
                    message: "hardcoded credential reaches a public boundary".to_string(),
                    path: path.to_string(),
                    line: index as u64 + 3,
                    column: 5,
                    matched: "needle".to_string(),
                    fingerprint: format!("{index:0>64}"),
                },
                status,
            })
            .collect();
        state.boundary_edges = vec![("api".to_string(), "core".to_string(), 0)];
        state
    }

    /// Cells of `region` carrying a foreground color other than the terminal
    /// default.
    fn styled_cells(buffer: &ratatui::buffer::Buffer, region: Rect) -> usize {
        let mut count = 0;
        for y in region.y..region.y.saturating_add(region.height) {
            for x in region.x..region.x.saturating_add(region.width) {
                if buffer
                    .cell((x, y))
                    .is_some_and(|cell| cell.fg != ratatui::style::Color::Reset)
                {
                    count += 1;
                }
            }
        }
        count
    }

    /// The palette has to survive the trip through the widgets and land in the
    /// buffer. Rendering without panicking proves nothing about color, so this
    /// reads the cells back: charts and tables must not come out monochrome,
    /// the dashboard must state its verdict, and a KPI card must still be a
    /// live link into triage.
    #[test]
    fn styling_reaches_buffer() {
        const WIDTH: u16 = 170;
        const HEIGHT: u16 = 44;

        let mut state = styled_state();

        // (a) Every screen paints color into its main content region.
        for screen in Screen::ALL {
            state.screen = screen;
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(WIDTH, HEIGHT)).unwrap();
            terminal.draw(|frame| draw(frame, &state)).unwrap();

            let map = layout();
            let region = match screen {
                Screen::Dashboard => map.dashboard,
                Screen::Triage | Screen::Silo => map.table,
                Screen::Ratchet => map.code,
            }
            .unwrap_or_else(|| panic!("{screen:?} recorded no content region"));

            // Measured inside the border: the pane frame is themed on its own,
            // so counting it would pass this even with monochrome content.
            let inner = Rect::new(
                region.x.saturating_add(1),
                region.y.saturating_add(1),
                region.width.saturating_sub(2),
                region.height.saturating_sub(2),
            );
            let styled = styled_cells(terminal.backend().buffer(), inner);
            assert!(
                styled > 0,
                "{screen:?}: content of {region:?} came out monochrome"
            );
        }

        // (b) The dashboard states the quality gate verdict in words.
        state.screen = Screen::Dashboard;
        let text = render_text(&state, WIDTH, HEIGHT);
        assert!(text.contains("Quality Gate"), "{text}");
        assert!(
            text.contains("PASSED") || text.contains("FAILED"),
            "no gate verdict: {text}"
        );

        // (c) A click inside the Errors card is a filtered jump to triage.
        let map = render(&state, WIDTH, HEIGHT);
        let card = map.cards[dashboard::Card::Errors.index()]
            .expect("the Errors card recorded no rectangle");
        handle_mouse(
            &mut state,
            mouse(
                MouseEventKind::Down(MouseButton::Left),
                card.x + card.width / 2,
                card.y + card.height / 2,
            ),
        );

        assert_eq!(state.screen, Screen::Triage);
        assert!(
            state.filters.severities.contains(&Severity::Error),
            "the error filter did not follow the click"
        );
    }

    #[test]
    fn the_status_line_carries_the_bindings_and_the_ticker() {
        let mut state = state();
        assert!(status_line(&state).contains("rescan"));

        state.screen = Screen::Triage;
        state.status = "2 new".to_string();
        state.filters.toggle_status(Status::New);
        let line = status_line(&state);
        assert!(line.starts_with("2 new"));
        assert!(line.contains("filtered"));
        assert!(line.contains("search"));

        assert_eq!(ticker(&state), "2 new | 1 base | 0 supp");

        state.scan_running = true;
        assert_eq!(ticker(&state), "starting");
        state.progress = Some(Progress {
            files_total: 10,
            files_done: 4,
            findings: 3,
        });
        assert_eq!(ticker(&state), "4/10 files | 3 findings");
    }
}
