//! Silo matrix: boundary violations as a from-silo by to-silo grid.
//!
//! The grid geometry is a pure function of the pane rectangle, the matrix and
//! the cursor, so scrolling needs no stored offsets: the visible window is
//! always derived from the cursor. Screen-local view state and the clickable
//! cell rectangles live in thread-locals written by the last draw, mirroring
//! `ui::triage`.

use std::cell::{Cell as StdCell, RefCell};

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use siloscan_core::findings::sanitize_for_terminal;

use crate::state::{AppState, SiloMatrix};
use crate::ui::LayoutMap;
use crate::ui::theme;

/// Width bounds for one matrix column, gap column included.
const MIN_CELL: u16 = 5;
const MAX_CELL: u16 = 10;
/// Width bounds for the row-header column.
const MIN_HEADER: u16 = 6;
const MAX_HEADER: u16 = 16;
const HINT: &str = "rows from, cols to | arrows move cell | enter open edge | esc close";
const EMPTY_HINT: &str = "nothing crossed a boundary | tab next screen";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SiloView {
    /// From-silo, an index into `SiloMatrix::names`.
    pub row: usize,
    /// To-silo, an index into `SiloMatrix::names`.
    pub col: usize,
    /// Whether the edge detail pane is open.
    pub open: bool,
    /// First listed finding in the detail pane.
    pub scroll: usize,
}

thread_local! {
    static VIEW: StdCell<SiloView> = const { StdCell::new(SiloView {
        row: 0,
        col: 0,
        open: false,
        scroll: 0,
    }) };
    static CELLS: RefCell<Vec<((usize, usize), Rect)>> = const { RefCell::new(Vec::new()) };
    static DETAIL: StdCell<Option<Rect>> = const { StdCell::new(None) };
}

pub fn view() -> SiloView {
    VIEW.with(StdCell::get)
}

pub fn set_view(view: SiloView) {
    VIEW.with(|cell| cell.set(view));
}

/// Cell rectangles of the last rendered frame, keyed by (from, to).
pub fn cells() -> Vec<((usize, usize), Rect)> {
    CELLS.with(|cell| cell.borrow().clone())
}

fn set_cells(cells: Vec<((usize, usize), Rect)>) {
    CELLS.with(|cell| *cell.borrow_mut() = cells);
}

fn detail_area() -> Option<Rect> {
    DETAIL.with(StdCell::get)
}

/// Geometry of the visible part of the matrix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grid {
    pub header_w: u16,
    pub cell_w: u16,
    /// First visible column and row, chosen so the cursor stays on screen.
    pub col_start: usize,
    pub row_start: usize,
    pub cols: usize,
    pub rows: usize,
    pub cells: Vec<((usize, usize), Rect)>,
}

/// Lay the matrix out inside `inner`, whose first line is the column header.
pub fn grid(inner: Rect, matrix: &SiloMatrix, view: SiloView) -> Grid {
    let count = matrix.names.len();
    let longest = matrix
        .names
        .iter()
        .map(|name| name.chars().count() as u16)
        .max()
        .unwrap_or(0);

    let header_w = (longest + 1)
        .clamp(MIN_HEADER, MAX_HEADER)
        .min(inner.width / 2);
    let cell_w = (longest + 1).clamp(MIN_CELL, MAX_CELL);

    let mut grid = Grid {
        header_w,
        cell_w,
        ..Grid::default()
    };
    if count == 0 || inner.height < 2 || header_w == 0 || inner.width <= header_w {
        return grid;
    }

    grid.cols = (((inner.width - header_w) / cell_w) as usize).min(count);
    grid.rows = ((inner.height - 1) as usize).min(count);
    if grid.cols == 0 || grid.rows == 0 {
        return grid;
    }

    grid.col_start = window_start(view.col, grid.cols, count);
    grid.row_start = window_start(view.row, grid.rows, count);

    for row in 0..grid.rows {
        for col in 0..grid.cols {
            let rect = Rect::new(
                inner.x + header_w + col as u16 * cell_w,
                inner.y + 1 + row as u16,
                cell_w,
                1,
            );
            grid.cells
                .push(((grid.row_start + row, grid.col_start + col), rect));
        }
    }
    grid
}

/// First visible index of a window of `size` that must contain `cursor`.
fn window_start(cursor: usize, size: usize, count: usize) -> usize {
    let last = count.saturating_sub(size);
    if cursor + 1 > size {
        (cursor + 1 - size).min(last)
    } else {
        0
    }
}

fn clamp(view: SiloView, count: usize) -> SiloView {
    if count == 0 {
        return SiloView::default();
    }
    SiloView {
        row: view.row.min(count - 1),
        col: view.col.min(count - 1),
        ..view
    }
}

/// Findings listed by the detail pane for the cursor's edge, as row indices
/// into `AppState::rows`.
pub fn edge_rows(matrix: &SiloMatrix, view: SiloView) -> Vec<usize> {
    let (Some(from), Some(to)) = (matrix.names.get(view.row), matrix.names.get(view.col)) else {
        return Vec::new();
    };
    matrix
        .edges
        .get(&(from.clone(), to.clone()))
        .cloned()
        .unwrap_or_default()
}

pub fn draw_silo(frame: &mut Frame, area: Rect, state: &AppState, layout: &mut LayoutMap) {
    let Some(matrix) = state.silo_matrix() else {
        set_cells(Vec::new());
        DETAIL.with(|cell| cell.set(None));
        draw_empty(frame, area);
        layout.table = Some(area);
        return;
    };

    let view = clamp(view(), matrix.names.len());
    let open = view.open && !edge_rows(&matrix, view).is_empty();

    let [matrix_area, detail, hint] = if open {
        Layout::vertical([
            Constraint::Min(4),
            Constraint::Percentage(40),
            Constraint::Length(1),
        ])
        .areas(area)
    } else {
        Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(0),
            Constraint::Length(1),
        ])
        .areas(area)
    };

    let cells = draw_matrix(frame, matrix_area, &matrix, view);
    set_cells(cells);

    if open {
        draw_detail(frame, detail, state, &matrix, view);
        DETAIL.with(|cell| cell.set(Some(detail)));
        layout.code = Some(detail);
    } else {
        DETAIL.with(|cell| cell.set(None));
    }

    frame.render_widget(Paragraph::new(Line::styled(HINT, theme::dim())), hint);

    layout.table = Some(matrix_area);
}

fn draw_empty(frame: &mut Frame, area: Rect) {
    let [body, hint] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    let lines = vec![
        Line::styled("no boundary violations", theme::dim()),
        Line::styled(
            "every import stayed inside its silo; run a scan to refresh",
            theme::dim(),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(theme::pane_block(" silos ", false)),
        body,
    );
    frame.render_widget(Paragraph::new(Line::styled(EMPTY_HINT, theme::dim())), hint);
}

fn draw_matrix(
    frame: &mut Frame,
    area: Rect,
    matrix: &SiloMatrix,
    view: SiloView,
) -> Vec<((usize, usize), Rect)> {
    let total: usize = matrix.cells.iter().flatten().sum();
    let title = format!(" silos {} | violations {total} ", matrix.names.len());
    let block = theme::pane_block(&title, true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return Vec::new();
    }

    let grid = grid(inner, matrix, view);
    if grid.cells.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled("terminal too small", theme::dim())),
            inner,
        );
        return Vec::new();
    }

    frame.render_widget(
        Paragraph::new(Line::styled(fit("from", grid.header_w), theme::dim())),
        Rect::new(inner.x, inner.y, grid.header_w, 1),
    );

    for offset in 0..grid.cols {
        let index = grid.col_start + offset;
        // Every header is accented; the cursor's own row and column are bold on
        // top of that, so the crosshair reads without a second color.
        let mut style = Style::default().fg(theme::ACCENT);
        if index == view.col {
            style = style.add_modifier(Modifier::BOLD);
        }
        frame.render_widget(
            Paragraph::new(Line::styled(
                fit(&matrix.names[index], grid.cell_w - 1),
                style,
            ))
            .right_aligned(),
            Rect::new(
                inner.x + grid.header_w + offset as u16 * grid.cell_w,
                inner.y,
                grid.cell_w - 1,
                1,
            ),
        );
    }

    for offset in 0..grid.rows {
        let index = grid.row_start + offset;
        let mut style = Style::default().fg(theme::ACCENT);
        if index == view.row {
            style = style.add_modifier(Modifier::BOLD);
        }
        frame.render_widget(
            Paragraph::new(Line::styled(
                fit(&matrix.names[index], grid.header_w),
                style,
            )),
            Rect::new(inner.x, inner.y + 1 + offset as u16, grid.header_w, 1),
        );
    }

    for ((row, col), rect) in &grid.cells {
        let count = matrix.cells[*row][*col];
        let mut style = if count > 0 {
            Style::default()
                .fg(Color::White)
                .bg(theme::ERROR)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::DIM).add_modifier(Modifier::DIM)
        };
        if (*row, *col) == (view.row, view.col) {
            style = style.add_modifier(Modifier::REVERSED);
        }
        let text = if count > 0 {
            count.to_string()
        } else {
            ".".to_string()
        };
        frame.render_widget(
            Paragraph::new(Line::styled(text, style)).right_aligned(),
            Rect::new(rect.x, rect.y, rect.width - 1, 1),
        );
    }

    grid.cells
}

fn draw_detail(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    matrix: &SiloMatrix,
    view: SiloView,
) {
    let rows = edge_rows(matrix, view);
    let title = format!(
        " {} -> {} | {} findings ",
        matrix.names[view.row],
        matrix.names[view.col],
        rows.len()
    );
    let block = theme::pane_block(&title, true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let start = view.scroll.min(rows.len().saturating_sub(1));
    let lines: Vec<Line<'static>> = rows
        .iter()
        .skip(start)
        .take(inner.height as usize)
        .filter_map(|index| state.rows.get(*index))
        .map(|row| {
            let finding = &row.finding;
            Line::from(vec![
                Span::styled(
                    format!("{}:{}", sanitize_for_terminal(&finding.path), finding.line),
                    theme::accent(),
                ),
                Span::raw("  "),
                Span::styled(
                    crate::ui::display_match(&state.rules, finding).to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(lines), inner);
}

/// Truncate to `width` characters without splitting one. Silo names come from
/// the repository's config, so they are sanitized before the cut.
fn fit(text: &str, width: u16) -> String {
    sanitize_for_terminal(text)
        .chars()
        .take(width as usize)
        .collect()
}

pub fn handle_key_silo(state: &mut AppState, key: KeyEvent) {
    let Some(matrix) = state.silo_matrix() else {
        return;
    };
    let count = matrix.names.len();
    if count == 0 {
        return;
    }

    let mut view = clamp(view(), count);
    match key.code {
        KeyCode::Right | KeyCode::Char('l') => {
            view.col = (view.col + 1).min(count - 1);
            view.scroll = 0;
        }
        KeyCode::Left | KeyCode::Char('h') => {
            view.col = view.col.saturating_sub(1);
            view.scroll = 0;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            view.row = (view.row + 1).min(count - 1);
            view.scroll = 0;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            view.row = view.row.saturating_sub(1);
            view.scroll = 0;
        }
        KeyCode::Enter => {
            view.open = true;
            view.scroll = 0;
        }
        KeyCode::Esc => {
            view.open = false;
            view.scroll = 0;
        }
        KeyCode::PageDown => view.scroll = view.scroll.saturating_add(1),
        KeyCode::PageUp => view.scroll = view.scroll.saturating_sub(1),
        KeyCode::Home => view.scroll = 0,
        _ => return,
    }
    set_view(view);
}

/// Clicking a cell moves the cursor; clicking the cell already under the
/// cursor opens its edge. The wheel scrolls the detail pane.
pub fn handle_mouse_silo(state: &mut AppState, event: MouseEvent) {
    let Some(matrix) = state.silo_matrix() else {
        return;
    };
    let count = matrix.names.len();
    if count == 0 {
        return;
    }

    let mut view = clamp(view(), count);
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let Some((row, col)) = cell_at(&cells(), event.column, event.row) else {
                return;
            };
            if (row, col) == (view.row, view.col) {
                view.open = true;
                view.scroll = 0;
            } else {
                view.row = row;
                view.col = col;
                view.scroll = 0;
            }
        }
        MouseEventKind::ScrollDown => {
            if !detail_area().is_some_and(|rect| contains(rect, event.column, event.row)) {
                return;
            }
            view.scroll = view.scroll.saturating_add(1);
        }
        MouseEventKind::ScrollUp => {
            if !detail_area().is_some_and(|rect| contains(rect, event.column, event.row)) {
                return;
            }
            view.scroll = view.scroll.saturating_sub(1);
        }
        _ => return,
    }
    set_view(view);
}

/// Matrix cell covering a position, if any.
pub fn cell_at(cells: &[((usize, usize), Rect)], column: u16, row: u16) -> Option<(usize, usize)> {
    cells
        .iter()
        .find(|(_, rect)| contains(*rect, column, row))
        .map(|(index, _)| *index)
}

fn contains(rect: Rect, column: u16, row: u16) -> bool {
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
    use siloscan_core::findings::Finding;
    use siloscan_core::rules::{RuleSet, Severity};

    use crate::state::{FindingRow, Status};

    fn finding(path: &str, line: u64, matched: &str) -> Finding {
        Finding {
            rule_id: "boundary.import".to_string(),
            severity: Severity::Error,
            message: "crosses a silo boundary".to_string(),
            path: path.to_string(),
            line,
            column: 1,
            matched: matched.to_string(),
            fingerprint: format!("{path}:{line}"),
        }
    }

    /// Three silos, four violations: api -> db twice, web -> api once,
    /// web -> db once.
    fn sample() -> AppState {
        let mut state = AppState::new(
            PathBuf::from("/repo"),
            Arc::new(RuleSet {
                rules: Vec::new(),
                ..Default::default()
            }),
            None,
        );
        state.rows = [
            ("api/handler.rs", 4, "db::pool"),
            ("api/query.rs", 9, "db::rows"),
            ("web/page.rs", 2, "api::client"),
            ("web/admin.rs", 7, "db::pool"),
        ]
        .into_iter()
        .map(|(path, line, matched)| FindingRow {
            finding: finding(path, line, matched),
            status: Status::New,
        })
        .collect();
        state.boundary_edges = vec![
            ("api".to_string(), "db".to_string(), 0),
            ("api".to_string(), "db".to_string(), 1),
            ("web".to_string(), "api".to_string(), 2),
            ("web".to_string(), "db".to_string(), 3),
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
                draw_silo(frame, area, state, &mut map);
            })
            .unwrap();
        (terminal.backend().buffer().clone(), map)
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
    fn renders_the_matrix_at_80x24() {
        set_view(SiloView::default());
        let (buffer, map) = render(&sample(), 80, 24);
        let text = dump(&buffer);

        assert!(text.contains("silos 3 | violations 4"), "{text}");
        assert!(text.contains("from"), "{text}");
        for name in ["api", "db", "web"] {
            assert!(text.contains(name), "{name} missing\n{text}");
        }
        // api -> db carries two findings, web -> api one.
        assert!(text.contains('2'), "{text}");
        assert!(text.contains("arrows move cell"), "{text}");
        assert!(map.table.is_some());
        assert!(map.code.is_none(), "detail pane stays shut");
    }

    #[test]
    fn renders_the_matrix_at_140x40() {
        set_view(SiloView::default());
        let (buffer, _) = render(&sample(), 140, 40);
        let text = dump(&buffer);

        assert!(text.contains("silos 3 | violations 4"), "{text}");
        assert_eq!(cells().len(), 9, "3x3 cells all fit");
    }

    #[test]
    fn zero_cells_and_violating_cells_are_styled_apart() {
        set_view(SiloView::default());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let state = sample();
        let mut map = LayoutMap::default();
        terminal
            .draw(|frame| draw_silo(frame, frame.area(), &state, &mut map))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();

        // api -> db is row 0, column 1; api -> api is row 0, column 0.
        let cells = cells();
        let violating = cells
            .iter()
            .find(|(index, _)| *index == (0, 1))
            .map(|(_, rect)| *rect)
            .unwrap();
        let empty = cells
            .iter()
            .find(|(index, _)| *index == (0, 2))
            .map(|(_, rect)| *rect)
            .unwrap();

        let hot = buffer
            .cell((violating.x + violating.width - 2, violating.y))
            .unwrap();
        assert_eq!(hot.symbol(), "2");
        assert_eq!(hot.style().fg, Some(Color::White));
        assert_eq!(hot.style().bg, Some(theme::ERROR));
        assert!(hot.style().add_modifier.contains(Modifier::BOLD));

        let cold = buffer.cell((empty.x + empty.width - 2, empty.y)).unwrap();
        assert_eq!(cold.symbol(), ".");
        assert_eq!(cold.style().fg, Some(theme::DIM));
        assert!(cold.style().add_modifier.contains(Modifier::DIM));
    }

    #[test]
    fn the_cell_cursor_clamps_at_the_edges() {
        set_view(SiloView::default());
        let mut state = sample();

        for _ in 0..6 {
            handle_key_silo(&mut state, key(KeyCode::Right));
        }
        assert_eq!(view().col, 2);
        for _ in 0..6 {
            handle_key_silo(&mut state, key(KeyCode::Down));
        }
        assert_eq!(view().row, 2);

        for _ in 0..6 {
            handle_key_silo(&mut state, key(KeyCode::Left));
        }
        assert_eq!(view().col, 0);
        for _ in 0..6 {
            handle_key_silo(&mut state, key(KeyCode::Up));
        }
        assert_eq!(view().row, 0);
    }

    #[test]
    fn a_stale_cursor_is_clamped_against_a_smaller_matrix() {
        set_view(SiloView {
            row: 9,
            col: 9,
            open: true,
            scroll: 3,
        });
        let mut state = sample();
        handle_key_silo(&mut state, key(KeyCode::Left));
        assert_eq!((view().row, view().col), (2, 1));
    }

    #[test]
    fn keys_without_a_matrix_do_nothing() {
        set_view(SiloView::default());
        let mut state = sample();
        state.boundary_edges.clear();

        handle_key_silo(&mut state, key(KeyCode::Right));
        handle_mouse_silo(&mut state, click(1, 1));
        assert_eq!(view(), SiloView::default());

        let (buffer, map) = render(&state, 80, 24);
        assert!(dump(&buffer).contains("no boundary violations"));
        assert!(map.table.is_some());
    }

    #[test]
    fn enter_opens_the_edge_detail_pane_with_that_edges_findings() {
        set_view(SiloView::default());
        let mut state = sample();

        // Cursor on api -> db.
        handle_key_silo(&mut state, key(KeyCode::Right));
        handle_key_silo(&mut state, key(KeyCode::Enter));
        assert!(view().open);

        let (buffer, map) = render(&state, 100, 30);
        let text = dump(&buffer);
        assert!(text.contains("api -> db | 2 findings"), "{text}");
        assert!(text.contains("api/handler.rs:4"), "{text}");
        assert!(text.contains("db::pool"), "{text}");
        assert!(text.contains("api/query.rs:9"), "{text}");
        assert!(
            !text.contains("web/page.rs"),
            "other edges stay out\n{text}"
        );
        assert!(map.code.is_some());

        handle_key_silo(&mut state, key(KeyCode::Esc));
        assert!(!view().open);
        let (buffer, map) = render(&state, 100, 30);
        assert!(!dump(&buffer).contains("2 findings"));
        assert!(map.code.is_none());
    }

    #[test]
    fn an_empty_edge_keeps_the_pane_shut() {
        set_view(SiloView::default());
        let mut state = sample();
        // api -> api has no findings.
        handle_key_silo(&mut state, key(KeyCode::Enter));

        let (_, map) = render(&state, 100, 30);
        assert!(map.code.is_none());
        assert!(edge_rows(&state.silo_matrix().unwrap(), view()).is_empty());
    }

    #[test]
    fn clicking_moves_the_cursor_and_clicking_again_opens_the_edge() {
        set_view(SiloView::default());
        let mut state = sample();
        let _ = render(&state, 100, 30);

        let cells = cells();
        let (_, rect) = cells
            .iter()
            .find(|(index, _)| *index == (2, 1))
            .copied()
            .unwrap();

        handle_mouse_silo(&mut state, click(rect.x, rect.y));
        assert_eq!((view().row, view().col), (2, 1));
        assert!(!view().open);

        handle_mouse_silo(&mut state, click(rect.x, rect.y));
        assert!(view().open);

        let (buffer, _) = render(&state, 100, 30);
        let text = dump(&buffer);
        assert!(text.contains("web -> db | 1 findings"), "{text}");
        assert!(text.contains("web/admin.rs:7"), "{text}");
    }

    #[test]
    fn a_click_outside_the_grid_is_ignored() {
        set_view(SiloView::default());
        let mut state = sample();
        let _ = render(&state, 100, 30);

        handle_mouse_silo(&mut state, click(0, 0));
        assert_eq!((view().row, view().col), (0, 0));
        assert!(!view().open);
    }

    #[test]
    fn the_wheel_scrolls_only_over_the_detail_pane() {
        set_view(SiloView {
            col: 1,
            open: true,
            ..SiloView::default()
        });
        let mut state = sample();
        let (_, map) = render(&state, 100, 30);
        let detail = map.code.unwrap();

        let wheel = |kind, column, row| MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        };
        handle_mouse_silo(
            &mut state,
            wheel(MouseEventKind::ScrollDown, detail.x + 1, detail.y + 1),
        );
        assert_eq!(view().scroll, 1);
        handle_mouse_silo(&mut state, wheel(MouseEventKind::ScrollDown, 0, 0));
        assert_eq!(view().scroll, 1);
        handle_mouse_silo(
            &mut state,
            wheel(MouseEventKind::ScrollUp, detail.x + 1, detail.y + 1),
        );
        assert_eq!(view().scroll, 0);
    }

    #[test]
    fn the_grid_scrolls_horizontally_when_the_silos_exceed_the_width() {
        let mut state = sample();
        state.boundary_edges = (0..12)
            .map(|index| (format!("silo{index:02}"), "silo00".to_string(), 0))
            .collect();
        let matrix = state.silo_matrix().unwrap();
        assert_eq!(matrix.names.len(), 12);

        let inner = Rect::new(0, 0, 60, 10);
        let left = grid(inner, &matrix, SiloView::default());
        assert!(left.cols < 12, "not every column fits");
        assert_eq!(left.col_start, 0);
        assert_eq!(left.rows, 9);

        let right = grid(
            inner,
            &matrix,
            SiloView {
                row: 11,
                col: 11,
                ..SiloView::default()
            },
        );
        assert_eq!(right.col_start + right.cols, 12, "cursor column is visible");
        assert_eq!(right.row_start + right.rows, 12, "cursor row is visible");
        assert_eq!(right.cells.len(), right.cols * right.rows);
    }

    #[test]
    fn a_tiny_pane_drops_the_grid_instead_of_panicking() {
        let matrix = sample().silo_matrix().unwrap();
        assert!(
            grid(Rect::new(0, 0, 4, 6), &matrix, SiloView::default())
                .cells
                .is_empty()
        );
        assert!(
            grid(Rect::new(0, 0, 40, 1), &matrix, SiloView::default())
                .cells
                .is_empty()
        );

        set_view(SiloView::default());
        let state = sample();
        let (_, map) = render(&state, 8, 5);
        assert!(cells().is_empty());
        assert!(map.table.is_some());
    }
}
