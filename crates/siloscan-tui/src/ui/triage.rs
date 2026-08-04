//! Triage screen: filter sidebar, findings table, code context pane.
//!
//! Everything the screen needs beyond `AppState` (sort mode, sidebar focus,
//! clickable rectangles) lives in two thread-locals written by the last draw,
//! mirroring how `ui::LayoutMap` is handed to the mouse handler. `LayoutMap`
//! itself is a fixed `Copy` struct owned by `ui/mod.rs`, so the chip and header
//! rectangles are kept here in `Hits` instead.

use std::cell::{Cell as StdCell, RefCell};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};

use siloscan_core::findings::Finding;
use siloscan_core::metrics::DUPLICATE_BLOCK_RULE_ID;
use siloscan_core::output::REDACTED_MATCH;
use siloscan_core::rules::Severity;

use crate::state::{AppState, Filters, Pane, Screen, Status};
use crate::ui::LayoutMap;
use crate::ui::theme;

const SIDEBAR_WIDTH: u16 = 24;
/// Below this width the sidebar is dropped whatever the collapse flag says.
const SIDEBAR_MIN_COLS: u16 = 90;
/// Below this width the code pane stacks under the table instead of beside it.
const STACK_COLS: u16 = 120;
const TOP_RULES: usize = 8;
const WHEEL_LINES: isize = 3;
const PAGE_ROWS: usize = 10;
/// Length of the block key inside a duplicate-block finding's matched text.
const BLOCK_KEY_LEN: usize = 12;
/// Indent of a copy row under its group header.
const COPY_INDENT: &str = "  ";

/// Findings table geometry. Status and severity are fixed; the rule column is
/// sized to the ids it has to show; path and message share what is left.
const STATUS_W: u16 = 4;
const SEVERITY_W: u16 = 4;
const RULE_MAX_W: u16 = 24;
const MIN_TEXT_W: u16 = 20;
/// One space between each of the five columns.
const COLUMN_GAPS: u16 = 4;

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

/// Clickable rectangles of the last rendered frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hits {
    pub chips: Vec<(Chip, Rect)>,
    /// Table header row: clicking it cycles the sort.
    pub header: Option<Rect>,
    /// Table data rows, excluding the header.
    pub rows: Option<Rect>,
}

/// Block grouping of the findings table: whether it is on, which duplicate sets
/// are expanded, and where the cursor sits in the grouped row list. Screen-local
/// like [`TriageView`], and kept apart from it because the expanded set is not
/// `Copy`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupState {
    pub on: bool,
    /// Block keys whose copies are listed. Absent means collapsed, so a fresh
    /// grouping starts with every set folded into its header.
    pub expanded: BTreeSet<String>,
    /// Index into `grouped_rows`, only meaningful while `on`.
    pub cursor: usize,
}

impl GroupState {
    /// Flip grouping, keeping which sets are expanded.
    pub fn toggle(mut self) -> GroupState {
        self.on = !self.on;
        self
    }

    /// Expand a collapsed set or collapse an expanded one.
    pub fn toggle_expanded(mut self, key: &str) -> GroupState {
        if !self.expanded.remove(key) {
            self.expanded.insert(key.to_string());
        }
        self
    }

    pub fn is_expanded(&self, key: &str) -> bool {
        self.expanded.contains(key)
    }
}

/// One duplicate set as its header row shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockGroup {
    /// The 12-hex block key: the identity of the duplicate set.
    pub key: String,
    /// Copies of the block currently visible.
    pub copies: usize,
    /// Lines in the block, as the finding's matched text reports them.
    pub lines: usize,
    pub expanded: bool,
}

/// A row of the grouped findings table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupRow {
    /// Collapsible header of one duplicate set.
    Header(BlockGroup),
    /// One copy of the set above it. `position` indexes `visible_rows()`, like
    /// every other row index on this screen.
    Copy { key: String, position: usize },
    /// A finding that is not part of a duplicate set.
    Ungrouped { position: usize },
}

impl GroupRow {
    /// Position into `visible_rows()` this row opens, if it is a finding.
    pub fn position(&self) -> Option<usize> {
        match self {
            GroupRow::Header(_) => None,
            GroupRow::Copy { position, .. } | GroupRow::Ungrouped { position } => Some(*position),
        }
    }
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
    static GROUP: RefCell<GroupState> = const { RefCell::new(GroupState {
        on: false,
        expanded: BTreeSet::new(),
        cursor: 0,
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

pub fn group() -> GroupState {
    GROUP.with(|cell| cell.borrow().clone())
}

pub fn set_group(group: GroupState) {
    GROUP.with(|cell| *cell.borrow_mut() = group);
}

/// Turn block grouping on or off. The two modes index different row spaces, so
/// the cursor and the table scroll restart; the flat view then re-anchors on the
/// selection it kept all along.
pub fn toggle_grouping(state: &mut AppState) {
    let mut group = group().toggle();
    group.cursor = 0;
    let on = group.on;
    set_group(group);

    state.scroll.table = 0;
    state.scroll.code = 0;
    if !on {
        follow_selection(state, view());
    }
}

/// Dashboard and silo-card click-through for the duplication numbers: triage
/// showing the duplicate-block findings only, grouped by block.
pub fn open_duplication(state: &mut AppState) {
    let mut filters = Filters::default();
    filters.toggle_rule(DUPLICATE_BLOCK_RULE_ID);
    state.filters = filters;
    state.screen = Screen::Triage;
    state.selected = 0;
    state.clamp_selection();
    state.scroll.table = 0;
    state.scroll.code = 0;

    let mut group = group();
    group.on = true;
    group.cursor = 0;
    set_group(group);
}

/// `"N duplicated lines (block HHHHHHHHHHHH)"` split into its line count and its
/// block key. The format is the reserved rule's contract; anything else is
/// rejected rather than guessed at.
fn parse_duplicate_matched(matched: &str) -> Option<(usize, String)> {
    let (count, rest) = matched.split_once(" duplicated lines (block ")?;
    let key = rest.strip_suffix(')')?;
    if key.len() != BLOCK_KEY_LEN || !key.chars().all(|symbol| symbol.is_ascii_hexdigit()) {
        return None;
    }
    Some((count.parse().ok()?, key.to_string()))
}

/// Key of the duplicate set a finding belongs to: the 12-hex block hash carried
/// by the reserved rule's matched text. `None` for every other rule and for
/// matched text that does not parse, which then triages ungrouped.
pub fn block_key(finding: &Finding) -> Option<String> {
    if finding.rule_id != DUPLICATE_BLOCK_RULE_ID {
        return None;
    }
    parse_duplicate_matched(&finding.matched).map(|(_, key)| key)
}

/// Lines in the block a finding copies, as its matched text reports them. Only
/// meaningful for a finding [`block_key`] accepted.
fn block_lines(finding: &Finding) -> usize {
    parse_duplicate_matched(&finding.matched).map_or(0, |(lines, _)| lines)
}

/// Rows of the grouped findings table.
///
/// The order is part of the contract:
/// 1. every duplicate set, by copy count descending then block key ascending,
///    each header immediately followed by its copies when expanded;
/// 2. every other finding, in the order the flat table would have shown it.
///
/// Copies inside a set keep that same flat order.
pub fn grouped_rows(state: &AppState, sort: Sort, group: &GroupState) -> Vec<GroupRow> {
    let order = view_order(state, sort);
    let visible = state.visible_rows();

    let mut sets: BTreeMap<String, (usize, Vec<usize>)> = BTreeMap::new();
    let mut ungrouped: Vec<usize> = Vec::new();
    for &position in &order {
        let finding = &state.rows[visible[position]].finding;
        match block_key(finding) {
            Some(key) => sets
                .entry(key)
                .or_insert((block_lines(finding), Vec::new()))
                .1
                .push(position),
            None => ungrouped.push(position),
        }
    }

    // The map already yields keys ascending; a stable sort by copy count keeps
    // that as the tie-break.
    let mut ranked: Vec<(String, usize, Vec<usize>)> = sets
        .into_iter()
        .map(|(key, (lines, positions))| (key, lines, positions))
        .collect();
    ranked.sort_by_key(|(_, _, positions)| Reverse(positions.len()));

    let mut rows = Vec::new();
    for (key, lines, positions) in ranked {
        let expanded = group.is_expanded(&key);
        rows.push(GroupRow::Header(BlockGroup {
            copies: positions.len(),
            lines,
            expanded,
            key: key.clone(),
        }));
        if expanded {
            rows.extend(positions.into_iter().map(|position| GroupRow::Copy {
                key: key.clone(),
                position,
            }));
        }
    }
    rows.extend(
        ungrouped
            .into_iter()
            .map(|position| GroupRow::Ungrouped { position }),
    );
    rows
}

/// Rows the table is showing, whichever mode it is in.
fn row_count(state: &AppState, view: TriageView, group: &GroupState) -> usize {
    if group.on {
        grouped_rows(state, view.sort, group).len()
    } else {
        state.visible_len()
    }
}

/// Keep the group cursor inside the row list after anything that changed it.
fn clamp_group_cursor(state: &AppState) {
    let mut group = group();
    if !group.on {
        return;
    }
    let rows = grouped_rows(state, view().sort, &group);
    group.cursor = group.cursor.min(rows.len().saturating_sub(1));
    set_group(group);
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

/// One chip as the sidebar renders it: marker, name and count are styled
/// apart, so they are kept apart here too.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SectionRow {
    chip: Chip,
    name: String,
    count: usize,
    active: bool,
}

/// Title and rows of one sidebar section.
fn section_rows(state: &AppState, section: Section) -> (&'static str, Vec<SectionRow>) {
    match section {
        Section::Severity => (
            "Severity",
            state
                .counts_by_severity()
                .into_iter()
                .map(|(severity, count)| SectionRow {
                    chip: Chip::Severity(severity),
                    name: severity.as_str().to_string(),
                    count,
                    active: state.filters.severities.contains(&severity),
                })
                .collect(),
        ),
        Section::Status => {
            let (new, baselined, suppressed) = state.debt_counts();
            (
                "Status",
                [
                    (Status::New, new),
                    (Status::Baselined, baselined),
                    (Status::Suppressed, suppressed),
                ]
                .into_iter()
                .map(|(status, count)| SectionRow {
                    chip: Chip::Status(status),
                    name: status.as_str().to_string(),
                    count,
                    active: state.filters.statuses.contains(&status),
                })
                .collect(),
            )
        }
        Section::Rules => (
            "Top rules",
            state
                .top_rules(TOP_RULES)
                .into_iter()
                .map(|(rule, count)| SectionRow {
                    active: state.filters.rules.contains(&rule),
                    name: rule.clone(),
                    chip: Chip::Rule(rule),
                    count,
                })
                .collect(),
        ),
    }
}

fn draw_sidebar(
    frame: &mut Frame,
    state: &AppState,
    area: Rect,
    view: TriageView,
    hits: &mut Hits,
) {
    let sections = [Section::Severity, Section::Status, Section::Rules];
    let rows: Vec<(&'static str, Vec<SectionRow>)> = sections
        .iter()
        .map(|section| section_rows(state, *section))
        .collect();

    // The first two sections are fixed lists; the rules section takes the rest
    // and is the only one that ever needs scrolling.
    let areas = Layout::vertical([
        Constraint::Length(rows[0].1.len() as u16 + 2),
        Constraint::Length(rows[1].1.len() as u16 + 2),
        Constraint::Min(3),
    ])
    .split(area);

    let focused = focused_chip(state, view);
    for ((section, (title, chips)), rect) in sections.into_iter().zip(rows.iter()).zip(areas.iter())
    {
        let block = theme::pane_block(title, view.focus == section);
        let inner = block.inner(*rect);
        frame.render_widget(block, *rect);
        if inner.width == 0 || inner.height == 0 {
            continue;
        }

        let start = if section == Section::Rules {
            state
                .scroll
                .sidebar
                .min(chips.len().saturating_sub(inner.height as usize))
        } else {
            0
        };

        for (offset, chip) in chips
            .iter()
            .skip(start)
            .take(inner.height as usize)
            .enumerate()
        {
            let row = Rect::new(inner.x, inner.y + offset as u16, inner.width, 1);
            let line = chip_line(chip, inner.width);
            let paragraph = if focused.as_ref() == Some(&chip.chip) {
                Paragraph::new(line).style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                Paragraph::new(line)
            };
            frame.render_widget(paragraph, row);
            hits.chips.push((chip.chip.clone(), row));
        }
    }
}

/// `[x] name          count`: marker and count carry the styling, the name
/// carries the text.
fn chip_line(chip: &SectionRow, width: u16) -> Line<'static> {
    let marker = if chip.active {
        Span::styled(
            "[x]",
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("[ ]", Style::default().fg(theme::DIM))
    };

    let count = chip.count.to_string();
    let room = (width as usize).saturating_sub(4 + count.len());
    let name = tail_truncate(&chip.name, room);
    let pad = room.saturating_sub(name.chars().count());

    let name_style = if chip.active {
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    Line::from(vec![
        marker,
        Span::raw(" "),
        Span::styled(name, name_style),
        Span::raw(" ".repeat(pad)),
        Span::styled(count, Style::default().fg(theme::DIM)),
    ])
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
            Span::styled(
                "/",
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(state.filters.text.clone()),
            Span::styled(caret, Style::default().add_modifier(Modifier::REVERSED)),
        ];
        frame.render_widget(Paragraph::new(Line::from(spans)), input_area);
    }

    let group = group();
    let grouping = if group.on { "  group:block" } else { "" };
    let title = format!(
        " findings {}/{}  sort:{}{grouping} ",
        state.visible_len(),
        state.rows.len(),
        view.sort.as_str()
    );
    let block = theme::pane_block(&title, true);
    let inner = block.inner(list_area);
    frame.render_widget(block, list_area);
    if inner.width == 0 || inner.height < 2 {
        return;
    }

    let header_rect = Rect::new(inner.x, inner.y, inner.width, 1);
    let rows_rect = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);
    hits.header = Some(header_rect);
    hits.rows = Some(rows_rect);

    let height = rows_rect.height as usize;
    let visible = state.visible_rows();
    let widths = column_widths(inner.width, rule_width(state, &visible));

    // Draw does not mutate state; the handlers clamp with the same rule.
    let (rows, total): (Vec<Row>, usize) = if group.on {
        let display = grouped_rows(state, view.sort, &group);
        let start = clamp_scroll(state.scroll.table, display.len(), height);
        let cursor = group.cursor.min(display.len().saturating_sub(1));
        let rows = display
            .iter()
            .skip(start)
            .take(height)
            .enumerate()
            .map(|(offset, entry)| {
                let row = match entry {
                    GroupRow::Header(block) => header_row(block, &widths),
                    GroupRow::Copy { position, .. } => {
                        finding_row(state, &visible, *position, &widths, COPY_INDENT)
                    }
                    GroupRow::Ungrouped { position } => {
                        finding_row(state, &visible, *position, &widths, "")
                    }
                };
                if start + offset == cursor {
                    row.style(theme::selected())
                } else {
                    row
                }
            })
            .collect();
        (rows, display.len())
    } else {
        let order = view_order(state, view.sort);
        let start = clamp_scroll(state.scroll.table, order.len(), height);
        let selected_display = display_position(&order, state.selected);
        let rows = order
            .iter()
            .skip(start)
            .take(height)
            .enumerate()
            .map(|(offset, &position)| {
                let row = finding_row(state, &visible, position, &widths, "");
                if start + offset == selected_display {
                    row.style(theme::selected())
                } else {
                    row
                }
            })
            .collect();
        (rows, order.len())
    };

    let header = Row::new(vec!["St", "Sev", "Path:Line", "Rule", "Message"]).style(
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    );
    let table = Table::new(rows, widths.map(Constraint::Length))
        .header(header)
        .column_spacing(1);
    frame.render_widget(table, inner);

    if total == 0 {
        frame.render_widget(Paragraph::new(empty_table_hint(state)), rows_rect);
    }
}

/// One finding as a table row. `indent` prefixes the path column, which is how a
/// copy row sits under its group header.
fn finding_row(
    state: &AppState,
    visible: &[usize],
    position: usize,
    widths: &[u16; 5],
    indent: &str,
) -> Row<'static> {
    let row = &state.rows[visible[position]];
    let finding = &row.finding;
    Row::new(vec![
        Span::styled(status_label(row.status), theme::dim()),
        theme::severity_span(finding.severity),
        // The tail of a path carries the file name, so it is the end that has
        // to survive the truncation.
        Span::raw(middle_truncate(
            &format!("{indent}{}:{}", finding.path, finding.line),
            widths[2] as usize,
        )),
        Span::raw(tail_truncate(&finding.rule_id, widths[3] as usize)),
        Span::raw(tail_truncate(&finding.message, widths[4] as usize)),
    ])
}

/// Header of one duplicate set, laid out over the same columns as a finding:
/// `[+]  block HHHHHHHHHHHH  N copies  M lines`.
fn header_row(block: &BlockGroup, widths: &[u16; 5]) -> Row<'static> {
    let marker = if block.expanded { "[-]" } else { "[+]" };
    let copies = if block.copies == 1 {
        "1 copy".to_string()
    } else {
        format!("{} copies", block.copies)
    };

    Row::new(vec![
        Span::styled(marker, theme::accent()),
        Span::raw(""),
        Span::styled(
            tail_truncate(&format!("block {}", block.key), widths[2] as usize),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(tail_truncate(&copies, widths[3] as usize), theme::dim()),
        Span::styled(
            tail_truncate(&format!("{} lines", block.lines), widths[4] as usize),
            theme::dim(),
        ),
    ])
}

/// Guidance for an empty table: what to do next depends on why it is empty.
fn empty_table_hint(state: &AppState) -> Vec<Line<'static>> {
    let lines = if state.rows.is_empty() {
        vec![
            "no findings loaded".to_string(),
            "press r to rescan the tree".to_string(),
        ]
    } else {
        vec![
            "no findings match the filters".to_string(),
            "press esc to clear them, / to search".to_string(),
        ]
    };
    lines
        .into_iter()
        .map(|line| Line::styled(line, theme::dim()))
        .collect()
}

/// Widest rule id on screen, bounded so one long id cannot starve the message
/// column.
fn rule_width(state: &AppState, visible: &[usize]) -> u16 {
    let longest = visible
        .iter()
        .map(|index| state.rows[*index].finding.rule_id.chars().count())
        .max()
        .unwrap_or(0);
    (longest as u16).clamp(4, RULE_MAX_W)
}

/// Column widths across `total`, gaps included. Path and message split what the
/// fixed columns leave, message taking the larger share.
fn column_widths(total: u16, rule_w: u16) -> [u16; 5] {
    let rest = total.saturating_sub(STATUS_W + SEVERITY_W + rule_w + COLUMN_GAPS);
    let path = if rest >= 2 * MIN_TEXT_W {
        ((rest as u32 * 2 / 5) as u16).max(MIN_TEXT_W)
    } else {
        rest / 2
    };
    [STATUS_W, SEVERITY_W, path, rule_w, rest - path]
}

/// Truncate the middle, keeping the tail: `core/.../app.js:1`.
fn middle_truncate(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    if width <= 3 {
        return chars[chars.len() - width..].iter().collect();
    }
    let tail_len = (width - 3) * 2 / 3;
    let head_len = width - 3 - tail_len;
    let head: String = chars[..head_len].iter().collect();
    let tail: String = chars[chars.len() - tail_len..].iter().collect();
    format!("{head}...{tail}")
}

/// Truncate the tail, marking the cut with an ellipsis.
fn tail_truncate(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    if width <= 3 {
        return text.chars().take(width).collect();
    }
    let kept: String = text.chars().take(width - 3).collect();
    format!("{kept}...")
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
    // A pane showing a file gets the accent title; an empty one recedes.
    let block = theme::pane_block(&title, selected.is_some());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let Some(row) = selected else {
        let hint = vec![
            Line::styled("no finding selected", theme::dim()),
            Line::styled("pick a row with j/k or the mouse", theme::dim()),
        ];
        frame.render_widget(Paragraph::new(hint), inner);
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
        let gutter = Span::styled(format!("{number:>5} "), theme::dim());
        if number as u64 == finding.line {
            let (before, matched, after) = split_span(
                text,
                finding.column.max(1) as usize - 1,
                highlight_len(finding),
            );
            // The finding line is drawn in its severity color; the matched span
            // inverts that color instead of inverting the terminal default, so
            // the severity stays readable inside the highlight.
            let color = theme::severity_color(finding.severity);
            let context = Style::default().fg(color);
            lines.push(Line::from(vec![
                gutter,
                Span::styled(before.to_string(), context),
                Span::styled(
                    matched.to_string(),
                    context.add_modifier(Modifier::REVERSED | Modifier::BOLD),
                ),
                Span::styled(after.to_string(), context),
            ]));
        } else {
            lines.push(Line::from(vec![gutter, Span::raw(text.to_string())]));
        }
    }
    lines
}

/// Bytes of the source line the finding's match covers.
///
/// A JSON report redacts a secret finding's `matched`, so its length describes
/// the placeholder and not the credential. Highlighting that many bytes would
/// mark the wrong span, so a redacted finding highlights nothing and the line
/// carries its severity color alone; the column still points at the match.
fn highlight_len(finding: &Finding) -> usize {
    match finding.matched == REDACTED_MATCH {
        true => 0,
        false => finding.matched.len(),
    }
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
        clamp_group_cursor(state);
        return;
    }

    let mut view = view();
    if key.code == KeyCode::Char('g') {
        toggle_grouping(state);
        return;
    }
    // While grouping is on the group list owns the cursor keys and Enter, so
    // Enter reaches a header or a copy instead of the sidebar chips; the chips
    // stay clickable with the mouse.
    if group().on && handle_group_key(state, key, view) {
        return;
    }

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

    clamp_group_cursor(state);
}

/// Grouped-mode navigation over headers and copies. Returns true when the key
/// belonged to the group list, which then keeps it from reaching the flat
/// handler. Landing on a finding selects it, so the code pane follows the cursor
/// exactly as it follows the flat selection.
fn handle_group_key(state: &mut AppState, key: KeyEvent, view: TriageView) -> bool {
    let mut group = group();
    let rows = grouped_rows(state, view.sort, &group);
    if rows.is_empty() {
        group.cursor = 0;
        set_group(group);
        return false;
    }

    let last = rows.len() - 1;
    let mut cursor = group.cursor.min(last);
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => cursor = (cursor + 1).min(last),
        KeyCode::Up | KeyCode::Char('k') => cursor = cursor.saturating_sub(1),
        KeyCode::PageDown => cursor = cursor.saturating_add(PAGE_ROWS).min(last),
        KeyCode::PageUp => cursor = cursor.saturating_sub(PAGE_ROWS),
        KeyCode::Enter | KeyCode::Char(' ') => {
            group = activate_group_row(state, group, &rows[cursor]);
            group.cursor = cursor;
            set_group(group);
            clamp_group_cursor(state);
            follow_group_cursor(state);
            return true;
        }
        _ => return false,
    }

    group.cursor = cursor;
    set_group(group);
    if let Some(position) = rows[cursor].position() {
        state.select_visible(position);
    }
    follow_group_cursor(state);
    true
}

/// Enter or a click on a grouped row: a header folds or unfolds, a finding opens
/// its file context.
fn activate_group_row(state: &mut AppState, group: GroupState, row: &GroupRow) -> GroupState {
    match row {
        GroupRow::Header(block) => group.toggle_expanded(&block.key),
        GroupRow::Copy { position, .. } | GroupRow::Ungrouped { position } => {
            state.select_visible(*position);
            group
        }
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
    let order = view_order(state, view.sort);
    scroll_to_display(state, display_position(&order, state.selected));
}

/// The same, for the cursor of the grouped list.
fn follow_group_cursor(state: &mut AppState) {
    scroll_to_display(state, group().cursor);
}

fn scroll_to_display(state: &mut AppState, display: usize) {
    let height = hits().rows.map_or(0, |rect| rect.height as usize);
    if height == 0 {
        return;
    }
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
                let view = view();
                let group = group();
                if group.on {
                    let rows = grouped_rows(state, view.sort, &group);
                    let start = clamp_scroll(state.scroll.table, rows.len(), rect.height as usize);
                    let display = start + (row - rect.y) as usize;
                    if let Some(entry) = rows.get(display) {
                        let mut group = activate_group_row(state, group, entry);
                        group.cursor = display;
                        set_group(group);
                        clamp_group_cursor(state);
                    }
                    return;
                }

                let order = view_order(state, view.sort);
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
                clamp_group_cursor(state);
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
        let total = row_count(state, view(), &group());
        state.scroll.table = clamp_scroll(state.scroll.table, total, height);
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
        let mut state = AppState::new(
            root,
            Arc::new(RuleSet {
                rules: Vec::new(),
                ..Default::default()
            }),
            None,
        );
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
    fn a_redacted_match_highlights_nothing_rather_than_the_wrong_span() {
        let source = "let token = \"hunter2\";\n";
        let mut finding = finding("secret.token", Severity::Error, "a.rs", 1, "m");
        finding.column = 14;
        finding.matched = REDACTED_MATCH.to_string();

        let lines = code_lines(source, &finding, 1, 0);
        // The placeholder is 10 bytes; highlighting them would mark
        // `hunter2";` and part of nothing at all.
        assert!(lines[0].spans[2].content.is_empty());
        assert_eq!(
            format!(
                "{}{}{}",
                lines[0].spans[1].content, lines[0].spans[2].content, lines[0].spans[3].content
            ),
            source.trim_end()
        );
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
    fn sidebar_sections_cover_every_axis() {
        let mut state = state(PathBuf::from("/nowhere"));
        state.filters.toggle_severity(Severity::Error);

        let sections = [Section::Severity, Section::Status, Section::Rules]
            .map(|section| section_rows(&state, section));

        let headers: Vec<&str> = sections.iter().map(|(title, _)| *title).collect();
        assert_eq!(headers, vec!["Severity", "Status", "Top rules"]);

        let active: Vec<&Chip> = sections
            .iter()
            .flat_map(|(_, rows)| rows.iter())
            .filter(|row| row.active)
            .map(|row| &row.chip)
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

    #[test]
    fn column_widths_fill_the_table_and_favour_the_message() {
        for total in [40u16, 80, 160, 200] {
            let widths = column_widths(total, 24);
            assert_eq!(
                widths.iter().sum::<u16>() + COLUMN_GAPS,
                total,
                "columns tile {total}"
            );
        }

        let wide = column_widths(160, 24);
        assert_eq!(wide[0], STATUS_W);
        assert_eq!(wide[1], SEVERITY_W);
        assert_eq!(wide[3], 24);
        assert!(wide[2] >= MIN_TEXT_W, "path keeps its floor");
        assert!(wide[4] > wide[2], "message takes the larger share");

        // Nothing to divide: the table degrades instead of underflowing.
        assert_eq!(column_widths(4, 24), [4, 4, 0, 24, 0]);
    }

    #[test]
    fn the_rule_column_is_sized_to_the_ids_on_screen() {
        let mut state = state(PathBuf::from("/nowhere"));
        let visible = state.visible_rows();
        // "secret.token" is the longest of the sample ids.
        assert_eq!(rule_width(&state, &visible), 12);

        state.rows[0].finding.rule_id = "a".repeat(80);
        assert_eq!(rule_width(&state, &state.visible_rows()), RULE_MAX_W);
        assert_eq!(rule_width(&state, &[]), 4);
    }

    #[test]
    fn a_long_path_keeps_its_file_name_and_line() {
        assert_eq!(
            middle_truncate("core/deep/nested/app.js:1", 17),
            "core/.../app.js:1"
        );
        assert_eq!(middle_truncate("src/a.rs:2", 20), "src/a.rs:2");
        // Too narrow for an ellipsis: the tail still wins.
        assert_eq!(middle_truncate("src/a.rs:2", 3), "s:2");
        assert_eq!(middle_truncate("src/a.rs:2", 0), "");
    }

    #[test]
    fn a_long_message_is_cut_at_the_tail() {
        assert_eq!(tail_truncate("hardcoded secret", 10), "hardcod...");
        assert_eq!(tail_truncate("short", 10), "short");
        assert_eq!(tail_truncate("hardcoded", 2), "ha");
        assert_eq!(tail_truncate("hardcoded", 0), "");
    }

    const BIG_KEY: &str = "a1b2c3d4e5f6";
    const MID_KEY: &str = "000000000000";
    const SMALL_KEY: &str = "ffffffffffff";

    fn duplicate_row(path: &str, line: u64, lines: usize, key: &str) -> FindingRow {
        let mut finding = finding(
            DUPLICATE_BLOCK_RULE_ID,
            Severity::Info,
            path,
            line,
            "duplicated block, also at src/b.rs:20",
        );
        finding.matched = format!("{lines} duplicated lines (block {key})");
        FindingRow {
            finding,
            status: Status::New,
        }
    }

    /// Three copies of one block, two copies of two more, one duplicate-block
    /// finding whose matched text does not parse, and one ordinary finding.
    /// Canonical order is the order below, which is what the positions in the
    /// assertions index.
    fn grouped_state(root: PathBuf) -> AppState {
        let mut state = state(root);
        state.rows = vec![
            row("secret.token", Severity::Info, "src/a.rs", Status::New),
            duplicate_row("src/a.rs", 10, 42, BIG_KEY),
            duplicate_row("src/b.rs", 20, 42, BIG_KEY),
            duplicate_row("src/a.rs", 30, 42, BIG_KEY),
            duplicate_row("src/b.rs", 40, 7, SMALL_KEY),
            duplicate_row("src/a.rs", 50, 7, SMALL_KEY),
            duplicate_row("src/b.rs", 60, 9, MID_KEY),
            duplicate_row("src/a.rs", 70, 9, MID_KEY),
            {
                let mut broken = duplicate_row("src/b.rs", 80, 5, BIG_KEY);
                broken.finding.matched = "duplicated block".to_string();
                broken
            },
        ];
        state
    }

    fn headers(rows: &[GroupRow]) -> Vec<(String, usize, usize)> {
        rows.iter()
            .filter_map(|row| match row {
                GroupRow::Header(block) => Some((block.key.clone(), block.copies, block.lines)),
                _ => None,
            })
            .collect()
    }

    fn reset_group() {
        set_view(TriageView::default());
        set_group(GroupState::default());
    }

    #[test]
    fn the_block_key_comes_from_the_reserved_matched_text() {
        let mut finding = finding(
            DUPLICATE_BLOCK_RULE_ID,
            Severity::Info,
            "src/a.rs",
            10,
            "duplicated block",
        );
        finding.matched = format!("42 duplicated lines (block {BIG_KEY})");
        assert_eq!(block_key(&finding).as_deref(), Some(BIG_KEY));
        assert_eq!(block_lines(&finding), 42);

        // Another rule with the same shape of matched text is not a block.
        let mut other = finding.clone();
        other.rule_id = "secret.token".to_string();
        assert_eq!(block_key(&other), None);

        for matched in [
            "duplicated block",
            "42 duplicated lines (block )",
            "42 duplicated lines (block a1b2c3d4e5f)",
            "42 duplicated lines (block a1b2c3d4e5f6",
            "42 duplicated lines (block zzzzzzzzzzzz)",
            "many duplicated lines (block a1b2c3d4e5f6)",
            "",
        ] {
            let mut broken = finding.clone();
            broken.matched = matched.to_string();
            assert_eq!(block_key(&broken), None, "{matched:?}");
        }
    }

    #[test]
    fn grouping_collapses_a_duplicate_set_into_one_header() {
        let root = temp_root("group-collapse");
        let mut state = grouped_state(root.clone());
        reset_group();

        let (flat, map) = render(&state, 200, 48);
        let flat_text = dump_rect(&flat, map.table.unwrap());
        assert!(flat_text.contains("src/a.rs:10"), "{flat_text}");
        assert!(!flat_text.contains("copies"), "{flat_text}");

        handle_key_triage(&mut state, key(KeyCode::Char('g')));
        assert!(group().on);

        let (grouped, map) = render(&state, 200, 48);
        let text = dump_rect(&grouped, map.table.unwrap());
        assert!(text.contains("group:block"), "{text}");
        assert!(text.contains(&format!("block {BIG_KEY}")), "{text}");
        assert!(text.contains("3 copies"), "{text}");
        assert!(text.contains("42 lines"), "{text}");
        // Collapsed: no copy of the set is on screen.
        assert!(!text.contains("src/a.rs:10"), "{text}");
        // The ungrouped findings are still listed.
        assert!(text.contains("src/a.rs:2"), "{text}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn expanding_a_group_lists_every_copy() {
        let root = temp_root("group-expand");
        let mut state = grouped_state(root.clone());
        reset_group();
        set_group(GroupState {
            on: true,
            ..GroupState::default()
        });
        let _ = render(&state, 200, 48);

        // The cursor starts on the first header: the biggest set.
        handle_key_triage(&mut state, key(KeyCode::Enter));
        assert!(group().is_expanded(BIG_KEY));

        let (buffer, map) = render(&state, 200, 48);
        let text = dump_rect(&buffer, map.table.unwrap());
        for line in ["src/a.rs:10", "src/b.rs:20", "src/a.rs:30"] {
            assert!(text.contains(line), "{line} missing: {text}");
        }
        assert_eq!(
            grouped_rows(&state, Sort::Canonical, &group())
                .iter()
                .filter(|row| matches!(row, GroupRow::Copy { .. }))
                .count(),
            3
        );

        // Enter again folds it back.
        handle_key_triage(&mut state, key(KeyCode::Enter));
        assert!(!group().is_expanded(BIG_KEY));
        let (buffer, map) = render(&state, 200, 48);
        assert!(!dump_rect(&buffer, map.table.unwrap()).contains("src/a.rs:10"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn toggling_grouping_off_restores_the_flat_view() {
        let root = temp_root("group-off");
        let mut state = grouped_state(root.clone());
        reset_group();

        let (before, map) = render(&state, 200, 48);
        let flat = dump_rect(&before, map.table.unwrap());

        handle_key_triage(&mut state, key(KeyCode::Char('g')));
        let _ = render(&state, 200, 48);
        handle_key_triage(&mut state, key(KeyCode::Char('g')));
        assert!(!group().on);

        let (after, map) = render(&state, 200, 48);
        assert_eq!(dump_rect(&after, map.table.unwrap()), flat);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_cursor_walks_headers_and_copies() {
        let root = temp_root("group-walk");
        let mut state = grouped_state(root.clone());
        reset_group();
        set_group(GroupState {
            on: true,
            expanded: [BIG_KEY.to_string()].into_iter().collect(),
            cursor: 0,
        });
        let _ = render(&state, 200, 48);

        // Header, three copies, then the two collapsed headers.
        let rows = grouped_rows(&state, Sort::Canonical, &group());
        assert!(matches!(rows[0], GroupRow::Header(_)));
        assert_eq!(rows[1].position(), Some(1));
        assert_eq!(rows[3].position(), Some(3));
        assert!(matches!(rows[4], GroupRow::Header(_)));

        handle_key_triage(&mut state, key(KeyCode::Char('j')));
        assert_eq!(group().cursor, 1);
        assert_eq!(state.selected, 1, "landing on a copy selects it");
        assert_eq!(state.selected_row().unwrap().finding.line, 10);

        handle_key_triage(&mut state, key(KeyCode::Down));
        handle_key_triage(&mut state, key(KeyCode::Down));
        assert_eq!(group().cursor, 3);
        assert_eq!(state.selected_row().unwrap().finding.line, 30);

        // Onto the next header: the cursor moves, the selection stays put.
        handle_key_triage(&mut state, key(KeyCode::Char('j')));
        assert_eq!(group().cursor, 4);
        assert_eq!(state.selected_row().unwrap().finding.line, 30);

        handle_key_triage(&mut state, key(KeyCode::Char('k')));
        assert_eq!(group().cursor, 3);

        // Space on a header folds it, and the cursor stays on that header.
        handle_key_triage(&mut state, key(KeyCode::Char('k')));
        handle_key_triage(&mut state, key(KeyCode::Char('k')));
        handle_key_triage(&mut state, key(KeyCode::Char('k')));
        assert_eq!(group().cursor, 0);
        handle_key_triage(&mut state, key(KeyCode::Char(' ')));
        assert!(!group().is_expanded(BIG_KEY));
        assert_eq!(group().cursor, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clicking_a_header_folds_it_and_clicking_a_copy_opens_it() {
        let root = temp_root("group-click");
        let mut state = grouped_state(root.clone());
        reset_group();
        set_group(GroupState {
            on: true,
            expanded: [BIG_KEY.to_string()].into_iter().collect(),
            cursor: 0,
        });
        let (_, map) = render(&state, 200, 48);
        let hits = hits();
        let rows = hits.rows.unwrap();

        // Row 1 is the first copy of the expanded set.
        handle_mouse_with(&mut state, click(rows.x + 1, rows.y + 1), &map, &hits);
        assert_eq!(state.selected, 1);
        assert_eq!(group().cursor, 1);

        // Row 0 is its header.
        handle_mouse_with(&mut state, click(rows.x + 1, rows.y), &map, &hits);
        assert!(!group().is_expanded(BIG_KEY));
        assert_eq!(group().cursor, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_finding_with_unparseable_matched_text_stays_ungrouped() {
        let state = grouped_state(PathBuf::from("/nowhere"));
        let rows = grouped_rows(&state, Sort::Canonical, &GroupState::default());

        // Three headers, then the plain finding and the unparseable one.
        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows[3..],
            [
                GroupRow::Ungrouped { position: 0 },
                GroupRow::Ungrouped { position: 8 },
            ]
        );
        assert_eq!(
            state.rows[8].finding.rule_id.as_str(),
            DUPLICATE_BLOCK_RULE_ID
        );
        assert_eq!(block_key(&state.rows[8].finding), None);
    }

    #[test]
    fn groups_sort_by_copy_count_then_block_key() {
        let state = grouped_state(PathBuf::from("/nowhere"));
        let rows = grouped_rows(&state, Sort::Canonical, &GroupState::default());

        assert_eq!(
            headers(&rows),
            vec![
                (BIG_KEY.to_string(), 3, 42),
                (MID_KEY.to_string(), 2, 9),
                (SMALL_KEY.to_string(), 2, 7),
            ]
        );

        // The order is a property of the findings, not of the row order they
        // arrived in.
        let mut reversed = state.clone();
        reversed.rows.reverse();
        assert_eq!(
            headers(&grouped_rows(
                &reversed,
                Sort::Canonical,
                &GroupState::default()
            )),
            headers(&rows)
        );
        // And it does not move with the table sort.
        for sort in [Sort::Canonical, Sort::Severity, Sort::Rule] {
            assert_eq!(
                headers(&grouped_rows(&state, sort, &GroupState::default())),
                headers(&rows),
                "{sort:?}"
            );
        }
    }

    #[test]
    fn the_duplication_click_through_filters_and_groups() {
        let mut state = grouped_state(PathBuf::from("/nowhere"));
        reset_group();
        state.screen = crate::state::Screen::Dashboard;

        open_duplication(&mut state);

        assert_eq!(state.screen, crate::state::Screen::Triage);
        assert_eq!(state.visible_len(), 8, "every duplicate-block finding");
        assert!(group().on);
        assert_eq!(group().cursor, 0);
        assert_eq!(
            grouped_rows(&state, Sort::Canonical, &group()).len(),
            4,
            "three headers and the unparseable copy"
        );
    }

    #[test]
    fn the_grouped_cursor_stays_visible_while_scrolling() {
        let mut state = grouped_state(PathBuf::from("/nowhere"));
        for index in 0..60 {
            state.rows.push(duplicate_row(
                &format!("src/f{index}.rs"),
                index as u64 + 1,
                3,
                "0123456789ab",
            ));
        }
        reset_group();
        set_group(GroupState {
            on: true,
            expanded: ["0123456789ab".to_string()].into_iter().collect(),
            cursor: 0,
        });
        let _ = render(&state, 160, 20);

        for _ in 0..40 {
            handle_key_triage(&mut state, key(KeyCode::Char('j')));
        }
        let height = hits().rows.unwrap().height as usize;
        assert!(state.scroll.table > 0);
        assert!(group().cursor >= state.scroll.table);
        assert!(group().cursor < state.scroll.table + height);

        for _ in 0..40 {
            handle_key_triage(&mut state, key(KeyCode::Char('k')));
        }
        assert_eq!(state.scroll.table, 0);
        assert_eq!(group().cursor, 0);
    }
}
