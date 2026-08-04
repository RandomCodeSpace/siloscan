//! Shared colors, spans and block helpers.
//!
//! Every screen pulls its styling from here so the palette stays consistent and
//! is changed in one place. Nothing in this module reads or writes application
//! state: it is pure presentation.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, BorderType};

use siloscan_core::rules::Severity;

/// Errors, failing findings, debt that still has to be paid.
pub const ERROR: Color = Color::Red;
/// Warnings and anything that narrows what the user is looking at.
pub const WARNING: Color = Color::Yellow;
/// Informational findings.
pub const INFO: Color = Color::Cyan;
/// Interactive chrome: focused borders, selected tabs, key letters, mini-bars.
pub const ACCENT: Color = Color::LightBlue;
/// Secondary text that should stay legible without competing for attention.
pub const DIM: Color = Color::DarkGray;
/// Background of the selected row in a list or table.
pub const SELECTED_BG: Color = Color::Rgb(40, 44, 60);
/// A passing quality gate, a clean rating, anything the user does not have to
/// act on.
pub const OK: Color = Color::Green;
/// Softer error shade, for the first rung of a graded scale.
pub const ERROR_SOFT: Color = Color::LightRed;

/// Color a severity is drawn in, wherever it appears.
pub fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Error => ERROR,
        Severity::Warning => WARNING,
        Severity::Info => INFO,
    }
}

/// Short severity name in its color, padded to a fixed width so columns of
/// them line up.
pub fn severity_span(severity: Severity) -> Span<'static> {
    let name = match severity {
        Severity::Error => "err ",
        Severity::Warning => "warn",
        Severity::Info => "info",
    };
    Span::styled(name, Style::default().fg(severity_color(severity)))
}

/// Full severity name in its color, for labels that have room to spell it out.
pub fn severity_name_span(severity: Severity) -> Span<'static> {
    Span::styled(
        severity.as_str(),
        Style::default().fg(severity_color(severity)),
    )
}

/// Border of a pane. Focused panes get an accent border and a bold title;
/// everything else recedes.
pub fn pane_block(title: &str, focused: bool) -> Block<'_> {
    let (border, title_style) = if focused {
        (
            Style::default().fg(ACCENT),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )
    } else {
        (Style::default().fg(DIM), Style::default().fg(DIM))
    };

    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(border)
        .title(Span::styled(title, title_style))
}

/// Border of a tile whose color carries meaning: the metric of a KPI card, the
/// verdict of the quality gate.
pub fn colored_block(title: &str, color: Color) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            title,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
}

/// Rows in one block glyph. Callers with fewer than `GLYPH_ROWS + 2` rows to
/// spend should print the plain number instead.
pub const GLYPH_ROWS: usize = 3;
/// Cell width of one block glyph, gaps excluded.
pub const GLYPH_WIDTH: usize = 4;

const SEG_TOP: u8 = 1 << 0;
const SEG_TOP_RIGHT: u8 = 1 << 1;
const SEG_BOTTOM_RIGHT: u8 = 1 << 2;
const SEG_BOTTOM: u8 = 1 << 3;
const SEG_BOTTOM_LEFT: u8 = 1 << 4;
const SEG_TOP_LEFT: u8 = 1 << 5;
const SEG_MIDDLE: u8 = 1 << 6;

/// Seven-segment mask of a symbol. Unknown symbols render blank.
fn segments(symbol: char) -> u8 {
    match symbol.to_ascii_uppercase() {
        '0' => {
            SEG_TOP | SEG_TOP_RIGHT | SEG_BOTTOM_RIGHT | SEG_BOTTOM | SEG_BOTTOM_LEFT | SEG_TOP_LEFT
        }
        '1' => SEG_TOP_RIGHT | SEG_BOTTOM_RIGHT,
        '2' => SEG_TOP | SEG_TOP_RIGHT | SEG_MIDDLE | SEG_BOTTOM_LEFT | SEG_BOTTOM,
        '3' => SEG_TOP | SEG_TOP_RIGHT | SEG_MIDDLE | SEG_BOTTOM_RIGHT | SEG_BOTTOM,
        '4' => SEG_TOP_LEFT | SEG_MIDDLE | SEG_TOP_RIGHT | SEG_BOTTOM_RIGHT,
        '5' => SEG_TOP | SEG_TOP_LEFT | SEG_MIDDLE | SEG_BOTTOM_RIGHT | SEG_BOTTOM,
        '6' => {
            SEG_TOP | SEG_TOP_LEFT | SEG_MIDDLE | SEG_BOTTOM_LEFT | SEG_BOTTOM_RIGHT | SEG_BOTTOM
        }
        '7' => SEG_TOP | SEG_TOP_RIGHT | SEG_BOTTOM_RIGHT,
        '8' => {
            SEG_TOP
                | SEG_TOP_RIGHT
                | SEG_BOTTOM_RIGHT
                | SEG_BOTTOM
                | SEG_BOTTOM_LEFT
                | SEG_TOP_LEFT
                | SEG_MIDDLE
        }
        '9' => SEG_TOP | SEG_TOP_RIGHT | SEG_BOTTOM_RIGHT | SEG_BOTTOM | SEG_TOP_LEFT | SEG_MIDDLE,
        'A' => {
            SEG_TOP | SEG_TOP_RIGHT | SEG_BOTTOM_RIGHT | SEG_BOTTOM_LEFT | SEG_TOP_LEFT | SEG_MIDDLE
        }
        'B' => SEG_TOP_LEFT | SEG_BOTTOM_LEFT | SEG_MIDDLE | SEG_BOTTOM_RIGHT | SEG_BOTTOM,
        'C' => SEG_TOP | SEG_TOP_LEFT | SEG_BOTTOM_LEFT | SEG_BOTTOM,
        'D' => SEG_TOP_RIGHT | SEG_BOTTOM_RIGHT | SEG_BOTTOM | SEG_BOTTOM_LEFT | SEG_MIDDLE,
        'E' => SEG_TOP | SEG_TOP_LEFT | SEG_MIDDLE | SEG_BOTTOM_LEFT | SEG_BOTTOM,
        _ => 0,
    }
}

/// A cell from its two half-height inks.
fn cell(upper: bool, lower: bool) -> char {
    match (upper, lower) {
        (true, true) => '\u{2588}',
        (true, false) => '\u{2580}',
        (false, true) => '\u{2584}',
        (false, false) => ' ',
    }
}

/// One symbol as `GLYPH_ROWS` strings of `GLYPH_WIDTH` cells. Each row holds
/// two half-height ink rows, which is what lets a seven-segment shape fit in
/// three terminal rows: bars land on half cells, stems on full ones.
fn glyph(symbol: char) -> [String; GLYPH_ROWS] {
    let mask = segments(symbol);
    let on = |segment: u8| mask & segment != 0;

    let top = [
        cell(on(SEG_TOP), on(SEG_TOP_LEFT)),
        cell(on(SEG_TOP), false),
        cell(on(SEG_TOP), false),
        cell(on(SEG_TOP), on(SEG_TOP_RIGHT)),
    ];
    let middle = [
        cell(on(SEG_TOP_LEFT), on(SEG_MIDDLE) || on(SEG_BOTTOM_LEFT)),
        cell(false, on(SEG_MIDDLE)),
        cell(false, on(SEG_MIDDLE)),
        cell(on(SEG_TOP_RIGHT), on(SEG_MIDDLE) || on(SEG_BOTTOM_RIGHT)),
    ];
    let bottom = [
        cell(on(SEG_BOTTOM_LEFT), on(SEG_BOTTOM)),
        cell(false, on(SEG_BOTTOM)),
        cell(false, on(SEG_BOTTOM)),
        cell(on(SEG_BOTTOM_RIGHT), on(SEG_BOTTOM)),
    ];

    [
        top.iter().collect(),
        middle.iter().collect(),
        bottom.iter().collect(),
    ]
}

/// A number as three rows of block glyphs, for the KPI cards. Digits are
/// separated by a blank column; every row comes back the same width. A caller
/// with fewer than five rows of card, or too few columns for
/// `big_width(digits)`, prints the plain number instead.
pub fn big_digits(n: usize) -> Vec<String> {
    big_text(&n.to_string())
}

/// The same rendering for short labels: the single-letter quality rating.
pub fn big_text(text: &str) -> Vec<String> {
    let mut rows = vec![String::new(); GLYPH_ROWS];
    for (index, symbol) in text.chars().enumerate() {
        let glyph = glyph(symbol);
        for (row, cells) in rows.iter_mut().zip(glyph.iter()) {
            if index > 0 {
                row.push(' ');
            }
            row.push_str(cells);
        }
    }
    rows
}

/// Columns `big_text` needs for a string of `symbols` characters.
pub fn big_width(symbols: usize) -> usize {
    match symbols {
        0 => 0,
        n => n * GLYPH_WIDTH + (n - 1),
    }
}

/// Dimmed text: hints, units, anything secondary.
pub fn dim() -> Style {
    Style::default().fg(DIM)
}

/// Accented text: key letters, counts the user is meant to act on.
pub fn accent() -> Style {
    Style::default().fg(ACCENT)
}

/// Style of the selected row in a list or table.
pub fn selected() -> Style {
    Style::default()
        .bg(SELECTED_BG)
        .add_modifier(Modifier::BOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_colors_are_distinct() {
        let colors = [
            severity_color(Severity::Error),
            severity_color(Severity::Warning),
            severity_color(Severity::Info),
        ];
        assert_eq!(colors, [ERROR, WARNING, INFO]);
    }

    #[test]
    fn severity_spans_are_fixed_width_and_colored() {
        for severity in [Severity::Error, Severity::Warning, Severity::Info] {
            let span = severity_span(severity);
            assert_eq!(span.content.chars().count(), 4, "{severity}");
            assert_eq!(span.style.fg, Some(severity_color(severity)));
        }
    }

    #[test]
    fn big_digits_are_three_rows_of_equal_width() {
        for (number, symbols) in [(0usize, 1), (7, 1), (42, 2), (1234, 4)] {
            let rows = big_digits(number);
            assert_eq!(rows.len(), GLYPH_ROWS, "{number}");
            for row in &rows {
                assert_eq!(row.chars().count(), big_width(symbols), "{number}: {row}");
            }
        }
    }

    #[test]
    fn every_digit_has_a_distinct_glyph() {
        let mut seen: Vec<Vec<String>> = Vec::new();
        for digit in 0..10 {
            let rows = big_digits(digit);
            assert!(!seen.contains(&rows), "{digit} repeats an earlier glyph");
            assert!(
                rows.iter().any(|row| row.contains('\u{2588}')),
                "{digit} rendered blank"
            );
            seen.push(rows);
        }
    }

    #[test]
    fn ratings_render_as_letters() {
        for letter in ['A', 'B', 'C', 'D', 'E'] {
            let rows = big_text(&letter.to_string());
            assert_eq!(rows.len(), GLYPH_ROWS);
            assert!(rows.iter().any(|row| row.trim() != ""), "{letter} blank");
        }
        assert!(big_text("").iter().all(String::is_empty));
    }

    #[test]
    fn focus_changes_the_pane_border_style() {
        assert_ne!(
            format!("{:?}", pane_block("Pane", true)),
            format!("{:?}", pane_block("Pane", false))
        );
    }
}
