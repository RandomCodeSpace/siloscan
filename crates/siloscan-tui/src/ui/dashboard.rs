use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::widgets::{BarChart, Gauge, List, ListItem};

use crate::state::AppState;

pub fn draw(frame: &mut Frame, area: Rect, state: &AppState) {
    let width = area.width as usize;

    if width < 30 {
        return;
    }

    if width < 80 {
        draw_2x2(frame, area, state);
    } else {
        draw_4col(frame, area, state);
    }
}

fn draw_2x2(frame: &mut Frame, area: Rect, state: &AppState) {
    let [top, bottom] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .areas(area);

    let [left, right] = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .areas(top);

    let [left_bottom, right_bottom] = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .areas(bottom);

    draw_severity_chart(frame, left, state);
    draw_top_rules_chart(frame, right, state);
    draw_directory_list(frame, left_bottom, state);
    draw_debt_gauge(frame, right_bottom, state);
}

fn draw_4col(frame: &mut Frame, area: Rect, state: &AppState) {
    let [sev, rules, dir, debt] = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .areas(area);

    draw_severity_chart(frame, sev, state);
    draw_top_rules_chart(frame, rules, state);
    draw_directory_list(frame, dir, state);
    draw_debt_gauge(frame, debt, state);
}

fn draw_severity_chart(frame: &mut Frame, area: Rect, state: &AppState) {
    let counts = state.counts_by_severity();
    let data: Vec<(&str, u64)> = counts
        .iter()
        .map(|(severity, count)| {
            let label = match severity {
                siloscan_core::rules::Severity::Error => "err",
                siloscan_core::rules::Severity::Warning => "warn",
                siloscan_core::rules::Severity::Info => "info",
            };
            (label, *count as u64)
        })
        .collect();

    let chart = BarChart::default()
        .block(ratatui::widgets::Block::bordered().title("Severity"))
        .data(&data)
        .bar_width(if area.width > 20 { 3 } else { 1 });

    frame.render_widget(chart, area);
}

fn draw_top_rules_chart(frame: &mut Frame, area: Rect, state: &AppState) {
    let top = state.top_rules(5);
    let data: Vec<(&str, u64)> = top
        .iter()
        .map(|(rule, count)| (rule.as_str(), *count as u64))
        .collect();

    let max = if data.is_empty() { 1 } else { data[0].1 };

    let chart = BarChart::default()
        .block(ratatui::widgets::Block::bordered().title("Top Rules"))
        .data(&data)
        .bar_width(if area.width > 20 { 3 } else { 1 })
        .max(max);

    frame.render_widget(chart, area);
}

fn draw_directory_list(frame: &mut Frame, area: Rect, state: &AppState) {
    let dirs = state.counts_by_dir();
    let items: Vec<ListItem> = dirs
        .iter()
        .take(8)
        .map(|(dir, count)| ListItem::new(format!("{}: {}", dir, count)))
        .collect();

    let list = List::new(items).block(ratatui::widgets::Block::bordered().title("Directories"));
    frame.render_widget(list, area);
}

fn draw_debt_gauge(frame: &mut Frame, area: Rect, state: &AppState) {
    let (new, baselined, suppressed) = state.debt_counts();
    let total = new + baselined + suppressed;

    let ratio = if total == 0 {
        0.0
    } else {
        (total - new) as f64 / total as f64
    };

    let label = format!("{} / {} / {}", new, baselined, suppressed);
    let gauge = Gauge::default()
        .block(ratatui::widgets::Block::bordered().title("Debt"))
        .ratio(ratio)
        .label(label);

    frame.render_widget(gauge, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use siloscan_core::findings::Finding;
    use siloscan_core::rules::Severity;
    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::state::{FindingRow, Status};

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

    #[test]
    fn dashboard_renders_80x24() {
        let mut state = AppState::new(
            PathBuf::from("."),
            Arc::new(siloscan_core::rules::RuleSet { rules: Vec::new() }),
            None,
        );

        for i in 0..20 {
            let severity = match i % 3 {
                0 => Severity::Error,
                1 => Severity::Warning,
                _ => Severity::Info,
            };
            let rule = format!("rule.{}", i % 5);
            let path = format!("src/file_{}.rs", i);
            state
                .rows
                .push(row(&rule, severity, &path, i as u64, Status::New));
        }

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                draw(frame, frame.area(), &state);
            })
            .unwrap();
    }

    #[test]
    fn dashboard_renders_200x50() {
        let mut state = AppState::new(
            PathBuf::from("."),
            Arc::new(siloscan_core::rules::RuleSet { rules: Vec::new() }),
            None,
        );

        for i in 0..20 {
            let severity = match i % 3 {
                0 => Severity::Error,
                1 => Severity::Warning,
                _ => Severity::Info,
            };
            let rule = format!("rule.{}", i % 5);
            let path = format!("src/deep/file_{}.rs", i);
            state
                .rows
                .push(row(&rule, severity, &path, i as u64, Status::New));
        }

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(200, 50)).unwrap();
        terminal
            .draw(|frame| {
                draw(frame, frame.area(), &state);
            })
            .unwrap();
    }

    #[test]
    fn dashboard_does_not_render_when_too_narrow() {
        let state = AppState::new(
            PathBuf::from("."),
            Arc::new(siloscan_core::rules::RuleSet { rules: Vec::new() }),
            None,
        );

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(20, 24)).unwrap();
        terminal
            .draw(|frame| {
                draw(frame, frame.area(), &state);
            })
            .unwrap();
    }
}
