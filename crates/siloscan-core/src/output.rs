use serde::Serialize;

use crate::config::Anchor;

/// Version of the machine-readable JSON report contract.
///
/// Single source of truth: every consumer (CLI, TUI, downstream tooling)
/// reads this constant instead of hardcoding the string. The contract is
/// additive-only within a major version: fields are appended, never renamed,
/// moved or removed.
pub const SCHEMA_VERSION: &str = "1.1";

#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub version: &'a str,
    pub findings: &'a [crate::findings::Finding],
    pub baselined: &'a [crate::findings::Finding],
    pub suppressed: &'a [crate::findings::Finding],
    pub skipped: &'a [crate::scan::SkippedFile],
    pub schema_version: &'static str,
    pub metrics: &'a crate::metrics::Metrics,
    /// Convention every path in this report is expressed in: `"scan-root"`
    /// (the default) or `"config"`. One convention holds for the whole
    /// report, so a consumer resolves finding paths, skipped-file paths and
    /// metrics file keys the same way.
    pub anchor: Anchor,
}

/// Render the machine-readable report. `anchor` is the path convention the
/// scan ran under and is recorded verbatim: it does not rewrite any path, it
/// tells the consumer what the paths already mean.
pub fn to_json(report: &crate::scan::ScanReport, anchor: Anchor) -> String {
    let json_report = JsonReport {
        version: env!("CARGO_PKG_VERSION"),
        findings: &report.findings,
        baselined: &report.baselined,
        suppressed: &report.suppressed,
        skipped: &report.skipped,
        schema_version: SCHEMA_VERSION,
        metrics: &report.metrics,
        anchor,
    };
    serde_json::to_string_pretty(&json_report).unwrap() // serialization cannot fail
}

/// One-line metrics summary for human output, printed after the findings
/// listing. The code-lines term is omitted when no scanned file reported a
/// code-line count (that is, no tier-1 language file was scanned).
pub fn human_metrics_summary(metrics: &crate::metrics::Metrics) -> String {
    let mut summary = format!("metrics: {} lines", metrics.totals.lines);
    if metrics.files.values().any(|file| file.code_lines.is_some()) {
        summary.push_str(&format!(", {} code lines", metrics.totals.code_lines));
    }
    summary.push_str(&format!(
        ", {} duplicated lines, {:.1}% duplication",
        metrics.totals.duplicated_lines, metrics.totals.duplication_density
    ));
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Finding;
    use crate::metrics::{FileMetrics, Metrics};
    use crate::rules::Severity;
    use crate::scan::{ScanReport, SkippedFile};

    /// Single construction point for the report, so a new `ScanReport` field
    /// is one edit rather than one per test.
    fn report(findings: Vec<Finding>, metrics: Metrics) -> ScanReport {
        ScanReport {
            findings,
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics,
        }
    }

    fn metrics_fixture() -> Metrics {
        let mut metrics = Metrics::default();
        metrics.files.insert(
            "src/zebra.rs".to_string(),
            FileMetrics {
                lines: 40,
                code_lines: Some(30),
                duplicated_lines: 10,
            },
        );
        metrics.files.insert(
            "src/alpha.txt".to_string(),
            FileMetrics {
                lines: 60,
                code_lines: None,
                duplicated_lines: 0,
            },
        );
        metrics.totals.lines = 100;
        metrics.totals.code_lines = 30;
        metrics.totals.duplicated_lines = 10;
        metrics.totals.duplication_density = 10.0;
        metrics
    }

    #[test]
    fn json_report_contains_findings_and_version() {
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warning,
            message: "test message".to_string(),
            path: "src/main.rs".to_string(),
            line: 1,
            column: 1,
            matched: "test".to_string(),
            fingerprint: "abc123".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let json = to_json(&report, Anchor::ScanRoot);
        assert!(json.contains("findings"));
        assert!(json.contains("baselined"));
        assert!(json.contains("suppressed"));
        assert!(json.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn json_output_is_identical_across_serializations() {
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Info,
            message: "test message".to_string(),
            path: "src/main.rs".to_string(),
            line: 5,
            column: 10,
            matched: "match".to_string(),
            fingerprint: "def456".to_string(),
        };
        let skipped = SkippedFile {
            path: "ignored/file.rs".to_string(),
            reason: "excluded by rule".to_string(),
        };
        let mut report = report(vec![finding.clone()], metrics_fixture());
        report.baselined = vec![finding.clone()];
        report.suppressed = vec![finding];
        report.skipped = vec![skipped];

        let json1 = to_json(&report, Anchor::ScanRoot);
        let json2 = to_json(&report, Anchor::ScanRoot);
        assert_eq!(json1, json2);
    }

    #[test]
    fn json_report_declares_schema_version() {
        let report = report(vec![], Metrics::default());

        let json = to_json(&report, Anchor::ScanRoot);
        assert!(
            json.contains("\"schema_version\": \"1.1\""),
            "report must carry the schema version: {json}"
        );
        assert_eq!(SCHEMA_VERSION, "1.1");
    }

    #[test]
    fn json_report_declares_the_path_anchor() {
        let report = report(vec![], Metrics::default());

        let json = to_json(&report, Anchor::ScanRoot);
        assert!(
            json.contains("\"anchor\": \"scan-root\""),
            "report must declare the path anchor: {json}"
        );

        let json = to_json(&report, Anchor::Config);
        assert!(
            json.contains("\"anchor\": \"config\""),
            "config-anchored report must say so: {json}"
        );
    }

    #[test]
    fn default_anchor_is_scan_root() {
        let report = report(vec![], Metrics::default());

        let json = to_json(&report, Anchor::default());
        assert!(
            json.contains("\"anchor\": \"scan-root\""),
            "the absent anchor key must mean scan-root: {json}"
        );
    }

    #[test]
    fn json_report_carries_metrics_in_stable_key_order() {
        let report = report(vec![], metrics_fixture());

        let json = to_json(&report, Anchor::ScanRoot);
        assert!(json.contains("\"metrics\""));
        assert!(json.contains("\"totals\""));

        // File keys are emitted in BTreeMap order, not insertion order.
        let alpha = json.find("src/alpha.txt").expect("alpha file present");
        let zebra = json.find("src/zebra.rs").expect("zebra file present");
        assert!(alpha < zebra, "file keys must be sorted: {json}");

        // A file without a code-line count omits the key entirely.
        let alpha_entry = &json[alpha..zebra];
        assert!(
            !alpha_entry.contains("code_lines"),
            "absent code_lines must not serialize: {alpha_entry}"
        );
        let zebra_entry = &json[zebra..];
        assert!(
            zebra_entry.contains("\"code_lines\": 30"),
            "present code_lines must serialize: {zebra_entry}"
        );
    }

    #[test]
    fn human_summary_includes_code_lines_when_any_file_has_them() {
        let summary = human_metrics_summary(&metrics_fixture());
        assert_eq!(
            summary,
            "metrics: 100 lines, 30 code lines, 10 duplicated lines, 10.0% duplication"
        );
    }

    #[test]
    fn human_summary_omits_code_lines_when_no_file_has_them() {
        let mut metrics = Metrics::default();
        metrics.files.insert(
            "notes.txt".to_string(),
            FileMetrics {
                lines: 8,
                code_lines: None,
                duplicated_lines: 0,
            },
        );
        metrics.totals.lines = 8;
        metrics.totals.code_lines = 0;
        metrics.totals.duplicated_lines = 0;
        metrics.totals.duplication_density = 0.0;

        let summary = human_metrics_summary(&metrics);
        assert_eq!(
            summary,
            "metrics: 8 lines, 0 duplicated lines, 0.0% duplication"
        );
    }

    #[test]
    fn human_summary_rounds_density_to_one_decimal() {
        let mut metrics = Metrics::default();
        metrics.totals.lines = 300;
        metrics.totals.duplicated_lines = 40;
        metrics.totals.duplication_density = 13.3333;

        let summary = human_metrics_summary(&metrics);
        assert_eq!(
            summary,
            "metrics: 300 lines, 40 duplicated lines, 13.3% duplication"
        );
    }
}
