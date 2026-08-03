use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub version: &'a str,
    pub findings: &'a [crate::findings::Finding],
    pub baselined: &'a [crate::findings::Finding],
    pub suppressed: &'a [crate::findings::Finding],
    pub skipped: &'a [crate::scan::SkippedFile],
}

pub fn to_json(report: &crate::scan::ScanReport) -> String {
    let json_report = JsonReport {
        version: env!("CARGO_PKG_VERSION"),
        findings: &report.findings,
        baselined: &report.baselined,
        suppressed: &report.suppressed,
        skipped: &report.skipped,
    };
    serde_json::to_string_pretty(&json_report).unwrap() // serialization cannot fail
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Finding;
    use crate::rules::Severity;
    use crate::scan::{ScanReport, SkippedFile};

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
        let report = ScanReport {
            findings: vec![finding],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
        };

        let json = to_json(&report);
        assert!(json.contains("findings"));
        assert!(json.contains("baselined"));
        assert!(json.contains("suppressed"));
        assert!(json.contains("0.1.0"));
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
        let report = ScanReport {
            findings: vec![finding.clone()],
            baselined: vec![finding.clone()],
            suppressed: vec![finding],
            skipped: vec![skipped],
            graph: Default::default(),
        };

        let json1 = to_json(&report);
        let json2 = to_json(&report);
        assert_eq!(json1, json2);
    }
}
