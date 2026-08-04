use std::collections::HashSet;

use serde::Serialize;

use crate::config::Anchor;
use crate::findings::Finding;
use crate::rules::{CompiledPayload, RuleSet, Severity};

/// Version of the machine-readable JSON report contract.
///
/// Single source of truth: every consumer (CLI, TUI, downstream tooling)
/// reads this constant instead of hardcoding the string. The contract is
/// additive-only within a major version: fields are appended, never renamed,
/// moved or removed.
///
/// 1.2 is what redaction cost: `findings[].matched` stopped carrying the match
/// text for secret-rule findings, and a consumer that reads that field cannot
/// tell 1.2 from the 1.1 that preceded it without the minor bump. No field was
/// added, renamed or dropped, so a 1.1 reader still parses a 1.2 report.
pub const SCHEMA_VERSION: &str = "1.2";

/// What `matched` says for a finding a secret rule produced.
///
/// The credential itself never reaches the report. Every other sink already
/// refuses to carry it - the cache stores a length, the baseline stores a
/// fingerprint, SARIF and the human listing emit no match text at all - and
/// this constant is how the JSON report says the same thing in a field the
/// schema cannot drop.
pub const REDACTED_MATCH: &str = "<redacted>";

/// Serialized shape of one finding: `Finding` field for field, in the same
/// order, differing only in that `matched` may carry [`REDACTED_MATCH`] instead
/// of the text that matched.
///
/// `fingerprint` is unaffected. It is computed at match time over the real
/// text, so it keeps identifying the real occurrence - baselines, suppressions
/// and SARIF `partialFingerprints` written before this redaction existed still
/// match.
#[derive(Debug, Serialize)]
pub struct ReportFinding<'a> {
    pub rule_id: &'a str,
    pub severity: Severity,
    pub message: &'a str,
    pub path: &'a str,
    pub line: u64,
    pub column: u64,
    pub matched: &'a str,
    pub fingerprint: &'a str,
}

#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub version: &'a str,
    pub findings: Vec<ReportFinding<'a>>,
    pub baselined: Vec<ReportFinding<'a>>,
    pub suppressed: Vec<ReportFinding<'a>>,
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
///
/// `rules` is read for one purpose: deciding which findings came from a secret
/// rule, whose `matched` is then redacted in all three finding arrays. Every
/// other payload - regex, ast, the duplication channel's synthetic text, a
/// coverage or duplication gate's density string - serializes verbatim, because
/// none of it is a credential and consumers parse some of it.
pub fn to_json(report: &crate::scan::ScanReport, rules: &RuleSet, anchor: Anchor) -> String {
    let secret_rules = secret_rule_ids(rules);
    let json_report = JsonReport {
        version: env!("CARGO_PKG_VERSION"),
        findings: report_findings(&report.findings, &secret_rules),
        baselined: report_findings(&report.baselined, &secret_rules),
        suppressed: report_findings(&report.suppressed, &secret_rules),
        skipped: &report.skipped,
        schema_version: SCHEMA_VERSION,
        metrics: &report.metrics,
        anchor,
    };
    serde_json::to_string_pretty(&json_report).unwrap() // serialization cannot fail
}

/// Whether `rule_id` names a rule with a secret payload, and so whether that
/// rule's findings carry a credential in `matched`.
///
/// This is the single definition of what gets redacted. Every sink that could
/// put match text in front of someone - this report, the TUI's panes - asks
/// here rather than deciding for itself, so none of them can drift from the
/// others. Callers redacting a whole report should build the id set once
/// instead of asking per finding.
pub fn is_secret_rule(rules: &RuleSet, rule_id: &str) -> bool {
    rules
        .rules
        .iter()
        .any(|rule| rule.id == rule_id && matches!(rule.payload, CompiledPayload::Secret { .. }))
}

/// Ids of every rule carrying a secret payload. A finding is matched to its
/// rule by id, which is the only link a `Finding` keeps.
fn secret_rule_ids(rules: &RuleSet) -> HashSet<&str> {
    rules
        .rules
        .iter()
        .filter(|rule| matches!(rule.payload, CompiledPayload::Secret { .. }))
        .map(|rule| rule.id.as_str())
        .collect()
}

fn report_findings<'a>(
    findings: &'a [Finding],
    secret_rules: &HashSet<&str>,
) -> Vec<ReportFinding<'a>> {
    findings
        .iter()
        .map(|finding| ReportFinding {
            rule_id: &finding.rule_id,
            severity: finding.severity,
            message: &finding.message,
            path: &finding.path,
            line: finding.line,
            column: finding.column,
            matched: if secret_rules.contains(finding.rule_id.as_str()) {
                REDACTED_MATCH
            } else {
                &finding.matched
            },
            fingerprint: &finding.fingerprint,
        })
        .collect()
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
    use crate::findings::{Finding, fingerprint};
    use crate::metrics::{FileMetrics, Metrics};
    use crate::rules::{RuleSet, Severity, load_str};
    use crate::scan::{ScanReport, SkippedFile};

    /// A rule set with no rules at all: enough for every test that does not
    /// care which payload produced a finding, since redaction is keyed on the
    /// rules a report was scanned with.
    fn no_rules() -> RuleSet {
        RuleSet::default()
    }

    /// A real credential, planted so a test can assert it never reaches the
    /// report. Matches `secret_rules`' pattern.
    const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

    /// One secret rule and one regex rule, so a single report can carry both a
    /// redacted and an untouched finding.
    fn secret_rules() -> RuleSet {
        let src = r#"
version: 1
rules:
  - id: secret.aws-key
    severity: error
    message: aws access key
    secret: { pattern: 'AKIA[0-9A-Z]{16}' }
  - id: style.needle
    severity: warning
    message: needle found
    regex: { pattern: 'needle' }
"#;
        RuleSet {
            rules: load_str(src, "test").expect("should load"),
            sources: vec![("test".to_string(), src.to_string())],
        }
    }

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

    /// The rendered report for `findings` under `secret_rules`.
    fn report_of(findings: Vec<Finding>) -> String {
        to_json(
            &report(findings, Metrics::default()),
            &secret_rules(),
            Anchor::ScanRoot,
        )
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

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot);
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

        let json1 = to_json(&report, &no_rules(), Anchor::ScanRoot);
        let json2 = to_json(&report, &no_rules(), Anchor::ScanRoot);
        assert_eq!(json1, json2);
    }

    /// A secret-rule finding carrying the real credential, as the engine builds
    /// it: `matched` is the raw text and `fingerprint` is taken over that raw
    /// text.
    fn secret_finding() -> Finding {
        Finding {
            rule_id: "secret.aws-key".to_string(),
            severity: Severity::Error,
            message: "aws access key".to_string(),
            path: "src/main.rs".to_string(),
            line: 7,
            column: 13,
            matched: SECRET.to_string(),
            fingerprint: fingerprint("secret.aws-key", "src/main.rs", SECRET, 0),
        }
    }

    fn regex_finding() -> Finding {
        Finding {
            rule_id: "style.needle".to_string(),
            severity: Severity::Warning,
            message: "needle found".to_string(),
            path: "src/main.rs".to_string(),
            line: 2,
            column: 4,
            matched: "needle".to_string(),
            fingerprint: fingerprint("style.needle", "src/main.rs", "needle", 0),
        }
    }

    /// Pull one array's entries out of the report, as `(rule_id, matched)`.
    fn matched_in(json: &serde_json::Value, array: &str) -> Vec<(String, String)> {
        json[array]
            .as_array()
            .unwrap_or_else(|| panic!("{array} must be an array"))
            .iter()
            .map(|f| {
                (
                    f["rule_id"].as_str().expect("rule_id").to_string(),
                    f["matched"].as_str().expect("matched").to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn a_secret_finding_never_serializes_its_credential() {
        let mut report = report(vec![secret_finding()], Metrics::default());
        report.baselined = vec![secret_finding()];
        report.suppressed = vec![secret_finding()];

        let json = to_json(&report, &secret_rules(), Anchor::ScanRoot);
        assert!(
            !json.contains(SECRET),
            "credential reached the report: {json}"
        );

        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        for array in ["findings", "baselined", "suppressed"] {
            assert_eq!(
                matched_in(&parsed, array),
                vec![("secret.aws-key".to_string(), REDACTED_MATCH.to_string())],
                "{array} must be redacted"
            );
        }
    }

    #[test]
    fn redaction_leaves_the_fingerprint_alone() {
        // Golden: the fingerprint of this finding as the engine computed it,
        // over the raw match text, before redaction existed. Redaction must not
        // move it - baselines and suppressions written against it still match.
        const GOLDEN: &str = "67622c356a1e434a95735e1d7a1a5f8a65c78386506d1e25e5beafbf1560d6a8";
        assert_eq!(
            fingerprint("secret.aws-key", "src/main.rs", SECRET, 0),
            GOLDEN
        );

        let report = report(vec![secret_finding()], Metrics::default());
        let parsed: serde_json::Value =
            serde_json::from_str(&to_json(&report, &secret_rules(), Anchor::ScanRoot))
                .expect("valid json");

        assert_eq!(parsed["findings"][0]["fingerprint"], GOLDEN);
    }

    #[test]
    fn only_secret_payloads_are_redacted() {
        // A duplication finding: synthetic text no rule in the set declares,
        // which consumers parse for the block key.
        let duplicate = Finding {
            rule_id: crate::metrics::DUPLICATE_BLOCK_RULE_ID.to_string(),
            severity: Severity::Info,
            message: "duplicated block".to_string(),
            path: "src/main.rs".to_string(),
            line: 1,
            column: 1,
            matched: "20 duplicated lines (block 0123456789ab)".to_string(),
            fingerprint: "ff".to_string(),
        };
        let report = report(vec![regex_finding(), duplicate], Metrics::default());

        let parsed: serde_json::Value =
            serde_json::from_str(&to_json(&report, &secret_rules(), Anchor::ScanRoot))
                .expect("valid json");

        assert_eq!(
            matched_in(&parsed, "findings"),
            vec![
                ("style.needle".to_string(), "needle".to_string()),
                (
                    crate::metrics::DUPLICATE_BLOCK_RULE_ID.to_string(),
                    "20 duplicated lines (block 0123456789ab)".to_string()
                ),
            ]
        );
    }

    #[test]
    fn json_and_sarif_agree_on_what_a_secret_finding_says() {
        let report = report(vec![secret_finding()], Metrics::default());
        let rules = secret_rules();

        let json = to_json(&report, &rules, Anchor::ScanRoot);
        let sarif = crate::output_sarif::to_sarif(&report, &rules, Anchor::ScanRoot);

        // Neither transport carries the credential. SARIF has no match-text
        // field at all, which is the representation JSON mirrors as closely as
        // a field it cannot drop allows.
        assert!(!json.contains(SECRET), "json leaked: {json}");
        assert!(!sarif.contains(SECRET), "sarif leaked: {sarif}");
        assert!(
            !sarif.contains("matched"),
            "sarif has no match text: {sarif}"
        );
        assert!(json.contains(REDACTED_MATCH));

        // Both still identify the same occurrence.
        let json: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let sarif: serde_json::Value = serde_json::from_str(&sarif).expect("valid sarif");
        assert_eq!(
            json["findings"][0]["fingerprint"],
            sarif["runs"][0]["results"][0]["partialFingerprints"]["siloscanFingerprint/v1"]
        );
    }

    #[test]
    fn redaction_does_not_disturb_the_serialized_shape() {
        // Field set and order are the schema's contract; only the value of
        // `matched` may differ between a redacted and an untouched finding.
        let report = report(vec![secret_finding()], Metrics::default());
        let json = to_json(&report, &secret_rules(), Anchor::ScanRoot);

        // Serde `Value` sorts object keys, so the order is checked on the text.
        let mut at = 0;
        for key in [
            "rule_id",
            "severity",
            "message",
            "path",
            "line",
            "column",
            "matched",
            "fingerprint",
        ] {
            let found = json[at..]
                .find(&format!("\"{key}\""))
                .unwrap_or_else(|| panic!("{key} missing or out of order: {json}"));
            at += found + 1;
        }

        // A redacted finding serializes exactly the keys an untouched one does:
        // nothing added, nothing dropped.
        let untouched = report_of(vec![regex_finding()]);
        assert_eq!(
            json.matches("\"matched\"").count(),
            untouched.matches("\"matched\"").count()
        );
    }

    #[test]
    fn json_report_declares_schema_version() {
        let report = report(vec![], Metrics::default());

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot);
        assert!(
            json.contains("\"schema_version\": \"1.2\""),
            "report must carry the schema version: {json}"
        );
        assert_eq!(SCHEMA_VERSION, "1.2");
    }

    #[test]
    fn json_report_declares_the_path_anchor() {
        let report = report(vec![], Metrics::default());

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot);
        assert!(
            json.contains("\"anchor\": \"scan-root\""),
            "report must declare the path anchor: {json}"
        );

        let json = to_json(&report, &no_rules(), Anchor::Config);
        assert!(
            json.contains("\"anchor\": \"config\""),
            "config-anchored report must say so: {json}"
        );
    }

    #[test]
    fn default_anchor_is_scan_root() {
        let report = report(vec![], Metrics::default());

        let json = to_json(&report, &no_rules(), Anchor::default());
        assert!(
            json.contains("\"anchor\": \"scan-root\""),
            "the absent anchor key must mean scan-root: {json}"
        );
    }

    #[test]
    fn json_report_carries_metrics_in_stable_key_order() {
        let report = report(vec![], metrics_fixture());

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot);
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
