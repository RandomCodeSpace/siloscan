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
///
/// It stays at 1.2 in the 1.4.0 release, which is a deliberate decision and not
/// an oversight. What that release changed, and why each is additive:
///
/// - `warnings` is a new top-level array, appended. A reader that does not know
///   it parses the rest of the report byte for byte as before.
/// - `min_severity` is a new top-level string, appended, and present only on a
///   run that filtered. An unfiltered report does not carry it at all, so the
///   usual document is unchanged and a reader that does not know the field
///   parses a filtered one as before.
/// - `ignored` was appended on the same terms one release earlier.
/// - `skipped` gained entries for symbolic links the scan did not read through.
///   The list gains members, not a meaning: it is documented as every path the
///   scan did not read the way its rules asked for, and a link to a file outside
///   the scan root is exactly that. A consumer could already meet a `skipped`
///   entry it had never seen - one more unreadable file does it - so nothing
///   that parsed a 1.2 report correctly breaks on one of these.
/// - `skipped[].reason` gained new wordings. The field's type is `string` and
///   has never been an enumeration; the schema promises a human-readable reason
///   and no particular set of them. Code matching on the exact text was reading
///   something the contract never offered.
///
/// The minor moves when a consumer that reads an existing field can be wrong
/// about what it now means, which is what happened at 1.1 -> 1.2. Nothing here
/// changes the meaning of a field that already existed, so nothing moves.
pub const SCHEMA_VERSION: &str = "1.2";

/// What `matched` says for a finding whose rule asked for its match text to be
/// withheld.
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
    /// How much of the tree an ignore file kept out of the scan, as
    /// `{"files": N, "directories": N}`.
    ///
    /// The machine-readable half of the same statement the human listing makes:
    /// a report with no findings and a non-zero count here is not a clean tree,
    /// it is a tree the scan did not fully look at. A gate reading this report
    /// can tell the two apart; without it, it cannot.
    ///
    /// Counted honestly and coarsely. An excluded directory counts as one, and
    /// its contents are not walked and so are counted nowhere - `directories:
    /// 1` may stand for a single empty folder or for a `node_modules` with
    /// forty thousand files under it. It answers "was anything held back", not
    /// "how much".
    ///
    /// Appended to the object, so this is an additive change: schema 1.2
    /// readers that do not know the field parse a 1.2 report exactly as before.
    pub ignored: crate::walk::Ignored,
    /// What the scan narrowed and why, in the scanner's own words - see
    /// [`crate::scan::ScanReport::warnings`].
    ///
    /// Here for the same reason `ignored` is. A coverage gate that landed on
    /// none of the files a subdirectory scan walked produces no findings and no
    /// failure, and without this a job reading the JSON sees an empty report and
    /// calls the tree clean. The human listing already says it on stderr; a
    /// machine consumer could not see it at all.
    ///
    /// Empty on a scan that narrowed nothing, which is the usual case. Appended,
    /// so it is additive on the same terms as `ignored`.
    pub warnings: &'a [String],
    /// The `--min-severity` threshold the three finding lists were filtered at,
    /// absent when the run reported everything it found.
    ///
    /// Here for the third time the same reason applies: a filtered report and a
    /// clean one are the same document, and a consumer reading the filtered one
    /// cannot tell that findings were withheld. The scan is unchanged - the
    /// threshold decides what is printed and never what is found, so the exit
    /// code, every surviving fingerprint and the metrics are what they would
    /// have been without it.
    ///
    /// Absent rather than `"info"` on an unfiltered run, so a report that
    /// withheld nothing is byte for byte the report this release wrote before
    /// the field existed. Appended, on the same additive terms as `warnings`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
}

/// Render the machine-readable report. `anchor` is the path convention the
/// scan ran under and is recorded verbatim: it does not rewrite any path, it
/// tells the consumer what the paths already mean.
///
/// `rules` is read for one purpose: deciding which findings came from a rule
/// that withholds its match text - every secret rule, plus any regex rule that
/// set `redact: true` - whose `matched` is then redacted in all three finding
/// arrays. Every other payload - a plain regex rule, ast, the duplication
/// channel's synthetic text, a coverage or duplication gate's density string -
/// serializes verbatim, because none of it is a credential and consumers parse
/// some of it.
///
/// `min_severity` is the threshold the caller already filtered the report at,
/// or `None` when it filtered nothing. It is recorded, not applied: this
/// function drops no finding.
pub fn to_json(
    report: &crate::scan::ScanReport,
    rules: &RuleSet,
    anchor: Anchor,
    min_severity: Option<Severity>,
) -> String {
    let redacted_rules = redacted_rule_ids(rules);
    let json_report = JsonReport {
        version: env!("CARGO_PKG_VERSION"),
        findings: report_findings(&report.findings, &redacted_rules),
        baselined: report_findings(&report.baselined, &redacted_rules),
        suppressed: report_findings(&report.suppressed, &redacted_rules),
        skipped: &report.skipped,
        schema_version: SCHEMA_VERSION,
        metrics: &report.metrics,
        anchor,
        ignored: report.ignored,
        warnings: &report.warnings,
        min_severity,
    };
    serde_json::to_string_pretty(&json_report).unwrap() // serialization cannot fail
}

/// Whether `rule_id` names a rule whose findings must not show their match
/// text.
///
/// Two rules qualify, and only two:
///
/// - a secret payload, always. Its `matched` is the credential itself, and no
///   rule author gets to opt out of that.
/// - a regex payload that asked, by setting `redact: true` on the rule. A regex
///   rule is the escape hatch for a credential format the secret rules do not
///   know, and one written for that purpose was printing the credential into
///   JSON, SARIF and the terminal while the built-in rules beside it withheld
///   theirs. The switch is opt-in because the default cannot change: most regex
///   rules match code, not credentials, and their match text is the whole point
///   of the finding - and for some of them (the duplication channel's block
///   key) it is a value consumers parse.
///
/// This is the single definition of what gets redacted. Every sink that could
/// put match text in front of someone - this report, the TUI's panes - asks
/// here rather than deciding for itself, so none of them can drift from the
/// others. Callers redacting a whole report should build the id set once
/// instead of asking per finding.
pub fn redacts_match(rules: &RuleSet, rule_id: &str) -> bool {
    rules
        .rules
        .iter()
        .any(|rule| rule.id == rule_id && payload_redacts(&rule.payload))
}

/// Whether a payload withholds its match text. One place, so the report and
/// the per-finding question above cannot answer differently.
fn payload_redacts(payload: &CompiledPayload) -> bool {
    match payload {
        CompiledPayload::Secret { .. } => true,
        CompiledPayload::Regex { redact, .. } => *redact,
        _ => false,
    }
}

/// Ids of every rule that withholds its match text. A finding is matched to its
/// rule by id, which is the only link a `Finding` keeps.
fn redacted_rule_ids(rules: &RuleSet) -> HashSet<&str> {
    rules
        .rules
        .iter()
        .filter(|rule| payload_redacts(&rule.payload))
        .map(|rule| rule.id.as_str())
        .collect()
}

fn report_findings<'a>(
    findings: &'a [Finding],
    redacted_rules: &HashSet<&str>,
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
            matched: if redacted_rules.contains(finding.rule_id.as_str()) {
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
    use crate::walk::quantity;

    let mut summary = format!(
        "metrics: {}",
        quantity(metrics.totals.lines, "line", "lines")
    );
    if metrics.files.values().any(|file| file.code_lines.is_some()) {
        summary.push_str(&format!(
            ", {}",
            quantity(metrics.totals.code_lines, "code line", "code lines")
        ));
    }
    summary.push_str(&format!(
        ", {}, {:.1}% duplication",
        quantity(
            metrics.totals.duplicated_lines,
            "duplicated line",
            "duplicated lines"
        ),
        metrics.totals.duplication_density
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

    /// A credential a regex rule catches because no secret rule knows the
    /// format - the case `redact: true` exists for.
    const HOUSE_TOKEN: &str = "ACME-482913";

    /// One secret rule, one plain regex rule and one regex rule that asked to
    /// be redacted, so a single report can carry all three treatments.
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
  - id: house.token
    severity: error
    message: house token
    regex: { pattern: 'ACME-[0-9]{6}', redact: true }
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
            ignored: Default::default(),
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics,
            warnings: Vec::new(),
        }
    }

    /// The rendered report for `findings` under `secret_rules`.
    fn report_of(findings: Vec<Finding>) -> String {
        to_json(
            &report(findings, Metrics::default()),
            &secret_rules(),
            Anchor::ScanRoot,
            None,
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
            column_utf16: 1,
            matched: "test".to_string(),
            fingerprint: "abc123".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot, None);
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
            column_utf16: 10,
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

        let json1 = to_json(&report, &no_rules(), Anchor::ScanRoot, None);
        let json2 = to_json(&report, &no_rules(), Anchor::ScanRoot, None);
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
            column_utf16: 13,
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
            column_utf16: 4,
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

        let json = to_json(&report, &secret_rules(), Anchor::ScanRoot, None);
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
            serde_json::from_str(&to_json(&report, &secret_rules(), Anchor::ScanRoot, None))
                .expect("valid json");

        assert_eq!(parsed["findings"][0]["fingerprint"], GOLDEN);
    }

    /// A finding from the regex rule that asked to be redacted, carrying the
    /// credential the way the engine hands it over.
    fn house_token_finding() -> Finding {
        Finding {
            rule_id: "house.token".to_string(),
            severity: Severity::Error,
            message: "house token".to_string(),
            path: "src/main.rs".to_string(),
            line: 11,
            column: 5,
            column_utf16: 5,
            matched: HOUSE_TOKEN.to_string(),
            fingerprint: fingerprint("house.token", "src/main.rs", HOUSE_TOKEN, 0),
        }
    }

    /// A regex rule is how someone catches a credential format the secret rules
    /// do not know, and that rule was the one printing the credential into the
    /// report while every built-in rule beside it withheld its own. `redact:
    /// true` is how the author asks for the same treatment.
    #[test]
    fn a_regex_rule_that_asked_to_be_redacted_is() {
        let mut report = report(vec![house_token_finding()], Metrics::default());
        report.baselined = vec![house_token_finding()];
        report.suppressed = vec![house_token_finding()];

        let json = to_json(&report, &secret_rules(), Anchor::ScanRoot, None);
        assert!(
            !json.contains(HOUSE_TOKEN),
            "the credential reached the report: {json}"
        );

        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        for array in ["findings", "baselined", "suppressed"] {
            assert_eq!(
                matched_in(&parsed, array),
                vec![("house.token".to_string(), REDACTED_MATCH.to_string())],
                "{array} must be redacted"
            );
        }
    }

    /// Redaction is a display decision, so it must not move the fingerprint any
    /// more for a regex rule than it does for a secret one: a baseline written
    /// before the switch was set still covers the finding after it is.
    #[test]
    fn asking_to_be_redacted_leaves_the_fingerprint_alone() {
        let expected = fingerprint("house.token", "src/main.rs", HOUSE_TOKEN, 0);
        let report = report(vec![house_token_finding()], Metrics::default());

        let parsed: serde_json::Value =
            serde_json::from_str(&to_json(&report, &secret_rules(), Anchor::ScanRoot, None))
                .expect("valid json");

        assert_eq!(parsed["findings"][0]["fingerprint"], expected);
    }

    /// The default has to stay verbatim. Most regex rules match code rather
    /// than credentials, and their match text is what makes the finding worth
    /// reading; a rule that says nothing gets exactly what it got before the
    /// switch existed.
    #[test]
    fn a_regex_rule_that_did_not_ask_keeps_its_match_text() {
        let parsed: serde_json::Value =
            serde_json::from_str(&report_of(vec![regex_finding()])).expect("valid json");

        assert_eq!(
            matched_in(&parsed, "findings"),
            vec![("style.needle".to_string(), "needle".to_string())]
        );
    }

    /// The per-finding question the TUI asks and the id set the report builds
    /// are two readings of one rule, and a sink that disagrees with the report
    /// is a sink that leaks. Both go through `payload_redacts`; this pins the
    /// answers.
    #[test]
    fn the_per_finding_question_agrees_with_the_report() {
        let rules = secret_rules();
        assert!(redacts_match(&rules, "secret.aws-key"));
        assert!(redacts_match(&rules, "house.token"));
        assert!(!redacts_match(&rules, "style.needle"));
        assert!(
            !redacts_match(&rules, "absent.rule"),
            "a rule the set does not carry keeps its text, which is what a \
             report loaded against unrelated rules needs"
        );
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
            column_utf16: 1,
            matched: "20 duplicated lines (block 0123456789ab)".to_string(),
            fingerprint: "ff".to_string(),
        };
        let report = report(vec![regex_finding(), duplicate], Metrics::default());

        let parsed: serde_json::Value =
            serde_json::from_str(&to_json(&report, &secret_rules(), Anchor::ScanRoot, None))
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

        let json = to_json(&report, &rules, Anchor::ScanRoot, None);
        let sarif = crate::output_sarif::to_sarif(&report, &rules, Anchor::ScanRoot, None);

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
        let json = to_json(&report, &secret_rules(), Anchor::ScanRoot, None);

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

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot, None);
        assert!(
            json.contains("\"schema_version\": \"1.2\""),
            "report must carry the schema version: {json}"
        );
        assert_eq!(SCHEMA_VERSION, "1.2");
    }

    #[test]
    fn json_report_declares_the_path_anchor() {
        let report = report(vec![], Metrics::default());

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot, None);
        assert!(
            json.contains("\"anchor\": \"scan-root\""),
            "report must declare the path anchor: {json}"
        );

        let json = to_json(&report, &no_rules(), Anchor::Config, None);
        assert!(
            json.contains("\"anchor\": \"config\""),
            "config-anchored report must say so: {json}"
        );
    }

    #[test]
    fn default_anchor_is_scan_root() {
        let report = report(vec![], Metrics::default());

        let json = to_json(&report, &no_rules(), Anchor::default(), None);
        assert!(
            json.contains("\"anchor\": \"scan-root\""),
            "the absent anchor key must mean scan-root: {json}"
        );
    }

    #[test]
    fn json_report_carries_metrics_in_stable_key_order() {
        let report = report(vec![], metrics_fixture());

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot, None);
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

    /// Every count in the line agrees with its noun. "1 lines" is the kind of
    /// thing that makes a reader wonder what else the tool is not checking, and
    /// all three terms are separate format calls, so all three are asserted.
    #[test]
    fn human_summary_counts_of_one_read_as_one() {
        let mut metrics = Metrics::default();
        metrics.files.insert(
            "a.rs".to_string(),
            FileMetrics {
                lines: 1,
                code_lines: Some(1),
                duplicated_lines: 1,
            },
        );
        metrics.totals.lines = 1;
        metrics.totals.code_lines = 1;
        metrics.totals.duplicated_lines = 1;
        metrics.totals.duplication_density = 100.0;

        assert_eq!(
            human_metrics_summary(&metrics),
            "metrics: 1 line, 1 code line, 1 duplicated line, 100.0% duplication"
        );
    }

    /// A coverage gate that measured nothing says so in `warnings`, and a job
    /// reading the JSON has to be able to see that. Without the field the report
    /// is an empty finding list, which is indistinguishable from a clean tree -
    /// the exact confusion `warnings` exists to prevent, reintroduced for every
    /// machine consumer.
    #[test]
    fn json_report_carries_the_scan_warnings() {
        let mut report = report(vec![], Metrics::default());
        report.warnings = vec!["coverage report names no scanned file".to_string()];

        let json = to_json(&report, &no_rules(), Anchor::ScanRoot, None);
        assert!(
            json.contains("\"warnings\": [\n    \"coverage report names no scanned file\"\n  ]"),
            "warnings must reach the JSON report: {json}"
        );
    }

    /// The usual case, and the one that must not grow noise: a scan that
    /// narrowed nothing emits an empty array rather than a null or a message.
    #[test]
    fn json_report_warnings_are_empty_when_nothing_was_narrowed() {
        let json = to_json(
            &report(vec![], Metrics::default()),
            &no_rules(),
            Anchor::ScanRoot,
            None,
        );
        assert!(json.contains("\"warnings\": []"), "{json}");
    }

    /// The same argument `warnings` and `ignored` make, for the third source of
    /// an empty finding list: a filtered report has to say it was filtered, or a
    /// consumer reads "no findings at or above error" as "no findings".
    ///
    /// Present only when a threshold was applied. A run that reported everything
    /// has nothing to declare, and its document must not grow a key that says
    /// so.
    #[test]
    fn json_report_records_the_threshold_it_was_filtered_at() {
        let report = report(vec![], Metrics::default());

        let filtered = to_json(
            &report,
            &no_rules(),
            Anchor::ScanRoot,
            Some(Severity::Warning),
        );
        assert!(
            filtered.contains("\"min_severity\": \"warning\""),
            "a filtered report must name its threshold: {filtered}"
        );

        let unfiltered = to_json(&report, &no_rules(), Anchor::ScanRoot, None);
        assert!(
            !unfiltered.contains("min_severity"),
            "an unfiltered report must not carry the key: {unfiltered}"
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
