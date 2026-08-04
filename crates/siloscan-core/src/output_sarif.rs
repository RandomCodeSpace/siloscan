use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::config::Anchor;
use crate::findings::Finding;
use crate::metrics::DUPLICATE_BLOCK_RULE_ID;
use crate::rules::{RuleSet, Severity};
use crate::scan::ScanReport;
use crate::walk::Ignored;

#[derive(Debug, Serialize)]
pub struct SarifRoot {
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub version: &'static str,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    /// Present only on a run that has something to notify about, which today
    /// means a run that produced scan warnings. Absent otherwise, so a document
    /// this release would have written without the array is byte for byte the
    /// document it writes now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
    pub results: Vec<SarifResult>,
    pub properties: SarifRunProperties,
}

/// One `invocation` object (SARIF 2.1.0 section 3.20). `executionSuccessful` is
/// the only required property; it is true because a scan that failed never
/// reaches a report at all.
///
/// This exists to carry [`ScanReport::warnings`]. Those already reach stderr and
/// the JSON report, and SARIF is the format a CI gate actually ingests, so
/// without them the one consumer that decides whether a build proceeds is the
/// one consumer that cannot see that the scan narrowed what it looked at.
///
/// `toolExecutionNotifications` is the spec's own place for "a condition
/// encountered while the tool ran", as opposed to a result about the scanned
/// code, so the warnings go there rather than into the property bag beside
/// `siloscan/skipped`. A run-level property would have been a private extension
/// that only siloscan's own readers understand; this is a field every conformant
/// consumer already knows how to render.
#[derive(Debug, Serialize)]
pub struct SarifInvocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    #[serde(rename = "toolExecutionNotifications")]
    pub tool_execution_notifications: Vec<SarifNotification>,
}

/// One `notification` object (SARIF 2.1.0 section 3.58). `message` is the only
/// required property; `level` is stated rather than left to its default so a
/// consumer does not have to know what the default is.
///
/// The level is always `warning`. These are conditions the scan chose to
/// continue past - a coverage report that landed on none of the scanned files,
/// say - and `error` is reserved for a run whose results cannot be trusted,
/// which some consumers treat as a failed upload.
#[derive(Debug, Serialize)]
pub struct SarifNotification {
    pub level: &'static str,
    pub message: SarifMessage,
}

/// Run-level property bag. Carries the scan-wide metric totals only:
/// per-file metrics stay out of SARIF, which is a findings transport. The
/// anchor rides along because artifact URIs are relative and mean nothing
/// without the convention they were written in.
///
/// The skipped list rides along for a different reason: a file the scan never
/// read produces no results, which is indistinguishable in SARIF from a file
/// that was read and came back clean. A parse cap or an unreadable file would
/// otherwise be reported as a pass. It is omitted when nothing was skipped, so
/// a clean run's document is unchanged.
///
/// The ignore counts ride along for the same reason and are omitted the same
/// way. A file an in-root `.gitignore` kept out of the walk produces no result
/// and no skipped entry either, so without them a SARIF consumer - which is
/// what a CI gate actually reads - cannot tell a clean tree from a tree the
/// scan did not fully look at.
///
/// The list is capped at [`MAX_SARIF_SKIPPED`] entries. An asset-heavy
/// repository skips one file per binary - 50k of them is several megabytes of
/// SARIF, past what code-scanning ingests - and the point of the record is to
/// say that files went unread, which a bounded sample plus a count says just as
/// well. The kept entries are the first `MAX_SARIF_SKIPPED` of
/// `ScanReport::skipped`, which the scanner already sorted by path, so the
/// sample is the same on every run of the same tree.
#[derive(Debug, Serialize)]
pub struct SarifRunProperties {
    #[serde(rename = "siloscan/metrics")]
    pub metrics: serde_json::Value,
    #[serde(rename = "siloscan/anchor")]
    pub anchor: Anchor,
    #[serde(rename = "siloscan/skipped", skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<crate::scan::SkippedFile>,
    /// Entries the cap dropped, absent when it dropped none. Present so a
    /// consumer can tell a 200-file sample from a 200-file scan.
    #[serde(
        rename = "siloscan/skippedTruncated",
        skip_serializing_if = "Option::is_none"
    )]
    pub skipped_truncated: Option<usize>,
    /// How much of the tree an ignore file kept out of the walk, absent when it
    /// kept out nothing. Counts rather than paths: an excluded directory is one
    /// count and its contents were never enumerated, which is what the walk
    /// deliberately does not pay for.
    #[serde(rename = "siloscan/ignored", skip_serializing_if = "nothing_ignored")]
    pub ignored: Ignored,
    /// The `--min-severity` threshold the results were filtered at, absent when
    /// the run reported everything it found.
    ///
    /// Same reason as the two above: a filtered document and a clean one are
    /// otherwise the same document, and the consumer deciding whether a build
    /// proceeds cannot tell that results were withheld. Nothing about the scan
    /// changed - the threshold decides what is printed, never what is found, so
    /// the exit code and every surviving `partialFingerprints` entry are what
    /// they would have been without it.
    #[serde(
        rename = "siloscan/minSeverity",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_severity: Option<Severity>,
}

/// Whether an [`Ignored`] has nothing to report, in the shape
/// `skip_serializing_if` asks for.
fn nothing_ignored(ignored: &Ignored) -> bool {
    ignored.is_empty()
}

/// Skipped entries SARIF carries in full before it starts counting instead.
pub const MAX_SARIF_SKIPPED: usize = 100;

#[derive(Debug, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize)]
pub struct SarifDriver {
    pub name: &'static str,
    pub version: &'static str,
    #[serde(rename = "informationUri")]
    pub information_uri: &'static str,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
pub struct SarifRule {
    pub id: String,
    /// Optional human-facing rule name. Only the synthesized descriptors carry
    /// one: a rule pack id is already the name a user reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifShortDescription,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifDefaultConfiguration,
}

#[derive(Debug, Serialize)]
pub struct SarifShortDescription {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct SarifDefaultConfiguration {
    pub level: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: &'static str,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

/// A relative URI reference built from the finding path by
/// [`encode_uri_reference`]. No base id is declared, so a consumer resolves it
/// against its own checkout root; which directory that has to be is what
/// `siloscan/anchor` states.
#[derive(Debug, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

/// `startColumn` is measured in UTF-16 code units, not bytes: see
/// [`sarif_column`].
#[derive(Debug, Serialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u64,
    #[serde(rename = "startColumn")]
    pub start_column: u64,
}

/// Percent-encode a repo-relative finding path into the URI reference SARIF
/// requires of `artifactLocation.uri`.
///
/// A finding path is a filesystem path, not a URI: it may hold a space, a `#`,
/// a `?` or any non-ASCII byte a filesystem accepts. Emitted raw, those produce
/// a document that is not conformant and that consumers mis-read rather than
/// reject - GitHub code scanning truncates the path at the first `#`, so a
/// finding in `docs/notes #2/a.rs` is attributed to `docs/notes ` and lands on
/// the wrong file, or on none.
///
/// Each `/`-separated segment is encoded on its own and the separators are
/// re-emitted verbatim, because a `/` inside a segment is not a thing a path
/// can carry: splitting first is what keeps the path structure intact while the
/// bytes within a segment are escaped. Within a segment only the RFC 3986
/// unreserved set (ALPHA / DIGIT / `-` / `.` / `_` / `~`) survives; every other
/// byte of the UTF-8 encoding becomes an uppercase percent triplet, per RFC 3986
/// section 2.1. That is stricter than `pchar` allows - `:` and the sub-delims
/// are legal in a segment - and deliberately so: encoding `:` is what stops a
/// first segment such as `c:file.rs` from parsing as a scheme, which is the one
/// way a relative reference can turn into something else entirely.
///
/// The result decodes back to the original path byte for byte, so a consumer
/// that resolves the reference recovers exactly what was scanned.
fn encode_uri_reference(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            encoded.push('/');
        }
        for &byte in segment.as_bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    encoded.push(byte as char)
                }
                _ => {
                    let _ = write!(encoded, "%{byte:02X}");
                }
            }
        }
    }
    encoded
}

/// The finding's column expressed the way SARIF reads it.
///
/// A finding carries a 1-based byte offset within its line, which is what the
/// JSON report has always published and keeps publishing. SARIF counts columns
/// in UTF-16 code units, so any line with non-ASCII text before the match -
/// a CJK identifier, an accented string literal - reports a column several
/// units too large and the consumer highlights the wrong span, or a span past
/// the end of the line. The producing engine measures both, and this is where
/// the SARIF measure is used.
///
/// A column of zero addresses nothing and is not a legal `startColumn`, so it
/// is raised to 1 rather than emitted: a region that points at the start of the
/// line is wrong by a few units, while a document a consumer rejects loses the
/// whole run.
fn sarif_column(finding: &Finding) -> u64 {
    finding.column_utf16.max(1)
}

/// Render the SARIF report. Every path in it is a finding path copied without
/// translation, so the whole document inherits whatever convention the scan
/// ran under; `anchor` is recorded at run level to name that convention. Result
/// URIs are that same path percent-encoded ([`encode_uri_reference`]), which is
/// a change of spelling and not of meaning.
///
/// `min_severity` is the threshold the caller already filtered the report at, or
/// `None` when it filtered nothing. It is recorded, not applied: this function
/// drops no result.
pub fn to_sarif(
    report: &ScanReport,
    rules: &RuleSet,
    anchor: Anchor,
    min_severity: Option<Severity>,
) -> String {
    // Collect unique rule ids from report.findings
    let mut rule_ids_in_findings: std::collections::HashSet<&str> =
        std::collections::HashSet::new();
    for finding in &report.findings {
        rule_ids_in_findings.insert(&finding.rule_id);
    }

    // Build a map of rule_id -> descriptor, sorted by id
    let mut rule_map: BTreeMap<&str, SarifRule> = BTreeMap::new();
    for rule in &rules.rules {
        if rule_ids_in_findings.contains(rule.id.as_str()) {
            rule_map.insert(
                &rule.id,
                SarifRule {
                    id: rule.id.clone(),
                    name: None,
                    short_description: SarifShortDescription {
                        text: rule.message.clone(),
                    },
                    default_configuration: SarifDefaultConfiguration {
                        level: severity_to_level(rule.severity),
                    },
                },
            );
        }
    }
    // The metrics channel owns this id and no rule file declares it, so its
    // descriptor is synthesized here rather than looked up.
    if rule_ids_in_findings.contains(DUPLICATE_BLOCK_RULE_ID) {
        rule_map.insert(DUPLICATE_BLOCK_RULE_ID, duplicate_block_rule());
    }

    // Create sorted rules list
    let sarif_rules: Vec<SarifRule> = rule_map.into_values().collect();

    // Create results from findings, mapped to SARIF level
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|finding| {
            let mut fingerprints = BTreeMap::new();
            fingerprints.insert(
                "siloscanFingerprint/v1".to_string(),
                finding.fingerprint.clone(),
            );

            SarifResult {
                rule_id: finding.rule_id.clone(),
                level: severity_to_level(finding.severity),
                message: SarifMessage {
                    text: finding.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: encode_uri_reference(&finding.path),
                        },
                        region: SarifRegion {
                            start_line: finding.line,
                            start_column: sarif_column(finding),
                        },
                    },
                }],
                partial_fingerprints: fingerprints,
            }
        })
        .collect();

    let root = SarifRoot {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "siloscan",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/RandomCodeSpace/siloscan",
                    rules: sarif_rules,
                },
            },
            invocations: match report.warnings.is_empty() {
                true => None,
                false => Some(vec![SarifInvocation {
                    execution_successful: true,
                    tool_execution_notifications: report
                        .warnings
                        .iter()
                        .map(|warning| SarifNotification {
                            level: "warning",
                            message: SarifMessage {
                                text: warning.clone(),
                            },
                        })
                        .collect(),
                }]),
            },
            results,
            properties: SarifRunProperties {
                // Totals only, never the per-file map.
                metrics: serde_json::to_value(&report.metrics.totals).unwrap(), // serialization cannot fail
                anchor,
                skipped: report
                    .skipped
                    .iter()
                    .take(MAX_SARIF_SKIPPED)
                    .cloned()
                    .collect(),
                skipped_truncated: match report.skipped.len() > MAX_SARIF_SKIPPED {
                    true => Some(report.skipped.len() - MAX_SARIF_SKIPPED),
                    false => None,
                },
                ignored: report.ignored,
                min_severity,
            },
        }],
    };

    serde_json::to_string_pretty(&root).unwrap() // serialization cannot fail
}

/// Descriptor for the reserved duplicate-block id, which every duplicate-block
/// finding references and which no rule set defines.
fn duplicate_block_rule() -> SarifRule {
    SarifRule {
        id: DUPLICATE_BLOCK_RULE_ID.to_string(),
        name: Some("DuplicateBlock".to_string()),
        short_description: SarifShortDescription {
            text: "Duplicated code block detected by the metrics channel.".to_string(),
        },
        default_configuration: SarifDefaultConfiguration { level: "note" },
    }
}

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Finding;
    use crate::metrics::Metrics;
    use crate::rules::load_str;
    use crate::scan::ScanReport;

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

    fn no_rules() -> RuleSet {
        RuleSet {
            rules: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn level_mapping_is_correct() {
        assert_eq!(severity_to_level(Severity::Error), "error");
        assert_eq!(severity_to_level(Severity::Warning), "warning");
        assert_eq!(severity_to_level(Severity::Info), "note");
    }

    #[test]
    fn to_sarif_includes_schema_version() {
        let report = report(vec![], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        assert!(sarif.contains("https://json.schemastore.org/sarif-2.1.0.json"));
        assert!(sarif.contains("\"version\": \"2.1.0\""));
    }

    #[test]
    fn to_sarif_includes_tool_metadata() {
        let report = report(vec![], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        assert!(sarif.contains("\"name\": \"siloscan\""));
        assert!(sarif.contains("https://github.com/RandomCodeSpace/siloscan"));
    }

    #[test]
    fn to_sarif_includes_findings() {
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warning,
            message: "test message".to_string(),
            path: "src/main.rs".to_string(),
            line: 5,
            column: 10,
            column_utf16: 10,
            matched: "test".to_string(),
            fingerprint: "abc123def456".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        assert!(sarif.contains("test.rule"));
        assert!(sarif.contains("test message"));
        assert!(sarif.contains("src/main.rs"));
        assert!(sarif.contains("\"startLine\": 5"));
        assert!(sarif.contains("\"startColumn\": 10"));
        assert!(sarif.contains("abc123def456"));
    }

    #[test]
    fn run_properties_carry_metric_totals_and_the_anchor() {
        let mut metrics = Metrics::default();
        metrics.files.insert(
            "src/main.rs".to_string(),
            crate::metrics::FileMetrics {
                lines: 100,
                code_lines: Some(80),
                duplicated_lines: 12,
            },
        );
        metrics.totals.lines = 100;
        metrics.totals.code_lines = 80;
        metrics.totals.duplicated_lines = 12;
        metrics.totals.duplication_density = 12.0;

        let report = report(vec![], metrics);

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let properties = &parsed["runs"][0]["properties"];
        assert_eq!(
            properties
                .as_object()
                .expect("properties is an object")
                .len(),
            2,
            "run properties must hold the metrics and anchor keys only"
        );
        assert_eq!(
            properties["siloscan/anchor"],
            serde_json::json!("scan-root")
        );

        let totals = &properties["siloscan/metrics"];
        let totals = totals.as_object().expect("metrics is an object");
        assert_eq!(totals.len(), 4, "totals must hold exactly four keys");
        assert_eq!(totals["lines"], serde_json::json!(100));
        assert_eq!(totals["code_lines"], serde_json::json!(80));
        assert_eq!(totals["duplicated_lines"], serde_json::json!(12));
        assert_eq!(totals["duplication_density"], serde_json::json!(12.0));

        assert!(
            !sarif.contains("src/main.rs"),
            "per-file metrics must not reach SARIF: {sarif}"
        );
    }

    #[test]
    fn skipped_files_are_reported_at_run_level() {
        use crate::scan::SkippedFile;

        let mut report = report(vec![], Metrics::default());
        report.skipped = vec![
            SkippedFile {
                path: "vendor/huge.ts".to_string(),
                reason: "exceeds max_parse_bytes".to_string(),
            },
            SkippedFile {
                path: "blob.bin".to_string(),
                reason: "binary".to_string(),
            },
        ];

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let properties = &parsed["runs"][0]["properties"];

        // A gated file produces no result, so without this the document reads
        // exactly like a clean scan.
        assert!(
            parsed["runs"][0]["results"]
                .as_array()
                .expect("results is an array")
                .is_empty()
        );
        assert_eq!(
            properties["siloscan/skipped"],
            serde_json::json!([
                { "path": "vendor/huge.ts", "reason": "exceeds max_parse_bytes" },
                { "path": "blob.bin", "reason": "binary" },
            ]),
            "skipped must carry path and reason in report order: {sarif}"
        );
        assert!(
            properties.get("siloscan/skippedTruncated").is_none(),
            "an untruncated list must not announce a remainder: {sarif}"
        );
    }

    /// An asset-heavy repository can skip tens of thousands of files. The
    /// record stays, bounded: a fixed sample plus the count of what it stands
    /// for. The sample is the head of a list the scanner sorted by path, so two
    /// runs of the same tree produce the same document.
    #[test]
    fn a_large_skipped_list_is_capped_and_the_remainder_counted() {
        use crate::scan::SkippedFile;

        let mut report = report(vec![], Metrics::default());
        report.skipped = (0..MAX_SARIF_SKIPPED + 37)
            .map(|index| SkippedFile {
                path: format!("assets/{index:05}.png"),
                reason: "binary".to_string(),
            })
            .collect();
        report.skipped.sort_by(|a, b| a.path.cmp(&b.path));

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let properties = &parsed["runs"][0]["properties"];

        let kept = properties["siloscan/skipped"]
            .as_array()
            .expect("skipped is an array");
        assert_eq!(kept.len(), MAX_SARIF_SKIPPED);
        assert_eq!(
            properties["siloscan/skippedTruncated"],
            serde_json::json!(37)
        );
        // The cap keeps the head of the sorted list, so the sample is stable.
        assert_eq!(kept[0]["path"], "assets/00000.png");
        assert_eq!(
            kept[MAX_SARIF_SKIPPED - 1]["path"],
            format!("assets/{:05}.png", MAX_SARIF_SKIPPED - 1)
        );
        assert_eq!(
            to_sarif(&report, &no_rules(), Anchor::ScanRoot, None),
            sarif
        );
    }

    #[test]
    fn a_scan_that_skipped_nothing_omits_the_key() {
        let report = report(vec![], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let properties = parsed["runs"][0]["properties"]
            .as_object()
            .expect("properties is an object");

        assert!(
            !properties.contains_key("siloscan/skipped"),
            "an empty skipped list must not serialize: {sarif}"
        );
        assert!(
            !properties.contains_key("siloscan/ignored"),
            "a scan that ignored nothing must not announce a count: {sarif}"
        );
        assert!(
            !properties.contains_key("siloscan/minSeverity"),
            "a run that withheld nothing must not announce a threshold: {sarif}"
        );
        assert!(
            parsed["runs"][0]
                .as_object()
                .expect("run is an object")
                .get("invocations")
                .is_none(),
            "a run with no warnings must not carry an invocations array: {sarif}"
        );
    }

    /// A filtered document and a clean one are otherwise the same document, and
    /// SARIF is what decides whether a build proceeds. Recorded, never applied:
    /// the threshold does not drop a result here.
    #[test]
    fn a_filtered_run_records_the_threshold_it_was_filtered_at() {
        let report = report(vec![], Metrics::default());

        let sarif = to_sarif(
            &report,
            &no_rules(),
            Anchor::ScanRoot,
            Some(Severity::Warning),
        );
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        assert_eq!(
            parsed["runs"][0]["properties"]["siloscan/minSeverity"],
            serde_json::json!("warning"),
            "{sarif}"
        );
    }

    /// The warnings reach stderr and the JSON report already. SARIF is the
    /// format CI ingests, so it is the one place their absence actually costs
    /// something: a coverage gate that measured nothing, reported as a pass.
    ///
    /// They go in `invocations[].toolExecutionNotifications` - the spec's place
    /// for a condition met while the tool ran, as against a result about the
    /// scanned code - rather than in a `siloscan/` property only this tool's own
    /// readers would understand.
    #[test]
    fn scan_warnings_are_reported_as_tool_execution_notifications() {
        let mut report = report(vec![], Metrics::default());
        report.warnings = vec![
            "coverage report names no scanned file".to_string(),
            "second warning".to_string(),
        ];

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let invocations = parsed["runs"][0]["invocations"]
            .as_array()
            .expect("invocations is an array");
        assert_eq!(invocations.len(), 1, "{sarif}");
        assert_eq!(
            invocations[0]["executionSuccessful"],
            serde_json::json!(true),
            "a scan that produced a report ran successfully: {sarif}"
        );
        assert_eq!(
            invocations[0]["toolExecutionNotifications"],
            serde_json::json!([
                {
                    "level": "warning",
                    "message": { "text": "coverage report names no scanned file" }
                },
                { "level": "warning", "message": { "text": "second warning" } },
            ]),
            "warnings must arrive in the scanner's order: {sarif}"
        );
    }

    /// SARIF is what a CI gate reads. A file an in-root `.gitignore` kept out
    /// of the walk produces no result and no skipped entry, so without this the
    /// document says "clean" about a tree the scan did not fully look at.
    #[test]
    fn ignored_counts_are_reported_at_run_level() {
        let mut report = report(vec![], Metrics::default());
        report.ignored = Ignored {
            files: 3,
            directories: 1,
        };

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let properties = &parsed["runs"][0]["properties"];

        assert!(
            parsed["runs"][0]["results"]
                .as_array()
                .expect("results is an array")
                .is_empty()
        );
        assert_eq!(
            properties["siloscan/ignored"],
            serde_json::json!({ "files": 3, "directories": 1 }),
            "{sarif}"
        );
        assert_eq!(
            to_sarif(&report, &no_rules(), Anchor::ScanRoot, None),
            sarif
        );
    }

    #[test]
    fn rules_are_deduplicated_and_sorted() {
        let finding1 = Finding {
            rule_id: "z.rule".to_string(),
            severity: Severity::Error,
            message: "error msg".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            column: 1,
            column_utf16: 1,
            matched: "x".to_string(),
            fingerprint: "fp1".to_string(),
        };
        let finding2 = Finding {
            rule_id: "a.rule".to_string(),
            severity: Severity::Info,
            message: "info msg".to_string(),
            path: "b.rs".to_string(),
            line: 2,
            column: 2,
            column_utf16: 2,
            matched: "y".to_string(),
            fingerprint: "fp2".to_string(),
        };
        let finding3 = Finding {
            rule_id: "z.rule".to_string(),
            severity: Severity::Error,
            message: "error msg".to_string(),
            path: "c.rs".to_string(),
            line: 3,
            column: 3,
            column_utf16: 3,
            matched: "z".to_string(),
            fingerprint: "fp3".to_string(),
        };
        let report = report(vec![finding1, finding2, finding3], Metrics::default());
        let rule_text = r#"
version: 1
rules:
  - id: a.rule
    severity: info
    message: "info msg"
    regex: { pattern: "y" }
  - id: z.rule
    severity: error
    message: "error msg"
    regex: { pattern: "x" }
"#;
        let rules = RuleSet {
            rules: load_str(rule_text, "test").expect("rules should load"),
            ..Default::default()
        };

        let sarif = to_sarif(&report, &rules, Anchor::ScanRoot, None);
        // Check that rules appear in sorted order (a.rule before z.rule)
        let a_pos = sarif.find("\"id\": \"a.rule\"").unwrap();
        let z_pos = sarif.find("\"id\": \"z.rule\"").unwrap();
        assert!(a_pos < z_pos, "rules should be sorted by id");

        // Count occurrences of each rule id in the rules array
        let rules_section_start = sarif.find("\"rules\"").unwrap();
        let results_section_start = sarif.find("\"results\"").unwrap();
        let rules_section = &sarif[rules_section_start..results_section_start];

        let z_count = rules_section.matches("\"id\": \"z.rule\"").count();
        assert_eq!(z_count, 1, "z.rule should appear exactly once in rules");
    }

    #[test]
    fn duplicate_block_findings_get_a_synthesized_descriptor() {
        let block = Finding {
            rule_id: DUPLICATE_BLOCK_RULE_ID.to_string(),
            severity: Severity::Info,
            message: "duplicated block, also at src/b.rs:1".to_string(),
            path: "src/a.rs".to_string(),
            line: 1,
            column: 1,
            column_utf16: 1,
            matched: "12 duplicated lines".to_string(),
            fingerprint: "fp1".to_string(),
        };
        let other = Finding {
            rule_id: "z.rule".to_string(),
            severity: Severity::Error,
            message: "error msg".to_string(),
            path: "src/c.rs".to_string(),
            line: 2,
            column: 1,
            column_utf16: 1,
            matched: "x".to_string(),
            fingerprint: "fp2".to_string(),
        };
        let rule_text = r#"
version: 1
rules:
  - id: z.rule
    severity: error
    message: "error msg"
    regex: { pattern: "x" }
"#;
        let rules = RuleSet {
            rules: load_str(rule_text, "test").expect("rules should load"),
            ..Default::default()
        };
        let with_findings = |findings: Vec<Finding>| report(findings, Metrics::default());

        let sarif = to_sarif(
            &with_findings(vec![block, other.clone()]),
            &rules,
            Anchor::ScanRoot,
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let driver_rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("driver rules array");
        assert_eq!(driver_rules.len(), 2);
        // Sorted by id: the reserved id sorts before z.rule.
        assert_eq!(driver_rules[0]["id"], DUPLICATE_BLOCK_RULE_ID);
        assert_eq!(driver_rules[0]["name"], "DuplicateBlock");
        assert_eq!(
            driver_rules[0]["shortDescription"]["text"],
            "Duplicated code block detected by the metrics channel."
        );
        assert_eq!(driver_rules[0]["defaultConfiguration"]["level"], "note");
        assert_eq!(driver_rules[1]["id"], "z.rule");
        assert!(
            driver_rules[1].get("name").is_none(),
            "rule pack descriptors carry no name: {sarif}"
        );

        // Without a block finding the descriptor stays out.
        let sarif = to_sarif(&with_findings(vec![other]), &rules, Anchor::ScanRoot, None);
        assert!(!sarif.contains(DUPLICATE_BLOCK_RULE_ID), "{sarif}");
    }

    #[test]
    fn baselined_and_suppressed_are_excluded() {
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: "src/main.rs".to_string(),
            line: 1,
            column: 1,
            column_utf16: 1,
            matched: "text".to_string(),
            fingerprint: "fp".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        // Verify that we have exactly one result
        let results_count = sarif.matches("\"ruleId\"").count();
        assert_eq!(results_count, 1, "should have exactly one result");
    }

    #[test]
    fn output_is_byte_stable() {
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Info,
            message: "message".to_string(),
            path: "src/main.rs".to_string(),
            line: 5,
            column: 10,
            column_utf16: 10,
            matched: "matched".to_string(),
            fingerprint: "fingerprint".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let sarif1 = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let sarif2 = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        assert_eq!(sarif1, sarif2, "output should be byte-stable");
    }

    #[test]
    fn config_anchored_run_says_so_and_leaves_paths_alone() {
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: "modules/api/src/main.rs".to_string(),
            line: 1,
            column: 1,
            column_utf16: 1,
            matched: "text".to_string(),
            fingerprint: "fp".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::Config, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let run = &parsed["runs"][0];
        assert_eq!(run["properties"]["siloscan/anchor"], "config");
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "modules/api/src/main.rs",
            "the finding path must reach SARIF untranslated: {sarif}"
        );
    }

    #[test]
    fn severity_levels_in_results_and_rules() {
        let finding_error = Finding {
            rule_id: "test.error".to_string(),
            severity: Severity::Error,
            message: "error".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            column: 1,
            column_utf16: 1,
            matched: "x".to_string(),
            fingerprint: "fp1".to_string(),
        };
        let finding_warning = Finding {
            rule_id: "test.warning".to_string(),
            severity: Severity::Warning,
            message: "warning".to_string(),
            path: "b.rs".to_string(),
            line: 2,
            column: 2,
            column_utf16: 2,
            matched: "y".to_string(),
            fingerprint: "fp2".to_string(),
        };
        let finding_info = Finding {
            rule_id: "test.info".to_string(),
            severity: Severity::Info,
            message: "info".to_string(),
            path: "c.rs".to_string(),
            line: 3,
            column: 3,
            column_utf16: 3,
            matched: "z".to_string(),
            fingerprint: "fp3".to_string(),
        };
        let report = report(
            vec![finding_error, finding_warning, finding_info],
            Metrics::default(),
        );
        let rule_text = r#"
version: 1
rules:
  - id: test.error
    severity: error
    message: "error"
    regex: { pattern: "x" }
  - id: test.info
    severity: info
    message: "info"
    regex: { pattern: "z" }
  - id: test.warning
    severity: warning
    message: "warning"
    regex: { pattern: "y" }
"#;
        let rules = RuleSet {
            rules: load_str(rule_text, "test").expect("rules should load"),
            ..Default::default()
        };

        let sarif = to_sarif(&report, &rules, Anchor::ScanRoot, None);
        // Verify error maps to "error"
        assert!(sarif.contains("\"id\": \"test.error\""));
        let error_section = sarif.split("\"id\": \"test.error\"").nth(1).unwrap();
        let next_section = error_section.split("\"id\": \"test.").next().unwrap();
        assert!(
            next_section.contains("\"level\": \"error\""),
            "error severity should map to error level"
        );

        // Verify warning maps to "warning"
        assert!(sarif.contains("\"id\": \"test.warning\""));

        // Verify info maps to "note"
        assert!(sarif.contains("\"id\": \"test.info\""));
        let info_section = sarif.split("\"id\": \"test.info\"").nth(1).unwrap();
        let next_section = info_section.split("\"id\": \"test.").next().unwrap();
        assert!(
            next_section.contains("\"level\": \"note\""),
            "info severity should map to note level"
        );
    }

    /// Reverses [`encode_uri_reference`], so a round-trip test states the
    /// property that matters - the consumer gets the path back - rather than
    /// re-asserting the expected spelling twice.
    fn percent_decode(uri: &str) -> String {
        let bytes = uri.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'%' => {
                    let triplet = &bytes[index + 1..index + 3];
                    let hex = std::str::from_utf8(triplet).expect("triplet digits are ascii");
                    out.push(u8::from_str_radix(hex, 16).expect("triplet digits are hex"));
                    index += 3;
                }
                byte => {
                    out.push(byte);
                    index += 1;
                }
            }
        }
        String::from_utf8(out).expect("a decoded path is utf-8")
    }

    /// Characters a URI reference may carry unescaped here: the unreserved set,
    /// the segment separator, and the percent that introduces a triplet.
    fn is_conformant_uri_char(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | '~' | '/' | '%')
    }

    #[test]
    fn segments_are_percent_encoded_and_separators_are_not() {
        assert_eq!(
            encode_uri_reference("docs/notes #2/\u{6587}\u{4ef6}?.rs"),
            "docs/notes%20%232/%E6%96%87%E4%BB%B6%3F.rs"
        );
        // The unreserved set survives untouched; everything else does not,
        // including the colon that would otherwise read as a scheme.
        assert_eq!(
            encode_uri_reference("aZ0-._~/c:x/a+b/100%"),
            "aZ0-._~/c%3Ax/a%2Bb/100%25"
        );
        assert_eq!(encode_uri_reference(""), "");
    }

    #[test]
    fn a_hostile_path_produces_a_conformant_uri_that_round_trips() {
        let path = "docs/notes #2/\u{6587}\u{4ef6}?.rs";
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: path.to_string(),
            line: 3,
            column: 7,
            column_utf16: 7,
            matched: "text".to_string(),
            fingerprint: "fp".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let uri =
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"]
                .as_str()
                .expect("uri is a string");

        assert_eq!(uri, "docs/notes%20%232/%E6%96%87%E4%BB%B6%3F.rs");
        assert!(
            uri.chars().all(is_conformant_uri_char),
            "uri must carry no character that needs escaping: {uri}"
        );
        // The fragment marker is gone, so nothing truncates at it.
        assert!(!uri.contains('#') && !uri.contains('?') && !uri.contains(' '));
        assert_eq!(percent_decode(uri), path, "the uri must decode to the path");
    }

    /// SARIF counts columns in UTF-16 code units. A line whose match sits behind
    /// a CJK prefix has a byte column several units past the character the
    /// consumer should highlight; the JSON report keeps the byte column, SARIF
    /// does not.
    #[test]
    fn a_column_behind_a_cjk_prefix_is_reported_in_utf16_units() {
        // Line: `let 名前 = "x"` - the match starts after 4 ascii bytes and two
        // three-byte characters, so byte column 11 is UTF-16 column 7.
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: "src/main.rs".to_string(),
            line: 2,
            column: 11,
            column_utf16: 7,
            matched: "x".to_string(),
            fingerprint: "fp".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], serde_json::json!(2));
        assert_eq!(
            region["startColumn"],
            serde_json::json!(7),
            "startColumn must be the utf-16 column, not the byte column: {sarif}"
        );
    }

    /// A column of zero addresses nothing. Emitting it would cost the consumer
    /// the whole run, so it is raised to the start of the line instead.
    #[test]
    fn a_zero_column_is_raised_to_a_legal_one() {
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: "src/main.rs".to_string(),
            line: 1,
            column: 0,
            column_utf16: 0,
            matched: "x".to_string(),
            fingerprint: "fp".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startColumn"],
            serde_json::json!(1)
        );
    }

    /// Regression guard. An ASCII path holds nothing outside the unreserved set
    /// beyond its separators, and an ASCII line measures the same in bytes and
    /// in UTF-16 units, so the document these two fixes produce is the document
    /// 1.2.0 produced.
    #[test]
    fn ascii_paths_and_columns_are_unchanged() {
        for path in [
            "src/main.rs",
            "modules/api/src/lib.rs",
            "a/b-c/d_e/f.test.ts",
            "~unreserved~/x.rs",
        ] {
            assert_eq!(encode_uri_reference(path), path, "{path} must not change");
        }

        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: "modules/api/src/lib.rs".to_string(),
            line: 5,
            column: 10,
            column_utf16: 10,
            matched: "text".to_string(),
            fingerprint: "fp".to_string(),
        };
        let report = report(vec![finding], Metrics::default());

        let sarif = to_sarif(&report, &no_rules(), Anchor::ScanRoot, None);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let location = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(
            location["artifactLocation"]["uri"],
            "modules/api/src/lib.rs"
        );
        assert_eq!(location["region"]["startLine"], serde_json::json!(5));
        assert_eq!(location["region"]["startColumn"], serde_json::json!(10));

        // The claim is about the artifact URIs, which are the only strings
        // percent-encoding is applied to. Asserting it over the whole document
        // asserted it over every message, rule name and property too, and a
        // finding whose matched text happened to contain a `%` would have
        // failed a test that is not about matched text.
        let uris = artifact_uris(&parsed);
        assert_eq!(uris, vec!["modules/api/src/lib.rs"]);
        for uri in uris {
            assert!(
                !uri.contains('%'),
                "an ascii path must escape nothing: {uri}"
            );
        }
    }

    /// Every `artifactLocation.uri` in a document, in document order.
    fn artifact_uris(value: &serde_json::Value) -> Vec<String> {
        let mut uris = Vec::new();
        collect_artifact_uris(value, &mut uris);
        uris
    }

    fn collect_artifact_uris(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if key == "artifactLocation"
                        && let Some(uri) = child.get("uri").and_then(serde_json::Value::as_str)
                    {
                        out.push(uri.to_string());
                    }
                    collect_artifact_uris(child, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_artifact_uris(item, out);
                }
            }
            _ => {}
        }
    }
}
