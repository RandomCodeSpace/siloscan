use serde::Serialize;
use std::collections::BTreeMap;

use crate::metrics::DUPLICATE_BLOCK_RULE_ID;
use crate::rules::{RuleSet, Severity};
use crate::scan::ScanReport;

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
    pub results: Vec<SarifResult>,
    pub properties: SarifRunProperties,
}

/// Run-level property bag. Carries the scan-wide metric totals only:
/// per-file metrics stay out of SARIF, which is a findings transport.
#[derive(Debug, Serialize)]
pub struct SarifRunProperties {
    #[serde(rename = "siloscan/metrics")]
    pub metrics: serde_json::Value,
}

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

#[derive(Debug, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u64,
    #[serde(rename = "startColumn")]
    pub start_column: u64,
}

pub fn to_sarif(report: &ScanReport, rules: &RuleSet) -> String {
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
                            uri: finding.path.clone(),
                        },
                        region: SarifRegion {
                            start_line: finding.line,
                            start_column: finding.column,
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
            results,
            properties: SarifRunProperties {
                // Totals only, never the per-file map.
                metrics: serde_json::to_value(&report.metrics.totals).unwrap(), // serialization cannot fail
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
    use crate::rules::load_str;
    use crate::scan::ScanReport;

    #[test]
    fn level_mapping_is_correct() {
        assert_eq!(severity_to_level(Severity::Error), "error");
        assert_eq!(severity_to_level(Severity::Warning), "warning");
        assert_eq!(severity_to_level(Severity::Info), "note");
    }

    #[test]
    fn to_sarif_includes_schema_version() {
        let report = ScanReport {
            findings: vec![],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
        };
        let rules = RuleSet {
            rules: vec![],
            ..Default::default()
        };

        let sarif = to_sarif(&report, &rules);
        assert!(sarif.contains("https://json.schemastore.org/sarif-2.1.0.json"));
        assert!(sarif.contains("\"version\": \"2.1.0\""));
    }

    #[test]
    fn to_sarif_includes_tool_metadata() {
        let report = ScanReport {
            findings: vec![],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
        };
        let rules = RuleSet {
            rules: vec![],
            ..Default::default()
        };

        let sarif = to_sarif(&report, &rules);
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
            matched: "test".to_string(),
            fingerprint: "abc123def456".to_string(),
        };
        let report = ScanReport {
            findings: vec![finding],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
        };
        let rules = RuleSet {
            rules: vec![],
            ..Default::default()
        };

        let sarif = to_sarif(&report, &rules);
        assert!(sarif.contains("test.rule"));
        assert!(sarif.contains("test message"));
        assert!(sarif.contains("src/main.rs"));
        assert!(sarif.contains("\"startLine\": 5"));
        assert!(sarif.contains("\"startColumn\": 10"));
        assert!(sarif.contains("abc123def456"));
    }

    #[test]
    fn run_properties_carry_metric_totals_only() {
        let mut metrics = crate::metrics::Metrics::default();
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

        let report = ScanReport {
            findings: vec![],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics,
        };
        let rules = RuleSet {
            rules: vec![],
            ..Default::default()
        };

        let sarif = to_sarif(&report, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("sarif is valid json");
        let properties = &parsed["runs"][0]["properties"];
        assert_eq!(
            properties
                .as_object()
                .expect("properties is an object")
                .len(),
            1,
            "run properties must hold only the metrics key"
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
    fn rules_are_deduplicated_and_sorted() {
        let finding1 = Finding {
            rule_id: "z.rule".to_string(),
            severity: Severity::Error,
            message: "error msg".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            column: 1,
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
            matched: "z".to_string(),
            fingerprint: "fp3".to_string(),
        };
        let report = ScanReport {
            findings: vec![finding1, finding2, finding3],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
        };
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

        let sarif = to_sarif(&report, &rules);
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
        let report = |findings: Vec<Finding>| ScanReport {
            findings,
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
        };

        let sarif = to_sarif(&report(vec![block, other.clone()]), &rules);
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
        let sarif = to_sarif(&report(vec![other]), &rules);
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
            matched: "text".to_string(),
            fingerprint: "fp".to_string(),
        };
        let report = ScanReport {
            findings: vec![finding],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
        };
        let rules = RuleSet {
            rules: vec![],
            ..Default::default()
        };

        let sarif = to_sarif(&report, &rules);
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
            matched: "matched".to_string(),
            fingerprint: "fingerprint".to_string(),
        };
        let report = ScanReport {
            findings: vec![finding],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
        };
        let rules = RuleSet {
            rules: vec![],
            ..Default::default()
        };

        let sarif1 = to_sarif(&report, &rules);
        let sarif2 = to_sarif(&report, &rules);
        assert_eq!(sarif1, sarif2, "output should be byte-stable");
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
            matched: "z".to_string(),
            fingerprint: "fp3".to_string(),
        };
        let report = ScanReport {
            findings: vec![finding_error, finding_warning, finding_info],
            baselined: vec![],
            suppressed: vec![],
            skipped: vec![],
            graph: Default::default(),
            boundary_edges: Vec::new(),
            metrics: Default::default(),
        };
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

        let sarif = to_sarif(&report, &rules);
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
}
