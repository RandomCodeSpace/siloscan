//! Loading a scan report from disk instead of running a scan.
//!
//! The JSON report contract is additive-only within a major version: fields are
//! appended, never renamed, moved or removed. This reader is therefore
//! deliberately tolerant - unknown keys, at the top level and inside every
//! nested object, are ignored, and absent optional keys take their defaults.
//! Three things are rejected: input that is not a readable JSON object, a
//! `schema_version` whose major component this build does not understand, and
//! a JSON object that is not a report at all.
//!
//! That last check is what keeps the tolerance from failing open. Every key is
//! optional and every section defaults to empty, so without it any JSON object
//! at all (`{}`, a SARIF log, a `package.json`) would load as an empty report
//! and render a passing gate. A report is recognised by declaring a
//! `schema_version` or, for the 1.0 reports written before that key existed,
//! by carrying a `findings` key.
//!
//! The report carries no timestamp and no scan root, so a snapshot is
//! identified by the file it was read from.
//!
//! Tolerance across minor versions has a consequence the UI has to honour.
//! Reports began redacting a secret rule's `matched` at the source in schema
//! 1.2; a 1.0 or 1.1 report carries the credential itself, in plain text, and
//! the major-1 gate accepts it. Snapshot mode boots with no rule set, so it
//! cannot tell which of those findings came from a secret rule and cannot
//! redact selectively. [`SnapshotData::hides_match_text`] is the answer: below
//! 1.2 no match text is shown at all, and the reason is said out loud rather
//! than left to look like an empty column.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use siloscan_core::config::Anchor;
use siloscan_core::findings::Finding;
use siloscan_core::metrics::Metrics;
use siloscan_core::rules::Severity;
use siloscan_core::serde_json::{self, Map, Value};

/// Report major version this build reads.
pub const SUPPORTED_MAJOR: u32 = 1;

/// Version assumed for a report written before `schema_version` existed.
const ASSUMED_VERSION: &str = "1.0";

/// First schema version whose `matched` fields are redacted by the writer.
/// Everything below it may carry a credential in plain text.
const REDACTING_VERSION: (u32, u32) = (1, 2);

/// What the footer says while match text is being withheld. It names the cause,
/// not just the effect: an empty match column is otherwise indistinguishable
/// from a report that had nothing to show.
pub const HIDDEN_MATCH_NOTE: &str = "pre-1.2 report: match text hidden";

/// A report read from disk, in the shape the UI consumes.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotData {
    /// File name the report was read from, for the read-only banner.
    pub source: String,
    /// Version the report declared, or `1.0` when it declared none.
    pub schema_version: String,
    /// Convention every path in the report is expressed in.
    pub anchor: Anchor,
    /// Threshold the report was filtered at, absent when it reported
    /// everything the scan found. A pre-1.4 report predates the key and loads
    /// as `None`, which is also what an unfiltered report writes.
    pub min_severity: Option<Severity>,
    pub findings: Vec<Finding>,
    pub baselined: Vec<Finding>,
    pub suppressed: Vec<Finding>,
    pub metrics: Metrics,
}

impl SnapshotData {
    /// Whether the UI must withhold every finding's match text.
    ///
    /// True for any report below [`REDACTING_VERSION`], and for a version
    /// string that does not read as `MAJOR.MINOR` at all. Withholding is the
    /// safe direction: showing a credential cannot be undone, and a redacted
    /// non-secret is a legible column short of one detail.
    pub fn hides_match_text(&self) -> bool {
        !redacts_at_source(&self.schema_version)
    }
}

/// Whether a report of this schema version had its match text redacted before
/// it was written. Anything unparseable is treated as older, never as newer.
fn redacts_at_source(version: &str) -> bool {
    let mut parts = version.split('.');
    let Ok(major) = parts.next().unwrap_or_default().parse::<u32>() else {
        return false;
    };
    let Ok(minor) = parts.next().unwrap_or_default().parse::<u32>() else {
        return false;
    };
    (major, minor) >= REDACTING_VERSION
}

#[derive(Debug)]
pub enum SnapshotError {
    /// The file could not be read at all.
    Read { path: String, source: io::Error },
    /// The file is not a JSON object of the expected shape.
    Parse {
        path: String,
        source: serde_json::Error,
    },
    /// The file is a JSON object, but nothing identifies it as a report.
    NotAReport { path: String },
    /// The report declares a major version this build does not read.
    UnsupportedVersion { path: String, found: String },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Read { path, source } => write!(f, "cannot read {path}: {source}"),
            SnapshotError::Parse { path, source } => {
                write!(f, "{path} is not a valid siloscan report: {source}")
            }
            SnapshotError::NotAReport { path } => write!(
                f,
                "{path} is not a siloscan report: it has neither a schema_version \
                 nor a findings key"
            ),
            SnapshotError::UnsupportedVersion { path, found } => write!(
                f,
                "{path}: report schema_version {found} is not supported; \
                 this build reads {SUPPORTED_MAJOR}.x reports"
            ),
        }
    }
}

impl std::error::Error for SnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SnapshotError::Read { source, .. } => Some(source),
            SnapshotError::Parse { source, .. } => Some(source),
            SnapshotError::NotAReport { .. } | SnapshotError::UnsupportedVersion { .. } => None,
        }
    }
}

/// Read and validate a JSON report.
pub fn load(path: &Path) -> Result<SnapshotData, SnapshotError> {
    let label = path.display().to_string();
    let text = fs::read_to_string(path).map_err(|source| SnapshotError::Read {
        path: label.clone(),
        source,
    })?;
    parse(&text, &label, source_name(path))
}

/// The banner name: the file name alone, falling back to the path as given
/// when it has no final component.
fn source_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Read one optional section of the report. Absent and null are both the same
/// as unset, so a report that omits a list and one that writes `null` for it
/// load identically. The target type comes from the field it is assigned to.
macro_rules! section {
    ($map:expr, $key:expr, $label:expr) => {
        match $map.remove($key) {
            None | Some(Value::Null) => Default::default(),
            Some(value) => {
                serde_json::from_value(value).map_err(|source| SnapshotError::Parse {
                    path: $label.to_string(),
                    source,
                })?
            }
        }
    };
}

/// `label` names the file in errors; `source` is what the banner shows.
fn parse(text: &str, label: &str, source: String) -> Result<SnapshotData, SnapshotError> {
    // Deserializing to a map, rather than a bare `Value`, makes "the top level
    // is not an object" a serde error like any other shape mismatch.
    let mut map: Map<String, Value> =
        serde_json::from_str(text).map_err(|source| SnapshotError::Parse {
            path: label.to_string(),
            source,
        })?;

    let version = version_of(&map, label)?;

    Ok(SnapshotData {
        source,
        schema_version: version,
        anchor: section!(map, "anchor", label),
        min_severity: section!(map, "min_severity", label),
        findings: section!(map, "findings", label),
        baselined: section!(map, "baselined", label),
        suppressed: section!(map, "suppressed", label),
        metrics: section!(map, "metrics", label),
    })
}

/// A missing version means the report predates the key, which is version 1.0 -
/// but only for a document that is a report at all. Every 1.0 report carries a
/// `findings` key, so a document with neither key is not one, and is rejected
/// by name rather than loaded as an empty passing report.
///
/// Anything that is not a `MAJOR.MINOR` string of a known major is rejected
/// with the value that was found.
fn version_of(map: &Map<String, Value>, label: &str) -> Result<String, SnapshotError> {
    let found = match map.get("schema_version") {
        None | Some(Value::Null) => {
            if !map.contains_key("findings") {
                return Err(SnapshotError::NotAReport {
                    path: label.to_string(),
                });
            }
            ASSUMED_VERSION.to_string()
        }
        Some(Value::String(version)) => version.clone(),
        Some(other) => other.to_string(),
    };
    let major = found.split('.').next().unwrap_or_default().parse::<u32>();
    if matches!(major, Ok(SUPPORTED_MAJOR)) {
        Ok(found)
    } else {
        Err(SnapshotError::UnsupportedVersion {
            path: label.to_string(),
            found,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use siloscan_core::rules::Severity;

    fn report_json(schema_version: Option<&str>) -> String {
        let version = match schema_version {
            Some(version) => format!("\"schema_version\": \"{version}\","),
            None => String::new(),
        };
        format!(
            r#"{{
  "version": "1.1.0",
  {version}
  "anchor": "config",
  "findings": [
    {{
      "rule_id": "metrics.duplicate-block",
      "severity": "info",
      "message": "duplicated block",
      "path": "src/a.rs",
      "line": 10,
      "column": 1,
      "matched": "12 duplicated lines (block 0123456789ab)",
      "fingerprint": "abc"
    }}
  ],
  "baselined": [],
  "suppressed": [],
  "skipped": [],
  "metrics": {{
    "files": {{
      "src/a.rs": {{ "lines": 40, "code_lines": 30, "duplicated_lines": 12 }}
    }},
    "totals": {{
      "lines": 40,
      "code_lines": 30,
      "duplicated_lines": 12,
      "duplication_density": 30.0
    }}
  }}
}}"#
        )
    }

    fn load_str(text: &str) -> Result<SnapshotData, SnapshotError> {
        parse(text, "report.json", "report.json".to_string())
    }

    fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn loads_a_current_report() {
        // The version this build's core writes, not a pinned string: the gate
        // reads the major component only, so a minor bump must not touch this.
        let current = siloscan_core::output::SCHEMA_VERSION;
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "report.json", &report_json(Some(current)));

        let data = load(&path).unwrap();

        assert_eq!(data.source, "report.json");
        assert_eq!(data.schema_version, current);
        assert_eq!(data.anchor, Anchor::Config);
        assert_eq!(data.findings.len(), 1);
        assert_eq!(data.findings[0].rule_id, "metrics.duplicate-block");
        assert_eq!(data.findings[0].severity, Severity::Info);
        assert_eq!(data.metrics.totals.lines, 40);
        assert_eq!(data.metrics.files["src/a.rs"].duplicated_lines, 12);
    }

    #[test]
    fn a_report_without_a_schema_version_is_read_as_one_zero() {
        let data = load_str(&report_json(None)).unwrap();

        assert_eq!(data.schema_version, "1.0");
        assert_eq!(data.findings.len(), 1);
    }

    #[test]
    fn a_newer_major_version_is_rejected_by_name() {
        let err = load_str(&report_json(Some("2.0"))).unwrap_err();

        assert!(matches!(err, SnapshotError::UnsupportedVersion { .. }));
        let message = err.to_string();
        assert!(message.contains("2.0"), "{message}");
        assert!(message.contains("1.x"), "{message}");

        for version in ["0.9", "", "next", "10.0"] {
            assert!(
                matches!(
                    load_str(&report_json(Some(version))),
                    Err(SnapshotError::UnsupportedVersion { .. })
                ),
                "version {version} must be rejected"
            );
        }
    }

    #[test]
    fn a_later_minor_version_of_the_same_major_loads() {
        let data = load_str(&report_json(Some("1.7"))).unwrap();

        assert_eq!(data.schema_version, "1.7");
        assert_eq!(data.findings.len(), 1);
    }

    #[test]
    fn unknown_fields_are_ignored_at_every_level() {
        let text = r#"{
  "schema_version": "1.1",
  "tomorrows_key": { "nested": true },
  "findings": [
    {
      "rule_id": "a.b",
      "severity": "error",
      "message": "m",
      "path": "src/a.rs",
      "line": 1,
      "column": 1,
      "matched": "x",
      "fingerprint": "f",
      "future_field": 7
    }
  ],
  "metrics": {
    "files": { "src/a.rs": { "lines": 3, "duplicated_lines": 0, "churn": 12 } },
    "totals": {
      "lines": 3,
      "code_lines": 0,
      "duplicated_lines": 0,
      "duplication_density": 0.0,
      "future_total": 1
    },
    "future_block": []
  }
}"#;

        let data = load_str(text).unwrap();

        assert_eq!(data.findings.len(), 1);
        assert_eq!(data.findings[0].fingerprint, "f");
        assert_eq!(data.metrics.files["src/a.rs"].lines, 3);
        assert_eq!(data.metrics.files["src/a.rs"].code_lines, None);
    }

    #[test]
    fn absent_sections_default_to_empty() {
        let data = load_str("{\"schema_version\": \"1.1\"}").unwrap();

        assert!(data.findings.is_empty());
        assert!(data.baselined.is_empty());
        assert!(data.suppressed.is_empty());
        assert_eq!(data.metrics, Metrics::default());
        assert_eq!(data.anchor, Anchor::ScanRoot);

        let null = load_str("{\"metrics\": null, \"findings\": null, \"anchor\": null}").unwrap();
        assert_eq!(null.metrics, Metrics::default());
        assert!(null.findings.is_empty());
        assert_eq!(null.anchor, Anchor::ScanRoot);
    }

    #[test]
    fn an_unreadable_file_and_invalid_json_are_distinct_errors() {
        let dir = tempfile::tempdir().unwrap();

        let missing = load(&dir.path().join("absent.json")).unwrap_err();
        assert!(matches!(missing, SnapshotError::Read { .. }), "{missing:?}");
        assert!(missing.to_string().contains("absent.json"));

        let path = write(&dir, "broken.json", "{ not json");
        let broken = load(&path).unwrap_err();
        assert!(matches!(broken, SnapshotError::Parse { .. }), "{broken:?}");
        assert!(broken.to_string().contains("broken.json"));

        // A well-formed document of the wrong shape is a parse error too.
        assert!(matches!(load_str("[]"), Err(SnapshotError::Parse { .. })));
        assert!(matches!(
            load_str("{\"findings\": 3}"),
            Err(SnapshotError::Parse { .. })
        ));
    }

    /// The tolerance must not fail open: every key is optional, so an arbitrary
    /// JSON object would otherwise load as an empty report and render a passing
    /// gate.
    #[test]
    fn a_json_object_that_is_not_a_report_is_rejected() {
        let sarif = r#"{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{ "tool": { "driver": { "name": "other" } }, "results": [] }]
}"#;
        let package = r#"{ "name": "app", "version": "1.0.0", "scripts": {} }"#;

        for text in ["{}", sarif, package] {
            let err = load_str(text).unwrap_err();
            assert!(matches!(err, SnapshotError::NotAReport { .. }), "{err:?}");
        }
    }

    #[test]
    fn the_not_a_report_error_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "package.json", r#"{ "name": "app" }"#);

        let err = load(&path).unwrap_err();

        let message = err.to_string();
        assert!(message.contains("package.json"), "{message}");
        assert!(message.contains("not a siloscan report"), "{message}");
    }

    /// A 1.0 report predates `schema_version` and is recognised by its
    /// `findings` key, whatever else it does or does not carry.
    #[test]
    fn a_one_zero_report_without_a_schema_version_is_still_a_report() {
        let data = load_str(r#"{ "findings": [] }"#).unwrap();

        assert_eq!(data.schema_version, "1.0");
        assert!(data.findings.is_empty());

        // A declared version is enough on its own: a report may legitimately
        // carry no findings key at all.
        assert!(load_str(r#"{ "schema_version": "1.1" }"#).is_ok());
    }

    /// The loader accepts every 1.x report, but only 1.2 and up redact a
    /// secret's match text before writing it. The older ones must be treated as
    /// carrying credentials, because they do.
    #[test]
    fn reports_below_one_two_hide_their_match_text() {
        for version in ["1.0", "1.1"] {
            let data = load_str(&report_json(Some(version))).unwrap();
            assert!(data.hides_match_text(), "{version} carries raw matches");
        }
        // The 1.0 reports that predate the key are the same case.
        assert!(load_str(&report_json(None)).unwrap().hides_match_text());

        for version in ["1.2", "1.3", "1.10"] {
            let data = load_str(&report_json(Some(version))).unwrap();
            assert!(!data.hides_match_text(), "{version} is redacted already");
        }

        // The version this build's core writes must not be withheld.
        let current = load_str(&report_json(Some(siloscan_core::output::SCHEMA_VERSION))).unwrap();
        assert!(!current.hides_match_text());
    }

    /// A version string that does not read as `MAJOR.MINOR` says nothing about
    /// what the writer did, so it is treated as an older report.
    #[test]
    fn an_unreadable_version_is_treated_as_pre_redaction() {
        for version in ["", "1", "1.x", "x.2", "1..2", " 1.2", "v1.2"] {
            assert!(
                !redacts_at_source(version),
                "{version:?} must not be trusted"
            );
        }
        assert!(redacts_at_source("1.2.7"), "a patch component is ignored");
    }

    #[test]
    fn the_banner_name_is_the_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "nightly-report.json", &report_json(Some("1.1")));

        assert_eq!(load(&path).unwrap().source, "nightly-report.json");
    }
}
