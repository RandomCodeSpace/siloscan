//! Loading a scan report from disk instead of running a scan.
//!
//! The JSON report contract is additive-only within a major version: fields are
//! appended, never renamed, moved or removed. This reader is therefore
//! deliberately tolerant - unknown keys, at the top level and inside every
//! nested object, are ignored, and absent optional keys take their defaults.
//! Only two things are rejected: input that is not a readable JSON object, and
//! a `schema_version` whose major component this build does not understand.
//!
//! The report carries no timestamp and no scan root, so a snapshot is
//! identified by the file it was read from.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use siloscan_core::config::Anchor;
use siloscan_core::findings::Finding;
use siloscan_core::metrics::Metrics;
use siloscan_core::serde_json::{self, Map, Value};

/// Report major version this build reads.
pub const SUPPORTED_MAJOR: u32 = 1;

/// Version assumed for a report written before `schema_version` existed.
const ASSUMED_VERSION: &str = "1.0";

/// A report read from disk, in the shape the UI consumes.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotData {
    /// File name the report was read from, for the read-only banner.
    pub source: String,
    /// Version the report declared, or `1.0` when it declared none.
    pub schema_version: String,
    /// Convention every path in the report is expressed in.
    pub anchor: Anchor,
    pub findings: Vec<Finding>,
    pub baselined: Vec<Finding>,
    pub suppressed: Vec<Finding>,
    pub metrics: Metrics,
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
            SnapshotError::UnsupportedVersion { .. } => None,
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
        findings: section!(map, "findings", label),
        baselined: section!(map, "baselined", label),
        suppressed: section!(map, "suppressed", label),
        metrics: section!(map, "metrics", label),
    })
}

/// A missing version means the report predates the key, which is version 1.0.
/// Anything that is not a `MAJOR.MINOR` string of a known major is rejected
/// with the value that was found.
fn version_of(map: &Map<String, Value>, label: &str) -> Result<String, SnapshotError> {
    let found = match map.get("schema_version") {
        None | Some(Value::Null) => ASSUMED_VERSION.to_string(),
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
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "report.json", &report_json(Some("1.1")));

        let data = load(&path).unwrap();

        assert_eq!(data.source, "report.json");
        assert_eq!(data.schema_version, "1.1");
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

    #[test]
    fn the_banner_name_is_the_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "nightly-report.json", &report_json(Some("1.1")));

        assert_eq!(load(&path).unwrap().source, "nightly-report.json");
    }
}
