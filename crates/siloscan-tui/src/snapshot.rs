//! Loading a scan report from disk instead of running a scan.
//!
//! The JSON report contract is additive-only within a major version: fields are
//! appended, never renamed, moved or removed. This reader is therefore
//! deliberately tolerant - unknown keys, at the top level and inside every
//! nested object, are ignored, and absent optional keys take their defaults.
//!
//! What it refuses is what tolerance alone would let through. Every key is
//! optional and every section defaults to empty, so without a discriminator any
//! JSON object at all (`{}`, a SARIF log, a `package.json`, a document carrying
//! nothing but a `schema_version`) would load as an empty report and render a
//! passing gate. A report is recognised by carrying a `findings` key with a
//! value, and by declaring a `schema_version` this build's major understands.
//!
//! The report carries no timestamp and no scan root, so a snapshot is
//! identified by the file it was read from.
//!
//! # Classifying a report
//!
//! A v2 resolved report appends four markers - `report_kind`, `scope`,
//! `outcome` and `setup` - after the legacy projection. Marker completeness,
//! not the product version, decides what a document is: the retained public
//! core writer emits a 2.x product version with no markers at all, so the
//! version says nothing about the shape.
//!
//! - No marker: a legacy or core-writer report. It carries findings and
//!   metrics; its setup and its saved outcome are unavailable.
//! - All four markers: an authoritative resolved report.
//! - Some markers: malformed. The writer appends them together, so a reader
//!   that filled in the rest would be inventing the parts it could not read.
//!
//! [`load`] takes what the caller expects. An explicit `--report FILE` expects
//! nothing and opens either shape. An implicit latest lookup passes the
//! [`ExpectedScope`] it derived and gets only a complete report for that exact
//! scope: a loose legacy document is never the latest report for a scope,
//! because nothing in it says which scope it describes.
//!
//! # Tolerance across minor versions
//!
//! Reports began redacting a secret rule's `matched` at the source in schema
//! 1.2; a 1.0 or 1.1 report carries the credential itself, in plain text, and
//! the major-1 gate accepts it. Snapshot mode boots with no rule set, so it
//! cannot tell which of those findings came from a secret rule and cannot
//! redact selectively. [`SnapshotData::hides_match_text`] is the answer: below
//! 1.2 no match text is shown at all, and the reason is said out loud rather
//! than left to look like an empty column.
//!
//! Additions within the same major are ignored rather than refused, and that
//! includes values as well as keys: a capability status is kept as the string
//! the writer wrote, so a status this build has never heard of loads and is
//! reported rather than invalidating the report that carries it.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use siloscan_core::config::Anchor;
use siloscan_core::findings::Finding;
use siloscan_core::metrics::Metrics;
use siloscan_core::plan::{RESOLVED_REPORT_KIND, ScopeKind};
use siloscan_core::rules::Severity;
use siloscan_core::serde_json::{self, Map, Value};

/// Report major version this build reads.
pub const SUPPORTED_MAJOR: u32 = 1;

/// Version assumed for a report written before `schema_version` existed.
const ASSUMED_VERSION: &str = "1.0";

/// First schema version whose `matched` fields are redacted by the writer.
/// Everything below it may carry a credential in plain text.
const REDACTING_VERSION: (u32, u32) = (1, 2);

/// The v2 markers, in the order the writer appends them. All four or none.
const MARKERS: [&str; 4] = ["report_kind", "scope", "outcome", "setup"];

/// What the footer says while match text is being withheld. It names the cause,
/// not just the effect: an empty match column is otherwise indistinguishable
/// from a report that had nothing to show.
pub const HIDDEN_MATCH_NOTE: &str = "pre-1.2 report: match text hidden";

/// The scope an implicit latest lookup expects the report to describe.
///
/// `identity` is the opaque scope key the caller derived from the canonical
/// requested path and its kind. This reader never computes one and never reads
/// a path out of a report: it compares what it was handed against what the
/// report claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedScope {
    pub identity: String,
    pub kind: ScopeKind,
}

/// Which scope a resolved report describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedScope {
    pub identity: String,
    pub kind: ScopeKind,
    /// Parents between the scope's measured directory and the source base the
    /// report's paths are relative to. Retained for the caller that resolves
    /// that base; this reader does not walk it.
    pub path_base_ancestor_levels: u32,
}

/// The gate the saved run was judged against, before output filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SavedOutcome {
    pub fail_on: Severity,
    pub threshold_reached: bool,
}

/// One capability of the saved run.
///
/// `status` is the string the writer wrote, not a parsed enum: a later build
/// may record a status this one has never heard of, and refusing the whole
/// report over one unknown word would break the additive contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedCapability {
    pub id: String,
    pub status: String,
    pub reason: Option<String>,
}

/// What setup resolved for the saved run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedSetup {
    pub languages: Vec<String>,
    pub capabilities: Vec<SavedCapability>,
    pub explicit_overrides: Vec<String>,
}

/// The four markers of a resolved report, present together or not at all.
///
/// `report_kind` is not a field: the only accepted value is
/// [`RESOLVED_REPORT_KIND`], so carrying it would be carrying a constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedMarkers {
    pub scope: SavedScope,
    pub outcome: SavedOutcome,
    pub setup: SavedSetup,
}

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
    /// The resolved metadata, when this is a v2 report. `None` for a legacy or
    /// core-writer report, whose saved outcome and setup are unavailable rather
    /// than clean.
    pub markers: Option<SavedMarkers>,
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

    /// The gate the saved run was judged against, when the report records one.
    pub fn outcome(&self) -> Option<SavedOutcome> {
        self.markers.as_ref().map(|markers| markers.outcome)
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
    /// The report declares a product version that is not a version.
    MalformedVersion { path: String, found: String },
    /// The report carries some of the four v2 markers, or one of them is not
    /// the shape a resolved report writes.
    IncompleteMarkers { path: String, problem: String },
    /// A latest-report lookup was handed a report with no resolved metadata,
    /// which cannot say which scope it describes.
    NotResolved { path: String },
    /// A latest-report lookup was handed another scope's report.
    ScopeMismatch { path: String },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Read { path, source } => write!(f, "cannot read {path}: {source}"),
            SnapshotError::Parse { path, source } => {
                write!(f, "{path} is not a valid siloscan report: {source}")
            }
            SnapshotError::NotAReport { path } => {
                write!(f, "{path} is not a siloscan report: it has no findings")
            }
            SnapshotError::UnsupportedVersion { path, found } => write!(
                f,
                "{path}: report schema_version {found} is not supported; \
                 this build reads {SUPPORTED_MAJOR}.x reports"
            ),
            SnapshotError::MalformedVersion { path, found } => {
                write!(f, "{path}: report version {found} is not a version")
            }
            SnapshotError::IncompleteMarkers { path, problem } => {
                write!(f, "{path} is not a complete resolved report: {problem}")
            }
            SnapshotError::NotResolved { path } => write!(
                f,
                "{path} carries no resolved scan metadata, so it cannot be this \
                 scope's latest report"
            ),
            SnapshotError::ScopeMismatch { path } => {
                write!(f, "{path} was saved for a different scan scope")
            }
        }
    }
}

impl std::error::Error for SnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SnapshotError::Read { source, .. } => Some(source),
            SnapshotError::Parse { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Read and validate a JSON report.
///
/// `expect` is `Some` only for an implicit latest lookup, which accepts nothing
/// but a complete resolved report for that exact scope.
pub fn load(path: &Path, expect: Option<&ExpectedScope>) -> Result<SnapshotData, SnapshotError> {
    let label = path.display().to_string();
    let text = fs::read_to_string(path).map_err(|source| SnapshotError::Read {
        path: label.clone(),
        source,
    })?;
    parse(&text, &label, source_name(path), expect)
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
fn parse(
    text: &str,
    label: &str,
    source: String,
    expect: Option<&ExpectedScope>,
) -> Result<SnapshotData, SnapshotError> {
    // Deserializing to a map, rather than a bare `Value`, makes "the top level
    // is not an object" a serde error like any other shape mismatch.
    let mut map: Map<String, Value> =
        serde_json::from_str(text).map_err(|source| SnapshotError::Parse {
            path: label.to_string(),
            source,
        })?;

    check_product_version(&map, label)?;
    check_is_a_report(&map, label)?;
    let version = schema_version_of(&map, label)?;
    let markers = markers_of(&mut map, label)?;
    check_expectation(markers.as_ref(), expect, label)?;

    Ok(SnapshotData {
        source,
        schema_version: version,
        anchor: section!(map, "anchor", label),
        min_severity: section!(map, "min_severity", label),
        findings: section!(map, "findings", label),
        baselined: section!(map, "baselined", label),
        suppressed: section!(map, "suppressed", label),
        metrics: section!(map, "metrics", label),
        markers,
    })
}

/// The product version says which build wrote the report. It does not classify
/// the document - the retained core writer emits a 2.x version with no resolved
/// metadata - but a value that is not a version at all is a malformed report
/// rather than an unknown one.
fn check_product_version(map: &Map<String, Value>, label: &str) -> Result<(), SnapshotError> {
    let found = match map.get("version") {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::String(text)) if is_product_version(text) => return Ok(()),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    };
    Err(SnapshotError::MalformedVersion {
        path: label.to_string(),
        found,
    })
}

/// `MAJOR.MINOR.PATCH` of decimal digits, with any pre-release or build suffix
/// ignored. Every siloscan writer has emitted exactly that.
fn is_product_version(text: &str) -> bool {
    let core = text.split(['-', '+']).next().unwrap_or_default();
    let mut parts = core.split('.');
    let numbered = [parts.next(), parts.next(), parts.next()]
        .iter()
        .all(|part| part.is_some_and(is_decimal));
    numbered && parts.next().is_none()
}

fn is_decimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Every key in a report is optional and every section defaults to empty, so
/// something has to say "this is a report at all". `findings` is that key: every
/// writer since 1.0 has emitted it, and a document without one is either not a
/// report or is withholding the only thing the board is built from.
///
/// A `schema_version` alone is not enough. An arbitrary object that happens to
/// carry one would otherwise open as a clean scan, which is the impostor this
/// check exists to refuse.
fn check_is_a_report(map: &Map<String, Value>, label: &str) -> Result<(), SnapshotError> {
    match map.get("findings") {
        None | Some(Value::Null) => Err(SnapshotError::NotAReport {
            path: label.to_string(),
        }),
        Some(_) => Ok(()),
    }
}

/// A missing version means the report predates the key, which is version 1.0.
/// Anything that is not a `MAJOR.MINOR` string of a known major is rejected
/// with the value that was found.
fn schema_version_of(map: &Map<String, Value>, label: &str) -> Result<String, SnapshotError> {
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

/// The resolved metadata, when the document carries any.
///
/// All four markers or none. A document with some of them was written by
/// something that stopped half way, and the fields a reader cannot see are
/// exactly the ones it would have to invent.
fn markers_of(
    map: &mut Map<String, Value>,
    label: &str,
) -> Result<Option<SavedMarkers>, SnapshotError> {
    let missing: Vec<&str> = MARKERS
        .iter()
        .copied()
        .filter(|key| matches!(map.get(*key), None | Some(Value::Null)))
        .collect();
    if missing.len() == MARKERS.len() {
        return Ok(None);
    }
    if !missing.is_empty() {
        return Err(incomplete(label, format!("missing {}", missing.join(", "))));
    }

    match map.remove("report_kind") {
        Some(Value::String(kind)) if kind == RESOLVED_REPORT_KIND => {}
        Some(other) => {
            return Err(incomplete(
                label,
                format!("report_kind is {other}, not \"{RESOLVED_REPORT_KIND}\""),
            ));
        }
        None => return Err(incomplete(label, "missing report_kind".to_string())),
    }

    let scope = scope_of(take_object(map, "scope", label)?, label)?;
    let outcome = outcome_of(take_object(map, "outcome", label)?, label)?;
    let setup = setup_of(take_object(map, "setup", label)?, label)?;
    Ok(Some(SavedMarkers {
        scope,
        outcome,
        setup,
    }))
}

/// An implicit latest lookup accepts one thing: a complete resolved report for
/// the exact scope it asked about. An explicit `--report FILE` names the file
/// itself and asks nothing about scope.
fn check_expectation(
    markers: Option<&SavedMarkers>,
    expect: Option<&ExpectedScope>,
    label: &str,
) -> Result<(), SnapshotError> {
    let Some(expect) = expect else {
        return Ok(());
    };
    let Some(markers) = markers else {
        return Err(SnapshotError::NotResolved {
            path: label.to_string(),
        });
    };
    if markers.scope.identity == expect.identity && markers.scope.kind == expect.kind {
        return Ok(());
    }
    Err(SnapshotError::ScopeMismatch {
        path: label.to_string(),
    })
}

fn scope_of(object: Map<String, Value>, label: &str) -> Result<SavedScope, SnapshotError> {
    let identity = string_field(&object, "scope", "identity", label)?;
    let kind = string_field(&object, "scope", "kind", label)?;
    let kind = match kind.as_str() {
        "directory" => ScopeKind::Directory,
        "file" => ScopeKind::File,
        other => {
            return Err(incomplete(
                label,
                format!("scope.kind is \"{other}\", not \"directory\" or \"file\""),
            ));
        }
    };
    let levels = match object
        .get("path_base_ancestor_levels")
        .and_then(Value::as_u64)
    {
        Some(levels) if u32::try_from(levels).is_ok() => levels as u32,
        _ => {
            return Err(incomplete(
                label,
                "scope.path_base_ancestor_levels is not a count".to_string(),
            ));
        }
    };
    Ok(SavedScope {
        identity,
        kind,
        path_base_ancestor_levels: levels,
    })
}

fn outcome_of(object: Map<String, Value>, label: &str) -> Result<SavedOutcome, SnapshotError> {
    let fail_on = object
        .get("fail_on")
        .cloned()
        .and_then(|value| serde_json::from_value::<Severity>(value).ok())
        .ok_or_else(|| incomplete(label, "outcome.fail_on is not a severity".to_string()))?;
    let threshold_reached = object
        .get("threshold_reached")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            incomplete(
                label,
                "outcome.threshold_reached is not a boolean".to_string(),
            )
        })?;
    Ok(SavedOutcome {
        fail_on,
        threshold_reached,
    })
}

fn setup_of(object: Map<String, Value>, label: &str) -> Result<SavedSetup, SnapshotError> {
    let languages = string_array(&object, "languages", label)?;
    let explicit_overrides = string_array(&object, "explicit_overrides", label)?;
    let capabilities = object
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| incomplete(label, "setup.capabilities is not a list".to_string()))?
        .iter()
        .map(|entry| capability_of(entry, label))
        .collect::<Result<Vec<SavedCapability>, SnapshotError>>()?;
    Ok(SavedSetup {
        languages,
        capabilities,
        explicit_overrides,
    })
}

/// One capability. `status` is kept verbatim, so a value added by a later build
/// is retained rather than rejected.
fn capability_of(entry: &Value, label: &str) -> Result<SavedCapability, SnapshotError> {
    let bad = || {
        incomplete(
            label,
            "setup.capabilities holds a malformed entry".to_string(),
        )
    };
    let object = entry.as_object().ok_or_else(bad)?;
    Ok(SavedCapability {
        id: object
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(bad)?
            .to_string(),
        status: object
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(bad)?
            .to_string(),
        reason: object
            .get("reason")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn take_object(
    map: &mut Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<Map<String, Value>, SnapshotError> {
    match map.remove(key) {
        Some(Value::Object(object)) => Ok(object),
        _ => Err(incomplete(label, format!("{key} is not an object"))),
    }
}

fn string_field(
    object: &Map<String, Value>,
    owner: &str,
    key: &str,
    label: &str,
) -> Result<String, SnapshotError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| incomplete(label, format!("{owner}.{key} is not a string")))
}

fn string_array(
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<Vec<String>, SnapshotError> {
    let bad = || incomplete(label, format!("setup.{key} is not a list of strings"));
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(bad)?
        .iter()
        .map(|entry| entry.as_str().map(str::to_string).ok_or_else(bad))
        .collect()
}

fn incomplete(label: &str, problem: String) -> SnapshotError {
    SnapshotError::IncompleteMarkers {
        path: label.to_string(),
        problem,
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

    /// The four markers a resolved report appends, as the core writer emits
    /// them.
    const RESOLVED_MARKERS: &str = r#"
  "report_kind": "scan",
  "scope": {
    "identity": "sha256-v1:aa",
    "kind": "directory",
    "path_base_ancestor_levels": 0
  },
  "outcome": { "fail_on": "error", "threshold_reached": true },
  "setup": {
    "evidence": [],
    "units": [],
    "workspaces": [],
    "languages": ["rust"],
    "source_roots": [],
    "rule_sources": [{ "id": "default-secrets@1", "origin": "embedded" }],
    "capabilities": [
      { "id": "cache", "status": "enabled", "reason": null },
      { "id": "coverage", "status": "not_configured", "reason": "no coverage report was given" }
    ],
    "explicit_overrides": ["path"]
  }"#;

    /// A complete resolved report: the legacy projection plus every marker.
    fn resolved_json() -> String {
        with_markers(RESOLVED_MARKERS)
    }

    /// The 1.2 legacy projection with `extra` spliced in after it.
    fn with_markers(extra: &str) -> String {
        let base = report_json(Some("1.2"));
        let (head, tail) = base.rsplit_once('}').expect("the document ends in a brace");
        format!("{head},{extra}\n}}{tail}")
    }

    fn load_str(text: &str) -> Result<SnapshotData, SnapshotError> {
        parse(text, "report.json", "report.json".to_string(), None)
    }

    fn load_as_latest(text: &str, expect: &ExpectedScope) -> Result<SnapshotData, SnapshotError> {
        parse(text, "report.json", "report.json".to_string(), Some(expect))
    }

    fn expected() -> ExpectedScope {
        ExpectedScope {
            identity: "sha256-v1:aa".to_string(),
            kind: ScopeKind::Directory,
        }
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

        let data = load(&path, None).unwrap();

        assert_eq!(data.source, "report.json");
        assert_eq!(data.schema_version, current);
        assert_eq!(data.anchor, Anchor::Config);
        assert_eq!(data.findings.len(), 1);
        assert_eq!(data.findings[0].rule_id, "metrics.duplicate-block");
        assert_eq!(data.findings[0].severity, Severity::Info);
        assert_eq!(data.metrics.totals.lines, 40);
        assert_eq!(data.metrics.files["src/a.rs"].duplicated_lines, 12);
        assert!(data.markers.is_none(), "no marker, no resolved metadata");
        assert!(data.outcome().is_none());
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
        let data = load_str("{\"schema_version\": \"1.1\", \"findings\": []}").unwrap();

        assert!(data.findings.is_empty());
        assert!(data.baselined.is_empty());
        assert!(data.suppressed.is_empty());
        assert_eq!(data.metrics, Metrics::default());
        assert_eq!(data.anchor, Anchor::ScanRoot);

        let null = load_str("{\"metrics\": null, \"findings\": [], \"anchor\": null}").unwrap();
        assert_eq!(null.metrics, Metrics::default());
        assert!(null.findings.is_empty());
        assert_eq!(null.anchor, Anchor::ScanRoot);
    }

    #[test]
    fn an_unreadable_file_and_invalid_json_are_distinct_errors() {
        let dir = tempfile::tempdir().unwrap();

        let missing = load(&dir.path().join("absent.json"), None).unwrap_err();
        assert!(matches!(missing, SnapshotError::Read { .. }), "{missing:?}");
        assert!(missing.to_string().contains("absent.json"));

        let path = write(&dir, "broken.json", "{ not json");
        let broken = load(&path, None).unwrap_err();
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

    /// A schema version is not a report discriminator, and neither is an
    /// explicit `null` findings list. v1.5.1 rendered both as an empty passing
    /// report; no writer ever produced one.
    #[test]
    fn a_schema_only_object_and_a_null_findings_list_are_not_reports() {
        for text in [
            r#"{ "schema_version": "1.2" }"#,
            r#"{ "schema_version": "1.2", "findings": null }"#,
            r#"{ "findings": null }"#,
        ] {
            let err = load_str(text).unwrap_err();
            assert!(
                matches!(err, SnapshotError::NotAReport { .. }),
                "{text}: {err:?}"
            );
        }
    }

    #[test]
    fn the_not_a_report_error_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "package.json", r#"{ "name": "app" }"#);

        let err = load(&path, None).unwrap_err();

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

        assert_eq!(load(&path, None).unwrap().source, "nightly-report.json");
    }

    // -- product version -------------------------------------------------

    /// The product version is display information, not a classifier: a 2.x
    /// report with no markers is the retained core writer's output and opens as
    /// a legacy report. What it may not be is nonsense.
    #[test]
    fn the_product_version_is_checked_for_syntax_and_nothing_else() {
        for version in ["1.5.1", "2.0.0", "2.0.0-rc.1", "10.2.3+build.7"] {
            let text = report_json(Some("1.2")).replace("\"1.1.0\"", &format!("\"{version}\""));
            assert!(load_str(&text).is_ok(), "{version} is a version");
        }

        for version in ["\"\"", "\"1\"", "\"1.2\"", "\"v1.2.3\"", "2", "[]", "true"] {
            let text = report_json(Some("1.2")).replace("\"1.1.0\"", version);
            let err = load_str(&text).unwrap_err();
            assert!(
                matches!(err, SnapshotError::MalformedVersion { .. }),
                "{version}: {err:?}"
            );
        }
    }

    // -- marker completeness ---------------------------------------------

    /// The whole marker set, read back as the writer wrote it.
    #[test]
    fn a_complete_resolved_report_is_authoritative() {
        let data = load_str(&resolved_json()).unwrap();

        let markers = data.markers.as_ref().expect("four markers");
        assert_eq!(markers.scope.identity, "sha256-v1:aa");
        assert_eq!(markers.scope.kind, ScopeKind::Directory);
        assert_eq!(markers.scope.path_base_ancestor_levels, 0);
        assert_eq!(
            data.outcome(),
            Some(SavedOutcome {
                fail_on: Severity::Error,
                threshold_reached: true
            })
        );
        assert_eq!(markers.setup.languages, vec!["rust".to_string()]);
        assert_eq!(markers.setup.explicit_overrides, vec!["path".to_string()]);
        assert_eq!(markers.setup.capabilities.len(), 2);
        assert_eq!(markers.setup.capabilities[0].id, "cache");
        assert_eq!(markers.setup.capabilities[0].status, "enabled");
        assert_eq!(markers.setup.capabilities[0].reason, None);
        assert_eq!(
            markers.setup.capabilities[1].reason.as_deref(),
            Some("no coverage report was given")
        );
        // The findings and metrics of the legacy projection are still read.
        assert_eq!(data.findings.len(), 1);
        assert_eq!(data.metrics.totals.lines, 40);
    }

    /// The writer appends the four together. A document carrying some of them
    /// is malformed, and the missing ones are exactly what a reader would have
    /// to invent.
    #[test]
    fn a_partial_marker_set_is_rejected_by_name() {
        let complete = RESOLVED_MARKERS.trim();
        for dropped in MARKERS {
            let partial = drop_marker(complete, dropped);
            let err = load_str(&with_markers(&partial)).unwrap_err();
            match err {
                SnapshotError::IncompleteMarkers { ref problem, .. } => {
                    assert!(problem.contains(dropped), "{dropped}: {problem}");
                }
                other => panic!("{dropped}: {other:?}"),
            }
        }
    }

    /// Every marker but `dropped`, as a JSON fragment.
    fn drop_marker(markers: &str, dropped: &str) -> String {
        let value: Value =
            serde_json::from_str(&format!("{{{markers}}}")).expect("the markers parse");
        let mut object = value.as_object().expect("an object").clone();
        object.remove(dropped);
        let text = serde_json::to_string(&Value::Object(object)).expect("re-serializes");
        // Exactly one brace off each end: the markers themselves end in braces.
        text[1..text.len() - 1].to_string()
    }

    /// `report_kind` is the discriminator, so a document that claims to be
    /// something else is not opened as a scan report.
    #[test]
    fn a_report_kind_other_than_scan_is_rejected() {
        let text = with_markers(&RESOLVED_MARKERS.replace("\"scan\"", "\"baseline\""));

        let err = load_str(&text).unwrap_err();

        match err {
            SnapshotError::IncompleteMarkers { problem, .. } => {
                assert!(problem.contains("report_kind"), "{problem}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// A marker that is present but not the shape a resolved report writes is
    /// the same failure as a missing one: the document is not complete.
    #[test]
    fn a_malformed_marker_is_rejected() {
        let cases = [
            ("\"identity\": \"sha256-v1:aa\"", "\"identity\": 7"),
            ("\"kind\": \"directory\"", "\"kind\": \"workspace\""),
            (
                "\"path_base_ancestor_levels\": 0",
                "\"path_base_ancestor_levels\": -1",
            ),
            ("\"fail_on\": \"error\"", "\"fail_on\": \"catastrophe\""),
            (
                "\"threshold_reached\": true",
                "\"threshold_reached\": \"yes\"",
            ),
            ("\"languages\": [\"rust\"]", "\"languages\": \"rust\""),
            (
                "\"explicit_overrides\": [\"path\"]",
                "\"explicit_overrides\": {}",
            ),
            (
                "\"id\": \"cache\", \"status\": \"enabled\"",
                "\"id\": \"cache\"",
            ),
        ];

        for (from, to) in cases {
            let text = with_markers(&RESOLVED_MARKERS.replace(from, to));
            let err = load_str(&text).unwrap_err();
            assert!(
                matches!(err, SnapshotError::IncompleteMarkers { .. }),
                "{to}: {err:?}"
            );
        }

        // A marker of the wrong JSON type altogether.
        for from in ["\"scope\": {", "\"outcome\": {", "\"setup\": {"] {
            let key = from.trim_end_matches(": {");
            let text = with_markers(&RESOLVED_MARKERS.replace(from, &format!("{key}: [")));
            assert!(load_str(&text).is_err(), "{key} as a list must be refused");
        }
    }

    /// A later build may record a capability status this one has never heard
    /// of. The report is still that scan's report.
    #[test]
    fn an_unknown_capability_status_is_retained() {
        let text = with_markers(&RESOLVED_MARKERS.replace("\"enabled\"", "\"deferred-to-daemon\""));

        let data = load_str(&text).unwrap();

        let markers = data.markers.expect("the report is still complete");
        assert_eq!(markers.setup.capabilities[0].status, "deferred-to-daemon");
    }

    // -- the two reader paths --------------------------------------------

    /// Explicit `--report FILE` opens what it was pointed at: a supported
    /// marker-free 1.x report, a marker-free report from the retained core
    /// writer, and a complete resolved report alike.
    #[test]
    fn an_explicit_report_opens_both_shapes() {
        let legacy = load_str(&report_json(Some("1.1"))).unwrap();
        assert!(legacy.markers.is_none(), "setup and outcome unavailable");

        let core_writer = report_json(Some("1.2")).replace("\"1.1.0\"", "\"2.0.0\"");
        let core_writer = load_str(&core_writer).unwrap();
        assert!(
            core_writer.markers.is_none(),
            "a 2.x product version is not a marker"
        );

        assert!(load_str(&resolved_json()).unwrap().markers.is_some());
    }

    /// Implicit latest opens one thing: a complete resolved report for the
    /// exact scope it asked about.
    #[test]
    fn implicit_latest_takes_only_a_complete_report_for_its_scope() {
        let data = load_as_latest(&resolved_json(), &expected()).unwrap();
        assert!(data.markers.is_some());

        for text in [
            report_json(Some("1.1")),
            report_json(None),
            report_json(Some("1.2")).replace("\"1.1.0\"", "\"2.0.0\""),
        ] {
            let err = load_as_latest(&text, &expected()).unwrap_err();
            assert!(matches!(err, SnapshotError::NotResolved { .. }), "{err:?}");
        }

        let partial = with_markers(&drop_marker(RESOLVED_MARKERS.trim(), "setup"));
        assert!(matches!(
            load_as_latest(&partial, &expected()),
            Err(SnapshotError::IncompleteMarkers { .. })
        ));
    }

    /// Another scope's report is not this scope's latest, whichever half of the
    /// identity differs.
    #[test]
    fn implicit_latest_refuses_another_scope() {
        let other_identity = ExpectedScope {
            identity: "sha256-v1:bb".to_string(),
            kind: ScopeKind::Directory,
        };
        let other_kind = ExpectedScope {
            identity: "sha256-v1:aa".to_string(),
            kind: ScopeKind::File,
        };

        for expect in [other_identity, other_kind] {
            let err = load_as_latest(&resolved_json(), &expect).unwrap_err();
            assert!(
                matches!(err, SnapshotError::ScopeMismatch { .. }),
                "{err:?}"
            );
        }
    }

    /// Every refusal names the file it read.
    #[test]
    fn every_refusal_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let partial = with_markers(&drop_marker(RESOLVED_MARKERS.trim(), "outcome"));

        let cases = [
            ("legacy.json", report_json(Some("1.1"))),
            ("partial.json", partial),
            ("scoped.json", resolved_json()),
        ];
        let expect = ExpectedScope {
            identity: "sha256-v1:zz".to_string(),
            kind: ScopeKind::Directory,
        };

        for (name, text) in cases {
            let path = write(&dir, name, &text);
            let err = load(&path, Some(&expect)).unwrap_err();
            assert!(err.to_string().contains(name), "{name}: {err}");
        }
    }
}
