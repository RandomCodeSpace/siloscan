//! The resolved report contract: the legacy public API is unchanged, and the
//! schema 1.2 resolved document is the legacy projection with exactly four
//! trailing fields after it.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use siloscan_core::config::Anchor;
use siloscan_core::output::{self, JsonReport, ReportFinding, SCHEMA_VERSION};
use siloscan_core::plan::{
    OutcomeMetadata, ResolvedScanPlan, ResolvedScanReport, ScanRequest, ScopeKind, ScopeMetadata,
    to_resolved_json, write_resolved_json,
};
use siloscan_core::rules::{RuleSet, Severity};
use siloscan_core::scan::{self, ScanOptions, ScanReport};
use siloscan_core::serde_json::{self, Value};
use tempfile::TempDir;

/// The four markers, in the settled order.
const MARKERS: [&str; 4] = ["report_kind", "scope", "outcome", "setup"];

const NEEDLE_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.hit\n",
    "    severity: error\n",
    "    message: pattern hit\n",
    "    regex:\n",
    "      pattern: 'n[e]edle'\n",
);

fn write(root: &Path, rel: &str, contents: &str) -> PathBuf {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, contents).unwrap();
    path
}

fn fixture() -> (TempDir, PathBuf) {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "let x = \"needle\";\n");
    write(
        tree.path(),
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    );
    let rules = tree.path().join("rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(rules.join("rules.yaml"), NEEDLE_RULE).unwrap();
    (tree, rules)
}

fn resolved(tree: &Path, rules: &Path) -> ResolvedScanReport {
    ResolvedScanPlan::resolve(
        &ScanRequest::explicit(tree)
            .without_embedded_rules()
            .with_rule_dirs(vec![rules.to_path_buf()]),
    )
    .expect("resolution")
    .execute(&mut |_| {})
    .expect("execution")
}

fn scope() -> ScopeMetadata {
    ScopeMetadata::new(
        "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0".to_string(),
        ScopeKind::Directory,
        0,
    )
}

fn outcome() -> OutcomeMetadata {
    OutcomeMetadata::new(Severity::Error, true)
}

fn render(report: &ResolvedScanReport) -> String {
    to_resolved_json(
        &report.scan,
        &report.setup,
        report.context(),
        &scope(),
        &outcome(),
        None,
    )
}

// ---------------------------------------------------------------------------
// The legacy public API, from an external crate's point of view
// ---------------------------------------------------------------------------

/// This file is a separate crate that depends on `siloscan-core` through its
/// published surface only, so anything that compiles here compiles for a
/// downstream embedder. Every item below is written the way v1.5.1 documented
/// it: struct literals for the exhaustive report types, `Default` plus field
/// assignment for `ScanOptions`, and the three scan entry points named by
/// their exact signatures.
#[test]
#[allow(clippy::type_complexity)]
fn the_legacy_public_api_still_compiles_unchanged() {
    let finding = ReportFinding {
        rule_id: "test.hit",
        severity: Severity::Error,
        message: "pattern hit",
        path: "src/a.rs",
        line: 1,
        column: 9,
        matched: "needle",
        fingerprint: "abc",
    };
    let metrics = siloscan_core::metrics::Metrics::default();
    let ignored = siloscan_core::walk::Ignored::default();
    let skipped: Vec<scan::SkippedFile> = Vec::new();
    let warnings: Vec<String> = Vec::new();
    let report = JsonReport {
        version: "1.5.1",
        findings: vec![finding],
        baselined: Vec::new(),
        suppressed: Vec::new(),
        skipped: &skipped,
        schema_version: SCHEMA_VERSION,
        metrics: &metrics,
        anchor: Anchor::ScanRoot,
        ignored,
        warnings: &warnings,
        min_severity: None,
    };
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(
        rendered.contains("\"schema_version\":\"1.2\""),
        "{rendered}"
    );

    let mut options = ScanOptions::default();
    options.ignore = Default::default();
    options.follow_symlinks = false;
    assert!(options.baseline.is_none());

    let _scan: fn(
        &Path,
        &RuleSet,
        Option<&siloscan_core::baseline::Baseline>,
    ) -> Result<ScanReport, String> = scan::scan;
    let _with_progress: fn(
        &Path,
        &RuleSet,
        Option<&siloscan_core::baseline::Baseline>,
        &mut dyn FnMut(scan::Progress),
    ) -> Result<ScanReport, String> = scan::scan_with_progress;
    let _opts: fn(
        &Path,
        &RuleSet,
        &ScanOptions,
        &mut dyn FnMut(scan::Progress),
    ) -> Result<ScanReport, String> = scan::scan_opts;
    let _json: fn(&ScanReport, &RuleSet, Anchor, Option<Severity>) -> String = output::to_json;
    let _sarif: fn(&ScanReport, &RuleSet, Anchor, Option<Severity>) -> String =
        siloscan_core::output_sarif::to_sarif;
}

#[test]
fn the_legacy_writer_still_produces_the_legacy_document() {
    let (tree, rules) = fixture();
    let report = resolved(tree.path(), &rules);
    let legacy = output::to_json(
        &report.scan,
        report.context().rules(),
        report.context().anchoring().anchor(),
        None,
    );

    let parsed: Value = serde_json::from_str(&legacy).unwrap();
    let object = parsed.as_object().unwrap();
    assert_eq!(object["schema_version"], Value::from(SCHEMA_VERSION));
    for marker in MARKERS {
        assert!(!object.contains_key(marker), "{marker}");
    }
}

// ---------------------------------------------------------------------------
// The resolved document
// ---------------------------------------------------------------------------

#[test]
fn the_resolved_document_appends_exactly_four_fields_in_order() {
    let (tree, rules) = fixture();
    let report = resolved(tree.path(), &rules);
    let document = render(&report);

    // Read off the document itself: `serde_json::Value` sorts its keys, so the
    // order the writer emitted is only visible in the bytes. Pretty printing
    // indents a top-level key by exactly two spaces and everything below it by
    // more, which is what makes this a top-level key list.
    let keys: Vec<&str> = document
        .lines()
        .filter(|line| line.starts_with("  \"") && !line.starts_with("   "))
        .filter_map(|line| line.split('"').nth(1))
        .collect();
    assert_eq!(&keys[keys.len() - 4..], &MARKERS);

    let parsed: Value = serde_json::from_str(&document).unwrap();
    let object = parsed.as_object().unwrap();
    assert_eq!(object["report_kind"], Value::from("scan"));
    assert_eq!(object["schema_version"], Value::from(SCHEMA_VERSION));

    let legacy: Value = serde_json::from_str(&output::to_json(
        &report.scan,
        report.context().rules(),
        report.context().anchoring().anchor(),
        None,
    ))
    .unwrap();
    let mut stripped = object.clone();
    for marker in MARKERS {
        stripped.remove(marker);
    }
    assert_eq!(Value::Object(stripped), legacy);
}

#[test]
fn the_resolved_document_reuses_the_legacy_projection_byte_for_byte() {
    let (tree, rules) = fixture();
    let report = resolved(tree.path(), &rules);
    let legacy = output::to_json(
        &report.scan,
        report.context().rules(),
        report.context().anchoring().anchor(),
        None,
    );
    let document = render(&report);

    // The legacy document is the same bytes up to its closing brace; the
    // resolved one continues from there with the four markers.
    let prefix = legacy
        .trim_end()
        .strip_suffix('}')
        .unwrap()
        .trim_end()
        .to_string();
    assert!(
        document.starts_with(&prefix),
        "resolved document does not open with the legacy projection"
    );
}

#[test]
fn the_setup_field_carries_the_resolved_facts() {
    let (tree, rules) = fixture();
    let report = resolved(tree.path(), &rules);
    let parsed: Value = serde_json::from_str(&render(&report)).unwrap();
    let setup = parsed["setup"].as_object().unwrap();

    for key in [
        "evidence",
        "units",
        "workspaces",
        "languages",
        "source_roots",
        "rule_sources",
        "capabilities",
        "explicit_overrides",
    ] {
        assert!(setup.contains_key(key), "{key}");
    }
    assert_eq!(
        setup["explicit_overrides"],
        serde_json::json!(["no-default-rules", "path", "rules"])
    );
    assert!(
        setup["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|state| state["id"] == "cache" && state["status"] == "enabled")
    );
    assert_eq!(parsed["scope"]["kind"], Value::from("directory"));
    assert_eq!(parsed["outcome"]["fail_on"], Value::from("error"));
    assert_eq!(parsed["outcome"]["threshold_reached"], Value::from(true));
}

#[test]
fn two_runs_of_one_tree_produce_the_same_resolved_bytes() {
    let (tree, rules) = fixture();
    let first = render(&resolved(tree.path(), &rules));
    let second = render(&resolved(tree.path(), &rules));
    assert_eq!(first, second);
}

/// Nothing in the document may name the machine it was produced on, or when.
/// A saved report that changes for either reason is not comparable, and a
/// report that carries a cache or output path is a report that leaks where the
/// scan ran.
#[test]
fn the_resolved_document_carries_no_environment_identity() {
    let (tree, rules) = fixture();
    let report = resolved(tree.path(), &rules);
    let document = render(&report);

    let absolute = tree.path().to_string_lossy().into_owned();
    assert!(!document.contains(&absolute), "absolute root leaked");
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(!document.contains(&cwd), "working directory leaked");
    if let Ok(host) = std::env::var("HOSTNAME")
        && !host.is_empty()
    {
        assert!(!document.contains(&host), "host leaked");
    }

    let parsed: Value = serde_json::from_str(&document).unwrap();
    let object = parsed.as_object().unwrap();
    for forbidden in [
        "root",
        "scan_root",
        "cwd",
        "working_directory",
        "command_line",
        "cache_path",
        "cache_dir",
        "output",
        "output_path",
        "manifest",
        "host",
        "hostname",
        "timestamp",
        "generated_at",
    ] {
        assert!(!object.contains_key(forbidden), "{forbidden}");
    }
    assert!(!document.contains(".siloscan"), "cache path leaked");
}

// ---------------------------------------------------------------------------
// One serialization, straight to the writer
// ---------------------------------------------------------------------------

/// Records what the serializer handed it, and how often. A second pass over the
/// report - or a full-document `String` built on the way to the writer - shows
/// up here as a second document.
#[derive(Default)]
struct CountingWriter {
    bytes: Vec<u8>,
    writes: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_writer_serializes_the_report_once_without_cloning_it() {
    let (tree, rules) = fixture();
    let report = resolved(tree.path(), &rules);

    // Borrowed, not moved and not cloned: every argument below is a reference,
    // so there is no copy of the report for the serializer to walk.
    let mut counting = CountingWriter::default();
    write_resolved_json(
        &mut counting,
        &report.scan,
        &report.setup,
        report.context(),
        &scope(),
        &outcome(),
        None,
    )
    .expect("serialization");

    assert!(counting.writes > 0);
    let document = String::from_utf8(counting.bytes).unwrap();
    assert_eq!(document.matches("\"report_kind\"").count(), 1);
    assert_eq!(document.matches("\"schema_version\"").count(), 1);
    assert_eq!(document, render(&report));

    // The report survived the write intact, so nothing consumed or replaced it.
    assert_eq!(report.scan.findings.len(), 1);
    assert_eq!(report.scan.findings[0].rule_id, "test.hit");
}

#[test]
fn the_string_helper_wraps_the_writer() {
    let (tree, rules) = fixture();
    let report = resolved(tree.path(), &rules);

    let mut buffer: Vec<u8> = Vec::new();
    write_resolved_json(
        &mut buffer,
        &report.scan,
        &report.setup,
        report.context(),
        &scope(),
        &outcome(),
        Some(Severity::Warning),
    )
    .expect("serialization");

    let helper = to_resolved_json(
        &report.scan,
        &report.setup,
        report.context(),
        &scope(),
        &outcome(),
        Some(Severity::Warning),
    );
    assert_eq!(String::from_utf8(buffer).unwrap(), helper);
    assert!(helper.contains("\"min_severity\""));
}
