//! The core resolved plan: what a request preserves, what resolution owns, and
//! that the scope is walked exactly once.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use siloscan_core::plan::{
    CapabilityState, CapabilityStatus, EMBEDDED_PACK_ID, ResolvedScanPlan, ResolvedScanReport,
    ScanRequest, ScanSetupReport,
};
use siloscan_core::project::DetectionStatus;
use siloscan_core::walk::IgnoreOptions;
use tempfile::TempDir;

/// The pattern is written so that the rule document does not match itself: a
/// rule directory inside the fixture tree is walked like any other file, and a
/// self-matching rule would report the fixture's own scaffolding.
const NEEDLE_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: test.hit\n",
    "    severity: error\n",
    "    message: pattern hit\n",
    "    regex:\n",
    "      pattern: 'n[e]edle'\n",
);

const BOUNDARY_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: arch.api-db\n",
    "    severity: error\n",
    "    message: api must not import db\n",
    "    boundary:\n",
    "      from: api\n",
    "      deny: [\"db\"]\n",
);

const COVERAGE_RULE: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: cov.min\n",
    "    severity: error\n",
    "    message: line coverage below threshold\n",
    "    coverage:\n",
    "      min: 80\n",
);

fn write(root: &Path, rel: &str, contents: &str) -> PathBuf {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, contents).unwrap();
    path
}

/// A rule directory holding one document, so a fixture can name the rules it
/// scans with instead of loading the 220-rule embedded pack.
fn rules_dir(root: &Path, name: &str, document: &str) -> PathBuf {
    let dir = root.join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("rules.yaml"), document).unwrap();
    dir
}

/// A tree with one matching file and a rule directory beside it.
fn fixture() -> (TempDir, PathBuf) {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "let x = \"needle\";\n");
    let rules = rules_dir(tree.path(), "rules", NEEDLE_RULE);
    (tree, rules)
}

fn request(root: &Path, rules: &Path) -> ScanRequest {
    ScanRequest::explicit(root)
        .without_embedded_rules()
        .with_rule_dirs(vec![rules.to_path_buf()])
}

fn run(request: &ScanRequest) -> ResolvedScanReport {
    ResolvedScanPlan::resolve(request)
        .expect("resolution")
        .execute(&mut |_| {})
        .expect("execution")
}

fn resolve_err(request: &ScanRequest) -> String {
    match ResolvedScanPlan::resolve(request) {
        Ok(_) => panic!("resolution was expected to fail"),
        Err(error) => error.to_string(),
    }
}

fn capability<'a>(setup: &'a ScanSetupReport, id: &str) -> &'a CapabilityState {
    setup
        .capabilities
        .iter()
        .find(|state| state.id() == id)
        .unwrap_or_else(|| panic!("no capability {id}"))
}

fn paths(report: &ResolvedScanReport) -> Vec<&str> {
    report
        .scan
        .findings
        .iter()
        .map(|finding| finding.path.as_str())
        .collect()
}

/// Serializes the tests that resolve an automatic request, which is the one
/// journey defined by the process working directory.
fn cwd_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// Plan and provenance
// ---------------------------------------------------------------------------

#[test]
fn an_omitted_path_and_an_explicit_dot_are_different_requests() {
    let automatic = ScanRequest::automatic();
    let explicit = ScanRequest::explicit(".");

    assert_eq!(automatic.root(), Path::new("."));
    assert_eq!(explicit.root(), Path::new("."));
    assert!(automatic.is_automatic());
    assert!(!explicit.is_automatic());
}

#[test]
fn an_automatic_request_resolves_the_working_directory_and_records_no_override() {
    let _guard = cwd_lock();
    let (tree, rules) = fixture();
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(tree.path()).unwrap();

    let plan = ResolvedScanPlan::resolve(&ScanRequest::automatic());

    std::env::set_current_dir(previous).unwrap();
    let report = plan
        .expect("resolution")
        .execute(&mut |_| {})
        .expect("execution");

    // The embedded pack is loaded because nothing asked for anything else, so
    // the one recorded fact is that nothing was supplied at all.
    assert!(report.setup.explicit_overrides.is_empty());
    assert!(!rules.join("rules.yaml").as_os_str().is_empty());
}

#[test]
fn an_explicit_path_is_recorded_as_an_override() {
    let (tree, rules) = fixture();
    let report = run(&request(tree.path(), &rules));

    assert_eq!(
        report.setup.explicit_overrides,
        vec![
            "no-default-rules".to_string(),
            "path".to_string(),
            "rules".to_string(),
        ]
    );
}

#[test]
fn a_supplied_option_is_recorded_even_when_its_value_is_the_default() {
    let (tree, rules) = fixture();
    let request = request(tree.path(), &rules)
        .with_ignore_options(IgnoreOptions::default())
        .with_cache_dir(tree.path().join(".siloscan"));
    let report = run(&request);

    assert!(
        report
            .setup
            .explicit_overrides
            .contains(&"ignore".to_string())
    );
    assert!(
        report
            .setup
            .explicit_overrides
            .contains(&"cache-dir".to_string())
    );
}

#[test]
fn resolution_owns_the_rule_set_the_baseline_the_cache_and_the_project_facts() {
    let (tree, rules) = fixture();
    write(
        tree.path(),
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    );
    let report = run(&request(tree.path(), &rules));

    assert_eq!(
        report.setup.rule_sources[0].id,
        "rules/rules.yaml".to_string()
    );
    assert_eq!(report.setup.rule_sources[0].origin, "directory".to_string());
    assert!(report.setup.languages.contains(&"rust".to_string()));
    assert!(
        report
            .setup
            .units
            .iter()
            .any(|unit| unit.ecosystem == "rust")
    );
    assert_eq!(
        capability(&report.setup, "project-detection").status(),
        &CapabilityStatus::Enabled
    );
    assert_eq!(
        capability(&report.setup, "cache").status(),
        &CapabilityStatus::Enabled
    );
    assert_eq!(paths(&report), vec!["src/a.rs"]);
}

#[test]
fn the_embedded_pack_reports_its_published_identity() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "fn main() {}\n");
    let report = run(&ScanRequest::explicit(tree.path()));

    let embedded: Vec<&str> = report
        .setup
        .rule_sources
        .iter()
        .filter(|source| source.origin == "embedded")
        .map(|source| source.id.as_str())
        .collect();
    assert_eq!(embedded, vec![EMBEDDED_PACK_ID]);
    assert_eq!(EMBEDDED_PACK_ID, "default-secrets@1");
}

#[test]
fn the_output_context_carries_the_rules_config_and_anchoring_a_writer_needs() {
    let (tree, rules) = fixture();
    let report = run(&request(tree.path(), &rules));
    let context = report.context();

    assert_eq!(context.scan_root(), tree.path());
    assert_eq!(context.baseline_root(), tree.path());
    assert_eq!(context.rules().rules.len(), 1);
    assert!(context.config().is_none());
    assert_eq!(context.anchoring().prefix(), "");
}

// ---------------------------------------------------------------------------
// Override precedence
// ---------------------------------------------------------------------------

#[test]
fn an_explicit_config_replaces_the_discovered_one() {
    let (tree, discovered) = fixture();
    let alternate = rules_dir(tree.path(), "alternate", NEEDLE_RULE);
    write(
        tree.path(),
        "siloscan.toml",
        &format!("rules = [{:?}]\n", discovered.file_name().unwrap()),
    );
    write(
        tree.path(),
        "explicit.toml",
        &format!("rules = [{:?}]\n", alternate.file_name().unwrap()),
    );

    let report = run(&ScanRequest::explicit(tree.path())
        .without_embedded_rules()
        .with_config(tree.path().join("explicit.toml")));

    let ids: Vec<&str> = report
        .setup
        .rule_sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    assert_eq!(ids, vec!["alternate/rules.yaml"]);
}

#[test]
fn config_rule_directories_load_beside_the_command_line_ones() {
    let (tree, command_line) = fixture();
    let from_config = rules_dir(
        tree.path(),
        "from-config",
        &NEEDLE_RULE.replace("test.hit", "test.other"),
    );
    write(
        tree.path(),
        "siloscan.toml",
        &format!("rules = [{:?}]\n", from_config.file_name().unwrap()),
    );

    let report = run(&request(tree.path(), &command_line));

    // The loader sorts the files it finds bytewise across every directory, so
    // the directory order decides which one a duplicate id is reported against
    // and not the order the documents appear in.
    let ids: Vec<&str> = report
        .setup
        .rule_sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    assert_eq!(ids, vec!["from-config/rules.yaml", "rules/rules.yaml"]);
    assert_eq!(report.context().rules().rules.len(), 2);
}

#[test]
fn disabling_the_cache_beats_naming_a_cache_directory() {
    let (tree, rules) = fixture();
    let request = request(tree.path(), &rules)
        .with_cache_dir(tree.path().join("cache"))
        .without_cache();
    let report = run(&request);

    let cache = capability(&report.setup, "cache");
    assert_eq!(cache.status(), &CapabilityStatus::Skipped);
    assert_eq!(cache.reason(), Some("the cache is disabled for this scan"));
    assert!(!tree.path().join("cache").exists());
}

#[test]
fn every_capability_that_is_not_enabled_says_why() {
    let (tree, rules) = fixture();
    let report = run(&request(tree.path(), &rules));

    assert!(!report.setup.capabilities.is_empty());
    for state in &report.setup.capabilities {
        match state.status() {
            CapabilityStatus::Enabled => assert_eq!(state.reason(), None, "{}", state.id()),
            _ => assert!(state.reason().is_some(), "{}", state.id()),
        }
    }
    assert_eq!(
        capability(&report.setup, "embedded-rules").status(),
        &CapabilityStatus::Skipped
    );
    assert_eq!(
        capability(&report.setup, "repository-config").status(),
        &CapabilityStatus::NotConfigured
    );
    assert_eq!(
        capability(&report.setup, "scan-baseline").status(),
        &CapabilityStatus::NotConfigured
    );
    assert_eq!(
        capability(&report.setup, "symlink-following").status(),
        &CapabilityStatus::NotConfigured
    );
}

// ---------------------------------------------------------------------------
// One walk
// ---------------------------------------------------------------------------

#[test]
fn execution_scans_the_inventory_resolution_admitted_and_walks_nothing_again() {
    let (tree, rules) = fixture();
    let plan = ResolvedScanPlan::resolve(&request(tree.path(), &rules)).expect("resolution");

    // Added after the walk. A second traversal at execution time would find it.
    write(tree.path(), "src/late.rs", "let y = \"needle\";\n");

    let report = plan.execute(&mut |_| {}).expect("execution");
    assert_eq!(paths(&report), vec!["src/a.rs"]);
}

#[test]
fn a_fresh_plan_sees_what_the_previous_plan_could_not() {
    let (tree, rules) = fixture();
    let first = ResolvedScanPlan::resolve(&request(tree.path(), &rules)).expect("resolution");
    write(tree.path(), "src/late.rs", "let y = \"needle\";\n");
    let second = ResolvedScanPlan::resolve(&request(tree.path(), &rules)).expect("resolution");

    assert_eq!(
        paths(&first.execute(&mut |_| {}).unwrap()),
        vec!["src/a.rs"]
    );
    assert_eq!(
        paths(&second.execute(&mut |_| {}).unwrap()),
        vec!["src/a.rs", "src/late.rs"]
    );
}

#[test]
fn detection_reads_the_same_inventory_the_engines_scan() {
    let (tree, rules) = fixture();
    let plan = ResolvedScanPlan::resolve(&request(tree.path(), &rules)).expect("resolution");
    let languages = plan.setup().languages.clone();
    let report = plan.execute(&mut |_| {}).expect("execution");

    assert_eq!(languages, report.setup.languages);
    for path in report.setup.source_roots.iter().map(|hint| &hint.path) {
        assert!(!path.contains('\\'), "{path}");
    }
}

// ---------------------------------------------------------------------------
// Setup failures
// ---------------------------------------------------------------------------

#[test]
fn a_missing_root_fails_resolution() {
    let tree = tempfile::tempdir().unwrap();
    let error = resolve_err(&ScanRequest::explicit(tree.path().join("absent")));
    assert!(error.contains("absent"), "{error}");
}

#[test]
fn a_malformed_config_fails_resolution() {
    let (tree, rules) = fixture();
    write(tree.path(), "siloscan.toml", "silos = \n");

    let error = resolve_err(&request(tree.path(), &rules));
    assert!(error.contains("siloscan.toml"), "{error}");
}

#[test]
fn loading_no_rules_at_all_fails_resolution() {
    let (tree, _rules) = fixture();
    let error = resolve_err(&ScanRequest::explicit(tree.path()).without_embedded_rules());
    assert!(error.starts_with("no rules loaded"), "{error}");
}

#[test]
fn a_boundary_rule_without_silos_fails_resolution() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "fn main() {}\n");
    let rules = rules_dir(tree.path(), "rules", BOUNDARY_RULE);

    let error = resolve_err(&request(tree.path(), &rules));
    assert!(error.contains("[silos]"), "{error}");
}

#[test]
fn a_coverage_rule_without_a_report_fails_resolution() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "fn main() {}\n");
    let rules = rules_dir(tree.path(), "rules", COVERAGE_RULE);

    let error = resolve_err(&request(tree.path(), &rules));
    assert!(!error.is_empty());
}

#[test]
fn an_unsupported_baseline_version_fails_resolution() {
    let (tree, rules) = fixture();
    let baseline = write(
        tree.path(),
        "baseline.json",
        "{\"version\":2,\"entries\":[]}",
    );

    let error = resolve_err(&request(tree.path(), &rules).with_baseline(baseline));
    assert!(error.contains("unsupported baseline version 2"), "{error}");
}

#[test]
fn an_anchor_that_cannot_be_honoured_fails_resolution() {
    let (tree, rules) = fixture();
    let elsewhere = tempfile::tempdir().unwrap();
    let config = write(elsewhere.path(), "siloscan.toml", "anchor = \"config\"\n");

    // The config measures every path from its own directory, which does not
    // contain the scan root.
    let error = resolve_err(&request(tree.path(), &rules).with_config(config));
    assert!(error.contains("anchor"), "{error}");
}

// ---------------------------------------------------------------------------
// Deterministic order
// ---------------------------------------------------------------------------

#[test]
fn two_resolutions_of_one_tree_produce_the_same_setup() {
    let tree = tempfile::tempdir().unwrap();
    write(
        tree.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n",
    );
    write(
        tree.path(),
        "crates/a/Cargo.toml",
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
    );
    write(
        tree.path(),
        "crates/b/Cargo.toml",
        "[package]\nname = \"b\"\nversion = \"0.1.0\"\n",
    );
    write(tree.path(), "package.json", "{\"name\":\"web\"}\n");
    write(tree.path(), "crates/a/src/lib.rs", "pub fn a() {}\n");
    let rules = rules_dir(tree.path(), "rules", NEEDLE_RULE);

    let first = run(&request(tree.path(), &rules));
    let second = run(&request(tree.path(), &rules));

    let render = |setup: &ScanSetupReport| siloscan_core::serde_json::to_string(setup).unwrap();
    assert_eq!(render(&first.setup), render(&second.setup));
}

#[test]
fn setup_facts_are_sorted_and_relative() {
    let tree = tempfile::tempdir().unwrap();
    write(
        tree.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/b\", \"crates/a\"]\n",
    );
    for name in ["a", "b"] {
        write(
            tree.path(),
            &format!("crates/{name}/Cargo.toml"),
            &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n"),
        );
    }
    let rules = rules_dir(tree.path(), "rules", NEEDLE_RULE);
    let report = run(&request(tree.path(), &rules));

    let evidence: Vec<&str> = report
        .setup
        .evidence
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    let mut sorted = evidence.clone();
    sorted.sort_unstable();
    assert_eq!(evidence, sorted);
    for path in &evidence {
        assert!(!path.starts_with('/'), "{path}");
        assert!(!path.contains('\\'), "{path}");
    }

    let ids: Vec<&str> = report
        .setup
        .capabilities
        .iter()
        .map(CapabilityState::id)
        .collect();
    let mut sorted_ids = ids.clone();
    sorted_ids.sort_unstable();
    assert_eq!(ids, sorted_ids);
}

// ---------------------------------------------------------------------------
// Setup microfixtures
// ---------------------------------------------------------------------------

#[test]
fn a_config_anchored_nested_module_reports_from_the_config_root() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), ".git/HEAD", "ref: refs/heads/main\n");
    write(
        tree.path(),
        "siloscan.toml",
        "anchor = \"config\"\ninclude = [\"modules/api/siloscan.toml\"]\n",
    );
    write(tree.path(), "modules/api/siloscan.toml", "");
    write(tree.path(), "modules/api/src/a.rs", "let x = \"needle\";\n");
    let rules = rules_dir(tree.path(), "rules", NEEDLE_RULE);

    let report = run(&request(&tree.path().join("modules/api"), &rules));

    assert_eq!(paths(&report), vec!["modules/api/src/a.rs"]);
    assert_eq!(report.context().anchoring().prefix(), "modules/api");
    assert_eq!(report.context().baseline_root(), tree.path());
}

#[test]
fn a_single_file_scope_scans_that_file_alone() {
    let (tree, rules) = fixture();
    write(tree.path(), "src/b.rs", "let y = \"needle\";\n");

    let report = run(&request(&tree.path().join("src/a.rs"), &rules));
    assert_eq!(paths(&report), vec!["a.rs"]);
}

#[test]
fn a_missing_config_is_not_a_failure() {
    let (tree, rules) = fixture();
    let report = run(&request(tree.path(), &rules));

    assert!(report.context().config().is_none());
    assert_eq!(
        capability(&report.setup, "repository-config").reason(),
        Some("no repository config applies to this scan root")
    );
}

#[test]
fn ignore_sources_decide_what_the_one_walk_admits() {
    let (tree, rules) = fixture();
    write(tree.path(), ".gitignore", "src/hidden.rs\n");
    write(tree.path(), "src/hidden.rs", "let z = \"needle\";\n");

    let honoured = run(&request(tree.path(), &rules));
    assert_eq!(paths(&honoured), vec!["src/a.rs"]);
    assert!(honoured.scan.ignored.files > 0);

    let ignored = run(
        &request(tree.path(), &rules).with_ignore_options(IgnoreOptions {
            respect_gitignore: false,
            ..IgnoreOptions::default()
        }),
    );
    assert_eq!(paths(&ignored), vec!["src/a.rs", "src/hidden.rs"]);
}

#[test]
fn a_binary_file_is_skipped_with_a_reason() {
    let (tree, rules) = fixture();
    fs::write(tree.path().join("src/blob.bin"), [0x6e, 0x00, 0x6f, 0x21]).unwrap();

    let report = run(&request(tree.path(), &rules));
    let skipped = report
        .scan
        .skipped
        .iter()
        .find(|file| file.path == "src/blob.bin")
        .expect("binary file recorded");
    assert!(skipped.reason.contains("binary"), "{}", skipped.reason);
}

#[cfg(unix)]
#[test]
fn an_in_root_symlink_names_a_file_the_scan_already_read() {
    let (tree, rules) = fixture();
    std::os::unix::fs::symlink(
        tree.path().join("src/a.rs"),
        tree.path().join("src/link.rs"),
    )
    .unwrap();

    let report = run(&request(tree.path(), &rules));
    assert_eq!(paths(&report), vec!["src/a.rs"]);
    assert!(
        !report
            .scan
            .skipped
            .iter()
            .any(|file| file.path == "src/link.rs")
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_scan_root_is_refused_and_recorded() {
    let (tree, rules) = fixture();
    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), "secret.rs", "let q = \"needle\";\n");
    std::os::unix::fs::symlink(
        outside.path().join("secret.rs"),
        tree.path().join("src/outside.rs"),
    )
    .unwrap();

    let report = run(&request(tree.path(), &rules));
    assert_eq!(paths(&report), vec!["src/a.rs"]);
    assert!(
        report
            .scan
            .skipped
            .iter()
            .any(|file| file.path == "src/outside.rs"),
        "{:?}",
        report.scan.skipped
    );
}

#[test]
fn a_generic_tree_reports_generic_detection_without_failing() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "notes.txt", "nothing here\n");
    let rules = rules_dir(tree.path(), "rules", NEEDLE_RULE);

    let plan = ResolvedScanPlan::resolve(&request(tree.path(), &rules)).expect("resolution");
    assert!(plan.setup().units.is_empty());
    assert_eq!(
        capability(plan.setup(), "project-detection").status(),
        &CapabilityStatus::NotConfigured
    );
    assert_eq!(
        siloscan_core::project::detect(
            tree.path(),
            &siloscan_core::walk::collect_files_counted_with(
                tree.path(),
                &siloscan_core::walk::WalkOptions::new(&IgnoreOptions::default()),
            ),
            None,
        )
        .status,
        DetectionStatus::Generic
    );
}
