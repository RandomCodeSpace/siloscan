//! The core resolved plan: what a request preserves, what resolution owns, and
//! that the scope is walked exactly once.

use siloscan_core::plan::{
    CapabilityState, CapabilityStatus, EMBEDDED_PACK_ID, ResolvedScanPlan, ResolvedScanReport,
    ScanRequest, ScanSetupReport,
};
use siloscan_core::profiles::{Profile, ProfileSelection};
use siloscan_core::project::DetectionStatus;
use siloscan_core::walk::IgnoreOptions;
use std::fs;
use std::path::{Path, PathBuf};
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

// ---------------------------------------------------------------------------
// Plan and provenance
// ---------------------------------------------------------------------------

/// The automatic journey is the one defined by the process working directory,
/// so it is asserted on the request rather than by moving the test process:
/// both requests name `.`, and only the provenance separates them.
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

    // Reported by id, not in load order. Load order follows the absolute paths
    // the loader opened, which differ per host - a config-declared directory
    // arrives canonicalised and a `--rules` one does not - so a literal here
    // would only be true on the machine that wrote it.
    let ids: Vec<&str> = report
        .setup
        .rule_sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    assert_eq!(ids, vec!["from-config/rules.yaml", "rules/rules.yaml"]);
    assert_eq!(report.context().rules().rules.len(), 2);
}

/// Whichever order the two are supplied in. v1 checks `--no-cache` first and
/// unconditionally, so a request carrying both has no cache either way.
#[test]
fn disabling_the_cache_beats_naming_a_cache_directory_in_either_order() {
    let (tree, rules) = fixture();
    let cache_dir = tree.path().join("cache");

    let directory_first = run(&request(tree.path(), &rules)
        .with_cache_dir(cache_dir.clone())
        .without_cache());
    let disabled_first = run(&request(tree.path(), &rules)
        .without_cache()
        .with_cache_dir(cache_dir.clone()));

    for report in [&directory_first, &disabled_first] {
        let cache = capability(&report.setup, "cache");
        assert_eq!(cache.status(), &CapabilityStatus::Skipped);
        assert_eq!(cache.reason(), Some("the cache is disabled for this scan"));
    }
    assert!(!cache_dir.exists());
}

/// A cache that opened but can never hold an entry is not an enabled cache.
/// The scan is correct and permanently cold, and only the report can say so.
#[cfg(unix)]
#[test]
fn an_unusable_cache_directory_is_unavailable_rather_than_enabled() {
    let (tree, rules) = fixture();
    // A regular file stands where the cache directory's parent would be, so
    // every path below it is refused rather than created.
    let blocked = write(tree.path(), "blocked", "not a directory\n");

    let report = run(&request(tree.path(), &rules).with_cache_dir(blocked.join("nested")));

    let cache = capability(&report.setup, "cache");
    assert_eq!(cache.status(), &CapabilityStatus::Unavailable);
    assert_eq!(
        cache.reason(),
        Some("the cache directory is not this user's or could not be secured")
    );
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
// Profile selection
// ---------------------------------------------------------------------------

/// Three profile documents standing in for the shipped registry, which is
/// empty: two languages, two families, distinct rule ids so the union check
/// still means something. The patterns are written so that no document matches
/// the fixture tree, because what is under test is which documents load and
/// not what they report.
const RELIABILITY_RUST: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: reliability.rust.probe\n",
    "    severity: warning\n",
    "    message: reliability probe\n",
    "    regex:\n",
    "      pattern: 'rust-r[e]liability-probe'\n",
);

const MAINTAINABILITY_RUST: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: maintainability.rust.probe\n",
    "    severity: warning\n",
    "    message: maintainability probe\n",
    "    regex:\n",
    "      pattern: 'rust-m[a]intainability-probe'\n",
);

const RELIABILITY_GO: &str = concat!(
    "version: 1\n",
    "rules:\n",
    "  - id: reliability.go.probe\n",
    "    severity: warning\n",
    "    message: reliability probe\n",
    "    regex:\n",
    "      pattern: 'go-r[e]liability-probe'\n",
);

static TEST_PROFILES: &[Profile] = &[
    Profile::new("maintainability-rust@1", "rust", MAINTAINABILITY_RUST),
    Profile::new("reliability-go@1", "go", RELIABILITY_GO),
    Profile::new("reliability-rust@1", "rust", RELIABILITY_RUST),
];

/// A profile carrying a rule whose preconditions the tree does not meet. The
/// gates that refuse it are the ones the append has to run in front of.
static GATED_PROFILES: &[Profile] = &[
    Profile::new("boundary-rust@1", "rust", BOUNDARY_RULE),
    Profile::new("coverage-rust@1", "rust", COVERAGE_RULE),
];

/// Two documents claiming one rule id. Neither loader sees the other, so only
/// the check over the union can refuse this.
static COLLIDING_PROFILES: &[Profile] = &[
    Profile::new("maintainability-rust@1", "rust", RELIABILITY_RUST),
    Profile::new("reliability-rust@1", "rust", RELIABILITY_RUST),
];

/// A document that is not a document. Shipped profiles are `include_str!` of
/// files in this repository, so this is a build mistake rather than user input
/// - which is exactly why the failure has to name the profile that caused it.
static BROKEN_PROFILES: &[Profile] = &[Profile::new(
    "reliability-rust@1",
    "rust",
    "version: 1\nrules: [\n",
)];

/// A request that loads the embedded pack, so the profile entries can be seen
/// in the company of the entry they are ordered against.
fn profile_request(root: &Path, rules: &Path) -> ScanRequest {
    ScanRequest::explicit(root)
        .with_rule_dirs(vec![rules.to_path_buf()])
        .with_profile_registry(TEST_PROFILES)
}

fn setup_of(request: &ScanRequest) -> ScanSetupReport {
    ResolvedScanPlan::resolve(request)
        .expect("resolution")
        .setup()
        .clone()
}

fn source_ids(setup: &ScanSetupReport) -> Vec<&str> {
    setup
        .rule_sources
        .iter()
        .map(|source| source.id.as_str())
        .collect()
}

fn has_capability(setup: &ScanSetupReport, id: &str) -> bool {
    setup.capabilities.iter().any(|state| state.id() == id)
}

/// The default, and the reason every existing report is byte-identical:
/// nothing is selected and the capability is not reported at all, so no line
/// and no document gains a clause. The provenance decides nothing here yet,
/// which is the whole amendment - a registry full of documents that a
/// `--profiles` nobody supplied still loads none of them.
#[test]
fn profile_selection_defaults_to_none() {
    let (tree, rules) = fixture();
    let setup = setup_of(&profile_request(tree.path(), &rules));

    assert_eq!(source_ids(&setup), [EMBEDDED_PACK_ID, "rules/rules.yaml"]);
    assert!(!has_capability(&setup, "profiles"));
    assert!(!setup.explicit_overrides.contains(&"profiles".to_string()));
}

/// An empty list named nothing, which is a fact about the request and not
/// about the tree. Saying no language had a document would send a reader
/// looking at their `.rs` files for the answer.
#[test]
fn an_empty_name_list_says_nothing_was_named() {
    let (tree, rules) = fixture();
    let setup = setup_of(
        &profile_request(tree.path(), &rules).with_profiles(ProfileSelection::Named(Vec::new())),
    );

    assert_eq!(
        capability(&setup, "profiles").status(),
        &CapabilityStatus::NotConfigured
    );
    assert_eq!(
        capability(&setup, "profiles").reason(),
        Some("no profile was named")
    );
}

/// The shipped registry holds no document, so `auto` on a tree the detector
/// reads perfectly well still loads nothing.
#[test]
fn auto_against_the_shipped_registry_selects_nothing() {
    let (tree, rules) = fixture();
    let setup = setup_of(
        &ScanRequest::explicit(tree.path())
            .with_rule_dirs(vec![rules.clone()])
            .with_profiles(ProfileSelection::Auto),
    );

    assert_eq!(setup.languages, ["rust"]);
    assert_eq!(source_ids(&setup), [EMBEDDED_PACK_ID, "rules/rules.yaml"]);
    assert_eq!(
        capability(&setup, "profiles").status(),
        &CapabilityStatus::NotConfigured
    );
    assert_eq!(
        capability(&setup, "profiles").reason(),
        Some("no detected language has an embedded profile")
    );
}

/// `auto` is detection ∩ registry, which is what keeps a Rust tree from
/// parsing Go. The fixture holds one `.rs` file and no `.go` file, so the two
/// Rust documents load and the Go one does not.
#[test]
fn auto_selects_the_documents_of_the_detected_languages() {
    let (tree, rules) = fixture();
    let setup =
        setup_of(&profile_request(tree.path(), &rules).with_profiles(ProfileSelection::Auto));

    assert_eq!(setup.languages, ["rust"]);
    assert_eq!(
        source_ids(&setup),
        [
            EMBEDDED_PACK_ID,
            "maintainability-rust@1",
            "reliability-rust@1",
            "rules/rules.yaml",
        ]
    );
    assert_eq!(
        capability(&setup, "profiles").status(),
        &CapabilityStatus::Enabled
    );
}

/// Every embedded source is reported before every directory one, and each
/// group by its own id, whatever order the documents were loaded in. The
/// profile documents load last and sort into the middle.
#[test]
fn profile_sources_are_reported_as_embedded_and_in_id_order() {
    let (tree, rules) = fixture();
    let setup = setup_of(&profile_request(tree.path(), &rules).with_profiles(
        ProfileSelection::Named(vec![
            "reliability-rust@1".to_string(),
            "maintainability-rust@1".to_string(),
        ]),
    ));

    let origins: Vec<&str> = setup
        .rule_sources
        .iter()
        .map(|source| source.origin.as_str())
        .collect();
    assert_eq!(origins, ["embedded", "embedded", "embedded", "directory"]);
    assert_eq!(
        source_ids(&setup),
        [
            EMBEDDED_PACK_ID,
            "maintainability-rust@1",
            "reliability-rust@1",
            "rules/rules.yaml",
        ]
    );
}

/// A named profile deliberately ignores detection: the fixture holds no Go
/// file, and a caller that named the Go profile asked for it.
#[test]
fn a_named_profile_ignores_detection() {
    let (tree, rules) = fixture();
    let setup = setup_of(&profile_request(tree.path(), &rules).with_profiles(
        ProfileSelection::Named(vec!["reliability-go@1".to_string()]),
    ));

    assert_eq!(setup.languages, ["rust"]);
    assert_eq!(
        source_ids(&setup),
        [EMBEDDED_PACK_ID, "reliability-go@1", "rules/rules.yaml"]
    );
    assert!(setup.explicit_overrides.contains(&"profiles".to_string()));
}

/// Loading nothing for a name the caller supplied would be the clean scan that
/// proved nothing, so it is a refusal that says what is available instead.
#[test]
fn a_named_profile_with_no_document_is_a_resolve_error() {
    let (tree, rules) = fixture();
    let error = resolve_err(&profile_request(tree.path(), &rules).with_profiles(
        ProfileSelection::Named(vec!["reliability-elixir@1".to_string()]),
    ));

    assert_eq!(
        error,
        "unknown profile: reliability-elixir@1; available: \
         maintainability-rust@1, reliability-go@1, reliability-rust@1"
    );
}

/// `--no-default-rules` means every embedded document, not just the pack. A
/// flag that left the profiles loaded would mean something else under the same
/// spelling.
#[test]
fn no_default_rules_suppresses_the_profiles_too() {
    let (tree, rules) = fixture();
    let setup = setup_of(
        &profile_request(tree.path(), &rules)
            .without_embedded_rules()
            .with_profiles(ProfileSelection::Auto),
    );

    assert_eq!(source_ids(&setup), ["rules/rules.yaml"]);
    assert_eq!(
        capability(&setup, "profiles").status(),
        &CapabilityStatus::Skipped
    );

    // And it wins over a name, which detection never gets a say in either.
    let named = setup_of(
        &profile_request(tree.path(), &rules)
            .without_embedded_rules()
            .with_profiles(ProfileSelection::Named(vec![
                "reliability-go@1".to_string(),
            ])),
    );
    assert_eq!(source_ids(&named), ["rules/rules.yaml"]);

    // Suppressing the documents does not stop the names being resolved. A
    // misspelling accepted here and refused on the next run without the flag
    // is the worse half of both answers.
    let error = resolve_err(
        &profile_request(tree.path(), &rules)
            .without_embedded_rules()
            .with_profiles(ProfileSelection::Named(vec![
                "reliability-elixir@1".to_string(),
            ])),
    );
    assert!(
        error.starts_with("unknown profile: reliability-elixir@1;"),
        "{error}"
    );
}

/// The rules a profile document declares are in the set the scan runs and the
/// digest the cache keys on, not in a side channel.
#[test]
fn a_selected_profile_contributes_its_rules_to_the_scan() {
    let tree = tempfile::tempdir().unwrap();
    write(
        tree.path(),
        "src/a.rs",
        "let x = \"rust-reliability-probe\";\n",
    );
    let rules_only = rules_dir(tree.path(), "rules", NEEDLE_RULE);
    let report = run(&ScanRequest::explicit(tree.path())
        .with_rule_dirs(vec![rules_only.clone()])
        .with_profile_registry(TEST_PROFILES)
        .with_profiles(ProfileSelection::Named(vec![
            "reliability-rust@1".to_string(),
        ])));

    let ids: Vec<&str> = report
        .scan
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert_eq!(ids, ["reliability.rust.probe"]);

    // The same tree without the profile. Its rule digest has to differ, or a
    // warm cache written by one of these two runs would be served to the
    // other - findings from a rule set that is not the one that produced them.
    let bare = run(&ScanRequest::explicit(tree.path()).with_rule_dirs(vec![rules_only]));
    assert!(bare.scan.findings.is_empty());
    assert_ne!(
        report.context().rules().source_hash(),
        bare.context().rules().source_hash()
    );
}

/// Every gate the scanner runs before it scans has to see the profile
/// documents, or a rule that arrived in one bypasses the check that makes it
/// mean anything and reports nothing at all. A boundary rule is the case with
/// its own refusal: the same document in a `--rules` directory fails
/// resolution, and it has to fail identically here.
#[test]
fn a_profile_carrying_a_boundary_rule_without_silos_fails_resolution() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "fn main() {}\n");
    let rules = rules_dir(tree.path(), "rules", NEEDLE_RULE);
    let error = resolve_err(
        &ScanRequest::explicit(tree.path())
            .with_rule_dirs(vec![rules])
            .with_profile_registry(GATED_PROFILES)
            .with_profiles(ProfileSelection::Named(vec!["boundary-rust@1".to_string()])),
    );

    assert!(error.contains("[silos]"), "{error}");
    assert!(error.contains("arch.api-db"), "{error}");
}

/// The same statement for the gate on the other side of the walk: a coverage
/// rule with no report is refused whichever document carried it.
#[test]
fn a_profile_carrying_a_coverage_rule_without_a_report_fails_resolution() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "fn main() {}\n");
    let rules = rules_dir(tree.path(), "rules", NEEDLE_RULE);
    let error = resolve_err(
        &ScanRequest::explicit(tree.path())
            .with_rule_dirs(vec![rules])
            .with_profile_registry(GATED_PROFILES)
            .with_profiles(ProfileSelection::Named(vec!["coverage-rust@1".to_string()])),
    );

    assert!(error.contains("cov.min"), "{error}");
}

/// Two profiles claiming one rule id. Each document loads on its own, so this
/// is only visible over the union.
#[test]
fn two_profiles_claiming_one_rule_id_are_refused() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "let x = 1;\n");
    let error = resolve_err(
        &ScanRequest::explicit(tree.path())
            .with_profile_registry(COLLIDING_PROFILES)
            .with_profiles(ProfileSelection::Auto),
    );

    assert_eq!(error, "duplicate rule id: reliability.rust.probe");
}

/// A profile document is shipped, not supplied, so one that does not parse is
/// a build mistake - and the failure has to name which document it was.
#[test]
fn a_profile_document_that_does_not_parse_names_the_profile() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "let x = 1;\n");
    let error = resolve_err(
        &ScanRequest::explicit(tree.path())
            .with_profile_registry(BROKEN_PROFILES)
            .with_profiles(ProfileSelection::Auto),
    );

    assert!(error.starts_with("reliability-rust@1: "), "{error}");
}

/// A rule directory that claims a profile's id is the same refusal a directory
/// claiming the pack's id already is - which is why the check has to run again
/// after the profiles are appended.
#[test]
fn a_rule_directory_colliding_with_a_profile_id_is_refused() {
    let tree = tempfile::tempdir().unwrap();
    write(tree.path(), "src/a.rs", "let x = 1;\n");
    let rules = rules_dir(tree.path(), "rules", RELIABILITY_RUST);
    let error = resolve_err(
        &ScanRequest::explicit(tree.path())
            .with_rule_dirs(vec![rules])
            .with_profile_registry(TEST_PROFILES)
            .with_profiles(ProfileSelection::Named(vec![
                "reliability-rust@1".to_string(),
            ])),
    );

    assert_eq!(error, "duplicate rule id: reliability.rust.probe");
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

/// A manifest is arbitrary bytes from the scanned tree. Resolution must survive
/// one that is malformed in the middle of a multi-byte character, and the setup
/// report must say where the parser stopped without quoting what it read.
#[test]
fn a_malformed_non_ascii_manifest_neither_panics_nor_reaches_the_report() {
    let (tree, rules) = fixture();
    let secret_line = "描述 = \"クレデンシャル ‚‚‚ ünïcödé påyload\" this is not toml";
    let manifest = format!(
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n# {}\n{secret_line}\n",
        "é".repeat(300)
    );
    write(tree.path(), "Cargo.toml", &manifest);

    let report = run(&request(tree.path(), &rules));
    let setup = siloscan_core::serde_json::to_string(&report.setup).unwrap();

    let invalid: Vec<&String> = report
        .setup
        .evidence
        .iter()
        .filter(|item| item.path == "Cargo.toml")
        .flat_map(|item| item.reasons.iter())
        .collect();
    assert!(
        invalid
            .iter()
            .any(|reason| reason.starts_with("invalid TOML at line")),
        "{invalid:?}"
    );
    for fragment in ["描述", "クレデンシャル", "påyload", "ééé"] {
        assert!(!setup.contains(fragment), "{fragment} reached the report");
    }
}

/// The root's spelling belongs to the caller, not to the report: `siloscan .`
/// and `siloscan /abs/repo` describe one tree and must produce one document.
#[test]
fn relative_and_absolute_root_spellings_produce_the_same_setup() {
    let (tree, rules) = fixture();
    let relative = pathdiff(tree.path());

    let absolute = run(&request(tree.path(), &rules));
    let spelled = run(&request(&relative, &rules));

    let render = |setup: &ScanSetupReport| siloscan_core::serde_json::to_string(setup).unwrap();
    assert_eq!(render(&absolute.setup), render(&spelled.setup));
    assert_eq!(
        absolute.setup.rule_sources[0].id,
        "rules/rules.yaml".to_string()
    );
}

/// The same tree named through a path that walks back out and in again. Not a
/// relative path - the test process' working directory is not this test's to
/// change - but a spelling `strip_prefix` cannot match textually.
fn pathdiff(tree: &Path) -> PathBuf {
    tree.join("src").join("..")
}

#[test]
fn two_rule_directories_holding_one_file_name_stay_distinguishable() {
    let (tree, first) = fixture();
    let outside = tempfile::tempdir().unwrap();
    let second = rules_dir(
        outside.path(),
        "extra",
        &NEEDLE_RULE.replace("test.hit", "test.other"),
    );

    let report = run(&ScanRequest::explicit(tree.path())
        .without_embedded_rules()
        .with_rule_dirs(vec![first, second]));

    let ids: Vec<&str> = report
        .setup
        .rule_sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    assert!(ids.contains(&"rules/rules.yaml"), "{ids:?}");
    assert!(ids.contains(&"extra/rules.yaml"), "{ids:?}");
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

/// The context reports the paths the caller asked for, not the paths the file
/// system would rather call them.
///
/// Config discovery canonicalises before it walks, so the loaded config knows
/// the link target and the long name; neither is what the caller typed. Both
/// accessors here have to echo the request, including through
/// `anchor = "config"`, where the baseline root is an ancestor of the scan root
/// and the config is the only thing that knows where it is.
#[cfg(unix)]
#[test]
fn the_context_echoes_the_requested_spelling_of_every_path() {
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

    let elsewhere = tempfile::tempdir().unwrap();
    let link = elsewhere.path().join("repo");
    std::os::unix::fs::symlink(tree.path(), &link).unwrap();
    let module = link.join("modules/api");

    let plain = run(&request(&link, &rules));
    assert_eq!(plain.context().scan_root(), link);
    assert_eq!(plain.context().baseline_root(), link);

    let nested = run(&request(&module, &rules));
    assert_eq!(nested.context().scan_root(), module);
    assert_eq!(nested.context().baseline_root(), link);
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
