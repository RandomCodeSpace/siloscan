//! One scan plan, one admitted inventory.
//!
//! A scan needs more than a root and a rule set: a config has to be discovered
//! or loaded, rules assembled, an anchor resolved, a baseline found, a cache
//! opened, the tree walked, and project evidence read off what the walk
//! admitted. Every front end used to do that itself, which is how the CLI and
//! the TUI came to hold two copies of the same policy and how detection would
//! have walked the tree a second time.
//!
//! This module owns that work exactly once:
//!
//! - [`ScanRequest`] is what the caller asked for, with its provenance intact.
//!   An omitted `PATH` and an explicit `.` are different requests, and every
//!   supplied option is recorded even when its value equals the default.
//! - [`ResolvedScanPlan::resolve`] performs the whole setup and the one walk.
//!   It fails with the wording the setup step itself produced.
//! - [`ResolvedScanPlan::execute`] derives a temporary [`ScanOptions`] and hands
//!   the owned inventory to the existing scanner. The plan never stores
//!   `ScanOptions`, and nothing walks the root twice.
//! - [`ResolvedScanReport`] carries the unchanged [`ScanReport`], the
//!   deterministic [`ScanSetupReport`], and an opaque [`ScanOutputContext`] with
//!   the rules, config and anchoring a writer needs.
//!
//! [`write_resolved_json`] is the schema 1.2 resolved document: the legacy
//! projection, byte for byte, with `report_kind`, `scope`, `outcome` and
//! `setup` appended in that order.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use globset::GlobSet;
use serde::Serialize;

use crate::baseline::{self, Baseline};
use crate::cache::{Cache, PathScope};
use crate::config::{self, Anchor, Config};
use crate::coverage::CoverageReport;
use crate::default_pack;
use crate::project::{
    self, DetectionStatus, Evidence, ProjectUnit, SourceRootHint, WorkspaceRelation,
};
use crate::rules::{self, CompiledPayload, CompiledRule, RuleSet, Severity};
use crate::scan::{self, Anchoring, Progress, ScanOptions, ScanReport};
use crate::walk::{self, IgnoreOptions, WalkResult};

/// How the setup report names the embedded rule pack.
///
/// The loader still records the pack's source as [`EMBEDDED_PACK_SOURCE`],
/// which is what the rule digest - and therefore every cache entry written
/// before this identity existed - is keyed on. This constant is a report label
/// and nothing else; renaming the load source would invalidate warm caches for
/// no gain.
pub const EMBEDDED_PACK_ID: &str = "default-secrets@1";

/// The origin the embedded pack is loaded under. Internal, and unchanged.
const EMBEDDED_PACK_SOURCE: &str = "default-pack";

/// What `report_kind` says for a resolved scan document.
pub const RESOLVED_REPORT_KIND: &str = "scan";

/// Whether the caller named a `PATH`.
///
/// Not a detail: a bare invocation and an explicit `.` name the same directory
/// and mean different things, and only the caller knows which one it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvocationKind {
    Automatic,
    Explicit,
}

/// What the caller said about the cache.
///
/// Two independent answers, not one: `--no-cache` decides whether to cache and
/// `--cache-dir` decides where. Collapsing them into one slot would make the
/// pair order-dependent, so `--no-cache --cache-dir x` would open a cache while
/// `--cache-dir x --no-cache` would not. v1 checks disabled first, always.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct CacheRequest {
    disabled: bool,
    dir: Option<PathBuf>,
}

/// The name each explicit option is recorded under in
/// [`ScanSetupReport::explicit_overrides`]. One string per v1 scan option, so a
/// reader can tell "the default applied" from "the default was asked for".
const OVERRIDE_PATH: &str = "path";
const OVERRIDE_CONFIG: &str = "config";
const OVERRIDE_RULES: &str = "rules";
const OVERRIDE_NO_DEFAULT_RULES: &str = "no-default-rules";
const OVERRIDE_BASELINE: &str = "baseline";
const OVERRIDE_COVERAGE_REPORT: &str = "coverage-report";
const OVERRIDE_NO_CACHE: &str = "no-cache";
const OVERRIDE_CACHE_DIR: &str = "cache-dir";
const OVERRIDE_IGNORE: &str = "ignore";
const OVERRIDE_FOLLOW_SYMLINKS: &str = "follow-symlinks";

/// What the caller asked to scan, and what it asked for explicitly.
///
/// Built from [`ScanRequest::automatic`] or [`ScanRequest::explicit`] and then
/// narrowed by the `with_*` methods, one per v1 scan option. Each of those
/// records the option as an explicit override whatever value it carries: a
/// `--cache-dir` pointing at the default location is still a supplied option,
/// and a later stage that treats it as absent would be describing a different
/// invocation.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    root: PathBuf,
    invocation: InvocationKind,
    config: Option<PathBuf>,
    rule_dirs: Vec<PathBuf>,
    no_embedded_rules: bool,
    baseline: Option<PathBuf>,
    coverage: Option<PathBuf>,
    cache: CacheRequest,
    ignore: IgnoreOptions,
    follow_symlinks: bool,
    explicit_overrides: BTreeSet<String>,
}

impl ScanRequest {
    /// A request with no `PATH`: the working directory, exactly as it stands.
    ///
    /// There is no root argument because there was no argument. The root is
    /// `.` and cannot be anything else - detection never promotes a scan to a
    /// git, manifest, package or workspace root.
    pub fn automatic() -> Self {
        Self::new(PathBuf::from("."), InvocationKind::Automatic)
    }

    /// A request naming `root`, including when the caller wrote `.`.
    pub fn explicit(root: impl Into<PathBuf>) -> Self {
        let mut request = Self::new(root.into(), InvocationKind::Explicit);
        request.explicit_overrides.insert(OVERRIDE_PATH.to_string());
        request
    }

    fn new(root: PathBuf, invocation: InvocationKind) -> Self {
        Self {
            root,
            invocation,
            config: None,
            rule_dirs: Vec::new(),
            no_embedded_rules: false,
            baseline: None,
            coverage: None,
            cache: CacheRequest::default(),
            ignore: IgnoreOptions::default(),
            follow_symlinks: false,
            explicit_overrides: BTreeSet::new(),
        }
    }

    /// The config file to load instead of discovering one.
    pub fn with_config(mut self, path: PathBuf) -> Self {
        self.config = Some(path);
        self.record(OVERRIDE_CONFIG)
    }

    /// Rule directories from the command line. Config-declared directories are
    /// appended to these during resolution, in that order.
    pub fn with_rule_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.rule_dirs = dirs;
        self.record(OVERRIDE_RULES)
    }

    /// Load no embedded rules.
    pub fn without_embedded_rules(mut self) -> Self {
        self.no_embedded_rules = true;
        self.record(OVERRIDE_NO_DEFAULT_RULES)
    }

    /// The baseline file to read instead of the default location.
    pub fn with_baseline(mut self, path: PathBuf) -> Self {
        self.baseline = Some(path);
        self.record(OVERRIDE_BASELINE)
    }

    /// The coverage report coverage rules read.
    pub fn with_coverage(mut self, path: PathBuf) -> Self {
        self.coverage = Some(path);
        self.record(OVERRIDE_COVERAGE_REPORT)
    }

    /// Run without a cache. Wins over [`ScanRequest::with_cache_dir`] whichever
    /// order the two are called in: disabling is a decision about whether to
    /// cache, not about where.
    pub fn without_cache(mut self) -> Self {
        self.cache.disabled = true;
        self.record(OVERRIDE_NO_CACHE)
    }

    /// Keep cache entries in `path` instead of the default location.
    pub fn with_cache_dir(mut self, path: PathBuf) -> Self {
        self.cache.dir = Some(path);
        self.record(OVERRIDE_CACHE_DIR)
    }

    /// Which ignore sources the walk consults.
    pub fn with_ignore_options(mut self, value: IgnoreOptions) -> Self {
        self.ignore = value;
        self.record(OVERRIDE_IGNORE)
    }

    /// Read files through symbolic links whose target is under the scan root.
    pub fn following_symlinks(mut self) -> Self {
        self.follow_symlinks = true;
        self.record(OVERRIDE_FOLLOW_SYMLINKS)
    }

    fn record(mut self, option: &str) -> Self {
        self.explicit_overrides.insert(option.to_string());
        self
    }

    /// The exact requested path. `.` for an automatic request.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// True when no `PATH` was supplied.
    pub fn is_automatic(&self) -> bool {
        self.invocation == InvocationKind::Automatic
    }
}

/// A setup step refused the request. `Display` is the step's own wording, with
/// no prefix of its own: callers that print `error: {e}` keep printing exactly
/// what they printed before.
#[derive(Debug, Clone)]
pub struct ResolveError {
    message: String,
}

impl ResolveError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ResolveError {}

struct ResolvedScanPlanInner {
    root: PathBuf,
    baseline_root: PathBuf,
    anchoring: Anchoring,
    config: Option<Config>,
    rules: RuleSet,
    silo_sets: Option<Vec<(String, GlobSet)>>,
    baseline: Option<Baseline>,
    coverage: Option<CoverageReport>,
    cache: Option<Cache>,
    ignore: IgnoreOptions,
    follow_symlinks: bool,
    inventory: WalkResult,
    setup: ScanSetupReport,
}

/// Everything a scan needs, resolved once and frozen.
///
/// Opaque on purpose. The CLI and the TUI are separately published crates, so
/// the plan has to be public; making its loader state, cache handle and
/// detector output public with it would freeze all of that into semver for no
/// caller's benefit. What a caller needs after the scan is on
/// [`ScanOutputContext`] instead.
pub struct ResolvedScanPlan {
    inner: ResolvedScanPlanInner,
}

impl ResolvedScanPlan {
    /// Perform the whole setup and the one walk.
    ///
    /// The steps run in the order the CLI ran them, so the first failure a
    /// caller sees is the one it saw before: root, config, rules, silos,
    /// coverage, anchor, baseline, cache, then the rule/config consistency
    /// checks the scanner used to make on its way in.
    pub fn resolve(request: &ScanRequest) -> Result<Self, ResolveError> {
        let root = request.root.clone();
        validate_root(&root)?;

        let (config, config_rule_dirs) = load_config(&root, request.config.as_deref())?;
        let mut rule_dirs = request.rule_dirs.clone();
        rule_dirs.extend(config_rule_dirs);
        let rules = load_rules(&rule_dirs, request.no_embedded_rules)?;
        require_silos(&rules, config.as_ref())?;

        let coverage = match &request.coverage {
            Some(path) => Some(crate::coverage::parse(path).map_err(ResolveError::new)?),
            None => None,
        };

        // Before the baseline is read and before the cache is opened: both are
        // bound to a path convention, and an anchor that cannot be honoured is
        // a setup error rather than a scan reporting the wrong paths.
        let anchoring = Anchoring::resolve(&root, config.as_ref()).map_err(ResolveError::new)?;
        let baseline_root = baseline_root(&root, config.as_ref());
        let baseline = load_baseline(&baseline_root, request.baseline.as_deref())?;
        let cache = open_cache(&root, &rules, &request.cache, &anchoring);

        let silo_sets = scan::prepared_setup(&root, &rules, config.as_ref(), coverage.as_ref())
            .map_err(ResolveError::new)?;

        let project_dirs = config
            .as_ref()
            .map(|config| config.project_ignore_dirs(&root))
            .unwrap_or_default();
        let mut inventory = walk::collect_files_counted_with(
            &root,
            &walk::WalkOptions::new(&request.ignore)
                .in_project(&project_dirs)
                .follow_symlinks(request.follow_symlinks),
        );

        // The cache's own entries are not content under review. The scanner
        // drops them too, so doing it here is idempotent for the scan; what it
        // buys is that detection reads the same inventory the engines do,
        // rather than one containing files a previous run wrote.
        if let Some(excluded) = cache
            .as_ref()
            .and_then(|cache| cache.exclusion_under(&root))
        {
            inventory.files.retain(|path| !path.starts_with(&excluded));
            inventory
                .symlinks
                .retain(|entry| !entry.path.starts_with(&excluded));
        }

        let facts = project::detect(&root, &inventory, config.as_ref());
        let setup = ScanSetupReport::build(
            &root,
            request,
            facts,
            &rules,
            &rule_dirs,
            Loaded {
                config: config.is_some(),
                baseline: baseline.is_some(),
                coverage: coverage.is_some(),
                cache: cache_state(&cache),
            },
        );

        Ok(Self {
            inner: ResolvedScanPlanInner {
                root,
                baseline_root,
                anchoring,
                config,
                rules,
                silo_sets,
                baseline,
                coverage,
                cache,
                ignore: request.ignore,
                follow_symlinks: request.follow_symlinks,
                inventory,
                setup,
            },
        })
    }

    /// What resolution found, before the scan runs.
    pub fn setup(&self) -> &ScanSetupReport {
        &self.inner.setup
    }

    /// Run the scan over the inventory this plan already holds.
    ///
    /// The plan is destructured first, which is what lets the temporary
    /// [`ScanOptions`] borrow siblings while the inventory moves into the
    /// scanner: the options are dropped before the remaining values move into
    /// the output context, and no `ScanOptions` is ever stored.
    pub fn execute(
        self,
        on_progress: &mut dyn FnMut(Progress),
    ) -> Result<ResolvedScanReport, String> {
        let ResolvedScanPlanInner {
            root,
            baseline_root,
            anchoring,
            config,
            rules,
            silo_sets,
            baseline,
            coverage,
            cache,
            ignore,
            follow_symlinks,
            inventory,
            setup,
        } = self.inner;

        let scan = {
            let options = ScanOptions {
                baseline: baseline.as_ref(),
                cache: cache.as_ref(),
                config: config.as_ref(),
                coverage: coverage.as_ref(),
                ignore,
                follow_symlinks,
            };
            scan::scan_prepared(
                &root,
                &rules,
                &options,
                silo_sets,
                &anchoring,
                inventory,
                on_progress,
            )?
        };

        Ok(ResolvedScanReport {
            scan,
            setup,
            output: ScanOutputContext {
                root,
                baseline_root,
                anchoring,
                rules,
                config,
            },
        })
    }
}

/// The scan, what setup resolved, and what a writer needs to render either.
///
/// `scan` is the unchanged v1 [`ScanReport`]: adding a field to that
/// exhaustive public struct would break every external struct literal, so the
/// v2 metadata is carried beside it instead of inside it.
pub struct ResolvedScanReport {
    pub scan: ScanReport,
    pub setup: ScanSetupReport,
    output: ScanOutputContext,
}

impl ResolvedScanReport {
    pub fn context(&self) -> &ScanOutputContext {
        &self.output
    }

    pub fn into_parts(self) -> (ScanReport, ScanSetupReport, ScanOutputContext) {
        (self.scan, self.setup, self.output)
    }
}

/// The runtime values a report writer needs, without exposing how they were
/// loaded. Opaque for the same reason the plan is.
pub struct ScanOutputContext {
    root: PathBuf,
    baseline_root: PathBuf,
    anchoring: Anchoring,
    rules: RuleSet,
    config: Option<Config>,
}

impl ScanOutputContext {
    pub fn scan_root(&self) -> &Path {
        &self.root
    }

    pub fn baseline_root(&self) -> &Path {
        &self.baseline_root
    }

    pub fn anchoring(&self) -> &Anchoring {
        &self.anchoring
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }
}

/// Where one rule document came from, for the setup report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuleSource {
    /// The embedded pack's published identity, or a rule file named relative
    /// to the scan root when it sits inside it and by file name when it does
    /// not. Never an absolute path: the report has to be the same bytes on
    /// every machine that scans the same tree.
    pub id: String,
    /// `"embedded"` or `"directory"`.
    pub origin: String,
}

/// Whether an optional part of the scan ran, and if not, why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CapabilityStatus {
    Enabled,
    Skipped,
    Unavailable,
    NotConfigured,
}

/// One capability and its state.
///
/// A capability that is not enabled always carries a reason, because the
/// constructor is the only way to build one and it demands the reason. Silence
/// is the failure mode this type exists to prevent: a coverage gate that never
/// ran looks exactly like a coverage gate that passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityState {
    id: String,
    status: CapabilityStatus,
    reason: Option<String>,
}

impl CapabilityState {
    pub fn enabled(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: CapabilityStatus::Enabled,
            reason: None,
        }
    }

    pub fn not_enabled(
        id: impl Into<String>,
        status: CapabilityStatus,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status,
            reason: Some(reason.into()),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn status(&self) -> &CapabilityStatus {
        &self.status
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

/// What resolution found, in a form two runs of the same tree agree on.
///
/// Every vector is sorted and every path in it is relative and slash-separated,
/// so this value is the same on Linux, macOS and Windows and the same on a
/// second run. Nothing here identifies the machine that produced it.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ScanSetupReport {
    pub evidence: Vec<Evidence>,
    pub units: Vec<ProjectUnit>,
    pub workspaces: Vec<WorkspaceRelation>,
    pub languages: Vec<String>,
    pub source_roots: Vec<SourceRootHint>,
    pub rule_sources: Vec<RuleSource>,
    pub capabilities: Vec<CapabilityState>,
    pub explicit_overrides: Vec<String>,
}

/// Which optional setup inputs resolution ended up with. One struct so the
/// capability list reads as a list rather than as eight positional booleans.
struct Loaded {
    config: bool,
    baseline: bool,
    coverage: bool,
    cache: CapabilityState,
}

/// The `cache` capability, which has three answers rather than two.
///
/// A cache the caller turned off is skipped. A cache that opened but has
/// nowhere to live, or whose directory this crate refused, is unavailable: the
/// scan is correct and permanently cold, and a report that called that
/// `enabled` would be describing a warm run that never happens.
fn cache_state(cache: &Option<Cache>) -> CapabilityState {
    match cache {
        None => CapabilityState::not_enabled(
            "cache",
            CapabilityStatus::Skipped,
            "the cache is disabled for this scan",
        ),
        Some(cache) => match cache.inert_reason() {
            Some(reason) => {
                CapabilityState::not_enabled("cache", CapabilityStatus::Unavailable, reason)
            }
            None => CapabilityState::enabled("cache"),
        },
    }
}

impl ScanSetupReport {
    fn build(
        root: &Path,
        request: &ScanRequest,
        facts: project::ProjectFacts,
        rules: &RuleSet,
        rule_dirs: &[PathBuf],
        loaded: Loaded,
    ) -> Self {
        let mut capabilities = vec![
            loaded.cache,
            state(
                "coverage",
                loaded.coverage,
                CapabilityStatus::NotConfigured,
                "no coverage report was given",
            ),
            state(
                "embedded-rules",
                !request.no_embedded_rules,
                CapabilityStatus::Skipped,
                "the embedded pack is disabled for this scan",
            ),
            state(
                "project-detection",
                facts.status != DetectionStatus::Generic,
                CapabilityStatus::NotConfigured,
                "the admitted inventory carries no supported project evidence",
            ),
            state(
                "repository-config",
                loaded.config,
                CapabilityStatus::NotConfigured,
                "no repository config applies to this scan root",
            ),
            state(
                "rule-directories",
                !rule_dirs.is_empty(),
                CapabilityStatus::NotConfigured,
                "no rule directory was given on the command line or by a config",
            ),
            state(
                "scan-baseline",
                loaded.baseline,
                CapabilityStatus::NotConfigured,
                "no baseline was given and none was found for this scan root",
            ),
            state(
                "symlink-following",
                request.follow_symlinks,
                CapabilityStatus::NotConfigured,
                "in-root symbolic links are not followed",
            ),
        ];
        capabilities.sort_by(|left, right| left.id.cmp(&right.id));

        Self {
            evidence: facts.evidence,
            units: facts.units,
            workspaces: facts.workspace_relations,
            languages: facts.languages,
            source_roots: facts.source_roots,
            rule_sources: rule_sources(root, rules),
            capabilities,
            explicit_overrides: request.explicit_overrides.iter().cloned().collect(),
        }
    }
}

/// Enabled, or not enabled with the one reason that explains it.
fn state(id: &str, enabled: bool, status: CapabilityStatus, reason: &str) -> CapabilityState {
    if enabled {
        CapabilityState::enabled(id)
    } else {
        CapabilityState::not_enabled(id, status, reason)
    }
}

fn rule_sources(root: &Path, rules: &RuleSet) -> Vec<RuleSource> {
    rules
        .sources
        .iter()
        .map(|(origin, _)| {
            if origin == EMBEDDED_PACK_SOURCE {
                RuleSource {
                    id: EMBEDDED_PACK_ID.to_string(),
                    origin: "embedded".to_string(),
                }
            } else {
                RuleSource {
                    id: rule_source_id(root, origin),
                    origin: "directory".to_string(),
                }
            }
        })
        .collect()
}

/// A rule file's report identity: its path from the scan root when it is
/// inside the tree being scanned, and its last two path components when it is
/// not.
///
/// The loader records the path it opened, which on a `--rules /abs/dir` run is
/// absolute and names the machine it ran on. Neither belongs in a report that
/// has to compare equal across two checkouts.
///
/// Both sides are canonicalised before the strip, because the spelling of the
/// root is the caller's and the report is not allowed to depend on it: `.` and
/// `/abs/repo` name one tree and have to produce one document. The fallback
/// keeps the directory as well as the file name, so two rule directories each
/// holding a `rules.yaml` stay distinguishable.
fn rule_source_id(root: &Path, origin: &str) -> String {
    let path = Path::new(origin);
    let canonical = |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let (root, absolute) = (canonical(root), canonical(path));

    match absolute.strip_prefix(&root) {
        Ok(relative) => join_slashes(relative),
        Err(_) => {
            let tail: Vec<String> = absolute
                .components()
                .rev()
                .take(2)
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .collect();
            tail.into_iter().rev().collect::<Vec<String>>().join("/")
        }
    }
}

fn join_slashes(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<String>>()
        .join("/")
}

/// The requested scope, as the persistence layer identifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScopeKind {
    Directory,
    File,
}

/// Which scope a saved report describes.
///
/// `identity` is the caller's opaque key for the canonical requested path - a
/// digest, not a path. Nothing here reveals where the scan ran.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeMetadata {
    identity: String,
    kind: ScopeKind,
    path_base_ancestor_levels: u32,
}

impl ScopeMetadata {
    pub fn new(identity: String, kind: ScopeKind, ancestor_levels: u32) -> Self {
        Self {
            identity,
            kind,
            path_base_ancestor_levels: ancestor_levels,
        }
    }
}

/// The gate the run was judged against, decided before output filtering.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct OutcomeMetadata {
    fail_on: Severity,
    threshold_reached: bool,
}

impl OutcomeMetadata {
    pub fn new(fail_on: Severity, threshold_reached: bool) -> Self {
        Self {
            fail_on,
            threshold_reached,
        }
    }
}

/// The resolved document: the legacy projection with the four v2 markers after
/// it, in the settled order.
///
/// `flatten` is what keeps the first half honest - there is one projection,
/// built by [`crate::output`], and this appends to it rather than restating it.
#[derive(Serialize)]
struct ResolvedJsonReport<'a> {
    #[serde(flatten)]
    legacy: crate::output::JsonReport<'a>,
    report_kind: &'static str,
    scope: &'a ScopeMetadata,
    outcome: &'a OutcomeMetadata,
    setup: &'a ScanSetupReport,
}

/// Write the schema 1.2 resolved report straight to `writer`.
///
/// This is the owning implementation. Persistence writes canonical bytes into a
/// buffered temporary file through it, without a full-report `String` and
/// without cloning the report: everything here is borrowed.
///
/// `min_severity` is recorded, not applied - the caller has already filtered
/// `report` if it filtered at all, exactly as with [`crate::output::to_json`].
pub fn write_resolved_json<W: io::Write>(
    writer: W,
    report: &ScanReport,
    setup: &ScanSetupReport,
    context: &ScanOutputContext,
    scope: &ScopeMetadata,
    outcome: &OutcomeMetadata,
    min_severity: Option<Severity>,
) -> serde_json::Result<()> {
    let document = ResolvedJsonReport {
        legacy: crate::output::json_report(
            report,
            context.rules(),
            context.anchoring().anchor(),
            min_severity,
        ),
        report_kind: RESOLVED_REPORT_KIND,
        scope,
        outcome,
        setup,
    };
    serde_json::to_writer_pretty(writer, &document)
}

/// [`write_resolved_json`] into a `String`, for a caller that wants the whole
/// document in memory.
pub fn to_resolved_json(
    report: &ScanReport,
    setup: &ScanSetupReport,
    context: &ScanOutputContext,
    scope: &ScopeMetadata,
    outcome: &OutcomeMetadata,
    min_severity: Option<Severity>,
) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    write_resolved_json(
        &mut buffer,
        report,
        setup,
        context,
        scope,
        outcome,
        min_severity,
    )
    .expect("serializing to a Vec cannot fail");
    String::from_utf8(buffer).expect("serde_json writes utf-8")
}

// ---------------------------------------------------------------------------
// Setup steps. These are the CLI's own resolution, moved here unchanged so the
// CLI and the TUI stop keeping two copies of it.
// ---------------------------------------------------------------------------

/// The walker cannot distinguish "nothing to scan" from "root is missing or
/// unreadable", so the root is checked up front.
fn validate_root(root: &Path) -> Result<(), ResolveError> {
    let check = if fs::metadata(root)
        .map_err(|e| ResolveError::new(format!("{}: {e}", root.display())))?
        .is_dir()
    {
        fs::read_dir(root).map(|_| ())
    } else {
        fs::File::open(root).map(|_| ())
    };
    check.map_err(|e| ResolveError::new(format!("{}: {e}", root.display())))
}

/// The repository config and the extra rule directories it declares. An
/// explicit config must exist and parse; the discovered one is simply absent
/// when there is none.
fn load_config(
    root: &Path,
    explicit: Option<&Path>,
) -> Result<(Option<Config>, Vec<PathBuf>), ResolveError> {
    let config = match explicit {
        Some(path) => Some(config::load(path).map_err(ResolveError::new)?),
        None => discover_config(root)?,
    };

    let Some(config) = config else {
        return Ok((None, Vec::new()));
    };
    let dirs = config.rule_dirs();
    Ok((Some(config), dirs))
}

/// The config a scan of `root` runs under when none was named: the one
/// discovery finds, or the root config that includes it.
///
/// In a multimodule repository a module's `siloscan.toml` is an included file,
/// and discovery stops at it because it sits in the scan root. Loading it as a
/// root config would drop the repository's anchor and silos without a word, so
/// `siloscan modules/api` would report under a different convention than
/// `siloscan .` and fingerprint every finding differently.
fn discover_config(root: &Path) -> Result<Option<Config>, ResolveError> {
    let Some(path) = config::discover(root) else {
        return Ok(None);
    };
    let config = config::load(&path).map_err(ResolveError::new)?;

    // `include` is single level, so a file that includes others can never be
    // included itself: it is already a root config.
    if !config.include.is_empty() {
        return Ok(Some(config));
    }
    Ok(Some(owning_root(&path)?.unwrap_or(config)))
}

/// The nearest config above `target` that lists `target` in its `include`.
///
/// The ascent stops at the repository root, mirroring [`config::discover`], so
/// nothing outside the repository is read. A candidate that does not parse is
/// an error rather than a reason to keep walking: it may be the file that owns
/// the scan.
fn owning_root(target: &Path) -> Result<Option<Config>, ResolveError> {
    let Some(mut dir) = target.parent() else {
        return Ok(None);
    };

    while !is_repo_root(dir) {
        let Some(parent) = dir.parent() else {
            return Ok(None);
        };
        dir = parent;

        let candidate = dir.join(config::CONFIG_NAME);
        if !candidate.is_file() {
            continue;
        }
        let config = config::load(&candidate).map_err(ResolveError::new)?;
        let owns = config
            .include
            .iter()
            .any(|entry| same_file(&config.config_root().join(entry), target));
        if owns {
            return Ok(Some(config));
        }
    }

    Ok(None)
}

/// True when `dir` holds the marker git leaves at a repository root.
fn is_repo_root(dir: &Path) -> bool {
    let git = dir.join(".git");
    match git.metadata() {
        Ok(meta) if meta.is_dir() => git.join("HEAD").exists(),
        Ok(_) => true,
        Err(_) => false,
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    let canonical = |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    canonical(a) == canonical(b)
}

/// The directory a scan root keeps its `.siloscan` state in: the root itself
/// when it is a directory, and the directory holding it when the root is a
/// single file.
fn state_root(root: &Path) -> PathBuf {
    if root.is_dir() {
        return root.to_path_buf();
    }
    match root.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The directory the default `.siloscan/baseline.json` is read from: the scan
/// root's state directory, and under `anchor = "config"` the config root, which
/// is where the fingerprints are measured from.
fn baseline_root(root: &Path, config: Option<&Config>) -> PathBuf {
    match config {
        Some(config)
            if config.anchor == Anchor::Config && !config.config_root().as_os_str().is_empty() =>
        {
            config.config_root().to_path_buf()
        }
        _ => state_root(root),
    }
}

/// An explicit baseline file must exist; the default location is optional.
fn load_baseline(root: &Path, explicit: Option<&Path>) -> Result<Option<Baseline>, ResolveError> {
    let Some(path) = explicit else {
        return baseline::load(root).map_err(ResolveError::new);
    };

    let text = fs::read_to_string(path)
        .map_err(|e| ResolveError::new(format!("{}: io error: {e}", path.display())))?;
    let baseline: Baseline = serde_json::from_str(&text)
        .map_err(|e| ResolveError::new(format!("{}: invalid baseline: {e}", path.display())))?;
    if baseline.version != 1 {
        return Err(ResolveError::new(format!(
            "{}: unsupported baseline version {}",
            path.display(),
            baseline.version
        )));
    }
    Ok(Some(baseline))
}

fn open_cache(
    root: &Path,
    rules: &RuleSet,
    request: &CacheRequest,
    anchoring: &Anchoring,
) -> Option<Cache> {
    // Disabled first and unconditionally, as v1 does: a request that names a
    // directory and also asks for no cache gets no cache.
    if request.disabled {
        return None;
    }
    let scope = PathScope::new(anchoring.anchor(), anchoring.prefix());
    let state = state_root(root);
    Some(match &request.dir {
        Some(dir) => Cache::open_in(dir, &state, rules, &scope),
        None => Cache::open(&state, rules, &scope),
    })
}

/// The embedded pack plus every rule directory, in load order.
///
/// A run that loads nothing fails: a scan with no rules cannot report a
/// finding, so it exits clean having proven nothing, and every later run does
/// the same.
fn load_rules(dirs: &[PathBuf], no_embedded_rules: bool) -> Result<RuleSet, ResolveError> {
    let mut rules: Vec<CompiledRule> = Vec::new();
    // Sources are recorded in the same order they are loaded; the cache keys
    // entries on their digest, so an unrecorded source is an unnoticed change.
    let mut sources: Vec<(String, String)> = Vec::new();

    if !no_embedded_rules {
        let loaded = rules::load_str(default_pack::default_rules(), EMBEDDED_PACK_SOURCE)
            .map_err(|e| ResolveError::new(e.to_string()))?;
        rules.extend(loaded);
        sources.push((
            EMBEDDED_PACK_SOURCE.to_string(),
            default_pack::default_rules().to_string(),
        ));
    }

    let loaded = rules::load_dirs(dirs).map_err(|e| ResolveError::new(e.to_string()))?;
    rules.extend(loaded.rules);
    sources.extend(loaded.sources);

    // The loader rejects duplicates within the pack and across `--rules`
    // directories; the union of the two is only visible here.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for rule in &rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(ResolveError::new(format!("duplicate rule id: {}", rule.id)));
        }
    }

    if rules.is_empty() {
        return Err(ResolveError::new(no_rules_message(dirs, no_embedded_rules)));
    }

    Ok(RuleSet { rules, sources })
}

fn no_rules_message(dirs: &[PathBuf], no_embedded_rules: bool) -> String {
    let searched = if dirs.is_empty() {
        "no rule directories were given".to_string()
    } else {
        let list = dirs
            .iter()
            .map(|dir| dir.display().to_string())
            .collect::<Vec<String>>()
            .join(", ");
        format!("searched: {list}")
    };
    let pack = if no_embedded_rules {
        "the built-in pack is disabled by --no-default-rules"
    } else {
        "the built-in pack loaded no rules"
    };
    format!("no rules loaded, so nothing would be checked: {pack}; {searched}")
}

/// A boundary rule can only fire against configured silos, so loading one
/// without a `[silos]` section is a config mistake, not a clean scan.
fn require_silos(rules: &RuleSet, config: Option<&Config>) -> Result<(), ResolveError> {
    let boundary = rules
        .rules
        .iter()
        .find(|rule| matches!(rule.payload, CompiledPayload::Boundary { .. }));
    let Some(rule) = boundary else {
        return Ok(());
    };
    if config.is_some_and(|config| !config.silos.is_empty()) {
        return Ok(());
    }
    Err(ResolveError::new(format!(
        "rule {}: boundary rules need a {} defining [silos]",
        rule.id,
        config::CONFIG_NAME
    )))
}
