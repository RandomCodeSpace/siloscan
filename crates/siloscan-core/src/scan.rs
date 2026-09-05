use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use globset::GlobSet;
use serde::Serialize;

use crate::config::Anchor;
use crate::findings::Finding;
use crate::graph::FileFacts;
use crate::metrics::{DUPLICATE_BLOCK_RULE_ID, DuplicationResult, FileMetrics, Metrics};
use crate::rules::{CompiledPayload, DuplicationScope, RegexCompileError, RuleSet, Severity};
use crate::walk::{self, FileKind};

/// Upper bound on scan workers. Past this the per-file work is dominated by the
/// file system, and every extra thread only costs memory for its parsers.
const MAX_WORKERS: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct SkippedFile {
    /// Repo-relative path using forward slashes.
    pub path: String,
    pub reason: String,
}

/// What the report says about a file the reader classified as binary.
///
/// Binary files are not scannable input, but dropping one without a word is
/// indistinguishable from finding nothing in it: a minified bundle or a UTF-16
/// config with one stray NUL would leave a secrets scan looking clean. The
/// reader reports no offset - it sniffs a fixed window of leading bytes - so
/// the wording names the window instead, and being a constant it words two runs
/// of the same tree identically.
const BINARY_SKIP_REASON: &str = "binary content (NUL byte in the first 8000 bytes)";

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Actionable findings: neither suppressed inline nor covered by the baseline.
    pub findings: Vec<Finding>,
    pub baselined: Vec<Finding>,
    pub suppressed: Vec<Finding>,
    /// Every file the scan did not read the way its rules asked for: unreadable,
    /// binary, or past the parse size cap. Sorted by path, so it is the same
    /// list whatever order the workers finished in.
    pub skipped: Vec<SkippedFile>,
    /// How much of the tree an ignore file kept out of the scan.
    ///
    /// A count and not a list: enumerating an ignored `node_modules` would
    /// swamp the report, and the point is only that a reader can tell "clean"
    /// from "did not look". An excluded directory is one entry - see
    /// [`walk::Ignored`] for exactly what is counted, and what is not.
    ///
    /// Zero on a scan whose walk consulted no ignore source, since nothing
    /// could have been excluded by one.
    pub ignored: walk::Ignored,
    /// Per-file semantic facts, populated only when a boundary rule is loaded.
    ///
    /// The import facts are the boundary engine's input and nothing else reads
    /// them, and extracting them from a parsed tree costs about as much as the
    /// parse. So a scan with no boundary rule leaves this empty even where it
    /// parsed every file for its ast rules. A library consumer must not read an
    /// empty graph as "the tree has no imports": it means no rule asked for
    /// them.
    pub graph: crate::graph::Graph,
    /// Every boundary violation as `(from silo, to silo, fingerprint)`, sorted.
    /// The finding itself is in `findings`, `baselined` or `suppressed`
    /// depending on how it was partitioned, and is identified by fingerprint.
    pub boundary_edges: Vec<(String, String, String)>,
    /// Size and duplication metrics for every text file that was scanned.
    pub metrics: Metrics,
    /// What the scan narrowed, and why, in the caller's own words to print.
    ///
    /// A gate that cannot evaluate fails the scan; this is the one case that is
    /// deliberately not a failure and so has to be said out loud instead - a
    /// coverage report that lands on none of the files a subdirectory scan
    /// walked (see the coverage arm of [`run_with_workers`]). Silence there
    /// would be a coverage gate that measured nothing and reported a pass.
    ///
    /// Scanner-generated wording plus a report path, in a fixed order, so two
    /// runs of the same tree produce the same list.
    pub warnings: Vec<String>,
}

/// Optional inputs to a scan. Defaults to no baseline, cache, config or
/// coverage report, which is exactly what [`scan`] and [`scan_with_progress`]
/// pass.
///
/// `#[non_exhaustive]`: a scan grows inputs over time, and each one added to a
/// plain struct is a source break for every caller that wrote a struct literal.
/// Outside this crate the type is therefore built from [`Default`] and then
/// assigned field by field - the fields stay public, so nothing is hidden, but
/// the next field costs no caller a compile error:
///
/// ```
/// # use siloscan_core::scan::ScanOptions;
/// let mut options = ScanOptions::default();
/// options.ignore = Default::default();
/// ```
#[derive(Default)]
#[non_exhaustive]
pub struct ScanOptions<'a> {
    pub baseline: Option<&'a crate::baseline::Baseline>,
    pub cache: Option<&'a crate::cache::Cache>,
    /// Repository config. Boundary rules are inert without one: silo
    /// membership is defined by the config and nowhere else.
    ///
    /// It is the caller's, never rediscovered here, and `None` means exactly
    /// that: no config, whether none exists or none was found. Where a caller
    /// got one from is worth knowing, because [`crate::config::discover`] stops
    /// ascending at a repository boundary or at the filesystem root, whichever
    /// comes first: an exported tarball with a `siloscan.toml` above the scan
    /// root and no `.git` anywhere discovers no config at all. That boundary is
    /// deliberate - a stray config in `$HOME` or `/` must not reach a scan -
    /// and it is stated here because passing `None` for that reason looks
    /// identical to passing `None` on purpose.
    ///
    /// What it costs: `silo`-scoped duplication rules and a config `anchor`
    /// fail the scan without a config rather than report an empty result that
    /// reads like a passing gate (`duplication_setup`, [`Anchoring::resolve`]).
    /// Boundary rules are the exception - without a config they are inert and
    /// silent, which is the same hole in a different place.
    pub config: Option<&'a crate::config::Config>,
    /// Parsed coverage report. Coverage rules are inert without one: absence
    /// of data is not evidence of an uncovered file.
    pub coverage: Option<&'a crate::coverage::CoverageReport>,
    /// Which ignore sources the walk consults. The default is self-contained:
    /// ignore files inside the scan root count, nothing above or outside it
    /// does. See [`walk::IgnoreOptions`] for why, and for what turning each
    /// one back on costs.
    ///
    /// This is a scan input like any other, so it belongs to the caller rather
    /// than to the walker: a scan that reads a different set of files is a
    /// different scan, and the decision has to be visible where the scan is
    /// asked for.
    pub ignore: walk::IgnoreOptions,
    /// Follow symbolic links whose target is under the scan root. Default
    /// `false`, which is the shipped behaviour.
    ///
    /// Like `ignore`, this decides which files the scan reads, so it is the
    /// caller's. See [`walk::WalkOptions::follow_symlinks`] for what it does:
    /// off, an in-root target is still reached on its own path; on, it is
    /// additionally read through the link and so reported under both paths. A
    /// target outside the scan root is refused either way, and turning this on
    /// cannot widen a scan past its own root.
    pub follow_symlinks: bool,
}

/// The path convention a scan reports under.
///
/// Every path a scan produces - a finding's `path`, a skipped file's, a metrics
/// key, a graph key - is built in one place, [`Anchoring::relative`], and every
/// fingerprint is derived from what that place returned. `prefix` is what it
/// prepends: empty under [`Anchor::ScanRoot`], and under [`Anchor::Config`] the
/// scan root's own path from the directory holding the config. Anchoring a whole
/// scan is therefore one string, which is what keeps fingerprints and displayed
/// paths from ever describing a file differently.
///
/// The consequence worth having: a scan of `modules/api` and a scan of the whole
/// repository both call a file `modules/api/src/a.rs`, so they fingerprint it
/// identically and one baseline serves both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Anchoring {
    anchor: Anchor,
    prefix: String,
}

impl Anchoring {
    /// The convention a scan of `root` under `config` runs in.
    ///
    /// Fails when `anchor = "config"` cannot be honoured: no config was loaded
    /// from disk to measure from, or the scan root lies outside the config root.
    /// Both are refused rather than quietly downgraded to scan-root paths, which
    /// would hand out fingerprints under a convention nobody asked for.
    pub fn resolve(
        root: &Path,
        config: Option<&crate::config::Config>,
    ) -> Result<Anchoring, String> {
        // No config means no anchor key, and the absent key means scan-root.
        let Some(config) = config else {
            return Ok(Anchoring::default());
        };

        match config.anchor {
            Anchor::ScanRoot => Ok(Anchoring::default()),
            Anchor::Config => {
                let config_root = config.config_root();
                if config_root.as_os_str().is_empty() {
                    return Err(format!(
                        "anchor = {:?} needs a {} on disk to measure paths from",
                        Anchor::Config.as_str(),
                        crate::config::CONFIG_NAME
                    ));
                }
                Ok(Anchoring {
                    anchor: Anchor::Config,
                    prefix: descent(config_root, measured_from(root))?,
                })
            }
        }
    }

    /// The convention, for the report field that declares it to consumers.
    pub fn anchor(&self) -> Anchor {
        self.anchor
    }

    /// Path from the anchor directory down to the directory scanned paths are
    /// measured from. Empty when they are the same directory, which is every
    /// scan-root-anchored run and a config-anchored run of the config root.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The scan root itself, in this convention.
    ///
    /// Findings that describe the scan as a whole rather than a file sit here.
    /// That is `"."` under scan-root anchoring, and under config anchoring it is
    /// the scan root's path from the config root - still `"."` when the two are
    /// the same directory.
    pub fn scan_root_path(&self) -> &str {
        if self.prefix.is_empty() {
            "."
        } else {
            &self.prefix
        }
    }

    /// A scanned file's path in this convention: the scan-root-relative path
    /// with the prefix in front of it.
    fn relative(&self, root: &Path, path: &Path) -> String {
        let rel = relative(root, path);
        if self.prefix.is_empty() {
            rel
        } else {
            format!("{}/{rel}", self.prefix)
        }
    }
}

/// The directory a scan root's relative paths are measured from: the root itself
/// for a directory, and the containing directory for a single-file scan, which
/// reports that file by name.
fn measured_from(root: &Path) -> &Path {
    if root.is_dir() {
        return root;
    }
    match root.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Forward-slash path from `base` down to `dir`, empty when they are the same
/// directory. Both sides are canonicalised, so `.`, `..` and symlinks in either
/// argument do not decide whether one contains the other.
fn descent(base: &Path, dir: &Path) -> Result<String, String> {
    let canonical = |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let (base_abs, dir_abs) = (canonical(base), canonical(dir));

    match dir_abs.strip_prefix(&base_abs) {
        Ok(tail) => Ok(join_slashes(tail)),
        Err(_) => Err(format!(
            "anchor = {:?} measures every path from {}, which does not contain the scan root {}",
            Anchor::Config.as_str(),
            base.display(),
            dir.display()
        )),
    }
}

/// Scan progress snapshot. `findings` counts raw matches as scanned, before
/// inline suppression and baseline partitioning, so it only ever grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Progress {
    pub files_total: usize,
    pub files_done: usize,
    pub findings: usize,
}

/// Fails only when a loaded rule turns out to be unusable; see
/// [`scan_with_progress`].
pub fn scan(
    root: &Path,
    rules: &RuleSet,
    baseline: Option<&crate::baseline::Baseline>,
) -> Result<ScanReport, String> {
    scan_with_progress(root, rules, baseline, &mut |_| {})
}

/// Same scan, with a callback invoked once after the walk (`files_done = 0`,
/// total known) and once after each file.
///
/// Silo validation and anchoring, the failures [`scan_opts`] adds, both need a
/// config that these options do not carry. What is left is a secret rule whose
/// pattern passed load-time validation and cannot be compiled when a file
/// finally makes it run: the scan fails rather than report nothing for it.
pub fn scan_with_progress(
    root: &Path,
    rules: &RuleSet,
    baseline: Option<&crate::baseline::Baseline>,
    on_progress: &mut dyn FnMut(Progress),
) -> Result<ScanReport, String> {
    let options = ScanOptions {
        baseline,
        ..ScanOptions::default()
    };
    run(
        root,
        rules,
        &options,
        None,
        &Anchoring::default(),
        on_progress,
    )
}

/// The scanner proper. Every file is read once, parsed at most once, and run
/// through every engine; a cache hit replaces the read-to-engine step only.
/// A file is parsed only when a loaded rule needs a tree for its language and
/// the file is within `limits.max_parse_bytes`; over the cap it is recorded in
/// [`ScanReport::skipped`] and reaches every engine that works on text.
///
/// Fails when a boundary rule names a silo the config does not define, when
/// boundary or silo-scoped duplication rules would run against a scan root below
/// the directory holding the config (a typo or a partial scan would otherwise
/// silently disable the rule), when the config's `anchor` cannot be honoured
/// for this scan root, and when a rule a file had to run cannot be compiled.
/// The parse size cap never fails a scan: what it stops is recorded instead
/// (see [`parse_decision`]).
pub fn scan_opts(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    on_progress: &mut dyn FnMut(Progress),
) -> Result<ScanReport, String> {
    let silo_sets = prepared_setup(root, rules, options.config, options.coverage)?;
    // Derived from the scan root and the config alone, so a caller that resolved
    // it separately - to key a cache, or to label a report - resolved the same
    // value. There is no way for the two to disagree.
    let anchoring = Anchoring::resolve(root, options.config)?;
    run(root, rules, options, silo_sets, &anchoring, on_progress)
}

/// A duplication rule scoped to silos needs a config that defines silos to know
/// what a silo is. Running it without one would report nothing at all, which
/// reads as a passing gate, so it is refused instead. A config that loads but
/// declares no `[silos]` is the same hole as no config, so both are refused,
/// and so is a scan root below the directory holding the config: the silo globs
/// would match nothing there.
fn duplication_setup(
    root: &Path,
    rules: &RuleSet,
    config: Option<&crate::config::Config>,
) -> Result<(), String> {
    let silo_scoped = rules.rules.iter().find(|rule| {
        matches!(
            rule.payload,
            CompiledPayload::Duplication {
                scope: DuplicationScope::Silo,
                ..
            }
        )
    });
    let Some(rule) = silo_scoped else {
        return Ok(());
    };
    let Some(config) = config.filter(|config| !config.silos.is_empty()) else {
        return Err(format!(
            "rule {}: duplication scope silo needs a {} defining [silos]",
            rule.id,
            crate::config::CONFIG_NAME
        ));
    };
    require_config_root(root, config, "silo-scoped duplication rules")
}

/// Compiled silo globs, once it is established that at least one boundary rule
/// and a config defining silos are both present. `None` disables the boundary
/// engine for this scan.
fn boundary_setup(
    root: &Path,
    rules: &RuleSet,
    config: Option<&crate::config::Config>,
) -> Result<Option<Vec<(String, GlobSet)>>, String> {
    let Some(config) = config else {
        return Ok(None);
    };

    let mut any = false;
    for rule in &rules.rules {
        let CompiledPayload::Boundary { from, deny } = &rule.payload else {
            continue;
        };
        any = true;
        for silo in std::iter::once(from).chain(deny) {
            if !config.silos.contains_key(silo) {
                return Err(format!("rule {}: unknown silo: {silo}", rule.id));
            }
        }
    }

    if !any || config.silos.is_empty() {
        return Ok(None);
    }
    require_config_root(root, config, "boundary rules")?;
    config.silo_sets().map(Some)
}

/// Silo globs are relative to the directory holding the config, while scanned
/// paths are relative to the scan root. Scanning below the config's directory
/// would match every file against the wrong path and report nothing at all, so
/// it is refused rather than silently passed.
///
/// The directory measured against is the loaded config's own, never one
/// rediscovered from the scan root: those differ whenever the config was named
/// explicitly, and a module holding its own `siloscan.toml` would otherwise wave
/// the scan through against a partial file population - a partial boundary graph
/// and a silo aggregate measured over part of its silo, both reported as if they
/// covered the whole. A config that is not on disk (built in memory by a caller)
/// cannot be located and is trusted. `subject` names the rules that forced the
/// check.
fn require_config_root(
    root: &Path,
    config: &crate::config::Config,
    subject: &str,
) -> Result<(), String> {
    let dir = config.config_root();
    if dir.as_os_str().is_empty() || same_dir(dir, root) {
        return Ok(());
    }
    Err(format!(
        "{subject} are relative to {}, the directory holding {}: scan it instead of {}",
        dir.display(),
        crate::config::CONFIG_NAME,
        root.display()
    ))
}

fn same_dir(a: &Path, b: &Path) -> bool {
    let canonical = |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    canonical(a) == canonical(b)
}

fn run(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    silo_sets: Option<Vec<(String, GlobSet)>>,
    anchoring: &Anchoring,
    on_progress: &mut dyn FnMut(Progress),
) -> Result<ScanReport, String> {
    run_with_workers(
        root,
        rules,
        options,
        silo_sets,
        anchoring,
        on_progress,
        workers(),
    )
}

/// Workers for the per-file phase: one per available core, bounded. Falls back
/// to a single worker when the platform will not report a count.
fn workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, MAX_WORKERS)
}

/// The scan proper, with the worker count pinned. Only the per-file phase is
/// parallel: every file's result is tagged with its position in the walk and
/// merged back in that order, so the report does not depend on `workers`.
fn run_with_workers(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    silo_sets: Option<Vec<(String, GlobSet)>>,
    anchoring: &Anchoring,
    on_progress: &mut dyn FnMut(Progress),
    workers: usize,
) -> Result<ScanReport, String> {
    // The walk counts what it excluded as it goes. Reported whatever the scan
    // finds: a tree whose one credential sits behind a `.gitignore` line must
    // not be reportable as a tree with nothing in it.
    let project_dirs = options
        .config
        .map(|config| config.project_ignore_dirs(root))
        .unwrap_or_default();
    let inventory = walk::collect_files_counted_with(
        root,
        &walk::WalkOptions::new(&options.ignore)
            .in_project(&project_dirs)
            .follow_symlinks(options.follow_symlinks),
    );

    scan_prepared_with_workers(
        root,
        rules,
        options,
        silo_sets,
        anchoring,
        inventory,
        on_progress,
        workers,
    )
}

/// The setup [`scan_opts`] performs before it walks: silo globs for boundary
/// rules, the duplication scope check, and the coverage report a coverage rule
/// needs. Split out so a caller that resolves setup ahead of the walk - see
/// [`crate::plan`] - fails on a bad config before it pays for the traversal,
/// and then hands the silo globs straight to [`scan_prepared`].
pub(crate) fn prepared_setup(
    root: &Path,
    rules: &RuleSet,
    config: Option<&crate::config::Config>,
    coverage: Option<&crate::coverage::CoverageReport>,
) -> Result<Option<Vec<(String, GlobSet)>>, String> {
    let silo_sets = boundary_setup(root, rules, config)?;
    duplication_setup(root, rules, config)?;
    // A coverage rule with no report to read produces no findings, which is
    // indistinguishable from a passing gate. Refused here rather than in the
    // CLI so that every caller - the CLI, the TUI, a library consumer - gets
    // the same refusal from the one place that knows both the rules and the
    // report.
    crate::coverage::require_report(&rules.rules, coverage)?;
    Ok(silo_sets)
}

/// Scan one already admitted inventory, with the same worker count the public
/// entry points use. The setup above has already run.
pub(crate) fn scan_prepared(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    silo_sets: Option<Vec<(String, GlobSet)>>,
    anchoring: &Anchoring,
    inventory: walk::WalkResult,
    on_progress: &mut dyn FnMut(Progress),
) -> Result<ScanReport, String> {
    scan_prepared_with_workers(
        root,
        rules,
        options,
        silo_sets,
        anchoring,
        inventory,
        on_progress,
        workers(),
    )
}

/// Scan one owned inventory without traversing the root again.
#[allow(clippy::too_many_arguments)]
fn scan_prepared_with_workers(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    silo_sets: Option<Vec<(String, GlobSet)>>,
    anchoring: &Anchoring,
    inventory: walk::WalkResult,
    on_progress: &mut dyn FnMut(Progress),
    workers: usize,
) -> Result<ScanReport, String> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut suppressed: Vec<Finding> = Vec::new();
    let mut skipped: Vec<SkippedFile> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut graph = crate::graph::Graph::default();
    // Anchored path -> the file it came from, for every scannable file. Every
    // key below is anchored the same way, because they all come from the one
    // `path_rel` each file was given.
    let mut scanned: BTreeMap<String, PathBuf> = BTreeMap::new();
    // Contents of every text file, kept until the duplication pass: it compares
    // every file against every other and so needs them all at once. Holding
    // them costs one copy of the scanned text; reading them a second time after
    // the walk would cost the same memory plus the reads.
    let mut contents: BTreeMap<String, String> = BTreeMap::new();
    let mut file_metrics: BTreeMap<String, FileMetrics> = BTreeMap::new();

    let walk::WalkResult {
        mut files,
        ignored: ignored_entries,
        mut symlinks,
    } = inventory;

    // The cache is not content under review, and when it lands under the scan
    // root it is also not a stable part of the tree: a cold run writes entries a
    // warm run would then walk, read and report, which is the one thing this
    // scanner promises its output does not depend on. Dropped here rather than
    // counted in `ignored`, for the same reason the walker's own `.git` and
    // `.siloscan` exclusions are not counted - an entry that exists only because
    // a scan already ran must not put a number in a report.
    if let Some(excluded) = options.cache.and_then(|cache| cache.exclusion_under(root)) {
        files.retain(|path| !path.starts_with(&excluded));
        symlinks.retain(|entry| !entry.path.starts_with(&excluded));
    }

    // A link whose target this scan never opened is a named path nothing was
    // reported for, which is exactly what `skipped` is: the report saying where
    // it did not look. Merged in before the per-file outcomes so the sort below
    // orders links and skipped files together.
    //
    // Only the unread ones. `SymlinkDisposition::target_was_scanned` is true for
    // a link into the scan root, a followed link and a self-containing directory
    // link, and in all three the file behind the link was read - on its own path
    // or, under `follow_symlinks`, through the link as well. Listing those as
    // skipped would claim the scan missed a file it read, and would bury the
    // links that actually cost coverage in a list of ones that did not. The walk
    // still records them all for a library caller that wants the full picture.
    skipped.extend(
        symlinks
            .iter()
            .filter(|entry| !entry.disposition.target_was_scanned())
            .map(|entry| SkippedFile {
                path: anchoring.relative(root, &entry.path),
                reason: entry.disposition.reason().to_string(),
            }),
    );
    let files_total = files.len();
    on_progress(Progress {
        files_total,
        files_done: 0,
        findings: 0,
    });

    // Built from the rules once rather than once per file: one tree-sitter
    // query per language carries every ast rule's patterns, so a file is
    // walked once instead of once per rule.
    let ast_queries = &crate::engines::ast::AstQueries::build(&rules.rules)?;
    let results = scan_files(
        root,
        rules,
        ast_queries,
        options,
        anchoring,
        &files,
        on_progress,
        workers,
    );

    // Results are in walk order, so the failure reported is the first one the
    // tree contains and not the first one a worker happened to reach. Raised
    // before anything is merged: a rule that could not run leaves holes the
    // rest of the report cannot describe.
    if let Some(error) = results.iter().find_map(|result| match &result.outcome {
        Outcome::Failed(error) => Some(error),
        _ => None,
    }) {
        return Err(error.clone());
    }

    // Every path the walk produced, in walk order, whatever the reader made of
    // it. A presence rule reports a file for existing, so its input is this
    // list and not the subset that read back as text.
    let mut walked: Vec<String> = Vec::with_capacity(results.len());

    for result in results {
        let FileResult {
            path_rel,
            path,
            outcome,
            ..
        } = result;
        walked.push(path_rel.clone());
        match outcome {
            // Binary files are not scannable input, and not a failure either -
            // but they are still files nothing was reported for, so they are
            // recorded. They stay out of `metrics.files`, which describes text
            // the scan actually measured.
            Outcome::Binary => skipped.push(SkippedFile {
                path: path_rel,
                reason: BINARY_SKIP_REASON.to_string(),
            }),
            // Rejected above, before any file was merged.
            Outcome::Failed(_) => unreachable!("a failed file aborts the scan"),
            Outcome::Unreadable(reason) => skipped.push(SkippedFile {
                path: path_rel,
                reason,
            }),
            Outcome::Text {
                facts,
                kept,
                ignored,
                content,
                metrics,
                parse_skipped,
            } => {
                if let Some(facts) = facts {
                    graph.files.insert(path_rel.clone(), facts);
                }
                // A file whose tree was wanted and not built is reported: its
                // ast findings are missing, and silence there would read as a
                // clean file. With a boundary rule loaded the file is still a
                // node in the graph (see [`parse_decision`]), so what is missing
                // there is the edges out of this file and nothing else; the
                // reason says so.
                if let Some(reason) = parse_skipped {
                    skipped.push(SkippedFile {
                        path: path_rel.clone(),
                        reason,
                    });
                }
                contents.insert(path_rel.clone(), content);
                file_metrics.insert(path_rel.clone(), metrics);
                scanned.insert(path_rel, path);

                findings.extend(kept);
                suppressed.extend(ignored);
            }
        }
    }

    // The boundary and coverage engines need the whole tree, so they run once
    // the walk is done. Their findings join the others before suppression and
    // baseline partitioning, so markers and baselines apply to them like any
    // other finding.
    let paths: Vec<String> = scanned.keys().cloned().collect();
    let mut whole_tree: Vec<Finding> = Vec::new();
    let mut boundary_edges: Vec<(String, String, String)> = Vec::new();

    // Presence rules run here, off the walked path list, for the same reason
    // the boundary engine does: their input is the tree rather than one file's
    // contents. Joining the other whole-tree findings puts them through inline
    // suppression, the baseline and the canonical sort like any other finding -
    // and through nothing else, since they are computed from the path and the
    // rules alone and so are never filed in the per-file cache.
    whole_tree.extend(crate::engines::presence::scan_paths(&rules.rules, &walked));

    if let (Some(config), Some(sets)) = (options.config, &silo_sets) {
        let modules = crate::engines::boundary::go_modules(&go_mod_sources(&scanned));
        for violation in
            crate::engines::boundary::scan_graph(&rules.rules, &graph, config, sets, &modules)
        {
            boundary_edges.push((
                violation.from,
                violation.to,
                violation.finding.fingerprint.clone(),
            ));
            whole_tree.push(violation.finding);
        }
    }
    if let Some(coverage) = options.coverage {
        let resolved = crate::coverage::resolve(coverage, &paths);
        // A report that lands on nothing is a coverage gate that measures
        // nothing, which is the missing-report hole with a file in the way of
        // seeing it. It can only be checked here, once the walk has said what
        // the scanned paths are.
        //
        // The rule: a report matching nothing fails the scan, except when both
        // of the following hold, where it is a warning and the coverage rules do
        // not evaluate.
        //
        // One, the scan root is a strict subdirectory of the config root. A
        // whole-project report legitimately covers files a one-module scan never
        // walked, and the module job is the one that was green yesterday; a
        // full-project scan has no such excuse and still fails.
        //
        // Two, the report named files of its own. `resolved` being empty says
        // only that nothing lined up, and there are two ways to get there: a
        // report about a tree this scan is a part of, which is the case above,
        // and a report that measured nothing at all - an empty lcov, a run
        // truncated before it wrote a record, a `--coverage-report` pointed at
        // the wrong file that still parsed. The second is a broken input, it
        // looks exactly the same from a subdirectory as from the root, and
        // excusing it would turn the missing-report hole back on for every
        // module job. So it fails wherever the scan root is.
        //
        // What is left is narrow: the report parsed, it named files, a coverage
        // rule was loaded, the scan root is below the config root, and the
        // warning says the gate did not run. Nothing here lets a subdirectory
        // scan report a coverage pass it did not measure - it reports that it
        // did not measure one.
        match crate::coverage::require_resolved(&rules.rules, coverage, &resolved) {
            Ok(()) => whole_tree.extend(crate::coverage::scan_coverage(
                &rules.rules,
                &resolved,
                &paths,
            )),
            Err(error)
                if !coverage.files.is_empty() && scan_root_below_config(root, options.config) =>
            {
                warnings.push(format!(
                    "{error}; the scan root is below the directory holding {}, so coverage rules \
                     did not evaluate for this scan",
                    crate::config::CONFIG_NAME
                ));
            }
            Err(error) => return Err(error),
        }
    }

    // Metrics are cross-file, so they are computed here rather than per file,
    // and they are never stored in or read from the per-file cache: a warm
    // cache must produce the same numbers as a cold one.
    let (metrics, duplication) = measure(contents, file_metrics, options.config);
    if report_duplicate_blocks(rules, options.config) {
        whole_tree.extend(duplicate_block_findings(&duplication));
    }
    whole_tree.extend(duplication_gates(
        rules,
        &metrics,
        options.config,
        anchoring,
    ));

    let (kept, ignored) = suppress_whole_tree(&scanned, whole_tree);
    findings.extend(kept);
    suppressed.extend(ignored);
    boundary_edges.sort();
    boundary_edges.dedup();

    sort_findings(&mut findings);
    sort_findings(&mut suppressed);
    skipped.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    // Partitioning preserves input order, so both halves stay canonical.
    let (findings, baselined) = match options.baseline {
        Some(baseline) => crate::baseline::partition(baseline, findings),
        None => (findings, Vec::new()),
    };

    Ok(ScanReport {
        findings,
        baselined,
        suppressed,
        skipped,
        // Named apart from the `ignored` half of the suppression split above,
        // which is findings a marker silenced rather than files a walk never
        // read.
        ignored: ignored_entries,
        graph,
        boundary_edges,
        metrics,
        warnings,
    })
}

/// True when the scan root sits strictly below the directory holding the config
/// the scan loaded.
///
/// The comparison is the one [`require_config_root`] makes, minus the equal
/// case: a config that is not on disk has no directory to measure from and is
/// not below anything, and a scan of the config root itself is the whole
/// project rather than a part of it. Both sides are canonicalised, so `.`, `..`
/// and symlinks in either argument do not decide the answer, and a single-file
/// scan root is measured by the directory holding it.
fn scan_root_below_config(root: &Path, config: Option<&crate::config::Config>) -> bool {
    let Some(config) = config else {
        return false;
    };
    let dir = config.config_root();
    if dir.as_os_str().is_empty() {
        return false;
    }

    let canonical = |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let base = canonical(dir);
    let scanned = canonical(measured_from(root));
    scanned != base && scanned.starts_with(&base)
}

/// Whether a scan emits one `metrics.duplicate-block` info finding per copy of
/// every duplicated block.
///
/// The rule: only when the run asked for them, either by `[duplication]
/// report_blocks = true` in `siloscan.toml` or by loading a duplication rule -
/// gating on duplication is asking where the duplication is.
///
/// Off by default because those findings are per copy of every block and so
/// dominate a report on any real tree: 46,891 of 47,102 findings on one Rust
/// codebase, a SARIF file too large for GitHub code scanning to ingest, and
/// every secret in the run buried under them. Nothing is lost by the default -
/// duplication is measured and reported either way, in
/// `metrics.files[*].duplicated_lines`, the totals and the density - and
/// nothing changes when it is turned back on: the same findings with the same
/// fingerprints an existing baseline already covers.
fn report_duplicate_blocks(rules: &RuleSet, config: Option<&crate::config::Config>) -> bool {
    if config.is_some_and(|config| config.duplication.report_blocks) {
        return true;
    }
    rules
        .rules
        .iter()
        .any(|rule| matches!(rule.payload, CompiledPayload::Duplication { .. }))
}

/// Fill the duplication counts into the per-file metrics and roll them up.
/// `contents` is keyed by path, so the files reach the detector in path order
/// and the blocks it reports do not depend on the order the walk finished in.
fn measure(
    contents: BTreeMap<String, String>,
    mut file_metrics: BTreeMap<String, FileMetrics>,
    config: Option<&crate::config::Config>,
) -> (Metrics, DuplicationResult) {
    let min_lines = config
        .map(|config| config.duplication.min_lines)
        .unwrap_or(crate::metrics::DEFAULT_MIN_LINES);

    let files: Vec<(String, String)> = contents.into_iter().collect();
    let duplication = crate::metrics::detect_duplication(&files, min_lines);

    for (path, count) in &duplication.duplicated_lines {
        if let Some(metrics) = file_metrics.get_mut(path) {
            metrics.duplicated_lines = *count;
        }
    }

    let totals = crate::metrics::compute_totals(&file_metrics);
    (
        Metrics {
            files: file_metrics,
            totals,
        },
        duplication,
    )
}

/// How many other copies a duplicate block message names before it stops
/// listing and starts counting. A block copied into every file of a repository
/// would otherwise put one location per copy into every one of its messages,
/// which is quadratic in both time and report size; the locations are all in the
/// report anyway, one finding per copy. The message is not part of the
/// fingerprint, so the cap does not move any identity.
const MAX_LISTED_COPIES: usize = 10;

/// One info finding per copy of every duplicate block, under the reserved rule
/// id. The matched text names the block, so every copy of one block shares it
/// and the occurrence index separates two copies that live in the same file;
/// the message names the other copies and stays out of the fingerprint.
///
/// Called only when [`report_duplicate_blocks`] says the run asked for these.
/// The measurement behind them happens either way.
fn duplicate_block_findings(duplication: &DuplicationResult) -> Vec<Finding> {
    let mut occurrences: HashMap<(String, String), u32> = HashMap::new();
    let mut findings = Vec::new();

    for block in &duplication.blocks {
        let matched = format!(
            "{} duplicated lines (block {})",
            block.line_count, block.normalized_hash_hex12
        );
        // Formatted once per block rather than once per copy: every copy needs
        // the same locations, only its own left out.
        let locations: Vec<String> = block
            .copies
            .iter()
            .map(|copy| format!("{}:{}", copy.path, copy.start_line))
            .collect();

        for (index, copy) in block.copies.iter().enumerate() {
            // Lazy, so at most `MAX_LISTED_COPIES` entries are cloned per copy.
            let others: Vec<&str> = locations
                .iter()
                .enumerate()
                .filter(|(other, _)| *other != index)
                .map(|(_, location)| location.as_str())
                .take(MAX_LISTED_COPIES)
                .collect();
            let hidden = block.copies.len().saturating_sub(1 + others.len());
            let message = if hidden == 0 {
                format!("duplicated block, also at {}", others.join(", "))
            } else {
                format!(
                    "duplicated block, also at {}, and {hidden} more",
                    others.join(", ")
                )
            };

            let counter = occurrences
                .entry((copy.path.clone(), matched.clone()))
                .or_insert(0);
            let occurrence = *counter;
            *counter += 1;

            findings.push(Finding {
                rule_id: DUPLICATE_BLOCK_RULE_ID.to_string(),
                severity: Severity::Info,
                message,
                path: copy.path.clone(),
                line: copy.start_line,
                // Reported at the start of the duplicated block's first line,
                // so both columns are 1 regardless of what that line holds.
                column: 1,
                column_utf16: 1,
                matched: matched.clone(),
                fingerprint: crate::findings::fingerprint(
                    DUPLICATE_BLOCK_RULE_ID,
                    &copy.path,
                    &matched,
                    occurrence,
                ),
            });
        }
    }

    findings
}

/// Run every duplication gate rule over the measured metrics. Silo scope needs
/// the config's silo globs; without a config it reports nothing, which
/// [`scan_opts`] refuses up front.
fn duplication_gates(
    rules: &RuleSet,
    metrics: &Metrics,
    config: Option<&crate::config::Config>,
    anchoring: &Anchoring,
) -> Vec<Finding> {
    let needs_silos = rules.rules.iter().any(|rule| {
        matches!(
            rule.payload,
            CompiledPayload::Duplication {
                scope: DuplicationScope::Silo,
                ..
            }
        )
    });

    // The globs were already validated when the config was loaded, so a failure
    // here is not reachable through the CLI; an in-memory config with a bad
    // glob simply claims no files.
    let sets = match (config, needs_silos) {
        (Some(config), true) => config.silo_sets().ok(),
        _ => None,
    };

    let mut gates = match (config, &sets) {
        (Some(config), Some(sets)) => {
            let silo_of = |path: &str| config.silo_of(sets, path).map(str::to_string);
            crate::engines::duplication::scan_duplication(&rules.rules, metrics, Some(&silo_of))
        }
        _ => crate::engines::duplication::scan_duplication(&rules.rules, metrics, None),
    };
    anchor_scan_aggregates(rules, &mut gates, anchoring);
    gates
}

/// Move whole-scan gate findings onto the scan root's anchored path.
///
/// A `scan` scope gate reports about the scan as a whole rather than about any
/// file, so the engine puts it at `"."`. Under config anchoring that is right
/// only when the scan root is the config root: a subdirectory scan has to say
/// where it was, or the whole-repository run and the module run would report the
/// same gate at two different places. The fingerprint is rebuilt from the inputs
/// the engine used, whose identity for this scope is the empty string - the
/// measured density is deliberately not part of it, so that a gate finding can
/// be baselined at all.
///
/// `silo` scope aggregates also sit at `"."` and are deliberately left where
/// they are. They exist only when the scan root is the config root, because
/// [`duplication_setup`] refuses them otherwise, so their `"."` already means
/// the config root and the prefix is empty in every run that can produce one.
/// `file` scope findings carry a real file path and are already anchored.
fn anchor_scan_aggregates(rules: &RuleSet, gates: &mut [Finding], anchoring: &Anchoring) {
    let scan_root = anchoring.scan_root_path();
    if scan_root == "." {
        return;
    }

    for gate in gates {
        if gate.path != "." || !is_scan_scoped(rules, &gate.rule_id) {
            continue;
        }
        gate.fingerprint = crate::findings::fingerprint(&gate.rule_id, scan_root, "", 0);
        gate.path = scan_root.to_string();
    }
}

/// True when `rule_id` names a duplication gate scoped to the whole scan. Read
/// from the rule rather than guessed from the finding, so the two aggregate
/// scopes are never confused for one another.
fn is_scan_scoped(rules: &RuleSet, rule_id: &str) -> bool {
    rules.rules.iter().any(|rule| {
        rule.id == rule_id
            && matches!(
                rule.payload,
                CompiledPayload::Duplication {
                    scope: DuplicationScope::Scan,
                    ..
                }
            )
    })
}

/// What one file contributed to the report, before any of it is merged.
struct FileResult {
    /// Position in the walk, which is the order the sequential scan merged in.
    index: usize,
    path_rel: String,
    path: PathBuf,
    outcome: Outcome,
}

enum Outcome {
    Binary,
    Unreadable(String),
    /// This file cannot be scanned as its rules demand: a rule it had to run
    /// could not be compiled, or the parse size cap cannot be honoured for it.
    /// Carried rather than raised on the spot: the workers run in parallel, and
    /// the scan reports the failure of the earliest file in walk order so the
    /// message does not depend on which worker reached it first.
    Failed(String),
    Text {
        facts: Option<FileFacts>,
        kept: Vec<Finding>,
        ignored: Vec<Finding>,
        /// Kept for the cross-file duplication pass.
        content: String,
        /// Line counts, measured from the file and never from the cache.
        metrics: FileMetrics,
        /// Why the size cap stopped a parse the rules asked for, when it did.
        /// Decided from the file and the config, never from the cache.
        parse_skipped: Option<String>,
    },
}

/// What the loaded rules need parse trees for, derived from the rule set alone.
///
/// Nothing else in the scanner reads a tree: `code_lines` classifies lines with
/// a heuristic, and the regex, secret, duplication and metrics passes all work
/// on the text. A file no rule needs parsed therefore never reaches tree-sitter,
/// which is the difference between reading a generated bundle and parsing one.
#[derive(Debug, Default)]
struct ParseNeeds {
    /// A boundary rule is loaded. The boundary engine reads its edges out of
    /// the import facts, and only a parse produces those, in any language.
    ///
    /// A flag and not the rules themselves: a rule's `paths` envelope selects
    /// the files it reports *from*, and says nothing about which files may be
    /// imported. The engine resolves an import by looking the target path up in
    /// the graph, so any file missing from the graph can hide an edge, whatever
    /// envelope the rules carry. See [`parse_decision`].
    boundary: bool,
    /// Languages some ast rule carries a query for, sorted and deduplicated.
    ast_languages: Vec<String>,
    /// Languages some metric rule measures, sorted and deduplicated. A metric
    /// rule with no `languages` filter measures every language the engine has a
    /// node-kind table for.
    metric_languages: Vec<String>,
}

impl ParseNeeds {
    fn of(rules: &RuleSet) -> ParseNeeds {
        let mut needs = ParseNeeds::default();
        for rule in &rules.rules {
            match &rule.payload {
                CompiledPayload::Boundary { .. } => needs.boundary = true,
                CompiledPayload::Ast { queries } => {
                    needs
                        .ast_languages
                        .extend(queries.iter().map(|q| q.language.clone()));
                }
                CompiledPayload::Metric { .. } => match &rule.languages {
                    Some(languages) => needs.metric_languages.extend(languages.iter().cloned()),
                    None => needs.metric_languages.extend(
                        crate::engines::metric::LANGUAGES
                            .iter()
                            .map(|lang| (*lang).to_string()),
                    ),
                },
                _ => {}
            }
        }
        needs.ast_languages.sort();
        needs.ast_languages.dedup();
        needs.metric_languages.sort();
        needs.metric_languages.dedup();
        needs
    }

    /// Whether a file in `language` has to be parsed at all.
    fn wants(&self, language: Option<&str>) -> bool {
        let Some(language) = language else {
            return false;
        };
        self.boundary
            || self.ast_languages.iter().any(|wanted| wanted == language)
            || self
                .metric_languages
                .iter()
                .any(|wanted| wanted == language)
    }
}

/// Whether one file is parsed, and what the scan says when it is not.
#[derive(Debug, PartialEq, Eq)]
enum ParseDecision {
    /// Build the tree.
    Parse,
    /// No tree, and no place in the graph. `Some` reason means the size cap
    /// stopped a parse the rules had asked for, which the report records;
    /// `None` means nothing asked.
    Skip(Option<String>),
    /// No tree, but the file still takes its place in the graph as a node with
    /// no imports of its own, so imports of it keep resolving. Always recorded.
    GraphNodeOnly(String),
}

/// What one file's parse decision costs the rest of the scan.
struct ParsePlan {
    /// Build the tree.
    parse: bool,
    /// Enter the file in the graph even without a tree.
    graph_node: bool,
    /// What the report records about the parse that did not happen.
    skipped: Option<String>,
}

impl ParseDecision {
    fn plan(self) -> ParsePlan {
        match self {
            ParseDecision::Parse => ParsePlan {
                parse: true,
                graph_node: false,
                skipped: None,
            },
            ParseDecision::Skip(reason) => ParsePlan {
                parse: false,
                graph_node: false,
                skipped: reason,
            },
            ParseDecision::GraphNodeOnly(reason) => ParsePlan {
                parse: false,
                graph_node: true,
                skipped: Some(reason),
            },
        }
    }
}

/// A file is parsed when some rule needs a tree for its language and the file
/// is no larger than `limits.max_parse_bytes`. Over the cap the file still goes
/// through every engine that works on text; only its tree, and with it its ast
/// findings, are absent, so the file is recorded as skipped.
///
/// The cap holds even when a boundary rule is loaded - a 112 MB tree is
/// gigabytes resident, and the cap is the number the user set to stop that -
/// but such a file is not simply dropped. The boundary engine resolves an
/// import by looking the target path up in the graph, so a file missing from
/// the graph is a hole in *other* files' results: an import from an under-cap
/// file to a dropped one stops resolving, and the violation the under-cap file
/// really commits is never reported - or, where the language resolves a package
/// directory to whichever file it finds there, reported against the wrong silo
/// pair. Which files those are cannot be read off a rule's `paths` envelope:
/// that envelope selects the files a rule reports *from*, while the hole is on
/// the side being imported.
///
/// So an oversized file with a boundary rule loaded is entered in the graph as
/// a node with no imports of its own. Imports of it resolve as they always did,
/// which is the whole-tree half of the problem; what is lost is the edges
/// leaving it, which is local to the file and is what the recorded reason
/// names. Under-reporting is confined to one file and never silent, and no
/// tree is built past the cap.
fn parse_decision(
    needs: &ParseNeeds,
    config: Option<&crate::config::Config>,
    language: Option<&str>,
    size: usize,
) -> ParseDecision {
    if !needs.wants(language) {
        return ParseDecision::Skip(None);
    }

    let cap = config
        .map(|config| config.limits.max_parse_bytes)
        .unwrap_or(crate::config::DEFAULT_MAX_PARSE_BYTES);
    if size as u64 <= cap {
        return ParseDecision::Parse;
    }

    let over_cap = format!("exceeds max_parse_bytes ({size} > {cap})");
    match needs.boundary {
        true => ParseDecision::GraphNodeOnly(format!(
            "{over_cap}; a boundary rule is loaded, so the file stays in the import graph as a \
             node with no imports of its own: imports of it still resolve, imports it makes are \
             not analysed"
        )),
        false => ParseDecision::Skip(Some(over_cap)),
    }
}

/// Run the per-file phase across `workers` scoped threads and return every
/// result in walk order.
///
/// Files are claimed one at a time from a shared cursor, so a slow file does not
/// strand a whole chunk, and each result carries its walk index so the merge is
/// independent of the order they finished in. `on_progress` stays on the calling
/// thread — the callback is `FnMut` and not required to be `Send` — and is
/// driven by one message per completed file, which keeps `files_done` rising by
/// exactly one per event and the event count at `files_total + 1`.
#[allow(clippy::too_many_arguments)]
fn scan_files(
    root: &Path,
    rules: &RuleSet,
    ast_queries: &crate::engines::ast::AstQueries,
    options: &ScanOptions,
    anchoring: &Anchoring,
    files: &[PathBuf],
    on_progress: &mut dyn FnMut(Progress),
    workers: usize,
) -> Vec<FileResult> {
    // Read from the rules once rather than once per file: the answer is the
    // same for every file of a language, and it decides who reaches a parser.
    let needs = &ParseNeeds::of(rules);
    let files_total = files.len();
    let cursor = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel::<usize>();

    let mut results: Vec<FileResult> = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers.max(1) {
            let sender = sender.clone();
            let cursor = &cursor;
            handles.push(scope.spawn(move || {
                let mut produced: Vec<FileResult> = Vec::new();
                loop {
                    let index = cursor.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = files.get(index) else {
                        break;
                    };
                    let (result, raw) = scan_one(
                        root,
                        rules,
                        ast_queries,
                        options,
                        anchoring,
                        needs,
                        index,
                        path,
                    );
                    produced.push(result);
                    // The receiver outlives every worker, so this cannot fail.
                    let _ = sender.send(raw);
                }
                produced
            }));
        }
        // Every remaining sender is worker-owned, so the loop below ends when
        // the last worker does.
        drop(sender);

        let mut raw_findings = 0usize;
        for (done, raw) in receiver.into_iter().enumerate() {
            raw_findings += raw;
            on_progress(Progress {
                files_total,
                files_done: done + 1,
                findings: raw_findings,
            });
        }

        let mut results = Vec::with_capacity(files_total);
        for handle in handles {
            match handle.join() {
                Ok(produced) => results.extend(produced),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        results
    });

    results.sort_by_key(|result| result.index);
    results
}

/// Everything one file contributes, plus its raw match count for progress.
/// Raw means as the engines produced it, before inline suppression.
#[allow(clippy::too_many_arguments)]
fn scan_one(
    root: &Path,
    rules: &RuleSet,
    ast_queries: &crate::engines::ast::AstQueries,
    options: &ScanOptions,
    anchoring: &Anchoring,
    needs: &ParseNeeds,
    index: usize,
    path: &Path,
) -> (FileResult, usize) {
    // The one place a scanned file gets a name. Everything downstream - the
    // fingerprint, the report, the metrics key, the baseline entry - is built
    // from this string, so anchoring it here anchors all of them together.
    let path_rel = anchoring.relative(root, path);
    let (outcome, raw) = match walk::read_text(path) {
        FileKind::Binary => (Outcome::Binary, 0),
        FileKind::Unreadable(reason) => (Outcome::Unreadable(reason), 0),
        FileKind::Text(content) => {
            let language = crate::lang::detect_configured(
                path,
                &content,
                options.config.map(|config| &config.languages),
            );
            // Measured here, from the file itself: a cache hit replaces the
            // engine work below, and metrics must not move with the cache.
            let metrics = crate::metrics::measure_file(&content, language);
            // Decided here, from the file and the config: the cache replaces
            // the engine work below, and a decision taken inside it would move
            // with the cache state.
            let plan = parse_decision(needs, options.config, language, content.len()).plan();
            match scan_text(
                rules,
                ast_queries,
                options,
                &path_rel,
                &content,
                language,
                plan.parse,
                needs.boundary,
            ) {
                Err(error) => (Outcome::Failed(error.to_string()), 0),
                Ok(entry) => {
                    let raw = entry.findings.len();
                    let (kept, ignored) = crate::suppress::partition(&content, entry.findings);
                    (
                        Outcome::Text {
                            // Derived here and not inside `scan_text`: the node
                            // stands in for a parse that did not happen, and a
                            // cache entry must never be able to carry it.
                            facts: entry.facts.or_else(|| graph_node(&plan, language)),
                            kept,
                            ignored,
                            content,
                            metrics,
                            parse_skipped: plan.skipped,
                        },
                        raw,
                    )
                }
            }
        }
    };

    (
        FileResult {
            index,
            path_rel,
            path: path.to_path_buf(),
            outcome,
        },
        raw,
    )
}

/// The graph entry for a file that was not parsed but must not go missing from
/// the graph. It declares the file's language and no imports at all: what the
/// scan knows about it, and nothing it does not. A file the plan does not ask
/// for, or one with no detected language, gets no entry.
fn graph_node(plan: &ParsePlan, language: Option<&str>) -> Option<FileFacts> {
    if !plan.graph_node {
        return None;
    }
    language.map(|language| FileFacts {
        language: language.to_string(),
        imports: Vec::new(),
        decls: Vec::new(),
    })
}

/// Contents of every `go.mod` in the scanned tree, keyed by repo-relative path.
/// They are read again after the walk, as inline suppression does, since the
/// walk keeps no file contents; an unreadable `go.mod` declares no module.
fn go_mod_sources(scanned: &BTreeMap<String, PathBuf>) -> BTreeMap<String, String> {
    let mut sources = BTreeMap::new();
    for (path_rel, path) in scanned {
        if path_rel != "go.mod" && !path_rel.ends_with("/go.mod") {
            continue;
        }
        if let FileKind::Text(content) = walk::read_text(path) {
            sources.insert(path_rel.clone(), content);
        }
    }
    sources
}

/// Apply inline suppression to findings produced after the walk. Their file
/// content is no longer in memory, so the files they landed on are read again;
/// a file that has become unreadable since the walk suppresses nothing.
fn suppress_whole_tree(
    scanned: &BTreeMap<String, PathBuf>,
    findings: Vec<Finding>,
) -> (Vec<Finding>, Vec<Finding>) {
    let mut by_path: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for finding in findings {
        by_path
            .entry(finding.path.clone())
            .or_default()
            .push(finding);
    }

    let mut kept: Vec<Finding> = Vec::new();
    let mut ignored: Vec<Finding> = Vec::new();
    for (path, group) in by_path {
        match scanned.get(&path).map(|file| walk::read_text(file)) {
            Some(FileKind::Text(content)) => {
                let (in_force, marked) = crate::suppress::partition(&content, group);
                kept.extend(in_force);
                ignored.extend(marked);
            }
            _ => kept.extend(group),
        }
    }

    (kept, ignored)
}

/// Engine results for one text file, from the cache when possible.
///
/// The cache holds raw engine output: findings as the engines produced them,
/// before inline suppression. Suppression is re-applied to every retrieved
/// entry. The content hash covers the markers either way, so this is a wash for
/// correctness and keeps the stored payload engine-pure.
///
/// `graph` is [`ParseNeeds::boundary`]: whether the import facts have a reader.
/// It is not part of the entry key, unlike `parse`, and does not need to be.
/// `parse` turns on the config's parse cap and the file's own size, neither of
/// which the key's rule hash covers; `graph` is a function of the loaded rules
/// alone, and [`Cache::bind`] folds [`RuleSet::source_hash`] into the scope
/// every entry is filed under. Two runs that disagree about `graph` disagree
/// about their rule sources, so they read and write different namespaces and a
/// run that needs facts can never be served an entry written without them.
#[allow(clippy::too_many_arguments)]
fn scan_text(
    rules: &RuleSet,
    ast_queries: &crate::engines::ast::AstQueries,
    options: &ScanOptions,
    path_rel: &str,
    content: &str,
    language: Option<&str>,
    parse: bool,
    graph: bool,
) -> Result<crate::cache::CachedFile, RegexCompileError> {
    let hash = options
        .cache
        .map(|_| entry_hash(path_rel, content, language, parse));

    if let (Some(cache), Some(hash)) = (options.cache, &hash)
        && let Some(entry) = cache.get(hash, content)
    {
        return Ok(entry);
    }

    let tree = match parse {
        true => {
            language.and_then(|lang| crate::parsers::parse_file(lang, Path::new(path_rel), content))
        }
        false => None,
    };

    let mut file_findings =
        crate::engines::regex::scan_file(&rules.rules, path_rel, language, content);
    // A secret rule that had to match and could not compile fails the scan
    // here, before anything is cached: a failed file must not leave an entry a
    // later run would be served in place of the same failure.
    file_findings.extend(crate::engines::secret::scan_file(
        &rules.rules,
        path_rel,
        language,
        content,
    )?);
    file_findings.extend(crate::engines::ast::scan_file(
        &rules.rules,
        ast_queries,
        path_rel,
        language,
        content,
        tree.as_ref(),
    ));
    // The same tree, walked once more: a metric rule counts what a query
    // cannot.
    file_findings.extend(crate::engines::metric::scan_file(
        &rules.rules,
        path_rel,
        language,
        content,
        tree.as_ref(),
    ));

    // Extracted only for the one thing that reads it. Walking a parsed tree for
    // its imports costs about as much as the parse did, and with no boundary
    // rule loaded the result is built, cached and never looked at.
    let facts = match (graph, language, &tree) {
        (true, Some(lang), Some(tree)) => Some(crate::graph::extract_file(
            lang,
            Path::new(path_rel),
            content,
            tree,
        )),
        _ => None,
    };

    let entry = crate::cache::CachedFile {
        findings: file_findings,
        facts,
    };
    if let (Some(cache), Some(hash)) = (options.cache, &hash) {
        cache.put(hash, &entry);
    }
    Ok(entry)
}

/// Cache entries are keyed by path and content together: a finding carries its
/// repo-relative path, and its fingerprint is derived from it, so two identical
/// files at different paths are not interchangeable.
///
/// The language and parse decision lead the key. Both select which engines ran,
/// and both may now come from config rather than from the rule sources the rest
/// of the key covers. A cache entry written under one configured extension or
/// parse-size decision must not be served under another.
fn entry_hash(path_rel: &str, content: &str, language: Option<&str>, parse: bool) -> String {
    let language = language.unwrap_or("");
    let mut buf = Vec::with_capacity(path_rel.len() + content.len() + language.len() + 3);
    buf.push(if parse { b'1' } else { b'0' });
    buf.extend_from_slice(language.as_bytes());
    buf.push(0);
    buf.extend_from_slice(path_rel.as_bytes());
    buf.push(0);
    buf.extend_from_slice(content.as_bytes());
    crate::cache::content_hash(&buf)
}

/// Canonical order: path (bytewise), line, column, rule id.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.path
            .as_bytes()
            .cmp(b.path.as_bytes())
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.rule_id.as_bytes().cmp(b.rule_id.as_bytes()))
    });
}

/// Scan-root-relative, forward-slash path. It must depend only on the scanned
/// tree, never on anything above the scan root; [`Anchoring::relative`] is what
/// puts a path from above the scan root in front of it, and only when the config
/// asked for one. A file scan root reports its file name so the path is never
/// empty.
fn relative(root: &Path, path: &Path) -> String {
    let tail = path.strip_prefix(root).unwrap_or(path);
    let joined = join_slashes(tail);
    if joined.is_empty() {
        join_slashes(Path::new(path.file_name().unwrap_or(path.as_os_str())))
    } else {
        joined
    }
}

fn join_slashes(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<String>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use crate::rules::load_str;

    const RULES: &str = r#"
version: 1
rules:
  - id: test.needle
    severity: warning
    message: "needle found"
    regex:
      pattern: "needle"
"#;

    const SECRET_RULES: &str = r#"
version: 1
rules:
  - id: test.token
    severity: error
    message: "token found"
    secret:
      pattern: "tok_[a-z0-9]+"
"#;

    fn ruleset() -> RuleSet {
        RuleSet {
            rules: load_str(RULES, "test").expect("rules should load"),
            sources: vec![("test".to_string(), RULES.to_string())],
        }
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // Every rule set below compiles, so a scan of it cannot fail on one. These
    // shadow the fallible entry points for the tests that only care about the
    // report; the failure path has its own tests at the bottom of this module.

    fn scan(
        root: &Path,
        rules: &RuleSet,
        baseline: Option<&crate::baseline::Baseline>,
    ) -> ScanReport {
        super::scan(root, rules, baseline).expect("rules compile")
    }

    fn scan_with_progress(
        root: &Path,
        rules: &RuleSet,
        baseline: Option<&crate::baseline::Baseline>,
        on_progress: &mut dyn FnMut(Progress),
    ) -> ScanReport {
        super::scan_with_progress(root, rules, baseline, on_progress).expect("rules compile")
    }

    fn run_with_workers(
        root: &Path,
        rules: &RuleSet,
        options: &ScanOptions,
        silo_sets: Option<Vec<(String, GlobSet)>>,
        anchoring: &Anchoring,
        on_progress: &mut dyn FnMut(Progress),
        workers: usize,
    ) -> ScanReport {
        super::run_with_workers(
            root,
            rules,
            options,
            silo_sets,
            anchoring,
            on_progress,
            workers,
        )
        .expect("rules compile")
    }

    /// Mark `dir` as a repository root the way git does, so `config::discover`
    /// may walk above it.
    fn git_root(dir: &Path) {
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    fn write(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    /// A cache base for one test, standing in for the user's cache directory.
    ///
    /// Tests take a base explicitly rather than letting [`crate::cache::Cache::open`]
    /// find the real one: `cargo test` must not write into the developer's
    /// `~/.cache/siloscan`, and a test that did would also read whatever an
    /// earlier run left there, which is a cache-state dependency in the one
    /// suite that exists to prove there is none.
    ///
    /// It is a parameter and not a per-cache tempdir because two caches in one
    /// test are often required to share a directory: separate bases would make
    /// `a_cache_entry_from_one_convention_never_serves_the_other` pass because
    /// the two caches were in different places, not because the scope
    /// discriminator kept them apart.
    fn cache_base() -> tempfile::TempDir {
        tempdir()
    }

    /// A cache for the default, scan-root-anchored convention.
    fn cache_for(base: &Path, root: &Path, rules: &RuleSet) -> crate::cache::Cache {
        crate::cache::Cache::open_in(base, root, rules, &crate::cache::PathScope::ScanRoot)
    }

    /// A cache for the convention `anchoring` describes.
    fn cache_anchored(
        base: &Path,
        root: &Path,
        rules: &RuleSet,
        anchoring: &Anchoring,
    ) -> crate::cache::Cache {
        let scope = crate::cache::PathScope::new(anchoring.anchor(), anchoring.prefix());
        crate::cache::Cache::open_in(base, root, rules, &scope)
    }

    #[test]
    fn prepared_scan_uses_one_admitted_walk_and_matches_legacy_bytes() {
        let dir = tempdir();
        write(dir.path(), "src/first.rs", b"needle\n");
        write(dir.path(), ".gitignore", b"ignored.rs\n");
        write(dir.path(), "ignored.rs", b"needle\n");

        let rules = ruleset();
        let options = ScanOptions::default();
        let anchoring = Anchoring::default();
        let legacy = scan(dir.path(), &rules, None);
        let inventory = walk::collect_files_counted(dir.path(), &options.ignore);
        // This match arrives after admission. A prepared scanner that walks a
        // second time reports it and disagrees with the legacy result below.
        write(dir.path(), "src/late.rs", b"needle\n");

        let prepared = super::scan_prepared_with_workers(
            dir.path(),
            &rules,
            &options,
            None,
            &anchoring,
            inventory,
            &mut |_| {},
            1,
        )
        .expect("prepared rules compile");

        assert_eq!(
            serde_json::to_string(&legacy).unwrap(),
            serde_json::to_string(&prepared).unwrap()
        );
        assert_eq!(prepared.findings.len(), 1, "the late file was not admitted");
        assert_eq!(prepared.findings[0].path, "src/first.rs");
    }

    /// The walk policy is a scan input, so `ScanOptions::ignore` has to reach
    /// the walker. Without this the field compiles, defaults correctly, and is
    /// ignored - a `--no-ignore` that reports "clean" on a tree whose secret is
    /// one `.gitignore` line away, which is the exact failure the option
    /// exists to prevent.
    #[test]
    fn the_ignore_policy_reaches_the_walk() {
        let dir = tempdir();
        write(dir.path(), ".gitignore", b"hidden/\n");
        write(dir.path(), "hidden/a.rs", b"let needle = 1;\n");
        write(dir.path(), "src/b.rs", b"let needle = 2;\n");
        let rules = ruleset();
        let anchoring = Anchoring::default();

        let honored = run_with_workers(
            dir.path(),
            &rules,
            &ScanOptions::default(),
            None,
            &anchoring,
            &mut |_| {},
            1,
        );
        assert_eq!(honored.findings.len(), 1, "the ignored file must stay out");
        assert_eq!(honored.findings[0].path, "src/b.rs");

        let everything = run_with_workers(
            dir.path(),
            &rules,
            &ScanOptions {
                ignore: walk::IgnoreOptions::all_files(),
                ..Default::default()
            },
            None,
            &anchoring,
            &mut |_| {},
            1,
        );
        let paths: Vec<&str> = everything
            .findings
            .iter()
            .map(|finding| finding.path.as_str())
            .collect();
        assert_eq!(paths, ["hidden/a.rs", "src/b.rs"]);

        // The finding both scans saw is the same finding: widening the walk
        // adds files, it does not renumber the ones already there.
        let widened = everything
            .findings
            .iter()
            .find(|finding| finding.path == "src/b.rs")
            .expect("src/b.rs is in both scans");
        assert_eq!(widened.fingerprint, honored.findings[0].fingerprint);
    }

    /// The 1.2.0 repro: a live credential behind one in-root `.gitignore` line
    /// produced no finding, no skipped entry and no count - a report
    /// indistinguishable from a tree that has nothing in it. The file is still
    /// out of the scan; what changed is that the report says so.
    #[test]
    fn an_ignored_file_is_counted_in_the_report() {
        let dir = tempdir();
        write(dir.path(), ".gitignore", b".env\n");
        write(dir.path(), ".env", b"needle\n");
        write(dir.path(), "src/main.rs", b"fn main() {}\n");

        let report = scan(dir.path(), &ruleset(), None);

        assert!(report.findings.is_empty());
        assert_eq!(
            report.ignored,
            walk::Ignored {
                files: 1,
                directories: 0
            }
        );
        let line = report
            .ignored
            .summary_line()
            .expect("the human summary has a line to print");
        assert!(line.contains("ignored by .gitignore/.ignore"), "{line}");
    }

    /// A count of zero and no line: "clean" has to stay distinguishable from
    /// "did not look", which means it must not carry the wording either.
    #[test]
    fn a_tree_with_nothing_ignored_reports_zero_and_no_line() {
        let dir = tempdir();
        write(dir.path(), "src/main.rs", b"needle\n");

        let report = scan(dir.path(), &ruleset(), None);

        assert_eq!(report.findings.len(), 1);
        assert!(report.ignored.is_empty());
        assert_eq!(report.ignored.summary_line(), None);
    }

    /// An ignored directory is counted once, from the outside. The walk does
    /// not descend into it, so the number cannot grow with what is inside.
    #[test]
    fn an_ignored_directory_is_counted_once() {
        let dir = tempdir();
        write(dir.path(), ".gitignore", b"node_modules/\n");
        for i in 0..5 {
            write(
                dir.path(),
                &format!("node_modules/pkg/f{i}.js"),
                b"const needle = 1;\n",
            );
        }
        write(dir.path(), "src/main.rs", b"needle\n");

        let report = scan(dir.path(), &ruleset(), None);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.ignored,
            walk::Ignored {
                files: 0,
                directories: 1
            }
        );
    }

    /// The count is part of the report, so it obeys the report's rule: the
    /// worker count may not change a byte of it.
    #[test]
    fn the_ignored_count_does_not_depend_on_the_worker_count() {
        let dir = tempdir();
        write(dir.path(), ".gitignore", b"*.log\nbuild/\n");
        synthetic_tree(dir.path(), 60);
        for name in ["a.log", "b.log", "src/c.log"] {
            write(dir.path(), name, b"needle\n");
        }
        write(dir.path(), "build/out/app.js", b"needle\n");

        let rules = ruleset();
        let options = ScanOptions::default();
        let counted = |workers| {
            run_with_workers(
                dir.path(),
                &rules,
                &options,
                None,
                &Anchoring::default(),
                &mut |_| {},
                workers,
            )
            .ignored
        };

        let expected = walk::Ignored {
            files: 3,
            directories: 1,
        };
        assert_eq!(counted(1), expected);
        assert_eq!(counted(8), expected);
    }

    /// Nothing about the count may move with cache state: the cache lives
    /// outside the scanned tree, and the walk runs before any entry is looked
    /// up. See [`a_cache_under_the_scan_root_is_kept_out_of_the_walk`] for the
    /// layouts where "outside the tree" is not enough on its own.
    #[test]
    fn the_ignored_count_is_the_same_cold_and_warm() {
        let dir = tempdir();
        write(dir.path(), ".gitignore", b"secret.txt\nvendor/\n");
        write(dir.path(), "secret.txt", b"needle\n");
        write(dir.path(), "vendor/dep.rs", b"needle\n");
        write(dir.path(), "src/main.rs", b"needle\n");

        let rules = ruleset();
        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        let expected = walk::Ignored {
            files: 1,
            directories: 1,
        };
        assert_eq!(cold.ignored, expected);
        assert_eq!(warm.ignored, expected);
        // The cold run filled the cache, so the warm run above is genuinely
        // warm - and it filled it outside the scanned tree, which is why the
        // two counts can be equal at all. A cache written into the tree would
        // appear in the second walk and not the first.
        assert!(!cache_entry_paths(cache_home.path()).is_empty());
        assert!(!dir.path().join(".siloscan").exists());
        assert_eq!(
            serde_json::to_string(&cold).unwrap(),
            serde_json::to_string(&warm).unwrap()
        );
    }

    /// The cache is out of the scanned tree by location policy, but a scan root
    /// can be put above it: `siloscan ~`, `siloscan /`, any root above
    /// `XDG_CACHE_HOME`, or a `--cache-dir` inside the root, which is the shape
    /// this test uses because it needs no environment. The cold run writes
    /// entries and a salt; without the exclusion the warm run walks them, and
    /// the two reports stop being the same report.
    #[test]
    fn a_cache_under_the_scan_root_is_kept_out_of_the_walk() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"needle\n");

        let rules = ruleset();
        let inside = dir.path().join("cache");
        let cache = cache_for(&inside, dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        // The cold run really did fill the cache inside the tree, so the warm
        // run had something to walk and did not.
        assert!(!cache_entry_paths(&inside).is_empty());
        assert_eq!(
            cold.metrics.files.keys().collect::<Vec<_>>(),
            vec!["src/a.rs"]
        );
        assert_eq!(
            serde_json::to_string(&cold).unwrap(),
            serde_json::to_string(&warm).unwrap()
        );
        // The salt is the sharpest case: a scan that reads it is reporting on
        // its own authentication secret.
        assert!(
            warm.metrics
                .files
                .keys()
                .all(|path| !path.contains(".salt")),
            "{:?}",
            warm.metrics.files.keys().collect::<Vec<_>>()
        );
    }

    /// Only the directory the cache actually occupies. A `--cache-dir` names a
    /// directory this crate does not own, so it does not get to declare the
    /// user's other files there unscannable - that would be a scanned tree
    /// silently shrinking, which is the thing the exclusion exists to prevent.
    #[test]
    fn the_exclusion_covers_the_cache_and_not_the_directory_holding_it() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"needle\n");
        write(dir.path(), "src/kept.rs", b"needle\n");

        let rules = ruleset();
        // The cache is put inside the source directory on purpose.
        let cache = cache_for(&dir.path().join("src"), dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        assert_eq!(
            warm.metrics.files.keys().collect::<Vec<_>>(),
            vec!["src/a.rs", "src/kept.rs"]
        );
        assert_eq!(
            serde_json::to_string(&cold).unwrap(),
            serde_json::to_string(&warm).unwrap()
        );
    }

    #[test]
    fn scans_a_tree_end_to_end() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let x = 1;\nlet needle = 2;\n");
        write(dir.path(), "src/deep/b.rs", b"// nothing here\n");

        let report = scan(dir.path(), &ruleset(), None);

        assert!(report.skipped.is_empty());
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "test.needle");
        assert_eq!(finding.path, "src/a.rs");
        assert_eq!(finding.line, 2);
        assert_eq!(finding.column, 5);
        assert_eq!(finding.matched, "needle");
        assert_eq!(finding.fingerprint.len(), 64);
    }

    #[test]
    fn findings_are_in_canonical_order() {
        let dir = tempdir();
        // Created in non-sorted order on purpose.
        write(dir.path(), "z.rs", b"needle\nfiller\nneedle\n");
        write(dir.path(), "src/m.rs", b"needle needle\n");
        write(dir.path(), "a.rs", b"filler\nneedle\n");

        let report = scan(dir.path(), &ruleset(), None);

        let order: Vec<(&str, u64, u64)> = report
            .findings
            .iter()
            .map(|f| (f.path.as_str(), f.line, f.column))
            .collect();
        assert_eq!(
            order,
            vec![
                ("a.rs", 2, 1),
                ("src/m.rs", 1, 1),
                ("src/m.rs", 1, 8),
                ("z.rs", 1, 1),
                ("z.rs", 3, 1),
            ]
        );
    }

    #[test]
    fn file_scan_root_still_reports_a_path() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"needle\n");

        let report = scan(&dir.path().join("src/a.rs"), &ruleset(), None);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "a.rs");
    }

    #[test]
    fn paths_are_relative_to_the_scan_root() {
        let dir = tempdir();
        write(dir.path(), "sub/b.rs", b"needle\n");

        let from_root = scan(dir.path(), &ruleset(), None);
        let from_sub = scan(&dir.path().join("sub"), &ruleset(), None);

        assert_eq!(from_root.findings.len(), 1);
        assert_eq!(from_root.findings[0].path, "sub/b.rs");
        assert_eq!(from_sub.findings.len(), 1);
        assert_eq!(from_sub.findings[0].path, "b.rs");
        // Paths never reach above the scan root, wherever the tree lives.
        assert!(!from_root.findings[0].path.contains(".."));
    }

    /// A binary file holds text the engines never see. Reporting nothing for it
    /// and saying nothing about it are the same output, so it is recorded.
    #[test]
    fn binary_file_is_recorded_as_skipped() {
        let dir = tempdir();
        write(dir.path(), "blob.bin", b"needle\0\0\0needle");
        write(dir.path(), "ok.txt", b"needle\n");

        let report = scan(dir.path(), &ruleset(), None);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, "blob.bin");
        assert_eq!(report.skipped[0].reason, BINARY_SKIP_REASON);
        // Recorded, not scanned, and not measured.
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "ok.txt");
        assert!(!report.metrics.files.contains_key("blob.bin"));
        assert!(report.metrics.files.contains_key("ok.txt"));
    }

    /// A presence rule: the file existing where the glob points is the finding,
    /// with no pattern and nothing read.
    fn presence_ruleset() -> RuleSet {
        const SRC: &str = r#"
version: 1
rules:
  - id: a.keystore
    severity: error
    message: a committed PKCS 12 keystore
    paths:
      case_insensitive: true
      include: ['**/*.p12']
"#;
        RuleSet {
            rules: load_str(SRC, "presence").expect("rules should load"),
            sources: vec![("presence".to_string(), SRC.to_string())],
        }
    }

    /// The point of the rule shape: a keystore is binary, the reader stops at
    /// its first NUL, and the finding is about the file being there at all. So
    /// the same file is both reported and recorded as skipped, which is the
    /// truth - nothing read it, and it is still a finding.
    #[test]
    fn a_presence_rule_reports_a_binary_file_the_scan_never_read() {
        let dir = tempdir();
        write(dir.path(), "certs/server.P12", b"\0\0keystore bytes\0\0");
        write(dir.path(), "certs/server.pem", b"not a keystore\n");

        let report = scan(dir.path(), &presence_ruleset(), None);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "a.keystore");
        assert_eq!(finding.path, "certs/server.P12");
        assert_eq!((finding.line, finding.column), (1, 1));
        assert_eq!(finding.matched, "server.P12");
        assert_eq!(
            finding.fingerprint,
            crate::findings::fingerprint("a.keystore", "certs/server.P12", "server.P12", 0)
        );
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, "certs/server.P12");
        assert_eq!(report.skipped[0].reason, BINARY_SKIP_REASON);
    }

    /// A presence finding is computed from the walked path and the rules, and
    /// is never filed in the per-file cache. A warm run has to produce it
    /// anyway - a cache that could swallow it would make a keystore a
    /// first-run-only finding.
    #[test]
    fn a_presence_finding_survives_a_warm_cache() {
        let dir = tempdir();
        write(dir.path(), "certs/server.p12", b"\0\0keystore bytes\0\0");
        write(dir.path(), "notes.txt", b"nothing here\n");

        let rules = presence_ruleset();
        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        assert_eq!(cold.findings.len(), 1);
        assert_eq!(
            serde_json::to_string(&cold).unwrap(),
            serde_json::to_string(&warm).unwrap()
        );
    }

    /// The entries are merged by whichever worker produced them, so the list is
    /// sorted before it is reported.
    #[test]
    fn skipped_binary_files_are_sorted_whatever_the_worker_count() {
        let dir = tempdir();
        for name in ["z.bin", "a.bin", "src/m.bin", "src/deep/b.bin"] {
            write(dir.path(), name, b"\0binary needle\n");
        }
        write(dir.path(), "ok.txt", b"needle\n");

        let rules = ruleset();
        let options = ScanOptions::default();
        let paths = |workers| {
            let report = run_with_workers(
                dir.path(),
                &rules,
                &options,
                None,
                &Anchoring::default(),
                &mut |_| {},
                workers,
            );
            report
                .skipped
                .iter()
                .map(|s| s.path.clone())
                .collect::<Vec<String>>()
        };

        let expected = vec!["a.bin", "src/deep/b.bin", "src/m.bin", "z.bin"];
        assert_eq!(paths(1), expected);
        assert_eq!(paths(8), expected);
    }

    #[test]
    fn secret_rules_run_alongside_regex_rules() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"let key = \"tok_abc123\";\n");

        let rules = RuleSet {
            rules: load_str(RULES, "regex")
                .unwrap()
                .into_iter()
                .chain(load_str(SECRET_RULES, "secret").unwrap())
                .collect(),
            ..Default::default()
        };
        let report = scan(dir.path(), &rules, None);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "test.token");
        assert_eq!(report.findings[0].matched, "tok_abc123");
    }

    #[test]
    fn inline_markers_move_findings_to_suppressed() {
        let dir = tempdir();
        write(
            dir.path(),
            "a.rs",
            b"// siloscan-ignore: test.needle\nlet a = needle;\nlet b = 2;\n",
        );
        write(dir.path(), "b.rs", b"needle\n");

        let report = scan(dir.path(), &ruleset(), None);

        // The marker line itself matches the rule; line 2 is suppressed.
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.suppressed.len(), 1);
        assert_eq!(report.suppressed[0].path, "a.rs");
        assert_eq!(report.suppressed[0].line, 2);
    }

    #[test]
    fn baseline_moves_known_findings_out_of_findings() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "b.rs", b"needle\n");

        let first = scan(dir.path(), &ruleset(), None);
        let baseline = crate::baseline::Baseline {
            version: 1,
            entries: vec![crate::baseline::BaselineEntry {
                fingerprint: first.findings[0].fingerprint.clone(),
                rule_id: first.findings[0].rule_id.clone(),
                path: first.findings[0].path.clone(),
            }],
        };

        let report = scan(dir.path(), &ruleset(), Some(&baseline));

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "b.rs");
        assert_eq!(report.baselined.len(), 1);
        assert_eq!(report.baselined[0].path, "a.rs");
    }

    fn collect_progress(root: &Path, rules: &RuleSet) -> (ScanReport, Vec<Progress>) {
        let mut events = Vec::new();
        let report = scan_with_progress(root, rules, None, &mut |p| events.push(p));
        (report, events)
    }

    #[test]
    fn progress_is_emitted_once_per_file_plus_one() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle needle\n");
        write(dir.path(), "src/c.rs", b"nothing\n");

        let (_report, events) = collect_progress(dir.path(), &ruleset());

        assert_eq!(events.len(), 4);
        assert_eq!(
            events[0],
            Progress {
                files_total: 3,
                files_done: 0,
                findings: 0,
            }
        );
        let last = events.last().unwrap();
        assert_eq!(last.files_done, 3);
        assert_eq!(last.files_total, 3);
        assert_eq!(last.findings, 3);
    }

    #[test]
    fn progress_counters_are_monotonic() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "b.rs", b"filler\n");
        write(dir.path(), "c.rs", b"needle\nneedle\n");

        let (_report, events) = collect_progress(dir.path(), &ruleset());

        for pair in events.windows(2) {
            assert_eq!(pair[1].files_done, pair[0].files_done + 1);
            assert!(pair[1].findings >= pair[0].findings);
            assert_eq!(pair[1].files_total, pair[0].files_total);
            assert!(pair[1].files_done <= pair[1].files_total);
        }
    }

    #[test]
    fn progress_counts_raw_matches_before_suppression() {
        let dir = tempdir();
        write(
            dir.path(),
            "a.rs",
            b"// siloscan-ignore: test.needle\nlet a = needle;\n",
        );

        let (report, events) = collect_progress(dir.path(), &ruleset());

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suppressed.len(), 1);
        assert_eq!(events.last().unwrap().findings, 2);
    }

    #[test]
    fn progress_scan_matches_plain_scan() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle\nneedle\n");
        write(dir.path(), "blob.bin", b"needle\0\0needle");

        let first = scan(dir.path(), &ruleset(), None);
        let baseline = crate::baseline::Baseline {
            version: 1,
            entries: vec![crate::baseline::BaselineEntry {
                fingerprint: first.findings[0].fingerprint.clone(),
                rule_id: first.findings[0].rule_id.clone(),
                path: first.findings[0].path.clone(),
            }],
        };

        let plain = scan(dir.path(), &ruleset(), Some(&baseline));
        let tracked = scan_with_progress(dir.path(), &ruleset(), Some(&baseline), &mut |_| {});

        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            serde_json::to_string(&tracked).unwrap()
        );
    }

    /// A tree big enough that a worker pool actually splits it, mixing every
    /// per-file outcome: matches, no matches, inline markers, binary files.
    fn synthetic_tree(root: &Path, files: usize) {
        for i in 0..files {
            let rel = format!("src/mod{:02}/f{i:03}.rs", i % 7);
            match i % 4 {
                0 => write(root, &rel, b"needle\nfiller\nneedle needle\n"),
                1 => write(root, &rel, b"nothing to see\n"),
                2 => write(
                    root,
                    &rel,
                    b"// siloscan-ignore: test.needle\nlet a = needle;\nneedle\n",
                ),
                _ => write(root, &rel, b"needle\0binary needle\n"),
            }
        }
    }

    #[test]
    fn worker_count_does_not_change_the_report() {
        let dir = tempdir();
        synthetic_tree(dir.path(), 200);

        let rules = ruleset();
        let options = ScanOptions::default();
        let report = |workers| {
            let mut events: Vec<Progress> = Vec::new();
            let report = run_with_workers(
                dir.path(),
                &rules,
                &options,
                None,
                &Anchoring::default(),
                &mut |p| events.push(p),
                workers,
            );
            (serde_json::to_string(&report).unwrap(), events)
        };

        let (single, single_events) = report(1);
        let (parallel, parallel_events) = report(8);

        assert_eq!(single, parallel);
        // Non-empty, so the comparison above is not vacuous.
        assert!(single.contains("test.needle"));
        assert_eq!(single_events.len(), parallel_events.len());
        assert_eq!(single_events.last(), parallel_events.last());
        for events in [&single_events, &parallel_events] {
            for pair in events.windows(2) {
                assert_eq!(pair[1].files_done, pair[0].files_done + 1);
                assert!(pair[1].findings >= pair[0].findings);
            }
        }
    }

    fn cached_scan(root: &Path, rules: &RuleSet, cache: &crate::cache::Cache) -> ScanReport {
        let options = ScanOptions {
            cache: Some(cache),
            ..ScanOptions::default()
        };
        scan_opts(root, rules, &options, &mut |_| {}).expect("no config, no failure")
    }

    #[test]
    fn cache_hit_reproduces_the_uncached_report() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle needle\n");

        let rules = ruleset();
        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        assert_eq!(
            serde_json::to_string(&cold).unwrap(),
            serde_json::to_string(&warm).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&scan(dir.path(), &rules, None)).unwrap(),
            serde_json::to_string(&warm).unwrap()
        );
    }

    /// End-to-end determinism across every cache state a scan can meet, on a
    /// tree whose one file holds a live-looking credential.
    ///
    /// Three runs: a cold cache, the warm cache that run left behind, and a
    /// cache whose entries have been rewritten to claim the file is clean. All
    /// three reports have to be byte-identical, and all three have to name the
    /// credential.
    ///
    /// The third run is the one that matters. An entry saying `findings: []`
    /// for a file holding a credential is the cheapest possible way to make a
    /// scanner report a clean tree, so the scan may not believe one it cannot
    /// authenticate. The entry is authenticated under a salt the writer of a
    /// forged entry does not have, so a rewritten one fails to authenticate,
    /// misses, and the file is scanned for real. "Cannot be read" resolves to
    /// "scan it", never to "it was clean".
    ///
    /// Moving the cache out of the scanned tree in 1.4.0 removed the cheapest
    /// route to a forged entry - a repository could previously commit one - but
    /// it did not remove the requirement. The cache is still a file on a disk
    /// that other things can write to, and an entry that is merely corrupt has
    /// to resolve the same way a hostile one does. This test is what says so.
    #[test]
    fn no_cache_state_can_change_what_a_scan_reports() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"let key = \"tok_abc123\";\n");
        write(dir.path(), "src/b.rs", b"let clean = 1;\n");

        let rules = RuleSet {
            rules: load_str(SECRET_RULES, "secret").unwrap(),
            sources: vec![("secret".to_string(), SECRET_RULES.to_string())],
        };

        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        // The cold run populated the cache, or the run below proves nothing.
        let entries = cache_entry_paths(cache_home.path());
        assert!(!entries.is_empty(), "the cold run wrote no cache entries");

        // Every entry now claims its file is clean. At least one of them said
        // otherwise a moment ago - without that, emptying `findings` would be
        // a no-op and this test would pass on a scanner that trusted it.
        let mut emptied_a_real_finding = false;
        for path in &entries {
            let text = std::fs::read_to_string(path).unwrap();
            let mut entry: serde_json::Value = serde_json::from_str(&text).unwrap();
            emptied_a_real_finding |= entry["findings"]
                .as_array()
                .is_some_and(|findings| !findings.is_empty());
            entry["findings"] = serde_json::Value::Array(Vec::new());
            std::fs::write(path, serde_json::to_string(&entry).unwrap()).unwrap();
        }
        assert!(
            emptied_a_real_finding,
            "no cached entry carried a finding, so the rewrite proves nothing"
        );
        let poisoned = cached_scan(dir.path(), &rules, &cache);

        let cold_json = serde_json::to_string(&cold).unwrap();
        assert_eq!(cold_json, serde_json::to_string(&warm).unwrap());
        assert_eq!(
            cold_json,
            serde_json::to_string(&poisoned).unwrap(),
            "a rewritten cache entry changed the report"
        );

        for report in [&cold, &warm, &poisoned] {
            assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
            assert_eq!(report.findings[0].rule_id, "test.token");
            assert_eq!(report.findings[0].matched, "tok_abc123");
        }
    }

    /// Every cache entry file under a scan root, sorted.
    /// Every cache entry written under `base`, sorted.
    ///
    /// `base` is the cache directory the test gave the cache, not the scan root:
    /// since 1.4.0 the cache is in the user's own cache directory and there is
    /// nothing to find under the scanned tree.
    fn cache_entry_paths(base: &Path) -> Vec<std::path::PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "json") {
                    out.push(path);
                }
            }
        }

        let mut out = Vec::new();
        walk(base, &mut out);
        out.sort();
        out
    }

    #[test]
    fn edited_content_invalidates_the_cached_entry() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");

        let rules = ruleset();
        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        assert_eq!(cached_scan(dir.path(), &rules, &cache).findings.len(), 1);

        write(
            dir.path(),
            "a.rs",
            b"// siloscan-ignore: test.needle\nneedle\n",
        );
        let report = cached_scan(dir.path(), &rules, &cache);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suppressed.len(), 1);
    }

    #[test]
    fn identical_content_at_two_paths_keeps_its_own_findings() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle\n");

        let rules = ruleset();
        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        cached_scan(dir.path(), &rules, &cache);
        let report = cached_scan(dir.path(), &rules, &cache);

        let paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["a.rs", "src/b.rs"]);
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn graph_facts_are_collected_cached_or_not() {
        let dir = tempdir();
        write(
            dir.path(),
            "src/a.rs",
            b"use std::io::Read;\n\nfn main() {}\n",
        );
        write(dir.path(), "notes.txt", b"needle\n");

        // A boundary rule in the set is what asks for the import facts; there
        // is no config here, so it reports nothing and the facts below are the
        // only thing it contributes. An ast rule alongside it asks for the same
        // tree and matches nothing. A rule set that needs no tree collects no
        // facts at all, which is what keeps a regex-only scan off tree-sitter.
        let mut rules = ruleset();
        rules.rules.extend(load_str(AST_RULES, "ast").unwrap());
        rules
            .sources
            .push(("ast".to_string(), AST_RULES.to_string()));
        rules
            .rules
            .extend(load_str(BOUNDARY_RULES, "boundary").unwrap());
        rules
            .sources
            .push(("boundary".to_string(), BOUNDARY_RULES.to_string()));

        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        assert_eq!(cold.graph, warm.graph);
        assert_eq!(cold.graph, scan(dir.path(), &rules, None).graph);
        let facts = cold.graph.files.get("src/a.rs").expect("facts");
        assert_eq!(facts.language, "rust");
        assert_eq!(
            facts
                .imports
                .iter()
                .map(|i| i.raw.as_str())
                .collect::<Vec<_>>(),
            vec!["std::io::Read"]
        );
        assert!(!cold.graph.files.contains_key("notes.txt"));
    }

    /// The import facts are the boundary engine's input and nothing else reads
    /// them, so a parsed file yields them only when a boundary rule is loaded.
    /// Extracting them costs about as much as the parse did.
    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn import_facts_are_extracted_only_for_a_boundary_rule() {
        let content = "use std::io::Read;\n\nfn main() { dbg!(1); }\n";

        let entry = |rules: &RuleSet| {
            let queries =
                crate::engines::ast::AstQueries::build(&rules.rules).expect("queries combine");
            let needs = ParseNeeds::of(rules);
            scan_text(
                rules,
                &queries,
                &ScanOptions::default(),
                "src/a.rs",
                content,
                Some("rust"),
                true,
                needs.boundary,
            )
            .expect("the scan should not fail")
        };

        let ast_only = entry(&ast_ruleset());
        // The tree was built and used: the ast rule matched.
        assert_eq!(ast_only.findings.len(), 1);
        assert_eq!(ast_only.findings[0].rule_id, "rust.dbg-macro");
        assert!(ast_only.facts.is_none());

        let with_boundary = entry(&boundary_rules());
        let facts = with_boundary.facts.expect("facts");
        assert_eq!(facts.language, "rust");
        assert_eq!(
            facts
                .imports
                .iter()
                .map(|import| import.raw.as_str())
                .collect::<Vec<_>>(),
            vec!["std::io::Read"]
        );
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn ast_rules_run_alongside_regex_rules() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"fn main() {\n    dbg!(1);\n}\n");

        let src = r#"
version: 1
rules:
  - id: rust.dbg-macro
    severity: warning
    message: "leftover dbg"
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "dbg"))'
"#;
        let rules = RuleSet {
            rules: load_str(src, "ast").unwrap(),
            sources: vec![("ast".to_string(), src.to_string())],
        };

        let report = scan(dir.path(), &rules, None);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "rust.dbg-macro");
        assert_eq!((report.findings[0].line, report.findings[0].column), (2, 5));
    }

    const BOUNDARY_RULES: &str = r#"
version: 1
rules:
  - id: arch.api-must-not-import-db
    severity: error
    message: "api must not import db"
    boundary:
      from: api
      deny: ["db"]
"#;

    const COVERAGE_RULES: &str = r#"
version: 1
rules:
  - id: cov.min
    severity: warning
    message: "line coverage below threshold"
    coverage:
      min: 80
"#;

    fn boundary_rules() -> RuleSet {
        RuleSet {
            rules: load_str(BOUNDARY_RULES, "boundary").unwrap(),
            sources: vec![("boundary".to_string(), BOUNDARY_RULES.to_string())],
        }
    }

    fn silo_config(src: &str) -> crate::config::Config {
        toml::from_str(src).expect("config should parse")
    }

    const SILOS: &str = r#"
[silos]
api = ["src/api/**"]
db = ["src/db/**"]
"#;

    /// Two javascript files across a denied boundary.
    fn boundary_tree(dir: &Path) {
        write(
            dir,
            "src/api/handler.js",
            b"import x from '../db/client';\n",
        );
        write(dir, "src/db/client.js", b"export const x = 1;\n");
    }

    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn boundary_findings_join_the_report_with_their_edge() {
        let dir = tempdir();
        boundary_tree(dir.path());

        let config = silo_config(SILOS);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report =
            scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {}).expect("valid silos");

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "arch.api-must-not-import-db");
        assert_eq!(finding.path, "src/api/handler.js");
        assert_eq!(
            report.boundary_edges,
            vec![(
                "api".to_string(),
                "db".to_string(),
                finding.fingerprint.clone()
            )]
        );
    }

    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn inline_markers_suppress_boundary_findings() {
        let dir = tempdir();
        write(
            dir.path(),
            "src/api/handler.js",
            b"// siloscan-ignore: arch.api-must-not-import-db\nimport x from '../db/client';\n",
        );
        write(dir.path(), "src/db/client.js", b"export const x = 1;\n");

        let config = silo_config(SILOS);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {}).unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.suppressed.len(), 1);
        // The edge is reported whichever partition its finding landed in.
        assert_eq!(report.boundary_edges.len(), 1);
    }

    #[test]
    fn boundary_rules_are_inert_without_a_config() {
        let dir = tempdir();
        boundary_tree(dir.path());

        let report = scan(dir.path(), &boundary_rules(), None);

        assert!(report.findings.is_empty());
        assert!(report.boundary_edges.is_empty());
    }

    #[test]
    fn a_boundary_rule_naming_an_unknown_silo_is_an_error() {
        let dir = tempdir();
        boundary_tree(dir.path());

        let config = silo_config("[silos]\napi = [\"src/api/**\"]\n");
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let err = scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {}).unwrap_err();

        assert!(err.contains("unknown silo: db"), "{err}");
    }

    #[test]
    fn a_scan_root_below_the_config_is_an_error() {
        let dir = tempdir();
        git_root(dir.path());
        write(dir.path(), "siloscan.toml", SILOS.as_bytes());
        boundary_tree(dir.path());

        // Loaded from disk, because the guard measures against the config's own
        // directory and an in-memory config has none.
        let config = root_config(dir.path());
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let err = scan_opts(
            &dir.path().join("src/api"),
            &boundary_rules(),
            &options,
            &mut |_| {},
        )
        .unwrap_err();

        assert!(err.contains("boundary rules are relative to"), "{err}");
        assert!(err.contains("siloscan.toml"), "{err}");
    }

    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn the_config_directory_is_a_valid_scan_root() {
        let dir = tempdir();
        git_root(dir.path());
        write(dir.path(), "siloscan.toml", SILOS.as_bytes());
        boundary_tree(dir.path());

        let config = silo_config(SILOS);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {}).unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "src/api/handler.js");
    }

    #[cfg(feature = "tree-sitter-go")]
    #[test]
    fn go_imports_resolve_through_the_module_declared_by_go_mod() {
        let go_silos = "[silos]\napi = [\"api/**\"]\ndb = [\"db/**\"]\n";
        let local = tempdir();
        write(local.path(), "go.mod", b"module example.com/app\n");
        write(
            local.path(),
            "api/server.go",
            b"package api\n\nimport \"example.com/app/db\"\n",
        );
        write(local.path(), "db/client.go", b"package db\n");

        // The same tree, differing only in the import path: an import of
        // another module must not resolve onto the local `db` package.
        let external = tempdir();
        write(external.path(), "go.mod", b"module example.com/app\n");
        write(
            external.path(),
            "api/server.go",
            b"package api\n\nimport \"github.com/vendor/otherproject/db\"\n",
        );
        write(external.path(), "db/client.go", b"package db\n");

        let config = silo_config(go_silos);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };

        let hit = scan_opts(local.path(), &boundary_rules(), &options, &mut |_| {}).unwrap();
        assert_eq!(hit.findings.len(), 1);
        assert_eq!(hit.findings[0].path, "api/server.go");

        let miss = scan_opts(external.path(), &boundary_rules(), &options, &mut |_| {}).unwrap();
        assert!(miss.findings.is_empty());
        assert!(miss.boundary_edges.is_empty());
    }

    #[test]
    fn coverage_findings_join_the_report() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let x = 1;\n");
        write(dir.path(), "src/b.rs", b"let y = 2;\n");

        let rules = RuleSet {
            rules: load_str(COVERAGE_RULES, "coverage").unwrap(),
            sources: vec![("coverage".to_string(), COVERAGE_RULES.to_string())],
        };
        let coverage = crate::coverage::CoverageReport {
            files: std::collections::BTreeMap::from([(
                "src/a.rs".to_string(),
                crate::coverage::FileCoverage {
                    lines_total: 10,
                    lines_covered: 1,
                },
            )]),
            source: String::new(),
        };
        let options = ScanOptions {
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &rules, &options, &mut |_| {}).unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "cov.min");
        assert_eq!(report.findings[0].path, "src/a.rs");
        // No coverage data for src/b.rs is not a violation.
        assert!(report.boundary_edges.is_empty());
    }

    #[test]
    fn whole_tree_findings_sort_with_the_rest() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle\n");

        let mut rules = ruleset();
        rules
            .rules
            .extend(load_str(COVERAGE_RULES, "coverage").unwrap());
        rules
            .sources
            .push(("coverage".to_string(), COVERAGE_RULES.to_string()));

        let coverage = crate::coverage::CoverageReport {
            files: std::collections::BTreeMap::from([(
                "src/b.rs".to_string(),
                crate::coverage::FileCoverage {
                    lines_total: 4,
                    lines_covered: 0,
                },
            )]),
            source: String::new(),
        };
        let options = ScanOptions {
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &rules, &options, &mut |_| {}).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .map(|f| (f.path.as_str(), f.rule_id.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("src/a.rs", "test.needle"),
                ("src/b.rs", "cov.min"),
                ("src/b.rs", "test.needle"),
            ]
        );
    }

    fn coverage_ruleset() -> RuleSet {
        RuleSet {
            rules: load_str(COVERAGE_RULES, "coverage").unwrap(),
            sources: vec![("coverage".to_string(), COVERAGE_RULES.to_string())],
        }
    }

    /// A coverage report of another checkout: it parsed, it names a file, and
    /// the file is one no scan of the fixture tree will ever walk.
    fn foreign_coverage() -> crate::coverage::CoverageReport {
        crate::coverage::CoverageReport {
            files: std::collections::BTreeMap::from([(
                "elsewhere/other.rs".to_string(),
                crate::coverage::FileCoverage {
                    lines_total: 10,
                    lines_covered: 1,
                },
            )]),
            source: "coverage/lcov.info".to_string(),
        }
    }

    /// A repository whose config sits at the root and whose sources sit one
    /// directory down, which is the shape a per-module CI job scans.
    fn module_tree(root: &Path) {
        git_root(root);
        write(root, "siloscan.toml", b"");
        write(root, "modules/api/src/a.rs", b"let x = 1;\n");
    }

    /// The subdirectory CI job that a coverage report of the whole repository
    /// legitimately misses. It was green yesterday and has to stay green: the
    /// gate says out loud that it did not evaluate, and the exit code is left
    /// to whatever else the scan found.
    #[test]
    fn a_subdirectory_scan_warns_when_the_coverage_report_matches_nothing() {
        let dir = tempdir();
        module_tree(dir.path());

        let config = root_config(dir.path());
        let coverage = foreign_coverage();
        let options = ScanOptions {
            config: Some(&config),
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };
        let report = scan_opts(
            &dir.path().join("modules/api"),
            &coverage_ruleset(),
            &options,
            &mut |_| {},
        )
        .expect("a module scan is not refused for a report of the whole repository");

        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        let warning = &report.warnings[0];
        assert!(warning.contains("cov.min"), "{warning}");
        assert!(warning.contains("coverage/lcov.info"), "{warning}");
        assert!(warning.contains("did not evaluate"), "{warning}");
        // The rules did not evaluate, so they reported neither a violation nor
        // a pass.
        assert!(
            report.findings.iter().all(|f| f.rule_id != "cov.min"),
            "{:?}",
            report.findings
        );
    }

    /// The other side of the same rule. A whole-project scan has no module to
    /// blame, so a report landing on nothing is still a gate that cannot
    /// evaluate, and that is exit 2.
    #[test]
    fn a_full_project_scan_with_a_non_matching_coverage_report_is_an_error() {
        let dir = tempdir();
        module_tree(dir.path());

        let config = root_config(dir.path());
        let coverage = foreign_coverage();
        let options = ScanOptions {
            config: Some(&config),
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };
        let err = scan_opts(dir.path(), &coverage_ruleset(), &options, &mut |_| {}).unwrap_err();
        assert!(err.contains("matches none of the scanned files"), "{err}");

        // And with no config at all there is no config root to be below, so the
        // scan root cannot be a subdirectory of one and the refusal stands.
        let options = ScanOptions {
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };
        assert!(
            scan_opts(
                &dir.path().join("modules/api"),
                &coverage_ruleset(),
                &options,
                &mut |_| {},
            )
            .is_err()
        );
    }

    /// The exception is for a report of a wider tree, not for a report of no
    /// tree. An empty report - an lcov with no records, a run truncated before
    /// it wrote one, a `--coverage-report` pointed at a file that parsed and
    /// measured nothing - is a broken input, it looks the same from a
    /// subdirectory as from the root, and excusing it would reopen the
    /// missing-report hole for every module job. Exit 2, wherever the scan root
    /// is.
    #[test]
    fn a_subdirectory_scan_with_an_empty_coverage_report_is_still_an_error() {
        let dir = tempdir();
        module_tree(dir.path());

        let config = root_config(dir.path());
        let coverage = crate::coverage::CoverageReport {
            files: std::collections::BTreeMap::new(),
            source: "coverage/lcov.info".to_string(),
        };
        let options = ScanOptions {
            config: Some(&config),
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };

        // The scan root is a strict subdirectory of the config root, which is
        // the whole of the other condition - so this is the empty report and
        // nothing else deciding the outcome.
        assert!(scan_root_below_config(
            &dir.path().join("modules/api"),
            Some(&config)
        ));
        let err = scan_opts(
            &dir.path().join("modules/api"),
            &coverage_ruleset(),
            &options,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(err.contains("matches none of the scanned files"), "{err}");
    }

    /// The warning is for a report that lands on nothing, not for a report that
    /// lands on something: a subdirectory scan whose report does match still
    /// evaluates its coverage rules and still fails them.
    #[test]
    fn a_subdirectory_scan_whose_report_matches_still_evaluates() {
        let dir = tempdir();
        module_tree(dir.path());

        let config = root_config(dir.path());
        let coverage = crate::coverage::CoverageReport {
            files: std::collections::BTreeMap::from([(
                "a.rs".to_string(),
                crate::coverage::FileCoverage {
                    lines_total: 10,
                    lines_covered: 1,
                },
            )]),
            source: String::new(),
        };
        let options = ScanOptions {
            config: Some(&config),
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };
        let report = scan_opts(
            &dir.path().join("modules/api/src"),
            &coverage_ruleset(),
            &options,
            &mut |_| {},
        )
        .unwrap();

        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "cov.min");
    }

    /// A scan that narrowed nothing says nothing, and the field is part of the
    /// report's determinism: a warning list that depended on the worker count
    /// or on a warm cache would be a scan describing itself differently twice.
    #[test]
    fn an_ordinary_scan_reports_no_warnings() {
        let dir = tempdir();
        duplicated_tree(dir.path());

        assert!(scan(dir.path(), &ruleset(), None).warnings.is_empty());
    }

    #[test]
    fn the_scan_root_is_below_the_config_only_when_it_is_strictly_below() {
        let dir = tempdir();
        module_tree(dir.path());
        let config = root_config(dir.path());

        assert!(scan_root_below_config(
            &dir.path().join("modules/api"),
            Some(&config)
        ));
        // A single-file root is measured by the directory holding it.
        assert!(scan_root_below_config(
            &dir.path().join("modules/api/src/a.rs"),
            Some(&config)
        ));
        // The config root itself is the whole project, not a part of it.
        assert!(!scan_root_below_config(dir.path(), Some(&config)));
        // No config, and a config that never came from disk, are below nothing.
        assert!(!scan_root_below_config(&dir.path().join("modules"), None));
        assert!(!scan_root_below_config(
            &dir.path().join("modules"),
            Some(&crate::config::Config::default())
        ));
    }

    const DUPLICATION_RULES: &str = r#"
version: 1
rules:
  - id: quality.duplication
    severity: warning
    message: "duplication over budget"
    duplication:
      max_percent: 10
      scope: scan
"#;

    /// Twelve identical lines: two copies of this clear the default ten-line
    /// window with room to spare.
    fn duplicated_block() -> String {
        (0..12).map(|i| format!("let value{i} = {i};\n")).collect()
    }

    /// One regex rule and one scan-scope duplication gate.
    fn duplication_ruleset() -> RuleSet {
        let mut rules = ruleset();
        rules
            .rules
            .extend(load_str(DUPLICATION_RULES, "duplication").unwrap());
        rules
            .sources
            .push(("duplication".to_string(), DUPLICATION_RULES.to_string()));
        rules
    }

    /// A config whose only setting is the key that asks for duplicate-block
    /// findings.
    fn report_blocks_config() -> crate::config::Config {
        crate::config::Config {
            duplication: crate::config::DuplicationConfig {
                report_blocks: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// A scan that reports duplicate blocks, for the tests that are about what
    /// those findings look like rather than about whether they are emitted.
    fn scan_blocks(root: &Path, rules: &RuleSet) -> ScanReport {
        let config = report_blocks_config();
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        scan_opts(root, rules, &options, &mut |_| {}).expect("rules compile")
    }

    /// Every duplicate-block finding in a report, in report order.
    fn blocks_of(report: &ScanReport) -> Vec<&Finding> {
        report
            .findings
            .iter()
            .filter(|f| f.rule_id == crate::metrics::DUPLICATE_BLOCK_RULE_ID)
            .collect()
    }

    /// Two files sharing a twelve-line block, plus a file that shares nothing.
    fn duplicated_tree(root: &Path) {
        let block = duplicated_block();
        write(root, "src/a.rs", format!("// header\n{block}").as_bytes());
        write(root, "src/b.rs", block.as_bytes());
        write(root, "notes.txt", b"plain text\n\nsecond line\n");
    }

    #[test]
    fn metrics_cover_every_text_file_and_count_duplication() {
        let dir = tempdir();
        duplicated_tree(dir.path());
        write(dir.path(), "blob.bin", b"\0\0binary\0\0");

        let report = scan(dir.path(), &ruleset(), None);

        let files = &report.metrics.files;
        assert_eq!(files.len(), 3, "binary files carry no metrics");
        assert_eq!(files["src/a.rs"].lines, 13);
        assert_eq!(files["src/a.rs"].code_lines, Some(12));
        assert_eq!(files["src/a.rs"].duplicated_lines, 12);
        assert_eq!(files["src/b.rs"].lines, 12);
        assert_eq!(files["src/b.rs"].duplicated_lines, 12);
        // A non-tier-1 language reports no code lines and no duplication.
        assert_eq!(files["notes.txt"].lines, 2);
        assert_eq!(files["notes.txt"].code_lines, None);
        assert_eq!(files["notes.txt"].duplicated_lines, 0);

        let totals = &report.metrics.totals;
        assert_eq!(totals.lines, 27);
        assert_eq!(totals.code_lines, 24);
        assert_eq!(totals.duplicated_lines, 24);
        assert!((totals.duplication_density - 24.0 / 27.0 * 100.0).abs() < 1e-9);
    }

    /// The default: the numbers stay, the per-block findings stop.
    ///
    /// This is the whole of the adoption fix. On a real tree those findings
    /// outnumber everything else by orders of magnitude, so a default that
    /// emits them is a report nobody reads and a SARIF file nobody can ingest -
    /// but the duplication a reader acts on is a number, and the numbers are
    /// measured and reported here exactly as before.
    #[test]
    fn duplicate_blocks_are_not_reported_by_default() {
        let dir = tempdir();
        duplicated_tree(dir.path());

        let report = scan(dir.path(), &ruleset(), None);

        assert!(blocks_of(&report).is_empty(), "{:?}", report.findings);
        assert!(
            report
                .suppressed
                .iter()
                .chain(&report.baselined)
                .all(|f| f.rule_id != crate::metrics::DUPLICATE_BLOCK_RULE_ID),
            "not emitted at all, rather than emitted and hidden"
        );

        // The measurement is untouched: same counts, same totals, same density
        // as the run that reports every block.
        assert_eq!(report.metrics.files["src/a.rs"].duplicated_lines, 12);
        assert_eq!(report.metrics.files["src/b.rs"].duplicated_lines, 12);
        assert_eq!(report.metrics.totals.duplicated_lines, 24);
        let asked = scan_blocks(dir.path(), &ruleset());
        assert_eq!(report.metrics.totals, asked.metrics.totals);
        assert_eq!(report.metrics.files, asked.metrics.files);
    }

    /// Loading a duplication rule is asking where the duplication is, so the
    /// locations come back without a config key. The default pack carries no
    /// duplication rule, so this cannot undo the default above by accident.
    #[test]
    fn a_duplication_rule_brings_the_block_findings_back() {
        let dir = tempdir();
        duplicated_tree(dir.path());

        assert!(
            !report_duplicate_blocks(&ruleset(), None),
            "a regex-only rule set asks for nothing"
        );
        assert!(report_duplicate_blocks(&duplication_ruleset(), None));
        assert!(report_duplicate_blocks(&silo_duplication_rules(), None));
        assert!(report_duplicate_blocks(
            &ruleset(),
            Some(&report_blocks_config())
        ));

        let report = scan(dir.path(), &duplication_ruleset(), None);
        assert_eq!(blocks_of(&report).len(), 2);
    }

    /// Turning them back on reproduces 1.3.0 byte for byte, fingerprints
    /// included, so a baseline written against that release keeps working.
    #[test]
    fn duplicate_blocks_are_reported_as_info_findings() {
        let dir = tempdir();
        duplicated_tree(dir.path());

        let report = scan_blocks(dir.path(), &ruleset());

        let blocks = blocks_of(&report);
        assert_eq!(blocks.len(), 2, "one finding per copy");

        // Copies sort with every other finding: a.rs before b.rs.
        assert_eq!((blocks[0].path.as_str(), blocks[0].line), ("src/a.rs", 2));
        assert_eq!((blocks[1].path.as_str(), blocks[1].line), ("src/b.rs", 1));
        assert!(blocks.iter().all(|f| f.column == 1));
        assert!(blocks.iter().all(|f| f.severity == Severity::Info));

        // Both copies of one block share the synthetic matched text.
        assert_eq!(blocks[0].matched, blocks[1].matched);
        let hash = blocks[0]
            .matched
            .strip_prefix("12 duplicated lines (block ")
            .and_then(|rest| rest.strip_suffix(')'))
            .expect("matched names the block");
        assert_eq!(hash.len(), 12);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // The message names the other copies, and stays out of the fingerprint.
        assert_eq!(blocks[0].message, "duplicated block, also at src/b.rs:1");
        assert_eq!(blocks[1].message, "duplicated block, also at src/a.rs:2");
        assert_eq!(
            blocks[0].fingerprint,
            crate::findings::fingerprint(
                crate::metrics::DUPLICATE_BLOCK_RULE_ID,
                "src/a.rs",
                &blocks[0].matched,
                0
            )
        );
        assert_ne!(blocks[0].fingerprint, blocks[1].fingerprint);
    }

    #[test]
    fn a_widely_copied_block_names_at_most_ten_other_copies() {
        let dir = tempdir();
        let block = duplicated_block();
        // Fifteen copies: ten named, four counted, one being the copy itself.
        for index in 0..15 {
            write(dir.path(), &format!("src/f{index:02}.rs"), block.as_bytes());
        }

        let report = scan_blocks(dir.path(), &ruleset());

        let blocks = blocks_of(&report);
        assert_eq!(blocks.len(), 15, "one finding per copy");

        let message = &blocks[0].message;
        assert!(message.ends_with(", and 4 more"), "{message}");
        let listed = message
            .strip_prefix("duplicated block, also at ")
            .and_then(|rest| rest.strip_suffix(", and 4 more"))
            .expect("the message lists the named copies");
        assert_eq!(listed.split(", ").count(), MAX_LISTED_COPIES);
        // The copy itself is never one of the others it names.
        assert!(!listed.contains("src/f00.rs:1"), "{listed}");
        assert!(listed.starts_with("src/f01.rs:1, "), "{listed}");
    }

    #[test]
    fn two_copies_in_one_file_differ_by_occurrence() {
        let dir = tempdir();
        // Twenty identical lines hold two disjoint ten-line copies.
        let content: String = (0..20).map(|_| "call(same);\n".to_string()).collect();
        write(dir.path(), "src/a.rs", content.as_bytes());

        let report = scan_blocks(dir.path(), &ruleset());

        let blocks = blocks_of(&report);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].matched, blocks[1].matched);
        assert_eq!(blocks[0].path, blocks[1].path);
        assert_ne!(blocks[0].fingerprint, blocks[1].fingerprint);
        assert_eq!(
            blocks[1].fingerprint,
            crate::findings::fingerprint(
                crate::metrics::DUPLICATE_BLOCK_RULE_ID,
                "src/a.rs",
                &blocks[1].matched,
                1
            )
        );
    }

    #[test]
    fn inline_markers_suppress_duplicate_block_findings() {
        let dir = tempdir();
        let block = duplicated_block();
        write(
            dir.path(),
            "src/a.rs",
            format!("// siloscan-ignore: metrics.duplicate-block\n{block}").as_bytes(),
        );
        write(dir.path(), "src/b.rs", block.as_bytes());

        let report = scan_blocks(dir.path(), &ruleset());

        let reported: Vec<&str> = blocks_of(&report).iter().map(|f| f.path.as_str()).collect();
        assert_eq!(reported, vec!["src/b.rs"]);
        assert_eq!(report.suppressed.len(), 1);
        assert_eq!(report.suppressed[0].path, "src/a.rs");
        // The lines stay counted: suppression hides a finding, not a metric.
        assert_eq!(report.metrics.files["src/a.rs"].duplicated_lines, 12);
    }

    #[test]
    fn a_duplication_gate_reports_against_the_whole_scan() {
        let dir = tempdir();
        duplicated_tree(dir.path());

        let report = scan(dir.path(), &duplication_ruleset(), None);

        let gate: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "quality.duplication")
            .collect();
        assert_eq!(gate.len(), 1);
        assert_eq!(gate[0].path, ".");
        assert_eq!((gate[0].line, gate[0].column), (1, 1));
        assert_eq!(gate[0].severity, Severity::Warning);
        assert_eq!(gate[0].matched, "density 88.9% (max 10.0%)");
    }

    #[test]
    fn a_duplication_gate_under_its_budget_is_quiet() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let x = 1;\n");

        let report = scan(dir.path(), &duplication_ruleset(), None);

        assert!(
            report
                .findings
                .iter()
                .all(|f| f.rule_id != "quality.duplication")
        );
    }

    #[test]
    fn config_min_lines_changes_what_counts_as_duplication() {
        let dir = tempdir();
        let block: String = (0..4).map(|i| format!("let short{i} = {i};\n")).collect();
        write(dir.path(), "src/a.rs", block.as_bytes());
        write(dir.path(), "src/b.rs", block.as_bytes());

        // Four lines is under the default window, so nothing is duplicated.
        let default = scan(dir.path(), &ruleset(), None);
        assert_eq!(default.metrics.totals.duplicated_lines, 0);

        let config = crate::config::Config {
            duplication: crate::config::DuplicationConfig {
                min_lines: 4,
                report_blocks: true,
            },
            ..Default::default()
        };
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &ruleset(), &options, &mut |_| {}).unwrap();

        assert_eq!(report.metrics.totals.duplicated_lines, 8);
        assert_eq!(blocks_of(&report).len(), 2);
    }

    const SILO_DUPLICATION_RULES: &str = r#"
version: 1
rules:
  - id: quality.silo-duplication
    severity: error
    message: "silo duplication over budget"
    duplication:
      max_percent: 10
      scope: silo
"#;

    fn silo_duplication_rules() -> RuleSet {
        RuleSet {
            rules: load_str(SILO_DUPLICATION_RULES, "duplication").unwrap(),
            sources: vec![(
                "duplication".to_string(),
                SILO_DUPLICATION_RULES.to_string(),
            )],
        }
    }

    #[test]
    fn a_silo_scoped_duplication_rule_without_a_config_is_an_error() {
        let dir = tempdir();
        duplicated_tree(dir.path());

        let err = scan_opts(
            dir.path(),
            &silo_duplication_rules(),
            &ScanOptions::default(),
            &mut |_| {},
        )
        .unwrap_err();

        assert!(err.contains("quality.silo-duplication"), "{err}");
        assert!(err.contains("duplication scope silo"), "{err}");
    }

    #[test]
    fn a_silo_scoped_duplication_rule_without_silos_is_an_error() {
        let dir = tempdir();
        duplicated_tree(dir.path());

        // A config that loads but defines no silos leaves the gate unable to
        // fire, which is the same hole as no config at all.
        let config = crate::config::Config::default();
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let err =
            scan_opts(dir.path(), &silo_duplication_rules(), &options, &mut |_| {}).unwrap_err();

        assert!(err.contains("quality.silo-duplication"), "{err}");
        assert!(err.contains("duplication scope silo"), "{err}");
    }

    #[test]
    fn a_silo_scoped_duplication_rule_below_the_config_is_an_error() {
        let dir = tempdir();
        git_root(dir.path());
        write(dir.path(), "siloscan.toml", SILOS.as_bytes());
        let block = duplicated_block();
        write(dir.path(), "src/api/a.rs", block.as_bytes());
        write(dir.path(), "src/api/b.rs", block.as_bytes());

        // Loaded from disk, because the guard measures against the config's own
        // directory and an in-memory config has none.
        let config = root_config(dir.path());
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let err = scan_opts(
            &dir.path().join("src/api"),
            &silo_duplication_rules(),
            &options,
            &mut |_| {},
        )
        .unwrap_err();

        assert!(
            err.contains("silo-scoped duplication rules are relative to"),
            "{err}"
        );
        assert!(err.contains("siloscan.toml"), "{err}");
    }

    #[test]
    fn a_silo_scoped_duplication_rule_reports_each_offending_silo() {
        let dir = tempdir();
        let block = duplicated_block();
        write(dir.path(), "src/api/a.rs", block.as_bytes());
        write(dir.path(), "src/api/b.rs", block.as_bytes());
        write(dir.path(), "src/db/c.rs", b"let unique = 1;\n");

        let config = silo_config("[silos]\napi = [\"src/api/**\"]\ndb = [\"src/db/**\"]\n");
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report =
            scan_opts(dir.path(), &silo_duplication_rules(), &options, &mut |_| {}).unwrap();

        let gate: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "quality.silo-duplication")
            .collect();
        assert_eq!(gate.len(), 1, "only api is over budget");
        assert_eq!(gate[0].path, ".");
        assert_eq!(gate[0].matched, "silo api: density 100.0% (max 10.0%)");
        assert_eq!(
            gate[0].fingerprint,
            crate::findings::fingerprint("quality.silo-duplication", ".", "silo api", 0)
        );
    }

    #[test]
    fn metrics_and_duplication_survive_workers_and_cache_state() {
        let dir = tempdir();
        synthetic_tree(dir.path(), 60);
        duplicated_tree(dir.path());

        let rules = duplication_ruleset();
        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        let report = |workers, cache: Option<&crate::cache::Cache>| {
            let options = ScanOptions {
                cache,
                ..ScanOptions::default()
            };
            let report = run_with_workers(
                dir.path(),
                &rules,
                &options,
                None,
                &Anchoring::default(),
                &mut |_| {},
                workers,
            );
            serde_json::to_string(&report).unwrap()
        };

        // Cold cache first, so the warm run below reads what it wrote.
        let cold = report(1, Some(&cache));
        let warm = report(8, Some(&cache));
        let uncached = report(4, None);

        assert_eq!(cold, warm, "a warm cache must not move the metrics");
        assert_eq!(cold, uncached, "the cache must not move the metrics at all");
        // Non-empty, so the comparisons above are not vacuous.
        assert!(cold.contains("metrics.duplicate-block"));
        assert!(cold.contains("quality.duplication"));
        assert!(cold.contains("\"duplicated_lines\":24"));
    }

    // Anchoring: one path convention per scan, chosen by the config, applied to
    // every path a scan produces.

    /// A rule pack that lives in the directory an included module config points
    /// at, so loading it at all proves the include contributed it.
    const MODULE_RULES: &str = r#"
version: 1
rules:
  - id: module.value
    severity: warning
    message: "module value"
    regex:
      pattern: "value3"
"#;

    /// A repository whose root config anchors on itself and includes a module
    /// config, and whose only duplicated block lives inside that module.
    ///
    /// The module config declares its silo and its rule directory relative to
    /// itself; the merged config speaks config-root-relative paths. `crates/core`
    /// shares nothing with the module, so the module's duplicate block is the
    /// same block whether the whole repository or only the module is scanned.
    fn multimodule_repo(root: &Path) {
        git_root(root);
        write(
            root,
            "siloscan.toml",
            b"anchor = \"config\"\ninclude = [\"modules/api/siloscan.toml\"]\n\n[silos]\ncore = [\"crates/core/**\"]\n",
        );
        write(
            root,
            "modules/api/siloscan.toml",
            b"rules = [\"rules\"]\n\n[silos]\napi = [\"src/**\"]\n",
        );
        write(
            root,
            "modules/api/rules/module.yml",
            MODULE_RULES.as_bytes(),
        );

        let block = duplicated_block();
        write(
            root,
            "modules/api/src/a.rs",
            format!("// module a\n{block}").as_bytes(),
        );
        write(root, "modules/api/src/b.rs", block.as_bytes());
        // Outside the module: one more `module.value` match and nothing else, so
        // the repository scan reports strictly more than the module scan.
        write(root, "crates/core/lib.rs", b"let value3 = 3;\n");
    }

    fn root_config(root: &Path) -> crate::config::Config {
        crate::config::load(&root.join("siloscan.toml")).expect("root config should load")
    }

    /// The rules the included module contributes, loaded the way the CLI loads
    /// them: from the merged config's rule directories.
    fn module_rules(config: &crate::config::Config) -> RuleSet {
        crate::rules::load_dirs(&config.rule_dirs()).expect("included rules should load")
    }

    fn options_for(config: &crate::config::Config) -> ScanOptions<'_> {
        ScanOptions {
            config: Some(config),
            ..ScanOptions::default()
        }
    }

    /// Path and fingerprint of every finding: what has to match across two
    /// scans for a baseline written by one to serve the other.
    fn identities(findings: &[Finding]) -> Vec<(String, String)> {
        findings
            .iter()
            .map(|f| (f.path.clone(), f.fingerprint.clone()))
            .collect()
    }

    #[test]
    fn an_included_module_contributes_its_silo_and_its_rules_to_the_scan() {
        let dir = tempdir();
        multimodule_repo(dir.path());

        let config = root_config(dir.path());
        // Both rebased onto the config root by the loader, so the scanner never
        // learns that an include existed.
        assert_eq!(config.silos["api"], vec!["modules/api/src/**"]);
        assert_eq!(
            config.rule_dirs(),
            vec![dir.path().join("modules/api/rules")]
        );

        let rules = module_rules(&config);
        assert!(rules.rules.iter().any(|rule| rule.id == "module.value"));

        let report =
            scan_opts(dir.path(), &rules, &options_for(&config), &mut |_| {}).expect("valid setup");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "module.value" && f.path == "modules/api/src/a.rs")
        );

        // The merged silo globs match the same paths the scan reports.
        let sets = config.silo_sets().expect("globs compile");
        assert_eq!(config.silo_of(&sets, "modules/api/src/a.rs"), Some("api"));
        assert_eq!(config.silo_of(&sets, "crates/core/lib.rs"), Some("core"));
    }

    #[test]
    fn a_module_scan_and_a_repository_scan_agree_on_every_shared_finding() {
        let dir = tempdir();
        multimodule_repo(dir.path());

        let config = root_config(dir.path());
        let rules = module_rules(&config);
        let options = options_for(&config);

        let whole = scan_opts(dir.path(), &rules, &options, &mut |_| {}).expect("repository scan");
        let module = scan_opts(
            &dir.path().join("modules/api"),
            &rules,
            &options,
            &mut |_| {},
        )
        .expect("module scan");

        assert!(
            !module.findings.is_empty(),
            "the fixture must find something"
        );
        assert!(
            module
                .findings
                .iter()
                .all(|f| f.path.starts_with("modules/api/")),
            "a module scan reports its files by their path from the config root: {:?}",
            identities(&module.findings)
        );

        // The point of the feature: every finding the module scan reports is one
        // the repository scan reported, with the same path and the same
        // fingerprint, so one baseline serves both.
        let whole_ids: std::collections::BTreeSet<(String, String)> =
            identities(&whole.findings).into_iter().collect();
        for identity in identities(&module.findings) {
            assert!(
                whole_ids.contains(&identity),
                "{identity:?} is not in the repository scan: {whole_ids:?}"
            );
        }
        assert!(
            whole.findings.len() > module.findings.len(),
            "the repository scan must also see what lies outside the module"
        );

        // Metrics keys ride the same convention as the findings.
        assert!(module.metrics.files.contains_key("modules/api/src/a.rs"));
        assert!(whole.metrics.files.contains_key("modules/api/src/a.rs"));
    }

    #[test]
    fn a_baseline_from_a_module_scan_covers_the_repository_scan() {
        let dir = tempdir();
        multimodule_repo(dir.path());

        let config = root_config(dir.path());
        let rules = module_rules(&config);
        let module_root = dir.path().join("modules/api");
        let module = scan_opts(&module_root, &rules, &options_for(&config), &mut |_| {})
            .expect("module scan");

        // Exactly what `siloscan baseline` records: fingerprint and path taken
        // from the finding, with nothing translated.
        let baseline = crate::baseline::Baseline {
            version: 1,
            entries: module
                .findings
                .iter()
                .map(|f| crate::baseline::BaselineEntry {
                    fingerprint: f.fingerprint.clone(),
                    rule_id: f.rule_id.clone(),
                    path: f.path.clone(),
                })
                .collect(),
        };

        let options = ScanOptions {
            baseline: Some(&baseline),
            config: Some(&config),
            ..ScanOptions::default()
        };
        let whole = scan_opts(dir.path(), &rules, &options, &mut |_| {}).expect("repository scan");

        assert_eq!(identities(&whole.baselined), identities(&module.findings));
        assert!(
            whole
                .findings
                .iter()
                .all(|f| f.path == "crates/core/lib.rs"),
            "only what lies outside the module is new: {:?}",
            identities(&whole.findings)
        );
    }

    #[test]
    fn a_whole_scan_gate_reports_where_the_scan_root_is() {
        let dir = tempdir();
        multimodule_repo(dir.path());

        let config = root_config(dir.path());
        let rules = duplication_ruleset();
        let options = options_for(&config);
        let gate = |report: &ScanReport| {
            report
                .findings
                .iter()
                .find(|f| f.rule_id == "quality.duplication")
                .cloned()
                .expect("the gate must fire")
        };

        let whole = gate(&scan_opts(dir.path(), &rules, &options, &mut |_| {}).unwrap());
        let module = gate(
            &scan_opts(
                &dir.path().join("modules/api"),
                &rules,
                &options,
                &mut |_| {},
            )
            .unwrap(),
        );

        // The repository scan root is the config root, so its path from the
        // config root is ".", exactly as it would be without any anchor.
        assert_eq!(whole.path, ".");
        assert_eq!(
            whole.fingerprint,
            crate::findings::fingerprint("quality.duplication", ".", "", 0)
        );

        // A subdirectory scan says where it measured, and fingerprints that way.
        assert_eq!(module.path, "modules/api");
        assert_eq!(
            module.fingerprint,
            crate::findings::fingerprint("quality.duplication", "modules/api", "", 0)
        );
        assert_ne!(whole.fingerprint, module.fingerprint);
    }

    #[test]
    fn a_single_file_scan_anchors_on_the_directory_holding_it() {
        let dir = tempdir();
        multimodule_repo(dir.path());

        let config = root_config(dir.path());
        let file = dir.path().join("modules/api/src/a.rs");
        let report = scan_opts(
            &file,
            &module_rules(&config),
            &options_for(&config),
            &mut |_| {},
        )
        .expect("file scan");

        // A file scan root reports its own name, so the prefix is the directory
        // holding it; getting that wrong would repeat the file name.
        assert!(!report.findings.is_empty());
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.path == "modules/api/src/a.rs"),
            "{:?}",
            identities(&report.findings)
        );
    }

    #[test]
    fn an_anchored_report_is_byte_identical_across_workers_and_cache_state() {
        let dir = tempdir();
        multimodule_repo(dir.path());
        let root = dir.path().join("modules/api");

        let config = root_config(dir.path());
        let rules = module_rules(&config);
        let anchoring = Anchoring::resolve(&root, Some(&config)).expect("anchoring resolves");
        assert_eq!(anchoring.prefix(), "modules/api");

        let cache_home = cache_base();
        let cache = cache_anchored(cache_home.path(), &root, &rules, &anchoring);
        let json = |workers, cache: Option<&crate::cache::Cache>| {
            let options = ScanOptions {
                cache,
                config: Some(&config),
                ..ScanOptions::default()
            };
            let report = run_with_workers(
                &root,
                &rules,
                &options,
                None,
                &anchoring,
                &mut |_| {},
                workers,
            );
            crate::output::to_json(&report, &rules, anchoring.anchor(), None)
        };

        // Cold cache first, so the warm run below reads what it wrote.
        let cold = json(1, Some(&cache));
        let warm = json(8, Some(&cache));
        let uncached = json(4, None);

        assert_eq!(cold, warm, "a warm cache must not move an anchored report");
        assert_eq!(cold, uncached, "the cache must not move it at all");
        // Non-empty and anchored, so the comparisons above are not vacuous.
        assert!(cold.contains("\"anchor\": \"config\""));
        assert!(cold.contains("\"modules/api/src/a.rs\""));
    }

    #[test]
    fn a_cache_entry_from_one_convention_never_serves_the_other() {
        let dir = tempdir();
        multimodule_repo(dir.path());
        let root = dir.path().join("modules/api");

        let config = root_config(dir.path());
        let rules = module_rules(&config);
        let run = |cache: Option<&crate::cache::Cache>, anchoring: &Anchoring| {
            let options = ScanOptions {
                cache,
                ..ScanOptions::default()
            };
            run_with_workers(&root, &rules, &options, None, anchoring, &mut |_| {}, 1)
        };

        // Fill the cache under config anchoring, then scan the same tree under
        // scan-root anchoring with a cache bound to that convention.
        let anchored = Anchoring::resolve(&root, Some(&config)).unwrap();
        // One base for both caches. The point of this test is that the scope
        // discriminator keeps the two conventions' entries apart inside a single
        // cache directory; giving each its own directory would prove nothing.
        let cache_home = cache_base();
        let warm = cache_anchored(cache_home.path(), &root, &rules, &anchored);
        let filled = run(Some(&warm), &anchored);
        assert!(!filled.findings.is_empty());

        let plain_cache = cache_for(cache_home.path(), &root, &rules);
        let plain = run(Some(&plain_cache), &Anchoring::default());
        let no_cache = run(None, &Anchoring::default());

        assert_eq!(
            identities(&plain.findings),
            identities(&no_cache.findings),
            "the anchored entries must not have been served here"
        );
        assert!(
            plain
                .findings
                .iter()
                .all(|f| !f.path.starts_with("modules/")),
            "scan-root paths carry no prefix: {:?}",
            identities(&plain.findings)
        );
    }

    #[test]
    fn anchoring_needs_a_config_that_is_on_disk() {
        let config = crate::config::Config {
            anchor: Anchor::Config,
            ..crate::config::Config::default()
        };

        let err = Anchoring::resolve(Path::new("."), Some(&config)).unwrap_err();
        assert!(err.contains(crate::config::CONFIG_NAME), "{err}");
    }

    #[test]
    fn a_scan_root_outside_the_config_root_cannot_be_anchored() {
        let dir = tempdir();
        multimodule_repo(dir.path());
        let outside = tempdir();

        let config = root_config(dir.path());
        let err = Anchoring::resolve(outside.path(), Some(&config)).unwrap_err();
        assert!(err.contains("does not contain the scan root"), "{err}");

        // And it reaches the caller as a scan setup failure, not as a scan.
        let options = options_for(&config);
        assert!(scan_opts(outside.path(), &ruleset(), &options, &mut |_| {}).is_err());
    }

    #[test]
    fn a_module_holding_a_config_is_still_below_the_one_the_scan_loaded() {
        let dir = tempdir();
        multimodule_repo(dir.path());

        // The module directory holds its own `siloscan.toml` - it is the file the
        // root includes - so a guard that rediscovered a config from the scan
        // root would find that one, call the scan root the config root, and run
        // a silo aggregate over part of the silo.
        let config = root_config(dir.path());
        let options = options_for(&config);
        let err = scan_opts(
            &dir.path().join("modules/api"),
            &silo_duplication_rules(),
            &options,
            &mut |_| {},
        )
        .unwrap_err();

        assert!(
            err.contains("silo-scoped duplication rules are relative to"),
            "{err}"
        );
        assert!(
            err.contains(&dir.path().display().to_string()),
            "the config root is named: {err}"
        );
    }

    #[test]
    fn without_an_anchor_key_nothing_moves() {
        let dir = tempdir();
        duplicated_tree(dir.path());
        write(dir.path(), "n.rs", b"needle\n");
        // Present on disk for both runs, so the only variable below is whether
        // the scan loaded it.
        write(dir.path(), "siloscan.toml", b"");

        let rules = duplication_ruleset();
        let anchor = crate::config::Anchor::ScanRoot;

        let bare = scan(dir.path(), &rules, None);
        let config = root_config(dir.path());
        let loaded = scan_opts(dir.path(), &rules, &options_for(&config), &mut |_| {})
            .expect("empty config");

        assert_eq!(
            crate::output::to_json(&bare, &rules, anchor, None),
            crate::output::to_json(&loaded, &rules, anchor, None),
            "an empty config must change nothing at all"
        );

        // Pinned to the scan-root convention, so a change of convention cannot
        // slip through by moving both sides of the comparison together.
        for report in [&bare, &loaded] {
            let fingerprints: Vec<&str> = report
                .findings
                .iter()
                .map(|f| f.fingerprint.as_str())
                .collect();
            for expected in [
                crate::findings::fingerprint("test.needle", "n.rs", "needle", 0),
                crate::findings::fingerprint("quality.duplication", ".", "", 0),
            ] {
                assert!(
                    fingerprints.contains(&expected.as_str()),
                    "missing {expected}: {fingerprints:?}"
                );
            }
        }
    }

    // Parse gating and the size cap: who reaches tree-sitter at all.

    #[cfg(feature = "tree-sitter-rust")]
    const AST_RULES: &str = r#"
version: 1
rules:
  - id: rust.dbg-macro
    severity: warning
    message: "leftover dbg"
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "dbg"))'
"#;

    #[cfg(feature = "tree-sitter-rust")]
    fn ast_ruleset() -> RuleSet {
        RuleSet {
            rules: load_str(AST_RULES, "ast").unwrap(),
            sources: vec![("ast".to_string(), AST_RULES.to_string())],
        }
    }

    /// A config whose only setting is the parse size cap.
    fn limits_config(max_parse_bytes: u64) -> crate::config::Config {
        crate::config::Config {
            limits: crate::config::LimitsConfig { max_parse_bytes },
            ..Default::default()
        }
    }

    /// Rust source holding one `dbg!` for the ast rule and one `needle` for the
    /// regex rule, so a run says both whether it parsed and whether it read.
    const GATED_SOURCE: &str = "fn main() {\n    dbg!(1);\n    let needle = 2;\n}\n";

    #[test]
    fn a_rule_set_needing_no_tree_never_reports_a_parse_skip() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", GATED_SOURCE.as_bytes());

        // A cap far below the file size: with no ast and no boundary rule
        // loaded, nothing asked for a tree, so the cap has nothing to stop.
        let config = limits_config(8);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &ruleset(), &options, &mut |_| {}).unwrap();

        assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        assert!(report.graph.files.is_empty());
        // The text engines ran regardless.
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "test.needle");
        assert_eq!(report.metrics.files["src/a.rs"].lines, 4);
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn an_oversize_file_is_skipped_when_an_ast_rule_targets_it() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", GATED_SOURCE.as_bytes());

        let config = limits_config(8);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &ast_ruleset(), &options, &mut |_| {}).unwrap();

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, "src/a.rs");
        assert_eq!(
            report.skipped[0].reason,
            format!("exceeds max_parse_bytes ({} > 8)", GATED_SOURCE.len())
        );
        // No tree means no ast finding and no graph entry for the file.
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert!(report.graph.files.is_empty());
        // And the file is still measured.
        assert_eq!(report.metrics.files["src/a.rs"].lines, 4);
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn a_file_at_the_cap_parses_and_one_byte_over_does_not() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", GATED_SOURCE.as_bytes());

        let size = GATED_SOURCE.len() as u64;
        let report = |cap: u64| {
            let config = limits_config(cap);
            let options = ScanOptions {
                config: Some(&config),
                ..ScanOptions::default()
            };
            scan_opts(dir.path(), &ast_ruleset(), &options, &mut |_| {}).unwrap()
        };

        let at_cap = report(size);
        assert!(at_cap.skipped.is_empty(), "{:?}", at_cap.skipped);
        assert_eq!(at_cap.findings.len(), 1);
        assert_eq!(at_cap.findings[0].rule_id, "rust.dbg-macro");
        // The finding is the proof the file parsed. No boundary rule is
        // loaded, so the parsed tree yields no import facts.
        assert!(at_cap.graph.files.is_empty());

        let over_cap = report(size - 1);
        assert_eq!(over_cap.skipped.len(), 1);
        assert_eq!(
            over_cap.skipped[0].reason,
            format!("exceeds max_parse_bytes ({size} > {})", size - 1)
        );
        assert!(over_cap.findings.is_empty());
        assert!(over_cap.graph.files.is_empty());
    }

    /// The cap gates a tree wanted for that file's own ast findings, and the
    /// file drops out of the graph with it. A tree wanted for the import graph
    /// is whole-tree state: dropping the file would stop every import of it
    /// resolving, changing the boundary results of files well under the cap, so
    /// the file keeps its place in the graph without a tree.
    #[test]
    fn an_oversized_file_keeps_its_graph_node_when_a_boundary_rule_is_loaded() {
        let config = limits_config(8);
        let rules = boundary_rules();
        let boundary = ParseNeeds::of(&rules);
        let ast_only = ParseNeeds {
            boundary: false,
            ast_languages: vec!["rust".to_string()],
            metric_languages: Vec::new(),
        };

        let gated = parse_decision(&boundary, Some(&config), Some("rust"), 4096);
        let reason = match gated {
            ParseDecision::GraphNodeOnly(reason) => reason,
            other => panic!("an oversized file must stay in the graph: {other:?}"),
        };
        // The size and the cap, then what is and is not still analysed.
        assert!(
            reason.starts_with("exceeds max_parse_bytes (4096 > 8)"),
            "{reason}"
        );
        assert!(reason.contains("imports of it still resolve"), "{reason}");
        assert!(reason.contains("not analysed"), "{reason}");

        // Under the cap nothing changes: the tree is built as before.
        assert_eq!(
            parse_decision(&boundary, Some(&config), Some("rust"), 8),
            ParseDecision::Parse
        );

        // An ast rule wants a tree for this file alone, so the hole is the
        // file's own and it leaves the graph with its tree.
        assert_eq!(
            parse_decision(&ast_only, Some(&config), Some("rust"), 4096),
            ParseDecision::Skip(Some("exceeds max_parse_bytes (4096 > 8)".to_string()))
        );
    }

    /// A metric rule reads a tree and nothing else, so a file it measures has
    /// to be parsed even when no ast or boundary rule asked for one. Without a
    /// `languages` filter the rule measures every language with a node-kind
    /// table.
    #[test]
    fn a_metric_rule_alone_wants_a_tree() {
        let unfiltered = "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    \
                          metric: { measure: nesting-depth, max: 3 }\n";
        let filtered = "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    \
                        languages: [\"rust\"]\n    metric: { measure: nesting-depth, max: 3 }\n";

        let needs = ParseNeeds::of(&RuleSet {
            rules: load_str(unfiltered, "metric").unwrap(),
            sources: vec![("metric".to_string(), unfiltered.to_string())],
        });
        assert!(!needs.boundary);
        assert!(needs.ast_languages.is_empty());
        assert!(needs.wants(Some("rust")));
        assert!(needs.wants(Some("ruby")));
        assert!(!needs.wants(Some("yaml")));
        assert!(!needs.wants(None));

        let needs = ParseNeeds::of(&RuleSet {
            rules: load_str(filtered, "metric").unwrap(),
            sources: vec![("metric".to_string(), filtered.to_string())],
        });
        assert!(needs.wants(Some("rust")));
        assert!(!needs.wants(Some("ruby")));
    }

    /// A boundary rule's `paths` envelope selects the files it reports *from*.
    /// The graph hole an oversized file leaves is on the imported side, which no
    /// envelope describes, so scoping a rule must not quietly drop the file out
    /// of the graph.
    #[test]
    fn a_scoped_boundary_rule_still_keeps_oversized_files_in_the_graph() {
        let config = limits_config(8);
        let src = r#"
version: 1
rules:
  - id: arch.api-must-not-import-db
    severity: error
    message: "api must not import db"
    paths:
      include: ["src/api/**"]
    boundary:
      from: api
      deny: ["db"]
"#;
        let rules = RuleSet {
            rules: load_str(src, "boundary").unwrap(),
            sources: vec![("boundary".to_string(), src.to_string())],
        };
        let needs = ParseNeeds::of(&rules);

        // Outside the rule's envelope, and still an import target for files
        // inside it.
        assert!(matches!(
            parse_decision(&needs, Some(&config), Some("javascript"), 4096),
            ParseDecision::GraphNodeOnly(_)
        ));
    }

    /// The same thing end to end, and the case the envelope makes tempting: the
    /// importer is under the cap, the file it imports is over it and outside the
    /// rule's `paths`. The violation belongs to the importer and is reported.
    #[test]
    #[cfg_attr(
        not(feature = "tree-sitter-javascript"),
        ignore = "needs the javascript parser"
    )]
    fn an_oversized_import_target_still_produces_the_violation() {
        let dir = tempdir();
        let importer = b"import x from '../db/client';\n";
        let imported = format!("// {}\nexport const x = 1;\n", "pad".repeat(64));
        write(dir.path(), "src/api/handler.js", importer);
        write(dir.path(), "src/db/client.js", imported.as_bytes());

        let src = r#"
version: 1
rules:
  - id: arch.api-must-not-import-db
    severity: error
    message: "api must not import db"
    paths:
      include: ["src/api/**"]
    boundary:
      from: api
      deny: ["db"]
"#;
        let rules = RuleSet {
            rules: load_str(src, "boundary").unwrap(),
            sources: vec![("boundary".to_string(), src.to_string())],
        };

        let mut config = silo_config(SILOS);
        config.limits.max_parse_bytes = 64;
        assert!(importer.len() < 64);
        assert!(imported.len() > 64);

        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report =
            scan_opts(dir.path(), &rules, &options, &mut |_| {}).expect("the cap never fails");

        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].rule_id, "arch.api-must-not-import-db");
        assert_eq!(report.findings[0].path, "src/api/handler.js");

        // The file is in the graph so the import resolves, and what it cost is
        // on the record.
        let node = report
            .graph
            .files
            .get("src/db/client.js")
            .expect("an oversized file keeps its node");
        assert!(node.imports.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, "src/db/client.js");
        assert!(
            report.skipped[0].reason.starts_with(&format!(
                "exceeds max_parse_bytes ({} > 64)",
                imported.len()
            )),
            "{}",
            report.skipped[0].reason
        );
    }

    /// A tree that scanned clean under a previous release must not start
    /// failing because one generated file sits over the cap. The oversized file
    /// costs its own outgoing edges, is recorded, and the scan runs.
    #[test]
    fn an_oversized_file_never_fails_the_scan() {
        let dir = tempdir();
        let imported = format!("// {}\nexport const x = 1;\n", "pad".repeat(64));
        write(dir.path(), "src/api/handler.js", b"export const y = 1;\n");
        write(dir.path(), "src/db/client.js", imported.as_bytes());

        let mut config = silo_config(SILOS);
        config.limits.max_parse_bytes = 64;
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {})
            .expect("the cap never fails");

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, "src/db/client.js");
        assert!(report.graph.files.contains_key("src/db/client.js"));
    }

    /// A tree of files the scan could not read the way its rules asked for -
    /// two over the cap, one binary - reports identically whatever the worker
    /// count, and every one of them is on the record.
    #[test]
    fn a_tree_of_skips_reports_identically_across_worker_counts() {
        let dir = tempdir();
        let big = format!("// {}\nexport const x = 1;\n", "pad".repeat(64));
        write(dir.path(), "src/api/a.js", big.as_bytes());
        write(dir.path(), "src/api/z.js", big.as_bytes());
        write(dir.path(), "src/api/small.js", b"export const y = 1;\n");
        write(dir.path(), "src/api/blob.bin", b"\0binary\n");
        write(dir.path(), "notes.txt", b"needle\n");

        let mut config = silo_config(SILOS);
        config.limits.max_parse_bytes = 64;
        let rules = boundary_rules();
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let sets = config.silo_sets().expect("globs compile");
        let anchoring = Anchoring::default();
        let run = |workers| {
            super::run_with_workers(
                dir.path(),
                &rules,
                &options,
                Some(sets.clone()),
                &anchoring,
                &mut |_| {},
                workers,
            )
            .expect("the cap never fails a scan")
        };

        let one = run(1);
        let paths: Vec<&str> = one
            .skipped
            .iter()
            .map(|skipped| skipped.path.as_str())
            .collect();
        assert_eq!(paths, ["src/api/a.js", "src/api/blob.bin", "src/api/z.js"]);

        let json = |workers| {
            crate::output::to_json(&run(workers), &rules, crate::config::Anchor::ScanRoot, None)
        };
        let single = json(1);
        assert_eq!(single, json(8));
        assert_eq!(single, json(3));
        assert!(single.contains(BINARY_SKIP_REASON), "{single}");
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn the_cap_decision_is_never_served_from_the_other_side_of_it() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", GATED_SOURCE.as_bytes());

        let rules = ast_ruleset();
        let cache_home = cache_base();
        let cache = cache_for(cache_home.path(), dir.path(), &rules);
        let json = |cap: u64, cache: Option<&crate::cache::Cache>| {
            let config = limits_config(cap);
            let options = ScanOptions {
                cache,
                config: Some(&config),
                ..ScanOptions::default()
            };
            let report = run_with_workers(
                dir.path(),
                &rules,
                &options,
                None,
                &Anchoring::default(),
                &mut |_| {},
                1,
            );
            crate::output::to_json(&report, &rules, crate::config::Anchor::ScanRoot, None)
        };

        let size = GATED_SOURCE.len() as u64;
        // A generous cap fills the cache with a parsed entry; the tight cap
        // that follows must not be handed that entry's ast finding.
        let parsed = json(size, Some(&cache));
        let gated = json(size - 1, Some(&cache));

        assert!(parsed.contains("rust.dbg-macro"));
        assert!(!gated.contains("rust.dbg-macro"), "{gated}");
        assert_eq!(gated, json(size - 1, None), "the cache must not move it");
        assert_eq!(parsed, json(size, None));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_is_counted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        write(dir.path(), "secret.txt", b"needle\n");
        write(dir.path(), "ok.txt", b"needle\n");

        let locked = dir.path().join("secret.txt");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&locked).is_ok() {
            // Privileged run: the mode bits are ignored, so there is nothing to assert.
            return;
        }

        let report = scan(dir.path(), &ruleset(), None);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, "secret.txt");
        assert!(!report.skipped[0].reason.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "ok.txt");

        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// Valid syntax, past the regex size limit: `regex_syntax` accepts it at
    /// load and the compile fails the first time a file makes the rule run.
    const OVERSIZED_RULES: &str = concat!(
        "version: 1\n",
        "rules:\n",
        "  - id: a.oversized\n",
        "    severity: error\n",
        "    message: m\n",
        "    secret:\n",
        "      pattern: 'needle-(?:[A-Za-z0-9]{1000}){1000}'\n",
        "      keywords: ['needle-']\n",
    );

    fn oversized_ruleset() -> RuleSet {
        RuleSet {
            rules: load_str(OVERSIZED_RULES, "test").expect("an oversized pattern still loads"),
            sources: vec![("test".to_string(), OVERSIZED_RULES.to_string())],
        }
    }

    /// A rule that cannot be compiled reports nothing, and a scan that reports
    /// nothing reads as a clean one. So the scan fails instead, and the failure
    /// names the rule.
    #[test]
    fn a_rule_that_cannot_compile_fails_the_scan_rather_than_sitting_out() {
        let dir = tempdir();
        write(dir.path(), "a.txt", b"needle-abc\n");

        let err = super::scan(dir.path(), &oversized_ruleset(), None)
            .expect_err("an unusable rule must not be skipped");

        assert!(err.contains("a.oversized"), "{err}");
    }

    /// A rule no file makes run never compiles, so it never fails. Laziness is
    /// the point of the deferred compile and must survive the failure path.
    #[test]
    fn a_rule_that_never_runs_cannot_fail_the_scan() {
        let dir = tempdir();
        write(dir.path(), "a.txt", b"haystack\n");

        let report = super::scan(dir.path(), &oversized_ruleset(), None)
            .expect("a rule that never runs cannot fail");

        assert!(report.findings.is_empty());
    }

    /// The workers race, so the failure a scan reports must be chosen by walk
    /// order and not by whoever hit one first. Two files fail here; both worker
    /// counts must name the same one.
    #[test]
    fn the_reported_failure_does_not_depend_on_the_worker_count() {
        let dir = tempdir();
        write(dir.path(), "a.txt", b"needle-first\n");
        write(dir.path(), "b.txt", b"needle-second\n");

        let rules = oversized_ruleset();
        let options = ScanOptions::default();
        let anchoring = &Anchoring::default();

        let one = super::run_with_workers(
            dir.path(),
            &rules,
            &options,
            None,
            anchoring,
            &mut |_| {},
            1,
        )
        .expect_err("the rule cannot compile");
        let many = super::run_with_workers(
            dir.path(),
            &rules,
            &options,
            None,
            anchoring,
            &mut |_| {},
            8,
        )
        .expect_err("the rule cannot compile");

        assert_eq!(one, many);
    }

    /// A link out of the scan root is the security-relevant case: its target is
    /// a file the scan never opened, sitting somewhere the scan root does not
    /// control. It has to appear in `skipped`, because that is the report saying
    /// where it did not look, and the target must not be read.
    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_scan_root_is_reported_and_its_target_is_not_read() {
        let outside = tempdir();
        write(outside.path(), "secret.rs", b"let needle = 1;\n");

        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let clean = 1;\n");
        std::os::unix::fs::symlink(outside.path().join("secret.rs"), dir.path().join("link.rs"))
            .unwrap();

        let report = scan(dir.path(), &ruleset(), None);

        // The target holds a match. Nothing may report it.
        assert!(
            report.findings.is_empty(),
            "a file outside the scan root was read: {:?}",
            identities(&report.findings)
        );
        let entry = report
            .skipped
            .iter()
            .find(|skipped| skipped.path == "link.rs")
            .expect("the link must be reported as a path nothing was read through");
        assert_eq!(
            entry.reason,
            walk::SymlinkDisposition::OutsideRoot.reason(),
            "the report has to say why, not just that"
        );
    }

    /// The other half of the same rule, and the one that keeps the list worth
    /// reading: a link whose target is inside the root costs no coverage,
    /// because the target is walked on its own path. Listing it as skipped would
    /// claim the scan missed a file it read, and would bury the links that do
    /// cost coverage under ones that do not.
    #[cfg(unix)]
    #[test]
    fn a_link_inside_the_scan_root_is_not_reported_as_skipped() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let needle = 1;\n");
        std::os::unix::fs::symlink(dir.path().join("src/a.rs"), dir.path().join("alias.rs"))
            .unwrap();

        let report = scan(dir.path(), &ruleset(), None);

        assert!(
            report.skipped.is_empty(),
            "nothing was missed, so nothing may be listed as missed: {:?}",
            report.skipped
        );
        // The target is still scanned, once, on its own path.
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.path == "src/a.rs")
                .count(),
            1
        );
    }

    /// `follow_symlinks` reads an in-root target through the link as well as on
    /// its own path, so the file is reported under both. That double report is
    /// what following means, and it is why the flag is off by default.
    #[cfg(unix)]
    #[test]
    fn following_links_reads_an_in_root_target_under_both_paths() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let needle = 1;\n");
        std::os::unix::fs::symlink(dir.path().join("src/a.rs"), dir.path().join("alias.rs"))
            .unwrap();

        let options = ScanOptions {
            follow_symlinks: true,
            ..ScanOptions::default()
        };
        let report = run_with_workers(
            dir.path(),
            &ruleset(),
            &options,
            None,
            &Anchoring::default(),
            &mut |_| {},
            1,
        );

        let paths: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.path.as_str())
            .collect();
        assert!(paths.contains(&"alias.rs"), "{paths:?}");
        assert!(paths.contains(&"src/a.rs"), "{paths:?}");
    }

    /// Following links may not become a way out of the scan root. This is the
    /// property the whole flag hangs on: a scan that reads files above its own
    /// root stops being a statement about the tree under review.
    #[cfg(unix)]
    #[test]
    fn following_links_still_refuses_a_target_outside_the_scan_root() {
        let outside = tempdir();
        write(outside.path(), "secret.rs", b"let needle = 1;\n");

        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let clean = 1;\n");
        std::os::unix::fs::symlink(outside.path().join("secret.rs"), dir.path().join("link.rs"))
            .unwrap();

        let options = ScanOptions {
            follow_symlinks: true,
            ..ScanOptions::default()
        };
        let report = run_with_workers(
            dir.path(),
            &ruleset(),
            &options,
            None,
            &Anchoring::default(),
            &mut |_| {},
            1,
        );

        assert!(
            report.findings.is_empty(),
            "--follow-symlinks must not reach outside the scan root: {:?}",
            identities(&report.findings)
        );
        assert!(
            report
                .skipped
                .iter()
                .any(|skipped| skipped.path == "link.rs"),
            "the refusal still has to be reported: {:?}",
            report.skipped
        );
    }

    /// A broken link names a path nothing was read from, whatever the reason, so
    /// it is reported the same way a refused one is.
    #[cfg(unix)]
    #[test]
    fn a_broken_link_is_reported_as_unread() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let clean = 1;\n");
        std::os::unix::fs::symlink(dir.path().join("gone.rs"), dir.path().join("dangling.rs"))
            .unwrap();

        let report = scan(dir.path(), &ruleset(), None);

        let entry = report
            .skipped
            .iter()
            .find(|skipped| skipped.path == "dangling.rs")
            .expect("a broken link is a path nothing was read from");
        assert_eq!(entry.reason, walk::SymlinkDisposition::Broken.reason());
    }

    /// The skipped list stays sorted and identical whatever the worker count,
    /// with links merged into it. Determinism is the property every baseline
    /// depends on, and links are the newest thing that could break it.
    #[cfg(unix)]
    #[test]
    fn reported_links_are_identical_across_worker_counts() {
        let outside = tempdir();
        write(outside.path(), "secret.rs", b"let x = 1;\n");

        let dir = tempdir();
        for name in ["a", "b", "c", "d"] {
            write(dir.path(), &format!("src/{name}.rs"), b"let clean = 1;\n");
            std::os::unix::fs::symlink(
                outside.path().join("secret.rs"),
                dir.path().join(format!("link_{name}.rs")),
            )
            .unwrap();
        }

        let run = |workers| {
            let report = run_with_workers(
                dir.path(),
                &ruleset(),
                &ScanOptions::default(),
                None,
                &Anchoring::default(),
                &mut |_| {},
                workers,
            );
            serde_json::to_string(&report.skipped).unwrap()
        };

        let one = run(1);
        assert_eq!(one, run(8));
        assert_eq!(one, run(3));
        // Non-vacuous: all four links are in there.
        for name in ["a", "b", "c", "d"] {
            assert!(one.contains(&format!("link_{name}.rs")), "{one}");
        }
    }
}
