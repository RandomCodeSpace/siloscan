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
use crate::rules::{CompiledPayload, DuplicationScope, RuleSet, Severity};
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

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Actionable findings: neither suppressed inline nor covered by the baseline.
    pub findings: Vec<Finding>,
    pub baselined: Vec<Finding>,
    pub suppressed: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
    /// Per-file semantic facts for every file that produced a parse tree.
    pub graph: crate::graph::Graph,
    /// Every boundary violation as `(from silo, to silo, fingerprint)`, sorted.
    /// The finding itself is in `findings`, `baselined` or `suppressed`
    /// depending on how it was partitioned, and is identified by fingerprint.
    pub boundary_edges: Vec<(String, String, String)>,
    /// Size and duplication metrics for every text file that was scanned.
    pub metrics: Metrics,
}

/// Optional inputs to a scan. Defaults to no baseline, cache, config or
/// coverage report, which is exactly what [`scan`] and [`scan_with_progress`]
/// pass.
#[derive(Default)]
pub struct ScanOptions<'a> {
    pub baseline: Option<&'a crate::baseline::Baseline>,
    pub cache: Option<&'a crate::cache::Cache>,
    /// Repository config. Boundary rules are inert without one: silo
    /// membership is defined by the config and nowhere else.
    pub config: Option<&'a crate::config::Config>,
    /// Parsed coverage report. Coverage rules are inert without one: absence
    /// of data is not evidence of an uncovered file.
    pub coverage: Option<&'a crate::coverage::CoverageReport>,
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

pub fn scan(
    root: &Path,
    rules: &RuleSet,
    baseline: Option<&crate::baseline::Baseline>,
) -> ScanReport {
    scan_with_progress(root, rules, baseline, &mut |_| {})
}

/// Same scan, with a callback invoked once after the walk (`files_done = 0`,
/// total known) and once after each file.
pub fn scan_with_progress(
    root: &Path,
    rules: &RuleSet,
    baseline: Option<&crate::baseline::Baseline>,
    on_progress: &mut dyn FnMut(Progress),
) -> ScanReport {
    let options = ScanOptions {
        baseline,
        ..ScanOptions::default()
    };
    // Silo validation and anchoring are the only fallible steps and both need a
    // config, which the default options do not carry, so this path cannot fail:
    // no config means no anchor key, and the absent key means scan-root.
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
///
/// Fails when a boundary rule names a silo the config does not define, when
/// boundary or silo-scoped duplication rules would run against a scan root below
/// the directory holding the config (a typo or a partial scan would otherwise
/// silently disable the rule), and when the config's `anchor` cannot be honoured
/// for this scan root.
pub fn scan_opts(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    on_progress: &mut dyn FnMut(Progress),
) -> Result<ScanReport, String> {
    let silo_sets = boundary_setup(root, rules, options.config)?;
    duplication_setup(root, rules, options.config)?;
    // Derived from the scan root and the config alone, so a caller that resolved
    // it separately - to key a cache, or to label a report - resolved the same
    // value. There is no way for the two to disagree.
    let anchoring = Anchoring::resolve(root, options.config)?;
    Ok(run(
        root,
        rules,
        options,
        silo_sets,
        &anchoring,
        on_progress,
    ))
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
) -> ScanReport {
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
) -> ScanReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut suppressed: Vec<Finding> = Vec::new();
    let mut skipped: Vec<SkippedFile> = Vec::new();
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

    let files = walk::collect_files(root);
    let files_total = files.len();
    on_progress(Progress {
        files_total,
        files_done: 0,
        findings: 0,
    });

    for result in scan_files(
        root,
        rules,
        options,
        anchoring,
        &files,
        on_progress,
        workers,
    ) {
        let FileResult {
            path_rel,
            path,
            outcome,
            ..
        } = result;
        match outcome {
            // Binary files are not scannable input, not a failure to report.
            Outcome::Binary => {}
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
            } => {
                if let Some(facts) = facts {
                    graph.files.insert(path_rel.clone(), facts);
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
        whole_tree.extend(crate::coverage::scan_coverage(
            &rules.rules,
            &resolved,
            &paths,
        ));
    }

    // Metrics are cross-file, so they are computed here rather than per file,
    // and they are never stored in or read from the per-file cache: a warm
    // cache must produce the same numbers as a cold one.
    let (metrics, duplication) = measure(contents, file_metrics, options.config);
    whole_tree.extend(duplicate_block_findings(&duplication));
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

    ScanReport {
        findings,
        baselined,
        suppressed,
        skipped,
        graph,
        boundary_edges,
        metrics,
    }
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
                column: 1,
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
    Text {
        facts: Option<FileFacts>,
        kept: Vec<Finding>,
        ignored: Vec<Finding>,
        /// Kept for the cross-file duplication pass.
        content: String,
        /// Line counts, measured from the file and never from the cache.
        metrics: FileMetrics,
    },
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
fn scan_files(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    anchoring: &Anchoring,
    files: &[PathBuf],
    on_progress: &mut dyn FnMut(Progress),
    workers: usize,
) -> Vec<FileResult> {
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
                    let (result, raw) = scan_one(root, rules, options, anchoring, index, path);
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
fn scan_one(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    anchoring: &Anchoring,
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
            let language = crate::lang::detect(path, &content);
            // Measured here, from the file itself: a cache hit replaces the
            // engine work below, and metrics must not move with the cache.
            let metrics = crate::metrics::measure_file(&content, language);
            let entry = scan_text(rules, options, &path_rel, &content, language);
            let raw = entry.findings.len();
            let (kept, ignored) = crate::suppress::partition(&content, entry.findings);
            (
                Outcome::Text {
                    facts: entry.facts,
                    kept,
                    ignored,
                    content,
                    metrics,
                },
                raw,
            )
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
fn scan_text(
    rules: &RuleSet,
    options: &ScanOptions,
    path_rel: &str,
    content: &str,
    language: Option<&'static str>,
) -> crate::cache::CachedFile {
    let hash = options.cache.map(|_| entry_hash(path_rel, content));

    if let (Some(cache), Some(hash)) = (options.cache, &hash)
        && let Some(entry) = cache.get(hash, content)
    {
        return entry;
    }

    let tree = language.and_then(|lang| crate::parsers::parse(lang, content));

    let mut file_findings =
        crate::engines::regex::scan_file(&rules.rules, path_rel, language, content);
    file_findings.extend(crate::engines::secret::scan_file(
        &rules.rules,
        path_rel,
        language,
        content,
    ));
    file_findings.extend(crate::engines::ast::scan_file(
        &rules.rules,
        path_rel,
        language,
        content,
        tree.as_ref(),
    ));

    let facts = match (language, &tree) {
        (Some(lang), Some(tree)) => Some(crate::graph::extract(lang, content, tree)),
        _ => None,
    };

    let entry = crate::cache::CachedFile {
        findings: file_findings,
        facts,
    };
    if let (Some(cache), Some(hash)) = (options.cache, &hash) {
        cache.put(hash, &entry);
    }
    entry
}

/// Cache entries are keyed by path and content together: a finding carries its
/// repo-relative path, and its fingerprint is derived from it, so two identical
/// files at different paths are not interchangeable.
fn entry_hash(path_rel: &str, content: &str) -> String {
    let mut buf = Vec::with_capacity(path_rel.len() + content.len() + 1);
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

    /// A cache for the default, scan-root-anchored convention.
    fn cache_for(root: &Path, rules: &RuleSet) -> crate::cache::Cache {
        crate::cache::Cache::open(root, rules, &crate::cache::PathScope::ScanRoot)
    }

    /// A cache for the convention `anchoring` describes.
    fn cache_anchored(root: &Path, rules: &RuleSet, anchoring: &Anchoring) -> crate::cache::Cache {
        let scope = crate::cache::PathScope::new(anchoring.anchor(), anchoring.prefix());
        crate::cache::Cache::open(root, rules, &scope)
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

    #[test]
    fn binary_file_is_skipped_silently() {
        let dir = tempdir();
        write(dir.path(), "blob.bin", b"needle\0\0\0needle");
        write(dir.path(), "ok.txt", b"needle\n");

        let report = scan(dir.path(), &ruleset(), None);

        assert!(report.skipped.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "ok.txt");
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
        let cache = cache_for(dir.path(), &rules);
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

    #[test]
    fn edited_content_invalidates_the_cached_entry() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");

        let rules = ruleset();
        let cache = cache_for(dir.path(), &rules);
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
        let cache = cache_for(dir.path(), &rules);
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

        let rules = ruleset();
        let cache = cache_for(dir.path(), &rules);
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

    #[test]
    fn duplicate_blocks_are_reported_as_info_findings() {
        let dir = tempdir();
        duplicated_tree(dir.path());

        let report = scan(dir.path(), &ruleset(), None);

        let blocks: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == crate::metrics::DUPLICATE_BLOCK_RULE_ID)
            .collect();
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

        let report = scan(dir.path(), &ruleset(), None);

        let blocks: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == crate::metrics::DUPLICATE_BLOCK_RULE_ID)
            .collect();
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

        let report = scan(dir.path(), &ruleset(), None);

        let blocks: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == crate::metrics::DUPLICATE_BLOCK_RULE_ID)
            .collect();
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

        let report = scan(dir.path(), &ruleset(), None);

        let reported: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == crate::metrics::DUPLICATE_BLOCK_RULE_ID)
            .map(|f| f.path.as_str())
            .collect();
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
            duplication: crate::config::DuplicationConfig { min_lines: 4 },
            ..Default::default()
        };
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &ruleset(), &options, &mut |_| {}).unwrap();

        assert_eq!(report.metrics.totals.duplicated_lines, 8);
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule_id == crate::metrics::DUPLICATE_BLOCK_RULE_ID)
                .count(),
            2
        );
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
        let cache = cache_for(dir.path(), &rules);
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

        let cache = cache_anchored(&root, &rules, &anchoring);
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
            crate::output::to_json(&report, anchoring.anchor())
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
        let warm = cache_anchored(&root, &rules, &anchored);
        let filled = run(Some(&warm), &anchored);
        assert!(!filled.findings.is_empty());

        let plain_cache = cache_for(&root, &rules);
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
            crate::output::to_json(&bare, anchor),
            crate::output::to_json(&loaded, anchor),
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
}
