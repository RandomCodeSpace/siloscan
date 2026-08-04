use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};
use siloscan_core::baseline::{self, Baseline};
use siloscan_core::cache::{Cache, PathScope};
use siloscan_core::config::{self, Anchor, Config};
use siloscan_core::coverage::{self, CoverageReport};
// Renders scanned text so a terminal displays it instead of obeying it. The
// TUI draws its spans through the same function, so the two front ends cannot
// drift apart; see the core definition for what is escaped and why.
use siloscan_core::findings::sanitize_for_terminal as safe;
use siloscan_core::harness;
use siloscan_core::rules::{self, CompiledPayload, CompiledRule, RuleSet, Severity};
use siloscan_core::scan;
use siloscan_core::walk;
use siloscan_core::{cache, default_pack, output, output_sarif};

// `args_conflicts_with_subcommands` is what keeps `siloscan services/api
// baseline` from baselining the current directory. The top-level positional and
// the subcommand's own positional are two separate arguments, so clap bound the
// path to the scan one and left `BaselineArgs::path` at its default of `.`: a
// monorepo user asking to accept one module's findings as debt accepted the
// whole repository's instead, secrets included, and nothing said so.
//
// The flag also fixes the usage line, which used to offer the path and a
// subcommand together and so documented the broken order as supported; it now
// renders the two forms that exist. A doc comment here would become clap's
// long help, so this stays a plain comment.
#[derive(Parser)]
#[command(
    about = "Universal offline rule-based static code scanner",
    long_about = "Universal offline rule-based static code scanner.\n\n\
        Scans PATH against YAML rule packs and reports findings as human text, \
        JSON or SARIF. Everything runs locally: no network, no telemetry, no \
        service.\n\n\
        A scan is self-contained by default. Ignore files inside PATH are \
        honoured; parent directories, git's global excludes and \
        .git/info/exclude are not consulted, so two checkouts of the same tree \
        scan the same way. The --respect-* flags opt each of those sources back \
        in.\n\n\
        Subcommands take their own PATH and their own flags, and cannot be \
        combined with the scan options above them.",
    version,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Record every current finding as accepted, so later scans report only new ones
    Baseline(BaselineArgs),

    /// Check a fixture tree against its inline `siloscan-expect:` markers
    Test(TestArgs),

    /// Maintain the on-disk scan cache
    #[command(subcommand)]
    Cache(CacheCommand),
}

#[derive(Subcommand)]
enum CacheCommand {
    /// Delete cache entries written by a different siloscan build
    Prune(CacheArgs),
}

#[derive(Args)]
struct CacheArgs {
    /// Path whose `.siloscan/cache` is pruned
    #[arg(default_value = ".")]
    path: PathBuf,
}

/// Which ignore sources a scan consults.
///
/// Every flag here widens or narrows what gets read, so every one of them is
/// spelled out rather than inherited. The defaults are `IgnoreOptions::default`:
/// ignore files inside the scan root count, nothing above or outside it does.
///
/// The three `--respect-*` flags exist so the pre-1.1.2 behavior is recoverable,
/// but only by asking for it. Each one makes the scan depend on something
/// outside the tree it was pointed at, which is why none of them is on by
/// default and why `--no-ignore` does not turn them on either: "scan everything
/// under the root" is not a reason to start reading files above it.
#[derive(Args, Clone, Copy, Default)]
struct IgnoreArgs {
    /// Scan every file: ignore no `.gitignore` and no `.ignore`
    #[arg(long)]
    no_ignore: bool,

    /// Ignore `.ignore` files but not `.gitignore` files
    #[arg(long)]
    no_gitignore: bool,

    /// Also honor ignore files in directories above the scan root
    #[arg(long)]
    respect_parent_ignores: bool,

    /// Also honor `<PATH>/.git/info/exclude`
    #[arg(long)]
    respect_git_exclude: bool,

    /// Also honor git's global `core.excludesFile`
    #[arg(long)]
    respect_global_gitignore: bool,
}

impl IgnoreArgs {
    /// The walk policy these flags describe.
    ///
    /// `--no-ignore` clears both in-root sources and is applied first, so
    /// `--no-ignore --respect-parent-ignores` still reads the parent ignore
    /// files it was asked for while scanning everything the root's own ignore
    /// files would have hidden. The two settings are about different
    /// directories and neither one implies the other.
    fn to_options(self) -> walk::IgnoreOptions {
        let mut options = if self.no_ignore {
            walk::IgnoreOptions::all_files()
        } else {
            walk::IgnoreOptions::default()
        };
        if self.no_gitignore {
            options.respect_gitignore = false;
        }
        options.respect_parent_ignores |= self.respect_parent_ignores;
        options.respect_git_exclude |= self.respect_git_exclude;
        options.respect_global_gitignore |= self.respect_global_gitignore;
        options
    }
}

#[derive(Args)]
struct ScanArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Rule directories
    #[arg(long, value_name = "DIR")]
    rules: Vec<PathBuf>,

    /// Do not load the built-in rule pack
    #[arg(long)]
    no_default_rules: bool,

    /// Output format
    #[arg(long, value_enum, default_value = "human")]
    format: Format,

    /// Exit with code 1 if any finding meets this severity or higher
    #[arg(long, value_enum, default_value = "error")]
    fail_on: FailOn,

    /// Baseline file (defaults to `.siloscan/baseline.json` under PATH, or under the
    /// config root when the config sets `anchor = "config"`)
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Repository config (defaults to the nearest `siloscan.toml` at or above PATH)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Coverage report to feed coverage rules (lcov or cobertura)
    #[arg(long, value_name = "FILE")]
    coverage_report: Option<PathBuf>,

    /// Do not read or write the scan cache under `.siloscan/cache`
    #[arg(long)]
    no_cache: bool,

    #[command(flatten)]
    ignore: IgnoreArgs,
}

#[derive(Args)]
struct BaselineArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Rule directories
    #[arg(long, value_name = "DIR")]
    rules: Vec<PathBuf>,

    /// Do not load the built-in rule pack
    #[arg(long)]
    no_default_rules: bool,

    /// Repository config (defaults to the nearest `siloscan.toml` at or above PATH)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Coverage report to feed coverage rules (lcov or cobertura)
    #[arg(long, value_name = "FILE")]
    coverage_report: Option<PathBuf>,

    /// Do not read or write the scan cache under `.siloscan/cache`
    #[arg(long)]
    no_cache: bool,

    #[command(flatten)]
    ignore: IgnoreArgs,
}

#[derive(Args)]
struct TestArgs {
    /// Fixture directory
    fixture_dir: PathBuf,

    /// Rule directories
    #[arg(long, value_name = "DIR")]
    rules: Vec<PathBuf>,

    /// Do not load the built-in rule pack
    #[arg(long)]
    no_default_rules: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum FailOn {
    Info,
    Warning,
    Error,
}

impl FailOn {
    fn to_severity(self) -> Severity {
        match self {
            FailOn::Info => Severity::Info,
            FailOn::Warning => Severity::Warning,
            FailOn::Error => Severity::Error,
        }
    }
}

fn main() {
    let cli = parse_cli();

    match cli.command {
        None => run_scan(cli.scan),
        Some(Command::Baseline(args)) => run_baseline(args),
        Some(Command::Test(args)) => run_test(args),
        Some(Command::Cache(CacheCommand::Prune(args))) => run_cache_prune(args),
    }
}

/// Drop cache entries left behind by other siloscan builds.
///
/// A scan already prunes the directory it is about to use, so this exists for
/// the case where no scan is coming: an upgrade in CI, or a checkout whose
/// `.siloscan/cache` outlived the build that wrote it. Pruning is best-effort
/// by design - an entry that cannot be read or removed is left alone - so there
/// is nothing here to fail on and the exit code is 0 unless the path itself is
/// unusable.
///
/// The count is printed because 0 and 400 are both successes and the user asked
/// which one it was; a command that says nothing is indistinguishable from one
/// that silently did not run.
fn run_cache_prune(args: CacheArgs) {
    require_root(&args.path);
    let removed = cache::prune(&state_root(&args.path));
    let plural = if removed == 1 { "entry" } else { "entries" };
    println!("pruned {removed} cache {plural}");
}

/// Parses the command line, and turns the one conflict this CLI declares into a
/// message naming the form that works.
///
/// A top-level path alongside a subcommand is rejected rather than forwarded to
/// the subcommand: forwarding would have to decide which of two positionals the
/// user meant when both are given, and guessing that is exactly what wrote a
/// baseline over the wrong tree. Refusing cannot pick the wrong one.
fn parse_cli() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) if e.kind() == ErrorKind::ArgumentConflict => {
            let _ = e.print();
            // The binary name rather than a literal, because this file is
            // also compiled as the `ss` alias.
            let bin = env!("CARGO_BIN_NAME");
            // Not "a subcommand takes its own path": that describes only the
            // `PATH baseline` order. `--format json baseline PATH` reaches here
            // too, and there the path is not the problem - the scan option in
            // front of the subcommand is. Clap has already named the arguments
            // it refused, so this says what the rule is and what the shape is.
            eprintln!(
                "\nA subcommand comes first and carries its own path and flags:\n\
                 \x20 {bin} baseline <PATH>\n\
                 \x20 {bin} test <PATH>\n\
                 \x20 {bin} cache prune <PATH>\n\
                 Scan options and the top-level PATH belong to a scan and cannot \
                 precede a subcommand.\n\
                 Run `{bin} <COMMAND> --help` for what each subcommand accepts."
            );
            process::exit(2);
        }
        // Help, version and every other parse failure keep clap's own reporting
        // and its exit codes.
        Err(e) => e.exit(),
    }
}

fn run_scan(args: ScanArgs) {
    require_root(&args.path);
    let (config, config_rule_dirs) = load_config(&args.path, args.config.as_deref())
        .unwrap_or_else(|e| fail(&format!("error: {e}")));
    let rules = load_rules(
        &args.path,
        &rule_dirs(&args.rules, config_rule_dirs),
        args.no_default_rules,
    );
    if let Err(e) = require_silos(&rules, config.as_ref()) {
        fail(&format!("error: {e}"));
    }
    let coverage = load_coverage(args.coverage_report.as_deref())
        .unwrap_or_else(|e| fail(&format!("error: {e}")));

    // Resolved before the baseline is read and before the cache is opened: both
    // are bound to a path convention, and a config asking for an anchor that
    // cannot be honoured is a setup error rather than a scan that quietly
    // reports the wrong paths.
    let anchoring = scan::Anchoring::resolve(&args.path, config.as_ref())
        .unwrap_or_else(|e| fail(&format!("error: {e}")));

    let baseline = match load_baseline(
        &baseline_root(&args.path, config.as_ref()),
        args.baseline.as_deref(),
    ) {
        Ok(baseline) => baseline,
        Err(e) => fail(&e),
    };

    let cache = open_cache(&args.path, &rules, args.no_cache, &anchoring);
    // `ScanOptions` is `#[non_exhaustive]`, so it is built from its default and
    // assigned into rather than written as a literal.
    let mut options = scan::ScanOptions::default();
    options.baseline = baseline.as_ref();
    options.cache = cache.as_ref();
    options.config = config.as_ref();
    options.coverage = coverage.as_ref();
    options.ignore = args.ignore.to_options();
    let report = match scan::scan_opts(&args.path, &rules, &options, &mut |_| {}) {
        Ok(report) => report,
        Err(e) => fail(&format!("error: {e}")),
    };

    warn_skipped(&report.skipped);

    let mut out = io::stdout().lock();
    match args.format {
        Format::Human => {
            for finding in &report.findings {
                // Path, rule id and message are all scanned-repository text;
                // line, column and severity are not.
                emit(
                    &mut out,
                    format_args!(
                        "{}:{}:{} {} {} {}",
                        safe(&finding.path),
                        finding.line,
                        finding.column,
                        finding.severity,
                        safe(&finding.rule_id),
                        safe(&finding.message)
                    ),
                );
            }
            if report.baselined.len() + report.suppressed.len() > 0 {
                emit(
                    &mut out,
                    format_args!(
                        "{} findings ({} baselined, {} suppressed)",
                        report.findings.len(),
                        report.baselined.len(),
                        report.suppressed.len()
                    ),
                );
            }
            emit(
                &mut out,
                format_args!("{}", output::human_metrics_summary(&report.metrics)),
            );
        }
        Format::Json => emit(
            &mut out,
            format_args!("{}", output::to_json(&report, &rules, anchoring.anchor())),
        ),
        Format::Sarif => emit(
            &mut out,
            format_args!(
                "{}",
                output_sarif::to_sarif(&report, &rules, anchoring.anchor())
            ),
        ),
    }
    let _ = out.flush();

    let fail_on_severity = args.fail_on.to_severity();
    if report
        .findings
        .iter()
        .any(|f| f.severity >= fail_on_severity)
    {
        process::exit(1);
    }
}

fn run_baseline(args: BaselineArgs) {
    require_root(&args.path);
    let (config, config_rule_dirs) = load_config(&args.path, args.config.as_deref())
        .unwrap_or_else(|e| fail(&format!("error: {e}")));
    let rules = load_rules(
        &args.path,
        &rule_dirs(&args.rules, config_rule_dirs),
        args.no_default_rules,
    );
    if let Err(e) = require_silos(&rules, config.as_ref()) {
        fail(&format!("error: {e}"));
    }
    let coverage = load_coverage(args.coverage_report.as_deref())
        .unwrap_or_else(|e| fail(&format!("error: {e}")));

    let anchoring = scan::Anchoring::resolve(&args.path, config.as_ref())
        .unwrap_or_else(|e| fail(&format!("error: {e}")));

    let cache = open_cache(&args.path, &rules, args.no_cache, &anchoring);
    let mut options = scan::ScanOptions::default();
    options.cache = cache.as_ref();
    options.config = config.as_ref();
    options.coverage = coverage.as_ref();
    options.ignore = args.ignore.to_options();
    let report = match scan::scan_opts(&args.path, &rules, &options, &mut |_| {}) {
        Ok(report) => report,
        Err(e) => fail(&format!("error: {e}")),
    };

    warn_skipped(&report.skipped);

    // The findings already speak the active convention, and a baseline entry is
    // its finding's fingerprint and path verbatim, so the entries need nothing
    // said about them here; only the file's location follows the anchor, so that
    // every scan measuring from the same directory reads the same baseline.
    // Changing the anchor changes the fingerprints and so requires running this
    // command again; that is the whole migration.
    match baseline::save(
        &baseline_root(&args.path, config.as_ref()),
        &report.findings,
    ) {
        Ok(count) => {
            let mut out = io::stdout().lock();
            emit(&mut out, format_args!("baseline written: {count} entries"));
            let _ = out.flush();
        }
        Err(e) => fail(&format!("error: {e}")),
    }
}

fn run_test(args: TestArgs) {
    let rules = load_rules(&args.fixture_dir, &args.rules, args.no_default_rules);

    let report = match harness::run(&args.fixture_dir, &rules) {
        Ok(report) => report,
        Err(e) => fail(&format!("error: {e}")),
    };

    let mut out = io::stdout().lock();
    // Each line is `<path>:<line> <rule id>`, built from the fixture tree.
    for line in &report.missing {
        emit(&mut out, format_args!("missing: {}", safe(line)));
    }
    for line in &report.unexpected {
        emit(&mut out, format_args!("unexpected: {}", safe(line)));
    }
    emit(
        &mut out,
        format_args!(
            "{} matched, {} missing, {} unexpected",
            report.matched,
            report.missing.len(),
            report.unexpected.len()
        ),
    );
    let _ = out.flush();

    if report.missing.len() + report.unexpected.len() > 0 {
        process::exit(1);
    }
}

/// The cache lives under the scan root's state directory, which for a
/// single-file scan is the directory holding the file. `siloscan test` never
/// caches: a fixture run must exercise the engines.
///
/// The anchoring is part of the cache key. A cached finding carries a path and a
/// fingerprint derived from that path, so an entry written under one convention
/// would be wrong under another, and the two must never share a key.
///
/// It stays under the scan root even under `anchor = "config"`, unlike the
/// baseline: entries keyed by convention can never be shared across two scan
/// roots anyway, so moving the directory would buy nothing and would make a
/// module scan write into the repository root.
fn open_cache(
    root: &Path,
    rules: &RuleSet,
    no_cache: bool,
    anchoring: &scan::Anchoring,
) -> Option<Cache> {
    if no_cache {
        return None;
    }
    let scope = PathScope::new(anchoring.anchor(), anchoring.prefix());
    Some(Cache::open(&state_root(root), rules, &scope))
}

/// The directory a scan root keeps its `.siloscan` state in: the root itself
/// when it is a directory, and the directory holding it when the root is a
/// single file.
///
/// Joining `.siloscan` onto a file names a directory below a file, which every
/// read and every write there fails on - the failure that made `siloscan
/// app.js` exit 2 before it had scanned anything. A single-file scan reports
/// that file by the name it has inside its own directory, so that directory is
/// also where its baseline and its cache entries belong: the file scan and a
/// scan of the directory around it then read the same state.
fn state_root(root: &Path) -> PathBuf {
    if root.is_dir() {
        return root.to_path_buf();
    }
    match root.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The repository config and the extra rule directories it declares, resolved
/// against the directory holding the config file. An explicit `--config` must
/// exist and parse; the discovered one is simply absent when there is none.
///
/// A config that includes others is already merged by the time it is returned,
/// so a rule directory contributed by an included module reaches the loader on
/// the same footing as one the root config declared, and rule id collisions
/// between them are caught where every other collision is.
fn load_config(
    root: &Path,
    explicit: Option<&Path>,
) -> Result<(Option<Config>, Vec<PathBuf>), String> {
    let config = match explicit {
        Some(path) => Some(config::load(path)?),
        None => discover_config(root)?,
    };

    let Some(config) = config else {
        return Ok((None, Vec::new()));
    };
    let dirs = config.rule_dirs();
    Ok((Some(config), dirs))
}

/// The config a scan of `root` runs under when none was named on the command
/// line: the one discovery finds, or the root config that includes it.
///
/// In a multimodule repository a module's `siloscan.toml` is an included file,
/// and discovery stops at it because it sits in the scan root. Loading it as a
/// root config would drop the repository's `anchor`, its other silos and its
/// duplication settings without a word, so `siloscan modules/api` would report
/// under a different convention than `siloscan .` and fingerprint every finding
/// differently - the one thing the anchor exists to prevent. The file that
/// declares the include owns it, so that is the config the scan runs under, and
/// `--config` stays an override rather than a requirement.
fn discover_config(root: &Path) -> Result<Option<Config>, String> {
    let Some(path) = config::discover(root) else {
        return Ok(None);
    };
    let config = config::load(&path)?;

    // `include` is single level, so a file that includes others can never be
    // included itself: it is already a root config and nothing above it applies.
    if !config.include.is_empty() {
        return Ok(Some(config));
    }
    Ok(Some(owning_root(&path)?.unwrap_or(config)))
}

/// The nearest config above `target` that lists `target` in its `include`.
///
/// The walk climbs one directory at a time and stops at the repository root,
/// mirroring `config::discover`, so nothing outside the repository is read. Each
/// candidate on the way is loaded, and a candidate that does not parse is an
/// error rather than a reason to keep walking: it may be the file that owns the
/// scan, and guessing which config a scan ran under is the failure being fixed.
fn owning_root(target: &Path) -> Result<Option<Config>, String> {
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
        let config = config::load(&candidate)?;
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

/// True when `dir` holds the marker git leaves at a repository root: a `.git`
/// directory with a `HEAD`, or the `.git` file a worktree or submodule uses.
/// This is the boundary `config::discover` stops at, and the ascent above must
/// stop at the same place or a stray `siloscan.toml` in a parent directory
/// outside the repository would be read.
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

/// The directory the default `.siloscan/baseline.json` is read from and written
/// to: the scan root's state directory, and under `anchor = "config"` the
/// config root.
///
/// Anchoring makes a module scan and a whole-repository scan fingerprint a
/// finding identically; a baseline they cannot both find buys nothing from that.
/// The file therefore sits where the fingerprints are measured from, which is
/// what makes the migration "set the key, run `siloscan baseline` once" true
/// through the CLI instead of true only with `--baseline` pointed by hand.
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

/// Rule directories from the command line and from the config, in that order.
/// The loader sorts the files it finds, so the order only affects which
/// directory a duplicate id is reported against.
fn rule_dirs(explicit: &[PathBuf], from_config: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut dirs = explicit.to_vec();
    dirs.extend(from_config);
    dirs
}

/// A boundary rule can only fire against configured silos, so loading one
/// without a `[silos]` section is a config mistake, not a clean scan.
fn require_silos(rules: &RuleSet, config: Option<&Config>) -> Result<(), String> {
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
    Err(format!(
        "rule {}: boundary rules need a {} defining [silos]",
        rule.id,
        config::CONFIG_NAME
    ))
}

fn load_coverage(path: Option<&Path>) -> Result<Option<CoverageReport>, String> {
    match path {
        Some(path) => coverage::parse(path).map(Some),
        None => Ok(None),
    }
}

/// Validates the scan root and loads the built-in pack plus every `--rules`
/// directory. Any failure here is exit 2.
fn load_rules(root: &Path, dirs: &[PathBuf], no_default_rules: bool) -> RuleSet {
    require_root(root);

    let mut rules: Vec<CompiledRule> = Vec::new();
    // Sources are recorded in the same order they are loaded; the cache keys
    // entries on their digest, so an unrecorded source is an unnoticed change.
    let mut sources: Vec<(String, String)> = Vec::new();
    if !no_default_rules {
        match rules::load_str(default_pack::default_rules(), "default-pack") {
            Ok(loaded) => {
                rules.extend(loaded);
                sources.push((
                    "default-pack".to_string(),
                    default_pack::default_rules().to_string(),
                ));
            }
            Err(e) => fail(&format!("error: {e}")),
        }
    }

    match rules::load_dirs(dirs) {
        Ok(loaded) => {
            rules.extend(loaded.rules);
            sources.extend(loaded.sources);
        }
        Err(e) => fail(&format!("error: {e}")),
    }

    // The loader rejects duplicates within the pack and across `--rules`
    // directories; the union of the two is only visible here.
    let mut seen: HashMap<&str, ()> = HashMap::new();
    for rule in &rules {
        if seen.insert(rule.id.as_str(), ()).is_some() {
            fail(&format!("error: duplicate rule id: {}", rule.id));
        }
    }

    RuleSet { rules, sources }
}

/// An explicit `--baseline` file must exist; the default location is optional.
fn load_baseline(root: &Path, explicit: Option<&Path>) -> Result<Option<Baseline>, String> {
    let Some(path) = explicit else {
        return baseline::load(root).map_err(|e| format!("error: {e}"));
    };

    let text = fs::read_to_string(path)
        .map_err(|e| format!("error: {}: io error: {e}", path.display()))?;
    let baseline: Baseline = siloscan_core::serde_json::from_str(&text)
        .map_err(|e| format!("error: {}: invalid baseline: {e}", path.display()))?;
    if baseline.version != 1 {
        return Err(format!(
            "error: {}: unsupported baseline version {}",
            path.display(),
            baseline.version
        ));
    }
    Ok(Some(baseline))
}

fn require_root(path: &Path) {
    if let Err(e) = validate_root(path) {
        fail(&format!("error: {}: {}", path.display(), e));
    }
}

/// The walker cannot distinguish "nothing to scan" from "root is missing or
/// unreadable", so the root is checked up front and a bad path is exit 2.
fn validate_root(path: &Path) -> io::Result<()> {
    if fs::metadata(path)?.is_dir() {
        fs::read_dir(path).map(|_| ())
    } else {
        fs::File::open(path).map(|_| ())
    }
}

/// Writes one stdout line, ignoring write errors. `println!` panics on a closed
/// pipe (`siloscan | head`), which would exit 101 and break the 0/1/2 contract.
///
/// Deliberately writes what it is given: JSON and SARIF reports go through here
/// whole. Human text is passed through [`safe`] at the point it is built.
fn emit(out: &mut impl Write, args: std::fmt::Arguments) {
    let _ = writeln!(out, "{args}");
}

/// Individual `warning: skipped` lines before the rest are counted instead.
///
/// One line per skipped file is right for a source tree and wrong for an asset
/// tree: a repository with 50k images buries whatever else stderr had to say
/// under 50k identical warnings. The names of the first few are the useful
/// part - they say which kind of file is being skipped - and a count says the
/// rest.
const MAX_SKIP_WARNINGS: usize = 10;

/// Report the files the scan did not read, bounded.
///
/// `report.skipped` is sorted by path, so the sample is the same on every run
/// of the same tree. The full list is in the JSON and SARIF reports; this is
/// the human channel and is allowed to summarise.
fn warn_skipped(skipped: &[scan::SkippedFile]) {
    for entry in skipped.iter().take(MAX_SKIP_WARNINGS) {
        eprintln!(
            "warning: skipped {}: {}",
            safe(&entry.path),
            safe(&entry.reason)
        );
    }
    if let Some(rest) = skipped
        .len()
        .checked_sub(MAX_SKIP_WARNINGS)
        .filter(|n| *n > 0)
    {
        eprintln!(
            "warning: ... and {rest} more files skipped (see --format json for the full list)"
        );
    }
}

/// Every exit-2 message is human text on stderr, and several of them quote a
/// path or a rule file, so the sanitising happens here once rather than at
/// twenty call sites.
fn fail(message: &str) -> ! {
    eprintln!("{}", safe(message));
    process::exit(2);
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    const BOUNDARY_RULE: &str = "\
version: 1
rules:
  - id: arch.api-db
    severity: error
    message: m
    boundary:
      from: api
      deny: [\"db\"]
";

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Mark `dir` as a repository root the way git does, so `config::discover`
    /// may walk above it.
    fn git_root(dir: &Path) {
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    fn write(dir: &Path, rel: &str, body: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn boundary_rules() -> RuleSet {
        RuleSet {
            rules: rules::load_str(BOUNDARY_RULE, "test").unwrap(),
            ..Default::default()
        }
    }

    /// Every ignore flag maps to exactly the field it names, and no flag turns
    /// on a source the user did not ask for. The last case is the one worth
    /// having: `--no-ignore` widening the walk to files above the scan root
    /// would reintroduce the machine-dependence 1.1.2 removed, and it would do
    /// it under a flag whose name says nothing about parents.
    #[test]
    fn ignore_flags_map_to_the_sources_they_name() {
        let default = IgnoreArgs::default().to_options();
        assert_eq!(default, walk::IgnoreOptions::default());
        assert!(default.respect_gitignore && default.respect_dot_ignore);

        let all = IgnoreArgs {
            no_ignore: true,
            ..IgnoreArgs::default()
        }
        .to_options();
        assert_eq!(all, walk::IgnoreOptions::all_files());
        assert!(!all.respect_parent_ignores);
        assert!(!all.respect_git_exclude);
        assert!(!all.respect_global_gitignore);

        let no_git = IgnoreArgs {
            no_gitignore: true,
            ..IgnoreArgs::default()
        }
        .to_options();
        assert!(!no_git.respect_gitignore);
        assert!(no_git.respect_dot_ignore, "only gitignore was named");

        // The 1.1.1 walk, recovered explicitly: every out-of-root source back
        // on, the in-root ones untouched.
        let legacy = IgnoreArgs {
            respect_parent_ignores: true,
            respect_git_exclude: true,
            respect_global_gitignore: true,
            ..IgnoreArgs::default()
        }
        .to_options();
        assert_eq!(
            legacy,
            walk::IgnoreOptions {
                respect_gitignore: true,
                respect_dot_ignore: true,
                respect_global_gitignore: true,
                respect_parent_ignores: true,
                respect_git_exclude: true,
            }
        );

        // The two settings are about different directories, so combining them
        // is neither a contradiction nor a no-op.
        let both = IgnoreArgs {
            no_ignore: true,
            respect_parent_ignores: true,
            ..IgnoreArgs::default()
        }
        .to_options();
        assert!(!both.respect_gitignore && !both.respect_dot_ignore);
        assert!(both.respect_parent_ignores);
    }

    /// The flags have to survive clap, on both commands that scan, or they are
    /// a struct nobody can reach.
    #[test]
    fn ignore_flags_are_accepted_by_scan_and_baseline() {
        let cli = Cli::try_parse_from(["siloscan", "src", "--no-ignore"]).unwrap();
        assert!(cli.command.is_none());
        assert!(cli.scan.ignore.no_ignore);
        assert_eq!(
            cli.scan.ignore.to_options(),
            walk::IgnoreOptions::all_files()
        );

        let cli =
            Cli::try_parse_from(["siloscan", "baseline", "src", "--respect-git-exclude"]).unwrap();
        let Some(Command::Baseline(args)) = cli.command else {
            panic!("baseline subcommand");
        };
        assert!(args.ignore.to_options().respect_git_exclude);

        // A flag that does not exist is refused rather than ignored.
        assert!(Cli::try_parse_from(["siloscan", "--respect-everything"]).is_err());
    }

    #[test]
    fn cache_prune_is_reachable_and_defaults_to_the_current_directory() {
        let cli = Cli::try_parse_from(["siloscan", "cache", "prune"]).unwrap();
        let Some(Command::Cache(CacheCommand::Prune(args))) = cli.command else {
            panic!("cache prune subcommand");
        };
        assert_eq!(args.path, PathBuf::from("."));

        // Pruning a tree with no cache at all is a no-op, not a failure: there
        // is nothing to report and nothing to remove.
        let dir = tempdir();
        run_cache_prune(CacheArgs {
            path: dir.path().to_path_buf(),
        });
        assert!(!dir.path().join(".siloscan").exists());
    }

    #[test]
    fn config_is_discovered_from_the_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        git_root(dir.path());
        write(
            dir.path(),
            "siloscan.toml",
            "rules = [\"rules/local\"]\n\n[silos]\napi = [\"src/api/**\"]\n",
        );

        let (config, dirs) = load_config(&dir.path().join("src"), None).expect("should load");

        assert!(config.expect("config").silos.contains_key("api"));
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].ends_with("rules/local"));
    }

    #[test]
    fn config_rule_dirs_resolve_against_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "cfg/siloscan.toml", "rules = [\"extra\"]\n");

        let (_, dirs) =
            load_config(dir.path(), Some(&dir.path().join("cfg/siloscan.toml"))).unwrap();

        assert_eq!(dirs, vec![dir.path().join("cfg/extra")]);
    }

    #[test]
    fn a_missing_or_invalid_config_override_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_config(dir.path(), Some(&dir.path().join("absent.toml"))).is_err());

        write(dir.path(), "bad.toml", "nonsense = true\n");
        assert!(load_config(dir.path(), Some(&dir.path().join("bad.toml"))).is_err());
    }

    #[test]
    fn no_config_anywhere_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        git_root(dir.path());
        assert_eq!(load_config(dir.path(), None).unwrap(), (None, Vec::new()));
    }

    /// A repository whose root config anchors on itself and includes a module
    /// config that sits in the module directory - the shape that makes
    /// `siloscan modules/api` and `siloscan .` interchangeable.
    fn multimodule_repo(root: &Path) {
        git_root(root);
        write(
            root,
            "siloscan.toml",
            "anchor = \"config\"\ninclude = [\"modules/api/siloscan.toml\"]\n\n[silos]\ncore = [\"crates/core/**\"]\n",
        );
        write(
            root,
            "modules/api/siloscan.toml",
            "[silos]\napi = [\"src/**\"]\n",
        );
    }

    #[test]
    fn a_module_scan_loads_the_root_config_that_includes_the_module() {
        let dir = tempdir();
        multimodule_repo(dir.path());

        let (config, _) = load_config(&dir.path().join("modules/api"), None).expect("should load");
        let config = config.expect("config");

        // The module's own file is an included one; adopting it as the root
        // config would drop all three of these silently.
        assert_eq!(config.anchor, Anchor::Config);
        assert!(same_file(config.config_root(), dir.path()));
        assert_eq!(config.silos.keys().collect::<Vec<_>>(), vec!["api", "core"]);
        // The included silo is rebased onto the config root, which is what makes
        // it match the paths a module scan reports.
        assert_eq!(config.silos["api"], vec!["modules/api/src/**"]);
    }

    #[test]
    fn a_module_config_nobody_includes_stays_the_root_config() {
        let dir = tempdir();
        git_root(dir.path());
        write(dir.path(), "siloscan.toml", "anchor = \"config\"\n");
        write(
            dir.path(),
            "modules/api/siloscan.toml",
            "[silos]\napi = [\"src/**\"]\n",
        );

        let (config, _) = load_config(&dir.path().join("modules/api"), None).expect("should load");
        let config = config.expect("config");

        assert_eq!(config.anchor, Anchor::ScanRoot);
        assert!(same_file(
            config.config_root(),
            &dir.path().join("modules/api")
        ));
    }

    #[test]
    fn nothing_above_the_repository_root_is_consulted() {
        let dir = tempdir();
        let repo = dir.path().join("repo");
        multimodule_repo(&repo);
        // Unreadable as a config, and outside the repository: reaching it at all
        // would turn every module scan into an error.
        write(dir.path(), "siloscan.toml", "nonsense = true\n");

        assert!(load_config(&repo.join("modules/api"), None).is_ok());
    }

    #[test]
    fn the_default_baseline_follows_the_anchor() {
        let dir = tempdir();
        multimodule_repo(dir.path());
        let module = dir.path().join("modules/api");

        let (anchored, _) = load_config(&module, None).unwrap();
        assert!(same_file(
            &baseline_root(&module, anchored.as_ref()),
            dir.path()
        ));

        // Without the key the baseline is where it has always been.
        assert_eq!(baseline_root(&module, None), module);
        let plain = Config::default();
        assert_eq!(baseline_root(&module, Some(&plain)), module);
    }

    #[test]
    fn a_file_scan_root_keeps_its_state_beside_the_file() {
        let dir = tempdir();
        write(dir.path(), "app.js", "const a = 1;\n");
        let file = dir.path().join("app.js");

        // Never below the file itself: `app.js/.siloscan/baseline.json` is not
        // a path any file system will open.
        assert_eq!(state_root(&file), dir.path());
        assert_eq!(baseline_root(&file, None), dir.path());
        assert_eq!(state_root(dir.path()), dir.path());

        // A bare filename has no parent directory to name, so it is the
        // current one rather than the empty path.
        assert_eq!(state_root(Path::new("app.js")), PathBuf::from("."));
    }

    #[test]
    fn a_file_scan_root_still_opens_a_cache() {
        let dir = tempdir();
        write(dir.path(), "app.js", "const a = 1;\n");
        let anchoring = scan::Anchoring::default();

        let cache = open_cache(
            &dir.path().join("app.js"),
            &RuleSet::default(),
            false,
            &anchoring,
        )
        .expect("a file root caches beside the file");
        assert_eq!(cache.root(), dir.path().join(".siloscan/cache"));

        assert!(
            open_cache(
                &dir.path().join("app.js"),
                &RuleSet::default(),
                true,
                &anchoring
            )
            .is_none()
        );
    }

    #[test]
    fn command_line_rule_dirs_come_before_the_config_ones() {
        let dirs = rule_dirs(&[PathBuf::from("a")], vec![PathBuf::from("b")]);
        assert_eq!(dirs, vec![PathBuf::from("a"), PathBuf::from("b")]);
    }

    #[test]
    fn a_boundary_rule_without_silos_is_rejected() {
        let rules = boundary_rules();

        let err = require_silos(&rules, None).unwrap_err();
        assert!(err.contains("arch.api-db"), "{err}");
        assert!(err.contains(config::CONFIG_NAME), "{err}");
        // A config with no silos is the same mistake.
        assert!(require_silos(&rules, Some(&Config::default())).is_err());

        let config = Config {
            silos: std::collections::BTreeMap::from([(
                "api".to_string(),
                vec!["src/api/**".to_string()],
            )]),
            ..Config::default()
        };
        assert!(require_silos(&rules, Some(&config)).is_ok());
        // No boundary rule, no requirement.
        assert!(require_silos(&RuleSet::default(), None).is_ok());
    }

    #[test]
    fn safe_text_is_returned_untouched_and_unallocated() {
        let text = "src/api/handler.js:1:15 error arch.api-db api must not import db";
        assert!(matches!(safe(text), Cow::Borrowed(_)));
        assert_eq!(safe(text), text);
        // Non-ASCII is not control text and must survive intact.
        assert_eq!(
            safe("src/\u{e9}t\u{e9}/caf\u{e9}.rs"),
            "src/\u{e9}t\u{e9}/caf\u{e9}.rs"
        );
    }

    #[test]
    fn every_control_class_is_rendered_visibly() {
        // The line-erasing sequence, the two vectors it arrives by.
        assert_eq!(safe("evil\u{1b}[2K\rok.js"), "evil\\x1b[2K\\x0dok.js");
        // NUL, tab and newline: tab included on purpose, it moves the cursor
        // between columns of a report line.
        assert_eq!(safe("a\u{0}b\tc\nd"), "a\\x00b\\x09c\\x0ad");
        // DEL and the C1 block, which carry their own CSI.
        assert_eq!(safe("a\u{7f}b\u{9b}2Kc\u{80}"), "a\\x7fb\\x9b2Kc\\x80");
    }

    #[test]
    fn no_control_byte_survives_any_scanned_text() {
        let text: String = (0u32..=0x9f)
            .filter_map(char::from_u32)
            .chain("plain text".chars())
            .collect();

        let rendered = safe(&text);

        // The predicate is restated rather than imported: this is the CLI's own
        // guarantee about what it prints, and it should fail here if core ever
        // narrows what it escapes.
        assert!(
            !rendered
                .chars()
                .any(|ch| matches!(ch, '\u{00}'..='\u{1f}' | '\u{7f}'..='\u{9f}')),
            "{rendered:?}"
        );
        assert!(rendered.contains("plain text"));
    }

    #[test]
    fn coverage_report_is_parsed_or_reported() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_coverage(None).unwrap(), None);

        write(
            dir.path(),
            "lcov.info",
            "SF:src/a.rs\nDA:1,0\nend_of_record\n",
        );
        let report = load_coverage(Some(&dir.path().join("lcov.info")))
            .unwrap()
            .expect("report");
        assert_eq!(report.files.len(), 1);

        write(dir.path(), "junk.txt", "coverage: 42%\n");
        assert!(load_coverage(Some(&dir.path().join("junk.txt"))).is_err());
        assert!(load_coverage(Some(&dir.path().join("absent.info"))).is_err());
    }
}
