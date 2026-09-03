mod saved_report;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

use clap::error::ErrorKind;
use clap::parser::ValueSource;
use clap::{ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use saved_report::CanonicalScope;
use siloscan_core::baseline;
use siloscan_core::cache::{Cache, PathScope};
use siloscan_core::config::{self, Anchor, Config};
use siloscan_core::coverage::{self, CoverageReport};
// Renders scanned text so a terminal displays it instead of obeying it. The
// TUI draws its spans through the same function, so the two front ends cannot
// drift apart; see the core definition for what is escaped and why.
use siloscan_core::findings::sanitize_for_terminal as safe;
use siloscan_core::harness;
use siloscan_core::plan::{
    CapabilityStatus, OutcomeMetadata, ResolvedScanPlan, ScanRequest, ScanSetupReport,
    ScopeMetadata, write_resolved_json,
};
use siloscan_core::rules::{self, CompiledPayload, CompiledRule, RuleSet, Severity};
use siloscan_core::scan::{self, Anchoring};
use siloscan_core::walk;
use siloscan_core::{cache, default_pack, output, output_sarif};
use siloscan_tui::ReviewSession;

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
        A scan that cannot be evaluated exits 2 rather than 0, because an empty \
        report is indistinguishable from a clean tree: loading no rules at all, \
        or loading a gate whose input is missing (a coverage rule with no \
        --coverage-report, a boundary rule with no [silos]), is refused and \
        names what was missing. Human output escapes control characters as \
        \\xNN and Unicode bidi controls as \\u{XXXX}.\n\n\
        Duplication is always measured and always reported in the metrics line \
        and in the JSON and SARIF metrics, but the per-copy \
        metrics.duplicate-block findings are off by default: on a real tree \
        they outnumber every other finding and bury it. They are emitted when a \
        duplication rule is loaded, or when siloscan.toml sets \
        [duplication] report_blocks = true.\n\n\
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

    #[command(flatten)]
    save: SaveArgs,
}

/// A scan with no subcommand, for the one case where `review` is a path rather
/// than a command.
///
/// It flattens the same two argument types the top-level parser does, so the
/// collision path accepts exactly the invocations a scan accepts and there is no
/// second list of scan flags to keep in step.
#[derive(Parser)]
struct ScanOnly {
    #[command(flatten)]
    scan: ScanArgs,

    #[command(flatten)]
    save: SaveArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Record every current finding as accepted, so later scans report only new ones
    Baseline(BaselineArgs),

    /// Open a saved report, or a live scan session, in the terminal UI
    Review(ReviewArgs),

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
    /// Scan root whose cache entries are pruned
    ///
    /// The path names the tree, not the cache: entries are keyed by scan root,
    /// so this says whose cache to sweep, and the cache itself is found the way
    /// a scan of that root would find it.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Prune under DIR instead of this user's cache directory; use the same
    /// value the scans being pruned were run with
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,
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

    /// Do not load the built-in rule pack (a run that ends up with no rules at
    /// all checks nothing and is refused with exit 2)
    #[arg(long)]
    no_default_rules: bool,

    /// Output format
    #[arg(long, value_enum, default_value = "human")]
    format: Format,

    /// Exit with code 1 if any finding meets this severity or higher
    #[arg(long, value_enum, default_value = "error")]
    fail_on: SeverityArg,

    /// Report only findings of this severity or higher
    ///
    /// This narrows the report and nothing else. The exit code is decided by
    /// --fail-on over everything the scan found, so filtering the output can
    /// neither turn a failing run green nor turn a green one red, and it moves
    /// no fingerprint. It applies to every format and to all three lists a
    /// report carries - findings, baselined and suppressed - so human, JSON and
    /// SARIF output show the same set.
    #[arg(long, value_enum, default_value = "info")]
    min_severity: SeverityArg,

    /// Baseline file (defaults to `.siloscan/baseline.json` under PATH, or under the
    /// config root when the config sets `anchor = "config"`)
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Repository config (defaults to the nearest `siloscan.toml` at PATH, or
    /// above it only when a `.git` marker exists at or above PATH; pass this
    /// explicitly for an exported tree that has none)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Coverage report to feed coverage rules (lcov or cobertura); required
    /// when any coverage rule is loaded, since a gate with no input reports
    /// nothing and would read as a pass
    #[arg(long, value_name = "FILE")]
    coverage_report: Option<PathBuf>,

    /// Follow symlinks whose target is inside the scan root; targets outside it
    /// are never followed
    ///
    /// Off, a link is reported as a path nothing was read through, and its
    /// target is still scanned on its own path. On, an in-root target is read
    /// through the link as well, so a file behind one is reported twice, under
    /// both paths. A link out of the scan root is refused either way: a scan
    /// that reads files above its own root is a scan of the machine it ran on.
    #[arg(long)]
    follow_symlinks: bool,

    /// Do not read or write the scan cache
    #[arg(long)]
    no_cache: bool,

    /// Read and write cache entries under DIR instead of this user's cache
    /// directory
    ///
    /// The default is `$XDG_CACHE_HOME/siloscan` (`$HOME/.cache/siloscan` when
    /// unset) on unix and `%LOCALAPPDATA%\siloscan` on Windows. Nothing about
    /// the scanned tree takes part in choosing it, which is why a tree cannot
    /// move its own cache; this flag is the user overriding that, not the tree.
    ///
    /// Pointing it inside the scan root works but is a poor idea: the entries
    /// become files the walk then sees, so a cold and a warm run count
    /// different numbers of files.
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,

    #[command(flatten)]
    ignore: IgnoreArgs,
}

/// Where this scan's report is written, if anywhere.
///
/// Kept out of [`ScanArgs`] on purpose. That type is exactly the v1 scan
/// grammar, and "did the user supply a v1 scan option" is the question that
/// decides whether an invocation is automatic; a persistence flag must not
/// answer it, or `siloscan --no-save` would stop being the bare command.
///
/// The three are pairwise exclusive, so one scan writes at most one report and
/// the conflict is a parse failure rather than a precedence rule nobody can
/// remember.
#[derive(Args, Default)]
struct SaveArgs {
    /// Save this scan's report to the requested scope's saved-report slot
    ///
    /// This is what a bare `siloscan` does by default; naming it opts an
    /// explicit scan in as well. The saved document is always canonical
    /// siloscan JSON, whatever `--format` prints.
    #[arg(long, conflicts_with_all = ["no_save", "output"])]
    save: bool,

    /// Save no report, including the one a bare invocation would save
    #[arg(long, conflicts_with_all = ["save", "output"])]
    no_save: bool,

    /// Write this scan's canonical JSON report to FILE instead of the saved
    /// slot, leaving the saved report as it was
    ///
    /// The parent directory must already exist. `-` is not accepted: machine
    /// stdout is what `--format json` and `--format sarif` are for.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["save", "no_save"])]
    output: Option<PathBuf>,
}

/// What `review` opens.
#[derive(Args)]
struct ReviewArgs {
    /// Scan scope whose saved report is opened
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Open this report file instead of the scope's saved report
    ///
    /// The file is opened exactly as given, with no scope lookup, so a report
    /// copied off the machine that produced it stays reviewable.
    #[arg(long, value_name = "FILE", conflicts_with = "live")]
    report: Option<PathBuf>,

    /// Scan PATH now and review the result, instead of opening a saved report
    #[arg(long)]
    live: bool,

    /// Repository config (defaults to the nearest `siloscan.toml`)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Args)]
struct BaselineArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Rule directories
    #[arg(long, value_name = "DIR")]
    rules: Vec<PathBuf>,

    /// Do not load the built-in rule pack (a run that ends up with no rules at
    /// all checks nothing and is refused with exit 2)
    #[arg(long)]
    no_default_rules: bool,

    /// Repository config (defaults to the nearest `siloscan.toml` at PATH, or
    /// above it only when a `.git` marker exists at or above PATH; pass this
    /// explicitly for an exported tree that has none)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Coverage report to feed coverage rules (lcov or cobertura); required
    /// when any coverage rule is loaded, since a gate with no input reports
    /// nothing and would read as a pass
    #[arg(long, value_name = "FILE")]
    coverage_report: Option<PathBuf>,

    /// Follow symlinks whose target is inside the scan root; targets outside it
    /// are never followed
    ///
    /// A baseline records what a scan found, so this has to be available here
    /// and has to mean the same thing: a baseline taken with it off does not
    /// cover the findings a scan with it on will report.
    #[arg(long)]
    follow_symlinks: bool,

    /// Do not read or write the scan cache
    #[arg(long)]
    no_cache: bool,

    /// Read and write cache entries under DIR instead of this user's cache
    /// directory
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,

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

    /// Do not load the built-in rule pack (a run that ends up with no rules at
    /// all checks nothing and is refused with exit 2)
    #[arg(long)]
    no_default_rules: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
}

/// A severity named on the command line. One type for `--fail-on` and
/// `--min-severity`, so the two flags accept the same three words and cannot
/// drift into spelling them differently; what each one does with the value is
/// where they differ, and only there.
#[derive(Clone, Copy, clap::ValueEnum)]
enum SeverityArg {
    Info,
    Warning,
    Error,
}

impl SeverityArg {
    fn to_severity(self) -> Severity {
        match self {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Warning => Severity::Warning,
            SeverityArg::Error => Severity::Error,
        }
    }
}

fn main() {
    let (cli, matches) = parse_cli();

    match cli.command {
        None => run_scan(cli.scan, cli.save, Provenance::of(&matches)),
        Some(Command::Baseline(args)) => run_baseline(args),
        Some(Command::Review(args)) => run_review(args),
        Some(Command::Test(args)) => run_test(args),
        Some(Command::Cache(CacheCommand::Prune(args))) => run_cache_prune(args),
    }
}

/// Which scan arguments this invocation actually supplied.
///
/// The distinction the whole automatic mode rests on: an omitted `PATH` and an
/// explicit `.` name the same directory and are different invocations, and so
/// are an omitted `--cache-dir` and one pointing at the default location. Only
/// clap knows which is which, so the answer comes from
/// [`ValueSource::CommandLine`] rather than from comparing values to defaults.
struct Provenance {
    supplied: Vec<clap::Id>,
}

impl Provenance {
    fn of(matches: &ArgMatches) -> Self {
        let supplied = arg_ids::<ScanArgs>()
            .into_iter()
            .filter(|id| matches.value_source(id.as_str()) == Some(ValueSource::CommandLine))
            .collect();
        Self { supplied }
    }

    fn has(&self, id: &str) -> bool {
        self.supplied.iter().any(|supplied| supplied == id)
    }

    /// True when any argument of `A` was supplied. `A` is always a subset of
    /// [`ScanArgs`], which is what makes this a question about the derived
    /// argument type rather than about a list kept here by hand.
    fn any<A: Args>(&self) -> bool {
        arg_ids::<A>().iter().any(|id| self.has(id.as_str()))
    }

    /// Automatic mode: no `PATH` and no v1 scan option. The persistence flags
    /// live outside [`ScanArgs`], so adding one does not leave automatic mode.
    fn is_automatic(&self) -> bool {
        self.supplied.is_empty()
    }
}

/// Every argument id a derived argument type declares.
///
/// Taken from the type itself, so an option added to [`ScanArgs`] counts as a
/// v1 scan option without anyone remembering to record it somewhere else.
fn arg_ids<A: Args>() -> Vec<clap::Id> {
    A::augment_args(clap::Command::new("probe"))
        .get_arguments()
        .map(|arg| arg.get_id().clone())
        .filter(|id| id != "help" && id != "version")
        .collect()
}

/// Drop cache entries left behind by other siloscan builds.
///
/// A scan already prunes the directory it is about to use, so this exists for
/// the case where no scan is coming: an upgrade in CI, or a scan root whose
/// cache outlived the build that wrote it. Pruning is best-effort by design -
/// an entry that cannot be read or removed is left alone - so there is nothing
/// here to fail on and the exit code is 0 unless the path itself is unusable.
///
/// The path names the scan root, not the cache. Entries are keyed by scan root,
/// so the root is what identifies the directory to sweep; `--cache-dir` says
/// where to look for it, and must match what the scans being pruned used.
///
/// The count is printed because 0 and 400 are both successes and the user asked
/// which one it was; a command that says nothing is indistinguishable from one
/// that silently did not run.
fn run_cache_prune(args: CacheArgs) {
    require_root(&args.path);
    let root = state_root(&args.path);
    let removed = match args.cache_dir.as_deref() {
        Some(dir) => cache::prune_in(dir, &root),
        None => cache::prune(&root),
    };
    let mut out = io::stdout().lock();
    emit(
        &mut out,
        format_args!(
            "pruned {}",
            quantity(removed, "cache entry", "cache entries")
        ),
    );
    let _ = out.flush();
}

/// Parses the command line, and turns the one conflict this CLI declares into a
/// message naming the form that works.
///
/// A top-level path alongside a subcommand is rejected rather than forwarded to
/// the subcommand: forwarding would have to decide which of two positionals the
/// user meant when both are given, and guessing that is exactly what wrote a
/// baseline over the wrong tree. Refusing cannot pick the wrong one.
fn parse_cli() -> (Cli, ArgMatches) {
    let argv: Vec<OsString> = std::env::args_os().collect();
    if let Some(scan) = review_is_a_path(&argv) {
        return scan;
    }

    match Cli::command().try_get_matches_from(argv.clone()) {
        Ok(matches) => {
            let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
            (cli, matches)
        }
        Err(e) if e.kind() == ErrorKind::ArgumentConflict && names_subcommand(&argv) => {
            let _ = e.print();
            // The binary name rather than a literal, because this file is
            // also compiled as the `ss` alias.
            let bin = env!("CARGO_BIN_NAME");
            // Not "a subcommand takes its own path": that describes only the
            // `PATH baseline` order. `--format json baseline PATH` reaches here
            // too, and there the path is not the problem - the scan option in
            // front of the subcommand is. Clap has already named the arguments
            // it refused, so this says what the rule is and what the shape is.
            emit_err(format_args!(
                "\nA subcommand comes first and carries its own path and flags:\n\
                 \x20 {bin} baseline <PATH>\n\
                 \x20 {bin} test <PATH>\n\
                 \x20 {bin} cache prune <PATH>\n\
                 Scan options and the top-level PATH belong to a scan and cannot \
                 precede a subcommand.\n\
                 Run `{bin} <COMMAND> --help` for what each subcommand accepts."
            ));
            process::exit(2);
        }
        // Help, version, the persistence conflicts and every other parse
        // failure keep clap's own reporting and its exit codes.
        Err(e) => e.exit(),
    }
}

/// True when one of this binary's subcommand names appears in `argv`.
///
/// The advice above is about a subcommand that came after a scan option, so it
/// only belongs on a conflict that involves one. `--save --no-save` is also an
/// argument conflict and has nothing to do with subcommands; clap's own message
/// already says everything there is to say about it.
fn names_subcommand(argv: &[OsString]) -> bool {
    let names: Vec<String> = Cli::command()
        .get_subcommands()
        .map(|command| command.get_name().to_string())
        .collect();
    argv.iter()
        .skip(1)
        .any(|arg| names.iter().any(|name| arg == name.as_str()))
}

/// The `./review` collision: a repository that really has a `review` directory.
///
/// `review` was a path long before it was a subcommand, so a scan of one keeps
/// working. The test is deliberately narrow - the first argument is literally
/// `review`, a file or directory by that name exists, and the whole command line
/// parses as a scan - because anything looser would swallow `review --report x`,
/// where the user plainly meant the subcommand.
///
/// The scan grammar is [`ScanOnly`], the same flattened argument types the
/// top-level parser uses, so this cannot drift out of step with what a scan
/// accepts.
fn review_is_a_path(argv: &[OsString]) -> Option<(Cli, ArgMatches)> {
    if argv.get(1)? != "review" {
        return None;
    }
    if !Path::new("review").exists() {
        return None;
    }

    let matches = ScanOnly::command().try_get_matches_from(argv).ok()?;
    let scan = ScanOnly::from_arg_matches(&matches).ok()?;
    Some((
        Cli {
            command: None,
            scan: scan.scan,
            save: scan.save,
        },
        matches,
    ))
}

/// Where this scan's report goes, decided before the scan runs.
enum Destination {
    /// Nothing is written. Every explicit v1 invocation lands here, and so does
    /// a bare one with `--no-save`.
    None,
    /// The requested scope's saved-report slot, already created.
    Saved(PathBuf),
    /// The file `--output` named.
    Named(PathBuf),
}

impl Destination {
    fn path(&self) -> Option<&Path> {
        match self {
            Destination::None => None,
            Destination::Saved(path) | Destination::Named(path) => Some(path),
        }
    }

    /// Automatic state is siloscan's own file and is written through a private
    /// temporary; a file the user named takes their umask like anything else
    /// they asked a tool to write.
    fn temp_mode(&self) -> saved_report::TempMode {
        match self {
            Destination::Named(_) => saved_report::TempMode::Umask,
            _ => saved_report::TempMode::Private,
        }
    }
}

fn run_scan(args: ScanArgs, save: SaveArgs, provenance: Provenance) {
    let automatic = provenance.is_automatic();

    // Everything cheap and deterministic happens before the expensive part: a
    // state root that does not exist, a scope that cannot be canonicalised or an
    // `--output` parent that is missing costs the user a scan otherwise, and the
    // answer would have been the same either way.
    let (destination, scope) = preflight_destination(&args, &save, automatic);

    let request = scan_request(&args, automatic, &provenance);
    let plan = ResolvedScanPlan::resolve(&request).unwrap_or_else(|e| fail(&format!("error: {e}")));
    let resolved = plan
        .execute(&mut |_| {})
        .unwrap_or_else(|e| fail(&format!("error: {e}")));
    let (mut report, setup, context) = resolved.into_parts();

    warn_skipped(&report.skipped);
    warn_scan(&report.warnings);

    // The exit code is decided over everything the scan found, before
    // --min-severity narrows what gets printed. The two flags govern different
    // things and must stay that way: a filter that could turn a failing run
    // green would be a way for a repository to pass a gate by hiding from it.
    let failing = args.fail_on.to_severity();
    let failed = report.findings.iter().any(|f| f.severity >= failing);

    // Applied to the report itself rather than at each format's call site, so
    // the human, JSON and SARIF paths below cannot disagree about what was
    // reported. Whole findings are dropped and none is rewritten, so every
    // fingerprint that survives is the one the scan produced.
    let min_severity = args.min_severity.to_severity();
    let reported_before = report.findings.len() + report.baselined.len() + report.suppressed.len();
    report.findings.retain(|f| f.severity >= min_severity);
    report.baselined.retain(|f| f.severity >= min_severity);
    report.suppressed.retain(|f| f.severity >= min_severity);
    // Counted over all three lists, because the human listing speaks for all
    // three: it prints the new findings and the counts of the other two, and a
    // threshold that removed baselined entries shrinks that line just as
    // silently as it shortens the listing.
    let withheld = reported_before
        - (report.findings.len() + report.baselined.len() + report.suppressed.len());

    let filtered_at = filtered_at(min_severity);
    let anchoring = context.anchoring();
    // Recorded before the output filter, so a review can tell a clean scan from
    // a failing one whose findings the threshold hid.
    let outcome = OutcomeMetadata::new(failing, failed);
    let scope_metadata = scope.as_ref().map(|scope| {
        ScopeMetadata::new(scope.identity(), scope.kind(), ancestor_levels(anchoring))
    });

    let mut out = io::stdout().lock();
    // JSON stdout and the saved file are one document, so it is serialized once
    // and the bytes are handed to both. Human and SARIF stdout are a different
    // document, and their saved report is streamed straight into the temporary
    // file below rather than built here.
    let mut serialized: Option<Vec<u8>> = None;
    match args.format {
        Format::Human => {
            // Only a bare invocation may add lines. An explicit scan's human
            // output is byte for byte what v1.5.1 printed.
            if automatic {
                for line in setup_lines(&setup) {
                    emit(&mut out, format_args!("{}", safe(&line)));
                }
            }
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
                        "{} ({} baselined, {} suppressed)",
                        quantity(report.findings.len(), "finding", "findings"),
                        report.baselined.len(),
                        report.suppressed.len()
                    ),
                );
            }
            // Where the scan did not look, said out loud. A tree whose only
            // credential sits behind a `.gitignore` line prints "0 findings"
            // either way; this is the line that stops that reading as "clean".
            // Scanner-generated wording and two integers - no scanned text - so
            // it needs no `safe()`.
            if let Some(line) = report.ignored.summary_line() {
                emit(&mut out, format_args!("{line}"));
            }
            // The same statement, for the third source of a short listing: what
            // the scan found and the threshold refused to print. Without it a
            // fully filtered report is byte for byte a clean one, which is the
            // reading `--min-severity` is otherwise indistinguishable from.
            // Scanner-generated wording, a count and a severity word - no
            // scanned text - so it needs no `safe()`.
            if let Some(threshold) = filtered_at
                && let Some(line) = withheld_line(withheld, threshold)
            {
                emit(&mut out, format_args!("{line}"));
            }
            emit(
                &mut out,
                format_args!("{}", output::human_metrics_summary(&report.metrics)),
            );
        }
        Format::Json => {
            let scope = scope_metadata
                .as_ref()
                .expect("a JSON report always resolves its scope");
            let mut buffer: Vec<u8> = Vec::new();
            if let Err(e) = write_resolved_json(
                &mut buffer,
                &report,
                &setup,
                &context,
                scope,
                &outcome,
                filtered_at,
            ) {
                fail(&format!("error: {e}"));
            }
            let _ = out.write_all(&buffer);
            let _ = out.write_all(b"\n");
            serialized = Some(buffer);
        }
        Format::Sarif => emit(
            &mut out,
            format_args!(
                "{}",
                output_sarif::to_sarif(&report, context.rules(), anchoring.anchor(), filtered_at)
            ),
        ),
    }
    let _ = out.flush();

    // The scan result is already on stdout, so a publication failure below costs
    // the user an exit code and not their report.
    if let Some(path) = destination.path() {
        let scope = scope_metadata
            .as_ref()
            .expect("a saved report always resolves its scope");
        let mode = destination.temp_mode();
        let published = match &serialized {
            Some(bytes) => {
                saved_report::write_report_atomic(path, mode, |writer| writer.write_all(bytes))
            }
            None => saved_report::write_report_atomic(path, mode, |writer| {
                write_resolved_json(
                    writer,
                    &report,
                    &setup,
                    &context,
                    scope,
                    &outcome,
                    filtered_at,
                )
                .map_err(io::Error::other)
            }),
        };

        match published {
            // Printed only now: a path announced before publication succeeded
            // would be a report that is not there.
            Ok(()) => announce_saved(&args, &destination, path),
            Err(e) => {
                emit_err(format_args!("{}", safe(&format!("error: {e}"))));
                // Ahead of a finding status, because the command did not finish
                // what it was asked to do.
                process::exit(2);
            }
        }
    }

    if failed {
        process::exit(1);
    }
}

/// Resolve and prepare this scan's destination, and the scope identity a saved
/// or JSON report records.
///
/// Bare invocations save unless told not to; explicit ones save only when asked.
/// A human or SARIF scan that saves nothing never resolves an identity at all,
/// which is what keeps the unchanged v1 path free of persistence work.
fn preflight_destination(
    args: &ScanArgs,
    save: &SaveArgs,
    automatic: bool,
) -> (Destination, Option<CanonicalScope>) {
    let wants_save = match automatic {
        true => !save.no_save,
        false => save.save || save.output.is_some(),
    };
    let needs_scope = wants_save || matches!(args.format, Format::Json);

    let scope = match needs_scope {
        false => None,
        true => Some(
            saved_report::canonical_scope(&args.path)
                .unwrap_or_else(|e| fail(&format!("error: {e}"))),
        ),
    };

    if !wants_save {
        return (Destination::None, scope);
    }

    if let Some(output) = &save.output {
        return (Destination::Named(named_destination(output)), scope);
    }

    let root = saved_report::state_root().unwrap_or_else(|e| fail(&format!("error: {e}")));
    let scope_ref = scope.as_ref().expect("a saved report resolves its scope");
    let path = saved_report::automatic_report_path(&root, scope_ref)
        .unwrap_or_else(|e| fail(&format!("error: {e}")));
    (Destination::Saved(path), scope)
}

/// The file `--output` named, checked but not created.
///
/// The parent has to exist already: the user chose this location, so siloscan
/// does not build directory trees on their behalf, and the temporary file has to
/// sit in that same directory for the replacement to stay on one file system.
fn named_destination(output: &Path) -> PathBuf {
    if output == Path::new("-") {
        fail(
            "error: --output does not accept -; use --format json or --format sarif for machine \
             stdout",
        );
    }
    let parent = match output.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    };
    if !parent.is_dir() {
        fail(&format!(
            "error: {}: the directory for --output does not exist",
            parent.display()
        ));
    }
    output.to_path_buf()
}

/// How many directories above the scope's own the report's paths are measured
/// from.
///
/// The anchoring prefix is the descent from the anchor directory down to the
/// measured one, so its component count is exactly the climb a review has to
/// make back up. Zero for every scan-root-anchored run, which is most of them.
fn ancestor_levels(anchoring: &Anchoring) -> u32 {
    anchoring
        .prefix()
        .split('/')
        .filter(|component| !component.is_empty())
        .count() as u32
}

/// Say where the report went, and how to open it.
///
/// Human output puts both lines on stdout, where the rest of the report is.
/// JSON and SARIF put them on stderr, because their stdout is one document a
/// consumer parses and a trailing English line would break it.
fn announce_saved(args: &ScanArgs, destination: &Destination, path: &Path) {
    let bin = env!("CARGO_BIN_NAME");
    let report = format!("Report: {}", path.display());
    let review = match destination {
        // `--output` did not touch the saved slot, so pointing at it would open
        // a different report than the one just written.
        Destination::Named(path) => {
            format!("Review: {bin} review --report {}", path.display())
        }
        _ => match args.path == Path::new(".") {
            true => format!("Review: {bin} review"),
            false => format!("Review: {bin} review {}", args.path.display()),
        },
    };

    match args.format {
        Format::Human => {
            let mut out = io::stdout().lock();
            emit(&mut out, format_args!("{}", safe(&report)));
            emit(&mut out, format_args!("{}", safe(&review)));
            let _ = out.flush();
        }
        Format::Json | Format::Sarif => {
            emit_err(format_args!("{}", safe(&report)));
            emit_err(format_args!("{}", safe(&review)));
        }
    }
}

/// What a bare invocation says about the setup it resolved, before the findings.
///
/// Two lines, both derived from the setup report and both deterministic for a
/// given tree: what was detected, and which optional parts of the scan actually
/// ran. The second matters more than it looks - a coverage gate that never ran
/// and one that passed print the same findings.
fn setup_lines(setup: &ScanSetupReport) -> Vec<String> {
    let units = match setup.units.len() {
        0 => "no project units".to_string(),
        count => quantity(count, "project unit", "project units"),
    };
    let languages = match setup.languages.is_empty() {
        true => "none".to_string(),
        false => setup.languages.join(", "),
    };
    let rules = match setup.rule_sources.is_empty() {
        true => "none".to_string(),
        false => setup
            .rule_sources
            .iter()
            .map(|source| source.id.clone())
            .collect::<Vec<String>>()
            .join(", "),
    };
    let capabilities = setup
        .capabilities
        .iter()
        .map(|capability| {
            format!(
                "{} {}",
                capability.id(),
                capability_status(capability.status())
            )
        })
        .collect::<Vec<String>>()
        .join("; ");

    vec![
        format!("setup: {units}; languages: {languages}; rules: {rules}"),
        format!("capabilities: {capabilities}"),
    ]
}

/// One word per capability state. `CapabilityStatus` is `#[non_exhaustive]`, so
/// a state added later prints as unknown rather than failing to compile a
/// binary that has nothing to say about it yet.
fn capability_status(status: &CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Enabled => "enabled",
        CapabilityStatus::Skipped => "skipped",
        CapabilityStatus::Unavailable => "unavailable",
        CapabilityStatus::NotConfigured => "not configured",
        _ => "unknown",
    }
}

/// The command line as a core scan request, with its provenance intact.
///
/// Each option is passed on only when it was actually supplied, so the setup
/// report can say "the default applied" rather than "the default was asked
/// for" - a `--cache-dir` pointing at the default location is still a supplied
/// option, and a stage that treated it as absent would be describing a
/// different invocation.
fn scan_request(args: &ScanArgs, automatic: bool, provenance: &Provenance) -> ScanRequest {
    let mut request = match automatic {
        true => ScanRequest::automatic(),
        false => ScanRequest::explicit(args.path.clone()),
    };
    if let Some(config) = &args.config {
        request = request.with_config(config.clone());
    }
    if provenance.has("rules") {
        request = request.with_rule_dirs(args.rules.clone());
    }
    if args.no_default_rules {
        request = request.without_embedded_rules();
    }
    if let Some(baseline) = &args.baseline {
        request = request.with_baseline(baseline.clone());
    }
    if let Some(coverage) = &args.coverage_report {
        request = request.with_coverage(coverage.clone());
    }
    if args.no_cache {
        request = request.without_cache();
    }
    if let Some(dir) = &args.cache_dir {
        request = request.with_cache_dir(dir.clone());
    }
    if provenance.any::<IgnoreArgs>() {
        request = request.with_ignore_options(args.ignore.to_options());
    }
    if args.follow_symlinks {
        request = request.following_symlinks();
    }
    request
}

/// Open a report, or a live scan, in the terminal UI.
///
/// Three forms, three different amounts of trust. A live session hands over the
/// same request a scan would resolve, and the UI resolves it. An explicitly
/// named report is opened whatever scope it came from, which is what makes a
/// report copied off its machine reviewable. Implicit latest is the strict one:
/// the scope it was asked for is the scope the report has to describe.
fn run_review(args: ReviewArgs) {
    if args.live {
        require_root(&args.path);
        let mut request = ScanRequest::explicit(args.path.clone());
        if let Some(config) = &args.config {
            request = request.with_config(config.clone());
        }
        open_review(ReviewSession::Live { request });
    }

    if let Some(report) = args.report {
        let source_base = match &args.config {
            Some(config) => config
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .to_path_buf(),
            None => PathBuf::from("."),
        };
        open_review(ReviewSession::SavedReport {
            report,
            source_base,
            config: args.config,
            // No expectation: this file was named, not looked up.
            expect: None,
        });
    }

    let scope =
        saved_report::canonical_scope(&args.path).unwrap_or_else(|e| fail(&format!("error: {e}")));
    let report = saved_report::latest_report_path(&args.path)
        .unwrap_or_else(|e| fail(&format!("error: {e}")));
    if !report.is_file() {
        let bin = env!("CARGO_BIN_NAME");
        fail(&format!(
            "error: {}: no saved report for this scope; run `{bin}` in it, or `{bin} {} --save`, \
             or open a report with `{bin} review --report FILE`",
            args.path.display(),
            args.path.display()
        ));
    }
    // The scope's own directory, deliberately: only the report knows how far
    // above it the paths are measured from, and the session climbs that many
    // parents once it has read the document. Working the number out here would
    // mean parsing the report before the loader does.
    let source_base =
        saved_report::source_base(&scope, 0).unwrap_or_else(|e| fail(&format!("error: {e}")));

    open_review(ReviewSession::SavedReport {
        report,
        source_base,
        config: args.config,
        expect: Some(siloscan_tui::ExpectedScope {
            identity: scope.identity(),
            kind: scope.kind(),
        }),
    });
}

/// The one place this binary enters the terminal UI.
///
/// Every review form funnels through here, so the session shape the UI accepts
/// is reached from exactly one call site and a change to it is a change to one
/// function.
///
/// `source_base` is the level-0 base - the requested directory, or the parent
/// of a single-file scope - and not the directory the report's paths are
/// relative to. A config-anchored report measures from the config root and
/// records how far above the scope that is; the session climbs those parents
/// after it loads the document, and refuses if it runs out of them. That number
/// lives only in the report, so computing the base here would cost a parse of a
/// file the loader is about to read anyway.
fn open_review(session: ReviewSession) -> ! {
    match siloscan_tui::run(session) {
        Ok(()) => process::exit(0),
        Err(e) => fail(&format!("error: {e}")),
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

    let cache = open_cache(
        &args.path,
        &rules,
        args.no_cache,
        args.cache_dir.as_deref(),
        &anchoring,
    );
    let mut options = scan::ScanOptions::default();
    options.cache = cache.as_ref();
    options.config = config.as_ref();
    options.coverage = coverage.as_ref();
    options.ignore = args.ignore.to_options();
    options.follow_symlinks = args.follow_symlinks;
    let report = match scan::scan_opts(&args.path, &rules, &options, &mut |_| {}) {
        Ok(report) => report,
        Err(e) => fail(&format!("error: {e}")),
    };

    warn_skipped(&report.skipped);
    warn_scan(&report.warnings);

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
            emit(
                &mut out,
                format_args!("baseline written: {}", quantity(count, "entry", "entries")),
            );
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

/// The cache for this run: in this user's own cache directory, or under
/// `cache_dir` when the command line named one. `siloscan test` never caches: a
/// fixture run must exercise the engines.
///
/// It is keyed on the scan root but stored nowhere near it. Nothing under the
/// scanned tree is read or written, so a repository cannot plant an entry, move
/// the cache, or tell a scan where to look for one - the location comes from
/// this process's environment and this command line, and from nothing else.
/// `state_root` still resolves a single-file root to the directory holding it,
/// so `siloscan app.js` and a scan of the directory around it key alike.
///
/// The anchoring is part of the cache key. A cached finding carries a path and a
/// fingerprint derived from that path, so an entry written under one convention
/// would be wrong under another, and the two must never share a key.
fn open_cache(
    root: &Path,
    rules: &RuleSet,
    no_cache: bool,
    cache_dir: Option<&Path>,
    anchoring: &scan::Anchoring,
) -> Option<Cache> {
    if no_cache {
        return None;
    }
    let scope = PathScope::new(anchoring.anchor(), anchoring.prefix());
    let root = state_root(root);
    Some(match cache_dir {
        Some(dir) => Cache::open_in(dir, &root, rules, &scope),
        None => Cache::open(&root, rules, &scope),
    })
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
/// directory. Any failure here is exit 2, and so is loading nothing.
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

    if rules.is_empty() {
        fail(&no_rules_message(dirs, no_default_rules));
    }

    RuleSet { rules, sources }
}

/// Why a run that loaded nothing is exit 2 rather than a clean scan.
///
/// A scan with no rules cannot report a finding, so it exits 0 having proven
/// nothing, and every later run does the same: a `--rules` path with a typo in
/// it, a rule directory that never made it into the container, a config naming a
/// directory that moved, all of them read as a passing gate forever. A gate that
/// could not evaluate has to fail.
///
/// The message names every directory that was searched and says whether the
/// built-in pack was in play, because those are the two things the user has to
/// look at and the difference between "my path is wrong" and "I disabled the
/// pack and forgot the replacement". Directory names come from the command line
/// or from a config inside the scanned tree, so they are quoted through [`fail`]
/// like any other scanned text - which is also why this stays one line.
fn no_rules_message(dirs: &[PathBuf], no_default_rules: bool) -> String {
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
    let pack = if no_default_rules {
        "the built-in pack is disabled by --no-default-rules"
    } else {
        "the built-in pack loaded no rules"
    };
    format!("error: no rules loaded, so nothing would be checked: {pack}; {searched}")
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

/// The same for stderr, and for the same reason.
///
/// `eprintln!` panics on a closed stderr exactly as `println!` does on a closed
/// stdout, and the panic exits 101 - a code this CLI does not promise and CI
/// cannot interpret. That was survivable while stderr was almost always empty;
/// a scan now reports every file it skipped, so the write happens on ordinary
/// runs and `siloscan . 2>&1 | head` was reaching it. Every stderr write in this
/// binary goes through here: the skip warnings, the exit-2 messages and the
/// subcommand usage note. Clap's own errors do not, because clap already
/// swallows the broken pipe itself.
///
/// The lock is taken per line rather than held, since the callers are a handful
/// of lines each and one of them ends the process.
fn emit_err(args: std::fmt::Arguments) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{args}");
    let _ = err.flush();
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
        emit_err(format_args!(
            "warning: skipped {}: {}",
            safe(&entry.path),
            safe(&entry.reason)
        ));
    }
    if let Some(rest) = skipped
        .len()
        .checked_sub(MAX_SKIP_WARNINGS)
        .filter(|n| *n > 0)
    {
        emit_err(format_args!(
            "warning: ... and {} skipped (see --format json for the full list)",
            quantity(rest, "more file", "more files")
        ));
    }
}

/// `count` with the noun it agrees with. Every summary line this binary prints
/// goes through here: "1 findings" in the line every scan ends with was the
/// most visible thing about the tool, and a count formatted by hand grows a
/// second one every time a line is added.
fn quantity(count: usize, singular: &str, plural: &str) -> String {
    match count {
        1 => format!("1 {singular}"),
        _ => format!("{count} {plural}"),
    }
}

/// The threshold a run was filtered at, or `None` when it reported everything
/// it found.
///
/// Recorded in the machine-readable formats so a consumer can tell a report
/// that withheld findings from one that had none to withhold - the same
/// distinction `skipped`, `ignored` and `warnings` exist to make - and the same
/// answer decides whether the human listing says anything. `None` on the
/// default threshold, which drops nothing and so has nothing to declare; the
/// report is then the document it was before any of this was recorded, in every
/// format.
fn filtered_at(min_severity: Severity) -> Option<Severity> {
    match min_severity > Severity::Info {
        true => Some(min_severity),
        false => None,
    }
}

/// What `--min-severity` withheld, for the human listing, or `None` when the
/// threshold withheld nothing.
///
/// The machine-readable formats record the threshold itself and let the
/// consumer work out the rest; a human reads a listing, and a listing that is
/// short because of a flag looks exactly like a listing that is short because
/// the tree is clean. The line exists to separate those two, so it is printed
/// only when they are actually confusable - a threshold that removed nothing
/// produces the same report either way and has nothing to announce, and saying
/// so on every filtered run would put a line on the terminal that is noise
/// exactly when the news is good.
///
/// `threshold` is the level that was applied, which the caller only has when
/// filtering was active at all: on the default the report is unfiltered and
/// this is never reached.
fn withheld_line(withheld: usize, threshold: Severity) -> Option<String> {
    match withheld {
        0 => None,
        count => Some(format!(
            "{} hidden by --min-severity {threshold}",
            quantity(count, "finding", "findings")
        )),
    }
}

/// What the scan narrowed, said before the report rather than inside it.
///
/// These are not findings and not skipped files: they are the places where a
/// gate did not evaluate and the run was allowed to continue anyway. Unbounded
/// on purpose - the scanner only produces one per input it could not use, and a
/// list short enough to print is the point of it being a warning instead of a
/// refusal.
fn warn_scan(warnings: &[String]) {
    for warning in warnings {
        emit_err(format_args!("warning: {}", safe(warning)));
    }
}

/// Every exit-2 message is human text on stderr, and several of them quote a
/// path or a rule file, so the sanitising happens here once rather than at
/// twenty call sites.
fn fail(message: &str) -> ! {
    emit_err(format_args!("{}", safe(message)));
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

    const SIMPLE_RULE: &str = "\
version: 1
rules:
  - id: test.needle
    severity: error
    message: m
    regex:
      pattern: 'needle'
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
            cache_dir: Some(tempdir().path().to_path_buf()),
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

        let cache_home = tempdir();
        let cache = open_cache(
            &dir.path().join("app.js"),
            &RuleSet::default(),
            false,
            Some(cache_home.path()),
            &anchoring,
        )
        .expect("a file root opens a cache");
        // That it opened at all is this test's subject: joining `.siloscan`
        // onto a file names a directory below a file, which is what made
        // `siloscan app.js` exit 2 before it had scanned anything. Where the
        // entries live is the cache's own contract and is asserted there.
        let _ = cache;

        assert!(
            open_cache(
                &dir.path().join("app.js"),
                &RuleSet::default(),
                true,
                Some(cache_home.path()),
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

    /// The exit-2 message for a run that loaded nothing has to name both halves
    /// of the mistake, and has to survive `fail`, which renders it through
    /// [`safe`]: a newline in it would print as `\x0a` instead of breaking the
    /// line.
    #[test]
    fn the_no_rules_error_names_what_was_searched() {
        let none = no_rules_message(&[], true);
        assert!(none.starts_with("error: "), "{none}");
        assert!(none.contains("no rules loaded"), "{none}");
        assert!(none.contains("--no-default-rules"), "{none}");
        assert!(none.contains("no rule directories were given"), "{none}");

        let dirs = no_rules_message(&[PathBuf::from("rules/a"), PathBuf::from("rules/b")], true);
        assert!(dirs.contains("searched: rules/a, rules/b"), "{dirs}");

        let pack = no_rules_message(&[], false);
        assert!(pack.contains("built-in pack loaded no rules"), "{pack}");

        for message in [none, dirs, pack] {
            assert!(!message.contains('\n'), "{message}");
            assert_eq!(safe(&message), message);
        }
    }

    /// The rule sets that are allowed through: the built-in pack on its own, and
    /// `--no-default-rules` with a directory that actually holds a rule. Neither
    /// of these may become collateral of rejecting the empty set.
    #[test]
    fn a_non_empty_rule_set_still_loads() {
        let dir = tempdir();
        write(dir.path(), "rules/needle.yaml", SIMPLE_RULE);

        let only_dir = load_rules(dir.path(), &[dir.path().join("rules")], true);
        assert_eq!(only_dir.rules.len(), 1);
        assert_eq!(only_dir.rules[0].id, "test.needle");
        assert_eq!(only_dir.sources.len(), 1);

        let pack_only = load_rules(dir.path(), &[], false);
        assert!(
            !pack_only.rules.is_empty(),
            "the built-in pack is not empty"
        );

        let both = load_rules(dir.path(), &[dir.path().join("rules")], false);
        assert_eq!(both.rules.len(), pack_only.rules.len() + 1);
    }

    /// Every summary line the binary prints agrees with its own number. The
    /// one that mattered is the scan summary, which printed "1 findings" on
    /// every run that had a baseline or a suppression.
    #[test]
    fn counted_nouns_agree_with_their_number() {
        assert_eq!(quantity(0, "finding", "findings"), "0 findings");
        assert_eq!(quantity(1, "finding", "findings"), "1 finding");
        assert_eq!(quantity(2, "finding", "findings"), "2 findings");
        assert_eq!(quantity(1, "entry", "entries"), "1 entry");
        assert_eq!(quantity(0, "entry", "entries"), "0 entries");
        assert_eq!(quantity(1, "more file", "more files"), "1 more file");
        assert_eq!(quantity(3, "more file", "more files"), "3 more files");
    }

    /// `--min-severity` has to survive clap, default to reporting everything,
    /// and stay separate from `--fail-on`: they are one enum and two arguments,
    /// and collapsing them would make hiding findings a way to pass a gate.
    #[test]
    fn min_severity_is_accepted_and_defaults_to_reporting_everything() {
        let cli = Cli::try_parse_from(["siloscan", "src"]).unwrap();
        assert_eq!(cli.scan.min_severity.to_severity(), Severity::Info);
        assert_eq!(cli.scan.fail_on.to_severity(), Severity::Error);

        let cli = Cli::try_parse_from([
            "siloscan",
            "src",
            "--min-severity",
            "error",
            "--fail-on",
            "warning",
        ])
        .unwrap();
        assert_eq!(cli.scan.min_severity.to_severity(), Severity::Error);
        assert_eq!(cli.scan.fail_on.to_severity(), Severity::Warning);

        assert!(Cli::try_parse_from(["siloscan", "--min-severity", "critical"]).is_err());
        // A scan-only flag, deliberately: a baseline narrowed by severity would
        // record part of the debt and silently accept the rest.
        assert!(Cli::try_parse_from(["siloscan", "baseline", "--min-severity", "error"]).is_err());
    }

    /// The filter as `run_scan` applies it: whole findings dropped, in every
    /// list, with nothing rewritten. Fingerprints survive because no finding is
    /// ever rebuilt - the ones that pass are the ones the scan produced.
    #[test]
    fn min_severity_drops_whole_findings_and_moves_nothing() {
        use siloscan_core::findings::{Finding, fingerprint};

        let finding = |severity, rule_id: &str| Finding {
            rule_id: rule_id.to_string(),
            severity,
            message: "m".to_string(),
            path: "src/a.rs".to_string(),
            line: 1,
            column: 1,
            column_utf16: 1,
            matched: "x".to_string(),
            fingerprint: fingerprint(rule_id, "src/a.rs", "x", 0),
        };

        let mut findings = vec![
            finding(Severity::Info, "a.info"),
            finding(Severity::Warning, "b.warning"),
            finding(Severity::Error, "c.error"),
        ];
        let before = findings.clone();

        findings.retain(|f| f.severity >= Severity::Warning);
        assert_eq!(
            findings
                .iter()
                .map(|f| f.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["b.warning", "c.error"]
        );
        assert_eq!(findings[0].fingerprint, before[1].fingerprint);
        assert_eq!(findings[1].fingerprint, before[2].fingerprint);

        // The default keeps everything, so today's output is unchanged.
        let mut all = before.clone();
        all.retain(|f| f.severity >= Severity::Info);
        assert_eq!(all.len(), 3);
    }

    /// A filtered human listing has to say it was filtered. JSON and SARIF have
    /// carried the threshold since it existed; the terminal, where most people
    /// read a report, carried nothing, so a run that hid every finding printed
    /// the same thing a clean tree does.
    #[test]
    fn a_filtered_human_listing_says_what_it_withheld() {
        assert_eq!(
            withheld_line(3, Severity::Error).as_deref(),
            Some("3 findings hidden by --min-severity error")
        );
        assert_eq!(
            withheld_line(1, Severity::Warning).as_deref(),
            Some("1 finding hidden by --min-severity warning"),
            "the count agrees with its noun, like every other summary line"
        );
    }

    /// The line is about a confusion, not about the flag: a threshold that
    /// removed nothing produced the report it would have produced anyway, and
    /// announcing it there would be noise on exactly the runs with no news.
    #[test]
    fn a_filter_that_withheld_nothing_says_nothing() {
        assert_eq!(withheld_line(0, Severity::Error), None);
    }

    /// The whole decision `run_scan` makes, composed as it composes it: the
    /// default threshold reports everything, so nothing new reaches the
    /// listing and an unfiltered run's output is byte for byte what it was
    /// before this line existed - whatever the counts happen to be.
    #[test]
    fn an_unfiltered_run_prints_nothing_new() {
        assert_eq!(filtered_at(Severity::Info), None);
        let line = filtered_at(SeverityArg::Info.to_severity())
            .and_then(|threshold| withheld_line(7, threshold));
        assert_eq!(line, None, "the default threshold must print no extra line");

        // And the flag being in play is not on its own enough either.
        assert_eq!(filtered_at(Severity::Error), Some(Severity::Error));
        let line = filtered_at(Severity::Error).and_then(|threshold| withheld_line(0, threshold));
        assert_eq!(line, None);
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
