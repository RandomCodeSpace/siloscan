use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

use clap::{Args, Parser, Subcommand};
use siloscan_core::baseline::{self, Baseline};
use siloscan_core::harness;
use siloscan_core::rules::{self, CompiledRule, RuleSet, Severity};
use siloscan_core::scan;
use siloscan_core::{default_pack, output, output_sarif};

#[derive(Parser)]
#[command(about = "Universal offline rule-based static code scanner", version)]
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

    /// Baseline file (defaults to `.siloscan/baseline.json` under PATH when present)
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
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
    let cli = Cli::parse();

    match cli.command {
        None => run_scan(cli.scan),
        Some(Command::Baseline(args)) => run_baseline(args),
        Some(Command::Test(args)) => run_test(args),
    }
}

fn run_scan(args: ScanArgs) {
    let rules = load_rules(&args.path, &args.rules, args.no_default_rules);
    let baseline = match load_baseline(&args.path, args.baseline.as_deref()) {
        Ok(baseline) => baseline,
        Err(e) => fail(&e),
    };

    let report = scan::scan(&args.path, &rules, baseline.as_ref());

    for skipped in &report.skipped {
        eprintln!("warning: skipped {}: {}", skipped.path, skipped.reason);
    }

    let mut out = io::stdout().lock();
    match args.format {
        Format::Human => {
            for finding in &report.findings {
                emit(
                    &mut out,
                    format_args!(
                        "{}:{}:{} {} {} {}",
                        finding.path,
                        finding.line,
                        finding.column,
                        finding.severity,
                        finding.rule_id,
                        finding.message
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
        }
        Format::Json => emit(&mut out, format_args!("{}", output::to_json(&report))),
        Format::Sarif => emit(
            &mut out,
            format_args!("{}", output_sarif::to_sarif(&report, &rules)),
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
    let rules = load_rules(&args.path, &args.rules, args.no_default_rules);

    let report = scan::scan(&args.path, &rules, None);

    for skipped in &report.skipped {
        eprintln!("warning: skipped {}: {}", skipped.path, skipped.reason);
    }

    match baseline::save(&args.path, &report.findings) {
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

    let report = harness::run(&args.fixture_dir, &rules);

    let mut out = io::stdout().lock();
    for line in &report.missing {
        emit(&mut out, format_args!("missing: {line}"));
    }
    for line in &report.unexpected {
        emit(&mut out, format_args!("unexpected: {line}"));
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

/// Validates the scan root and loads the built-in pack plus every `--rules`
/// directory. Any failure here is exit 2.
fn load_rules(root: &Path, dirs: &[PathBuf], no_default_rules: bool) -> RuleSet {
    if let Err(e) = validate_root(root) {
        fail(&format!("error: {}: {}", root.display(), e));
    }

    let mut rules: Vec<CompiledRule> = Vec::new();
    if !no_default_rules {
        match rules::load_str(default_pack::default_rules(), "default-pack") {
            Ok(loaded) => rules.extend(loaded),
            Err(e) => fail(&format!("error: {e}")),
        }
    }

    match rules::load_dirs(dirs) {
        Ok(loaded) => rules.extend(loaded.rules),
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

    RuleSet { rules }
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
fn emit(out: &mut impl Write, args: std::fmt::Arguments) {
    let _ = writeln!(out, "{args}");
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    process::exit(2);
}
