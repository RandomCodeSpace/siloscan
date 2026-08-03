use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

use clap::{Args, Parser, Subcommand};
use siloscan_core::baseline::{self, Baseline};
use siloscan_core::cache::Cache;
use siloscan_core::config::{self, Config};
use siloscan_core::coverage::{self, CoverageReport};
use siloscan_core::harness;
use siloscan_core::rules::{self, CompiledPayload, CompiledRule, RuleSet, Severity};
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

    /// Repository config (defaults to the nearest `siloscan.toml` at or above PATH)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Coverage report to feed coverage rules (lcov or cobertura)
    #[arg(long, value_name = "FILE")]
    coverage_report: Option<PathBuf>,

    /// Do not read or write the scan cache under `.siloscan/cache`
    #[arg(long)]
    no_cache: bool,
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
    let baseline = match load_baseline(&args.path, args.baseline.as_deref()) {
        Ok(baseline) => baseline,
        Err(e) => fail(&e),
    };

    let cache = open_cache(&args.path, &rules, args.no_cache);
    let options = scan::ScanOptions {
        baseline: baseline.as_ref(),
        cache: cache.as_ref(),
        config: config.as_ref(),
        coverage: coverage.as_ref(),
    };
    let report = match scan::scan_opts(&args.path, &rules, &options, &mut |_| {}) {
        Ok(report) => report,
        Err(e) => fail(&format!("error: {e}")),
    };

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

    let cache = open_cache(&args.path, &rules, args.no_cache);
    let options = scan::ScanOptions {
        cache: cache.as_ref(),
        config: config.as_ref(),
        coverage: coverage.as_ref(),
        ..Default::default()
    };
    let report = match scan::scan_opts(&args.path, &rules, &options, &mut |_| {}) {
        Ok(report) => report,
        Err(e) => fail(&format!("error: {e}")),
    };

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

/// The cache lives under the scan root, so it is only available when the root
/// is a directory. `siloscan test` never caches: a fixture run must exercise
/// the engines.
fn open_cache(root: &Path, rules: &RuleSet, no_cache: bool) -> Option<Cache> {
    if no_cache || !root.is_dir() {
        return None;
    }
    Some(Cache::open(root, rules))
}

/// The repository config and the extra rule directories it declares, resolved
/// against the directory holding the config file. An explicit `--config` must
/// exist and parse; the discovered one is simply absent when there is none.
fn load_config(
    root: &Path,
    explicit: Option<&Path>,
) -> Result<(Option<Config>, Vec<PathBuf>), String> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => match config::discover(root) {
            Some(path) => path,
            None => return Ok((None, Vec::new())),
        },
    };

    let config = config::load(&path)?;
    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let dirs = config.rules.iter().map(|rel| dir.join(rel)).collect();
    Ok((Some(config), dirs))
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
fn emit(out: &mut impl Write, args: std::fmt::Arguments) {
    let _ = writeln!(out, "{args}");
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    process::exit(2);
}

#[cfg(test)]
mod tests {
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
