use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;
use siloscan_core::output;
use siloscan_core::rules::{self, Severity};
use siloscan_core::scan;

#[derive(Parser)]
#[command(about = "Universal offline rule-based static code scanner", version)]
struct Args {
    /// Path to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Rule directories
    #[arg(long, value_name = "DIR")]
    rules: Vec<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value = "human")]
    format: Format,

    /// Exit with code 1 if any finding meets this severity or higher
    #[arg(long, value_enum, default_value = "error")]
    fail_on: FailOn,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Human,
    Json,
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

/// The walker cannot distinguish "nothing to scan" from "root is missing or
/// unreadable", so the root is checked up front and a bad path is exit 2.
fn validate_root(path: &Path) -> io::Result<()> {
    if fs::metadata(path)?.is_dir() {
        fs::read_dir(path).map(|_| ())
    } else {
        fs::File::open(path).map(|_| ())
    }
}

fn main() {
    let args = Args::parse();

    if let Err(e) = validate_root(&args.path) {
        eprintln!("error: {}: {}", args.path.display(), e);
        process::exit(2);
    }

    // Load rules
    let rules = match rules::load_dirs(&args.rules) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(2);
        }
    };

    // Run scan
    let report = scan::scan(&args.path, &rules);

    // Print skipped files
    for skipped in &report.skipped {
        eprintln!("warning: skipped {}: {}", skipped.path, skipped.reason);
    }

    // Output findings
    match args.format {
        Format::Human => {
            for finding in &report.findings {
                println!(
                    "{}:{}:{} {} {} {}",
                    finding.path,
                    finding.line,
                    finding.column,
                    finding.severity,
                    finding.rule_id,
                    finding.message
                );
            }
        }
        Format::Json => {
            println!("{}", output::to_json(&report));
        }
    }

    // Determine exit code
    let fail_on_severity = args.fail_on.to_severity();
    if report
        .findings
        .iter()
        .any(|f| f.severity >= fail_on_severity)
    {
        process::exit(1);
    }
}
