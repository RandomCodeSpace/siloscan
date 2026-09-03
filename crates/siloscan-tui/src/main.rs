//! Standalone compatibility wrapper for the `siloscan-tui` library.

use std::env;
use std::path::PathBuf;
use std::process;

use siloscan_core::plan::ScanRequest;
use siloscan_core::walk::IgnoreOptions;
use siloscan_tui::ReviewSession;

const USAGE: &str = "\
siloscan-tui - interactive terminal UI for siloscan

Usage: siloscan-tui [PATH] [--rules DIR]... [--no-default-rules] [--config FILE]
       siloscan-tui --report FILE [--config FILE]

Arguments:
  PATH                 Path to scan (default: .)

Options:
      --rules DIR      Rule directory, repeatable
      --no-default-rules
                       Do not load the built-in rule pack. A run that ends up
                       with no rules at all checks nothing and is refused with
                       exit 2, since an empty dashboard would read as a clean
                       tree
      --config FILE    Repository config (default: nearest siloscan.toml at
                       PATH, or above it only when a .git marker exists at or
                       above PATH; pass this explicitly for an exported tree
                       that has none)
      --report FILE    Open a JSON report as a read-only snapshot instead of
                       scanning; cannot be combined with PATH
      --no-ignore      Scan every file: ignore no .gitignore and no .ignore
      --no-gitignore   Ignore .ignore files but not .gitignore files
      --respect-parent-ignores
                       Also honor ignore files above the scan root
      --respect-git-exclude
                       Also honor PATH/.git/info/exclude
      --respect-global-gitignore
                       Also honor git's global core.excludesFile
      --follow-symlinks
                       Follow symlinks whose target is inside the scan root.
                       Targets outside it are never followed. A file behind a
                       followed link is reported under both paths
  -h, --help           Print help
  -V, --version        Print version
";

/// Everything this command line says about the walk, in one value.
///
/// One value rather than a loose flag each: nothing here is read on its own,
/// the whole of it is either handed to the [`ScanRequest`] or refused beside
/// `--report`, and "did this command line configure its walk at all" stays a
/// single comparison.
#[derive(Debug, Default, PartialEq, Eq)]
struct WalkPolicy {
    /// Which ignore sources the walk consults.
    ignore: IgnoreOptions,
    /// Follow symlinks whose target is inside the scan root. A target outside
    /// it is never followed, whatever this says.
    follow_symlinks: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    path: PathBuf,
    rules: Vec<PathBuf>,
    no_default_rules: bool,
    config: Option<PathBuf>,
    /// A report to open instead of scanning. Mutually exclusive with `path`.
    report: Option<PathBuf>,
    /// What this session's walk reads. Defaults to the self-contained policy:
    /// ignore files inside the scan root count, nothing above or outside it
    /// does, and symlinks are not followed. The `--respect-*` flags each
    /// re-admit one out-of-root source, which is the only way back to the
    /// pre-1.1.2 behavior.
    walk: WalkPolicy,
    help: bool,
    version: bool,
}

fn main() {
    let args = match parse_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => fail(&format!("error: {e}")),
    };
    if args.help {
        print!("{USAGE}");
        return;
    }
    if args.version {
        println!("siloscan-tui {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let session = match args.report {
        Some(report) => ReviewSession::SavedReport {
            report,
            source_base: PathBuf::from("."),
            config: args.config,
            // This command names the file to open, so it is the explicit
            // reader: there is no scope to match it against.
            expect: None,
        },
        None => ReviewSession::Live {
            request: scan_request(args),
        },
    };
    if let Err(error) = siloscan_tui::run(session) {
        fail(&format!("error: {error}"));
    }
}

/// What this command line asks the core to scan.
///
/// Every `with_*` call records an explicit override whatever value it carries,
/// so each one is made only when the option was actually supplied. This command
/// always names a path - `.` is its documented default - so the request is
/// always an explicit one.
fn scan_request(args: Args) -> ScanRequest {
    let mut request = ScanRequest::explicit(args.path);
    if !args.rules.is_empty() {
        request = request.with_rule_dirs(args.rules);
    }
    if args.no_default_rules {
        request = request.without_embedded_rules();
    }
    if let Some(config) = args.config {
        request = request.with_config(config);
    }
    if args.walk.ignore != IgnoreOptions::default() {
        request = request.with_ignore_options(args.walk.ignore);
    }
    if args.walk.follow_symlinks {
        request = request.following_symlinks();
    }
    request
}

fn parse_args<I: IntoIterator<Item = String>>(argv: I) -> Result<Args, String> {
    let mut args = Args {
        path: PathBuf::from("."),
        ..Args::default()
    };
    let mut path_seen = false;
    let mut argv = argv.into_iter();

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => args.help = true,
            "-V" | "--version" => args.version = true,
            "--no-default-rules" => args.no_default_rules = true,
            // Each of these sets one field, and no two set the same field in
            // opposite directions, so the flags are order-independent.
            "--no-ignore" => {
                args.walk.ignore.respect_gitignore = false;
                args.walk.ignore.respect_dot_ignore = false;
            }
            "--no-gitignore" => args.walk.ignore.respect_gitignore = false,
            "--respect-parent-ignores" => args.walk.ignore.respect_parent_ignores = true,
            "--respect-git-exclude" => args.walk.ignore.respect_git_exclude = true,
            "--respect-global-gitignore" => args.walk.ignore.respect_global_gitignore = true,
            "--follow-symlinks" => args.walk.follow_symlinks = true,
            "--report" => {
                let file = argv
                    .next()
                    .ok_or_else(|| "--report requires a file".to_string())?;
                args.report = Some(PathBuf::from(file));
            }
            "--config" => {
                let file = argv
                    .next()
                    .ok_or_else(|| "--config requires a file".to_string())?;
                args.config = Some(PathBuf::from(file));
            }
            "--rules" => {
                let dir = argv
                    .next()
                    .ok_or_else(|| "--rules requires a directory".to_string())?;
                args.rules.push(PathBuf::from(dir));
            }
            other => {
                if let Some(dir) = other.strip_prefix("--rules=") {
                    args.rules.push(PathBuf::from(dir));
                } else if let Some(file) = other.strip_prefix("--config=") {
                    args.config = Some(PathBuf::from(file));
                } else if let Some(file) = other.strip_prefix("--report=") {
                    args.report = Some(PathBuf::from(file));
                } else if other.starts_with('-') && other != "-" {
                    return Err(format!("unknown option: {other}"));
                } else if path_seen {
                    return Err(format!("unexpected argument: {other}"));
                } else {
                    args.path = PathBuf::from(other);
                    path_seen = true;
                }
            }
        }
    }

    // A snapshot is the whole input: there is nothing for a scan path to mean.
    if args.report.is_some() && path_seen {
        return Err("--report cannot be combined with a scan path".to_string());
    }
    // Nor is there a walk to configure. Accepting the flags would show a
    // report built under whatever policy wrote it while the command line
    // claimed another, which is the silent disagreement these flags exist to
    // end.
    if args.report.is_some() && args.walk != WalkPolicy::default() {
        return Err("--report does not scan, so walk options cannot apply to it".to_string());
    }

    Ok(args)
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Result<Args, String> {
        parse_args(argv.iter().map(|arg| (*arg).to_string()))
    }

    #[test]
    fn defaults_to_the_current_directory() {
        let args = parse(&[]).unwrap();
        assert_eq!(args.path, PathBuf::from("."));
        assert!(args.rules.is_empty());
        assert!(!args.no_default_rules);
    }

    #[test]
    fn parses_path_and_repeated_rule_dirs() {
        let args = parse(&["src", "--rules", "a", "--rules=b", "--no-default-rules"]).unwrap();
        assert_eq!(args.path, PathBuf::from("src"));
        assert_eq!(args.rules, vec![PathBuf::from("a"), PathBuf::from("b")]);
        assert!(args.no_default_rules);
    }

    #[test]
    fn parses_the_config_override_in_both_forms() {
        assert_eq!(
            parse(&["--config", "a.toml"]).unwrap().config,
            Some(PathBuf::from("a.toml"))
        );
        assert_eq!(
            parse(&["--config=b.toml"]).unwrap().config,
            Some(PathBuf::from("b.toml"))
        );
        assert_eq!(parse(&[]).unwrap().config, None);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&["--rules"]).is_err());
        assert!(parse(&["--nope"]).is_err());
        assert!(parse(&["a", "b"]).is_err());
        assert!(parse(&["--config"]).is_err());
        assert!(parse(&["--report"]).is_err());
    }

    #[test]
    fn parses_the_report_snapshot_in_both_forms() {
        assert_eq!(
            parse(&["--report", "r.json"]).unwrap().report,
            Some(PathBuf::from("r.json"))
        );
        assert_eq!(
            parse(&["--report=r.json"]).unwrap().report,
            Some(PathBuf::from("r.json"))
        );
        assert_eq!(parse(&[]).unwrap().report, None);
        // A config still applies: it declares the silos the dashboard groups by.
        let args = parse(&["--report=r.json", "--config=s.toml"]).unwrap();
        assert_eq!(args.report, Some(PathBuf::from("r.json")));
        assert_eq!(args.config, Some(PathBuf::from("s.toml")));
    }

    #[test]
    fn a_report_and_a_scan_path_are_mutually_exclusive() {
        for argv in [
            vec!["src", "--report", "r.json"],
            vec!["--report", "r.json", "src"],
            vec!["--report=r.json", "src"],
        ] {
            let err = parse(&argv).unwrap_err();
            assert!(err.contains("--report"), "{err}");
        }
    }

    /// The TUI has to be able to look past an ignore file too: a session that
    /// cannot be told to scan everything is a session that reports whatever the
    /// repository's `.gitignore` allows, with nothing on screen saying so.
    #[test]
    fn parses_the_ignore_flags() {
        assert_eq!(parse(&[]).unwrap().walk.ignore, IgnoreOptions::default());

        let all = parse(&["--no-ignore"]).unwrap().walk.ignore;
        assert_eq!(all, IgnoreOptions::all_files());

        let no_git = parse(&["--no-gitignore"]).unwrap().walk.ignore;
        assert!(!no_git.respect_gitignore);
        assert!(no_git.respect_dot_ignore, "only gitignore was named");

        let legacy = parse(&[
            "--respect-parent-ignores",
            "--respect-git-exclude",
            "--respect-global-gitignore",
        ])
        .unwrap()
        .walk
        .ignore;
        assert!(legacy.respect_parent_ignores);
        assert!(legacy.respect_git_exclude);
        assert!(legacy.respect_global_gitignore);
        assert!(legacy.respect_gitignore, "in-root sources are untouched");

        // Order cannot change the policy: no two flags write the same field.
        assert_eq!(
            parse(&["--no-ignore", "--respect-parent-ignores"])
                .unwrap()
                .walk
                .ignore,
            parse(&["--respect-parent-ignores", "--no-ignore"])
                .unwrap()
                .walk
                .ignore
        );
    }

    /// The TUI and the CLI have to be able to scan the same set of files, so a
    /// flag that decides which files those are cannot exist on only one of them:
    /// a session that cannot be told to follow a link reports a tree the CLI
    /// would report differently, with nothing on screen saying why.
    #[test]
    fn parses_the_follow_symlinks_flag() {
        assert!(
            !parse(&[]).unwrap().walk.follow_symlinks,
            "not following links is the default on both front ends"
        );
        assert!(parse(&["--follow-symlinks"]).unwrap().walk.follow_symlinks);
        // It is a walk option like the ignore flags, so a snapshot refuses it
        // for the same reason: there is no walk for it to apply to.
        let err = parse(&["--report", "r.json", "--follow-symlinks"]).unwrap_err();
        assert!(err.contains("--report"), "{err}");
    }

    /// A snapshot never walks anything, so an ignore flag beside `--report` is
    /// a policy that silently would not apply. Refusing beats showing a report
    /// built one way while the command line claimed another.
    #[test]
    fn ignore_flags_are_rejected_alongside_a_report() {
        for flag in [
            "--no-ignore",
            "--no-gitignore",
            "--respect-parent-ignores",
            "--respect-git-exclude",
            "--respect-global-gitignore",
        ] {
            let err = parse(&["--report=r.json", flag]).unwrap_err();
            assert!(err.contains("--report"), "{flag}: {err}");
        }
        assert!(parse(&["--report=r.json"]).is_ok());
    }

    #[test]
    fn version_short_circuits() {
        assert!(parse(&["--version"]).unwrap().version);
        assert!(parse(&["-V"]).unwrap().version);
        assert!(!parse(&[]).unwrap().version);
    }

    #[test]
    fn help_short_circuits() {
        assert!(parse(&["--help"]).unwrap().help);
        assert!(parse(&["-h"]).unwrap().help);
    }
}
