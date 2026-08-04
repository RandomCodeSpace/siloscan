//! siloscan-tui entry point: argument parsing, rule/baseline loading, and the
//! event loop that drives the `ui` module.

mod actions;
mod app;
mod snapshot;
mod state;
mod term;
mod ui;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use siloscan_core::baseline;
use siloscan_core::config::{self, Config};
use siloscan_core::default_pack;
use siloscan_core::rules::{self, CompiledPayload, CompiledRule, RuleSet};

use app::{AppEvent, WalkPolicy};
use state::{AppState, READ_ONLY_RESCAN, Screen};

const POLL_INTERVAL: Duration = Duration::from_millis(50);

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

    let (mut state, config) = match args.report.as_deref() {
        Some(report) => boot_snapshot(&args, report),
        None => boot_live(&args),
    };

    let mut terminal = match term::init() {
        Ok(terminal) => terminal,
        Err(e) => fail(&format!("error: terminal setup failed: {e}")),
    };
    let result = run(&mut terminal, &mut state, config, args.walk);
    let restored = term::restore();

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(2);
    }
    if let Err(e) = restored {
        eprintln!("error: terminal restore failed: {e}");
        process::exit(2);
    }
}

/// Live boot: rules, config and baseline for the path to be scanned.
fn boot_live(args: &Args) -> (AppState, Option<Arc<Config>>) {
    let (config, config_rule_dirs) = match load_config(&args.path, args.config.as_deref()) {
        Ok(loaded) => loaded,
        Err(e) => fail(&format!("error: {e}")),
    };
    let mut dirs = args.rules.clone();
    dirs.extend(config_rule_dirs);

    let rules = match load_rules(&args.path, &dirs, args.no_default_rules) {
        Ok(rules) => Arc::new(rules),
        Err(e) => fail(&format!("error: {e}")),
    };
    if let Err(e) = require_silos(&rules, config.as_deref()) {
        fail(&format!("error: {e}"));
    }
    let baseline = match baseline::load(&args.path) {
        Ok(baseline) => baseline.map(Arc::new),
        Err(e) => fail(&format!("error: {e}")),
    };

    (AppState::new(args.path.clone(), rules, baseline), config)
}

/// Snapshot boot: the report supplies the findings and metrics, so no rules,
/// no baseline and no scan. The report records no scan root, so paths resolve
/// against the working directory - a snapshot opened elsewhere still lists
/// every finding, it just cannot show file context. The config is still read,
/// since silo declarations shape the dashboard whether or not a scan runs.
fn boot_snapshot(args: &Args, report: &Path) -> (AppState, Option<Arc<Config>>) {
    match load_snapshot(report, args.config.as_deref()) {
        Ok(booted) => booted,
        Err(e) => fail(&format!("error: {e}")),
    }
}

/// The fallible half of `boot_snapshot`, so the boot path is testable without
/// taking the process down with it.
fn load_snapshot(
    report: &Path,
    config_arg: Option<&Path>,
) -> Result<(AppState, Option<Arc<Config>>), String> {
    let data = snapshot::load(report).map_err(|e| e.to_string())?;
    let root = PathBuf::from(".");
    let (config, _) = load_config(&root, config_arg)?;

    let mut state = AppState::new(root, Arc::new(RuleSet::default()), None);
    app::apply_snapshot(&mut state, data, config.as_deref());
    Ok((state, config))
}

/// One scan starts up front; `r` starts another once the previous one is done.
/// Each iteration drains scan events, redraws, then waits up to
/// `POLL_INTERVAL` for input, so progress keeps ticking on an idle terminal.
fn run(
    terminal: &mut term::Tui,
    state: &mut AppState,
    config: Option<Arc<Config>>,
    walk: WalkPolicy,
) -> io::Result<()> {
    let (tx, rx): (Sender<AppEvent>, Receiver<AppEvent>) = mpsc::channel();
    // A snapshot is already loaded and never scans; the channel stays empty.
    if state.snapshot.is_none() {
        start_scan(state, config.clone(), walk, &tx);
    }

    while !state.should_quit {
        drain_events(state, &rx, config.as_deref());
        terminal.draw(|frame| ui::draw(frame, state))?;

        if event::poll(POLL_INTERVAL)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    on_key(state, key, config.clone(), walk, &tx)
                }
                Event::Mouse(mouse) => ui::handle_mouse(state, mouse),
                // Resize needs no bookkeeping: the next draw re-lays out.
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }

    Ok(())
}

fn drain_events(state: &mut AppState, rx: &Receiver<AppEvent>, config: Option<&Config>) {
    while let Ok(event) = rx.try_recv() {
        match event {
            AppEvent::Progress(progress) => state.progress = Some(progress),
            AppEvent::ScanDone(report) => app::apply_report(state, *report, config),
            AppEvent::Failed(message) => app::apply_failure(state, message),
        }
    }
}

/// Global bindings win unless a screen is capturing text (the filter box), in
/// which case every key is forwarded verbatim. Ctrl-C always quits.
fn on_key(
    state: &mut AppState,
    key: KeyEvent,
    config: Option<Arc<Config>>,
    walk: WalkPolicy,
    tx: &Sender<AppEvent>,
) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.should_quit = true;
        return;
    }
    if state.captures_input() {
        ui::handle_key(state, key);
        return;
    }

    match key.code {
        KeyCode::Char('q') => state.should_quit = true,
        // A snapshot refuses with its reason in the status line and nothing else.
        KeyCode::Char('r') => {
            if !state.refuse_if_snapshot(READ_ONLY_RESCAN) && !state.scan_running {
                reload_baseline(state);
                start_scan(state, config, walk, tx);
            }
        }
        KeyCode::Char('1') => state.screen = Screen::Dashboard,
        KeyCode::Char('2') => state.screen = Screen::Triage,
        KeyCode::Char('3') => state.screen = Screen::Ratchet,
        KeyCode::Char('4') => state.screen = Screen::Silo,
        _ => ui::handle_key(state, key),
    }
}

fn start_scan(
    state: &mut AppState,
    config: Option<Arc<Config>>,
    walk: WalkPolicy,
    tx: &Sender<AppEvent>,
) {
    state.begin_scan();
    app::spawn_scan(
        state.root.clone(),
        Arc::clone(&state.rules),
        state.baseline.clone(),
        config,
        walk,
        tx.clone(),
    );
}

/// The ratchet console writes the baseline, so a rescan re-reads it. A baseline
/// that has become unreadable is reported in the status line and the loaded one
/// stays in force, rather than killing the session mid-triage.
fn reload_baseline(state: &mut AppState) {
    match baseline::load(&state.root) {
        Ok(baseline) => state.baseline = baseline.map(Arc::new),
        Err(e) => state.status = format!("baseline: {e}"),
    }
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

/// The repository config and the extra rule directories it declares, resolved
/// against the directory holding the config file. Same rules as the CLI: an
/// explicit `--config` must exist, a discovered one is optional.
fn load_config(
    root: &Path,
    explicit: Option<&Path>,
) -> Result<(Option<Arc<Config>>, Vec<PathBuf>), String> {
    validate_root(root).map_err(|e| format!("{}: {e}", root.display()))?;

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
    Ok((Some(Arc::new(config)), dirs))
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

/// Same loading order and duplicate check as the CLI: built-in pack first, then
/// each `--rules` directory.
fn load_rules(root: &Path, dirs: &[PathBuf], no_default_rules: bool) -> Result<RuleSet, String> {
    validate_root(root).map_err(|e| format!("{}: {e}", root.display()))?;

    let mut rules: Vec<CompiledRule> = Vec::new();
    // Sources are recorded in the same order they are loaded; the cache keys
    // entries on their digest, so an unrecorded source is an unnoticed change.
    let mut sources: Vec<(String, String)> = Vec::new();
    if !no_default_rules {
        rules.extend(
            rules::load_str(default_pack::default_rules(), "default-pack")
                .map_err(|e| e.to_string())?,
        );
        sources.push((
            "default-pack".to_string(),
            default_pack::default_rules().to_string(),
        ));
    }
    let loaded = rules::load_dirs(dirs).map_err(|e| e.to_string())?;
    rules.extend(loaded.rules);
    sources.extend(loaded.sources);

    let mut seen: HashMap<&str, ()> = HashMap::new();
    for rule in &rules {
        if seen.insert(rule.id.as_str(), ()).is_some() {
            return Err(format!("duplicate rule id: {}", rule.id));
        }
    }

    // A scan with no rules checks nothing and reports nothing, which on screen
    // is indistinguishable from a clean tree. The CLI refuses it; so does this,
    // in the same words, because the two load rules the same way and a hole
    // closed in one of them is not closed.
    if rules.is_empty() {
        return Err(no_rules_message(dirs, no_default_rules));
    }

    Ok(RuleSet { rules, sources })
}

/// Why nothing loaded, naming the rule directories that were searched and
/// whether the built-in pack was in play. Kept identical to the CLI's message:
/// the two binaries answer the same question, and a user comparing them must
/// not have to work out whether they mean the same thing.
///
/// The `error: ` prefix is *not* here, unlike the CLI's copy. Every failure in
/// this binary is a `Result` the caller renders with that prefix, so carrying
/// one here printed `error: error: no rules loaded`. The line that reaches the
/// terminal is the one that has to match the CLI's, and it does.
///
/// Directory names come from the command line or from a config inside the
/// scanned tree, so they are rendered through the terminal sanitizer wherever
/// this is printed, like any other scanned text.
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
    format!("no rules loaded, so nothing would be checked: {pack}; {searched}")
}

/// The walker cannot tell "nothing to scan" from "root is missing", so the root
/// is checked up front.
fn validate_root(path: &Path) -> io::Result<()> {
    if fs::metadata(path)?.is_dir() {
        fs::read_dir(path).map(|_| ())
    } else {
        fs::File::open(path).map(|_| ())
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use siloscan_core::walk::IgnoreOptions;

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
    fn a_boundary_rule_without_silos_is_rejected() {
        let rules = RuleSet {
            rules: rules::load_str(
                "version: 1\nrules:\n  - id: arch.a-b\n    severity: error\n    message: m\n    boundary:\n      from: api\n      deny: [\"db\"]\n",
                "test",
            )
            .unwrap(),
            ..Default::default()
        };

        let err = require_silos(&rules, None).unwrap_err();
        assert!(err.contains("arch.a-b"), "{err}");
        assert!(err.contains(config::CONFIG_NAME), "{err}");
        assert!(require_silos(&rules, Some(&Config::default())).is_err());

        let config = Config {
            silos: std::collections::BTreeMap::from([(
                "api".to_string(),
                vec!["a/**".to_string()],
            )]),
            ..Config::default()
        };
        assert!(require_silos(&rules, Some(&config)).is_ok());
        assert!(require_silos(&RuleSet::default(), None).is_ok());
    }

    #[test]
    fn help_short_circuits() {
        assert!(parse(&["--help"]).unwrap().help);
        assert!(parse(&["-h"]).unwrap().help);
    }

    #[test]
    fn missing_root_is_an_error() {
        let err = load_rules(Path::new("/nonexistent/siloscan-tui"), &[], true).unwrap_err();
        assert!(err.contains("/nonexistent/siloscan-tui"));
    }

    #[test]
    fn the_default_pack_loads_rules() {
        let with = load_rules(Path::new("."), &[], false).unwrap();
        assert!(!with.rules.is_empty());
    }

    /// Skipping the pack with nothing to replace it leaves zero rules, and a
    /// zero-rule scan paints an empty dashboard that reads as a clean tree.
    /// Refused here exactly as the CLI refuses it, and in the same words - one
    /// `error: ` prefix, added by whoever prints the failure.
    #[test]
    fn skipping_the_default_pack_with_no_rule_dirs_is_refused() {
        let err = load_rules(Path::new("."), &[], true).unwrap_err();
        assert!(
            err.starts_with("no rules loaded, so nothing would be checked"),
            "{err}"
        );
        assert!(
            err.contains("the built-in pack is disabled by --no-default-rules"),
            "{err}"
        );
        assert_eq!(err, super::no_rules_message(&[], true));
        assert_eq!(
            format!("error: {err}"),
            "error: no rules loaded, so nothing would be checked: the built-in pack is disabled \
             by --no-default-rules; no rule directories were given",
            "the printed line must carry exactly one prefix"
        );
    }
}
