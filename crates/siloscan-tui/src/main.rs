//! siloscan-tui entry point: argument parsing, rule/baseline loading, and the
//! event loop that drives the `ui` module.

mod actions;
mod app;
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

use app::AppEvent;
use state::{AppState, Screen};

const POLL_INTERVAL: Duration = Duration::from_millis(50);

const USAGE: &str = "\
siloscan-tui - interactive terminal UI for siloscan

Usage: siloscan-tui [PATH] [--rules DIR]... [--no-default-rules] [--config FILE]

Arguments:
  PATH                 Path to scan (default: .)

Options:
      --rules DIR      Rule directory, repeatable
      --no-default-rules
                       Do not load the built-in rule pack
      --config FILE    Repository config (default: nearest siloscan.toml at or
                       above PATH)
  -h, --help           Print help
";

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    path: PathBuf,
    rules: Vec<PathBuf>,
    no_default_rules: bool,
    config: Option<PathBuf>,
    help: bool,
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

    let mut state = AppState::new(args.path, rules, baseline);

    let mut terminal = match term::init() {
        Ok(terminal) => terminal,
        Err(e) => fail(&format!("error: terminal setup failed: {e}")),
    };
    let result = run(&mut terminal, &mut state, config);
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

/// One scan starts up front; `r` starts another once the previous one is done.
/// Each iteration drains scan events, redraws, then waits up to
/// `POLL_INTERVAL` for input, so progress keeps ticking on an idle terminal.
fn run(
    terminal: &mut term::Tui,
    state: &mut AppState,
    config: Option<Arc<Config>>,
) -> io::Result<()> {
    let (tx, rx): (Sender<AppEvent>, Receiver<AppEvent>) = mpsc::channel();
    start_scan(state, config.clone(), &tx);

    while !state.should_quit {
        drain_events(state, &rx);
        terminal.draw(|frame| ui::draw(frame, state))?;

        if event::poll(POLL_INTERVAL)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    on_key(state, key, config.clone(), &tx)
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

fn drain_events(state: &mut AppState, rx: &Receiver<AppEvent>) {
    while let Ok(event) = rx.try_recv() {
        match event {
            AppEvent::Progress(progress) => state.progress = Some(progress),
            AppEvent::ScanDone(report) => app::apply_report(state, *report),
            AppEvent::Failed(message) => app::apply_failure(state, message),
        }
    }
}

/// Global bindings win unless a screen is capturing text (the filter box), in
/// which case every key is forwarded verbatim. Ctrl-C always quits.
fn on_key(state: &mut AppState, key: KeyEvent, config: Option<Arc<Config>>, tx: &Sender<AppEvent>) {
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
        KeyCode::Char('r') => {
            if !state.scan_running {
                reload_baseline(state);
                start_scan(state, config, tx);
            }
        }
        KeyCode::Char('1') => state.screen = Screen::Dashboard,
        KeyCode::Char('2') => state.screen = Screen::Triage,
        KeyCode::Char('3') => state.screen = Screen::Ratchet,
        KeyCode::Char('4') => state.screen = Screen::Silo,
        _ => ui::handle_key(state, key),
    }
}

fn start_scan(state: &mut AppState, config: Option<Arc<Config>>, tx: &Sender<AppEvent>) {
    state.begin_scan();
    app::spawn_scan(
        state.root.clone(),
        Arc::clone(&state.rules),
        state.baseline.clone(),
        config,
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
            "--no-default-rules" => args.no_default_rules = true,
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

    Ok(RuleSet { rules, sources })
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
    fn default_pack_can_be_skipped() {
        let with = load_rules(Path::new("."), &[], false).unwrap();
        let without = load_rules(Path::new("."), &[], true).unwrap();
        assert!(!with.rules.is_empty());
        assert!(without.rules.is_empty());
    }
}
