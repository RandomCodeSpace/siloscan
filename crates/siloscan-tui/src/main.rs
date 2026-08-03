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
use siloscan_core::default_pack;
use siloscan_core::rules::{self, CompiledRule, RuleSet};

use app::AppEvent;
use state::{AppState, Screen};

const POLL_INTERVAL: Duration = Duration::from_millis(50);

const USAGE: &str = "\
siloscan-tui - interactive terminal UI for siloscan

Usage: siloscan-tui [PATH] [--rules DIR]... [--no-default-rules]

Arguments:
  PATH                 Path to scan (default: .)

Options:
      --rules DIR      Rule directory, repeatable
      --no-default-rules
                       Do not load the built-in rule pack
  -h, --help           Print help
";

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    path: PathBuf,
    rules: Vec<PathBuf>,
    no_default_rules: bool,
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

    let rules = match load_rules(&args.path, &args.rules, args.no_default_rules) {
        Ok(rules) => Arc::new(rules),
        Err(e) => fail(&format!("error: {e}")),
    };
    let baseline = match baseline::load(&args.path) {
        Ok(baseline) => baseline.map(Arc::new),
        Err(e) => fail(&format!("error: {e}")),
    };

    let mut state = AppState::new(args.path, rules, baseline);

    let mut terminal = match term::init() {
        Ok(terminal) => terminal,
        Err(e) => fail(&format!("error: terminal setup failed: {e}")),
    };
    let result = run(&mut terminal, &mut state);
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
fn run(terminal: &mut term::Tui, state: &mut AppState) -> io::Result<()> {
    let (tx, rx): (Sender<AppEvent>, Receiver<AppEvent>) = mpsc::channel();
    start_scan(state, &tx);

    while !state.should_quit {
        drain_events(state, &rx);
        terminal.draw(|frame| ui::draw(frame, state))?;

        if event::poll(POLL_INTERVAL)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => on_key(state, key, &tx),
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
        }
    }
}

/// Global bindings win unless a screen is capturing text (the filter box), in
/// which case every key is forwarded verbatim. Ctrl-C always quits.
fn on_key(state: &mut AppState, key: KeyEvent, tx: &Sender<AppEvent>) {
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
                start_scan(state, tx);
            }
        }
        KeyCode::Char('1') => state.screen = Screen::Dashboard,
        KeyCode::Char('2') => state.screen = Screen::Triage,
        KeyCode::Char('3') => state.screen = Screen::Ratchet,
        _ => ui::handle_key(state, key),
    }
}

fn start_scan(state: &mut AppState, tx: &Sender<AppEvent>) {
    state.begin_scan();
    app::spawn_scan(
        state.root.clone(),
        Arc::clone(&state.rules),
        state.baseline.clone(),
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
            "--rules" => {
                let dir = argv
                    .next()
                    .ok_or_else(|| "--rules requires a directory".to_string())?;
                args.rules.push(PathBuf::from(dir));
            }
            other => {
                if let Some(dir) = other.strip_prefix("--rules=") {
                    args.rules.push(PathBuf::from(dir));
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
    fn rejects_bad_input() {
        assert!(parse(&["--rules"]).is_err());
        assert!(parse(&["--nope"]).is_err());
        assert!(parse(&["a", "b"]).is_err());
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
