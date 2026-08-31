//! Reusable live and snapshot sessions for the siloscan terminal UI.

mod actions;
mod app;
mod snapshot;
mod state;
mod term;
mod ui;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use siloscan_core::baseline;
use siloscan_core::config::{self, Config};
use siloscan_core::default_pack;
use siloscan_core::rules::{self, CompiledPayload, CompiledRule, RuleSet};

pub use app::WalkPolicy;

use app::AppEvent;
use state::{AppState, READ_ONLY_RESCAN, Screen};

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A live scan or a read-only report session.
#[derive(Debug)]
pub enum ReviewSession {
    /// Preserve the standalone TUI's current live setup until `ScanRequest`
    /// replaces these fields in the v2 session package.
    Live {
        path: PathBuf,
        rules: Vec<PathBuf>,
        no_default_rules: bool,
        config: Option<PathBuf>,
        walk: WalkPolicy,
    },
    /// Open an existing report without resolving or running a scan.
    SavedReport {
        report: PathBuf,
        source_base: PathBuf,
        config: Option<PathBuf>,
    },
}

/// A setup, terminal, or session failure returned to the caller after any
/// required terminal restoration has been attempted.
#[derive(Debug)]
pub struct TuiError(TuiErrorKind);

#[derive(Debug)]
enum TuiErrorKind {
    Setup(String),
    TerminalSetup(io::Error),
    Session(io::Error),
    TerminalRestore(io::Error),
}

impl fmt::Display for TuiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            TuiErrorKind::Setup(message) => formatter.write_str(message),
            TuiErrorKind::TerminalSetup(error) => {
                write!(formatter, "terminal setup failed: {error}")
            }
            TuiErrorKind::Session(error) => error.fmt(formatter),
            TuiErrorKind::TerminalRestore(error) => {
                write!(formatter, "terminal restore failed: {error}")
            }
        }
    }
}

impl std::error::Error for TuiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            TuiErrorKind::Setup(_) => None,
            TuiErrorKind::TerminalSetup(error)
            | TuiErrorKind::Session(error)
            | TuiErrorKind::TerminalRestore(error) => Some(error),
        }
    }
}

/// Run one TUI session. This function owns terminal setup and always attempts
/// restoration after an event-loop result before returning it to the caller.
pub fn run(session: ReviewSession) -> Result<(), TuiError> {
    let (mut state, config, walk) = match session {
        ReviewSession::Live {
            path,
            rules,
            no_default_rules,
            config,
            walk,
        } => {
            let (state, config) = boot_live(path, rules, no_default_rules, config)
                .map_err(|error| TuiError(TuiErrorKind::Setup(error)))?;
            (state, config, walk)
        }
        ReviewSession::SavedReport {
            report,
            source_base,
            config,
        } => {
            let (state, config) = load_snapshot(&report, &source_base, config.as_deref())
                .map_err(|error| TuiError(TuiErrorKind::Setup(error)))?;
            (state, config, WalkPolicy::default())
        }
    };

    let mut terminal =
        term::init().map_err(|error| TuiError(TuiErrorKind::TerminalSetup(error)))?;
    let result = run_session(&mut terminal, &mut state, config, walk);
    let restored = term::restore();

    result.map_err(|error| TuiError(TuiErrorKind::Session(error)))?;
    restored.map_err(|error| TuiError(TuiErrorKind::TerminalRestore(error)))?;
    Ok(())
}

/// Live boot: rules, config and baseline for the path to be scanned.
fn boot_live(
    path: PathBuf,
    mut dirs: Vec<PathBuf>,
    no_default_rules: bool,
    config_arg: Option<PathBuf>,
) -> Result<(AppState, Option<Arc<Config>>), String> {
    let (config, config_rule_dirs) = load_config(&path, config_arg.as_deref())?;
    dirs.extend(config_rule_dirs);

    let rules = Arc::new(load_rules(&path, &dirs, no_default_rules)?);
    require_silos(&rules, config.as_deref())?;
    let baseline = baseline::load(&path)
        .map_err(|error| error.to_string())?
        .map(Arc::new);

    Ok((AppState::new(path, rules, baseline), config))
}

/// Snapshot boot: the report supplies findings and metrics, so no rules,
/// baseline, or scan is resolved. The caller supplies the path base used for
/// source context; the standalone binary preserves its existing `.` base.
fn load_snapshot(
    report: &Path,
    source_base: &Path,
    config_arg: Option<&Path>,
) -> Result<(AppState, Option<Arc<Config>>), String> {
    let data = snapshot::load(report).map_err(|e| e.to_string())?;
    let (config, _) = load_config(source_base, config_arg)?;

    let mut state = AppState::new(
        source_base.to_path_buf(),
        Arc::new(RuleSet::default()),
        None,
    );
    app::apply_snapshot(&mut state, data, config.as_deref());
    Ok((state, config))
}

/// One scan starts up front; `r` starts another once the previous one is done.
/// Each iteration drains scan events, redraws, then waits up to
/// `POLL_INTERVAL` for input, so progress keeps ticking on an idle terminal.
fn run_session(
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

#[cfg(test)]
mod tests {
    use super::*;

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
