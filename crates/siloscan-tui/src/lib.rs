//! Reusable live and snapshot sessions for the siloscan terminal UI.
//!
//! [`ReviewSession`] is the whole entry point: one live session that scans, and
//! one read-only session that opens a report someone else saved. Both the
//! `siloscan-tui` binary and the `siloscan review` subcommand build one and
//! hand it to [`run`], so there is one setup path and one set of semantics
//! rather than one per front end.
//!
//! A live session owns a [`ScanRequest`] and nothing else about setup. The
//! config, the owning root, the anchoring, the baseline location, the rules,
//! the coverage report and the cache are all resolved by
//! [`ResolvedScanPlan`], which is the same resolution the CLI performs, so a
//! tree reviewed here and the same tree scanned from the command line cannot
//! disagree about where its config or its baseline lives.

mod actions;
mod app;
mod snapshot;
mod state;
mod term;
mod ui;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::Backend;
use siloscan_core::config::{self, Config};
use siloscan_core::plan::{ResolvedScanPlan, ScanRequest, ScanSetupReport};
use siloscan_core::rules::RuleSet;

pub use snapshot::ExpectedScope;

use app::AppEvent;
use state::{AppState, READ_ONLY_RESCAN, Screen};

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A live scan or a read-only report session.
#[derive(Debug)]
pub enum ReviewSession {
    /// Scan what `request` asks for, and scan it again on every `r`.
    Live { request: ScanRequest },
    /// Open an existing report without resolving a plan or running a scan.
    SavedReport {
        report: PathBuf,
        /// Directory the report's paths are read from, for the source pane.
        source_base: PathBuf,
        /// Config whose silos the module cards are grouped by. Discovered from
        /// `source_base` when absent.
        config: Option<PathBuf>,
        /// The scope this report has to describe, for an implicit latest
        /// lookup. `None` for an explicitly named report file, which is opened
        /// whatever scope it came from.
        expect: Option<ExpectedScope>,
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
    let mut open = OpenSession::open(session)?;

    let mut terminal =
        term::init().map_err(|error| TuiError(TuiErrorKind::TerminalSetup(error)))?;
    let result = open.event_loop(&mut terminal);
    let restored = term::restore();

    result.map_err(|error| TuiError(TuiErrorKind::Session(error)))?;
    restored.map_err(|error| TuiError(TuiErrorKind::TerminalRestore(error)))?;
    Ok(())
}

/// A session whose setup has finished and whose terminal has not been touched.
///
/// [`run`] is this plus the terminal and the input loop. The split is what lets
/// a setup refusal reach the caller before anything is drawn - the standalone
/// binary prints it and exits 2 with an untouched terminal - and what lets the
/// session tests drive a whole session against a test backend rather than a
/// pseudo-terminal.
pub struct OpenSession {
    state: AppState,
    /// The config the last report was resolved under, for the module cards.
    config: Option<Arc<Config>>,
    /// What a live session asks for, kept so every rescan can resolve its own
    /// plan. `None` for a saved report, which is what makes that session unable
    /// to scan rather than merely unwilling to.
    request: Option<ScanRequest>,
    tx: Sender<AppEvent>,
    rx: Receiver<AppEvent>,
}

impl OpenSession {
    /// Perform `session`'s setup and, for a live session, start its first scan.
    pub fn open(session: ReviewSession) -> Result<Self, TuiError> {
        let (tx, rx) = mpsc::channel();
        match session {
            ReviewSession::Live { request } => {
                // Resolved here rather than on the worker so that a refused
                // request - a missing root, an unreadable config, a boundary
                // rule with no silos - is returned to the caller with the
                // terminal as it was. Every later scan resolves its own plan on
                // the worker, where a refusal is a status line instead.
                let plan = ResolvedScanPlan::resolve(&request)
                    .map_err(|error| TuiError(TuiErrorKind::Setup(error.to_string())))?;

                let mut state =
                    AppState::new(request.root().to_path_buf(), Arc::new(RuleSet::default()));
                state.begin_scan();
                app::spawn_scan(plan, tx.clone());

                Ok(Self {
                    state,
                    config: None,
                    request: Some(request),
                    tx,
                    rx,
                })
            }
            ReviewSession::SavedReport {
                report,
                source_base,
                config,
                expect,
            } => {
                let data = snapshot::load(&report, expect.as_ref())
                    .map_err(|error| TuiError(TuiErrorKind::Setup(error.to_string())))?;
                let config = silo_config(&source_base, config.as_deref())
                    .map_err(|error| TuiError(TuiErrorKind::Setup(error)))?;

                let mut state = AppState::new(source_base, Arc::new(RuleSet::default()));
                app::apply_snapshot(&mut state, data, config.as_deref());

                Ok(Self {
                    state,
                    config,
                    request: None,
                    tx,
                    rx,
                })
            }
        }
    }

    /// Start another scan, resolving a fresh plan for it. A saved session never
    /// scans and this does nothing.
    pub fn rescan(&mut self) {
        let Some(request) = self.request.clone() else {
            return;
        };
        if self.state.scan_running {
            return;
        }
        self.state.begin_scan();
        app::spawn_fresh_scan(request, self.tx.clone());
    }

    /// Fold every scan event that has arrived into the session.
    pub fn drain(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                AppEvent::Progress(progress) => self.state.progress = Some(progress),
                AppEvent::ScanDone(resolved) => {
                    // Setup belongs to the plan, so the session takes what the
                    // scan ran under rather than resolving anything itself. The
                    // scan root and the baseline root are separate answers: a
                    // config-anchored scan reads sources from one and ratchets
                    // against the other.
                    let (report, setup, context) = resolved.into_parts();
                    self.state.root = context.scan_root().to_path_buf();
                    self.state.baseline_root = context.baseline_root().to_path_buf();
                    self.state.rules = Arc::new(context.rules().clone());
                    self.state.setup = Some(setup);
                    self.config = context.config().cloned().map(Arc::new);
                    app::apply_report(&mut self.state, report, self.config.as_deref());
                }
                AppEvent::Failed(message) => app::apply_failure(&mut self.state, message),
            }
        }
    }

    /// Draw one frame.
    pub fn draw<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<(), B::Error> {
        terminal.draw(|frame| ui::draw(frame, &self.state))?;
        Ok(())
    }

    /// The status line, which is where a session says what it is showing and
    /// what it is not.
    pub fn status(&self) -> &str {
        &self.state.status
    }

    /// True while a scan is running.
    pub fn is_scanning(&self) -> bool {
        self.state.scan_running
    }

    /// True when this session opened a report rather than scanning.
    pub fn is_read_only(&self) -> bool {
        self.state.is_snapshot()
    }

    /// What resolution found for the last live scan.
    pub fn setup(&self) -> Option<&ScanSetupReport> {
        self.state.setup.as_ref()
    }

    /// One scan is already running when a live session opens; `r` starts
    /// another once the previous one is done. Each iteration drains scan
    /// events, redraws, then waits up to `POLL_INTERVAL` for input, so progress
    /// keeps ticking on an idle terminal.
    fn event_loop(&mut self, terminal: &mut term::Tui) -> io::Result<()> {
        while !self.state.should_quit {
            self.drain();
            self.draw(terminal)?;

            if event::poll(POLL_INTERVAL)? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => self.on_key(key),
                    Event::Mouse(mouse) => ui::handle_mouse(&mut self.state, mouse),
                    // Resize needs no bookkeeping: the next draw re-lays out.
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Global bindings win unless a screen is capturing text (the filter box),
    /// in which case every key is forwarded verbatim. Ctrl-C always quits.
    fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.state.should_quit = true;
            return;
        }
        if self.state.captures_input() {
            ui::handle_key(&mut self.state, key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.state.should_quit = true,
            // A snapshot refuses with its reason in the status line and nothing
            // else.
            KeyCode::Char('r') => {
                if !self.state.refuse_if_snapshot(READ_ONLY_RESCAN) {
                    self.rescan();
                }
            }
            KeyCode::Char('1') => self.state.screen = Screen::Dashboard,
            KeyCode::Char('2') => self.state.screen = Screen::Triage,
            KeyCode::Char('3') => self.state.screen = Screen::Ratchet,
            KeyCode::Char('4') => self.state.screen = Screen::Silo,
            _ => ui::handle_key(&mut self.state, key),
        }
    }
}

/// The config whose silos a read-only session groups its module cards by.
///
/// This is the whole of a saved session's setup: no rules, no baseline, no
/// walk, no plan. The report already carries the findings and the metrics, and
/// resolving a plan to open one would be a scan nobody asked for.
///
/// An explicit `--config` must exist and parse; a discovered one is optional.
fn silo_config(base: &Path, explicit: Option<&Path>) -> Result<Option<Arc<Config>>, String> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => match config::discover(base) {
            Some(path) => path,
            None => return Ok(None),
        },
    };
    Ok(Some(Arc::new(config::load(&path)?)))
}
