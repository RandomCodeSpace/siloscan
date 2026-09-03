//! Terminal shell: raw mode, alternate screen, mouse capture, and a panic hook
//! that restores all three before the default hook prints its message.

use std::io::{self, Stdout, Write};
use std::panic;
use std::sync::Once;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

static PANIC_HOOK: Once = Once::new();

/// Enter the full-screen UI. The panic hook is installed first so a failure
/// part-way through setup still leaves a restorable terminal.
///
/// The hook covers a panic, not an `Err`: a caller that gets one returns it and
/// never reaches `restore`. So a setup that fails after raw mode was enabled
/// undoes itself here, and `Err` from `init` always means the terminal is as it
/// was.
pub fn init() -> io::Result<Tui> {
    install_panic_hook();
    enable_raw_mode()?;
    enter().inspect_err(|_| {
        let _ = restore();
    })
}

/// The setup that follows raw mode, split out so its error path is a single
/// place to undo.
fn enter() -> io::Result<Tui> {
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(out))?;
    terminal.clear()?;
    Ok(terminal)
}

/// Undo `init`, in reverse order. Safe to call when the terminal is already
/// restored: every step is idempotent.
pub fn restore() -> io::Result<()> {
    let mut out = io::stdout();
    execute!(out, DisableMouseCapture, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    out.flush()
}

/// Chain a restore in front of the existing hook, once per process.
pub fn install_panic_hook() {
    PANIC_HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let _ = restore();
            previous(info);
        }));
    });
}
