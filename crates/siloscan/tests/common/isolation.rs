//! One rule for pointing a test run at directories the test owns.
//!
//! Included by every suite that spawns the binary, because the rule is subtle,
//! platform-dependent, and had already drifted into three not-quite-identical
//! copies when each suite kept its own.

use std::path::Path;
use std::process::Command;

/// Point `command`'s cache, saved-report state and home at directories this test
/// owns, as far as each platform lets a parent do that.
///
/// Unix redirects all of it. The cache root, the state root and the home
/// directory the state root falls back to are environment variables the binary
/// reads directly, so a child cannot reach the developer's own files.
///
/// Windows redirects the cache and nothing else, and the missing piece is not an
/// oversight. Its state root comes from `SHGetKnownFolderPath`, which reads no
/// environment variable of its own: it expands the registry's
/// `%USERPROFILE%\AppData\Local` against the child's environment and then, with
/// default flags, verifies the directory is really there. Pointing `USERPROFILE`
/// at a temporary directory therefore does not move the state root - it breaks
/// it, because `<temp>\AppData\Local` does not exist, and every run that needs a
/// state root fails with "no platform state directory is available". Passing
/// `KF_FLAG_DONT_VERIFY` in the binary to paper over that would hand back a
/// directory nothing created, and inventing a location is what the saved-report
/// contract refuses to do.
///
/// So a Windows child keeps the real profile and writes under the real local
/// application data folder. That is safe rather than merely tolerated: the scope
/// key is a SHA-256 over a canonical path inside this run's own temporary
/// directory, so it names a report directory that no other run and no real scan
/// can collide with.
///
/// `cfg!` rather than `#[cfg]` so both halves compile on every host and neither
/// can rot unnoticed.
pub fn isolate<'a>(
    command: &'a mut Command,
    cache: &Path,
    state: &Path,
    home: &Path,
) -> &'a mut Command {
    // `%LOCALAPPDATA%` is the cache root on Windows, per
    // `cache::default_cache_base`. It has nothing to do with the state root.
    command
        .env("XDG_CACHE_HOME", cache)
        .env("LOCALAPPDATA", cache);

    if cfg!(windows) {
        return command;
    }

    command
        .env("XDG_STATE_HOME", state)
        .env("HOME", home)
        .env("USERPROFILE", home)
        // Foundation's user home on macOS, so `URLForDirectory:inDomain:`
        // answers with a directory this run owns.
        .env("CFFIXED_USER_HOME", home)
}
