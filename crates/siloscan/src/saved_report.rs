//! Where a saved report lives, and how one replaces another.
//!
//! A scan report that `siloscan review` can open later is durable state, not a
//! cache and not repository data. This module owns the whole of that: the
//! platform state root, the identity a scan scope is filed under, the automatic
//! path built from the two, and the publication protocol that leaves a reader
//! with the old complete report or the new complete report and never a partial
//! one.
//!
//! Three rules shape everything below.
//!
//! - There is no fallback location. If the platform cannot name a state root,
//!   automatic persistence is unavailable and the caller exits 2. Guessing a
//!   writable directory would make review lookup depend on where the scan
//!   happened to fail.
//! - Automatic state never lands inside the tree being scanned. A state root
//!   under the scan boundary would become an input the same scan discovers, so
//!   containment is checked before any directory is created.
//! - Identity is the canonical requested path and its kind, hashed. Not a
//!   detected git root, not a manifest directory: the requested scope owns scan
//!   semantics, so it owns the report slot too.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use siloscan_core::plan::ScopeKind;

/// The application directory under the platform state root.
const APPLICATION_DIR: &str = "siloscan";

/// The fixed components under the application directory.
const REPORTS_DIR: &str = "reports";

/// The one automatic review candidate in a scope directory.
const LATEST_FILE: &str = "latest.json";

/// The domain separator and version of the scope-key encoding. It is part of
/// the hashed bytes so a future encoding change cannot silently collide with a
/// key written by this one.
const IDENTITY_PREFIX: &[u8] = b"siloscan-scan-scope\0sha256-v1\0";

/// How the report records the digest, so a reader can tell which encoding
/// produced it.
const IDENTITY_LABEL: &str = "sha256-v1";

/// The tag that says how the canonical path was turned into bytes.
///
/// `OsStr::as_encoded_bytes` is documented as unspecified and comparable only
/// within one Rust version and target, so it cannot be the persisted identity
/// encoding. These two are stable platform views instead.
#[cfg(unix)]
const PLATFORM_ENCODING: &[u8] = b"unix-bytes\0";
#[cfg(windows)]
const PLATFORM_ENCODING: &[u8] = b"windows-utf16le\0";

/// Distinguishes two temporaries written by one process. Process id alone is
/// not enough: two scans in one process would collide, and a reused process id
/// can collide with a stale file.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A requested scan scope, resolved to the identity it is filed under.
///
/// `canonical` is the path `std::fs::canonicalize` returned, so relative,
/// absolute and symlinked spellings of one scope produce one value. `measured`
/// is the directory the scan measures paths from, which is the scope itself for
/// a directory and the containing directory for a single file - the same rule
/// the scanner and the cache already use.
#[derive(Debug, Clone)]
pub struct CanonicalScope {
    canonical: PathBuf,
    measured: PathBuf,
    kind: ScopeKind,
}

impl CanonicalScope {
    /// The self-describing key the report records and the state directory is
    /// named by: `sha256-v1:<64 lowercase hex>`.
    pub fn identity(&self) -> String {
        format!("{IDENTITY_LABEL}:{}", self.digest())
    }

    /// The directory name under `reports/`: the full digest, never truncated.
    fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(IDENTITY_PREFIX);
        // `ScopeKind` is `#[non_exhaustive]`, but `canonical_scope` is the only
        // constructor and it produces exactly these two.
        hasher.update(match self.kind {
            ScopeKind::File => b"file\0".as_slice(),
            _ => b"directory\0".as_slice(),
        });
        hasher.update(PLATFORM_ENCODING);
        hasher.update(canonical_path_bytes(&self.canonical));

        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    pub fn kind(&self) -> ScopeKind {
        self.kind
    }
}

#[cfg(unix)]
fn canonical_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

/// Every `encode_wide` code unit, little-endian. Lossless for the Windows wide
/// paths that are not valid Unicode, which a `to_string_lossy` key would
/// collapse together.
#[cfg(windows)]
fn canonical_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    let mut bytes = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// Resolve `requested` to the scope it identifies.
///
/// The path must exist and be a regular file or a directory, which is the same
/// check a scan makes before it starts, and it must canonicalize: hashing a
/// display string would let two distinct non-Unicode paths share a report.
pub fn canonical_scope(requested: &Path) -> Result<CanonicalScope, String> {
    let metadata = fs::metadata(requested).map_err(|e| {
        format!(
            "{}: cannot resolve the scan scope: {e}",
            requested.display()
        )
    })?;
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(format!(
            "{}: a scan scope must be a directory or a regular file",
            requested.display()
        ));
    }
    let is_dir = metadata.is_dir();

    let canonical = requested.canonicalize().map_err(|e| {
        format!(
            "{}: cannot resolve the scan scope: {e}",
            requested.display()
        )
    })?;
    let (kind, measured) = match is_dir {
        true => (ScopeKind::Directory, canonical.clone()),
        false => (
            ScopeKind::File,
            canonical
                .parent()
                .ok_or_else(|| {
                    format!(
                        "{}: a single-file scope has no containing directory",
                        requested.display()
                    )
                })?
                .to_path_buf(),
        ),
    };

    Ok(CanonicalScope {
        canonical,
        measured,
        kind,
    })
}

/// This user's platform state root, or why there is not one.
///
/// Never falls back to the scanned repository, the working directory, the cache
/// directory, a temporary directory, or a machine-wide location. A caller that
/// cannot get one reports the problem and exits 2.
pub fn state_root() -> Result<PathBuf, String> {
    platform_state_root()
}

/// Linux and the other unix targets that are not macOS: `XDG_STATE_HOME` when
/// it is absolute, else `$HOME/.local/state`.
///
/// A relative `XDG_STATE_HOME` is invalid and is not resolved against the
/// working directory: doing so would let the launch directory move siloscan's
/// own state into the repository being scanned.
#[cfg(all(unix, not(target_os = "macos")))]
fn platform_state_root() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("XDG_STATE_HOME") {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            return Ok(path);
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home);
        if path.is_absolute() {
            return Ok(path.join(".local").join("state"));
        }
    }
    Err(no_state_root())
}

/// macOS: the user-domain Application Support directory Foundation reports.
///
/// `create` is false, so this asks where the directory is rather than making
/// one; the report directories below it are created by the caller with the
/// modes this module sets. The path is never assembled by hand from a home
/// directory, because a sandboxed or relocated container answers differently.
#[cfg(target_os = "macos")]
fn platform_state_root() -> Result<PathBuf, String> {
    use objc2_foundation::{NSFileManager, NSSearchPathDirectory, NSSearchPathDomainMask};

    let manager = NSFileManager::defaultManager();
    let url = manager
        .URLForDirectory_inDomain_appropriateForURL_create_error(
            NSSearchPathDirectory::ApplicationSupportDirectory,
            NSSearchPathDomainMask::UserDomainMask,
            None,
            false,
        )
        .map_err(|_| no_state_root())?;
    url.to_file_path().ok_or_else(no_state_root)
}

/// Windows: `FOLDERID_LocalAppData`, the per-user non-roaming application data
/// folder. Local rather than roaming because a report's identity is a local
/// checkout path, which does not travel with a roaming profile.
#[cfg(windows)]
fn platform_state_root() -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};

    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `FOLDERID_LocalAppData` is a valid known-folder id, the token is
    // null for the calling user, and `raw` is a valid out pointer.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, std::ptr::null_mut(), &mut raw) };
    if result < 0 || raw.is_null() {
        if !raw.is_null() {
            // SAFETY: the shell allocated `raw` with the task allocator.
            unsafe { CoTaskMemFree(raw.cast()) };
        }
        return Err(no_state_root());
    }

    // SAFETY: on success the shell returns a null-terminated wide string.
    let mut length = 0usize;
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `raw` is valid for `length` code units, as counted above.
    let units = unsafe { std::slice::from_raw_parts(raw, length) };
    let path = PathBuf::from(std::ffi::OsString::from_wide(units));
    // SAFETY: the shell allocated `raw` with the task allocator.
    unsafe { CoTaskMemFree(raw.cast()) };

    if path.as_os_str().is_empty() {
        return Err(no_state_root());
    }
    Ok(path)
}

/// The one message for "there is nowhere to save". It names both ways out, so
/// the user is not left to discover them.
fn no_state_root() -> String {
    "no platform state directory is available, so there is nowhere to save this report; \
     run with --no-save for a stateless scan, or --output FILE to choose a destination"
        .to_string()
}

/// The same absence, said to someone who was reading rather than writing.
///
/// `--no-save` and `--output` are answers to "where should this go"; a review
/// has already been written and is asking where it went, so the only thing left
/// to offer is a report file.
fn no_state_root_to_read() -> String {
    "no platform state directory is available, so there is no saved report to open; \
     name one with --report FILE"
        .to_string()
}

/// The automatic destination for `scope`, with its directories created.
///
/// Containment is checked before anything is created. The complete report
/// directory is resolved through its longest existing canonical ancestor, so a
/// symlink anywhere along the state path that leads back into the scan boundary
/// or into the repository around it is caught, not just a literal prefix match.
pub fn automatic_report_path(state_root: &Path, scope: &CanonicalScope) -> Result<PathBuf, String> {
    let report_dir = state_root
        .join(APPLICATION_DIR)
        .join(REPORTS_DIR)
        .join(scope.digest());

    let resolved = resolve_through_existing(&report_dir);
    for boundary in protected_boundaries(scope) {
        if resolved.starts_with(&boundary) {
            return Err(format!(
                "the automatic report directory would sit inside {}, which this scan reads; \
                 point XDG_STATE_HOME outside it, or run with --no-save or --output FILE",
                boundary.display()
            ));
        }
    }

    create_state_dir(state_root)?;
    create_state_dir(&state_root.join(APPLICATION_DIR))?;
    create_state_dir(&state_root.join(APPLICATION_DIR).join(REPORTS_DIR))?;
    create_state_dir(&report_dir)?;

    Ok(report_dir.join(LATEST_FILE))
}

/// The directories automatic state must stay out of: the scope the scan reads,
/// and the nearest repository boundary around it.
///
/// The repository lookup exists only to prevent a write. It does not promote
/// the scan scope and it adds no project fact.
fn protected_boundaries(scope: &CanonicalScope) -> Vec<PathBuf> {
    let mut boundaries = vec![scope.measured.clone()];
    if let Some(repo) = repository_boundary(&scope.measured)
        && repo != scope.measured
    {
        boundaries.push(repo);
    }
    boundaries
}

/// The nearest ancestor holding the marker git leaves at a repository root, by
/// the same test that bounds config discovery.
fn repository_boundary(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        let git = current.join(".git");
        let is_root = match git.metadata() {
            Ok(meta) if meta.is_dir() => git.join("HEAD").exists(),
            Ok(_) => true,
            Err(_) => false,
        };
        if is_root {
            return Some(current.to_path_buf());
        }
        dir = current.parent();
    }
    None
}

/// `path` with its longest existing ancestor canonicalized and the components
/// below it appended unchanged.
///
/// The whole path usually does not exist yet - that is what is about to be
/// created - so `canonicalize` on it would fail and tell us nothing. Resolving
/// the existing head is what makes a symlinked state directory visible.
fn resolve_through_existing(path: &Path) -> PathBuf {
    let mut remainder: Vec<&std::ffi::OsStr> = Vec::new();
    let mut current = path;
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut resolved = canonical;
            for component in remainder.iter().rev() {
                resolved.push(component);
            }
            return resolved;
        }
        match (current.file_name(), current.parent()) {
            (Some(name), Some(parent)) => {
                remainder.push(name);
                current = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Create one state directory if it is missing, with the private mode the XDG
/// specification asks for.
///
/// The mode is set on the directory this call created, so an unusually
/// restrictive umask cannot leave the writer unable to open its own report on
/// the next run. An existing directory is left exactly as it is: its
/// permissions are the user's business, not this scan's.
fn create_state_dir(path: &Path) -> Result<(), String> {
    if path.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|e| {
        format!(
            "{}: cannot create the report directory: {e}",
            path.display()
        )
    })?;
    set_private_dir_mode(path);
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

/// Created objects inherit the ACL of the local application data folder, which
/// is already per-user. No new ACL policy belongs here.
#[cfg(not(unix))]
fn set_private_dir_mode(_path: &Path) {}

/// The `latest.json` a review of `requested` opens, without creating anything.
///
/// There is no search: exactly one path is derived from the scope the caller
/// named. Falling back to the newest report of some other scope would open the
/// wrong findings, which is worse than saying the report is missing.
pub fn latest_report_path(requested: &Path) -> Result<PathBuf, String> {
    let scope = canonical_scope(requested)?;
    let root = state_root().map_err(|_| no_state_root_to_read())?;
    Ok(root
        .join(APPLICATION_DIR)
        .join(REPORTS_DIR)
        .join(scope.digest())
        .join(LATEST_FILE))
}

/// The directory a saved report's paths are measured from: `levels` parents
/// above the scope's own measured directory.
///
/// The report records the count rather than the text, because JSON cannot
/// losslessly round-trip every native path, and a count recovers the same base
/// without asking it to.
pub fn source_base(scope: &CanonicalScope, ancestor_levels: u32) -> Result<PathBuf, String> {
    let mut base = scope.measured.clone();
    for _ in 0..ancestor_levels {
        base = base
            .parent()
            .ok_or_else(|| {
                format!(
                    "the saved report is measured from {ancestor_levels} directories above {}, \
                     which does not exist",
                    scope.measured.display()
                )
            })?
            .to_path_buf();
    }
    Ok(base)
}

/// Serialize into a unique sibling temporary, synchronize it, and publish it
/// over `destination` with the platform's atomic replacement.
///
/// `serialize` writes the document body; the trailing newline is added here so
/// every saved report ends with exactly one. The old file is never truncated or
/// removed first, so a concurrent reader sees the old complete report or the
/// new complete one.
///
/// On any failure before publication the temporary this call created is
/// removed, best effort, and the existing report is left byte for byte as it
/// was. No other process's temporary is ever swept: it may still be being
/// written.
pub fn write_report_atomic<F>(
    destination: &Path,
    mode: TempMode,
    serialize: F,
) -> Result<(), String>
where
    F: FnOnce(&mut BufWriter<File>) -> io::Result<()>,
{
    let (temp_path, file) = create_temp(destination, mode)?;

    let file = match fill(file, serialize) {
        Ok(file) => file,
        Err(e) => {
            let _ = fs::remove_file(&temp_path);
            return Err(format!("{}: {e}", destination.display()));
        }
    };

    // The handle stays open across publication: the Windows rename is issued
    // through it, and it is closed only after the call succeeded.
    if let Err(e) = publish(&file, &temp_path, destination) {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return Err(format!("{}: {e}", destination.display()));
    }
    drop(file);

    sync_parent(destination).map_err(|e| {
        format!(
            "{}: the replacement may already be visible, but the directory could not be \
             synchronized: {e}",
            destination.display()
        )
    })
}

/// Write the body, flush the buffer, and synchronize contents and metadata.
///
/// Dropping a `File` ignores close errors, so `sync_all` is called explicitly
/// and its result is handled: a report that failed to reach the disk must not
/// be published over one that did.
fn fill<F>(file: File, serialize: F) -> io::Result<File>
where
    F: FnOnce(&mut BufWriter<File>) -> io::Result<()>,
{
    let mut writer = BufWriter::new(file);
    serialize(&mut writer)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    let file = writer
        .into_inner()
        .map_err(|e| io::Error::other(e.to_string()))?;
    file.sync_all()?;
    Ok(file)
}

/// A temporary beside `destination`, named after it, created if and only if it
/// did not exist.
///
/// The name carries the process id and a process-local counter, so two scans
/// never share one, and `create_new` makes the create-or-fail atomic. A stale
/// file left by a reused process id is stepped over rather than reused.
fn create_temp(destination: &Path, mode: TempMode) -> Result<(PathBuf, File), String> {
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = match parent {
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    };
    let name = destination
        .file_name()
        .ok_or_else(|| format!("{}: is not a file name", destination.display()))?
        .to_owned();

    for _ in 0..64 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut candidate = name.clone();
        candidate.push(format!(".{}.{counter}.tmp", std::process::id()));
        let path = parent.join(candidate);
        match temp_options(mode).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "{}: cannot create a temporary report file: {e}",
                    destination.display()
                ));
            }
        }
    }
    Err(format!(
        "{}: cannot create a temporary report file: every candidate name was taken",
        destination.display()
    ))
}

/// How private the temporary a report is written through is created.
///
/// Automatic state is siloscan's own file in siloscan's own directory, so it is
/// created `0600` whatever the umask says - a report the writer cannot reopen on
/// the next run is a slot that stops working. `--output` names a file the user
/// chose, and its mode is theirs: the umask decides, as it does for every other
/// file they ask a tool to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempMode {
    Private,
    Umask,
}

#[cfg(unix)]
fn temp_options(mode: TempMode) -> fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    if mode == TempMode::Private {
        options.mode(0o600);
    }
    options
}

/// The temporary is published by handle on Windows, so it is opened with the
/// `DELETE` access `FileRenameInfoEx` requires and shared with the delete
/// access a concurrent replacement of the destination needs.
///
/// [`TempMode`] has nothing to say here: created objects inherit the ACL of the
/// directory they are made in, which for automatic state is the per-user local
/// application data folder and for `--output` is whatever the user chose. No new
/// ACL policy belongs in this writer.
#[cfg(windows)]
fn temp_options(_mode: TempMode) -> fs::OpenOptions {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Foundation::GENERIC_WRITE;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };

    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_WRITE | DELETE | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    options
}

/// Unix publication: POSIX `rename`, which keeps the destination name visible
/// throughout and leaves it naming either the old file or the new one.
#[cfg(unix)]
fn publish(_file: &File, temp: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temp, destination)
}

/// Windows publication: `FileRenameInfoEx` with `REPLACE_IF_EXISTS` and
/// `POSIX_SEMANTICS`, through the still-open temporary handle.
///
/// Those flags are what give a reader holding the old file a valid handle to the
/// old bytes while every subsequent open sees the new file. `MoveFileExW`,
/// `ReplaceFileW` and delete-then-rename do not document that, so there is no
/// weaker fallback here: an unsupported publication fails visibly and the caller
/// exits 2.
#[cfg(windows)]
fn publish(file: &File, _temp: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_RENAME_INFO, FileRenameInfoEx, SetFileInformationByHandle,
    };

    const REPLACE_IF_EXISTS: u32 = 0x1;
    const POSIX_SEMANTICS: u32 = 0x2;

    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let name_bytes = std::mem::size_of_val(name.as_slice());
    let size = std::mem::size_of::<FILE_RENAME_INFO>() + name_bytes;
    // Allocated as `u64` so the buffer is aligned for the struct's handle
    // field; a `Vec<u8>` would only be byte aligned.
    let mut buffer: Vec<u64> = vec![0; size.div_ceil(std::mem::size_of::<u64>())];

    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buffer` is at least `size` bytes, aligned for the struct, and
    // `name` holds exactly `name.len()` code units.
    unsafe {
        (*info).Anonymous.Flags = REPLACE_IF_EXISTS | POSIX_SEMANTICS;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
    }

    // SAFETY: the handle is open with DELETE access and `buffer` holds a
    // complete `FILE_RENAME_INFO` of `size` bytes.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfoEx,
            buffer.as_ptr().cast(),
            size as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Linux does not persist a directory entry as part of a file's `fsync`, so the
/// parent is synchronized after publication. Elsewhere the rename is enough for
/// the guarantee this module claims.
#[cfg(target_os = "linux")]
fn sync_parent(destination: &Path) -> io::Result<()> {
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(target_os = "linux"))]
fn sync_parent(_destination: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn one_scope_has_one_key_however_it_is_spelled() {
        let dir = tempdir();
        let nested = dir.path().join("repo/src");
        fs::create_dir_all(&nested).unwrap();

        let absolute = canonical_scope(&nested).unwrap();
        let dotted = canonical_scope(&dir.path().join("repo/./src")).unwrap();
        let climbed = canonical_scope(&dir.path().join("repo/src/../src")).unwrap();

        assert_eq!(absolute.identity(), dotted.identity());
        assert_eq!(absolute.identity(), climbed.identity());
        assert!(absolute.identity().starts_with("sha256-v1:"));
        assert_eq!(absolute.identity().len(), "sha256-v1:".len() + 64);
    }

    #[test]
    fn a_nested_scope_and_a_file_scope_get_their_own_slots() {
        let dir = tempdir();
        let nested = dir.path().join("src");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("a.rs"), "fn main() {}\n").unwrap();

        let root = canonical_scope(dir.path()).unwrap();
        let child = canonical_scope(&nested).unwrap();
        let file = canonical_scope(&nested.join("a.rs")).unwrap();

        assert_ne!(root.identity(), child.identity());
        assert_ne!(child.identity(), file.identity());
        assert_eq!(file.kind(), ScopeKind::File);
        // A single-file scope measures from the directory holding it, which is
        // the directory a scan of that file reports paths against.
        assert_eq!(
            source_base(&file, 0).unwrap(),
            source_base(&child, 0).unwrap()
        );
    }

    #[test]
    fn a_missing_scope_is_an_error_rather_than_a_key() {
        let dir = tempdir();
        assert!(canonical_scope(&dir.path().join("absent")).is_err());
    }

    #[test]
    fn source_base_climbs_the_recorded_number_of_parents() {
        let dir = tempdir();
        let nested = dir.path().join("modules/api");
        fs::create_dir_all(&nested).unwrap();
        let scope = canonical_scope(&nested).unwrap();

        assert_eq!(
            source_base(&scope, 0).unwrap(),
            nested.canonicalize().unwrap()
        );
        assert_eq!(
            source_base(&scope, 2).unwrap(),
            dir.path().canonicalize().unwrap()
        );
        assert!(source_base(&scope, 4096).is_err());
    }

    #[test]
    fn a_state_root_inside_the_scanned_tree_is_refused_before_anything_is_created() {
        let dir = tempdir();
        let scope = canonical_scope(dir.path()).unwrap();
        let inside = dir.path().join("state");

        let error = automatic_report_path(&inside, &scope).unwrap_err();
        assert!(error.contains("--no-save"), "{error}");
        assert!(
            !inside.exists(),
            "nothing may be created before the refusal"
        );
    }

    /// The check is on the resolved path, not on the spelling: a symlinked
    /// state directory that lands back in the scan is the case a prefix
    /// comparison misses.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_state_ancestor_into_the_scope_is_refused() {
        let dir = tempdir();
        let scanned = dir.path().join("repo");
        fs::create_dir_all(&scanned).unwrap();
        let link = dir.path().join("state");
        std::os::unix::fs::symlink(&scanned, &link).unwrap();

        let scope = canonical_scope(&scanned).unwrap();
        assert!(automatic_report_path(&link, &scope).is_err());
    }

    /// Scanning a directory inside a repository must not put state anywhere in
    /// that repository either, or the next scan would find its own output.
    #[test]
    fn a_state_root_inside_the_repository_around_the_scope_is_refused() {
        let dir = tempdir();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        let module = dir.path().join("modules/api");
        fs::create_dir_all(&module).unwrap();

        let scope = canonical_scope(&module).unwrap();
        let inside = dir.path().join("elsewhere/state");
        let error = automatic_report_path(&inside, &scope).unwrap_err();
        assert!(error.contains("--output FILE"), "{error}");
    }

    #[test]
    fn an_outside_state_root_is_created_private_and_named_by_the_scope() {
        let dir = tempdir();
        let state = tempdir();
        let scope = canonical_scope(dir.path()).unwrap();

        let path = automatic_report_path(state.path(), &scope).unwrap();

        assert!(path.ends_with("latest.json"));
        let scope_dir = path.parent().unwrap();
        assert!(scope_dir.is_dir());
        assert_eq!(
            scope_dir.file_name().unwrap().to_str().unwrap().len(),
            64,
            "the key is the full digest"
        );
        assert!(scope_dir.starts_with(state.path().join("siloscan/reports")));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(scope_dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn publication_replaces_the_previous_report_and_leaves_no_temporary() {
        let dir = tempdir();
        let destination = dir.path().join("latest.json");
        fs::write(&destination, b"{\"old\":true}\n").unwrap();

        write_report_atomic(&destination, TempMode::Private, |writer| {
            writer.write_all(b"{\"new\":true}")
        })
        .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"{\"new\":true}\n");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name())
            .filter(|name| name != "latest.json")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_failed_serialization_leaves_the_previous_report_intact() {
        let dir = tempdir();
        let destination = dir.path().join("latest.json");
        fs::write(&destination, b"{\"old\":true}\n").unwrap();

        let error = write_report_atomic(&destination, TempMode::Private, |_| {
            Err(io::Error::other("serialization refused"))
        })
        .unwrap_err();

        assert!(error.contains("serialization refused"), "{error}");
        assert_eq!(fs::read(&destination).unwrap(), b"{\"old\":true}\n");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name())
            .filter(|name| name != "latest.json")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_missing_destination_directory_is_a_save_error() {
        let dir = tempdir();
        let destination = dir.path().join("absent/latest.json");
        assert!(
            write_report_atomic(&destination, TempMode::Private, |writer| writer
                .write_all(b"{}"))
            .is_err()
        );
    }
}
