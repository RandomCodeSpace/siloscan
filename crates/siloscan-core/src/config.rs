//! Optional repository configuration (`siloscan.toml`).
//!
//! The config is discovered from the scan root upwards and never from the user
//! environment: no home-directory config, no environment variables. A scan of
//! the same tree therefore resolves the same config on every machine.
//!
//! Discovery ascends from the scan root and stops at a repository boundary - a
//! `.git` entry at or above the scan root - or at the filesystem root,
//! whichever comes first. A `siloscan.toml` found above the scan root in a tree
//! with no repository marker is *not* adopted: the ascent reaches the
//! filesystem root, and what it found on the way is discarded rather than used.
//!
//! The consequence is worth stating plainly, because it is the difference
//! between a scan that is configured and one that silently is not: an exported
//! tarball, a `git archive` checkout, or any copy of a subtree without its
//! `.git` scans with no config at all. Silos, source roots and the anchor are
//! then undefined, and rules that need them are refused rather than quietly
//! skipped. Pass `--config` explicitly for those trees.
//!
//! The boundary is deliberate. Without it, a config anywhere above a scan root
//! (a stray file in `/tmp`, a home directory, a shared build agent's working
//! directory) would reach into the scan and change what it looks at, and the
//! same tree would scan differently depending on where it happened to be
//! unpacked.
//!
//! A root config may pull in module-level configs with `include`. An included
//! file contributes silos, source roots and rule directories and nothing else,
//! and every path it declares is relative to the included file itself; `load`
//! rewrites those paths so that the merged [`Config`] speaks one convention:
//! forward-slash paths relative to the directory holding the root config.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

pub const CONFIG_NAME: &str = "siloscan.toml";

const fn default_min_lines() -> usize {
    10
}

/// Largest file, in bytes, that is handed to a parser: 2 MiB.
///
/// Parsing costs memory in the tens of times the source size, so a generated
/// bundle or a vendored blob can turn a scan into hundreds of megabytes of
/// parser state for findings nobody reads. Above the cap a file still goes
/// through every engine that works on text; only its tree is never built.
pub const DEFAULT_MAX_PARSE_BYTES: u64 = 2 * 1024 * 1024;

const fn default_max_parse_bytes() -> u64 {
    DEFAULT_MAX_PARSE_BYTES
}

/// The directory every path a scan reports is relative to.
///
/// One convention holds for a whole scan: fingerprints, displayed paths, JSON
/// and SARIF output, baseline entries and metrics keys all use the same
/// anchor, so a fingerprint never depends on where the scan was started from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Anchor {
    /// Paths are relative to the scan root. The default, and the only
    /// behaviour before this key existed.
    #[default]
    ScanRoot,
    /// Paths are relative to the directory holding the root config file, so a
    /// module scan and a whole-repository scan agree on every path.
    Config,
}

impl Anchor {
    /// The spelling used in config files and in the JSON report.
    pub const fn as_str(self) -> &'static str {
        match self {
            Anchor::ScanRoot => "scan-root",
            Anchor::Config => "config",
        }
    }
}

/// Duplication detection settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicationConfig {
    #[serde(default = "default_min_lines")]
    pub min_lines: usize,

    /// Whether every copy of every duplicated block is reported as its own
    /// `metrics.duplicate-block` info finding.
    ///
    /// Off by default, and the numbers are unaffected either way: duplication
    /// is always measured, `metrics.files[*].duplicated_lines`, the totals and
    /// the density are always reported. What this key controls is only whether
    /// the per-copy locations are emitted as findings.
    ///
    /// The default is off because those findings are per copy of every block in
    /// the tree, so on a real repository they outnumber every other finding by
    /// two or three orders of magnitude - the count that made a SARIF report
    /// too large for GitHub code scanning to ingest, and that buried the
    /// secrets a scan exists to surface. Nothing is hidden by the default: the
    /// duplication a reader acts on is in the metrics line, and turning this on
    /// (or loading a duplication rule, which turns it on by itself - see
    /// `scan::report_duplicate_blocks`) produces exactly the findings 1.3.0
    /// produced, fingerprints included.
    #[serde(default)]
    pub report_blocks: bool,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        DuplicationConfig {
            min_lines: 10,
            report_blocks: false,
        }
    }
}

/// Bounds on the work one file may cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Files larger than this are never parsed. Measured on the file's bytes.
    #[serde(default = "default_max_parse_bytes")]
    pub max_parse_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_parse_bytes: DEFAULT_MAX_PARSE_BYTES,
        }
    }
}

/// Repository configuration. Every section is optional; the default value is a
/// config that changes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Silo name -> path globs, matched against repo-relative forward-slash
    /// paths.
    #[serde(default)]
    pub silos: BTreeMap<String, Vec<String>>,

    /// Directories that import resolution may anchor to, repo-relative. Empty
    /// means the repository root only.
    #[serde(default)]
    pub source_roots: Vec<String>,

    /// File extension (without the dot) -> language name override.
    #[serde(default)]
    pub languages: BTreeMap<String, String>,

    /// Extra rule directories, relative to the directory holding the config
    /// file.
    #[serde(default)]
    pub rules: Vec<String>,

    /// Duplication detection settings. Root-only key.
    #[serde(default)]
    pub duplication: DuplicationConfig,

    /// Bounds on the work one file may cost. Root-only key.
    #[serde(default)]
    pub limits: LimitsConfig,

    /// The directory every reported path is relative to. Root-only key.
    #[serde(default)]
    pub anchor: Anchor,

    /// Config files to merge, relative to the directory holding this file.
    /// Root-only key: an included file may not include further files.
    #[serde(default)]
    pub include: Vec<String>,

    /// Directory holding the root config file. Not a config key: [`load`]
    /// fills it in, and every relative path above resolves against it.
    #[serde(skip)]
    pub config_dir: PathBuf,
}

/// The keys an included config may set. Everything else - `anchor`,
/// `duplication`, `languages`, `include`, and every root-only key added later -
/// is rejected by `deny_unknown_fields` with the offending key in the message.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIncludedConfig {
    #[serde(default)]
    silos: BTreeMap<String, Vec<String>>,

    #[serde(default)]
    source_roots: Vec<String>,

    #[serde(default)]
    rules: Vec<String>,

    /// Accepted only so that a nested `include` gets a message about the
    /// single-level rule instead of a bare "unknown field".
    #[serde(default)]
    include: Option<Vec<String>>,
}

/// True when `name` is a well-formed silo name (`^[a-z0-9-]+$`).
pub fn is_silo_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Nearest `siloscan.toml` at or above `scan_root`.
///
/// A config in the scan root itself always counts. Ascending above the scan
/// root requires evidence that the scan root is part of a repository, so an
/// ancestor's config is adopted only once a `.git` entry is found at or above
/// it; the walk stops there. Without a VCS marker nothing above the scan root
/// is read, which keeps a stray config in `$HOME` or `/` out of the scan.
pub fn discover(scan_root: &Path) -> Option<PathBuf> {
    let start = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());

    let mut found: Option<PathBuf> = None;
    let mut dir = start.as_path();
    loop {
        if found.is_none() {
            let candidate = dir.join(CONFIG_NAME);
            if candidate.is_file() {
                if dir == start.as_path() {
                    return Some(candidate);
                }
                found = Some(candidate);
            }
        }
        if is_repo_root(dir) {
            return found;
        }
        dir = dir.parent()?;
    }
}

/// True when `dir` is the root of a git repository: a `.git` directory holding
/// a `HEAD`, or the `.git` file a worktree or submodule uses. An empty `.git`
/// directory is not a repository, and treating it as one would let a stray
/// entry (`/tmp/.git` is a real example) turn an unrelated ancestor into a
/// repository root.
fn is_repo_root(dir: &Path) -> bool {
    let git = dir.join(".git");
    match git.metadata() {
        Ok(meta) if meta.is_dir() => git.join("HEAD").exists(),
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Read and validate a config file, merging every file it includes. Errors
/// carry the path of the file that holds the mistake.
pub fn load(path: &Path) -> Result<Config, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut config: Config =
        toml::from_str(&src).map_err(|e| format!("{}: {e}", path.display()))?;
    config.config_dir = config_dir_of(path);

    check_silo_names(config.silos.keys(), path)?;

    // The tree being scanned is untrusted input, and its `siloscan.toml` is
    // discovered and loaded without anyone naming it, so a path declared inside
    // it may not point outside the config root: an absolute path or a `..`
    // climb would read a directory the caller never pointed the scanner at and
    // echo what it found there in load errors. The escape hatch is `--rules` on
    // the command line, where the person typing the path chose it.
    config.source_roots = contain(&config.source_roots, path, "source_roots")?;
    config.rules = contain(&config.rules, path, "rules")?;

    if config.duplication.min_lines < 2 {
        return Err(format!(
            "{}: duplication.min_lines must be at least 2, got {}",
            path.display(),
            config.duplication.min_lines
        ));
    }

    // Zero would read as "no limit" to whoever wrote it and would mean "parse
    // nothing" to the scanner, so it is refused rather than silently disabling
    // every ast and boundary rule in the pack.
    if config.limits.max_parse_bytes == 0 {
        return Err(format!(
            "{}: limits.max_parse_bytes must be at least 1, got 0",
            path.display()
        ));
    }

    // Silo origins, so a collision can name both declaring files.
    let mut origins: BTreeMap<String, PathBuf> = config
        .silos
        .keys()
        .map(|name| (name.clone(), path.to_path_buf()))
        .collect();

    let includes = config.include.clone();
    let mut merged: Vec<PathBuf> = Vec::with_capacity(includes.len());
    for entry in &includes {
        merge_include(&mut config, path, entry, &mut origins, &mut merged)?;
    }

    // Compiling the sets is the glob validation, for merged silos too.
    config
        .silo_sets()
        .map_err(|e| format!("{}: {e}", path.display()))?;

    Ok(config)
}

/// The directory holding `path`, as a directory that can be joined against and
/// measured from. `Path::parent` of a bare filename is `Some("")`, which names
/// no directory at all: `--config siloscan.toml` would otherwise leave the
/// config root empty and `anchor = "config"` would refuse a config that loaded
/// perfectly well.
fn config_dir_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Reject silo names that are not `^[a-z0-9-]+$`, naming the declaring file.
fn check_silo_names<'a>(
    names: impl Iterator<Item = &'a String>,
    file: &Path,
) -> Result<(), String> {
    for name in names {
        if !is_silo_name(name) {
            return Err(format!(
                "{}: invalid silo name: {name} (expected ^[a-z0-9-]+$)",
                file.display()
            ));
        }
    }
    Ok(())
}

/// Read one included config and merge its contributions into `config`.
///
/// `root_path` is the root config file, which is the one that got the include
/// wrong when the entry itself is unusable; mistakes inside the included file
/// are reported against that file.
fn merge_include(
    config: &mut Config,
    root_path: &Path,
    entry: &str,
    origins: &mut BTreeMap<String, PathBuf>,
    merged: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let prefix = include_prefix(root_path, entry)?;
    let root_dir = config.config_dir.clone();
    let file = root_dir.join(entry);
    // The lexical guard in `include_prefix` is not the whole of it: a symlink
    // inside the tree is a path with no `..` in it that still lands outside the
    // config root. See `confine`.
    confine(&root_dir, &file, root_path, "include", entry)?;

    if merged.contains(&file) {
        return Err(format!(
            "{}: include {entry:?} is listed more than once",
            root_path.display()
        ));
    }
    merged.push(file.clone());

    let src = fs::read_to_string(&file).map_err(|e| {
        format!(
            "{}: cannot read included config {}: {e}",
            root_path.display(),
            file.display()
        )
    })?;
    let raw: RawIncludedConfig = toml::from_str(&src).map_err(|e| {
        format!(
            "{}: {e} (an included config may set only silos, source_roots and rules)",
            file.display()
        )
    })?;

    if raw.include.is_some() {
        return Err(format!(
            "{}: include is not allowed in an included config (include is single level)",
            file.display()
        ));
    }

    check_silo_names(raw.silos.keys(), &file)?;
    for (name, patterns) in raw.silos {
        if let Some(first) = origins.get(&name) {
            return Err(format!(
                "{}: duplicate silo name: {name} (declared in {} and in {})",
                root_path.display(),
                first.display(),
                file.display()
            ));
        }
        let mut globs = Vec::with_capacity(patterns.len());
        for pattern in &patterns {
            globs.push(rebase(
                &prefix,
                pattern,
                &file,
                "silo glob",
                Rebased::SiloGlob,
            )?);
        }
        origins.insert(name.clone(), file.clone());
        config.silos.insert(name, globs);
    }

    for source_root in &raw.source_roots {
        config.source_roots.push(declared_path(
            &root_dir,
            &prefix,
            source_root,
            &file,
            "source_roots",
        )?);
    }

    // Rule directories are held to the same boundary as everything else a
    // config declares. An included file is as much part of the untrusted tree
    // as the root config is, so letting it name a directory outside the config
    // root would leave the root guard bypassable by one `include` line.
    for dir in &raw.rules {
        config
            .rules
            .push(declared_path(&root_dir, &prefix, dir, &file, "rules")?);
    }

    Ok(())
}

/// Resolve every entry of a path-valued key declared by the root config,
/// confined to the config root.
fn contain(entries: &[String], file: &Path, key: &str) -> Result<Vec<String>, String> {
    let root_dir = config_dir_of(file);
    entries
        .iter()
        .map(|entry| declared_path(&root_dir, &[], entry, file, key))
        .collect()
}

/// One filesystem path declared inside a config file: resolved against
/// `prefix`, and an error when it names anything outside the config root -
/// lexically, and then again on the filesystem (see [`confine`]). `key` is the
/// config key it came from, so the message points at the line to change.
///
/// `root_dir` is the root config's directory, which every rebased path is
/// relative to; `file` is the config file that declared the entry, which is the
/// one an error names.
fn declared_path(
    root_dir: &Path,
    prefix: &[String],
    rel: &str,
    file: &Path,
    key: &str,
) -> Result<String, String> {
    if is_rooted(rel) {
        return Err(format!(
            "{}: {key} {rel:?} must be a relative path inside the config root",
            file.display()
        ));
    }
    let rebased = rebase(prefix, rel, file, key, Rebased::Path)?;
    confine(root_dir, &root_dir.join(&rebased), file, key, rel)?;
    Ok(rebased)
}

/// Refuse a path that leaves the config root once the filesystem has its say.
///
/// [`rebase`] and [`include_prefix`] resolve `..` textually, which a symlink
/// defeats: with `link -> ../outside` inside the tree, `rules = ["link"]` holds
/// no `..` at all and still reads a directory the scanner was never pointed at.
/// The symlink and the config that names it are both content of the untrusted
/// tree, so this is the same attack the lexical guard exists to stop, one
/// indirection later. The escape hatch stays `--rules` on the command line,
/// where the person typing the path chose it.
///
/// Both sides are resolved to their deepest existing ancestor rather than
/// canonicalised outright, because [`fs::canonicalize`] fails on a path that
/// does not exist and a rule directory that is simply missing must still
/// produce the missing-directory error the user can act on rather than a
/// containment error that misnames the problem. Every component that exists is
/// resolved, so a symlink anywhere along the path is followed and caught, and
/// only a tail that exists nowhere is appended textually - a tail that reads
/// nothing.
///
/// A config root that cannot be resolved is refused rather than waved through:
/// containment that cannot be evaluated does not get to pass.
fn confine(root_dir: &Path, path: &Path, file: &Path, key: &str, rel: &str) -> Result<(), String> {
    let escaped = || {
        format!(
            "{}: {key} {rel:?} resolves outside the config root",
            file.display()
        )
    };
    let Some(root) = resolve_existing(root_dir) else {
        return Err(escaped());
    };
    match resolve_existing(path) {
        Some(resolved) if resolved.starts_with(&root) => Ok(()),
        Some(_) => Err(escaped()),
        // Nothing of the path exists, so it reads nothing and names nothing
        // outside the root; whatever wanted it reports its own absence.
        None => Ok(()),
    }
}

/// `path` with every component that exists resolved through symlinks, and the
/// non-existent tail appended as written.
///
/// `None` when not even the outermost component resolves, which for a path
/// built on a config root that was just read from disk means the root itself
/// went away.
fn resolve_existing(path: &Path) -> Option<PathBuf> {
    let mut base = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(mut resolved) = fs::canonicalize(&base) {
            for name in tail.iter().rev() {
                resolved.push(name);
            }
            return Some(resolved);
        }
        let name = base.file_name()?.to_os_string();
        tail.push(name);
        if !base.pop() {
            return None;
        }
    }
}

/// True when an entry names a filesystem root rather than something below the
/// config root: absolute on this platform, a leading separator in either
/// spelling, or a Windows drive prefix. The last two are checked as text
/// because a config written on one platform is read on every other, and a path
/// that is absolute where it was written must not become a relative one here.
fn is_rooted(rel: &str) -> bool {
    if Path::new(rel).is_absolute() || rel.starts_with('/') || rel.starts_with('\\') {
        return true;
    }
    let bytes = rel.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// The directory of an included file, as forward-slash path components
/// relative to the root config directory.
fn include_prefix(root_path: &Path, entry: &str) -> Result<Vec<String>, String> {
    if is_rooted(entry) {
        return Err(format!(
            "{}: include {entry:?} must be a relative path",
            root_path.display()
        ));
    }

    let mut segments: Vec<&str> = entry.split(['/', '\\']).collect();
    let name = segments.pop().unwrap_or("");
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!(
            "{}: include {entry:?} must name a config file",
            root_path.display()
        ));
    }

    // An included file lives inside the config root like everything else the
    // config names. Reading one above it would pull an arbitrary TOML file from
    // outside the scanned tree into the scan and quote it back in load errors.
    let mut parts: Vec<String> = Vec::new();
    for segment in segments {
        match segment {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!(
                        "{}: include {entry:?} resolves outside the config root",
                        root_path.display()
                    ));
                }
            }
            other => parts.push(other.to_string()),
        }
    }
    Ok(parts)
}

/// What an entry declared by a config file is, which decides how it splits into
/// segments.
#[derive(Clone, Copy)]
enum Rebased {
    /// A silo glob. Splits on `/` only: `\` is globset's escape character, so
    /// treating it as a separator would rewrite the pattern - `a\[0\].rs` would
    /// become `a/[0/].rs`, a silently different glob.
    SiloGlob,
    /// A filesystem path.
    Path,
}

impl Rebased {
    /// Separators that split an entry of this kind into segments.
    fn separators(self) -> &'static [char] {
        match self {
            Rebased::SiloGlob => &['/'],
            Rebased::Path => &['/', '\\'],
        }
    }
}

/// Join `prefix` with an entry declared inside a config file, resolving `.` and
/// `..` lexically. A result that climbs above the config root is an error. Such
/// an entry is either a pattern that could never match a repository-relative
/// path, where silently keeping it would be a rule that never fires, or a
/// directory outside the tree the scanner was pointed at.
fn rebase(
    prefix: &[String],
    rel: &str,
    file: &Path,
    subject: &str,
    kind: Rebased,
) -> Result<String, String> {
    let escaped = |rel: &str| {
        format!(
            "{}: {subject} {rel:?} resolves outside the config root",
            file.display()
        )
    };

    let mut parts: Vec<&str> = prefix.iter().map(String::as_str).collect();
    for segment in rel.split(kind.separators()) {
        match segment {
            "" | "." => {}
            ".." => match parts.last() {
                Some(&last) if last != ".." => {
                    parts.pop();
                }
                _ => return Err(escaped(rel)),
            },
            other => parts.push(other),
        }
    }

    if parts.first() == Some(&"..") {
        return Err(escaped(rel));
    }
    if parts.is_empty() {
        return Ok(".".to_string());
    }
    Ok(parts.join("/"))
}

impl Config {
    /// Directory holding the root config file. Every relative path in the
    /// merged config resolves against it, and it is the anchor directory when
    /// [`Config::anchor`] is [`Anchor::Config`].
    pub fn config_root(&self) -> &Path {
        &self.config_dir
    }

    /// Extra rule directories, resolved against the config root. Directories
    /// contributed by an included file are already rebased onto it.
    pub fn rule_dirs(&self) -> Vec<PathBuf> {
        self.rules
            .iter()
            .map(|rel| self.config_dir.join(rel))
            .collect()
    }

    /// Directories above the scan root whose ignore files this config brings
    /// into scope, outermost first: the config root and every directory between
    /// it and `scan_root`, the scan root itself excluded - a walk reads the
    /// ignore files inside its own root already. Empty under
    /// `anchor = "scan-root"`, when no config was loaded from disk, and when
    /// the scan root is not inside the config root.
    ///
    /// `anchor = "config"` declares the config root as the project boundary, so
    /// the project's own ignore files are in-scope by definition, and this is
    /// exactly what makes module and root scans produce comparable results: a
    /// file the repository ignores must be absent from a module scan too,
    /// otherwise it shows up only there and a baseline written from the
    /// repository root does not cover it. Sources outside the config root stay
    /// excluded - this widens the boundary to the declared project and no
    /// further.
    pub fn project_ignore_dirs(&self, scan_root: &Path) -> Vec<PathBuf> {
        if self.anchor != Anchor::Config || self.config_dir.as_os_str().is_empty() {
            return Vec::new();
        }

        // Both sides are canonicalised, so `.`, `..` and symlinks in either
        // argument do not decide whether one contains the other.
        let canonical = |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let base = canonical(&self.config_dir);
        let mut scanned = canonical(scan_root);
        if !scanned.is_dir() {
            // A single-file scan root: the directory holding it is what sits
            // under the config root.
            match scanned.parent() {
                Some(parent) => scanned = parent.to_path_buf(),
                None => return Vec::new(),
            }
        }

        let Ok(tail) = scanned.strip_prefix(&base) else {
            return Vec::new();
        };

        let mut dirs = Vec::new();
        let mut dir = base;
        for segment in tail.components() {
            dirs.push(dir.clone());
            dir.push(segment);
        }
        dirs
    }

    /// Compiled silo globs, sorted by silo name.
    pub fn silo_sets(&self) -> Result<Vec<(String, GlobSet)>, String> {
        let mut sets = Vec::with_capacity(self.silos.len());
        // `BTreeMap` iterates in key order, so `sets` is sorted by name.
        for (name, patterns) in &self.silos {
            let mut builder = GlobSetBuilder::new();
            for pattern in patterns {
                let glob = Glob::new(pattern)
                    .map_err(|e| format!("silo {name}: invalid glob {pattern:?}: {e}"))?;
                builder.add(glob);
            }
            let set = builder
                .build()
                .map_err(|e| format!("silo {name}: invalid globs: {e}"))?;
            sets.push((name.clone(), set));
        }
        Ok(sets)
    }

    /// The silo owning `path_rel`, or `None` when no silo matches. `sets` must
    /// come from [`Config::silo_sets`]; overlapping silos resolve to the
    /// alphabetically first matching name, which makes the assignment
    /// deterministic rather than dependent on config file order.
    pub fn silo_of<'a>(&self, sets: &'a [(String, GlobSet)], path_rel: &str) -> Option<&'a str> {
        sets.iter()
            .find(|(_, set)| set.is_match(path_rel))
            .map(|(name, _)| name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
source_roots = ["src", "lib"]
rules = ["rules/local"]

[silos]
api = ["crates/api/**"]
core = ["crates/core/**", "crates/shared/**"]

[languages]
mjs = "javascript"
"#;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        path
    }

    /// Mark `dir` as a repository root the way git does.
    fn git_root(dir: &Path) {
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    #[test]
    fn parses_every_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, SAMPLE);
        let config = load(&path).expect("should load");

        assert_eq!(config.silos.keys().collect::<Vec<_>>(), vec!["api", "core"]);
        assert_eq!(config.silos["core"].len(), 2);
        assert_eq!(config.source_roots, vec!["src", "lib"]);
        assert_eq!(config.languages["mjs"], "javascript");
        assert_eq!(config.rules, vec!["rules/local"]);
    }

    #[test]
    fn empty_config_is_default_apart_from_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        let expected = Config {
            config_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        assert_eq!(load(&path).unwrap(), expected);
    }

    #[test]
    fn config_root_is_the_directory_of_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "rules = [\"rules/local\"]\n");
        let config = load(&path).expect("should load");

        assert_eq!(config.config_root(), dir.path());
        assert_eq!(config.rule_dirs(), vec![dir.path().join("rules/local")]);
    }

    #[test]
    fn config_root_of_a_bare_filename_is_the_current_directory() {
        // `Path::parent` of a bare filename is `Some("")`, which anchoring
        // cannot measure from: `--config siloscan.toml` must still name a
        // directory.
        assert_eq!(config_dir_of(Path::new(CONFIG_NAME)), Path::new("."));
        assert_eq!(
            config_dir_of(Path::new("modules/api/siloscan.toml")),
            Path::new("modules/api")
        );
    }

    #[test]
    fn unknown_key_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "nonsense = true\n");
        assert!(load(&path).is_err());
    }

    #[test]
    fn bad_silo_name_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "[silos]\n\"Api Layer\" = [\"a/**\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("invalid silo name"), "{err}");
    }

    #[test]
    fn bad_glob_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[silos]\napi = [\"a[b\"]\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("invalid glob"), "{err}");
    }

    #[test]
    fn discover_walks_up_to_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("repo/src/deep")).unwrap();
        git_root(&root.join("repo"));
        let expected = write(&root.join("repo"), CONFIG_NAME, "");

        let found = discover(&root.join("repo/src/deep")).expect("should discover");
        assert_eq!(found, expected.canonicalize().unwrap());
    }

    #[test]
    fn discover_stops_at_the_git_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("repo/src")).unwrap();
        git_root(&root.join("repo"));
        // Config lives above the repository: out of reach.
        write(root, CONFIG_NAME, "");

        assert_eq!(discover(&root.join("repo/src")), None);
    }

    #[test]
    fn discover_finds_a_config_in_the_scan_root_without_a_vcs_marker() {
        let dir = tempfile::tempdir().unwrap();
        let expected = write(dir.path(), CONFIG_NAME, "");

        let found = discover(dir.path()).expect("should discover");
        assert_eq!(found, expected.canonicalize().unwrap());
    }

    #[test]
    fn discover_ignores_an_ancestor_config_without_a_vcs_marker() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("repo/src")).unwrap();
        // No `.git` anywhere: nothing above the scan root is in reach.
        write(root, CONFIG_NAME, "");

        assert_eq!(discover(&root.join("repo")), None);
        assert_eq!(discover(&root.join("repo/src")), None);
    }

    #[test]
    fn silo_of_prefers_the_alphabetically_first_match() {
        let config: Config = toml::from_str(
            r#"
[silos]
zulu = ["src/**"]
alpha = ["src/**"]
"#,
        )
        .unwrap();
        let sets = config.silo_sets().unwrap();

        assert_eq!(
            sets.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "zulu"]
        );
        assert_eq!(config.silo_of(&sets, "src/main.rs"), Some("alpha"));
        assert_eq!(config.silo_of(&sets, "docs/readme.md"), None);
    }

    #[test]
    fn duplication_absent_defaults_to_10() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        let config = load(&path).expect("should load");
        assert_eq!(config.duplication.min_lines, 10);
    }

    #[test]
    fn duplication_explicit_value_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[duplication]\nmin_lines = 5\n");
        let config = load(&path).expect("should load");
        assert_eq!(config.duplication.min_lines, 5);
    }

    /// The key that brings the per-block findings back. Off unless asked for,
    /// on both the absent-section and the present-section paths, because those
    /// are two different serde defaults and only one of them is the struct's.
    #[test]
    fn duplication_report_blocks_defaults_to_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        assert!(!load(&path).unwrap().duplication.report_blocks);

        let path = write(dir.path(), "other.toml", "[duplication]\nmin_lines = 5\n");
        assert!(!load(&path).unwrap().duplication.report_blocks);

        assert!(!DuplicationConfig::default().report_blocks);
    }

    #[test]
    fn duplication_report_blocks_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "[duplication]\nreport_blocks = true\n",
        );
        let config = load(&path).expect("should load");
        assert!(config.duplication.report_blocks);
        // Independent of the window: turning the findings on must not move what
        // counts as a duplicate.
        assert_eq!(config.duplication.min_lines, 10);

        let path = write(
            dir.path(),
            "off.toml",
            "[duplication]\nmin_lines = 4\nreport_blocks = false\n",
        );
        let config = load(&path).expect("should load");
        assert!(!config.duplication.report_blocks);
        assert_eq!(config.duplication.min_lines, 4);
    }

    /// An included config may not turn the findings on: `duplication` is a
    /// root-only key, and a module quietly changing what the whole scan reports
    /// is the thing root-only keys exist to prevent.
    #[test]
    fn include_cannot_set_report_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            "[duplication]\nreport_blocks = true\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("duplication"), "{err}");
    }

    #[test]
    fn duplication_min_lines_zero_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[duplication]\nmin_lines = 0\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("min_lines must be at least 2"), "{err}");
        assert!(err.contains("0"), "{err}");
    }

    #[test]
    fn duplication_min_lines_one_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[duplication]\nmin_lines = 1\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("min_lines must be at least 2"), "{err}");
        assert!(err.contains("1"), "{err}");
    }

    #[test]
    fn limits_absent_defaults_to_two_mib() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        let config = load(&path).expect("should load");
        assert_eq!(config.limits.max_parse_bytes, 2_097_152);
        assert_eq!(DEFAULT_MAX_PARSE_BYTES, 2_097_152);
    }

    #[test]
    fn limits_explicit_value_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "[limits]\nmax_parse_bytes = 4096\n",
        );
        let config = load(&path).expect("should load");
        assert_eq!(config.limits.max_parse_bytes, 4096);
    }

    #[test]
    fn limits_max_parse_bytes_zero_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[limits]\nmax_parse_bytes = 0\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("max_parse_bytes must be at least 1"), "{err}");
        assert!(err.contains("0"), "{err}");
    }

    #[test]
    fn limits_unknown_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "[limits]\nmax_parse_bytes = 4096\nwrongkey = true\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn limits_rejects_a_negative_or_fractional_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[limits]\nmax_parse_bytes = -1\n");
        assert!(load(&path).is_err());

        let path = write(
            dir.path(),
            "other.toml",
            "[limits]\nmax_parse_bytes = 1.5\n",
        );
        assert!(load(&path).is_err());
    }

    /// Root config plus a module config two directories down.
    fn with_include(dir: &Path, root_body: &str, module_body: &str) -> PathBuf {
        fs::create_dir_all(dir.join("modules/api")).unwrap();
        write(&dir.join("modules/api"), CONFIG_NAME, module_body);
        write(dir, CONFIG_NAME, root_body)
    }

    #[test]
    fn include_contributes_paths_relative_to_the_included_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\nrules = [\"rules/root\"]\n",
            r#"
source_roots = ["src"]
rules = ["../../rules/shared", "./rules/api"]

[silos]
api = ["src/**", "tests/**"]
"#,
        );
        let config = load(&path).expect("should load");

        assert_eq!(
            config.silos["api"],
            vec!["modules/api/src/**", "modules/api/tests/**"]
        );
        assert_eq!(config.source_roots, vec!["modules/api/src"]);
        assert_eq!(
            config.rules,
            vec!["rules/root", "rules/shared", "modules/api/rules/api"]
        );
        assert_eq!(
            config.rule_dirs(),
            vec![
                dir.path().join("rules/root"),
                dir.path().join("rules/shared"),
                dir.path().join("modules/api/rules/api"),
            ]
        );
    }

    #[test]
    fn include_silo_globs_match_config_root_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n\n[silos]\ncore = [\"crates/core/**\"]\n",
            "[silos]\napi = [\"src/**\"]\n",
        );
        let config = load(&path).expect("should load");
        let sets = config.silo_sets().expect("globs should compile");

        assert_eq!(
            config.silo_of(&sets, "modules/api/src/main.rs"),
            Some("api")
        );
        assert_eq!(config.silo_of(&sets, "crates/core/lib.rs"), Some("core"));
        assert_eq!(config.silo_of(&sets, "src/main.rs"), None);
    }

    #[test]
    fn include_silo_glob_keeps_globset_escapes_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            r#"[silos]
api = ["src/a\\[0\\].rs"]
"#,
        );
        let config = load(&path).expect("should load");

        // `\` escapes the bracket for globset: the pattern survives the rebase
        // byte for byte under its new prefix.
        assert_eq!(config.silos["api"], vec![r"modules/api/src/a\[0\].rs"]);
        let sets = config.silo_sets().expect("globs should compile");
        assert_eq!(
            config.silo_of(&sets, "modules/api/src/a[0].rs"),
            Some("api")
        );
    }

    #[test]
    fn include_rejects_root_only_keys() {
        for (key, body) in [
            ("anchor", "anchor = \"config\"\n"),
            ("duplication", "[duplication]\nmin_lines = 4\n"),
            ("limits", "[limits]\nmax_parse_bytes = 4096\n"),
            ("languages", "[languages]\nmjs = \"javascript\"\n"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = with_include(
                dir.path(),
                "include = [\"modules/api/siloscan.toml\"]\n",
                body,
            );
            let err = load(&path).unwrap_err();
            assert!(err.contains(key), "{key}: {err}");
            assert!(err.contains("modules/api"), "{key}: {err}");
        }
    }

    #[test]
    fn include_inside_an_included_config_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            "include = [\"../core/siloscan.toml\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("single level"), "{err}");
        assert!(err.contains("modules/api"), "{err}");
    }

    #[test]
    fn silo_collision_between_root_and_include_names_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n\n[silos]\napi = [\"legacy/**\"]\n",
            "[silos]\napi = [\"src/**\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("duplicate silo name: api"), "{err}");
        assert!(err.contains("modules/api/siloscan.toml"), "{err}");
        assert!(
            err.contains(&dir.path().join(CONFIG_NAME).display().to_string()),
            "{err}"
        );
    }

    #[test]
    fn silo_collision_between_two_includes_names_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("modules/one")).unwrap();
        fs::create_dir_all(root.join("modules/two")).unwrap();
        write(
            &root.join("modules/one"),
            CONFIG_NAME,
            "[silos]\napi = [\"src/**\"]\n",
        );
        write(
            &root.join("modules/two"),
            CONFIG_NAME,
            "[silos]\napi = [\"src/**\"]\n",
        );
        let path = write(
            root,
            CONFIG_NAME,
            "include = [\"modules/one/siloscan.toml\", \"modules/two/siloscan.toml\"]\n",
        );

        let err = load(&path).unwrap_err();
        assert!(err.contains("duplicate silo name: api"), "{err}");
        assert!(err.contains("modules/one/siloscan.toml"), "{err}");
        assert!(err.contains("modules/two/siloscan.toml"), "{err}");
    }

    #[test]
    fn missing_include_file_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "include = [\"modules/api/siloscan.toml\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("cannot read included config"), "{err}");
        assert!(err.contains("modules/api/siloscan.toml"), "{err}");
    }

    #[test]
    fn include_listed_twice_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\", \"modules/api/siloscan.toml\"]\n",
            "rules = [\"rules\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn include_must_be_a_relative_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "include = [\"/etc/siloscan.toml\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("must be a relative path"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "include = [\"modules/\"]\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("must name a config file"), "{err}");
    }

    #[test]
    fn include_silo_glob_leaving_the_config_root_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            "[silos]\napi = [\"../../../elsewhere/**\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("silo glob"), "{err}");
        assert!(err.contains("outside the config root"), "{err}");
    }

    #[test]
    fn include_bad_silo_name_names_the_included_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            "[silos]\n\"API\" = [\"src/**\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("invalid silo name"), "{err}");
        assert!(err.contains("modules/api/siloscan.toml"), "{err}");
    }

    #[test]
    fn anchor_defaults_to_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        assert_eq!(load(&path).unwrap().anchor, Anchor::ScanRoot);
        assert_eq!(Anchor::default(), Anchor::ScanRoot);
    }

    #[test]
    fn anchor_parses_both_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "anchor = \"scan-root\"\n");
        assert_eq!(load(&path).unwrap().anchor, Anchor::ScanRoot);

        let path = write(dir.path(), "other.toml", "anchor = \"config\"\n");
        assert_eq!(load(&path).unwrap().anchor, Anchor::Config);
    }

    #[test]
    fn unknown_anchor_value_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "anchor = \"repo\"\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("repo"), "{err}");
        assert!(err.contains("scan-root"), "{err}");
    }

    #[test]
    fn anchor_round_trips_through_its_spelling() {
        assert_eq!(Anchor::ScanRoot.as_str(), "scan-root");
        assert_eq!(Anchor::Config.as_str(), "config");
    }

    #[test]
    fn root_rules_leaving_the_config_root_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "rules = [\"../outside\"]\n");
        let err = load(&path).unwrap_err();

        assert!(err.contains("rules"), "{err}");
        assert!(err.contains("../outside"), "{err}");
        assert!(err.contains("outside the config root"), "{err}");
    }

    #[test]
    fn root_rules_with_an_absolute_path_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        for entry in ["/etc/siloscan-rules", "\\\\server\\rules", "C:/rules"] {
            let path = write(dir.path(), CONFIG_NAME, &format!("rules = [{entry:?}]\n"));
            let err = load(&path).unwrap_err();

            assert!(err.contains("rules"), "{entry}: {err}");
            assert!(err.contains("relative path"), "{entry}: {err}");
        }
    }

    #[test]
    fn root_source_roots_leaving_the_config_root_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "source_roots = [\"../outside\"]\n");
        let err = load(&path).unwrap_err();

        assert!(err.contains("source_roots"), "{err}");
        assert!(err.contains("../outside"), "{err}");

        let path = write(dir.path(), "other.toml", "source_roots = [\"/srv\"]\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("source_roots"), "{err}");
        assert!(err.contains("relative path"), "{err}");
    }

    #[test]
    fn root_paths_inside_the_config_root_are_normalised() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "rules = [\"./rules/local\", \"a/../b\"]\nsource_roots = [\"./src\"]\n",
        );
        let config = load(&path).expect("should load");

        assert_eq!(config.rules, vec!["rules/local", "b"]);
        assert_eq!(config.source_roots, vec!["src"]);
    }

    #[test]
    fn include_rules_leaving_the_config_root_is_fatal() {
        // The root guard would be one `include` line away from useless if an
        // included file could still name a directory outside the config root.
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            "rules = [\"../../../shared-rules\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("rules"), "{err}");
        assert!(err.contains("outside the config root"), "{err}");
        assert!(err.contains("modules/api"), "{err}");
    }

    /// `link` inside `dir`, pointing at `target`. Unix only: the symlink escape
    /// these tests cover needs a symlink to exist.
    #[cfg(unix)]
    fn symlink(dir: &Path, link: &str, target: &Path) {
        std::os::unix::fs::symlink(target, dir.join(link)).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn root_rules_through_a_symlink_out_of_the_config_root_is_fatal() {
        // The lexical guard sees `"link"`, a path with no `..` in it. Both the
        // symlink and the config naming it are content of the untrusted tree.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("outside/rules")).unwrap();
        fs::create_dir_all(root.join("tree")).unwrap();
        symlink(&root.join("tree"), "link", &root.join("outside/rules"));

        let path = write(&root.join("tree"), CONFIG_NAME, "rules = [\"link\"]\n");
        let err = load(&path).unwrap_err();

        assert!(err.contains("rules"), "{err}");
        assert!(err.contains("\"link\""), "{err}");
        assert!(err.contains("outside the config root"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn root_source_roots_through_a_symlink_out_of_the_config_root_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("outside/src")).unwrap();
        fs::create_dir_all(root.join("tree")).unwrap();
        symlink(&root.join("tree"), "link", &root.join("outside/src"));

        let path = write(
            &root.join("tree"),
            CONFIG_NAME,
            "source_roots = [\"link/nested\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("source_roots"), "{err}");
        assert!(err.contains("outside the config root"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn include_through_a_symlink_out_of_the_config_root_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("outside")).unwrap();
        fs::create_dir_all(root.join("tree")).unwrap();
        write(&root.join("outside"), CONFIG_NAME, "rules = [\"pack\"]\n");
        symlink(&root.join("tree"), "link", &root.join("outside"));

        let path = write(
            &root.join("tree"),
            CONFIG_NAME,
            "include = [\"link/siloscan.toml\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("include"), "{err}");
        assert!(err.contains("outside the config root"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_that_stays_inside_the_config_root_still_loads() {
        // Containment is about where a path lands, not about symlinks: one that
        // resolves back inside the tree is as legitimate as a real directory.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("real/rules")).unwrap();
        symlink(&root, "link", &root.join("real/rules"));

        let path = write(&root, CONFIG_NAME, "rules = [\"link\", \"real/rules\"]\n");
        let config = load(&path).expect("should load");
        assert_eq!(config.rules, vec!["link", "real/rules"]);
    }

    #[test]
    fn a_real_subdirectory_of_the_config_root_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("modules/api/rules")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();

        let path = write(
            &root,
            CONFIG_NAME,
            "rules = [\"modules/api/rules\"]\nsource_roots = [\"src\"]\n",
        );
        let config = load(&path).expect("should load");

        assert_eq!(config.rules, vec!["modules/api/rules"]);
        assert_eq!(config.source_roots, vec!["src"]);
    }

    #[test]
    fn include_entry_leaving_the_config_root_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "include = [\"../elsewhere/siloscan.toml\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("outside the config root"), "{err}");
    }

    /// A config root holding a module directory, with the config anchored to
    /// the config root unless `anchor` says otherwise.
    fn anchored(dir: &Path, anchor: &str) -> Config {
        fs::create_dir_all(dir.join("modules/api/src")).unwrap();
        let path = write(dir, CONFIG_NAME, anchor);
        load(&path).expect("should load")
    }

    #[test]
    fn config_anchor_brings_the_directories_above_the_scan_root_into_scope() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let config = anchored(&root, "anchor = \"config\"\n");

        assert_eq!(
            config.project_ignore_dirs(&root.join("modules/api")),
            vec![root.clone(), root.join("modules")]
        );
        // The scan root's own ignore files are the walk's business, not this
        // list's: scanning the config root itself adds nothing.
        assert!(config.project_ignore_dirs(&root).is_empty());
    }

    #[test]
    fn scan_root_anchor_brings_nothing_above_the_scan_root_into_scope() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let config = anchored(&root, "");

        assert_eq!(config.anchor, Anchor::ScanRoot);
        assert!(
            config
                .project_ignore_dirs(&root.join("modules/api"))
                .is_empty()
        );
    }

    #[test]
    fn project_ignore_dirs_stop_at_the_config_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("inside")).unwrap();
        fs::create_dir_all(root.join("outside")).unwrap();
        let config = anchored(&root.join("inside"), "anchor = \"config\"\n");

        // A scan root the config root does not contain gets nothing.
        assert!(config.project_ignore_dirs(&root.join("outside")).is_empty());
        assert!(config.project_ignore_dirs(&root).is_empty());
    }

    #[test]
    fn project_ignore_dirs_of_a_single_file_scan_root_use_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let config = anchored(&root, "anchor = \"config\"\n");
        fs::write(root.join("modules/api/src/a.rs"), "").unwrap();

        assert_eq!(
            config.project_ignore_dirs(&root.join("modules/api/src/a.rs")),
            vec![root.clone(), root.join("modules"), root.join("modules/api")]
        );
    }

    #[test]
    fn duplication_unknown_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "[duplication]\nmin_lines = 10\nwrongkey = true\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
    }
}
