//! Content-addressed cache of per-file scan results.
//!
//! An entry is keyed by the file's content hash, the hash of the rule sources
//! that produced it, and the path convention the scan ran under, so a hit is
//! only possible when all three are unchanged. Entries are self-describing: the
//! crate version and the path scope are stored inside the file and re-checked
//! on read. Every failure mode here is a miss, never an error and never a panic.
//!
//! The path scope is part of the key because a cached finding carries a path
//! and a fingerprint computed from that path. Serving an entry written under
//! `anchor = "scan-root"` to a config-anchored scan would emit paths and
//! fingerprints from the wrong convention, which no amount of downstream
//! sorting could repair.
//!
//! Entries live inside the scanned tree and hold no match text: a finding's
//! match is frequently the secret that was found. Only its length is stored,
//! and the text is read back out of the scanned file itself. A `.gitignore` is
//! written beside the cache directory so entries cannot be committed to the
//! scanned repository.
//!
//! The crate version inside an entry makes it a miss after an upgrade, but a
//! miss is not a removal: without one, every release left the whole of the
//! previous release's cache on disk for good. [`Cache::open`] therefore prunes
//! entries stamped with a different version, once, up front. The pass is
//! tolerant by construction - it only removes a file that says, in its own
//! bytes, which build wrote it and names another one. Anything unreadable,
//! unrecognised or foreign is left exactly where it is, and a removal that
//! fails is ignored: a cache that cannot be tidied is still a correct cache.

use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Anchor;
use crate::findings::Finding;
use crate::graph::FileFacts;
use crate::rules::{RuleSet, Severity};

/// Cache location, relative to the scan root.
pub const CACHE_DIR: &str = ".siloscan/cache";

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How much of the scope hash goes into the entry file name.
const SCOPE_HASH_PREFIX: usize = 16;

/// The bytes every entry this build writes starts with: `version` is the first
/// field of [`StoredEntry`], and serde emits fields in declaration order.
const VERSION_PREFIX: &[u8] = b"{\"version\":\"";

/// How much of an entry is read to recover the version it declares. The field
/// sits at the very front, so this is a single short read per file rather than
/// a parse of the whole document.
const VERSION_PROBE_BYTES: u64 = 128;

/// Stamp naming the build that last pruned this cache directory. Its presence
/// with this build's version is the evidence that no entry from another build
/// is left, which is what makes the prune skippable. It lives inside
/// `.siloscan/cache`, which the `.gitignore` below already covers.
const STAMP_NAME: &str = ".version";

/// Written to `.siloscan/.gitignore`. Scoped to `cache/` so a committed
/// baseline beside it stays visible to git.
const IGNORE_MARKER: &str = "# Written by siloscan. Cache entries are local state.\ncache/\n";

/// The path convention every path inside a cache entry was recorded under.
///
/// Two scans that disagree on this produce different paths for the same file,
/// and therefore different fingerprints, so their entries must never mix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathScope {
    /// Paths are relative to the scan root. The default convention.
    ScanRoot,
    /// Paths are relative to the config root. `prefix` is the scan root's
    /// path from the config root, forward-slashed and empty when the two
    /// coincide; it is what a subdirectory scan prepends to every path, so it
    /// belongs to the key as much as the anchor does.
    Config { prefix: String },
}

impl PathScope {
    /// Build the scope from a loaded config's anchor and the scan root's
    /// position under the config root. `prefix` is ignored under
    /// [`Anchor::ScanRoot`], where nothing is measured from the config root.
    pub fn new(anchor: Anchor, prefix: &str) -> PathScope {
        match anchor {
            Anchor::ScanRoot => PathScope::ScanRoot,
            Anchor::Config => PathScope::Config {
                prefix: prefix.trim_matches('/').to_string(),
            },
        }
    }

    /// Stable textual form, folded into the key hash and stored in the entry.
    /// The two arms cannot collide: an anchor name has no `:` in it.
    pub fn discriminator(&self) -> String {
        match self {
            PathScope::ScanRoot => "scan-root".to_string(),
            PathScope::Config { prefix } => format!("config:{prefix}"),
        }
    }
}

/// Everything an entry's validity depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    /// Hex SHA-256 of the file's bytes.
    pub content_hash: String,
    /// [`RuleSet::source_hash`] of the rules used for the scan.
    pub rules_hash: String,
    /// [`PathScope::discriminator`] of the scan's path convention.
    pub path_scope: String,
    /// Crate version that wrote the entry.
    pub version: String,
}

/// Cached result of scanning one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFile {
    pub findings: Vec<Finding>,
    pub facts: Option<FileFacts>,
}

/// On-disk shape. Field order is fixed, so identical input serializes to
/// identical bytes.
#[derive(Serialize, Deserialize)]
struct StoredEntry {
    version: String,
    /// The scope the paths below were written under. The file name already
    /// separates scopes, but only through a truncated hash; this is the
    /// authoritative check, and it costs one string comparison.
    path_scope: String,
    findings: Vec<StoredFinding>,
    facts: Option<FileFacts>,
}

/// On-disk shape of one finding, without its match text. `matched_len` is the
/// span's length in bytes, which together with the line and column recovers the
/// text from the scanned file.
#[derive(Serialize, Deserialize)]
struct StoredFinding {
    rule_id: String,
    severity: Severity,
    message: String,
    path: String,
    line: u64,
    column: u64,
    matched_len: usize,
    fingerprint: String,
}

impl StoredFinding {
    fn new(finding: &Finding) -> StoredFinding {
        StoredFinding {
            rule_id: finding.rule_id.clone(),
            severity: finding.severity,
            message: finding.message.clone(),
            path: finding.path.clone(),
            line: finding.line,
            column: finding.column,
            matched_len: finding.matched.len(),
            fingerprint: finding.fingerprint.clone(),
        }
    }

    /// Rebuild the finding, reading its match text back out of `content`.
    /// Returns `None` when the span does not address `content`, which makes the
    /// whole entry a miss.
    fn restore(self, starts: &[usize], content: &str) -> Option<Finding> {
        let start = offset_of(starts, self.line, self.column)?;
        let end = start.checked_add(self.matched_len)?;
        let matched = content.get(start..end)?;

        Some(Finding {
            rule_id: self.rule_id,
            severity: self.severity,
            message: self.message,
            path: self.path,
            line: self.line,
            column: self.column,
            matched: matched.to_string(),
            fingerprint: self.fingerprint,
        })
    }
}

pub struct Cache {
    root: PathBuf,
    rules_hash: String,
    path_scope: String,
    /// Hash of everything in the key except the content: the entry file name
    /// carries a prefix of it, so entries from different rule sets or
    /// different path conventions land on different names and coexist.
    scope_hash: String,
}

impl Cache {
    /// Bind a cache to a scan root, a rule set and a path convention, and drop
    /// whatever a different build left behind (see [`prune`]). Nothing is
    /// created here beyond the prune stamp: an absent cache directory is nothing
    /// to prune and nothing to write until the first [`Cache::put`].
    ///
    /// The prune is skipped when the stamp already names this build. It has to
    /// be, because it is not free: the pass opens and reads the head of every
    /// entry in the directory, which on a 20k-entry cache is a measured 0.4s
    /// added to every scan, forever, to find nothing. The stamp turns that into
    /// one `read` on the steady path and leaves the full pass for the run after
    /// an upgrade, which is the only run that can find anything.
    pub fn open(scan_root: &Path, rules: &RuleSet, scope: &PathScope) -> Cache {
        let rules_hash = rules.source_hash();
        let path_scope = scope.discriminator();
        let root = scan_root.join(CACHE_DIR);
        prune_if_stale(&root);
        Cache {
            root,
            scope_hash: scope_hash(&rules_hash, &path_scope),
            rules_hash,
            path_scope,
        }
    }

    /// The cache directory, which may not exist yet.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn rules_hash(&self) -> &str {
        &self.rules_hash
    }

    /// The path convention this cache reads and writes entries for.
    pub fn path_scope(&self) -> &str {
        &self.path_scope
    }

    /// The full key for `content`, for callers that want to record or compare it.
    pub fn key(&self, content: &[u8]) -> CacheKey {
        CacheKey {
            content_hash: content_hash(content),
            rules_hash: self.rules_hash.clone(),
            path_scope: self.path_scope.clone(),
            version: VERSION.to_string(),
        }
    }

    /// Look up an entry. `content` is the scanned file's current text, which the
    /// entry's spans are read against to recover match text that was never
    /// stored. Absent, unreadable, malformed, version-mismatched,
    /// scope-mismatched and unrecoverable entries are all plain misses.
    pub fn get(&self, content_hash: &str, content: &str) -> Option<CachedFile> {
        let path = self.entry_path(content_hash)?;
        let bytes = fs::read(path).ok()?;
        let stored: StoredEntry = serde_json::from_slice(&bytes).ok()?;
        if stored.version != VERSION || stored.path_scope != self.path_scope {
            return None;
        }

        let starts = line_starts(content);
        let mut findings = Vec::with_capacity(stored.findings.len());
        for finding in stored.findings {
            findings.push(finding.restore(&starts, content)?);
        }

        Some(CachedFile {
            findings,
            facts: stored.facts,
        })
    }

    /// Store an entry, replacing any existing one. The write goes to a temporary
    /// file in the same directory and is renamed into place, so a reader never
    /// observes a partial entry. Failures are silent: a cache that cannot be
    /// written is a cache that misses.
    pub fn put(&self, content_hash: &str, entry: &CachedFile) {
        let Some(path) = self.entry_path(content_hash) else {
            return;
        };
        let Some(dir) = path.parent() else {
            return;
        };
        if fs::create_dir_all(dir).is_err() {
            return;
        }
        self.write_ignore_marker();

        let stored = StoredEntry {
            version: VERSION.to_string(),
            path_scope: self.path_scope.clone(),
            findings: entry.findings.iter().map(StoredFinding::new).collect(),
            facts: entry.facts.clone(),
        };
        let Ok(mut bytes) = serde_json::to_vec(&stored) else {
            return;
        };
        bytes.push(b'\n');

        let temp = dir.join(temp_name(content_hash));
        if fs::write(&temp, &bytes).is_err() {
            let _ = fs::remove_file(&temp);
            return;
        }
        if fs::rename(&temp, &path).is_err() {
            let _ = fs::remove_file(&temp);
        }
    }

    /// Keep cache entries out of the scanned repository's history. Written once
    /// beside the cache directory and never overwritten, so a user's own
    /// `.siloscan/.gitignore` wins.
    fn write_ignore_marker(&self) {
        let Some(dir) = self.root.parent() else {
            return;
        };
        let marker = dir.join(".gitignore");
        if marker.exists() {
            return;
        }
        let _ = fs::write(marker, IGNORE_MARKER);
    }

    /// `<cache>/<first two hex chars>/<content hash>-<scope hash prefix>.json`.
    /// Returns `None` for a content hash that is not a usable file name, which
    /// keeps a caller-supplied string from escaping the cache directory.
    fn entry_path(&self, content_hash: &str) -> Option<PathBuf> {
        if content_hash.len() < 2 || !content_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let prefix = self
            .scope_hash
            .get(..SCOPE_HASH_PREFIX)
            .unwrap_or(&self.scope_hash);
        Some(
            self.root
                .join(&content_hash[..2])
                .join(format!("{content_hash}-{prefix}.json")),
        )
    }
}

/// Drop every cache entry under `scan_root` that a different build wrote, and
/// report how many went.
///
/// This is what [`Cache::open`] does for the scan it is opening; it is exposed
/// so the same tidy-up can be asked for on its own. It removes entries across
/// every rule set and path convention in the directory, not just the caller's:
/// a stale entry is stale whoever wrote it.
///
/// Unlike the open path this always walks the directory, stamp or no stamp: a
/// user who asked for a prune asked for the pass, not for this build's opinion
/// about whether it would find anything.
pub fn prune(scan_root: &Path) -> usize {
    let root = scan_root.join(CACHE_DIR);
    let removed = prune_dir(&root);
    write_stamp(&root);
    removed
}

/// Prune unless the stamp says this build already did.
///
/// Every failure mode leads to pruning: no stamp, an unreadable stamp, a stamp
/// naming another version. The stamp is only ever trusted to say "this build has
/// already swept here", never to say the opposite, so a missing or corrupt one
/// costs a pass that was correct to run anyway. It is written after the pass, so
/// a prune that dies halfway leaves no stamp and the next open retries.
fn prune_if_stale(root: &Path) {
    if fs::read_to_string(root.join(STAMP_NAME)).is_ok_and(|stamp| stamp.trim() == VERSION) {
        return;
    }
    prune_dir(root);
    write_stamp(root);
}

/// Record this build as the last to sweep `root`.
///
/// Written only into a cache directory that already exists: a scan of a tree
/// with no cache must not create one, and the first [`Cache::put`] stamps it
/// through the next [`Cache::open`]. Failures are ignored - an unwritable stamp
/// costs a prune pass per scan, which is only where this started.
fn write_stamp(root: &Path) {
    if root.is_dir() {
        let _ = fs::write(root.join(STAMP_NAME), format!("{VERSION}\n"));
    }
}

/// One pass over `<root>/<shard>/*.json`, removing the entries that name a
/// version other than this build's. Returns how many were removed.
///
/// Every step is permissive. A directory that cannot be listed ends the pass, a
/// shard that cannot be listed is skipped, a file that is not an entry is
/// skipped, and a removal that fails is dropped on the floor. Nothing here is
/// allowed to turn a cache into a scan failure, and nothing here touches a file
/// that has not identified itself as this crate's. A removal that failed is not
/// counted: the number is what left, not what was attempted.
fn prune_dir(root: &Path) -> usize {
    let mut removed = 0;
    let Ok(shards) = fs::read_dir(root) else {
        return removed;
    };
    for shard in shards.flatten() {
        if !shard.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Ok(entries) = fs::read_dir(shard.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Temporary files belong to a writer that is still running.
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            if entry_version(&path).is_some_and(|version| version != VERSION)
                && fs::remove_file(&path).is_ok()
            {
                removed += 1;
            }
        }
    }
    removed
}

/// The version an entry declares, read from its first [`VERSION_PROBE_BYTES`]
/// rather than by parsing it.
///
/// `None` means "not an entry this build recognises": the file could not be
/// opened or read, does not begin the way [`StoredEntry`] serializes, or has no
/// closing quote on its version within the probe. Every one of those is a
/// reason to leave the file alone rather than a reason to delete it. The
/// comparison is on raw bytes because a crate version is a semver string, which
/// carries no JSON escape and no multi-byte character.
fn entry_version(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut head = Vec::with_capacity(VERSION_PROBE_BYTES as usize);
    file.take(VERSION_PROBE_BYTES).read_to_end(&mut head).ok()?;

    let rest = head.strip_prefix(VERSION_PREFIX)?;
    let end = rest.iter().position(|byte| *byte == b'"')?;
    let version = rest.get(..end)?;
    if version.contains(&b'\\') {
        return None;
    }
    std::str::from_utf8(version).ok().map(str::to_string)
}

/// Hex SHA-256 of the rules hash and the path scope, NUL-separated so no pair
/// of inputs can be concatenated into another pair's bytes.
fn scope_hash(rules_hash: &str, path_scope: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rules_hash.as_bytes());
    hasher.update([0]);
    hasher.update(path_scope.as_bytes());
    hex(&hasher.finalize())
}

/// Hex SHA-256 of `bytes`.
pub fn content_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Lowercase hex of a digest.
fn hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Byte offset of each line start, the first being 0.
fn line_starts(content: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(16);
    starts.push(0);
    starts.extend(content.match_indices('\n').map(|(i, _)| i + 1));
    starts
}

/// Byte offset of a 1-based line and 1-based byte column, the inverse of the
/// position an engine reports. `None` for a position outside `starts`.
fn offset_of(starts: &[usize], line: u64, column: u64) -> Option<usize> {
    let index = usize::try_from(line.checked_sub(1)?).ok()?;
    let column = usize::try_from(column.checked_sub(1)?).ok()?;
    starts.get(index)?.checked_add(column)
}

/// Unique within a run and across concurrent runs, so two writers never share a
/// temporary file. Cache entries are always `*.json`, so a stray temporary can
/// never be mistaken for one.
fn temp_name(content_hash: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{content_hash}.{}.{n}.tmp", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for a real leaked credential: it must never reach the disk.
    const SECRET: &str = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn ruleset(source: &str) -> RuleSet {
        RuleSet {
            rules: Vec::new(),
            sources: vec![("origin".to_string(), source.to_string())],
        }
    }

    /// The scanned file the cached findings point into.
    fn content() -> String {
        format!("let token = \"{SECRET}\";\nlet other = 2;\n")
    }

    fn hash() -> String {
        content_hash(content().as_bytes())
    }

    /// A finding for the first occurrence of `matched` on `line`, positioned
    /// exactly as an engine would report it.
    fn finding(rule_id: &str, line: u64, matched: &str) -> Finding {
        let content = content();
        let text = content.lines().nth(line as usize - 1).expect("line");
        let column = text.find(matched).expect("match on line") as u64 + 1;

        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: "src/a.rs".to_string(),
            line,
            column,
            matched: matched.to_string(),
            fingerprint: "ff".to_string(),
        }
    }

    fn entry() -> CachedFile {
        CachedFile {
            findings: vec![finding("a.rule", 1, SECRET), finding("b.rule", 2, "other")],
            facts: None,
        }
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[test]
    fn put_then_get_round_trips() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();

        assert!(cache.get(&hash, &content()).is_none());
        cache.put(&hash, &entry());

        let hit = cache
            .get(&hash, &content())
            .expect("entry should be cached");
        assert_eq!(hit.findings, entry().findings);
        assert!(hit.facts.is_none());
    }

    #[test]
    fn stored_entry_holds_no_match_text() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();
        cache.put(&hash, &entry());

        let bytes = fs::read(cache.entry_path(&hash).unwrap()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(SECRET), "secret persisted to disk: {text}");
        assert!(!text.contains("other"));
        assert!(text.contains("matched_len"));
    }

    #[test]
    fn put_writes_a_gitignore_beside_the_cache() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash(), &entry());

        let marker = cache.root().parent().unwrap().join(".gitignore");
        assert_eq!(fs::read_to_string(&marker).unwrap(), IGNORE_MARKER);

        // An existing marker is left alone.
        fs::write(&marker, "mine\n").unwrap();
        cache.put(&hash(), &entry());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "mine\n");
    }

    #[test]
    fn content_without_the_recorded_span_is_a_miss() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();
        cache.put(&hash, &entry());

        assert!(cache.get(&hash, "").is_none());
        assert!(cache.get(&hash, "let token = \"\";\n").is_none());
    }

    #[test]
    fn open_does_not_create_the_directory() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(!cache.root().exists());
        assert!(cache.get(&content_hash(b"x"), "x").is_none());
        assert!(!cache.root().exists());
    }

    #[test]
    fn key_reports_content_rules_scope_and_version() {
        let dir = tempdir();
        let rules = ruleset("a");
        let cache = Cache::open(dir.path(), &rules, &PathScope::ScanRoot);
        let key = cache.key(b"file contents");

        assert_eq!(key.content_hash, content_hash(b"file contents"));
        assert_eq!(key.rules_hash, rules.source_hash());
        assert_eq!(key.path_scope, "scan-root");
        assert_eq!(key.version, VERSION);
        assert_eq!(key.content_hash.len(), 64);

        let scope = PathScope::Config {
            prefix: "modules/api".to_string(),
        };
        let cache = Cache::open(dir.path(), &rules, &scope);
        assert_eq!(cache.key(b"file contents").path_scope, "config:modules/api");
    }

    #[test]
    fn version_mismatch_is_a_miss() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();
        cache.put(&hash, &entry());

        let path = cache.entry_path(&hash).unwrap();
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored["version"] = serde_json::Value::String("0.0.0-not-this-build".to_string());
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();

        assert!(cache.get(&hash, &content()).is_none());
    }

    #[test]
    fn corrupt_entry_is_a_miss() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();
        cache.put(&hash, &entry());

        let path = cache.entry_path(&hash).unwrap();
        fs::write(&path, b"{ not json").unwrap();

        assert!(cache.get(&hash, &content()).is_none());
    }

    #[test]
    fn truncated_entry_is_a_miss() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();
        cache.put(&hash, &entry());

        let path = cache.entry_path(&hash).unwrap();
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

        assert!(cache.get(&hash, &content()).is_none());
    }

    #[test]
    fn different_rules_hash_is_a_miss() {
        let dir = tempdir();
        let hash = hash();

        let first = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        first.put(&hash, &entry());

        let second = Cache::open(dir.path(), &ruleset("b"), &PathScope::ScanRoot);
        assert_ne!(first.rules_hash(), second.rules_hash());
        assert!(second.get(&hash, &content()).is_none());
        // The original entry is untouched, so both rule sets can coexist.
        assert!(first.get(&hash, &content()).is_some());
    }

    /// The contract that makes anchored scans safe: a result recorded under one
    /// path convention must never be handed to a scan running under another,
    /// because every path and fingerprint inside it belongs to the first.
    #[test]
    fn scan_root_entries_are_not_served_to_a_config_anchored_scan() {
        let dir = tempdir();
        let hash = hash();

        let scan_root = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        scan_root.put(&hash, &entry());
        assert!(scan_root.get(&hash, &content()).is_some());

        let anchored = Cache::open(
            dir.path(),
            &ruleset("a"),
            &PathScope::Config {
                prefix: String::new(),
            },
        );
        assert!(
            anchored.get(&hash, &content()).is_none(),
            "a scan-root entry must not serve a config-anchored scan"
        );

        // Both conventions coexist: writing the anchored entry leaves the
        // scan-root one readable.
        anchored.put(&hash, &entry());
        assert!(anchored.get(&hash, &content()).is_some());
        assert!(scan_root.get(&hash, &content()).is_some());
    }

    /// Two module scans under the same config root see the same file at
    /// different paths, so they cannot share an entry either.
    #[test]
    fn a_different_config_prefix_is_a_miss() {
        let dir = tempdir();
        let hash = hash();
        let scope = |prefix: &str| PathScope::Config {
            prefix: prefix.to_string(),
        };

        let api = Cache::open(dir.path(), &ruleset("a"), &scope("modules/api"));
        api.put(&hash, &entry());

        let web = Cache::open(dir.path(), &ruleset("a"), &scope("modules/web"));
        assert!(web.get(&hash, &content()).is_none());
        assert!(api.get(&hash, &content()).is_some());
    }

    /// Belt and braces: the file name only carries a truncated hash of the
    /// scope, so the entry states its own scope and that statement decides.
    #[test]
    fn a_rewritten_scope_inside_the_entry_is_a_miss() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();
        cache.put(&hash, &entry());

        let path = cache.entry_path(&hash).unwrap();
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored["path_scope"], "scan-root");
        stored["path_scope"] = serde_json::Value::String("config:".to_string());
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();

        assert!(cache.get(&hash, &content()).is_none());
    }

    #[test]
    fn path_scope_follows_the_anchor() {
        assert_eq!(
            PathScope::new(Anchor::ScanRoot, "modules/api"),
            PathScope::ScanRoot,
            "the prefix is meaningless without a config anchor"
        );
        assert_eq!(PathScope::ScanRoot.discriminator(), "scan-root");

        let scope = PathScope::new(Anchor::Config, "/modules/api/");
        assert_eq!(
            scope,
            PathScope::Config {
                prefix: "modules/api".to_string()
            },
            "surrounding slashes must not fork the key"
        );
        assert_eq!(scope.discriminator(), "config:modules/api");
        assert_eq!(
            PathScope::new(Anchor::Config, "").discriminator(),
            "config:"
        );
    }

    #[test]
    fn different_content_hash_is_a_miss() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&content_hash(b"one"), &entry());

        assert!(cache.get(&content_hash(b"two"), &content()).is_none());
    }

    #[test]
    fn put_leaves_no_temporary_file_behind() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();

        cache.put(&hash, &entry());
        cache.put(&hash, &entry());

        let shard = cache.root().join(&hash[..2]);
        let names = files_in(&shard);
        assert_eq!(names.len(), 1, "unexpected files in the shard: {names:?}");
        assert!(names[0].ends_with(".json"));
    }

    #[test]
    fn stored_bytes_are_identical_across_puts() {
        let dir_a = tempdir();
        let dir_b = tempdir();
        let hash = hash();

        let a = Cache::open(dir_a.path(), &ruleset("a"), &PathScope::ScanRoot);
        let b = Cache::open(dir_b.path(), &ruleset("a"), &PathScope::ScanRoot);
        a.put(&hash, &entry());
        b.put(&hash, &entry());

        let left = fs::read(a.entry_path(&hash).unwrap()).unwrap();
        let right = fs::read(b.entry_path(&hash).unwrap()).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.last(), Some(&b'\n'));

        // Rewriting the same entry reproduces the same bytes.
        a.put(&hash, &entry());
        assert_eq!(fs::read(a.entry_path(&hash).unwrap()).unwrap(), left);
    }

    #[test]
    fn entry_path_is_sharded_and_scope_scoped() {
        let cache = Cache::open(Path::new("/root"), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();
        let path = cache.entry_path(&hash).unwrap();

        assert!(path.starts_with(Path::new("/root").join(CACHE_DIR)));
        assert_eq!(
            path.parent().unwrap().file_name().unwrap().to_str(),
            Some(&hash[..2])
        );
        assert_eq!(
            path.file_name().unwrap().to_str(),
            Some(format!("{hash}-{}.json", &cache.scope_hash[..SCOPE_HASH_PREFIX]).as_str())
        );

        // The rules hash and the path scope both move the name.
        let other_rules = Cache::open(Path::new("/root"), &ruleset("b"), &PathScope::ScanRoot);
        let other_scope = Cache::open(
            Path::new("/root"),
            &ruleset("a"),
            &PathScope::Config {
                prefix: String::new(),
            },
        );
        assert_ne!(path, other_rules.entry_path(&hash).unwrap());
        assert_ne!(path, other_scope.entry_path(&hash).unwrap());
    }

    #[test]
    fn non_hex_content_hash_is_rejected() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);

        for bad in ["", "a", "../../etc/passwd", "zz", "ab/cd"] {
            assert!(cache.entry_path(bad).is_none(), "{bad} should be rejected");
            assert!(cache.get(bad, &content()).is_none());
            cache.put(bad, &entry());
        }
        assert!(!cache.root().exists());
    }

    /// Write an entry byte-for-byte as `version` would have written it, so the
    /// prune pass sees exactly what an older release left behind. The rewrite
    /// asserts the layout the probe depends on: an entry opens with its own
    /// version field.
    fn seed_foreign_entry(cache: &Cache, content_hash: &str, version: &str) -> PathBuf {
        cache.put(content_hash, &entry());
        let path = cache.entry_path(content_hash).unwrap();
        let text = String::from_utf8(fs::read(&path).unwrap()).unwrap();
        let rewritten = text.replacen(
            &format!("{{\"version\":\"{VERSION}\""),
            &format!("{{\"version\":\"{version}\""),
            1,
        );
        assert_ne!(rewritten, text, "an entry must open with its version");
        fs::write(&path, rewritten.as_bytes()).unwrap();
        path
    }

    /// The whole point of the pass: an upgrade must not leave the previous
    /// release's entries on disk for ever, and must not take this one's with
    /// them.
    #[test]
    fn open_removes_entries_written_by_another_version() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        // Opened before anything is seeded: opening prunes, which is the
        // behaviour under test and would otherwise clear the fixture early.
        let other_rules = Cache::open(dir.path(), &ruleset("b"), &PathScope::ScanRoot);

        let mine = hash();
        cache.put(&mine, &entry());
        let theirs = seed_foreign_entry(&cache, &content_hash(b"older release"), "0.0.0-old");
        // A stale entry from a different rule set is stale all the same.
        let other_scope = seed_foreign_entry(&other_rules, &content_hash(b"older too"), "1.0.0");

        assert!(theirs.exists());
        assert!(other_scope.exists());

        let reopened = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);

        assert!(!theirs.exists(), "a foreign-version entry survived open");
        assert!(!other_scope.exists(), "only this cache's scope was pruned");
        assert!(
            reopened.entry_path(&mine).unwrap().exists(),
            "this build's entry was removed"
        );
        assert!(reopened.get(&mine, &content()).is_some());
    }

    /// Removal is only ever justified by a file that names another build. A
    /// file that says nothing intelligible says nothing about its version
    /// either, and deleting it would be this pass guessing.
    #[test]
    fn unreadable_and_foreign_files_are_left_in_place() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash(), &entry());
        let shard = cache.root().join(&hash()[..2]);

        let corrupt = shard.join("corrupt.json");
        let truncated = shard.join("truncated.json");
        let unrelated = shard.join("notes.txt");
        let temp = shard.join(temp_name(&hash()));
        let long = shard.join("padded.json");
        fs::write(&corrupt, b"{ not json").unwrap();
        fs::write(&truncated, b"{\"version\":\"9.9.9").unwrap();
        fs::write(&unrelated, b"whatever").unwrap();
        fs::write(&temp, b"{\"version\":\"0.0.0\"}").unwrap();
        // A version that runs past the probe window is unreadable, not foreign.
        fs::write(&long, format!("{{\"version\":\"{}\"}}", "9".repeat(200))).unwrap();

        Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);

        for path in [&corrupt, &truncated, &unrelated, &temp, &long] {
            assert!(path.exists(), "{} was removed", path.display());
        }
        assert!(cache.get(&hash(), &content()).is_some(), "still a hit");
    }

    #[test]
    fn pruning_is_idempotent_and_creates_nothing() {
        let dir = tempdir();

        // Nothing on disk yet: open must not conjure the directory.
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(!cache.root().exists());
        prune(dir.path());
        assert!(!cache.root().exists());

        cache.put(&hash(), &entry());
        let stale = seed_foreign_entry(&cache, &content_hash(b"older release"), "0.0.0-old");
        let mine = cache.entry_path(&hash()).unwrap();
        let bytes = fs::read(&mine).unwrap();

        for _ in 0..3 {
            prune(dir.path());
            assert!(!stale.exists());
            assert_eq!(
                fs::read(&mine).unwrap(),
                bytes,
                "a live entry was rewritten"
            );
        }
        assert!(cache.get(&hash(), &content()).is_some());
    }

    /// The prune pass opens every entry in the directory, so on a large cache
    /// it is the most expensive thing about opening one. A stamp naming this
    /// build is proof the sweep already happened, and the sweep is skipped.
    #[test]
    fn a_current_stamp_skips_the_prune() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash(), &entry());
        let stale = seed_foreign_entry(&cache, &content_hash(b"older release"), "0.0.0-old");

        // Claim the sweep already happened. Nothing else does this - the point
        // is that the stamp alone is what open trusts.
        fs::write(cache.root().join(STAMP_NAME), format!("{VERSION}\n")).unwrap();
        Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(stale.exists(), "a current stamp must skip the pass");

        // An explicit prune ignores the stamp: the user asked for the pass.
        assert_eq!(prune(dir.path()), 1);
        assert!(!stale.exists());
    }

    /// Every way of not having a usable stamp leads to the same place: sweep,
    /// then stamp. The stamp is trusted to skip work, never to authorise it.
    #[test]
    fn an_absent_or_foreign_stamp_prunes_and_then_stamps() {
        for stamp in [
            None,
            Some(""),
            Some("0.0.0-old"),
            Some("\u{0}\u{1}not a version"),
        ] {
            let dir = tempdir();
            let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
            cache.put(&hash(), &entry());
            let stale = seed_foreign_entry(&cache, &content_hash(b"older release"), "0.0.0-old");

            let path = cache.root().join(STAMP_NAME);
            match stamp {
                Some(text) => fs::write(&path, text).unwrap(),
                None => {
                    let _ = fs::remove_file(&path);
                }
            }

            Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);

            assert!(!stale.exists(), "stamp {stamp:?} must not skip the pass");
            assert_eq!(
                fs::read_to_string(&path).unwrap().trim(),
                VERSION,
                "the pass must leave this build's stamp"
            );
            // The live entry is untouched, stamp or no stamp.
            assert!(cache.get(&hash(), &content()).is_some());
        }
    }

    /// A tree with no cache directory must not grow one, so there is nowhere to
    /// put a stamp and the next open sweeps an empty directory. That is the
    /// cheap case anyway.
    #[test]
    fn a_missing_cache_directory_is_not_created_by_the_stamp() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(!cache.root().exists());
        assert_eq!(prune(dir.path()), 0);
        assert!(!cache.root().exists(), "prune created a cache directory");
    }

    /// The count is what the CLI prints, so it has to be the number of entries
    /// that actually left.
    #[test]
    fn prune_counts_the_entries_it_removed() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash(), &entry());
        assert_eq!(prune(dir.path()), 0, "nothing foreign yet");

        for (index, version) in ["0.0.1", "0.9.0", "1.0.0"].iter().enumerate() {
            seed_foreign_entry(
                &cache,
                &content_hash(format!("old {index}").as_bytes()),
                version,
            );
        }
        assert_eq!(prune(dir.path()), 3);
        assert_eq!(prune(dir.path()), 0, "a second pass finds nothing");
        assert!(cache.get(&hash(), &content()).is_some());
    }

    #[test]
    fn entry_version_reads_the_declared_version_only() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash(), &entry());

        assert_eq!(
            entry_version(&cache.entry_path(&hash()).unwrap()).as_deref(),
            Some(VERSION),
            "an entry this build wrote must name this build"
        );
        assert_eq!(entry_version(&dir.path().join("absent.json")), None);

        let probe = |bytes: &[u8]| {
            let path = dir.path().join("probe.json");
            fs::write(&path, bytes).unwrap();
            entry_version(&path)
        };
        assert_eq!(
            probe(b"{\"version\":\"1.2.3\",\"rest\":1}").as_deref(),
            Some("1.2.3")
        );
        assert_eq!(probe(b"{\"version\":\"\"}").as_deref(), Some(""));
        assert_eq!(probe(b"{ \"version\": \"1.2.3\" }"), None, "not our shape");
        assert_eq!(probe(b"{\"version\":\"1.2\\\"3\"}"), None, "escaped quote");
        assert_eq!(probe(b""), None);
    }

    #[test]
    fn offset_of_inverts_a_reported_position() {
        let content = content();
        let starts = line_starts(&content);

        let offset = offset_of(&starts, 2, 5).unwrap();
        assert_eq!(&content[offset..offset + 5], "other");
        assert_eq!(offset_of(&starts, 1, 1), Some(0));
        assert_eq!(offset_of(&starts, 0, 1), None);
        assert_eq!(offset_of(&starts, 1, 0), None);
        assert_eq!(offset_of(&starts, 99, 1), None);
    }
}
