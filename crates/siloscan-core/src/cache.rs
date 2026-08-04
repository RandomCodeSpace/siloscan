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
//! Entries live inside the scanned tree and are never evicted, so they hold no
//! match text: a finding's match is frequently the secret that was found.
//! Only its length is stored, and the text is read back out of the scanned file
//! itself. A `.gitignore` is written beside the cache directory so entries
//! cannot be committed to the scanned repository.

use std::fmt::Write as _;
use std::fs;
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
    /// Bind a cache to a scan root, a rule set and a path convention. Nothing
    /// touches the file system until the first [`Cache::put`].
    pub fn open(scan_root: &Path, rules: &RuleSet, scope: &PathScope) -> Cache {
        let rules_hash = rules.source_hash();
        let path_scope = scope.discriminator();
        Cache {
            root: scan_root.join(CACHE_DIR),
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
