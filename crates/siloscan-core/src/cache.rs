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
//! # The cache is inside untrusted input
//!
//! A `.gitignore` is a courtesy, not a boundary. Nothing stops a repository
//! from committing a `.siloscan/cache` whose entries claim a file containing a
//! live credential has no findings, and every part of the key - content hash,
//! rule hash, path scope - would legitimately match on a fresh clone. Before
//! this, the scan of that clone reported nothing and exited 0.
//!
//! So an entry is only believed on the checkout that wrote it. Each cache
//! directory holds a `.salt` (see [`SALT_NAME`]), and every entry carries an
//! authentication tag over its own canonical body computed with that salt. A
//! tag that is absent, malformed or does not recompute is a miss - never an
//! error, never a warning - so a foreign, poisoned or simply borrowed cache
//! costs a real scan and nothing else. Rejecting an entry cannot change a
//! report: a miss is a rescan, and a rescan is what a cold run does.
//!
//! The salt is bound to the absolute path of the cache directory as well as to
//! its own random bytes (see [`resolve_salt`]), because an attacker who commits
//! the entries can commit the salt beside them. Their clone and the victim's do
//! not sit at the same absolute path, so the tags do not recompute. That alone
//! is not enough where checkout paths are public and fixed - a GitHub Actions
//! windows runner builds every repository at `D:\a\<repo>\<repo>` - so a salt
//! also has to prove it was written by this build rather than checked out with
//! the tree ([`salt_file`]): an owner-only mode on unix, an alternate data
//! stream on Windows, and on any platform that offers neither, no salt is
//! trusted at all and the cache stays cold. Both are anti-tampering measures,
//! not key management - the honest statement of the residual risk is in
//! [`resolve_salt`].
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Per-directory secret that makes an entry believable. It lives beside the
/// entries it authenticates, inside `.siloscan/cache`, which the walk excludes
/// from every scan and the `.gitignore` above covers.
const SALT_NAME: &str = ".salt";

/// Salt width in bytes, matching the digest that consumes it.
const SALT_LEN: usize = 32;

/// Owner-only file mode for the salt, and the mask a stored salt is checked
/// against on read. Group or world access means the file did not come from
/// [`create_salt`].
#[cfg(unix)]
const SALT_MODE: u32 = 0o600;

/// The NTFS alternate data stream a salt's bytes live in on Windows, appended
/// to [`SALT_NAME`]. See [`salt_file`] for why the salt is not simply the file.
#[cfg(windows)]
const SALT_STREAM: &str = ":siloscan";

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
    /// Hex [`entry_tag`] over the fields above. Defaulted rather than required
    /// so an entry without one parses and then fails the comparison: an
    /// untagged entry is a miss like any other, not a parse error.
    #[serde(default)]
    tag: String,
}

/// The part of an entry the tag covers, borrowed from a [`StoredEntry`].
///
/// Reading re-serializes this from the parsed entry rather than tagging the
/// bytes on disk, so the tag is over one canonical form of the body. Whitespace,
/// field order and any field this build does not know about are then free to
/// differ without touching the tag, and none of them can carry meaning past it.
#[derive(Serialize)]
struct EntryBody<'a> {
    version: &'a str,
    path_scope: &'a str,
    findings: &'a [StoredFinding],
    facts: &'a Option<FileFacts>,
}

impl StoredEntry {
    /// Canonical bytes of everything but the tag. `None` only if the body
    /// cannot be serialized, which makes the entry unusable either way.
    ///
    /// [`StoredEntry`] is destructured exhaustively - no `..` - so this list
    /// cannot drift from the one above it. A field added to a stored entry and
    /// not to [`EntryBody`] would otherwise land outside the tag and be
    /// attacker-controlled data the authentication says nothing about; with the
    /// binding written out, adding one is a compile error until it is either
    /// covered or explicitly named and dropped here.
    ///
    /// Chosen over tagging the serialized entry minus its `tag` field, which
    /// would derive the coverage from the type with no list to keep in step:
    /// that shape has to reach the same bytes through a serde value or a
    /// string edit of the JSON, and either one changes what the tag is computed
    /// over. Every cache entry in existence would then fail to authenticate
    /// against the build that wrote it - a silent, tree-wide cold scan bought
    /// for a guard the compiler can give for free.
    fn body_bytes(&self) -> Option<Vec<u8>> {
        let StoredEntry {
            version,
            path_scope,
            findings,
            facts,
            // The tag is what this body is tagged with; covering it with itself
            // is not a thing that can be done.
            tag: _,
        } = self;
        serde_json::to_vec(&EntryBody {
            version,
            path_scope,
            findings,
            facts,
        })
        .ok()
    }
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
    ///
    /// The UTF-16 column is recomputed here rather than stored. It is a
    /// function of the line prefix, and the entry is only usable at all when
    /// that prefix is present and addressable, so recomputing costs one pass
    /// over a line and keeps the on-disk shape free of a second spelling of a
    /// column that could drift from the first. A cache hit and a cold scan of
    /// the same bytes therefore produce identical findings, which is what makes
    /// SARIF output independent of cache state.
    fn restore(self, starts: &[usize], content: &str) -> Option<Finding> {
        let start = offset_of(starts, self.line, self.column)?;
        let end = start.checked_add(self.matched_len)?;
        let matched = content.get(start..end)?;
        let line_start = *starts.get(usize::try_from(self.line.checked_sub(1)?).ok()?)?;
        let prefix = content.get(line_start..start)?;

        Some(Finding {
            rule_id: self.rule_id,
            severity: self.severity,
            message: self.message,
            path: self.path,
            line: self.line,
            column: self.column,
            column_utf16: crate::engines::utf16_column(prefix),
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
    /// This directory's salt, bound to its location, resolved at most once per
    /// cache. Reading may find none; writing creates one. Opening resolves
    /// nothing, because a scan of a tree with no cache must not grow one.
    salt: OnceLock<[u8; SALT_LEN]>,
    /// Set once a read has failed to find a usable salt, so a cold or foreign
    /// cache is not probed again for every file in the tree. Writing ignores
    /// it: [`Cache::put`] creates the directory and the salt with it, and
    /// publishes the result through `salt`, which is consulted first.
    salt_missing: AtomicBool,
    /// Held while this process creates the salt, so exactly one thread does.
    ///
    /// [`create_salt`] tolerates losing the create race by reading back what
    /// the winner wrote, and across processes that is enough - the loser reads
    /// a half-written file at worst, and pays one uncached run for it. Inside
    /// one process it is not enough: the workers reach a cold cache together,
    /// so nearly all of them lose the race, read a file whose bytes do not
    /// exist yet, and write no entry at all. A cold scan then caches one file
    /// out of however many it read, and the cache only fills over later runs.
    salt_create: Mutex<()>,
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
            salt: OnceLock::new(),
            salt_missing: AtomicBool::new(false),
            salt_create: Mutex::new(()),
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
    /// scope-mismatched, untrusted and unrecoverable entries are all plain
    /// misses: the caller scans the file, which is what it would have done on a
    /// cold cache, so no report depends on any of this.
    pub fn get(&self, content_hash: &str, content: &str) -> Option<CachedFile> {
        let path = self.entry_path(content_hash)?;
        let bytes = fs::read(path).ok()?;
        let stored: StoredEntry = serde_json::from_slice(&bytes).ok()?;
        if stored.version != VERSION || stored.path_scope != self.path_scope {
            return None;
        }
        // Nothing below this line trusts the entry's contents until the tag
        // over them recomputes under this checkout's salt.
        let salt = self.salt_for_read()?;
        let body = stored.body_bytes()?;
        if entry_tag(salt, &self.entry_key(content_hash), &body) != stored.tag {
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
        // An entry this checkout cannot authenticate would be an entry it could
        // never read back, so there is no point writing one.
        let Some(salt) = self.salt_for_write() else {
            return;
        };

        let stored = StoredEntry {
            version: VERSION.to_string(),
            path_scope: self.path_scope.clone(),
            findings: entry.findings.iter().map(StoredFinding::new).collect(),
            facts: entry.facts.clone(),
            tag: String::new(),
        };
        let Some(body) = stored.body_bytes() else {
            return;
        };
        let stored = StoredEntry {
            tag: entry_tag(salt, &self.entry_key(content_hash), &body),
            ..stored
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

    /// The identity the tag binds a body to: the content it was produced from
    /// and the rules and path convention that produced it. Both halves are
    /// fixed-width hex, so no pair of keys can be read as another.
    fn entry_key(&self, content_hash: &str) -> String {
        format!("{content_hash}\0{}", self.scope_hash)
    }

    /// This cache's salt for reading, or `None` when there is nothing to read
    /// it from - an absent, unreadable or foreign salt file, or a directory
    /// whose location cannot be resolved. Every one of those makes the whole
    /// cache cold, which is a correct cache.
    fn salt_for_read(&self) -> Option<&[u8; SALT_LEN]> {
        if let Some(salt) = self.salt.get() {
            return Some(salt);
        }
        if self.salt_missing.load(Ordering::Relaxed) {
            return None;
        }
        match resolve_salt(&self.root, false) {
            Some(salt) => Some(self.salt.get_or_init(|| salt)),
            None => {
                self.salt_missing.store(true, Ordering::Relaxed);
                None
            }
        }
    }

    /// This cache's salt for writing, creating one if the directory has none.
    /// `None` when it cannot be created or read back, which means this run
    /// writes no entries.
    ///
    /// Creation is serialized on `salt_create`, so within this process exactly
    /// one thread calls [`create_salt`] and the rest find the finished value in
    /// the [`OnceLock`]. Doing it unlocked would make every worker race for a
    /// file that exists before its bytes do: the winner writes an entry and the
    /// losers read an empty salt and write none, which costs a cold scan nearly
    /// all of its entries. Another *process* racing this one still resolves the
    /// same way [`create_salt`] describes.
    ///
    /// The lock is held across a file create and a small write, and only until
    /// the first salt is resolved; afterwards the [`OnceLock`] answers without
    /// taking it.
    fn salt_for_write(&self) -> Option<&[u8; SALT_LEN]> {
        if let Some(salt) = self.salt.get() {
            return Some(salt);
        }
        // A poisoned lock guards no invariant of its own: the salt either
        // resolved into the `OnceLock` or it did not, and either way the value
        // behind the guard is `()`.
        let _guard = self
            .salt_create
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Re-checked under the lock: the thread that held it may have resolved
        // the salt while this one waited.
        if let Some(salt) = self.salt.get() {
            return Some(salt);
        }
        let salt = resolve_salt(&self.root, true)?;
        Some(self.salt.get_or_init(|| salt))
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

/// The salt this cache directory's entries are authenticated with, or `None`
/// when there is none to be had. With `create`, a directory that exists and has
/// no salt gets one; without it, nothing is written and nothing is created.
///
/// The value returned is not the file's bytes but those bytes bound to the
/// directory's absolute location, so an entry authenticates for one checkout at
/// one path. That is what defeats a committed cache: the attacker can commit
/// the salt beside the entries they forged, and their tree and their victim's
/// still do not sit at the same absolute path. A location that cannot be
/// resolved yields `None` - a cache that cannot say where it is does not get
/// believed.
///
/// This is tamper resistance, not key management. The salt sits unencrypted in
/// a file any process running as this user can read, and an attacker who knows
/// the absolute path a target will scan at, can read or predict that target's
/// salt, and can get the file there with owner-only permissions can still forge
/// an entry. What it stops is the case that shipped: a cache committed to a
/// repository, cloned somewhere else, and believed.
fn resolve_salt(root: &Path, create: bool) -> Option<[u8; SALT_LEN]> {
    let stored = match read_salt(root) {
        Some(salt) => salt,
        None if create => create_salt(root)?,
        None => return None,
    };
    let location = fs::canonicalize(root).ok()?;

    let mut hasher = Sha256::new();
    hasher.update(stored);
    hasher.update([0]);
    hasher.update(location.as_os_str().as_encoded_bytes());
    Some(hasher.finalize().into())
}

/// Where a salt's bytes are read from and written to under `root`, or `None` on
/// a platform where this build cannot tell a salt it wrote from one that
/// arrived with the tree.
///
/// The check has to be something a repository cannot carry, because the
/// committed-cache attack hands the victim a `.salt` along with the forged
/// entries and the path binding in [`resolve_salt`] is not enough on its own
/// where checkout paths are public and fixed.
///
/// - unix: the file itself, and [`read_salt`] rejects any mode wider than
///   [`SALT_MODE`]. Git records no file mode but the executable bit, so a
///   checked-out `.salt` is never owner-only.
/// - windows: an NTFS alternate data stream on `.salt` ([`SALT_STREAM`]). Git
///   does not record streams, and no archive format a tree arrives in carries
///   one, so a `.salt` that came with the checkout has no stream and the bytes
///   this build reads are ones it wrote. A committed `.salt` is simply never
///   read: only the stream is. On a volume with no stream support - FAT32,
///   exFAT, some network shares - creating it fails and the cache stays cold,
///   which is a correct cache.
/// - anything else: `None`. A gate that cannot be evaluated does not get to
///   pass, so a platform where provenance cannot be established trusts no salt,
///   writes none, and scans cold every time.
fn salt_file(root: &Path) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(root.join(SALT_NAME))
    }
    #[cfg(windows)]
    {
        Some(root.join(format!("{SALT_NAME}{SALT_STREAM}")))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = root;
        None
    }
}

/// The salt stored in `root`, if it is one this build would have written.
///
/// Provenance is [`salt_file`]'s business, plus the mode check below on the one
/// platform where the path alone does not carry it. Everything else - absent,
/// unreadable, not hex, wrong length - lands in the same place, which is a cold
/// cache.
fn read_salt(root: &Path) -> Option<[u8; SALT_LEN]> {
    let path = salt_file(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = fs::metadata(&path).ok()?;
        if !meta.is_file() {
            return None;
        }
        if meta.permissions().mode() & !SALT_MODE & 0o777 != 0 {
            return None;
        }
    }
    unhex(fs::read_to_string(&path).ok()?.trim())
}

/// Write a fresh salt into an existing cache directory and return it.
///
/// The file is created exclusively, so a concurrent writer cannot be
/// overwritten - losing that race means reading the winner's salt instead. A
/// directory that does not exist is not created here; only [`Cache::put`]
/// creates one, and it does so before asking for a salt.
///
/// A salt that fails the provenance check is *replaced*, once, rather than left
/// where it is. Leaving it was the previous behavior and it was a trap: the
/// exclusive create can never overwrite the file, [`read_salt`] can never
/// accept it, and the result is a cache that is cold on every scan, forever,
/// with nothing said about why. Replacement costs whatever was written under
/// the salt it replaces, which becomes misses like any other stale entry, and
/// costs it once. It is silent, like every other failure in this module: a
/// cache is not a channel this crate reports through, and a line per scan for a
/// condition that fixes itself on the first one would be noise on every run
/// afterwards.
///
/// On Windows the exclusive create is on the stream ([`salt_file`]), so a
/// `.salt` that arrived with a checkout is neither read nor rewritten: the
/// stream beside it is this build's, and the file's own contents stay where
/// they are and mean nothing to anyone here.
///
/// The file exists for a moment before its bytes do, so a second process that
/// looks in exactly that window reads a salt it cannot parse and treats the
/// cache as cold for that run. It costs the loser of that race a scan it was
/// going to do anyway on a cache this empty, and the next run finds a finished
/// file. Nothing about a report depends on which side of it a process lands.
fn create_salt(root: &Path) -> Option<[u8; SALT_LEN]> {
    if !root.is_dir() {
        return None;
    }
    let path = salt_file(root)?;
    let salt = generate_salt(root);

    if let Some(written) = write_salt(&path, &salt) {
        return Some(written);
    }
    // Either someone else got there first, or the file is one this build can
    // never use. Only the second is replaced, and only once: losing the second
    // create too means another process refilled it in the same window, and its
    // salt is the one to read.
    if foreign_salt(&path)
        && fs::remove_file(&path).is_ok()
        && let Some(written) = write_salt(&path, &salt)
    {
        return Some(written);
    }
    read_salt(root)
}

/// Create `path` exclusively, owner-only, holding `salt`. `None` when the file
/// already existed or the write did not complete.
fn write_salt(path: &Path, salt: &[u8; SALT_LEN]) -> Option<[u8; SALT_LEN]> {
    use std::io::Write as _;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(SALT_MODE);
    }
    let mut file = options.open(path).ok()?;
    let mut text = hex(salt);
    text.push('\n');
    file.write_all(text.as_bytes()).ok()?;
    file.sync_all().ok()?;
    Some(*salt)
}

/// True when a salt file exists and fails the provenance check [`read_salt`]
/// applies before it reads a byte: on unix, a regular file whose mode is wider
/// than [`SALT_MODE`].
///
/// Deliberately narrower than "[`read_salt`] returned `None`". A salt with the
/// right mode whose bytes do not parse is the create race described on
/// [`create_salt`] - a file that exists a moment before its contents do - and
/// deleting it on sight would be one process undoing another's work. That case
/// recovers by itself on the next run. A file that cannot have been written
/// here never recovers, which is what makes it worth replacing.
///
/// Anything that is not a regular file is left alone: it is not a salt this
/// build wrote and not one it can remove with a single `unlink` either.
#[cfg(unix)]
fn foreign_salt(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & !SALT_MODE & 0o777 != 0)
}

/// No provenance check outside unix carries a signal a file can fail on its
/// own: on Windows the salt is an alternate data stream, which a checkout
/// cannot carry at all, and elsewhere there is no salt to begin with.
#[cfg(not(unix))]
fn foreign_salt(_path: &Path) -> bool {
    false
}

/// Unpredictable bytes for a new salt.
///
/// Every platform contributes randomness the operating system produced, and it
/// has to: a salt an attacker can guess is a tag they can forge, and the whole
/// of the committed-cache defense rests on not being able to. Where a salt was
/// derived from the process id, the wall clock and the directory path alone -
/// which is what a platform without `/dev/urandom` used to get - anyone who
/// knew roughly when and where the cache was created could produce it.
///
/// Two sources, folded together:
///
/// - `/dev/urandom`, where the platform has it.
/// - [`RandomState`](std::collections::hash_map::RandomState), which the
///   standard library seeds from the operating system's randomness. It is the
///   only OS randomness `std` exposes on every target, and on Windows it is the
///   only one available here without a dependency. Its key is 128 bits, so a
///   salt made from it alone has 128 bits behind it rather than 256; four
///   keyed hashes of distinct inputs spread that key across the digest.
///
/// The process id, the clock, a per-process counter and the directory path are
/// still folded in. They are not entropy and are not counted as any: they only
/// keep two salts made in the same process from colliding if a random source
/// ever repeats itself.
fn generate_salt(root: &Path) -> [u8; SALT_LEN] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut hasher = Sha256::new();
    if let Ok(mut urandom) = fs::File::open("/dev/urandom") {
        let mut bytes = [0u8; SALT_LEN];
        if urandom.read_exact(&mut bytes).is_ok() {
            hasher.update(bytes);
        }
    }
    hasher.update([0]);
    hasher.update(os_random_bytes());
    hasher.update([0]);
    hasher.update(std::process::id().to_le_bytes());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or_default();
    hasher.update(nanos.to_le_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hasher.update(root.as_os_str().as_encoded_bytes());
    hasher.finalize().into()
}

/// [`SALT_LEN`] bytes derived from a freshly constructed
/// [`RandomState`](std::collections::hash_map::RandomState), whose keys the
/// standard library takes from the operating system.
///
/// The state is not readable, so it is spent through the one thing a
/// [`BuildHasher`](std::hash::BuildHasher) does: four hashes of four distinct
/// inputs under the same key, which is eight bytes of output each. The result
/// is not more than the 128 bits of key behind it and is not claimed to be; it
/// is unpredictable to anyone who cannot read this process's memory, which is
/// what a salt needs and what a clock never was.
fn os_random_bytes() -> [u8; SALT_LEN] {
    use std::hash::{BuildHasher as _, RandomState};

    let state = RandomState::new();
    let mut bytes = [0u8; SALT_LEN];
    for (index, chunk) in bytes.chunks_mut(8).enumerate() {
        let word = state.hash_one((index as u64, u64::MAX - index as u64));
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    bytes
}

/// The [`SALT_LEN`]-byte value `text` spells in lowercase or uppercase hex, or
/// `None` if it does not spell exactly one.
fn unhex(text: &str) -> Option<[u8; SALT_LEN]> {
    let bytes = text.as_bytes();
    if bytes.len() != SALT_LEN * 2 {
        return None;
    }
    if !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; SALT_LEN];
    for (byte, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let text = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

/// Hex SHA-256 binding an entry's body to its key and this directory's salt,
/// NUL-separated like every other composite hash here. The salt comes first, so
/// no attacker-controlled prefix can position itself ahead of it.
fn entry_tag(salt: &[u8; SALT_LEN], key: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update([0]);
    hasher.update(key.as_bytes());
    hasher.update([0]);
    hasher.update(body);
    hex(&hasher.finalize())
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
            // The fixture is ASCII, so the two columns coincide. A restored
            // finding recomputes this, and comparing it against the original
            // is what proves the recomputation agrees with the engine.
            column_utf16: column,
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

    /// The body an entry stores is a pure function of what was cached: two
    /// caches record the same result the same way. Only the tag differs, and it
    /// has to - it is what ties the entry to the directory it lives in.
    #[test]
    fn stored_bodies_are_identical_across_puts_and_tags_are_not() {
        let dir_a = tempdir();
        let dir_b = tempdir();
        let hash = hash();

        let a = Cache::open(dir_a.path(), &ruleset("a"), &PathScope::ScanRoot);
        let b = Cache::open(dir_b.path(), &ruleset("a"), &PathScope::ScanRoot);
        a.put(&hash, &entry());
        b.put(&hash, &entry());

        let left = fs::read(a.entry_path(&hash).unwrap()).unwrap();
        assert_eq!(
            read_entry(&a, &hash).body_bytes(),
            read_entry(&b, &hash).body_bytes()
        );
        assert_ne!(
            read_entry(&a, &hash).tag,
            read_entry(&b, &hash).tag,
            "two directories must not authenticate each other's entries"
        );
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

    /// The entry as it sits on disk.
    fn read_entry(cache: &Cache, content_hash: &str) -> StoredEntry {
        let path = cache.entry_path(content_hash).unwrap();
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    /// Rewrite an entry the way an attacker with a text editor would: change
    /// the body, leave the tag alone.
    fn tamper(cache: &Cache, content_hash: &str, edit: impl FnOnce(&mut StoredEntry)) {
        let mut stored = read_entry(cache, content_hash);
        edit(&mut stored);
        let path = cache.entry_path(content_hash).unwrap();
        fs::write(path, serde_json::to_vec(&stored).unwrap()).unwrap();
    }

    /// Rewrite an entry the way this build would: change the body and re-tag it
    /// with the salt that is actually in the directory.
    fn retag(cache: &Cache, content_hash: &str, edit: impl FnOnce(&mut StoredEntry)) {
        let mut stored = read_entry(cache, content_hash);
        edit(&mut stored);
        let salt = resolve_salt(cache.root(), false).expect("a written cache has a salt");
        stored.tag = entry_tag(
            &salt,
            &cache.entry_key(content_hash),
            &stored.body_bytes().unwrap(),
        );
        let path = cache.entry_path(content_hash).unwrap();
        fs::write(path, serde_json::to_vec(&stored).unwrap()).unwrap();
    }

    /// Where this platform keeps a salt's bytes, which is not always the file
    /// named [`SALT_NAME`] - see [`salt_file`].
    fn salt_path(cache: &Cache) -> PathBuf {
        salt_file(cache.root()).expect("this platform trusts no salt at all")
    }

    /// Put `text` in the salt file with the permissions this build writes, so a
    /// test about the salt's contents is not quietly decided by its mode.
    fn write_salt(cache: &Cache, text: &str) {
        let path = salt_path(cache);
        fs::write(&path, text).unwrap();
        set_owner_only(&path);
    }

    fn set_owner_only(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(SALT_MODE)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    /// The shipped defect, at this layer: an entry that says the file is clean
    /// is believed, and the credential in it is never reported. Editing the
    /// findings out of an entry must cost the attacker the entry.
    #[test]
    fn an_entry_whose_body_was_edited_is_a_miss() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hash = hash();
        cache.put(&hash, &entry());
        assert!(cache.get(&hash, &content()).is_some(), "warm to begin with");

        // The exact edit from the report: the findings are emptied out.
        tamper(&cache, &hash, |stored| stored.findings.clear());
        assert!(
            cache.get(&hash, &content()).is_none(),
            "an emptied entry was served, so the credential goes unreported"
        );

        // Every other edit to the body lands the same way.
        type Edit = Box<dyn FnOnce(&mut StoredEntry)>;
        let cases: Vec<Edit> = vec![
            Box::new(|stored: &mut StoredEntry| stored.findings.truncate(1)),
            Box::new(|stored: &mut StoredEntry| stored.findings[0].severity = Severity::Info),
            Box::new(|stored: &mut StoredEntry| stored.findings[0].matched_len = 1),
            Box::new(|stored: &mut StoredEntry| stored.findings[0].fingerprint = "00".to_string()),
            Box::new(|stored: &mut StoredEntry| stored.tag = String::new()),
            Box::new(|stored: &mut StoredEntry| stored.tag.insert(0, 'a')),
        ];
        for edit in cases {
            cache.put(&hash, &entry());
            assert!(cache.get(&hash, &content()).is_some());
            tamper(&cache, &hash, edit);
            assert!(cache.get(&hash, &content()).is_none());
        }
    }

    /// An entry written by another checkout is not this checkout's to believe,
    /// whether or not the salt travelled with it. The second half is the
    /// committed-cache attack: `.siloscan` is checked in wholesale, salt
    /// included, and cloned somewhere else.
    #[test]
    fn an_entry_from_another_cache_directory_is_a_miss() {
        let hash = hash();
        let theirs_dir = tempdir();
        let mine_dir = tempdir();
        let theirs = Cache::open(theirs_dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let mine = Cache::open(mine_dir.path(), &ruleset("a"), &PathScope::ScanRoot);

        theirs.put(&hash, &entry());
        let source = theirs.entry_path(&hash).unwrap();
        let target = mine.entry_path(&hash).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(&source, &target).unwrap();

        assert!(
            mine.get(&hash, &content()).is_none(),
            "a foreign entry was served"
        );

        // Now with the salt as well, as a committed `.siloscan/cache` would
        // arrive. A fresh instance is used because the first one has already
        // resolved this directory as saltless.
        fs::copy(salt_path(&theirs), salt_path(&mine)).unwrap();
        set_owner_only(&salt_path(&mine));
        let mine = Cache::open(mine_dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(
            mine.get(&hash, &content()).is_none(),
            "a cache committed with its salt was served to a different checkout"
        );

        // The directory it was written in still reads it.
        assert!(theirs.get(&hash, &content()).is_some());
    }

    /// Warm caches still have to be warm, and a hit has to be the stored entry
    /// rather than a coincidence. The message here is one no engine produces:
    /// seeing it back proves the value came off the disk.
    #[test]
    fn a_legitimate_entry_is_a_hit_across_cache_instances() {
        let dir = tempdir();
        let hash = hash();
        let first = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        first.put(&hash, &entry());

        retag(&first, &hash, |stored| {
            stored.findings[0].message = "served from the cache".to_string();
        });

        // A second instance reads the salt back off the disk, which is what the
        // next run of the binary does.
        let second = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        let hit = second
            .get(&hash, &content())
            .expect("a warm entry is a hit");
        assert_eq!(hit.findings[0].message, "served from the cache");
        assert_eq!(hit.findings[0].matched, SECRET, "match text is recovered");
        assert_eq!(hit.findings.len(), 2);
    }

    /// No salt, an unreadable salt, or one that is not a salt: all of them are
    /// a cold cache. None of them is an error, and none of them removes an
    /// entry - a salt that comes back is a cache that comes back.
    #[test]
    fn a_missing_or_unusable_salt_is_a_cold_cache() {
        let dir = tempdir();
        let hash = hash();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash, &entry());
        let good = fs::read_to_string(salt_path(&cache)).unwrap();
        let entry_bytes = fs::read(cache.entry_path(&hash).unwrap()).unwrap();

        for salt in [
            None,
            Some(String::new()),
            Some("not hex at all\n".to_string()),
            Some("ab\n".to_string()),
            Some(format!("{}\n", "zz".repeat(SALT_LEN))),
            Some(format!("{}\n", "ab".repeat(SALT_LEN + 1))),
        ] {
            match &salt {
                Some(text) => write_salt(&cache, text),
                None => fs::remove_file(salt_path(&cache)).unwrap(),
            }

            let cold = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
            assert!(cold.get(&hash, &content()).is_none(), "salt {salt:?}");
            // Repeated misses stay misses and stay quiet.
            assert!(cold.get(&hash, &content()).is_none(), "salt {salt:?}");
            assert_eq!(
                fs::read(cache.entry_path(&hash).unwrap()).unwrap(),
                entry_bytes,
                "a rejected entry must not be disturbed"
            );
        }

        write_salt(&cache, &good);
        let warm = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(warm.get(&hash, &content()).is_some());
    }

    /// A cache directory with a salt this build will not use writes no entries
    /// either: an entry it could not read back is not worth the bytes.
    #[test]
    fn an_unusable_salt_is_not_replaced_and_stops_writes() {
        let dir = tempdir();
        let hash = hash();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash, &entry());

        let foreign = "not a salt\n";
        write_salt(&cache, foreign);
        fs::remove_file(cache.entry_path(&hash).unwrap()).unwrap();

        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash, &entry());
        assert!(
            !cache.entry_path(&hash).unwrap().exists(),
            "an entry was written that could never be read back"
        );
        assert_eq!(
            fs::read_to_string(salt_path(&cache)).unwrap(),
            foreign,
            "a salt this build did not write must not be overwritten"
        );
    }

    #[test]
    fn the_salt_is_written_once_and_is_random() {
        let dir_a = tempdir();
        let dir_b = tempdir();
        let a = Cache::open(dir_a.path(), &ruleset("a"), &PathScope::ScanRoot);
        let b = Cache::open(dir_b.path(), &ruleset("a"), &PathScope::ScanRoot);

        a.put(&hash(), &entry());
        let written = fs::read_to_string(salt_path(&a)).unwrap();
        assert_eq!(written.trim().len(), SALT_LEN * 2);
        assert!(unhex(written.trim()).is_some());

        // Writing more entries does not rewrite it.
        a.put(&content_hash(b"other"), &entry());
        assert_eq!(fs::read_to_string(salt_path(&a)).unwrap(), written);

        b.put(&hash(), &entry());
        assert_ne!(
            fs::read_to_string(salt_path(&b)).unwrap(),
            written,
            "two caches must not share a salt"
        );
    }

    /// A scan of a tree with no cache still creates nothing, salt included.
    #[test]
    fn no_salt_is_created_by_reading() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(cache.get(&hash(), &content()).is_none());
        assert!(!cache.root().exists());
        assert!(!salt_path(&cache).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_salt_is_owner_only_and_a_wider_one_is_ignored() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir();
        let hash = hash();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash, &entry());

        let mode = fs::metadata(salt_path(&cache))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, SALT_MODE, "salt mode {:o}", mode & 0o777);

        // A checkout produces a group- or world-readable file, which is the
        // signal that this salt arrived with the tree rather than being written
        // here.
        for wider in [0o644, 0o640, 0o604, 0o666] {
            fs::set_permissions(salt_path(&cache), fs::Permissions::from_mode(wider)).unwrap();
            let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
            assert!(
                cache.get(&hash, &content()).is_none(),
                "a {wider:o} salt was trusted"
            );
        }

        fs::set_permissions(salt_path(&cache), fs::Permissions::from_mode(SALT_MODE)).unwrap();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(cache.get(&hash, &content()).is_some());
    }

    /// A salt this build cannot use is not a permanent dead end. Rejecting it
    /// and never replacing it left the cache cold on every scan, forever, with
    /// no diagnostic - the exclusive create could not overwrite the file and the
    /// mode check could not accept it.
    #[cfg(unix)]
    #[test]
    fn a_foreign_salt_is_replaced_and_the_cache_warms_again() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir();
        let hash = hash();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash, &entry());

        let path = salt_path(&cache);
        let before = fs::read_to_string(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        // The entries under the old salt are misses, as they must be: nothing
        // here starts trusting a salt it rejected.
        let reopened = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(reopened.get(&hash, &content()).is_none());

        // The next write replaces the salt rather than giving up on it.
        reopened.put(&hash, &entry());
        let after = fs::read_to_string(&path).unwrap();
        assert_ne!(after, before, "the rejected salt must not survive");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            SALT_MODE
        );

        let warm = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        assert!(
            warm.get(&hash, &content()).is_some(),
            "the cache must work again once the salt is this build's"
        );
    }

    /// Moving a checkout is not tampering, but the entries were authenticated
    /// where they were written, so the move costs a cold scan and nothing else.
    #[test]
    fn a_relocated_cache_is_a_cold_cache() {
        let dir = tempdir();
        let hash = hash();
        let from = dir.path().join("before");
        let to = dir.path().join("after");
        fs::create_dir_all(&from).unwrap();

        let cache = Cache::open(&from, &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash, &entry());
        assert!(cache.get(&hash, &content()).is_some());

        fs::rename(&from, &to).unwrap();
        let moved = Cache::open(&to, &ruleset("a"), &PathScope::ScanRoot);
        assert!(moved.get(&hash, &content()).is_none());

        // And it warms right back up where it now lives.
        moved.put(&hash, &entry());
        let reopened = Cache::open(&to, &ruleset("a"), &PathScope::ScanRoot);
        assert!(reopened.get(&hash, &content()).is_some());
    }

    #[test]
    fn the_tag_covers_the_key_as_well_as_the_body() {
        let dir = tempdir();
        let cache = Cache::open(dir.path(), &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash(), &entry());
        let salt = resolve_salt(cache.root(), false).unwrap();
        let body = read_entry(&cache, &hash()).body_bytes().unwrap();

        let tag = entry_tag(&salt, &cache.entry_key(&hash()), &body);
        assert_eq!(tag, read_entry(&cache, &hash()).tag);
        assert_eq!(tag.len(), 64);
        assert_ne!(
            tag,
            entry_tag(&salt, &cache.entry_key(&content_hash(b"other")), &body),
            "the tag must not travel between keys"
        );
        assert_ne!(
            tag,
            entry_tag(&[0u8; SALT_LEN], &cache.entry_key(&hash()), &body),
            "the tag must not survive a different salt"
        );
    }

    /// A salt is only as good as the randomness behind it: one derived from the
    /// process id, the clock and the directory path is reproducible by anyone
    /// who knows roughly when and where the cache was created, and reproducing
    /// the salt is forging the entries.
    #[test]
    fn salt_bytes_come_from_a_live_random_source() {
        let first = os_random_bytes();
        let second = os_random_bytes();

        assert_ne!(first, second, "the random source repeated itself");
        assert_ne!(first, [0u8; SALT_LEN], "the random source produced nothing");

        // And the salt for one fixed directory is not a function of that
        // directory.
        let root = Path::new("/fixed/cache/directory");
        assert_ne!(generate_salt(root), generate_salt(root));
    }

    #[test]
    fn unhex_accepts_exactly_one_salt() {
        assert_eq!(unhex(&"00".repeat(SALT_LEN)), Some([0u8; SALT_LEN]));
        assert_eq!(unhex(&"ff".repeat(SALT_LEN)), Some([0xffu8; SALT_LEN]));
        assert_eq!(unhex(&"AB".repeat(SALT_LEN)), Some([0xabu8; SALT_LEN]));
        assert_eq!(unhex(""), None);
        assert_eq!(unhex(&"ab".repeat(SALT_LEN - 1)), None);
        assert_eq!(unhex(&"ab".repeat(SALT_LEN + 1)), None);
        assert_eq!(unhex(&"zz".repeat(SALT_LEN)), None);
        assert_eq!(unhex(&format!("+1{}", "ab".repeat(SALT_LEN - 1))), None);
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
