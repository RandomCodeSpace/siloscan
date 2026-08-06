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
//! Entries hold no match text: a finding's match is frequently the secret that
//! was found. Only its length is stored, and the text is read back out of the
//! scanned file itself.
//!
//! # Where the cache lives, and why that is the defence
//!
//! Not in the scanned tree. Entries live under the invoking user's own cache
//! directory - `XDG_CACHE_HOME`, else `$HOME/.cache` on unix, `LOCALAPPDATA` on
//! Windows - in a [`CACHE_NAMESPACE`] directory, and inside that a directory
//! named by a hash of the scan root's canonical path ([`root_dir`]). Where no
//! such directory can be determined there is no cache at all: every read is a
//! miss, nothing is written, and the scan runs cold and correct rather than
//! falling back into the tree.
//!
//! A repository can commit anything, including a cache. An entry claiming that
//! a file holding a live credential has no findings matches on every part of
//! the key - content hash, rule hash, path scope - on a fresh clone, and the
//! scan of that clone reported nothing and exited 0. Up to 1.3.0 the only thing
//! between that entry and a clean report was the authentication tag below,
//! whose provenance rested on the salt file's mode. A tree delivered as an
//! archive, a container layer or a vendored dependency carries a `0600` file
//! exactly as it was packed, so that gate passed; an attacker who also knows the
//! absolute path the tree will be scanned at - a published `WORKDIR`, a CI
//! checkout path - defeated the rest, and the scan reported a poisoned tree as
//! clean. Moving the cache out of the tree removes the delivery mechanism
//! rather than one of its checks: no path leads from anything inside the scanned
//! tree to the bytes this module reads.
//!
//! An in-tree `.siloscan/cache` ([`CACHE_DIR`]) is therefore never read and
//! never written. It is also never removed - deleting files inside a repository
//! this crate was asked to read is not this crate's business.
//!
//! A `--cache-dir` comes from the command line rather than from the tree, so it
//! is used as given ([`Cache::open_in`]). The per-scan-root subdirectory still
//! applies inside it, because keeping two scan roots apart is a correctness
//! property - entries carry paths - and not a location policy.
//!
//! Out of the tree is not the same as out of the walk. A scan root can sit above
//! the user's cache directory - `siloscan ~`, `siloscan /`, a `--cache-dir`
//! pointed inside the root - and then the cache is walked like any other
//! directory, which makes a warm run report the entries the cold run wrote and
//! makes the scan read its own salt as content. [`Cache::exclusion_under`] is
//! what the scan keeps out of the walk to prevent that, and it is the caller's
//! job to ask.
//!
//! Because the location is derived from the invoking user's environment, two
//! uids get two caches without contending for one set of files. The mixed-uid
//! container case that lost its cache permanently in 1.3.0 resolves into two
//! independent caches here, and only a deliberately shared `HOME` puts them back
//! in one directory.
//!
//! # Entries are still authenticated
//!
//! Location is the boundary; the tag is what makes a cache that was copied,
//! moved or borrowed cost a rescan instead of a wrong answer. Each cache
//! directory holds a `.salt` (see [`SALT_NAME`]), and every entry carries a tag
//! over its own canonical body computed with that salt. A tag that is absent,
//! malformed or does not recompute is a miss - never an error, never a warning.
//! Rejecting an entry cannot change a report: a miss is a rescan, and a rescan
//! is what a cold run does.
//!
//! A salt's bytes come from the operating system's random source and from
//! nothing else ([`generate_salt`]). Where that source cannot be reached there
//! is no salt at all: none is written, every entry is a miss, and every scan
//! runs cold. A cold scan is a correct scan, and it is the only safe direction
//! to fail in - a salt made from anything an attacker could reproduce is a tag
//! they can forge.
//!
//! The salt is bound to the absolute path of the cache directory as well as to
//! its own random bytes (see [`resolve_salt`]), so entries authenticate in one
//! directory and nowhere else. The owner-only mode on unix and the alternate
//! data stream on Windows ([`salt_file`]) are kept as defence in depth against a
//! salt that arrived from somewhere else; they are no longer load-bearing, and
//! they were never sufficient on their own. What keeps the scanned tree out is
//! that the scanned tree is not where any of this is read from.
//!
//! # Who else can read it, and who else can write it
//!
//! Being in the user's own cache directory is a statement about which tree the
//! bytes came from, not about which users can reach them. An entry is an
//! inventory of a private tree - every scanned file's path, the rule that fired,
//! the line and column it fired at, and the exact byte length of each secret -
//! and up to 1.4.1 it was created with whatever the process umask allowed. At
//! the common `022` that is a world-readable file in a world-readable directory,
//! which hands every local account a map of a tree they cannot open. At `002` or
//! `000` the directory is group- or world-*writable*, and then the salt below is
//! replaceable by anyone on the machine: they delete it, write their own, and
//! every entry they forge under it authenticates. That is the tag-forging
//! primitive the 1.4.0 relocation existed to remove, restored by a umask.
//!
//! So on unix nothing here is left to the umask:
//!
//! - The cache root, the per-scan-root directory and every directory created
//!   between them are made with mode `0700`, set explicitly after creation
//!   because `mkdir`'s mode argument is masked ([`create_dir_all_secure`]).
//! - Entries, the salt and the prune stamp are created `0600`, set explicitly
//!   on the open file for the same reason.
//! - Before the directory is read from or written to it is checked
//!   ([`secure_dir`]): it must be owned by this process's effective uid, and it
//!   must grant nothing to group or other. A directory that fails either test is
//!   not repaired and not used - the cache is simply unavailable, every read is
//!   a miss, nothing is written, and the scan runs cold, which is a scan that
//!   reports exactly what a warm one would.
//! - A directory that *is* ours but has been widened is tightened back to
//!   `0700`, its salt is discarded, and this run still treats it as unavailable.
//!   Discarding the salt is what makes the widening cost something: every entry
//!   written before it authenticates under a salt that no longer exists, so
//!   nothing produced while the directory stood open to other accounts can ever
//!   be served. The next run finds an owner-only directory and warms normally.
//! - The salt is checked the same way before its bytes are used: owned by us,
//!   and no bit outside `0600`.
//!
//! There is no way to ask this process for its own effective uid through the
//! standard library, and a dependency for one call is not worth it, so it is
//! measured rather than asked for: a file created with `O_EXCL` is owned by the
//! effective uid of whoever created it, whatever the directory around it says
//! ([`euid`]). It is a process constant, so this happens at most once per run.
//!
//! On Windows none of the above is implemented and none of it is claimed. There
//! is no ownership check and no ACL is set: files and directories this crate
//! creates inherit the ACL of the containing directory, which for `LOCALAPPDATA`
//! is the account's own and for a `--cache-dir` is whatever the user pointed at.
//! An administrator, a process running as the same account, and anyone with
//! write access to a loosened `--cache-dir` can therefore read the entries and
//! replace the salt. What does hold there is the alternate data stream the salt
//! lives in ([`salt_file`]), which keeps a `.salt` that arrived with a checkout
//! or an archive from ever being read, and the per-entry tag, which keeps a
//! borrowed cache from being believed. A Windows cache should be treated as
//! readable by anything running as that user.
//!
//! The crate version inside an entry makes it a miss after an upgrade, but a
//! miss is not a removal: without one, every release left the whole of the
//! previous release's cache on disk for good. [`Cache::open`] therefore prunes
//! entries stamped with a different version, once, up front. The pass is
//! tolerant by construction - it only removes a file that says, in its own
//! bytes, which build wrote it and names another one. Anything unreadable,
//! unrecognised or foreign is left exactly where it is, and a removal that
//! fails is ignored: a cache that cannot be tidied is still a correct cache.
//!
//! That bounds the cache across upgrades, and not within one. An entry is keyed
//! by content, so every edit to a file abandons the entry for its previous
//! contents - an entry this build wrote, which the version test keeps forever.
//! The same pass therefore also drops entries nothing has written for
//! [`MAX_ENTRY_AGE`], and runs at least every [`SWEEP_INTERVAL`] rather than
//! only after an upgrade, because a user who stays on one release is exactly the
//! user whose cache would otherwise only grow. Removing an entry that was still
//! wanted costs one file re-scanned once, which is why the window can be as
//! generous as it is.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Anchor;
use crate::findings::Finding;
use crate::graph::FileFacts;
use crate::rules::{RuleSet, Severity};

/// The cache location this crate used up to 1.3.0, relative to the scan root.
///
/// Nothing here reads it, writes it or removes it any more; it is named so that
/// callers can say where the cache is not. See the module docs for what a cache
/// inside the scanned tree cost.
pub const CACHE_DIR: &str = ".siloscan/cache";

/// The directory this crate claims inside the user's cache directory. Every
/// scan root's cache is a subdirectory of it.
pub const CACHE_NAMESPACE: &str = "siloscan";

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How many hex characters of the scan root's path hash name its cache
/// directory. 128 bits, which is a collision nobody is going to arrange by
/// accident and nobody gains anything by arranging on purpose: a collision
/// costs the two roots a shared salt, and entries still carry the path scope
/// and their own tag.
const ROOT_HASH_PREFIX: usize = 32;

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

/// How long an entry may go untouched before a prune pass removes it.
///
/// A version mismatch bounds the cache across upgrades but not within one: a
/// file that keeps changing writes a new content-keyed entry every time and
/// abandons the old one, which this build still recognises as its own and so
/// never removed. Under 1.3.0 that grew a directory inside the scanned tree,
/// where a user could see it and delete it; it now grows in the user's home,
/// where nobody looks.
///
/// Thirty days is deliberately far longer than any working rhythm. What it
/// removes is an entry for content nothing has produced in a month, and the
/// cost of removing one that was still wanted is a single file re-scanned once.
const MAX_ENTRY_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How long this build waits before sweeping a directory it has already swept.
///
/// The version stamp alone makes the pass once-per-upgrade, which bounds nothing
/// for a user who stays on one release: that is the case this age window exists
/// for, so the stamp cannot be the only thing that triggers it. The stamp's own
/// mtime is when the last pass ran, so the extra trigger costs one `stat` on the
/// steady path and nothing else.
///
/// An entry therefore survives at most `MAX_ENTRY_AGE + SWEEP_INTERVAL` past its
/// last write, which is a bound, which is the entire point.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Per-directory secret that makes an entry believable. It lives beside the
/// entries it authenticates, in the user's own cache directory rather than in
/// the scanned tree.
const SALT_NAME: &str = ".salt";

/// Salt width in bytes, matching the digest that consumes it.
const SALT_LEN: usize = 32;

/// Owner-only mode for every directory this crate creates for a cache, and the
/// mode an existing cache directory has to be at before it is used. Search and
/// write are the same bit here: a directory nobody else can enter is a directory
/// whose entries nobody else can read, and one nobody else can write is one
/// whose salt nobody else can replace.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Owner-only mode for every file this crate creates for a cache: entries, the
/// salt, the prune stamp, and the probe [`euid`] measures itself with.
///
/// It is a file permission mode and nothing else. The salt's file is created
/// with it and read back against it ([`read_salt`]), but the value is never
/// part of a salt, a key or anything else a digest sees.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// The bits a cache directory or a salt must not grant. Anything here means
/// group or other can reach the file, which is the whole of what these checks
/// are about.
#[cfg(unix)]
const OTHERS_MASK: u32 = 0o077;

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
    /// This scan root's cache directory, or `None` when there is nowhere to put
    /// one - no user cache directory could be determined, or the scan root has
    /// no canonical path. A cache with no directory is a cache that misses
    /// every read and writes nothing, which is a cold scan and a correct one.
    root: Option<PathBuf>,
    /// The outermost directory this crate may create files in for this cache,
    /// which is what a scan has to be kept out of. See [`Cache::exclusion_under`]
    /// for why the two differ and when each is used.
    ///
    /// For a cache in the user's own cache directory it is the
    /// [`CACHE_NAMESPACE`] directory: this crate owns all of it, and every scan
    /// root's entries sit inside it. For a `--cache-dir` it is only the
    /// per-scan-root subdirectory, because the directory the user named is the
    /// user's and this crate does not get to declare its contents unscannable.
    owned: Option<PathBuf>,
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
    /// Set once [`secure_dir`] has refused this cache's directory - it belongs
    /// to another uid, it grants group or other something and could not be
    /// tightened, or it had to be tightened and its salt retired with it.
    ///
    /// Separate from `salt_missing` because the two mean opposite things to a
    /// writer. A missing salt is the normal state of a first run and must not
    /// stop [`Cache::put`] from creating one; a refused directory must, or every
    /// file in the tree pays for the same rejected `stat` and the same mutex.
    dir_rejected: AtomicBool,
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
    /// Bind a cache to a scan root, a rule set and a path convention, in this
    /// user's own cache directory (see [`default_cache_base`]), and drop
    /// whatever a different build left behind (see [`prune`]).
    ///
    /// Nothing under the scan root is read, written or consulted: the scanned
    /// tree is input to the scan and to nothing else. A user with no cache
    /// directory, or a scan root with no canonical path, gets a cache with no
    /// location, which misses everything and writes nothing.
    ///
    /// Nothing is created here beyond the prune stamp: an absent cache directory
    /// is nothing to prune and nothing to write until the first [`Cache::put`].
    ///
    /// The prune is skipped when the stamp already names this build. It has to
    /// be, because it is not free: the pass opens and reads the head of every
    /// entry in the directory, which on a 20k-entry cache is a measured 0.4s
    /// added to every scan, forever, to find nothing. The stamp turns that into
    /// one `read` on the steady path and leaves the full pass for the run after
    /// an upgrade, which is the only run that can find anything.
    pub fn open(scan_root: &Path, rules: &RuleSet, scope: &PathScope) -> Cache {
        let base = default_cache_base();
        let root = base.as_deref().and_then(|base| root_dir(base, scan_root));
        Cache::bind(base, root, rules, scope)
    }

    /// Bind a cache the way [`Cache::open`] does, but under a directory the user
    /// named rather than the one this crate would have picked.
    ///
    /// `cache_dir` is used as given - it is not searched for, not relocated and
    /// not namespaced - because it came from the command line, which is the user
    /// speaking and not the scanned tree. The per-scan-root subdirectory inside
    /// it stays: an entry carries the path its finding was reported under, so
    /// serving one scan root's entries to another would emit paths and
    /// fingerprints for files the second root does not have.
    pub fn open_in(
        cache_dir: &Path,
        scan_root: &Path,
        rules: &RuleSet,
        scope: &PathScope,
    ) -> Cache {
        let root = root_dir(cache_dir, scan_root);
        Cache::bind(root.clone(), root, rules, scope)
    }

    fn bind(
        owned: Option<PathBuf>,
        root: Option<PathBuf>,
        rules: &RuleSet,
        scope: &PathScope,
    ) -> Cache {
        let rules_hash = rules.source_hash();
        let path_scope = scope.discriminator();
        // Judged once, here, so that what this cache does is decided by the
        // directory it opened rather than by which of `get` and `put` a caller
        // reached first. A directory found exposed is tightened by this call and
        // is unusable for the rest of the run either way.
        let trust = root.as_deref().map(|root| secure_dir(root, false));
        if let Some(root) = &root
            && matches!(trust, Some(DirTrust::Owned(_)))
        {
            prune_if_stale(root);
        }
        Cache {
            root,
            owned,
            scope_hash: scope_hash(&rules_hash, &path_scope),
            rules_hash,
            path_scope,
            salt: OnceLock::new(),
            salt_missing: AtomicBool::new(false),
            dir_rejected: AtomicBool::new(trust == Some(DirTrust::Rejected)),
            salt_create: Mutex::new(()),
        }
    }

    /// The cache directory, which may not exist yet, or `None` when this cache
    /// has no location and is therefore permanently cold.
    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    /// Where this cache's own files sit inside `scan_root`, spelled as a prefix
    /// of `scan_root` as it was given, or `None` when the cache is not under the
    /// scan root at all.
    ///
    /// A scan must not read this. Moving the cache into the user's own cache
    /// directory took it out of the scanned tree in every normal layout, but not
    /// in every layout: `siloscan ~`, `siloscan /`, any root above
    /// `XDG_CACHE_HOME`, and a `--cache-dir` pointed inside the root all put it
    /// back under the walk. A scan that walks its own cache reports a cold run
    /// and a warm run differently - the warm one finds the entries the cold one
    /// wrote - and reads its own `.salt` as scanned content. Neither is
    /// acceptable, and neither is fixed by anything the cache does to its
    /// entries: the entries are not the problem, their being walked is.
    ///
    /// Two directories are tried, widest first. The [`owned`](Cache::owned) one
    /// is the answer whenever it is strictly below the scan root, because
    /// everything this crate writes for any scan root lands in it and none of it
    /// is content under review. When it *is* the scan root - someone scanning
    /// their cache directory itself - excluding it would empty the whole scan
    /// silently, so the narrower per-scan-root directory answers instead: that
    /// one is the cache this run writes, which is the part that has to be out of
    /// the walk for a warm run to match a cold one.
    ///
    /// The comparison is made on canonical paths, so `.`, `..` and symlinks in
    /// either argument do not decide it, and the result is re-spelled against
    /// `scan_root` as given because that is the spelling the walk produces. A
    /// directory that does not exist yet canonicalizes to itself and is simply
    /// not under the root; it is also not in the walk, so there is nothing to
    /// exclude until the run after it appears.
    pub fn exclusion_under(&self, scan_root: &Path) -> Option<PathBuf> {
        let canonical = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let base = canonical(scan_root);
        [self.owned.as_deref(), self.root.as_deref()]
            .into_iter()
            .flatten()
            .find_map(|candidate| {
                let rel = canonical(candidate).strip_prefix(&base).ok()?.to_path_buf();
                // The candidate is the scan root itself. Not an exclusion, and
                // not this candidate's turn to answer.
                if rel.as_os_str().is_empty() {
                    return None;
                }
                Some(scan_root.join(rel))
            })
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
    ///
    /// Every directory and every file created here is owner-only, and the cache
    /// directory is checked before anything is put in it - see the module docs
    /// and [`secure_dir`]. The salt is resolved first because resolving it is
    /// what creates and checks the directory; the shard below it follows.
    pub fn put(&self, content_hash: &str, entry: &CachedFile) {
        let Some(path) = self.entry_path(content_hash) else {
            return;
        };
        let Some(dir) = path.parent() else {
            return;
        };
        // An entry this checkout cannot authenticate would be an entry it could
        // never read back, so there is no point writing one - and an entry in a
        // directory this checkout does not trust is one it must not write at all.
        let Some(salt) = self.salt_for_write() else {
            return;
        };
        if create_dir_all_secure(dir).is_err() {
            return;
        }

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
        if write_owner_only(&temp, &bytes).is_err() {
            let _ = fs::remove_file(&temp);
            return;
        }
        if fs::rename(&temp, &path).is_err() {
            let _ = fs::remove_file(&temp);
        }
    }

    /// `<cache>/<first two hex chars>/<content hash>-<scope hash prefix>.json`.
    /// Returns `None` for a cache with no location, and for a content hash that
    /// is not a usable file name, which keeps a caller-supplied string from
    /// escaping the cache directory.
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
                .as_ref()?
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
    /// it from - an absent, unreadable or foreign salt file, a directory this
    /// user does not own or that others can reach ([`secure_dir`]), or a
    /// directory whose location cannot be resolved. Every one of those makes the
    /// whole cache cold, which is a correct cache.
    fn salt_for_read(&self) -> Option<&[u8; SALT_LEN]> {
        if let Some(salt) = self.salt.get() {
            return Some(salt);
        }
        if self.salt_missing.load(Ordering::Relaxed) || self.dir_rejected.load(Ordering::Relaxed) {
            return None;
        }
        let root = self.root.as_ref()?;
        let owner = match secure_dir(root, false) {
            DirTrust::Owned(owner) => owner,
            // Nothing to read from, and nothing to hold against the directory:
            // a cache that has not been written yet is the normal first run, and
            // the write path is still allowed to create it.
            DirTrust::Absent => {
                self.salt_missing.store(true, Ordering::Relaxed);
                return None;
            }
            DirTrust::Rejected => {
                self.dir_rejected.store(true, Ordering::Relaxed);
                return None;
            }
        };
        match resolve_salt(root, owner, false) {
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
    /// The lock is held across a directory create, a file create and a small
    /// write, and only until the first salt is resolved; afterwards the
    /// [`OnceLock`] answers without taking it.
    ///
    /// The cache directory is created here rather than in [`Cache::put`] so that
    /// it is created once per cache, with the mode it must have, and checked
    /// before a single entry is written into it. A directory that fails that
    /// check is recorded in `dir_rejected` so the rest of the tree does not
    /// re-run the same refusal per file.
    fn salt_for_write(&self) -> Option<&[u8; SALT_LEN]> {
        if let Some(salt) = self.salt.get() {
            return Some(salt);
        }
        if self.dir_rejected.load(Ordering::Relaxed) {
            return None;
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
        let root = self.root.as_ref()?;
        let DirTrust::Owned(owner) = secure_dir(root, true) else {
            self.dir_rejected.store(true, Ordering::Relaxed);
            return None;
        };
        let salt = resolve_salt(root, owner, true)?;
        Some(self.salt.get_or_init(|| salt))
    }
}

/// This crate's directory inside the invoking user's cache directory, or `None`
/// when there is no such directory to be had.
///
/// This is the whole of the location policy, and it deliberately reads only the
/// environment of the process running the scan. Nothing about the scanned tree
/// takes part, so nothing in a scanned tree can move the cache, name it, or put
/// a file where one will be read from.
///
/// `None` is not a failure and not an error: it means this run has no cache, so
/// it scans cold and reports exactly what a warm run would have. A fallback
/// location - the scan root, the working directory, a shared temporary
/// directory - would put the cache somewhere an attacker or another user can
/// reach, which is the whole of what moving it out of the tree was for.
pub fn default_cache_base() -> Option<PathBuf> {
    Some(user_cache_dir(&|name| std::env::var_os(name))?.join(CACHE_NAMESPACE))
}

/// The user cache directory `get` describes, by this platform's convention.
///
/// - unix: `XDG_CACHE_HOME`, else `$HOME/.cache`. An unset, empty or relative
///   value is no value: the specification says a relative `XDG_CACHE_HOME` is
///   to be ignored, and resolving one against the working directory is how a
///   cache ends up inside whatever tree the scan was launched from.
/// - windows: `LOCALAPPDATA`, under the same absolute-path rule. Roaming is
///   deliberately not used: a cache is machine-local state, and the entries
///   here are bound to absolute paths on this machine.
/// - anywhere else: `None`, and therefore no cache. A platform whose
///   convention this build does not know does not get a guess.
///
/// Taking the environment through a closure keeps the policy testable without a
/// process-wide `set_var`, which in a threaded test binary is a race and, since
/// the 2024 edition, `unsafe`.
fn user_cache_dir(get: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        if let Some(dir) = get("XDG_CACHE_HOME").and_then(absolute_dir) {
            return Some(dir);
        }
        Some(absolute_dir(get("HOME")?)?.join(".cache"))
    }
    #[cfg(windows)]
    {
        absolute_dir(get("LOCALAPPDATA")?)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = get;
        None
    }
}

/// An environment value that names an absolute path, or `None`. Empty and
/// relative values are both "unset" here.
#[cfg(any(unix, windows))]
fn absolute_dir(value: OsString) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return None;
    }
    Some(path)
}

/// What [`secure_dir`] found where a cache directory was expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirTrust {
    /// A directory owned by this process's effective uid, granting nothing to
    /// group or other. The value is that uid, which the salt beside it is
    /// checked against too.
    Owned(u32),
    /// Nothing is there. Not a failure: a cache that has never been written is
    /// the first run of every scan, and the write path creates it.
    Absent,
    /// There is something there, and it is not a directory this crate will read
    /// from or write to. Left exactly as it was found unless it was ours, in
    /// which case its mode is tightened and its salt retired - see [`secure_dir`].
    Rejected,
}

/// Establish that `root` is a cache directory this crate may use, creating it
/// when asked to, and answer with the uid that owns it.
///
/// This is the check the module docs describe, and it is the whole of it:
///
/// - With `create`, `root` and every missing directory above it are created
///   `0700` ([`create_dir_all_secure`]). A directory this crate has just created
///   is owned by this process by construction.
/// - The directory is opened once and every question is asked of that one
///   handle, so the answer cannot change between the ownership test and the
///   `chmod` that follows it.
/// - Owned by another uid: [`DirTrust::Rejected`], and nothing is written,
///   changed or removed. Someone else's directory is someone else's, and
///   "repairing" it would mean writing into a directory this user does not
///   control on the strength of a check that just failed.
/// - Ours, but granting something to group or other: tightened back to
///   [`DIR_MODE`], the salt beside it removed, and still [`DirTrust::Rejected`]
///   for this run. Anything written while other accounts could reach the
///   directory is now unauthenticatable, which is the point; the next run finds
///   an owner-only directory with no salt and warms up from cold.
/// - Ours and owner-only: [`DirTrust::Owned`].
///
/// On unix the effective uid comes from [`euid`], which measures it rather than
/// asking for it. Where it cannot be measured nothing is trusted.
#[cfg(unix)]
fn secure_dir(root: &Path, create: bool) -> DirTrust {
    use std::io::ErrorKind;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if create && create_dir_all_secure(root).is_err() {
        return DirTrust::Rejected;
    }
    let dir = match fs::File::open(root) {
        Ok(dir) => dir,
        // A directory that is not there is not a directory that failed a check.
        // Anything else - a permission error, a path that is not a directory -
        // is one this crate does not get to use.
        Err(err) if err.kind() == ErrorKind::NotFound => return DirTrust::Absent,
        Err(_) => return DirTrust::Rejected,
    };
    let Ok(meta) = dir.metadata() else {
        return DirTrust::Rejected;
    };
    if !meta.is_dir() {
        return DirTrust::Rejected;
    }
    let Some(owner) = euid(root) else {
        return DirTrust::Rejected;
    };
    if meta.uid() != owner {
        return DirTrust::Rejected;
    }
    if meta.permissions().mode() & OTHERS_MASK != 0 {
        // Ours, so this is closing our own directory rather than editing
        // someone else's. The salt goes with it: entries written while the
        // directory stood open must not be servable afterwards, and without a
        // salt none of them is.
        if dir
            .set_permissions(fs::Permissions::from_mode(DIR_MODE))
            .is_err()
        {
            return DirTrust::Rejected;
        }
        if let Some(salt) = salt_file(root)
            && let Err(err) = fs::remove_file(&salt)
            && err.kind() != ErrorKind::NotFound
        {
            return DirTrust::Rejected;
        }
        return DirTrust::Rejected;
    }
    DirTrust::Owned(owner)
}

/// No ownership or permission model is enforced off unix. On Windows the
/// directory is created and used as it is: see the module docs for what that
/// does and does not mean, and [`salt_file`] for the one provenance signal that
/// does hold there.
#[cfg(not(unix))]
fn secure_dir(root: &Path, create: bool) -> DirTrust {
    if create && create_dir_all_secure(root).is_err() {
        return DirTrust::Rejected;
    }
    if root.is_dir() {
        DirTrust::Owned(0)
    } else if root.exists() {
        DirTrust::Rejected
    } else {
        DirTrust::Absent
    }
}

/// Create `dir` and every missing directory above it, owner-only.
///
/// The mode is set twice on purpose. `mkdir` takes one, but the kernel masks it
/// with the process umask, which can only clear bits: for [`DIR_MODE`] that can
/// never add group or other access, but a `umask` of `0700` would leave a
/// directory this process cannot itself use. The explicit `chmod` after each
/// successful create is what makes the mode the stated one rather than the
/// umask's opinion of it, and it only ever touches a directory this call just
/// made.
///
/// Directories that already exist are left exactly as they are: this function
/// creates, and [`secure_dir`] judges. Losing a create race is not a failure -
/// the winner made the same directory with the same mode.
#[cfg(unix)]
fn create_dir_all_secure(dir: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    let mut missing = Vec::new();
    for ancestor in dir.ancestors() {
        // The empty path is what a relative path's ancestors end on. It is not
        // a directory to create, and asking for it is an error.
        if ancestor.as_os_str().is_empty() || ancestor.is_dir() {
            break;
        }
        missing.push(ancestor);
    }
    for path in missing.iter().rev() {
        let mut builder = fs::DirBuilder::new();
        builder.mode(DIR_MODE);
        match builder.create(path) {
            Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE))?,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
    if dir.is_dir() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::NotADirectory,
            "cache path is not a directory",
        ))
    }
}

#[cfg(not(unix))]
fn create_dir_all_secure(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)
}

/// Write `bytes` to `path`, owner-only, replacing whatever was there.
///
/// The mode is given to the create and then set again on the open file, for the
/// reason [`create_dir_all_secure`] gives: `open`'s mode argument is masked by
/// the umask, and an existing file keeps the mode it already had. The second
/// call is on the file descriptor, so it lands on the file that was just
/// written and not on whatever the path names by the time it runs.
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(FILE_MODE);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
    }
    file.write_all(bytes)
}

/// This process's effective uid, or `None` when it cannot be established.
///
/// The standard library exposes no way to ask, and a dependency for one number
/// is not one this crate is going to take, so it is measured: a file created
/// with `O_EXCL` belongs to the effective uid of the process that created it,
/// whoever owns the directory it was created in and whatever mode that directory
/// carries. Exclusive creation is what makes it sound - a file that already
/// existed, or a symlink standing in for one, fails the create rather than
/// answering with someone else's uid - and the probe is removed immediately
/// afterwards.
///
/// `hint` is tried first, because the caller is about to use that directory
/// anyway and a probe there costs nothing extra. A directory this user cannot
/// write to falls back to the temporary directory; a machine where neither works
/// gets no cache, which is a cold scan and a correct one.
///
/// A uid is a process constant, so this happens at most once per process: the
/// answer is memoized and every later call is a load.
#[cfg(unix)]
fn euid(hint: &Path) -> Option<u32> {
    static EUID: OnceLock<u32> = OnceLock::new();

    if let Some(uid) = EUID.get() {
        return Some(*uid);
    }
    let uid = probe_uid(hint).or_else(|| probe_uid(&std::env::temp_dir()))?;
    Some(*EUID.get_or_init(|| uid))
}

/// The uid a file created in `dir` by this process comes out owned by, or `None`
/// when no file could be created there. The probe never outlives the call, and
/// its name cannot collide with an entry: entries are `*.json`.
#[cfg(unix)]
fn probe_uid(dir: &Path) -> Option<u32> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!(".owner.{}.{n}.probe", std::process::id()));

    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)
        .ok()?;
    let uid = file.metadata().ok().map(|meta| meta.uid());
    drop(file);
    let _ = fs::remove_file(&path);
    uid
}

/// The directory under `base` that holds `scan_root`'s entries: a hash of the
/// root's canonical path, so every scan root gets its own cache, its own salt
/// and its own prune stamp.
///
/// The hash is over the canonical path rather than the path as given, so
/// `.`, a relative path and a symlinked path all reach the same cache. A root
/// that cannot be canonicalized has no stable identity to key on and gets no
/// cache: it is a root that does not exist, which is a scan with nothing to
/// cache anyway. The path as given is never a fallback, because two different
/// spellings of one root would then quietly own two caches, and a root that
/// vanished would own one keyed on a name.
///
/// The name is a hash and not the path itself: paths are longer than file names
/// are allowed to be, and they contain separators.
fn root_dir(base: &Path, scan_root: &Path) -> Option<PathBuf> {
    let canonical = fs::canonicalize(scan_root).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_os_str().as_encoded_bytes());
    let digest = hex(&hasher.finalize());
    Some(base.join(digest.get(..ROOT_HASH_PREFIX).unwrap_or(&digest)))
}

/// Drop every cache entry of `scan_root`'s cache that a different build wrote,
/// and report how many went.
///
/// This is what [`Cache::open`] does for the scan it is opening; it is exposed
/// so the same tidy-up can be asked for on its own. It removes entries across
/// every rule set and path convention in the directory, not just the caller's:
/// a stale entry is stale whoever wrote it. A user with no cache directory has
/// no entries to remove, and the answer is 0.
///
/// Unlike the open path this always walks the directory, stamp or no stamp: a
/// user who asked for a prune asked for the pass, not for this build's opinion
/// about whether it would find anything.
pub fn prune(scan_root: &Path) -> usize {
    let Some(root) = default_cache_base().and_then(|base| root_dir(&base, scan_root)) else {
        return 0;
    };
    prune_at(&root)
}

/// [`prune`] against a cache directory the user named, matching
/// [`Cache::open_in`].
pub fn prune_in(cache_dir: &Path, scan_root: &Path) -> usize {
    let Some(root) = root_dir(cache_dir, scan_root) else {
        return 0;
    };
    prune_at(&root)
}

/// A prune only ever removes files and writes a stamp, and both are things this
/// crate does to its own directory. A directory [`secure_dir`] will not vouch
/// for is therefore not walked and not stamped either: it is not this user's to
/// tidy, and a stamp in it would be this build claiming it had swept a directory
/// it never read.
fn prune_at(root: &Path) -> usize {
    if !matches!(secure_dir(root, false), DirTrust::Owned(_)) {
        return 0;
    }
    let removed = prune_dir(root, SystemTime::now());
    write_stamp(root);
    removed
}

/// Prune unless the stamp says this build already did, recently.
///
/// Every failure mode leads to pruning: no stamp, an unreadable stamp, a stamp
/// naming another version, a stamp with no readable mtime. The stamp is only
/// ever trusted to say "this build has already swept here", never to say the
/// opposite, so a missing or corrupt one costs a pass that was correct to run
/// anyway. It is written after the pass, so a prune that dies halfway leaves no
/// stamp and the next open retries.
///
/// "Recently" is [`SWEEP_INTERVAL`], measured from the stamp's own mtime, which
/// is when the last pass finished. Without it the pass is once per upgrade and
/// the age window in [`prune_dir`] would never fire for a user who stays on one
/// release - which is exactly the user whose cache grows.
///
/// The caller establishes that the directory is one this crate may touch
/// ([`secure_dir`]); this function only decides whether the pass is due. Doing
/// the check here as well would mean [`Cache::bind`] and this function each
/// forming their own opinion of the same directory, and the two could differ -
/// which is how the order of `get` and `put` started to matter.
fn prune_if_stale(root: &Path) {
    let stamp = root.join(STAMP_NAME);
    if fs::read_to_string(&stamp).is_ok_and(|named| named.trim() == VERSION)
        && swept_recently(&stamp)
    {
        return;
    }
    prune_dir(root, SystemTime::now());
    write_stamp(root);
}

/// Whether the last pass over this directory finished within
/// [`SWEEP_INTERVAL`].
///
/// Unreadable, or dated in the future by a clock that moved, both answer "no":
/// the wrong answer here costs one pass, and the pass was always safe to run.
fn swept_recently(stamp: &Path) -> bool {
    fs::metadata(stamp)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|swept| SystemTime::now().duration_since(swept).ok())
        .is_some_and(|since| since < SWEEP_INTERVAL)
}

/// Record this build as the last to sweep `root`.
///
/// Written only into a cache directory that already exists: a scan of a tree
/// with no cache must not create one, and the first [`Cache::put`] stamps it
/// through the next [`Cache::open`]. Failures are ignored - an unwritable stamp
/// costs a prune pass per scan, which is only where this started.
fn write_stamp(root: &Path) {
    if root.is_dir() {
        let _ = write_owner_only(&root.join(STAMP_NAME), format!("{VERSION}\n").as_bytes());
    }
}

/// One pass over `<root>/<shard>/*.json`, removing the entries that name a
/// version other than this build's, and the entries nothing has written for
/// [`MAX_ENTRY_AGE`]. Returns how many were removed.
///
/// The version test alone leaves a directory that only grows: an entry is keyed
/// by content, so every edit to a file abandons the entry for its previous
/// contents, and that entry names this build and is kept forever. The age test
/// is what puts a ceiling on it.
///
/// Age is the entry file's mtime, which is when it was written. A cache hit does
/// not touch it - a read that wrote would make every warm scan a write pass over
/// the cache, and the point of a warm scan is that it does not - so an entry
/// that is still being hit is still removed once it is a month old. That costs
/// one file re-scanned once, which is what makes it safe to be wrong about.
///
/// Every step is permissive. A directory that cannot be listed ends the pass, a
/// shard that cannot be listed is skipped, a file that is not an entry is
/// skipped, a file whose age cannot be read is kept, and a removal that fails is
/// dropped on the floor. Nothing here is allowed to turn a cache into a scan
/// failure, and nothing here touches a file that has not identified itself as
/// this crate's. A removal that failed is not counted: the number is what left,
/// not what was attempted.
///
/// `now` is the instant every age is measured against. It is a parameter and not
/// a call to the clock so that a test can state an age instead of arranging one
/// on the filesystem, which the standard library cannot do.
fn prune_dir(root: &Path, now: SystemTime) -> usize {
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
            let foreign = entry_version(&path).is_some_and(|version| version != VERSION);
            if (foreign || is_stale(&entry, now)) && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// Whether nothing has written this entry for [`MAX_ENTRY_AGE`].
///
/// False whenever the answer cannot be established - no metadata, no mtime, or
/// an mtime ahead of `now` because a clock moved. Keeping an entry is the
/// harmless direction: the cost is one file's worth of disk, against a rescan of
/// work that was still wanted.
fn is_stale(entry: &fs::DirEntry, now: SystemTime) -> bool {
    entry
        .metadata()
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|written| now.duration_since(written).ok())
        .is_some_and(|age| age > MAX_ENTRY_AGE)
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
/// Either way a directory whose salt cannot be read or made has no salt at all,
/// and the cache that would have used it stays cold.
///
/// The value returned is not the file's bytes but those bytes bound to the
/// directory's absolute location, so entries authenticate in one directory and
/// nowhere else: a cache that is copied, moved or restored somewhere else is
/// cold rather than believed. A location that cannot be resolved yields `None`
/// - a cache that cannot say where it is does not get believed.
///
/// `owner` is the uid [`secure_dir`] established for the directory, which the
/// salt file has to match: a salt owned by anyone else was not written here, and
/// a cache directory whose salt someone else owns is one whose entries this
/// build has no reason to believe. Callers resolve the directory first, so this
/// function neither creates nor checks it.
///
/// This is tamper resistance, not key management, and it is not what keeps the
/// scanned tree out - the cache's location does that (see the module docs). The
/// salt sits unencrypted in a file any process running as this user can read,
/// so anything already running as this user can forge an entry. What no longer
/// follows is "so can anything that can write into this user's cache directory":
/// nothing else can, because [`secure_dir`] will not use a directory that lets
/// it.
fn resolve_salt(root: &Path, owner: u32, create: bool) -> Option<[u8; SALT_LEN]> {
    let stored = match read_salt(root, owner) {
        Some(salt) => salt,
        None if create => create_salt(root, owner)?,
        None => return None,
    };
    let location = fs::canonicalize(root).ok()?;

    let mut hasher = Sha256::new();
    hasher.update(stored);
    hasher.update([0]);
    hasher.update(location.as_os_str().as_encoded_bytes());
    Some(hasher.finalize().into())
}

/// Where a salt's bytes are read from and written to under `root`.
///
/// Defence in depth, not the boundary. The boundary is that `root` is inside
/// the invoking user's cache directory and no scanned tree can reach it; what
/// is left for this to do is make a salt that arrived from somewhere else -
/// unpacked over the cache directory, restored from a CI artifact, copied by
/// hand - fail to be read rather than be trusted on sight.
///
/// - unix: the file itself, and [`read_salt`] rejects any mode wider than
///   [`FILE_MODE`], and any owner but this one. The mode is a weak signal on its
///   own: an archive preserves a `0600` mode exactly, and a `umask` of `077`
///   gives a checked-out file one. It costs a `stat` this code path already
///   needs, so it stays; it is not relied on, and 1.3.0's claim that it proved
///   provenance was wrong. The ownership test is not provenance either - it is
///   what stops another local account from putting its own salt here, which is
///   how a world-writable cache directory turned into forged entries.
/// - windows: an NTFS alternate data stream on `.salt` ([`SALT_STREAM`]). Git
///   does not record streams and the common archive formats do not carry them,
///   so a `.salt` that arrived from elsewhere has no stream and is simply never
///   read: only the stream is. On a volume with no stream support - FAT32,
///   exFAT, some network shares - creating it fails and the cache stays cold,
///   which is a correct cache. Provenance is all this settles; the bytes
///   themselves come from the OS random source like everywhere else
///   ([`generate_salt`]).
/// - anything else: `None`, no salt, and a cache that is cold every time. A
///   platform this build has no convention for gets no guess, and the same
///   platform has no [`user_cache_dir`] either, so it has no cache to begin
///   with.
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
/// [`salt_file`] says where to look and what the mode and ownership checks below
/// are worth. Everything else - absent, unreadable, not hex, wrong length -
/// lands in the same place, which is a cold cache.
fn read_salt(root: &Path, owner: u32) -> Option<[u8; SALT_LEN]> {
    let path = salt_file(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let meta = fs::metadata(&path).ok()?;
        if !meta.is_file() {
            return None;
        }
        if meta.uid() != owner {
            return None;
        }
        // Any 0o777 bit outside [`FILE_MODE`]: anything at all for group or
        // other, or an execute bit for the owner. None of them is a bit this
        // crate sets, so a file carrying one is not one [`write_salt`] made.
        if meta.permissions().mode() & !FILE_MODE & 0o777 != 0 {
            return None;
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    unhex(fs::read_to_string(&path).ok()?.trim())
}

/// Write a fresh salt into an existing cache directory and return it.
///
/// `None` when the OS random source will not answer ([`generate_salt`]), when
/// this platform has nowhere to keep a salt ([`salt_file`]), or when the
/// directory does not exist.
/// In every one of those the cache simply has no salt, which makes it cold
/// rather than weakly keyed.
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
fn create_salt(root: &Path, owner: u32) -> Option<[u8; SALT_LEN]> {
    if !root.is_dir() {
        return None;
    }
    let path = salt_file(root)?;
    let salt = generate_salt()?;

    if write_salt(&path, &salt) {
        return Some(salt);
    }
    // Either someone else got there first, or the file is one this build can
    // never use. Only the second is replaced, and only once: losing the second
    // create too means another process refilled it in the same window, and its
    // salt is the one to read.
    if foreign_salt(&path, owner) && fs::remove_file(&path).is_ok() && write_salt(&path, &salt) {
        return Some(salt);
    }
    read_salt(root, owner)
}

/// Create `path` exclusively, owner-only, holding `salt`. False when the file
/// already existed or the write did not complete.
///
/// The mode is set on the open file as well as on the create, for the reason
/// [`create_dir_all_secure`] gives: the create's mode is masked by the process
/// umask, and this file's mode is checked on every later read.
///
/// What it reports is whether the write happened, and nothing else. Handing the
/// caller back its own `salt` was the earlier signature, and it claimed more
/// than it delivered: the caller already holds those bytes. A return typed as a
/// salt also made the value this process goes on to hash with look - to a
/// reader, and to anything that follows values rather than types - like
/// something derived from the file mode this function sets on the way.
fn write_salt(path: &Path, salt: &[u8; SALT_LEN]) -> bool {
    use std::io::Write as _;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(FILE_MODE);
    }
    let Ok(mut file) = options.open(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if file
            .set_permissions(fs::Permissions::from_mode(FILE_MODE))
            .is_err()
        {
            return false;
        }
    }
    let mut text = hex(salt);
    text.push('\n');
    file.write_all(text.as_bytes()).is_ok() && file.sync_all().is_ok()
}

/// True when a salt file exists and fails a check [`read_salt`] applies before
/// it reads a byte: on unix, a regular file whose mode is wider than
/// [`FILE_MODE`], or one owned by anyone but `owner`.
///
/// A salt owned by another uid inside a directory this uid owns and nobody else
/// can write is a leftover - a directory created by `root`, a restored backup,
/// a container that changed uids - and not something another account can arrange
/// today. Replacing it is the same one-time repair the mode case gets, in a
/// directory this crate has already established is its own.
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
fn foreign_salt(path: &Path, owner: u32) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    fs::metadata(path).is_ok_and(|meta| {
        meta.is_file()
            && (meta.uid() != owner || meta.permissions().mode() & !FILE_MODE & 0o777 != 0)
    })
}

/// No provenance check outside unix carries a signal a file can fail on its
/// own: on Windows the salt is an alternate data stream, which a checkout
/// cannot carry at all, and elsewhere there is no salt to begin with.
#[cfg(not(unix))]
fn foreign_salt(_path: &Path, _owner: u32) -> bool {
    false
}

/// [`SALT_LEN`] bytes straight from the operating system's random source, or
/// `None` when that source cannot be reached or does not answer in full.
///
/// The kernel's bytes are the salt. Nothing is folded in beside them and
/// nothing is derived from them, because a salt an attacker can guess is a tag
/// they can forge and the whole of the committed-cache defense rests on not
/// being able to. The process id, the wall clock and the directory path are all
/// reproducible by anyone who knows roughly when and where a cache was created,
/// so none of them is entropy and none of them belongs here - not even as
/// padding, which a salt that is already random end to end does not need.
///
/// The source is `getrandom`, which asks each target for the random source that
/// target actually has - `getrandom(2)` on Linux, `getentropy` on the BSDs and
/// macOS, `ProcessPrng` on Windows - rather than the one file `std` alone can
/// reach. `std` exposes no OS random API on stable, so this is a dependency or
/// it is nothing, and on every platform this project ships a binary for it is a
/// working salt instead of a permanently cold cache.
///
/// When the source errors the answer is `None`, and `None` means no salt exists
/// rather than a weaker one being invented: [`create_salt`] writes nothing,
/// [`resolve_salt`] yields nothing, every entry is a miss and every scan runs
/// cold. That is the safe direction to fail in. A cold scan is what the first
/// run of any build does, it produces the same report a warm one would, and it
/// costs time and only time.
///
/// The buffer handed to the source is uninitialized rather than zeroed, and the
/// salt is built from the bytes the call returns, so every byte of a salt
/// arrives from the operating system and no value written in this file can
/// reach the tag. A partial fill is not a partial salt: `fill_uninit` reports
/// any short read as an error, and an error here is `None`.
fn generate_salt() -> Option<[u8; SALT_LEN]> {
    let mut buffer = [const { std::mem::MaybeUninit::<u8>::uninit() }; SALT_LEN];
    let filled = getrandom::fill_uninit(&mut buffer).ok()?;
    <[u8; SALT_LEN]>::try_from(&*filled).ok()
}

/// The [`SALT_LEN`]-byte value `text` spells in lowercase or uppercase hex, or
/// `None` if it does not spell exactly one.
///
/// Like [`generate_salt`], the result is accumulated from what was parsed
/// rather than written over a buffer of zeros: a salt is made of the bytes it
/// was given and of nothing this file spells out.
fn unhex(text: &str) -> Option<[u8; SALT_LEN]> {
    let bytes = text.as_bytes();
    if bytes.len() != SALT_LEN * 2 {
        return None;
    }
    if !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = Vec::with_capacity(SALT_LEN);
    for pair in bytes.chunks_exact(2) {
        let text = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    out.try_into().ok()
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

    /// A scan root and a stand-in for the user's cache directory, in two
    /// separate temporary directories: the cache is never inside the tree it
    /// caches, which is the property this module now rests on.
    ///
    /// Every test opens through [`Cache::open_in`] rather than [`Cache::open`].
    /// The default location is the machine's real cache directory, and a test
    /// suite has no business writing there or leaving entries behind; what the
    /// default resolves to is asserted directly on the functions that resolve
    /// it.
    struct Fixture {
        root: tempfile::TempDir,
        base: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Fixture {
            Fixture {
                root: tempdir(),
                base: tempdir(),
            }
        }

        fn root(&self) -> &Path {
            self.root.path()
        }

        fn base(&self) -> &Path {
            self.base.path()
        }

        /// The cache this fixture's scan root gets under its own base.
        fn open(&self) -> Cache {
            self.open_with("a", &PathScope::ScanRoot)
        }

        fn open_with(&self, source: &str, scope: &PathScope) -> Cache {
            Cache::open_in(self.base(), self.root(), &ruleset(source), scope)
        }
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

    /// The uid this test process runs as, measured the way the code under test
    /// measures it.
    fn this_uid() -> u32 {
        #[cfg(unix)]
        {
            euid(&std::env::temp_dir()).expect("a uid must be measurable to test ownership")
        }
        #[cfg(not(unix))]
        {
            0
        }
    }

    /// The mode of `path`, or `None` off unix.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
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
        let fx = Fixture::new();
        let cache = fx.open();
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
        let fx = Fixture::new();
        let cache = fx.open();
        let hash = hash();
        cache.put(&hash, &entry());

        let bytes = fs::read(cache.entry_path(&hash).unwrap()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(SECRET), "secret persisted to disk: {text}");
        assert!(!text.contains("other"));
        assert!(text.contains("matched_len"));
    }

    /// A scan writes into the cache directory and nowhere else. The scanned
    /// tree is input: no entry, no salt, no stamp, and no `.gitignore` to
    /// apologize for any of them.
    #[test]
    fn nothing_is_written_into_the_scanned_tree() {
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&hash(), &entry());
        assert!(
            cache.get(&hash(), &content()).is_some(),
            "warm to begin with"
        );

        assert_eq!(files_in(fx.root()), Vec::<String>::new());
        assert!(!fx.root().join(CACHE_DIR).exists());
        assert!(cache.root().unwrap().starts_with(fx.base()));
    }

    #[test]
    fn content_without_the_recorded_span_is_a_miss() {
        let fx = Fixture::new();
        let cache = fx.open();
        let hash = hash();
        cache.put(&hash, &entry());

        assert!(cache.get(&hash, "").is_none());
        assert!(cache.get(&hash, "let token = \"\";\n").is_none());
    }

    #[test]
    fn open_does_not_create_the_directory() {
        let fx = Fixture::new();
        let cache = fx.open();
        assert!(!cache.root().unwrap().exists());
        assert!(cache.get(&content_hash(b"x"), "x").is_none());
        assert!(!cache.root().unwrap().exists());
    }

    #[test]
    fn key_reports_content_rules_scope_and_version() {
        let fx = Fixture::new();
        let rules = ruleset("a");
        let cache = Cache::open_in(fx.base(), fx.root(), &rules, &PathScope::ScanRoot);
        let key = cache.key(b"file contents");

        assert_eq!(key.content_hash, content_hash(b"file contents"));
        assert_eq!(key.rules_hash, rules.source_hash());
        assert_eq!(key.path_scope, "scan-root");
        assert_eq!(key.version, VERSION);
        assert_eq!(key.content_hash.len(), 64);

        let scope = PathScope::Config {
            prefix: "modules/api".to_string(),
        };
        let cache = Cache::open_in(fx.base(), fx.root(), &rules, &scope);
        assert_eq!(cache.key(b"file contents").path_scope, "config:modules/api");
    }

    #[test]
    fn version_mismatch_is_a_miss() {
        let fx = Fixture::new();
        let cache = fx.open();
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
        let fx = Fixture::new();
        let cache = fx.open();
        let hash = hash();
        cache.put(&hash, &entry());

        let path = cache.entry_path(&hash).unwrap();
        fs::write(&path, b"{ not json").unwrap();

        assert!(cache.get(&hash, &content()).is_none());
    }

    #[test]
    fn truncated_entry_is_a_miss() {
        let fx = Fixture::new();
        let cache = fx.open();
        let hash = hash();
        cache.put(&hash, &entry());

        let path = cache.entry_path(&hash).unwrap();
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

        assert!(cache.get(&hash, &content()).is_none());
    }

    #[test]
    fn different_rules_hash_is_a_miss() {
        let fx = Fixture::new();
        let hash = hash();

        let first = fx.open();
        first.put(&hash, &entry());

        let second = fx.open_with("b", &PathScope::ScanRoot);
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
        let fx = Fixture::new();
        let hash = hash();

        let scan_root = fx.open();
        scan_root.put(&hash, &entry());
        assert!(scan_root.get(&hash, &content()).is_some());

        let anchored = Cache::open_in(
            fx.base(),
            fx.root(),
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
        let fx = Fixture::new();
        let hash = hash();
        let scope = |prefix: &str| PathScope::Config {
            prefix: prefix.to_string(),
        };

        let api = fx.open_with("a", &scope("modules/api"));
        api.put(&hash, &entry());

        let web = fx.open_with("a", &scope("modules/web"));
        assert!(web.get(&hash, &content()).is_none());
        assert!(api.get(&hash, &content()).is_some());
    }

    /// Belt and braces: the file name only carries a truncated hash of the
    /// scope, so the entry states its own scope and that statement decides.
    #[test]
    fn a_rewritten_scope_inside_the_entry_is_a_miss() {
        let fx = Fixture::new();
        let cache = fx.open();
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
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&content_hash(b"one"), &entry());

        assert!(cache.get(&content_hash(b"two"), &content()).is_none());
    }

    #[test]
    fn put_leaves_no_temporary_file_behind() {
        let fx = Fixture::new();
        let cache = fx.open();
        let hash = hash();

        cache.put(&hash, &entry());
        cache.put(&hash, &entry());

        let shard = cache.root().unwrap().join(&hash[..2]);
        let names = files_in(&shard);
        assert_eq!(names.len(), 1, "unexpected files in the shard: {names:?}");
        assert!(names[0].ends_with(".json"));
    }

    /// The body an entry stores is a pure function of what was cached: two
    /// caches record the same result the same way. Only the tag differs, and it
    /// has to - it is what ties the entry to the directory it lives in.
    #[test]
    fn stored_bodies_are_identical_across_puts_and_tags_are_not() {
        let fx_a = Fixture::new();
        let fx_b = Fixture::new();
        let hash = hash();

        let a = fx_a.open();
        let b = fx_b.open();
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
        let fx = Fixture::new();
        let cache = fx.open();
        let hash = hash();
        let path = cache.entry_path(&hash).unwrap();

        assert!(path.starts_with(cache.root().unwrap()));
        assert_eq!(
            path.parent().unwrap().file_name().unwrap().to_str(),
            Some(&hash[..2])
        );
        assert_eq!(
            path.file_name().unwrap().to_str(),
            Some(format!("{hash}-{}.json", &cache.scope_hash[..SCOPE_HASH_PREFIX]).as_str())
        );

        // The rules hash and the path scope both move the name.
        let other_rules = fx.open_with("b", &PathScope::ScanRoot);
        let other_scope = fx.open_with(
            "a",
            &PathScope::Config {
                prefix: String::new(),
            },
        );
        assert_ne!(path, other_rules.entry_path(&hash).unwrap());
        assert_ne!(path, other_scope.entry_path(&hash).unwrap());
    }

    #[test]
    fn non_hex_content_hash_is_rejected() {
        let fx = Fixture::new();
        let cache = fx.open();

        for bad in ["", "a", "../../etc/passwd", "zz", "ab/cd"] {
            assert!(cache.entry_path(bad).is_none(), "{bad} should be rejected");
            assert!(cache.get(bad, &content()).is_none());
            cache.put(bad, &entry());
        }
        assert!(!cache.root().unwrap().exists());
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
        let fx = Fixture::new();
        let cache = fx.open();
        // Opened before anything is seeded: opening prunes, which is the
        // behaviour under test and would otherwise clear the fixture early.
        let other_rules = fx.open_with("b", &PathScope::ScanRoot);

        let mine = hash();
        cache.put(&mine, &entry());
        let theirs = seed_foreign_entry(&cache, &content_hash(b"older release"), "0.0.0-old");
        // A stale entry from a different rule set is stale all the same.
        let other_scope = seed_foreign_entry(&other_rules, &content_hash(b"older too"), "1.0.0");

        assert!(theirs.exists());
        assert!(other_scope.exists());

        let reopened = fx.open();

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
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&hash(), &entry());
        let shard = cache.root().unwrap().join(&hash()[..2]);

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

        fx.open();

        for path in [&corrupt, &truncated, &unrelated, &temp, &long] {
            assert!(path.exists(), "{} was removed", path.display());
        }
        assert!(cache.get(&hash(), &content()).is_some(), "still a hit");
    }

    #[test]
    fn pruning_is_idempotent_and_creates_nothing() {
        let fx = Fixture::new();

        // Nothing on disk yet: open must not conjure the directory.
        let cache = fx.open();
        assert!(!cache.root().unwrap().exists());
        prune_in(fx.base(), fx.root());
        assert!(!cache.root().unwrap().exists());

        cache.put(&hash(), &entry());
        let stale = seed_foreign_entry(&cache, &content_hash(b"older release"), "0.0.0-old");
        let mine = cache.entry_path(&hash()).unwrap();
        let bytes = fs::read(&mine).unwrap();

        for _ in 0..3 {
            prune_in(fx.base(), fx.root());
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
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&hash(), &entry());
        let stale = seed_foreign_entry(&cache, &content_hash(b"older release"), "0.0.0-old");

        // Claim the sweep already happened. Nothing else does this - the point
        // is that the stamp alone is what open trusts.
        fs::write(
            cache.root().unwrap().join(STAMP_NAME),
            format!("{VERSION}\n"),
        )
        .unwrap();
        fx.open();
        assert!(stale.exists(), "a current stamp must skip the pass");

        // An explicit prune ignores the stamp: the user asked for the pass.
        assert_eq!(prune_in(fx.base(), fx.root()), 1);
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
            let fx = Fixture::new();
            let cache = fx.open();
            cache.put(&hash(), &entry());
            let stale = seed_foreign_entry(&cache, &content_hash(b"older release"), "0.0.0-old");

            let path = cache.root().unwrap().join(STAMP_NAME);
            match stamp {
                Some(text) => fs::write(&path, text).unwrap(),
                None => {
                    let _ = fs::remove_file(&path);
                }
            }

            fx.open();

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

    /// The version test bounds the cache across upgrades and not within one:
    /// every edit to a file abandons the entry for its previous contents, and
    /// that entry names this build. Without an age window the directory only
    /// ever grows, in the user's home, where nobody is going to notice.
    #[test]
    fn entries_nothing_has_written_for_a_month_are_swept() {
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&hash(), &entry());
        let path = cache.entry_path(&hash()).unwrap();
        let root = cache.root().unwrap();

        // The age is stated rather than arranged on the filesystem, which the
        // standard library cannot do: the pass is asked what it would remove a
        // day either side of the window.
        let a_day = Duration::from_secs(24 * 60 * 60);
        let now = SystemTime::now();

        assert_eq!(prune_dir(root, now), 0, "a fresh entry stays");
        assert_eq!(
            prune_dir(root, now + MAX_ENTRY_AGE - a_day),
            0,
            "an entry inside the window stays"
        );
        assert!(path.exists());

        assert_eq!(
            prune_dir(root, now + MAX_ENTRY_AGE + a_day),
            1,
            "an entry past the window goes"
        );
        assert!(!path.exists());
    }

    /// A clock that moved backwards makes an entry look as though it was written
    /// in the future. Every unanswerable question about an entry's age has the
    /// same answer - keep it - because the cost of keeping one is a file's worth
    /// of disk and the cost of removing one is work redone.
    #[test]
    fn an_entry_dated_in_the_future_is_kept() {
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&hash(), &entry());
        let root = cache.root().unwrap();

        let long_ago = SystemTime::now() - MAX_ENTRY_AGE * 2;
        assert_eq!(prune_dir(root, long_ago), 0);
        assert!(cache.get(&hash(), &content()).is_some());
    }

    /// A tree with no cache directory must not grow one, so there is nowhere to
    /// put a stamp and the next open sweeps an empty directory. That is the
    /// cheap case anyway.
    #[test]
    fn a_missing_cache_directory_is_not_created_by_the_stamp() {
        let fx = Fixture::new();
        let cache = fx.open();
        assert!(!cache.root().unwrap().exists());
        assert_eq!(prune_in(fx.base(), fx.root()), 0);
        assert!(
            !cache.root().unwrap().exists(),
            "prune created a cache directory"
        );
    }

    /// The count is what the CLI prints, so it has to be the number of entries
    /// that actually left.
    #[test]
    fn prune_counts_the_entries_it_removed() {
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&hash(), &entry());
        assert_eq!(prune_in(fx.base(), fx.root()), 0, "nothing foreign yet");

        for (index, version) in ["0.0.1", "0.9.0", "1.0.0"].iter().enumerate() {
            seed_foreign_entry(
                &cache,
                &content_hash(format!("old {index}").as_bytes()),
                version,
            );
        }
        assert_eq!(prune_in(fx.base(), fx.root()), 3);
        assert_eq!(
            prune_in(fx.base(), fx.root()),
            0,
            "a second pass finds nothing"
        );
        assert!(cache.get(&hash(), &content()).is_some());
    }

    #[test]
    fn entry_version_reads_the_declared_version_only() {
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&hash(), &entry());

        assert_eq!(
            entry_version(&cache.entry_path(&hash()).unwrap()).as_deref(),
            Some(VERSION),
            "an entry this build wrote must name this build"
        );
        assert_eq!(entry_version(&fx.root().join("absent.json")), None);

        let probe = |bytes: &[u8]| {
            let path = fx.root().join("probe.json");
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
        let salt = resolve_salt(cache.root().unwrap(), this_uid(), false)
            .expect("a written cache has a salt");
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
        salt_file(cache.root().unwrap()).expect("this platform trusts no salt at all")
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
            fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    /// The shipped defect, at this layer: an entry that says the file is clean
    /// is believed, and the credential in it is never reported. Editing the
    /// findings out of an entry must cost the attacker the entry.
    #[test]
    fn an_entry_whose_body_was_edited_is_a_miss() {
        let fx = Fixture::new();
        let cache = fx.open();
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

    /// An entry written for another cache directory is not this one's to
    /// believe, whether or not the salt travelled with it. The location is what
    /// keeps a scanned tree from delivering either; this is what happens when
    /// they arrive some other way - an unpacked archive, a restored CI cache, a
    /// copy by hand.
    #[test]
    fn an_entry_from_another_cache_directory_is_a_miss() {
        let hash = hash();
        let theirs_fx = Fixture::new();
        let mine_fx = Fixture::new();
        let theirs = theirs_fx.open();
        let mine = mine_fx.open();

        theirs.put(&hash, &entry());
        let source = theirs.entry_path(&hash).unwrap();
        let target = mine.entry_path(&hash).unwrap();
        // Owner-only, like every directory this crate makes: a directory staged
        // any other way would be refused for its mode and prove nothing about
        // the entry inside it.
        create_dir_all_secure(target.parent().unwrap()).unwrap();
        fs::copy(&source, &target).unwrap();

        assert!(
            mine.get(&hash, &content()).is_none(),
            "a foreign entry was served"
        );

        // Now with the salt as well, as a wholesale copy of a cache directory
        // would arrive. A fresh instance is used because the first one has
        // already resolved this directory as saltless.
        fs::copy(salt_path(&theirs), salt_path(&mine)).unwrap();
        set_owner_only(&salt_path(&mine));
        let mine = mine_fx.open();
        assert!(
            mine.get(&hash, &content()).is_none(),
            "a copied cache was served in a directory that did not write it"
        );

        // The directory it was written in still reads it.
        assert!(theirs.get(&hash, &content()).is_some());
    }

    /// Warm caches still have to be warm, and a hit has to be the stored entry
    /// rather than a coincidence. The message here is one no engine produces:
    /// seeing it back proves the value came off the disk.
    #[test]
    fn a_legitimate_entry_is_a_hit_across_cache_instances() {
        let fx = Fixture::new();
        let hash = hash();
        let first = fx.open();
        first.put(&hash, &entry());

        retag(&first, &hash, |stored| {
            stored.findings[0].message = "served from the cache".to_string();
        });

        // A second instance reads the salt back off the disk, which is what the
        // next run of the binary does.
        let second = fx.open();
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
        let fx = Fixture::new();
        let hash = hash();
        let cache = fx.open();
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

            let cold = fx.open();
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
        let warm = fx.open();
        assert!(warm.get(&hash, &content()).is_some());
    }

    /// A cache directory with a salt this build will not use writes no entries
    /// either: an entry it could not read back is not worth the bytes.
    #[test]
    fn an_unusable_salt_is_not_replaced_and_stops_writes() {
        let fx = Fixture::new();
        let hash = hash();
        let cache = fx.open();
        cache.put(&hash, &entry());

        let foreign = "not a salt\n";
        write_salt(&cache, foreign);
        fs::remove_file(cache.entry_path(&hash).unwrap()).unwrap();

        let cache = fx.open();
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
        let fx_a = Fixture::new();
        let fx_b = Fixture::new();
        let a = fx_a.open();
        let b = fx_b.open();

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
        let fx = Fixture::new();
        let cache = fx.open();
        assert!(cache.get(&hash(), &content()).is_none());
        assert!(!cache.root().unwrap().exists());
        assert!(!salt_path(&cache).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_salt_is_owner_only_and_a_wider_one_is_ignored() {
        use std::os::unix::fs::PermissionsExt as _;

        let fx = Fixture::new();
        let hash = hash();
        let cache = fx.open();
        cache.put(&hash, &entry());

        let mode = fs::metadata(salt_path(&cache))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, FILE_MODE, "salt mode {:o}", mode & 0o777);

        // A checkout produces a group- or world-readable file, which is the
        // signal that this salt arrived with the tree rather than being written
        // here.
        for wider in [0o644, 0o640, 0o604, 0o666] {
            fs::set_permissions(salt_path(&cache), fs::Permissions::from_mode(wider)).unwrap();
            let cache = fx.open();
            assert!(
                cache.get(&hash, &content()).is_none(),
                "a {wider:o} salt was trusted"
            );
        }

        fs::set_permissions(salt_path(&cache), fs::Permissions::from_mode(FILE_MODE)).unwrap();
        let cache = fx.open();
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

        let fx = Fixture::new();
        let hash = hash();
        let cache = fx.open();
        cache.put(&hash, &entry());

        let path = salt_path(&cache);
        let before = fs::read_to_string(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        // The entries under the old salt are misses, as they must be: nothing
        // here starts trusting a salt it rejected.
        let reopened = fx.open();
        assert!(reopened.get(&hash, &content()).is_none());

        // The next write replaces the salt rather than giving up on it.
        reopened.put(&hash, &entry());
        let after = fs::read_to_string(&path).unwrap();
        assert_ne!(after, before, "the rejected salt must not survive");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            FILE_MODE
        );

        let warm = fx.open();
        assert!(
            warm.get(&hash, &content()).is_some(),
            "the cache must work again once the salt is this build's"
        );
    }

    /// Everything this crate creates for a cache is owner-only, and none of it
    /// is left to the process umask.
    ///
    /// The shipped defect: at the common `umask 022` the cache directory came
    /// out `0755` and every entry `0644`, so an inventory of a private tree -
    /// paths, rule ids, positions, and each secret's exact length - was readable
    /// by every account on the machine. At `002` or `000` the directory was
    /// group- or world-writable as well, which is a salt anyone could replace.
    ///
    /// Run under `umask 000` by re-executing this one test through a shell,
    /// because there is no way to set a umask from inside a process without a
    /// dependency this crate does not have. The child is asserted to have
    /// actually run the test, so a rename here cannot turn into a silent pass.
    /// Where there is no shell to be had, the assertions still run under
    /// whatever umask the harness has, and say so.
    #[cfg(unix)]
    #[test]
    fn created_directories_and_files_are_owner_only_whatever_the_umask() {
        const CHILD: &str = "SILOSCAN_TEST_PERMISSIVE_UMASK";
        const NAME: &str =
            "cache::tests::created_directories_and_files_are_owner_only_whatever_the_umask";

        if std::env::var_os(CHILD).is_some() {
            assert_created_paths_are_owner_only();
            return;
        }
        let Ok(exe) = std::env::current_exe() else {
            assert_created_paths_are_owner_only();
            return;
        };
        let run = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("umask 000; exec \"$0\" --exact --nocapture {NAME}"))
            .arg(&exe)
            .env(CHILD, "1")
            .output();
        let Ok(run) = run else {
            // No shell, so no umask to set. The property is still asserted, it
            // is just asserted under this process's umask.
            assert_created_paths_are_owner_only();
            return;
        };
        let mut text = String::from_utf8_lossy(&run.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&run.stderr));
        assert!(run.status.success(), "under umask 000:\n{text}");
        assert!(
            text.contains("1 passed"),
            "the child ran no test, so this proves nothing:\n{text}"
        );
    }

    #[cfg(unix)]
    fn assert_created_paths_are_owner_only() {
        let fx = Fixture::new();
        let hash = hash();
        let cache = fx.open();
        cache.put(&hash, &entry());

        // What the umask would have produced on its own, for the failure
        // message: at 000 this is 0666 and at 022 it is 0644, and either way
        // the modes below are the ones this crate set rather than the ones it
        // was given.
        let reference = fx.base().join("reference");
        fs::write(&reference, "x").unwrap();
        let umask = format!("a umask-created file here is {:o}", mode_of(&reference));

        let root = cache.root().unwrap().to_path_buf();
        let entry_file = cache.entry_path(&hash).unwrap();
        let shard = entry_file.parent().unwrap();

        assert_eq!(mode_of(&root), DIR_MODE, "cache root: {umask}");
        assert_eq!(mode_of(shard), DIR_MODE, "shard: {umask}");
        assert_eq!(mode_of(&entry_file), FILE_MODE, "entry: {umask}");
        assert_eq!(mode_of(&salt_path(&cache)), FILE_MODE, "salt: {umask}");

        // The stamp is written by the open after the directory exists, which is
        // the next run of the binary.
        let _ = fx.open();
        let stamp = root.join(STAMP_NAME);
        assert!(stamp.is_file(), "no stamp to check");
        assert_eq!(mode_of(&stamp), FILE_MODE, "stamp: {umask}");

        // And nothing else this crate leaves behind is readable either.
        for path in [
            root.as_path(),
            shard,
            &entry_file,
            &salt_path(&cache),
            &stamp,
        ] {
            assert_eq!(
                mode_of(path) & OTHERS_MASK,
                0,
                "{} is reachable by others: {umask}",
                path.display()
            );
        }
    }

    /// A cache directory that grants group or other anything is not read from,
    /// not written to, and not believed - whatever it holds was reachable by
    /// accounts that are not this one. It is tightened back to `0700` and its
    /// salt goes with it, so nothing written while it stood open can ever
    /// authenticate again, and the run after it is a normal cold one.
    #[cfg(unix)]
    #[test]
    fn a_cache_directory_others_can_reach_is_not_trusted() {
        for loose in [0o777, 0o770, 0o707, 0o750, 0o705, 0o701] {
            let fx = Fixture::new();
            let hash = hash();
            let cache = fx.open();
            cache.put(&hash, &entry());
            assert!(cache.get(&hash, &content()).is_some(), "warm to begin with");

            let root = cache.root().unwrap().to_path_buf();
            let entry_file = cache.entry_path(&hash).unwrap();
            set_mode(&root, loose);

            let exposed = fx.open();
            assert!(
                exposed.get(&hash, &content()).is_none(),
                "a {loose:o} cache directory was read"
            );
            let other = content_hash(b"another file");
            exposed.put(&other, &entry());
            assert_eq!(
                files_in(&root),
                vec![hash[..2].to_string()],
                "a {loose:o} cache directory was written to"
            );
            assert_eq!(
                files_in(&root.join(&hash[..2])),
                vec![entry_file.file_name().unwrap().to_string_lossy()],
                "a {loose:o} cache directory was written to"
            );
            assert_eq!(
                mode_of(&root),
                DIR_MODE,
                "a {loose:o} directory was left as it was"
            );
            assert!(
                !salt_path(&exposed).exists(),
                "the salt survived a directory others could write"
            );

            // The next run finds a directory that is owner-only again. The
            // entries written before it was exposed stay unreadable - their
            // salt is gone - and the cache refills from cold.
            let next = fx.open();
            assert!(
                next.get(&hash, &content()).is_none(),
                "an entry from an exposed directory came back"
            );
            next.put(&hash, &entry());
            assert!(
                next.get(&hash, &content()).is_some(),
                "the cache never warmed up again"
            );
        }
    }

    /// A cache directory or a salt belonging to another uid is not this user's
    /// to read, write or repair.
    ///
    /// Staging one needs `chown`, which needs root, so the full sequence only
    /// runs where the suite runs as root, as a container-based CI does. An
    /// unprivileged run gets what it can honestly get instead: a directory that
    /// already belongs to another uid - `/usr` and friends - must come back
    /// [`DirTrust::Rejected`] and must come back untouched. That does not
    /// isolate the ownership test from the mode test, because a system directory
    /// fails both, and an unprivileged process could not carry out the repair
    /// either way. It does establish that no directory belonging to somebody
    /// else is ever accepted, which is the property.
    #[cfg(unix)]
    #[test]
    fn a_cache_directory_or_salt_owned_by_another_uid_is_not_trusted() {
        use std::os::unix::fs::{MetadataExt as _, chown};

        /// `nobody` on every distribution this is likely to run on, and an
        /// account that certainly is not the one running the tests.
        const OTHER: u32 = 65534;

        if this_uid() != 0 {
            let foreign: Vec<PathBuf> = ["/usr", "/etc", "/var", "/bin"]
                .iter()
                .map(PathBuf::from)
                .filter(|path| {
                    fs::metadata(path).is_ok_and(|meta| meta.is_dir() && meta.uid() != this_uid())
                })
                .collect();
            assert!(
                !foreign.is_empty(),
                "no directory owned by another uid to test against"
            );
            for path in foreign {
                let before = mode_of(&path);
                assert_eq!(
                    secure_dir(&path, false),
                    DirTrust::Rejected,
                    "{} belongs to another uid and was accepted",
                    path.display()
                );
                assert_eq!(
                    mode_of(&path),
                    before,
                    "{} belongs to another uid and was modified",
                    path.display()
                );
            }
            eprintln!(
                "partial: staging a cache directory owned by another uid needs \
                 root, and this run is uid {}. What ran here is the refusal of \
                 directories that already belong to somebody else; the salt half \
                 and the do-not-repair half need a root run.",
                this_uid()
            );
            return;
        }

        let fx = Fixture::new();
        let hash = hash();
        let cache = fx.open();
        cache.put(&hash, &entry());
        assert!(cache.get(&hash, &content()).is_some(), "warm to begin with");
        let root = cache.root().unwrap().to_path_buf();
        let salt = salt_path(&cache);
        let salt_before = fs::read_to_string(&salt).unwrap();

        chown(&root, Some(OTHER), None).unwrap();
        let theirs = fx.open();
        assert!(
            theirs.get(&hash, &content()).is_none(),
            "a directory owned by another uid was read"
        );
        theirs.put(&content_hash(b"another file"), &entry());
        assert_eq!(
            fs::read_to_string(&salt).unwrap(),
            salt_before,
            "another user's directory was repaired"
        );
        assert_eq!(
            mode_of(&root),
            DIR_MODE,
            "another user's directory was chmodded"
        );

        // The directory back, the salt not. A salt this user does not own is
        // one this user did not write, whatever its mode says.
        chown(&root, Some(this_uid()), None).unwrap();
        chown(&salt, Some(OTHER), None).unwrap();
        let cache = fx.open();
        assert!(
            cache.get(&hash, &content()).is_none(),
            "a salt owned by another uid was used"
        );

        // Inside a directory this user owns and nobody else can write, that
        // salt is a leftover rather than an attack, and the next write replaces
        // it instead of leaving the cache cold forever.
        cache.put(&hash, &entry());
        assert_ne!(fs::read_to_string(&salt).unwrap(), salt_before);
        assert!(fx.open().get(&hash, &content()).is_some());
    }

    /// The determinism rule, against the state the checks above introduce: a
    /// cache that is refused produces exactly what a cold scan produces, because
    /// a refused cache is a miss and a miss is a rescan.
    #[cfg(unix)]
    #[test]
    fn cold_warm_and_refused_caches_produce_identical_findings() {
        let fx = Fixture::new();
        let hash = hash();
        let cold = entry();

        let cache = fx.open();
        cache.put(&hash, &cold);
        let warm = fx
            .open()
            .get(&hash, &content())
            .expect("a warm cache is a hit");

        set_mode(cache.root().unwrap(), 0o777);
        // A refused cache answers `None`, which is the caller's signal to scan
        // the file - and scanning the file is what produced `cold`.
        let refused = fx.open().get(&hash, &content());
        assert!(refused.is_none(), "a refused cache served an entry");
        let refused = refused.unwrap_or_else(|| cold.clone());

        let bytes = |file: &CachedFile| serde_json::to_vec(&file.findings).unwrap();
        assert_eq!(bytes(&cold), bytes(&warm), "warm output differs from cold");
        assert_eq!(
            bytes(&cold),
            bytes(&refused),
            "refused output differs from cold"
        );
    }

    /// A scan root's cache is keyed by where the root is, so moving the root is
    /// a cold scan and nothing else. Moving it is not tampering; it is also not
    /// something the entries, which carry paths, can be dragged through.
    #[test]
    fn a_moved_scan_root_gets_its_own_cache() {
        let fx = Fixture::new();
        let hash = hash();
        let from = fx.root().join("before");
        let to = fx.root().join("after");
        fs::create_dir_all(&from).unwrap();

        let cache = Cache::open_in(fx.base(), &from, &ruleset("a"), &PathScope::ScanRoot);
        cache.put(&hash, &entry());
        assert!(cache.get(&hash, &content()).is_some());

        fs::rename(&from, &to).unwrap();
        let moved = Cache::open_in(fx.base(), &to, &ruleset("a"), &PathScope::ScanRoot);
        assert_ne!(cache.root(), moved.root());
        assert!(moved.get(&hash, &content()).is_none());

        // And it warms right back up where it now lives.
        moved.put(&hash, &entry());
        let reopened = Cache::open_in(fx.base(), &to, &ruleset("a"), &PathScope::ScanRoot);
        assert!(reopened.get(&hash, &content()).is_some());
    }

    #[test]
    fn the_tag_covers_the_key_as_well_as_the_body() {
        let fx = Fixture::new();
        let cache = fx.open();
        cache.put(&hash(), &entry());
        let salt = resolve_salt(cache.root().unwrap(), this_uid(), false).unwrap();
        let body = read_entry(&cache, &hash()).body_bytes().unwrap();

        let tag = entry_tag(&salt, &cache.entry_key(&hash()), &body);
        assert_eq!(tag, read_entry(&cache, &hash()).tag);
        assert_eq!(tag.len(), 64);
        assert_ne!(
            tag,
            entry_tag(&salt, &cache.entry_key(&content_hash(b"other")), &body),
            "the tag must not travel between keys"
        );
        let mut other = salt;
        other[0] ^= 0xff;
        assert_ne!(
            tag,
            entry_tag(&other, &cache.entry_key(&hash()), &body),
            "the tag must not survive a different salt"
        );
    }

    /// A salt is only as good as the randomness behind it: one derived from the
    /// process id, the clock and the directory path is reproducible by anyone
    /// who knows roughly when and where the cache was created, and reproducing
    /// the salt is forging the entries. The OS source is the only input, so a
    /// salt is a function of nothing this process, this machine or this
    /// directory can be asked about.
    ///
    /// Ungated: every platform this ships on has an OS random source, so a
    /// platform that cannot produce a salt here is a platform whose cache is
    /// broken, and a failure is what should say so.
    #[test]
    fn salt_bytes_come_from_the_os_random_source() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            let salt = generate_salt().expect("this platform has an OS random source");
            assert!(
                salt.iter().any(|byte| *byte != 0),
                "the random source produced nothing"
            );
            assert!(seen.insert(salt), "the random source repeated itself");
        }
    }

    /// Fail closed: a salt that cannot be made is not made up. Every step that
    /// wants one takes `None` for an answer and leaves the directory exactly as
    /// it found it - no file, no fallback stitched together out of the clock
    /// and the path.
    ///
    /// The random source refusing is one way into that `None` and cannot be
    /// staged from a test without either `unsafe` or a fault-injecting
    /// dependency, neither of which is worth a branch that is one `ok()?`. A
    /// missing directory is the other way in, it reaches the same `None` in the
    /// same function, and everything downstream of it is what this asserts.
    #[test]
    fn a_salt_that_cannot_be_made_is_never_invented() {
        let fx = Fixture::new();
        let root = fx.root().join("gone");

        assert!(create_salt(&root, this_uid()).is_none());
        assert!(resolve_salt(&root, this_uid(), true).is_none());
        assert!(!root.exists(), "a failed salt left something behind");
    }

    /// The failure direction the whole design turns on, from the outside: a
    /// cache directory with no salt writes no entries and serves none, so the
    /// scan is cold and correct rather than warm and forged.
    #[test]
    fn a_cache_with_no_salt_writes_nothing_and_serves_nothing() {
        let fx = Fixture::new();
        let hash = hash();
        let cache = fx.open();
        cache.put(&hash, &entry());
        fs::remove_file(salt_path(&cache)).unwrap();

        // A read never invents a salt, so the entries stay unreadable.
        let cold = fx.open();
        assert!(cold.get(&hash, &content()).is_none());
        assert!(!salt_path(&cold).exists(), "a read created a salt");
        assert!(resolve_salt(cache.root().unwrap(), this_uid(), false).is_none());
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

    /// A cache rooted exactly at `root`, which is what 1.3.0 built for
    /// `<scan root>/.siloscan/cache`. Nothing in this build produces one: it is
    /// how the attacker's in-tree cache is staged below, written the way the
    /// release that read it would have written it.
    fn cache_rooted_at(root: &Path) -> Cache {
        Cache::bind(
            Some(root.to_path_buf()),
            Some(root.to_path_buf()),
            &ruleset("a"),
            &PathScope::ScanRoot,
        )
    }

    /// The 1.3.0 blocker, at this layer.
    ///
    /// The attacker ships a tree with a `.siloscan/cache` in it, salted and
    /// tagged by them, whose entry says the file holding the credential has no
    /// findings. Every check 1.3.0 applied passes - the tag authenticates, the
    /// mode is `0600` because an archive preserves it, and the absolute path is
    /// the one the tree extracts to - and the scan reported clean and exited 0.
    ///
    /// The entry is still perfectly valid. It is simply never looked at, because
    /// the cache is not there any more.
    #[test]
    fn an_in_tree_cache_is_never_consulted_even_when_it_authenticates() {
        let fx = Fixture::new();
        let hash = hash();

        let in_tree = fx.root().join(CACHE_DIR);
        // Owner-only, as an attacker's archive would unpack it: the point here
        // is that the directory is never looked at, so it must not fail for a
        // reason as incidental as its mode.
        create_dir_all_secure(&in_tree).unwrap();
        let forged = cache_rooted_at(&in_tree);
        forged.put(
            &hash,
            &CachedFile {
                findings: Vec::new(),
                facts: None,
            },
        );
        assert!(
            forged
                .get(&hash, &content())
                .expect("the forged entry must authenticate, or this proves nothing")
                .findings
                .is_empty()
        );
        let staged = files_in(&in_tree);

        // What the scan actually opens. Cold, and it stays cold: the tree's
        // entry is not a miss because it failed a check, it is a miss because
        // nothing here reads that directory.
        let cache = fx.open();
        assert!(
            cache.get(&hash, &content()).is_none(),
            "an in-tree cache was consulted, so a poisoned tree reports clean"
        );

        // Warm, in the new location, serves what the scan itself recorded - the
        // findings, not the attacker's empty list.
        cache.put(&hash, &entry());
        assert_eq!(
            cache.get(&hash, &content()).unwrap().findings,
            entry().findings
        );
        assert_eq!(
            fx.open().get(&hash, &content()).unwrap().findings,
            entry().findings,
            "the next run of the binary must see the same entry"
        );

        // The repository is left as it was found. Not read is not the same as
        // deleted, and deleting files inside a scanned tree is not our business.
        assert_eq!(files_in(&in_tree), staged);
        assert!(forged.get(&hash, &content()).is_some());
    }

    /// The location policy, which is the whole defence. It reads the
    /// environment of the process running the scan and nothing else.
    #[cfg(unix)]
    #[test]
    fn the_user_cache_directory_follows_xdg_then_home() {
        let resolve = |xdg: Option<&str>, home: Option<&str>| -> Option<PathBuf> {
            let xdg = xdg.map(OsString::from);
            let home = home.map(OsString::from);
            user_cache_dir(&|name| match name {
                "XDG_CACHE_HOME" => xdg.clone(),
                "HOME" => home.clone(),
                _ => None,
            })
        };

        let xdg = Some(PathBuf::from("/xdg"));
        let home = Some(PathBuf::from("/home/u/.cache"));
        assert_eq!(resolve(Some("/xdg"), Some("/home/u")), xdg);
        assert_eq!(resolve(Some("/xdg"), None), xdg);
        assert_eq!(resolve(None, Some("/home/u")), home);

        // Empty and relative values are not values. Resolving a relative one
        // against the working directory is how a cache lands back inside the
        // tree being scanned.
        assert_eq!(resolve(Some(""), Some("/home/u")), home);
        assert_eq!(resolve(Some("cache"), Some("/home/u")), home);
        assert_eq!(resolve(Some("../cache"), Some("/home/u")), home);
        assert_eq!(resolve(None, Some("u")), None);

        // Neither one set: no cache directory, therefore no cache.
        assert_eq!(resolve(None, None), None);
        assert_eq!(resolve(Some(""), None), None);
    }

    #[test]
    fn the_default_base_is_this_crate_namespace_under_the_user_cache_directory() {
        let expected =
            user_cache_dir(&|name| std::env::var_os(name)).map(|dir| dir.join(CACHE_NAMESPACE));
        assert_eq!(default_cache_base(), expected);
        if let Some(base) = default_cache_base() {
            assert_eq!(base.file_name().unwrap(), CACHE_NAMESPACE);
            assert!(base.is_absolute());
        }
    }

    /// The ordinary layout: the cache is somewhere else entirely, so a scan has
    /// nothing to keep out of its walk.
    #[test]
    fn a_cache_outside_the_scan_root_has_no_exclusion() {
        let fx = Fixture::new();
        assert_eq!(fx.open().exclusion_under(fx.root()), None);
    }

    /// The layout the exclusion exists for. The answer is the directory the
    /// cache occupies, spelled against the scan root as it was given, because
    /// that is the spelling the walk produces - and it is that directory only,
    /// not the directory holding it, which under `--cache-dir` belongs to the
    /// user and may hold anything.
    #[test]
    fn a_cache_under_the_scan_root_is_named_for_exclusion() {
        let root = tempdir();
        let named = root.path().join("vendor");
        let cache = Cache::open_in(&named, root.path(), &ruleset("a"), &PathScope::ScanRoot);

        let excluded = cache.exclusion_under(root.path()).expect("under the root");
        assert_eq!(excluded, cache.root().unwrap());
        assert!(excluded.starts_with(&named));
        assert_ne!(excluded, named, "the directory holding the cache is not it");

        // Spelled against the scan root as given rather than as canonicalized,
        // because that is what the walk's paths are built from: a root reached
        // through `.` and `..` produces entries spelled the same way, and a
        // canonical prefix would match none of them.
        fs::create_dir(root.path().join("sub")).unwrap();
        let indirect = root.path().join("sub").join("..");
        assert_eq!(
            cache.exclusion_under(&indirect).expect("under the root"),
            indirect.join("vendor").join(excluded.file_name().unwrap())
        );
    }

    /// Scanning the cache directory itself. Excluding the whole of it would
    /// empty the scan without saying so, so the narrower per-scan-root
    /// directory answers instead - which is still the part a warm run would
    /// otherwise walk and a cold run would not.
    #[test]
    fn scanning_the_cache_directory_itself_excludes_only_this_run_s_cache() {
        let base = tempdir();
        let cache = Cache::open_in(
            base.path(),
            base.path(),
            &ruleset("a"),
            &PathScope::ScanRoot,
        );

        assert_eq!(
            cache.exclusion_under(base.path()).as_deref(),
            cache.root(),
            "a scan of the cache directory must not exclude the scan root"
        );
    }

    /// No `XDG_CACHE_HOME` and no `HOME` is no cache directory, and no cache
    /// directory is a cold cache: reads miss, writes go nowhere, and nothing is
    /// invented to compensate - least of all a location inside the scanned tree.
    #[test]
    fn a_cache_with_no_location_is_cold_and_creates_nothing() {
        let fx = Fixture::new();
        let cache = Cache::bind(None, None, &ruleset("a"), &PathScope::ScanRoot);

        assert!(cache.root().is_none());
        // Nowhere to put a cache is nowhere for a walk to find one.
        assert_eq!(cache.exclusion_under(fx.root()), None);
        assert!(cache.get(&hash(), &content()).is_none());
        cache.put(&hash(), &entry());
        assert!(cache.get(&hash(), &content()).is_none());
        assert_eq!(files_in(fx.root()), Vec::<String>::new());
        assert_eq!(prune_in(fx.base(), fx.root()), 0);
    }

    /// One cache directory, two scan roots, two caches. It has to be two: an
    /// entry is keyed by file content, and identical bytes in two trees are
    /// findings at two different paths with two different fingerprints.
    #[test]
    fn two_scan_roots_do_not_share_entries() {
        let base = tempdir();
        let left = tempdir();
        let right = tempdir();
        let hash = hash();

        let scope = PathScope::ScanRoot;
        let a = Cache::open_in(base.path(), left.path(), &ruleset("a"), &scope);
        let b = Cache::open_in(base.path(), right.path(), &ruleset("a"), &scope);

        assert!(a.root().unwrap().starts_with(base.path()));
        assert!(b.root().unwrap().starts_with(base.path()));
        assert_ne!(a.root(), b.root());

        a.put(&hash, &entry());
        assert!(a.get(&hash, &content()).is_some());
        assert!(
            b.get(&hash, &content()).is_none(),
            "one scan root's entry was served to another"
        );
    }

    /// The per-root directory is keyed by the canonical path, so one root
    /// spelled two ways is one cache, and a root that does not resolve is no
    /// cache rather than a cache keyed on a name.
    #[test]
    fn the_root_directory_is_keyed_by_the_canonical_path() {
        let fx = Fixture::new();
        fs::create_dir(fx.root().join("sub")).unwrap();

        let direct = root_dir(fx.base(), fx.root()).unwrap();
        let round_about = root_dir(fx.base(), &fx.root().join("sub").join("..")).unwrap();

        assert_eq!(direct, round_about);
        assert_eq!(direct.parent(), Some(fx.base()));
        assert_eq!(direct.file_name().unwrap().len(), ROOT_HASH_PREFIX);
        assert_ne!(direct, root_dir(fx.base(), &fx.root().join("sub")).unwrap());
        assert_eq!(root_dir(fx.base(), &fx.root().join("absent")), None);
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
