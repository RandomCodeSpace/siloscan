//! Accepted findings, recorded so a scan can report only what is new.
//!
//! Membership is decided by fingerprint alone. A stored entry's path is
//! carried through verbatim from the finding that produced it and is never
//! rewritten on read or write: there is no translation layer here, and there
//! must not be one.
//!
//! That makes a baseline bound to the path convention of the scan that wrote
//! it. A fingerprint hashes the finding's path, so the same finding fingerprints
//! differently under `anchor = "scan-root"` and `anchor = "config"`, and every
//! entry written under one convention misses under the other. Switching the
//! anchor therefore requires re-baselining: set the key, run `siloscan
//! baseline` once, commit the result. That single explicit re-write is the
//! whole migration, which is why nothing here tries to be clever about it.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::findings::Finding;

/// Baseline location, relative to the scan root.
pub const BASELINE_PATH: &str = ".siloscan/baseline.json";

const SUPPORTED_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule_id: String,
    /// The finding's path, forward-slashed, in the convention the scan that
    /// wrote this entry used. Recorded for readability; matching never reads
    /// it.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub entries: Vec<BaselineEntry>,
}

fn baseline_file(root: &Path) -> PathBuf {
    root.join(BASELINE_PATH)
}

/// Read the baseline under `root`. An absent file is `Ok(None)`; anything
/// present but unusable is an error, so a stale or damaged baseline can never
/// be mistaken for "nothing suppressed".
pub fn load(root: &Path) -> Result<Option<Baseline>, String> {
    let path = baseline_file(root);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: io error: {e}", path.display())),
    };

    let baseline: Baseline = serde_json::from_str(&text)
        .map_err(|e| format!("{}: invalid baseline: {e}", path.display()))?;

    if baseline.version != SUPPORTED_VERSION {
        return Err(format!(
            "{}: unsupported baseline version {} (expected {SUPPORTED_VERSION})",
            path.display(),
            baseline.version
        ));
    }

    Ok(Some(baseline))
}

/// Write a baseline covering `findings` under `root`, returning the entry
/// count. Entries are sorted by (fingerprint, path, rule id) so the file is
/// byte-identical for identical input. The file is replaced atomically: a
/// re-baseline that fails part way through leaves the previous baseline whole,
/// because a truncated one would fail strict loading and wedge every later
/// scan.
pub fn save(root: &Path, findings: &[Finding]) -> Result<usize, String> {
    let mut entries: Vec<BaselineEntry> = findings
        .iter()
        .map(|f| BaselineEntry {
            fingerprint: f.fingerprint.clone(),
            rule_id: f.rule_id.clone(),
            path: f.path.clone(),
        })
        .collect();

    entries.sort_by(|a, b| {
        a.fingerprint
            .as_bytes()
            .cmp(b.fingerprint.as_bytes())
            .then(a.path.as_bytes().cmp(b.path.as_bytes()))
            .then(a.rule_id.as_bytes().cmp(b.rule_id.as_bytes()))
    });

    let count = entries.len();
    let baseline = Baseline {
        version: SUPPORTED_VERSION,
        entries,
    };

    let path = baseline_file(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: io error: {e}", parent.display()))?;
    }

    let mut json = serde_json::to_string_pretty(&baseline).unwrap(); // serialization cannot fail
    json.push('\n');
    write_atomic(&path, json.as_bytes())?;

    Ok(count)
}

/// Replace `path` with `bytes` in one step: the content goes to a temporary
/// file beside it and is renamed into place, so a failed or interrupted write
/// leaves whatever was already there untouched. On failure the temporary file
/// is removed and nothing else is disturbed.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temp = write_temp(path, bytes)?;
    fs::rename(&temp, path).map_err(|e| {
        let _ = fs::remove_file(&temp);
        format!("{}: io error: {e}", path.display())
    })
}

/// Write `bytes` to a temporary file in `path`'s directory and return it. The
/// temporary lives beside its target so the rename that follows stays within
/// one file system, which is what makes the replacement atomic.
fn write_temp(path: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("{}: has no parent directory", path.display()))?;
    let temp = dir.join(temp_name());
    match write_synced(&temp, bytes) {
        Ok(()) => Ok(temp),
        Err(e) => {
            let _ = fs::remove_file(&temp);
            Err(format!("{}: io error: {e}", temp.display()))
        }
    }
}

/// Write `bytes` and flush them to the device before returning.
///
/// Closing the file only guarantees the bytes survive the process dying. The
/// rename that follows can still reach the disk ahead of the content, so
/// without this `sync_all` a power loss between the two leaves the baseline
/// under its final name with nothing - or a prefix - inside it.
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Unique within a run and across concurrent runs, so two writers never share a
/// temporary file. The baseline is always `baseline.json`, so a stray temporary
/// can never be mistaken for it.
fn temp_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("baseline.{}.{n}.tmp", std::process::id())
}

/// Split findings into (new, baselined) by fingerprint membership. Input order
/// is preserved, so both halves stay canonically ordered.
pub fn partition(baseline: &Baseline, findings: Vec<Finding>) -> (Vec<Finding>, Vec<Finding>) {
    let known: HashSet<&str> = baseline
        .entries
        .iter()
        .map(|e| e.fingerprint.as_str())
        .collect();

    let mut new = Vec::new();
    let mut baselined = Vec::new();
    for finding in findings {
        if known.contains(finding.fingerprint.as_str()) {
            baselined.push(finding);
        } else {
            new.push(finding);
        }
    }

    (new, baselined)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::rules::Severity;

    fn finding(rule_id: &str, path: &str, fingerprint: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Warning,
            message: "message".to_string(),
            path: path.to_string(),
            line: 1,
            column: 1,
            matched: "matched".to_string(),
            fingerprint: fingerprint.to_string(),
        }
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempdir();
        let findings = vec![
            finding("b.rule", "src/b.rs", "ff"),
            finding("a.rule", "src/a.rs", "aa"),
        ];

        let count = save(dir.path(), &findings).unwrap();
        assert_eq!(count, 2);

        let baseline = load(dir.path()).unwrap().expect("baseline should exist");
        assert_eq!(baseline.version, 1);
        assert_eq!(
            baseline.entries,
            vec![
                BaselineEntry {
                    fingerprint: "aa".to_string(),
                    rule_id: "a.rule".to_string(),
                    path: "src/a.rs".to_string(),
                },
                BaselineEntry {
                    fingerprint: "ff".to_string(),
                    rule_id: "b.rule".to_string(),
                    path: "src/b.rs".to_string(),
                },
            ]
        );
    }

    #[test]
    fn saved_json_is_byte_stable() {
        let dir_a = tempdir();
        let dir_b = tempdir();
        // Same findings, different input order.
        let first = vec![
            finding("z.rule", "src/z.rs", "cc"),
            finding("a.rule", "src/a.rs", "aa"),
            finding("m.rule", "src/m.rs", "bb"),
        ];
        let second = vec![
            finding("a.rule", "src/a.rs", "aa"),
            finding("m.rule", "src/m.rs", "bb"),
            finding("z.rule", "src/z.rs", "cc"),
        ];

        save(dir_a.path(), &first).unwrap();
        save(dir_b.path(), &second).unwrap();

        let a = fs::read(dir_a.path().join(BASELINE_PATH)).unwrap();
        let b = fs::read(dir_b.path().join(BASELINE_PATH)).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.last(), Some(&b'\n'));
    }

    #[test]
    fn save_creates_the_baseline_directory() {
        let dir = tempdir();
        save(dir.path(), &[]).unwrap();
        assert!(dir.path().join(BASELINE_PATH).is_file());
    }

    #[test]
    fn save_leaves_no_temporary_file_behind() {
        let dir = tempdir();
        save(dir.path(), &[finding("a.rule", "src/a.rs", "aa")]).unwrap();

        let strays: Vec<PathBuf> = fs::read_dir(dir.path().join(".siloscan"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(strays.is_empty(), "{strays:?}");
    }

    /// A re-baseline that dies between the write and the rename - the ENOSPC or
    /// interrupted case - must leave the previous baseline whole, because a
    /// truncated one fails strict loading and wedges every later scan.
    #[test]
    fn a_failure_before_the_rename_leaves_the_original_intact() {
        let dir = tempdir();
        save(dir.path(), &[finding("a.rule", "src/a.rs", "aa")]).unwrap();

        let path = dir.path().join(BASELINE_PATH);
        let original = fs::read(&path).unwrap();

        // The first half of an atomic write, then the failure: no rename.
        let temp = write_temp(&path, b"truncated").unwrap();

        assert!(temp.is_file(), "the replacement went to a temporary file");
        assert_ne!(temp, path);
        assert_eq!(
            fs::read(&path).unwrap(),
            original,
            "the baseline must be untouched until the rename"
        );
        let baseline = load(dir.path()).unwrap().expect("baseline should exist");
        assert_eq!(baseline.entries.len(), 1);

        // Completing the write is what makes the replacement visible.
        fs::rename(&temp, &path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"truncated");
    }

    #[test]
    fn temporary_names_do_not_collide() {
        let first = temp_name();
        let second = temp_name();
        assert_ne!(first, second);
        assert!(first.ends_with(".tmp"), "{first}");
    }

    #[test]
    fn partition_splits_by_fingerprint() {
        let baseline = Baseline {
            version: 1,
            entries: vec![BaselineEntry {
                fingerprint: "aa".to_string(),
                rule_id: "a.rule".to_string(),
                path: "src/a.rs".to_string(),
            }],
        };
        let findings = vec![
            finding("a.rule", "src/a.rs", "aa"),
            finding("b.rule", "src/b.rs", "bb"),
        ];

        let (new, baselined) = partition(&baseline, findings);

        assert_eq!(new.len(), 1);
        assert_eq!(new[0].fingerprint, "bb");
        assert_eq!(baselined.len(), 1);
        assert_eq!(baselined[0].fingerprint, "aa");
    }

    #[test]
    fn absent_baseline_is_none() {
        let dir = tempdir();
        assert!(load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn corrupt_baseline_is_an_error() {
        let dir = tempdir();
        let path = dir.path().join(BASELINE_PATH);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"{ not json").unwrap();

        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn unsupported_version_is_an_error() {
        let dir = tempdir();
        let path = dir.path().join(BASELINE_PATH);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"{\"version\": 2, \"entries\": []}\n").unwrap();

        assert!(load(dir.path()).is_err());
    }
}
