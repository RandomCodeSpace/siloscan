use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::rules::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    /// Repo-relative path using forward slashes.
    pub path: String,
    /// 1-based line number.
    pub line: u64,
    /// 1-based byte offset within the line.
    pub column: u64,
    pub matched: String,
    pub fingerprint: String,
}

/// Stable identity for a match. Line numbers are deliberately excluded so that
/// unrelated edits above a finding do not change its fingerprint; `occurrence`
/// disambiguates repeated identical matches within the same file.
pub fn fingerprint(rule_id: &str, path: &str, matched: &str, occurrence: u32) -> String {
    let normalized = matched.split_whitespace().collect::<Vec<&str>>().join(" ");

    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(path.as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized.as_bytes());
    hasher.update(b"\0");
    hasher.update(occurrence.to_string().as_bytes());
    let digest = hasher.finalize();

    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable() {
        let a = fingerprint("a.b", "src/main.rs", "let x = 1;", 0);
        let b = fingerprint("a.b", "src/main.rs", "let x = 1;", 0);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_normalizes_whitespace() {
        let a = fingerprint("a.b", "src/main.rs", "let  x\t=\n1;", 0);
        let b = fingerprint("a.b", "src/main.rs", "let x = 1;", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_is_occurrence_sensitive() {
        let a = fingerprint("a.b", "src/main.rs", "let x = 1;", 0);
        let b = fingerprint("a.b", "src/main.rs", "let x = 1;", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_varies_by_rule_and_path() {
        let base = fingerprint("a.b", "src/main.rs", "m", 0);
        assert_ne!(base, fingerprint("a.c", "src/main.rs", "m", 0));
        assert_ne!(base, fingerprint("a.b", "src/other.rs", "m", 0));
    }
}
