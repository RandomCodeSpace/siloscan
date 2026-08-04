use std::borrow::Cow;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::rules::Severity;

/// `Deserialize` is required by the incremental cache, which stores findings
/// verbatim and reads them back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Renders text taken from a scanned repository so that a terminal displays it
/// instead of obeying it.
///
/// A finding's path, rule id and message are all attacker-controlled: the path
/// is a file name, the message comes from a rule file the repository can supply
/// through `siloscan.toml`, and a skip reason quotes both. The lines of a source
/// file, which the TUI's detail pane draws verbatim, are the repository's own
/// bytes. Written raw, an `ESC [ 2 K` in any of them erases the line it lands on
/// and `ESC [ A` walks back over the ones above, so a repository holding a live
/// credential can paint "scan complete: 0 findings" over its own report. Every
/// C0 control (0x00-0x1F), DEL (0x7F) and every C1 control (U+0080-U+009F) is
/// therefore replaced by a visible `\xNN`.
///
/// Tab is included, and the choice is deliberate. It moves the cursor to the
/// next stop rather than emitting a glyph, which is enough to push a report
/// line's fields out of their columns and hide a path behind the message beside
/// it; a scanned path or message has no legitimate reason to carry one.
///
/// The result is a display form and not a reversible encoding: text that
/// literally contains the four characters `\x1b` renders as itself. Nothing
/// reads this back, and the property that has to hold is only that no control
/// byte reaches the terminal.
///
/// Human output only - the CLI's stderr and stdout, and every span the TUI
/// draws. JSON and SARIF are read by tools, already escape C0 controls per
/// RFC 8259, and carry the fingerprints; rewriting their bytes would move output
/// that other things compare. Nor may the result be fed back to the filesystem,
/// a baseline entry or a fingerprint: it is a rendering of a path, not the path.
///
/// Callers that also slice by byte offset - a source line highlighted at a
/// finding's column - must slice first and sanitize the pieces, since expanding
/// a control byte to four characters moves every offset after it.
pub fn sanitize_for_terminal(text: &str) -> Cow<'_, str> {
    if !text.chars().any(is_display_control) {
        return Cow::Borrowed(text);
    }

    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if is_display_control(ch) {
            let _ = write!(out, "\\x{:02x}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

/// C0 including tab, DEL, and C1. Every one of them is at most two hex digits
/// wide, which is what makes the `\xNN` rendering above unambiguous.
fn is_display_control(ch: char) -> bool {
    matches!(ch, '\u{00}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_every_control_and_borrows_otherwise() {
        assert_eq!(
            sanitize_for_terminal("evil\u{1b}[2K\rok.js"),
            "evil\\x1b[2K\\x0dok.js"
        );
        assert_eq!(sanitize_for_terminal("a\tb"), "a\\x09b");
        assert_eq!(sanitize_for_terminal("\u{7f}\u{9f}"), "\\x7f\\x9f");
        // Text with nothing to escape is passed through untouched, allocation
        // included: this runs on every span of every frame.
        assert!(matches!(
            sanitize_for_terminal("src/main.rs"),
            Cow::Borrowed("src/main.rs")
        ));
        // Non-ASCII above the C1 block is text, not a control.
        assert_eq!(
            sanitize_for_terminal("caf\u{e9} \u{4e2d}"),
            "caf\u{e9} \u{4e2d}"
        );
    }

    #[test]
    fn no_control_byte_survives_sanitizing() {
        let hostile: String = (0u32..0x100).filter_map(char::from_u32).collect();
        let safe = sanitize_for_terminal(&hostile);
        assert!(!safe.chars().any(is_display_control), "{safe:?}");
    }

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
