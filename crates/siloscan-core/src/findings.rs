use std::borrow::Cow;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::rules::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    /// Repo-relative path using forward slashes.
    pub path: String,
    /// 1-based line number.
    pub line: u64,
    /// 1-based byte offset within the line. This is what the JSON report
    /// publishes, and what it has always published.
    pub column: u64,
    /// 1-based offset within the line counted in UTF-16 code units, which is
    /// how SARIF measures a column.
    ///
    /// The two agree exactly when everything before the match on that line is
    /// ASCII, and diverge otherwise: a `\u{4e2d}` costs three bytes and one
    /// UTF-16 unit, an emoji four bytes and two. Publishing the byte column as
    /// a SARIF `startColumn` therefore points a consumer past the match, or
    /// past the end of the line, on any line with non-ASCII text before it.
    ///
    /// Measured by whatever produces the finding, because that is the only
    /// place the line's bytes are certainly in hand; see
    /// [`crate::engines::LineIndex::position`]. It is deliberately absent from
    /// [`fingerprint`], which must not move when a report gains a second way to
    /// spell a column, and absent from the JSON report, whose schema is
    /// unchanged.
    ///
    /// Zero means "the source this finding was reconstructed from does not
    /// carry a UTF-16 column", and it arises in exactly one place: the TUI
    /// loading a finished JSON report, which by design publishes only the byte
    /// column. That path renders findings and emits no SARIF, so a zero never
    /// reaches a `startColumn`; the one that would, `sarif_column`, clamps it
    /// anyway rather than emit an illegal region.
    ///
    /// Every path that can reach SARIF measures it for real. The incremental
    /// cache is the case that matters, and it does not store this field: it
    /// recomputes it from the file's own bytes on the way back, so a warm scan
    /// and a cold scan of the same tree emit byte-identical SARIF. Defaulting
    /// there instead of recomputing would make cache state visible in the
    /// output, which is the one thing it must never be.
    #[serde(default)]
    pub column_utf16: u64,
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
/// Escape sequences are not the only way to forge a line. The Unicode
/// bidirectional formatting codes reorder the text around them without emitting
/// anything themselves - the Trojan Source trick - so a file named
/// `report\u{202e}sj.eruces` is displayed as `reportsecures.js` while the scan
/// reads the name it really has, and an override left open in a rule message
/// reverses the rest of the report line it sits on. The explicit formatting and
/// override codes are therefore escaped too: U+061C, U+200E, U+200F,
/// U+202A-U+202E and U+2066-U+2069.
///
/// Only those codes. Arabic and Hebrew letters carry their direction as a
/// property of the script and are ordinary content: a path or a message written
/// in either must render as itself, and escaping the letters would make the
/// scanner unusable on a repository that is simply not written in English.
/// A bidi code is written `\u{202e}` rather than `\xNN` because it does not fit
/// in two hex digits, and `\x202e` could not be told apart from `\x20` followed
/// by the text `2e`. Both forms are visible, neither is a control.
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
    if !text.chars().any(needs_escape) {
        return Cow::Borrowed(text);
    }

    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if is_display_control(ch) {
            let _ = write!(out, "\\x{:02x}", ch as u32);
        } else if is_bidi_control(ch) {
            let _ = write!(out, "\\u{{{:04x}}}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

/// Everything [`sanitize_for_terminal`] rewrites. Kept as one predicate so the
/// borrowing fast path and the rewriting loop can never disagree about what
/// counts as safe to print.
fn needs_escape(ch: char) -> bool {
    is_display_control(ch) || is_bidi_control(ch)
}

/// C0 including tab, DEL, and C1. Every one of them is at most two hex digits
/// wide, which is what makes the `\xNN` rendering above unambiguous.
fn is_display_control(ch: char) -> bool {
    matches!(ch, '\u{00}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

/// The Unicode bidirectional formatting and override codes, and nothing else.
///
/// These are the codepoints whose entire effect is to reorder the characters
/// around them: the marks (U+061C, U+200E, U+200F), the embeddings and
/// overrides with their terminator (U+202A-U+202E) and the isolates with theirs
/// (U+2066-U+2069). Letters of right-to-left scripts are deliberately absent -
/// they are content, not instructions.
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
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

    /// The Trojan Source half of the forgery hole: a name that reads as one
    /// thing and is another. The escaped form must show where the override was.
    #[test]
    fn sanitize_escapes_every_bidi_control() {
        assert_eq!(
            sanitize_for_terminal("report\u{202e}sj.eruces"),
            "report\\u{202e}sj.eruces"
        );
        assert_eq!(
            sanitize_for_terminal("\u{61c}\u{200e}\u{200f}"),
            "\\u{061c}\\u{200e}\\u{200f}"
        );
        assert_eq!(
            sanitize_for_terminal("\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}"),
            "\\u{202a}\\u{202b}\\u{202c}\\u{202d}\\u{202e}"
        );
        assert_eq!(
            sanitize_for_terminal("\u{2066}\u{2067}\u{2068}\u{2069}"),
            "\\u{2066}\\u{2067}\\u{2068}\\u{2069}"
        );
        // Mixed with an escape sequence: each class keeps its own rendering.
        assert_eq!(
            sanitize_for_terminal("a\u{1b}[2Kb\u{202e}c"),
            "a\\x1b[2Kb\\u{202e}c"
        );
    }

    /// Right-to-left scripts are text. A repository whose paths and messages are
    /// written in Arabic or Hebrew has to stay readable, and none of these
    /// characters reorders anything on its own.
    #[test]
    fn sanitize_leaves_ordinary_text_alone() {
        for text in [
            "src/\u{645}\u{644}\u{641}\u{627}\u{62a}/\u{62a}\u{62c}\u{631}\u{628}\u{629}.rs",
            "\u{5e7}\u{5d5}\u{5d1}\u{5e5}/\u{5d1}\u{5d3}\u{5d9}\u{5e7}\u{5d4}.js",
            "\u{4e2d}\u{6587}/\u{30c6}\u{30b9}\u{30c8}.py",
            "e\u{301}te\u{301}/cafe\u{301}.rs",
            "\u{1f600}\u{1f469}\u{200d}\u{1f4bb}/ok.rs",
        ] {
            assert!(
                matches!(sanitize_for_terminal(text), Cow::Borrowed(_)),
                "{text:?} was rewritten"
            );
            assert_eq!(sanitize_for_terminal(text), text);
        }
    }

    #[test]
    fn no_bidi_control_survives_sanitizing() {
        let hostile: String = (0u32..0x2100).filter_map(char::from_u32).collect();
        let safe = sanitize_for_terminal(&hostile);
        assert!(!safe.chars().any(needs_escape), "{safe:?}");
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
