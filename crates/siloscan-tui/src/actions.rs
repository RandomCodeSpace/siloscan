//! The only two writes the TUI performs: accepting a finding into the baseline
//! and inserting an inline ignore marker into a source file. Both are explicit
//! user verdicts from the ratchet console.
//!
//! Everything here is plain state plus filesystem work, so it is unit-testable
//! without a terminal.

use std::fs;
use std::io;
use std::path::Path;

use siloscan_core::baseline::{self, Baseline, BaselineEntry};
use siloscan_core::findings::Finding;
use siloscan_core::lang;
use siloscan_core::serde_json;

use crate::state::{AppState, Status};

/// Baseline schema version this build writes. Matches `siloscan_core::baseline`.
const BASELINE_VERSION: u32 = 1;

/// Marker understood by `siloscan_core::suppress` for its own line. It is only
/// valid inside a comment: the scanner matches by substring, but the compiler
/// does not, so the marker is always written behind a language-appropriate
/// comment prefix.
const IGNORE_LINE_MARKER: &str = "siloscan-ignore-line:";

/// Line-comment prefix for each language `siloscan_core::lang::detect`
/// recognizes. `None` means the file type is unknown and no suppression may be
/// written into it.
pub fn comment_prefix(language: &str) -> Option<&'static str> {
    match language {
        "rust" | "javascript" | "typescript" | "go" | "java" | "c" | "cpp" | "csharp" => Some("//"),
        "python" | "ruby" | "shell" => Some("#"),
        _ => None,
    }
}

/// Accept the row into the baseline: mark it in memory, queue it, and persist
/// the merged baseline file immediately. A write failure is reported in the
/// status line and leaves the in-memory state accepted, so the next accept
/// retries the whole queue.
pub fn accept_baseline(state: &mut AppState, row_idx: usize) {
    let Some(row) = state.rows.get_mut(row_idx) else {
        return;
    };
    if row.status != Status::Baselined {
        row.status = Status::Baselined;
        let finding = row.finding.clone();
        state.dirty_baseline.push(finding);
    }
    state.clamp_ratchet();
    state.clamp_selection();

    if let Err(e) = persist_baseline(&state.root, &state.dirty_baseline) {
        state.status = format!("baseline: {e}");
    }
}

/// Merge the queued findings into the baseline on disk. Prior entries are
/// preserved; the result is deduped by fingerprint and ordered exactly as
/// `baseline::save` orders it, so the file stays byte-stable.
pub fn persist_baseline(root: &Path, dirty: &[Finding]) -> Result<usize, String> {
    let mut entries: Vec<BaselineEntry> = baseline::load(root)?
        .map(|baseline| baseline.entries)
        .unwrap_or_default();
    entries.extend(dirty.iter().map(entry));

    entries.sort_by(|a, b| {
        a.fingerprint
            .as_bytes()
            .cmp(b.fingerprint.as_bytes())
            .then(a.path.as_bytes().cmp(b.path.as_bytes()))
            .then(a.rule_id.as_bytes().cmp(b.rule_id.as_bytes()))
    });
    entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);

    let count = entries.len();
    let baseline = Baseline {
        version: BASELINE_VERSION,
        entries,
    };

    let path = root.join(baseline::BASELINE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: io error: {e}", parent.display()))?;
    }

    let mut json = serde_json::to_string_pretty(&baseline)
        .map_err(|e| format!("{}: serialization failed: {e}", path.display()))?;
    json.push('\n');
    fs::write(&path, json).map_err(|e| format!("{}: io error: {e}", path.display()))?;

    Ok(count)
}

fn entry(finding: &Finding) -> BaselineEntry {
    BaselineEntry {
        fingerprint: finding.fingerprint.clone(),
        rule_id: finding.rule_id.clone(),
        path: finding.path.clone(),
    }
}

/// Append an inline ignore comment to the finding's own line in the source file
/// and mark the row suppressed in memory. The file is rewritten only when the
/// line actually changes, and not at all when the language is unknown: writing
/// a bare marker would corrupt the source.
pub fn insert_suppression(state: &mut AppState, row_idx: usize) -> io::Result<()> {
    let Some(row) = state.rows.get(row_idx) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no finding at index {row_idx}"),
        ));
    };
    let finding = row.finding.clone();

    let path = state.root.join(&finding.path);
    let content = fs::read_to_string(&path)?;
    let comment = lang::detect(&path, &content)
        .and_then(comment_prefix)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: unknown file type, no comment syntax", finding.path),
            )
        })?;
    let edited =
        insert_marker(&content, finding.line, &finding.rule_id, comment).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: no line {}", finding.path, finding.line),
            )
        })?;
    if edited != content {
        fs::write(&path, edited)?;
    }

    state.rows[row_idx].status = Status::Suppressed;
    state.clamp_ratchet();
    state.clamp_selection();
    Ok(())
}

/// Append `  <comment> siloscan-ignore-line: <rule_id>` to the end of 1-based
/// `line`, where `comment` is the language's line-comment prefix. Returns
/// `None` when the line does not exist, and the input unchanged when the marker
/// is already there. Line terminators are copied verbatim, so the file's
/// newline style and trailing-newline presence survive.
pub fn insert_marker(content: &str, line: u64, rule_id: &str, comment: &str) -> Option<String> {
    if line == 0 {
        return None;
    }
    let target = (line - 1) as usize;
    let marker = format!("{comment} {IGNORE_LINE_MARKER} {rule_id}");

    let mut out = String::with_capacity(content.len() + marker.len() + 2);
    let mut found = false;
    for (index, segment) in content.split_inclusive('\n').enumerate() {
        if index != target {
            out.push_str(segment);
            continue;
        }

        found = true;
        let (body, terminator) = split_terminator(segment);
        out.push_str(body);
        if !suppresses(body, rule_id) {
            out.push_str("  ");
            out.push_str(&marker);
        }
        out.push_str(terminator);
    }

    found.then_some(out)
}

/// Split a line into its text and its terminator (`""`, `"\n"` or `"\r\n"`).
fn split_terminator(segment: &str) -> (&str, &str) {
    match segment.strip_suffix('\n') {
        Some(body) => {
            let body = body.strip_suffix('\r').unwrap_or(body);
            (body, &segment[body.len()..])
        }
        None => (segment, ""),
    }
}

/// True when the line already carries a same-line marker for this rule.
fn suppresses(body: &str, rule_id: &str) -> bool {
    body.match_indices(IGNORE_LINE_MARKER).any(|(offset, _)| {
        body[offset + IGNORE_LINE_MARKER.len()..]
            .split(',')
            .any(|token| token.split_whitespace().next() == Some(rule_id))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use siloscan_core::rules::{RuleSet, Severity};
    use siloscan_core::suppress;

    use crate::state::FindingRow;

    fn finding(rule_id: &str, path: &str, line: u64, fingerprint: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Warning,
            message: "hardcoded secret".to_string(),
            path: path.to_string(),
            line,
            column: 9,
            matched: "needle".to_string(),
            fingerprint: fingerprint.to_string(),
        }
    }

    fn state(root: &Path, rows: Vec<FindingRow>) -> AppState {
        let mut state = AppState::new(
            root.to_path_buf(),
            Arc::new(RuleSet { rules: Vec::new() }),
            None,
        );
        state.rows = rows;
        state
    }

    fn row(finding: Finding, status: Status) -> FindingRow {
        FindingRow { finding, status }
    }

    #[test]
    fn accept_baseline_writes_a_loadable_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(
            dir.path(),
            vec![row(finding("a.one", "src/a.rs", 1, "aa"), Status::New)],
        );

        accept_baseline(&mut state, 0);

        assert_eq!(state.rows[0].status, Status::Baselined);
        assert_eq!(state.dirty_baseline.len(), 1);
        assert!(state.status.is_empty());

        let baseline = baseline::load(dir.path()).unwrap().unwrap();
        assert_eq!(baseline.version, 1);
        assert_eq!(
            baseline.entries,
            vec![BaselineEntry {
                fingerprint: "aa".to_string(),
                rule_id: "a.one".to_string(),
                path: "src/a.rs".to_string(),
            }]
        );
    }

    #[test]
    fn accept_baseline_keeps_prior_entries_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        baseline::save(
            dir.path(),
            &[
                finding("old.rule", "src/old.rs", 3, "bb"),
                finding("a.one", "src/a.rs", 1, "aa"),
            ],
        )
        .unwrap();

        let mut state = state(
            dir.path(),
            vec![
                // Already in the file: must not be duplicated.
                row(finding("a.one", "src/a.rs", 1, "aa"), Status::New),
                row(finding("c.two", "src/c.rs", 7, "cc"), Status::New),
            ],
        );

        accept_baseline(&mut state, 0);
        accept_baseline(&mut state, 1);

        let baseline = baseline::load(dir.path()).unwrap().unwrap();
        let fingerprints: Vec<&str> = baseline
            .entries
            .iter()
            .map(|e| e.fingerprint.as_str())
            .collect();
        assert_eq!(fingerprints, vec!["aa", "bb", "cc"]);
    }

    #[test]
    fn accept_baseline_is_idempotent_for_the_same_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(
            dir.path(),
            vec![row(finding("a.one", "src/a.rs", 1, "aa"), Status::New)],
        );

        accept_baseline(&mut state, 0);
        accept_baseline(&mut state, 0);

        assert_eq!(state.dirty_baseline.len(), 1);
        assert_eq!(
            baseline::load(dir.path()).unwrap().unwrap().entries.len(),
            1
        );
    }

    #[test]
    fn accept_baseline_ignores_an_out_of_range_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(dir.path(), Vec::new());

        accept_baseline(&mut state, 3);

        assert!(state.dirty_baseline.is_empty());
        // Nothing was accepted, so nothing was written.
        assert!(baseline::load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn accept_baseline_reports_a_damaged_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(baseline::BASELINE_PATH);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"{ not json").unwrap();

        let mut state = state(
            dir.path(),
            vec![row(finding("a.one", "src/a.rs", 1, "aa"), Status::New)],
        );
        accept_baseline(&mut state, 0);

        assert!(state.status.starts_with("baseline:"));
        // The verdict stands in memory and stays queued for the next write.
        assert_eq!(state.rows[0].status, Status::Baselined);
        assert_eq!(state.dirty_baseline.len(), 1);
    }

    #[test]
    fn insert_suppression_edits_only_the_finding_line() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        let file = dir.path().join("src/a.rs");
        fs::write(&file, "let a = 1;\nlet needle = 2;\nlet c = 3;\n").unwrap();

        let mut state = state(
            dir.path(),
            vec![row(
                finding("test.needle", "src/a.rs", 2, "aa"),
                Status::New,
            )],
        );

        insert_suppression(&mut state, 0).unwrap();

        let edited = fs::read_to_string(&file).unwrap();
        assert_eq!(
            edited,
            "let a = 1;\nlet needle = 2;  // siloscan-ignore-line: test.needle\nlet c = 3;\n"
        );
        assert_eq!(state.rows[0].status, Status::Suppressed);
    }

    #[test]
    fn insert_suppression_uses_the_language_comment_syntax() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        let file = dir.path().join("src/a.py");
        fs::write(&file, "x = 1\nneedle = 2\n").unwrap();

        let mut state = state(
            dir.path(),
            vec![row(
                finding("test.needle", "src/a.py", 2, "aa"),
                Status::New,
            )],
        );

        insert_suppression(&mut state, 0).unwrap();

        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "x = 1\nneedle = 2  # siloscan-ignore-line: test.needle\n"
        );
    }

    #[test]
    fn insert_suppression_refuses_an_unknown_file_type() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        let file = dir.path().join("src/a.xyz");
        fs::write(&file, "needle\n").unwrap();

        let mut state = state(
            dir.path(),
            vec![row(
                finding("test.needle", "src/a.xyz", 1, "aa"),
                Status::New,
            )],
        );

        let err = insert_suppression(&mut state, 0).unwrap_err();

        assert!(err.to_string().contains("unknown file type"));
        // The file is untouched and the verdict did not stick.
        assert_eq!(fs::read_to_string(&file).unwrap(), "needle\n");
        assert_eq!(state.rows[0].status, Status::New);
    }

    #[test]
    fn inserted_marker_suppresses_on_a_rescan() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        let file = dir.path().join("src/a.rs");
        fs::write(&file, "let a = 1;\nlet needle = 2;\n").unwrap();

        let f = finding("test.needle", "src/a.rs", 2, "aa");
        let mut state = state(dir.path(), vec![row(f.clone(), Status::New)]);
        insert_suppression(&mut state, 0).unwrap();

        let edited = fs::read_to_string(&file).unwrap();
        let (kept, suppressed) = suppress::partition(&edited, vec![f]);

        assert!(kept.is_empty());
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].rule_id, "test.needle");
    }

    #[test]
    fn insert_suppression_rejects_a_missing_row_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(
            dir.path(),
            vec![row(finding("a.one", "src/gone.rs", 1, "aa"), Status::New)],
        );

        assert!(insert_suppression(&mut state, 9).is_err());
        assert!(insert_suppression(&mut state, 0).is_err());
        assert_eq!(state.rows[0].status, Status::New);
    }

    #[test]
    fn insert_marker_preserves_crlf_and_the_missing_trailing_newline() {
        let crlf = insert_marker("a\r\nneedle\r\nc\r\n", 2, "r.id", "//").unwrap();
        assert_eq!(crlf, "a\r\nneedle  // siloscan-ignore-line: r.id\r\nc\r\n");

        let bare = insert_marker("a\nneedle", 2, "r.id", "//").unwrap();
        assert_eq!(bare, "a\nneedle  // siloscan-ignore-line: r.id");

        let mixed = insert_marker("a\r\nneedle\nc", 3, "r.id", "#").unwrap();
        assert_eq!(mixed, "a\r\nneedle\nc  # siloscan-ignore-line: r.id");
    }

    #[test]
    fn insert_marker_rejects_lines_outside_the_file() {
        assert!(insert_marker("a\nb\n", 0, "r.id", "//").is_none());
        assert!(insert_marker("a\nb\n", 3, "r.id", "//").is_none());
        assert!(insert_marker("", 1, "r.id", "//").is_none());
    }

    #[test]
    fn insert_marker_does_not_duplicate_an_existing_marker() {
        let once = insert_marker("needle\n", 1, "r.id", "//").unwrap();
        let twice = insert_marker(&once, 1, "r.id", "//").unwrap();
        assert_eq!(once, twice);

        // A marker for a different rule is not the same marker; the second one
        // lands inside the comment the first one opened.
        let other = insert_marker(&once, 1, "other.id", "//").unwrap();
        assert_eq!(
            other,
            "needle  // siloscan-ignore-line: r.id  // siloscan-ignore-line: other.id\n"
        );
    }

    #[test]
    fn every_detectable_language_has_a_comment_prefix() {
        for language in [
            "rust",
            "python",
            "javascript",
            "typescript",
            "go",
            "java",
            "c",
            "cpp",
            "csharp",
            "ruby",
            "shell",
        ] {
            assert!(comment_prefix(language).is_some(), "{language}");
        }
        assert_eq!(comment_prefix("klingon"), None);
    }
}
