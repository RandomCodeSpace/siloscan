//! Size and duplication metrics.
//!
//! Three numbers are produced per file:
//!
//! * `lines` - non-blank physical lines. A line consisting only of whitespace is
//!   blank. Counted for every text file regardless of language.
//! * `code_lines` - non-blank lines that carry content outside of comments.
//!   Only produced for the tier-1 languages that `crate::lang` recognises;
//!   absent for anything else.
//! * `duplicated_lines` - distinct lines of the file covered by a reported
//!   duplicate block. Each line is counted once even when several blocks
//!   overlap it.
//!
//! The comment classifier is a deliberate heuristic, not a parser. It scans each
//! line for the language's line- and block-comment delimiters and has no notion
//! of string literals, escapes, raw strings, or nested block comments. A
//! delimiter appearing inside a string literal (`"/* "`, `"# "`) will therefore
//! be treated as a comment delimiter. Python docstrings and other
//! string-literal-as-documentation idioms count as code. This is accurate enough
//! for size reporting and cheap enough to run on every file; anything stricter
//! belongs in the AST engine.
//!
//! Duplication detection is language-agnostic: lines are trimmed, blank lines
//! are dropped, and a CPD-style rolling window of `min_lines` normalized lines
//! is grouped across the whole scanned set. Matches are extended to their
//! maximal common length and reported as longest non-overlapping blocks.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default rolling-window size for duplication detection.
pub const DEFAULT_MIN_LINES: usize = 10;

/// Reserved rule id used for the info-severity findings emitted per duplicate
/// block copy.
pub const DUPLICATE_BLOCK_RULE_ID: &str = "metrics.duplicate-block";

/// Per-file metrics. Keys of the enclosing map are scan-root-relative paths with
/// forward slashes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FileMetrics {
    /// Non-blank physical lines.
    pub lines: u64,
    /// Non-comment, non-blank lines. Absent for non-tier-1 languages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_lines: Option<u64>,
    /// Distinct lines covered by a reported duplicate block, counted once.
    pub duplicated_lines: u64,
}

/// Scan-wide rollups. The only rollups stored in the report.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MetricsTotals {
    pub lines: u64,
    /// Sum over files that have a `code_lines` value.
    pub code_lines: u64,
    pub duplicated_lines: u64,
    /// `duplicated_lines / lines * 100`, or `0.0` when `lines` is zero.
    pub duplication_density: f64,
}

/// The `metrics` block of the JSON report.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Metrics {
    /// `BTreeMap` so serialization order is byte-identical run to run.
    pub files: BTreeMap<String, FileMetrics>,
    pub totals: MetricsTotals,
}

/// One occurrence of a duplicate block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockCopy {
    /// Scan-root-relative path with forward slashes.
    pub path: String,
    /// 1-based line of the first duplicated line of this copy.
    pub start_line: u64,
    /// 1-based line of the last duplicated line of this copy.
    pub end_line: u64,
}

/// A group of identical blocks. Copies are sorted by `(path, start_line)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateBlock {
    /// First 12 hex characters of SHA-256 over the normalized block content.
    pub normalized_hash_hex12: String,
    pub copies: Vec<BlockCopy>,
    /// Number of normalized (non-blank) lines in the block.
    pub line_count: u64,
}

/// Result of a duplication pass over a scanned set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DuplicationResult {
    /// Sorted by `(normalized_hash_hex12, first copy path, first copy line)`.
    pub blocks: Vec<DuplicateBlock>,
    /// Path -> count of distinct duplicated lines in that file.
    pub duplicated_lines: BTreeMap<String, u64>,
}

/// Count non-blank physical lines.
pub fn count_lines(content: &str) -> u64 {
    content.lines().filter(|l| !l.trim().is_empty()).count() as u64
}

/// Count lines carrying content outside comments. Returns `None` when the
/// language is not tier-1 (or is unknown).
pub fn count_code_lines(content: &str, language: Option<&str>) -> Option<u64> {
    let syntax = comment_syntax(language?)?;
    let mut count: u64 = 0;
    let mut in_block = false;
    for line in content.lines() {
        if line_has_code(line, &syntax, &mut in_block) {
            count += 1;
        }
    }
    Some(count)
}

/// Convenience constructor for the per-file entry. `duplicated_lines` starts at
/// zero; the duplication pass fills it in afterwards.
pub fn measure_file(content: &str, language: Option<&str>) -> FileMetrics {
    FileMetrics {
        lines: count_lines(content),
        code_lines: count_code_lines(content, language),
        duplicated_lines: 0,
    }
}

/// Whether `code_lines` is produced for this language.
pub fn is_tier_one(language: &str) -> bool {
    comment_syntax(language).is_some()
}

/// Comment delimiters for one language.
struct CommentSyntax {
    /// Tokens that comment out the rest of the line.
    line: &'static [&'static str],
    /// Block open/close tokens, if the language has them.
    block: Option<(&'static str, &'static str)>,
    /// True when the block delimiters must start a line on their own, as with
    /// Ruby's `=begin` / `=end`.
    block_whole_line: bool,
}

/// The tier-1 language table. Language names match `crate::lang::detect`.
fn comment_syntax(language: &str) -> Option<CommentSyntax> {
    let c_style = CommentSyntax {
        line: &["//"],
        block: Some(("/*", "*/")),
        block_whole_line: false,
    };
    match language {
        "rust" | "javascript" | "typescript" | "go" | "java" | "c" | "cpp" | "csharp" => {
            Some(c_style)
        }
        "python" => Some(CommentSyntax {
            line: &["#"],
            block: None,
            block_whole_line: false,
        }),
        "ruby" => Some(CommentSyntax {
            line: &["#"],
            block: Some(("=begin", "=end")),
            block_whole_line: true,
        }),
        _ => None,
    }
}

/// Classify a single line, carrying block-comment state across lines.
fn line_has_code(line: &str, syntax: &CommentSyntax, in_block: &mut bool) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    if syntax.block_whole_line {
        let (open, close) = syntax.block.expect("whole-line blocks need delimiters");
        if *in_block {
            if trimmed.starts_with(close) {
                *in_block = false;
            }
            return false;
        }
        if trimmed.starts_with(open) {
            *in_block = true;
            return false;
        }
        return !starts_with_line_comment(trimmed, syntax);
    }

    let mut has_code = false;
    let mut i = 0usize;
    while i < line.len() {
        let rest = &line[i..];
        if *in_block {
            let (_, close) = syntax.block.expect("block state needs delimiters");
            match rest.find(close) {
                Some(at) => {
                    *in_block = false;
                    i += at + close.len();
                }
                None => break,
            }
            continue;
        }

        if syntax.line.iter().any(|token| rest.starts_with(*token)) {
            break;
        }

        if let Some((open, _)) = syntax.block
            && rest.starts_with(open)
        {
            *in_block = true;
            i += open.len();
            continue;
        }

        let ch = rest.chars().next().expect("non-empty remainder");
        if !ch.is_whitespace() {
            has_code = true;
        }
        i += ch.len_utf8();
    }

    has_code
}

fn starts_with_line_comment(trimmed: &str, syntax: &CommentSyntax) -> bool {
    syntax.line.iter().any(|t| trimmed.starts_with(*t))
}

/// Sum per-file metrics into the scan-wide rollup.
pub fn compute_totals(files: &BTreeMap<String, FileMetrics>) -> MetricsTotals {
    let mut totals = MetricsTotals::default();
    for metrics in files.values() {
        totals.lines += metrics.lines;
        totals.code_lines += metrics.code_lines.unwrap_or(0);
        totals.duplicated_lines += metrics.duplicated_lines;
    }
    totals.duplication_density = density(totals.duplicated_lines, totals.lines);
    totals
}

/// Duplication density as a percentage. Zero when there are no lines.
pub fn density(duplicated_lines: u64, lines: u64) -> f64 {
    if lines == 0 {
        return 0.0;
    }
    duplicated_lines as f64 / lines as f64 * 100.0
}

/// Detect duplicate blocks across `files`, which must be sorted by path.
///
/// Blank lines are dropped before matching, so a block's `start_line` and
/// `end_line` bracket the original span while blank lines inside it are not
/// counted as duplicated.
pub fn detect_duplication(files: &[(String, String)], min_lines: usize) -> DuplicationResult {
    let mut result = DuplicationResult::default();
    if min_lines == 0 {
        return result;
    }

    // Flatten every file into one sequence of normalized non-blank lines.
    let mut tok_file: Vec<usize> = Vec::new();
    let mut tok_line: Vec<u64> = Vec::new();
    let mut tok_norm: Vec<String> = Vec::new();
    for (index, (_, content)) in files.iter().enumerate() {
        for (offset, line) in content.lines().enumerate() {
            let normalized = line.trim();
            if normalized.is_empty() {
                continue;
            }
            tok_file.push(index);
            tok_line.push(offset as u64 + 1);
            tok_norm.push(normalized.to_string());
        }
    }

    let total = tok_norm.len();
    if total < min_lines {
        return result;
    }
    let last_start = total - min_lines;

    // One digest per normalized line, so window keys hash a fixed small input.
    let digests: Vec<[u8; 32]> = tok_norm
        .iter()
        .map(|line| Sha256::digest(line.as_bytes()).into())
        .collect();

    let same_file = |a: usize, b: usize| tok_file[a] == tok_file[b];
    let window_key = |start: usize| -> [u8; 32] {
        let mut hasher = Sha256::new();
        for digest in &digests[start..start + min_lines] {
            hasher.update(digest);
        }
        hasher.finalize().into()
    };

    let mut windows: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
    for start in 0..=last_start {
        if !same_file(start, start + min_lines - 1) {
            continue;
        }
        windows.entry(window_key(start)).or_default().push(start);
    }

    let mut consumed = vec![false; total];
    let mut blocks: Vec<DuplicateBlock> = Vec::new();
    let mut covered: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();

    for start in 0..=last_start {
        if consumed[start] || !same_file(start, start + min_lines - 1) {
            continue;
        }
        let Some(candidates) = windows.get(&window_key(start)) else {
            continue;
        };

        // Hash equality is verified against the actual lines; the digest only
        // narrows the candidate set.
        let group: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|&other| {
                other >= start
                    && !consumed[other..other + min_lines].iter().any(|c| *c)
                    && tok_norm[other..other + min_lines] == tok_norm[start..start + min_lines]
            })
            .collect();
        if group.len() < 2 {
            continue;
        }

        // Extend while every member agrees on the next line, stays inside its
        // own file, and does not run into an already reported block.
        let mut length = min_lines;
        loop {
            let next = start + length;
            if next >= total || !same_file(next, start) || consumed[next] {
                break;
            }
            let extends = group.iter().all(|&other| {
                let candidate = other + length;
                candidate < total
                    && same_file(candidate, other)
                    && !consumed[candidate]
                    && tok_norm[candidate] == tok_norm[next]
            });
            if !extends {
                break;
            }
            length += 1;
        }

        // Copies must not overlap each other; keep the earliest of any run.
        let mut chosen: Vec<usize> = Vec::new();
        for &other in &group {
            if let Some(&last) = chosen.last()
                && other < last + length
            {
                continue;
            }
            chosen.push(other);
        }
        if chosen.len() < 2 {
            continue;
        }

        let mut hasher = Sha256::new();
        for (index, line) in tok_norm[start..start + length].iter().enumerate() {
            if index > 0 {
                hasher.update(b"\n");
            }
            hasher.update(line.as_bytes());
        }
        let hash = hex(&hasher.finalize());

        let mut copies = Vec::with_capacity(chosen.len());
        for &other in &chosen {
            for index in other..other + length {
                consumed[index] = true;
                covered
                    .entry(tok_file[index])
                    .or_default()
                    .insert(tok_line[index]);
            }
            copies.push(BlockCopy {
                path: files[tok_file[other]].0.clone(),
                start_line: tok_line[other],
                end_line: tok_line[other + length - 1],
            });
        }
        copies.sort_by(|a, b| a.path.cmp(&b.path).then(a.start_line.cmp(&b.start_line)));

        blocks.push(DuplicateBlock {
            normalized_hash_hex12: hash[..12].to_string(),
            copies,
            line_count: length as u64,
        });
    }

    blocks.sort_by(|a, b| {
        a.normalized_hash_hex12
            .cmp(&b.normalized_hash_hex12)
            .then_with(|| a.copies[0].path.cmp(&b.copies[0].path))
            .then_with(|| a.copies[0].start_line.cmp(&b.copies[0].start_line))
    });

    result.blocks = blocks;
    result.duplicated_lines = covered
        .into_iter()
        .map(|(file, lines)| (files[file].0.clone(), lines.len() as u64))
        .collect();
    result
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, content: &str) -> (String, String) {
        (path.to_string(), content.to_string())
    }

    fn block(prefix: &str, count: usize) -> String {
        (0..count)
            .map(|i| format!("{prefix} statement {i};\n"))
            .collect()
    }

    #[test]
    fn count_lines_skips_blank_and_whitespace_only() {
        let content = "alpha\n\n   \n\t\nbeta\n";
        assert_eq!(count_lines(content), 2);
    }

    #[test]
    fn count_lines_counts_unterminated_last_line() {
        assert_eq!(count_lines("alpha\nbeta"), 2);
    }

    #[test]
    fn count_lines_of_empty_file_is_zero() {
        assert_eq!(count_lines(""), 0);
        assert_eq!(count_lines("\n\n\n"), 0);
    }

    #[test]
    fn code_lines_absent_for_unknown_language() {
        assert_eq!(count_code_lines("anything\n", None), None);
        assert_eq!(count_code_lines("anything\n", Some("shell")), None);
        assert_eq!(count_code_lines("anything\n", Some("cobol")), None);
    }

    #[test]
    fn code_lines_rust_line_comments() {
        let content = "\
// leading comment
fn main() {
    let x = 1; // trailing comment
    // indented comment

}
";
        assert_eq!(count_lines(content), 5);
        assert_eq!(count_code_lines(content, Some("rust")), Some(3));
    }

    #[test]
    fn code_lines_rust_block_comments() {
        let content = "\
/* block start
   still comment
   end of block */
fn main() {}
/* one-liner */ let y = 2;
let z = 3; /* trailing */
";
        assert_eq!(count_code_lines(content, Some("rust")), Some(3));
    }

    #[test]
    fn code_lines_rust_code_before_block_open() {
        let content = "let a = 1; /* comment\ncontinues */\n";
        assert_eq!(count_code_lines(content, Some("rust")), Some(1));
    }

    #[test]
    fn code_lines_python_hash_comments() {
        let content = "\
# module comment
import os

def main():  # trailing
    return os.getcwd()
    #
";
        assert_eq!(count_lines(content), 5);
        assert_eq!(count_code_lines(content, Some("python")), Some(3));
    }

    #[test]
    fn code_lines_python_has_no_block_comments() {
        // Docstrings are string literals, so the heuristic counts them as code.
        let content = "\"\"\"docstring\"\"\"\nvalue = 1\n";
        assert_eq!(count_code_lines(content, Some("python")), Some(2));
    }

    #[test]
    fn code_lines_ruby_begin_end_block() {
        let content = "\
=begin
documentation
=end
puts 'hi' # trailing
# whole line
";
        assert_eq!(count_lines(content), 5);
        assert_eq!(count_code_lines(content, Some("ruby")), Some(1));
    }

    #[test]
    fn code_lines_handles_non_ascii() {
        let content = "let s = \"caf\u{e9}\"; // \u{2713} done\n// \u{2713}\n";
        assert_eq!(count_code_lines(content, Some("rust")), Some(1));
    }

    #[test]
    fn tier_one_membership() {
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
        ] {
            assert!(is_tier_one(language), "{language} should be tier-1");
        }
        assert!(!is_tier_one("shell"));
    }

    #[test]
    fn measure_file_fills_lines_and_code_lines() {
        let metrics = measure_file("// c\nlet x = 1;\n\n", Some("rust"));
        assert_eq!(metrics.lines, 2);
        assert_eq!(metrics.code_lines, Some(1));
        assert_eq!(metrics.duplicated_lines, 0);
    }

    #[test]
    fn duplication_finds_shared_twelve_line_block() {
        let shared = block("shared", 12);
        let a = format!("unique a one;\nunique a two;\n{shared}");
        let b = format!("{shared}unique b one;\n");
        let files = vec![file("a.rs", &a), file("b.rs", &b)];

        let result = detect_duplication(&files, DEFAULT_MIN_LINES);
        assert_eq!(result.blocks.len(), 1);
        let found = &result.blocks[0];
        assert_eq!(found.line_count, 12);
        assert_eq!(found.normalized_hash_hex12.len(), 12);
        assert!(
            found
                .normalized_hash_hex12
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
        assert_eq!(
            found.copies,
            vec![
                BlockCopy {
                    path: "a.rs".to_string(),
                    start_line: 3,
                    end_line: 14,
                },
                BlockCopy {
                    path: "b.rs".to_string(),
                    start_line: 1,
                    end_line: 12,
                },
            ]
        );
        assert_eq!(result.duplicated_lines.get("a.rs"), Some(&12));
        assert_eq!(result.duplicated_lines.get("b.rs"), Some(&12));
    }

    #[test]
    fn duplication_ignores_indentation_and_blank_lines() {
        let mut a = String::new();
        let mut b = String::new();
        for i in 0..12 {
            a.push_str(&format!("call({i});\n"));
            b.push_str(&format!("        call({i});\n"));
            b.push('\n');
        }
        let files = vec![file("a.rs", &a), file("b.rs", &b)];

        let result = detect_duplication(&files, DEFAULT_MIN_LINES);
        assert_eq!(result.blocks.len(), 1);
        assert_eq!(result.blocks[0].line_count, 12);
        // Blank filler lines are not part of the block, so b spans 23 lines but
        // only 12 count as duplicated.
        assert_eq!(result.blocks[0].copies[1].start_line, 1);
        assert_eq!(result.blocks[0].copies[1].end_line, 23);
        assert_eq!(result.duplicated_lines.get("b.rs"), Some(&12));
    }

    #[test]
    fn duplication_respects_min_lines_threshold() {
        let shared = block("shared", 9);
        let a = format!("{shared}unique a;\n");
        let b = format!("{shared}unique b;\n");
        let files = vec![file("a.rs", &a), file("b.rs", &b)];

        assert!(
            detect_duplication(&files, DEFAULT_MIN_LINES)
                .blocks
                .is_empty()
        );
        let smaller = detect_duplication(&files, 9);
        assert_eq!(smaller.blocks.len(), 1);
        assert_eq!(smaller.blocks[0].line_count, 9);
    }

    #[test]
    fn duplication_extends_to_maximal_length() {
        let shared = block("shared", 25);
        let files = vec![
            file("a.rs", &format!("{shared}tail a;\n")),
            file("b.rs", &format!("{shared}tail b;\n")),
        ];

        let result = detect_duplication(&files, DEFAULT_MIN_LINES);
        assert_eq!(result.blocks.len(), 1);
        assert_eq!(result.blocks[0].line_count, 25);
        assert_eq!(result.duplicated_lines.get("a.rs"), Some(&25));
    }

    #[test]
    fn duplication_never_reports_overlapping_copies() {
        // Fifteen identical lines admit only one ten-line window without
        // overlap, so nothing is reported.
        let content: String = "same line;\n".repeat(15);
        let files = vec![file("a.rs", &content)];
        assert!(
            detect_duplication(&files, DEFAULT_MIN_LINES)
                .blocks
                .is_empty()
        );

        // Twenty identical lines fit two disjoint copies.
        let content: String = "same line;\n".repeat(20);
        let files = vec![file("a.rs", &content)];
        let result = detect_duplication(&files, DEFAULT_MIN_LINES);
        assert_eq!(result.blocks.len(), 1);
        assert_eq!(result.blocks[0].line_count, 10);
        assert_eq!(
            result.blocks[0].copies,
            vec![
                BlockCopy {
                    path: "a.rs".to_string(),
                    start_line: 1,
                    end_line: 10,
                },
                BlockCopy {
                    path: "a.rs".to_string(),
                    start_line: 11,
                    end_line: 20,
                },
            ]
        );
        assert_eq!(result.duplicated_lines.get("a.rs"), Some(&20));
    }

    #[test]
    fn duplication_counts_each_line_once_across_blocks() {
        // A line shared with two partners is still one duplicated line.
        let shared = block("shared", 12);
        let files = vec![
            file("a.rs", &shared),
            file("b.rs", &shared),
            file("c.rs", &shared),
        ];

        let result = detect_duplication(&files, DEFAULT_MIN_LINES);
        assert_eq!(result.blocks.len(), 1);
        assert_eq!(result.blocks[0].copies.len(), 3);
        for path in ["a.rs", "b.rs", "c.rs"] {
            assert_eq!(result.duplicated_lines.get(path), Some(&12));
        }
    }

    #[test]
    fn duplication_does_not_match_across_file_boundaries() {
        // Six lines at the end of a and six at the start of b would form a
        // twelve-line window if the files were concatenated.
        let tail = block("shared", 6);
        let files = vec![
            file("a.rs", &format!("unique a;\n{tail}")),
            file("b.rs", &format!("{tail}unique b;\n")),
        ];
        assert!(
            detect_duplication(&files, DEFAULT_MIN_LINES)
                .blocks
                .is_empty()
        );
    }

    #[test]
    fn duplication_is_deterministic_and_sorted() {
        let first = block("alpha", 11);
        let second = block("beta", 11);
        let files = vec![
            file("a.rs", &format!("{first}{second}")),
            file("b.rs", &format!("{second}{first}")),
        ];

        let result = detect_duplication(&files, DEFAULT_MIN_LINES);
        assert_eq!(result.blocks.len(), 2);
        let hashes: Vec<&str> = result
            .blocks
            .iter()
            .map(|b| b.normalized_hash_hex12.as_str())
            .collect();
        let mut sorted = hashes.clone();
        sorted.sort_unstable();
        assert_eq!(hashes, sorted);
        for found in &result.blocks {
            assert_eq!(found.copies.len(), 2);
            assert_eq!(found.copies[0].path, "a.rs");
            assert_eq!(found.copies[1].path, "b.rs");
        }
        assert_eq!(detect_duplication(&files, DEFAULT_MIN_LINES), result);
    }

    #[test]
    fn duplication_empty_and_degenerate_inputs() {
        assert_eq!(
            detect_duplication(&[], DEFAULT_MIN_LINES),
            DuplicationResult::default()
        );
        let files = vec![file("a.rs", "one;\ntwo;\n")];
        assert_eq!(
            detect_duplication(&files, DEFAULT_MIN_LINES),
            DuplicationResult::default()
        );
        let content: String = "same;\n".repeat(40);
        assert_eq!(
            detect_duplication(&[file("a.rs", &content)], 0),
            DuplicationResult::default()
        );
    }

    #[test]
    fn totals_sum_and_density() {
        let mut files = BTreeMap::new();
        files.insert(
            "a.rs".to_string(),
            FileMetrics {
                lines: 100,
                code_lines: Some(80),
                duplicated_lines: 20,
            },
        );
        files.insert(
            "b.txt".to_string(),
            FileMetrics {
                lines: 100,
                code_lines: None,
                duplicated_lines: 5,
            },
        );

        let totals = compute_totals(&files);
        assert_eq!(totals.lines, 200);
        assert_eq!(totals.code_lines, 80);
        assert_eq!(totals.duplicated_lines, 25);
        assert!((totals.duplication_density - 12.5).abs() < 1e-9);
    }

    #[test]
    fn totals_of_empty_set_have_zero_density() {
        let totals = compute_totals(&BTreeMap::new());
        assert_eq!(totals.lines, 0);
        assert_eq!(totals.duplication_density, 0.0);
    }

    #[test]
    fn density_helper_handles_zero_lines() {
        assert_eq!(density(0, 0), 0.0);
        assert_eq!(density(5, 0), 0.0);
        assert!((density(1, 3) - 33.333_333_333_333_336).abs() < 1e-9);
    }

    #[test]
    fn code_lines_omitted_from_json_when_absent() {
        let metrics = FileMetrics {
            lines: 3,
            code_lines: None,
            duplicated_lines: 0,
        };
        let json = serde_json::to_string(&metrics).expect("serialize");
        assert!(!json.contains("code_lines"), "{json}");

        let metrics = FileMetrics {
            lines: 3,
            code_lines: Some(2),
            duplicated_lines: 0,
        };
        let json = serde_json::to_string(&metrics).expect("serialize");
        assert!(json.contains("\"code_lines\":2"), "{json}");
    }

    #[test]
    fn metrics_serialize_in_path_order() {
        let mut metrics = Metrics::default();
        for path in ["z.rs", "a.rs", "m.rs"] {
            metrics.files.insert(
                path.to_string(),
                FileMetrics {
                    lines: 1,
                    code_lines: Some(1),
                    duplicated_lines: 0,
                },
            );
        }
        metrics.totals = compute_totals(&metrics.files);
        let json = serde_json::to_string(&metrics).expect("serialize");
        let a = json.find("a.rs").expect("a");
        let m = json.find("m.rs").expect("m");
        let z = json.find("z.rs").expect("z");
        assert!(a < m && m < z);
    }
}
