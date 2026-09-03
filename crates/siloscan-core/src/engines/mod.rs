pub mod regex;
pub mod secret;

use std::collections::HashMap;

use crate::rules::CompiledRule;

/// Envelope gating shared by every engine: language, then path include, then
/// path exclude.
pub(crate) fn applies(rule: &CompiledRule, path_rel: &str, language: Option<&str>) -> bool {
    if let Some(languages) = &rule.languages {
        match language {
            Some(lang) => {
                if !languages.iter().any(|l| l == lang) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(include) = &rule.include
        && !include.is_match(path_rel)
    {
        return false;
    }

    if let Some(exclude) = &rule.exclude
        && exclude.is_match(path_rel)
    {
        return false;
    }

    true
}

/// The reported span for a match: the configured capture group if set, else the
/// whole match. `None` means the group did not participate.
pub(crate) fn capture_span<'t>(
    caps: &::regex::Captures<'t>,
    group: Option<usize>,
) -> Option<::regex::Match<'t>> {
    match group {
        Some(index) => caps.get(index),
        None => caps.get(0),
    }
}

/// Per-file occurrence counter keyed by rule id and whitespace-normalized match
/// text; feeds the occurrence index of a finding's fingerprint.
pub(crate) struct Occurrences<'a> {
    counts: HashMap<(&'a str, String), u32>,
}

impl<'a> Occurrences<'a> {
    pub(crate) fn new() -> Self {
        Occurrences {
            counts: HashMap::new(),
        }
    }

    pub(crate) fn next(&mut self, rule_id: &'a str, matched: &str) -> u32 {
        let normalized = matched.split_whitespace().collect::<Vec<&str>>().join(" ");
        let counter = self.counts.entry((rule_id, normalized)).or_insert(0);
        let occurrence = *counter;
        *counter += 1;
        occurrence
    }
}

/// Line-start byte offsets, built at most once per file and only when the file
/// produces at least one match.
pub(crate) struct LineIndex<'a> {
    content: &'a str,
    starts: Option<Vec<usize>>,
}

impl<'a> LineIndex<'a> {
    pub(crate) fn new(content: &'a str) -> Self {
        LineIndex {
            content,
            starts: None,
        }
    }

    /// Returns the 1-based line, byte column and UTF-16 column of `offset`.
    pub(crate) fn position(&mut self, offset: usize) -> Position {
        let content = self.content;
        let starts = self.starts.get_or_insert_with(|| line_starts(content));
        // `starts` always begins with 0, so the partition point is at least 1.
        let index = starts.partition_point(|&start| start <= offset) - 1;
        let line_start = starts[index];
        Position {
            line: (index as u64) + 1,
            column: (offset - line_start) as u64 + 1,
            column_utf16: utf16_column(&content[line_start..offset]),
        }
    }
}

/// Where a match starts, in the two ways a report has to spell it.
///
/// Both columns are 1-based and both are measured within the line, so they are
/// equal whenever `prefix` is ASCII and differ only on lines carrying
/// multi-byte text before the match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Position {
    pub(crate) line: u64,
    /// 1-based byte offset within the line, for the JSON report.
    pub(crate) column: u64,
    /// 1-based UTF-16 code unit offset within the line, for SARIF.
    pub(crate) column_utf16: u64,
}

/// The 1-based UTF-16 column that follows `prefix`, the text between the start
/// of a line and a match on it.
///
/// Counting code units rather than characters is the point: SARIF inherits
/// UTF-16 indexing, so an astral character is two units even though it is one
/// `char`. An empty prefix is column 1, which is why the count is offset by
/// one and why the result can never be zero.
pub(crate) fn utf16_column(prefix: &str) -> u64 {
    prefix.encode_utf16().count() as u64 + 1
}

fn line_starts(content: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(16);
    starts.push(0);
    starts.extend(content.match_indices('\n').map(|(i, _)| i + 1));
    starts
}
pub mod ast;
pub mod boundary;
pub mod duplication;
pub mod metric;
