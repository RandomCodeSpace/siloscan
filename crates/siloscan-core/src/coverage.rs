//! Coverage report parsing and the coverage engine.
//!
//! Siloscan never runs tests. It reads a report produced by someone else, maps
//! the paths inside it onto the scanned tree, and reports files whose line
//! coverage is below a rule's threshold. A file with no coverage data is not a
//! violation: absence of data is not evidence of an uncovered file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::engines::applies;
use crate::findings::{Finding, fingerprint};
use crate::rules::{CompiledPayload, CompiledRule};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileCoverage {
    pub lines_total: u64,
    pub lines_covered: u64,
}

impl FileCoverage {
    /// Percentage of covered lines. A file with no instrumented lines counts as
    /// fully covered, so an empty or generated file never trips a threshold.
    pub fn percent(&self) -> f64 {
        if self.lines_total == 0 {
            return 100.0;
        }
        (self.lines_covered as f64 / self.lines_total as f64) * 100.0
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageReport {
    /// Path as written in the report, normalized to forward slashes.
    pub files: BTreeMap<String, FileCoverage>,
    /// Where the report was read from, for errors that have to name it. Empty
    /// for a report a caller built rather than parsed.
    pub source: String,
}

impl CoverageReport {
    /// How to refer to this report in a message.
    fn describe(&self) -> &str {
        if self.source.is_empty() {
            "the supplied coverage report"
        } else {
            &self.source
        }
    }
}

/// Parse a coverage report, detecting its format from the content: lcov when an
/// `SF:` line is present, cobertura when the document is XML rooted at
/// `<coverage>`.
pub fn parse(path: &Path) -> Result<CoverageReport, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let source = path.display().to_string();

    if src.lines().any(|line| line.trim_start().starts_with("SF:")) {
        return Ok(CoverageReport {
            source,
            ..parse_lcov(&src)
        });
    }

    if let Ok(doc) = roxmltree::Document::parse(&src)
        && doc.root_element().has_tag_name("coverage")
    {
        return Ok(CoverageReport {
            source,
            ..parse_cobertura(&doc)
        });
    }

    Err(format!(
        "{}: unrecognized coverage format (expected lcov or cobertura)",
        path.display()
    ))
}

/// Per-file accumulator. `hits` is keyed by line number so repeated records for
/// the same file union rather than double count; `lines_found` / `lines_hit`
/// hold the LF/LH summary when the producer emitted one.
#[derive(Default)]
struct Accumulator {
    hits: BTreeMap<u64, u64>,
    lines_found: Option<u64>,
    lines_hit: Option<u64>,
}

impl Accumulator {
    fn finish(&self) -> FileCoverage {
        let counted_total = self.hits.len() as u64;
        let counted_covered = self.hits.values().filter(|&&hits| hits > 0).count() as u64;
        match self.lines_found {
            Some(total) => FileCoverage {
                lines_total: total,
                lines_covered: self.lines_hit.unwrap_or(counted_covered).min(total),
            },
            None => FileCoverage {
                lines_total: counted_total,
                lines_covered: counted_covered,
            },
        }
    }
}

fn finish(files: BTreeMap<String, Accumulator>) -> CoverageReport {
    CoverageReport {
        files: files
            .into_iter()
            .map(|(path, acc)| (path, acc.finish()))
            .collect(),
        source: String::new(),
    }
}

/// lcov tracefile: `SF:` opens a record, `DA:`/`LF:`/`LH:` populate it and
/// `end_of_record` closes it. LF/LH win over the DA tally when present, since a
/// producer may report lines it emitted no DA entry for.
fn parse_lcov(src: &str) -> CoverageReport {
    let mut files: BTreeMap<String, Accumulator> = BTreeMap::new();
    let mut current: Option<String> = None;

    for line in src.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("SF:") {
            let path = normalize(rest.trim());
            if path.is_empty() {
                current = None;
                continue;
            }
            files.entry(path.clone()).or_default();
            current = Some(path);
            continue;
        }
        if line == "end_of_record" {
            current = None;
            continue;
        }

        let Some(path) = current.as_deref() else {
            continue;
        };
        let Some(acc) = files.get_mut(path) else {
            continue;
        };

        if let Some(rest) = line.strip_prefix("DA:") {
            let mut parts = rest.split(',');
            let (Some(number), Some(count)) = (parts.next(), parts.next()) else {
                continue;
            };
            let (Ok(number), Ok(count)) =
                (number.trim().parse::<u64>(), count.trim().parse::<u64>())
            else {
                continue;
            };
            let entry = acc.hits.entry(number).or_insert(0);
            *entry = (*entry).max(count);
        } else if let Some(rest) = line.strip_prefix("LF:") {
            if let Ok(value) = rest.trim().parse::<u64>() {
                acc.lines_found = Some(acc.lines_found.unwrap_or(0).max(value));
            }
        } else if let Some(rest) = line.strip_prefix("LH:")
            && let Ok(value) = rest.trim().parse::<u64>()
        {
            acc.lines_hit = Some(acc.lines_hit.unwrap_or(0).max(value));
        }
    }

    finish(files)
}

/// Cobertura XML: every `<class filename="...">` contributes its direct
/// `<lines><line number hits>` children. Method-level `<lines>` are ignored
/// because they repeat the class lines, and several classes may share one
/// filename, so lines are unioned per file.
fn parse_cobertura(doc: &roxmltree::Document<'_>) -> CoverageReport {
    let mut files: BTreeMap<String, Accumulator> = BTreeMap::new();

    for class in doc
        .descendants()
        .filter(|node| node.is_element() && node.has_tag_name("class"))
    {
        let Some(filename) = class.attribute("filename") else {
            continue;
        };
        let filename = normalize(filename.trim());
        if filename.is_empty() {
            continue;
        }
        let acc = files.entry(filename).or_default();

        for lines in class
            .children()
            .filter(|node| node.is_element() && node.has_tag_name("lines"))
        {
            for line in lines
                .children()
                .filter(|node| node.is_element() && node.has_tag_name("line"))
            {
                let Some(Ok(number)) = line.attribute("number").map(str::parse::<u64>) else {
                    continue;
                };
                let hits = line
                    .attribute("hits")
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                let entry = acc.hits.entry(number).or_insert(0);
                *entry = (*entry).max(hits);
            }
        }
    }

    finish(files)
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

/// True when `path` ends with `tail` on a path-segment boundary.
fn has_suffix(path: &str, tail: &str) -> bool {
    if path == tail {
        return true;
    }
    if tail.is_empty() || path.len() <= tail.len() {
        return false;
    }
    path.ends_with(tail) && path.as_bytes()[path.len() - tail.len() - 1] == b'/'
}

/// Map report paths onto repo-relative scanned paths. Exact matches win; the
/// rest resolve only when exactly one scanned path is a segment-aligned suffix
/// of the report path (or the other way round, for reports written relative to
/// a source root). Anything ambiguous in either direction is dropped rather
/// than guessed.
pub fn resolve(report: &CoverageReport, scan_paths: &[String]) -> BTreeMap<String, FileCoverage> {
    let scanned: BTreeSet<&str> = scan_paths.iter().map(String::as_str).collect();
    let mut resolved: BTreeMap<String, FileCoverage> = BTreeMap::new();
    let mut pending: Vec<(&str, FileCoverage)> = Vec::new();

    for (path, coverage) in &report.files {
        match scanned.get(path.as_str()) {
            Some(exact) => {
                resolved.insert((*exact).to_string(), *coverage);
            }
            None => pending.push((path.as_str(), *coverage)),
        }
    }

    // Report path -> its single candidate, when it has one.
    let mut proposals: BTreeMap<&str, Vec<FileCoverage>> = BTreeMap::new();
    for (path, coverage) in pending {
        let mut candidates = scanned
            .iter()
            .copied()
            .filter(|scanned| {
                !resolved.contains_key(*scanned)
                    && (has_suffix(path, scanned) || has_suffix(scanned, path))
            })
            .take(2);
        let (Some(candidate), None) = (candidates.next(), candidates.next()) else {
            continue;
        };
        proposals.entry(candidate).or_default().push(coverage);
    }

    // A scanned path claimed by several report entries is ambiguous too.
    for (path, mut claims) in proposals {
        if claims.len() == 1 {
            resolved.insert(path.to_string(), claims.pop().expect("one claim"));
        }
    }

    resolved
}

/// Refuse a run that loaded a coverage rule with no coverage report to
/// evaluate it against, naming the rule.
///
/// Without a report a coverage rule cannot measure anything, so it reports
/// nothing and the run exits clean - a gate that never fails is
/// indistinguishable from a gate that passes. A rule that cannot be evaluated
/// is a setup error, the same way a boundary rule loaded without configured
/// silos is, and it is refused on the same exit-2 path rather than counted as a
/// pass.
pub fn require_report(
    rules: &[CompiledRule],
    report: Option<&CoverageReport>,
) -> Result<(), String> {
    if report.is_some() {
        return Ok(());
    }
    let Some(rule) = first_coverage_rule(rules) else {
        return Ok(());
    };
    Err(format!(
        "rule {}: coverage rules need a coverage report (--coverage-report)",
        rule.id
    ))
}

/// Refuse a run whose coverage report resolves onto none of the scanned files,
/// naming the rule and the report.
///
/// [`require_report`] establishes that a report was passed; this establishes
/// that it is a report of *this* tree. One written from another checkout, with
/// a path prefix [`resolve`] cannot reconcile, or simply stale, produces an
/// empty mapping - and an empty mapping is a coverage rule that measures
/// nothing, reports nothing, and exits clean. That is the missing-report hole
/// with a file in the way of seeing it, so it is refused on the same exit-2
/// path.
///
/// Only a mapping that is empty *entirely* is refused. A report that covers
/// some scanned files and not others is the normal case - files with no
/// coverage data are not violations, by design - and nothing here interferes
/// with it.
pub fn require_resolved(
    rules: &[CompiledRule],
    report: &CoverageReport,
    resolved: &BTreeMap<String, FileCoverage>,
) -> Result<(), String> {
    if !resolved.is_empty() {
        return Ok(());
    }
    let Some(rule) = first_coverage_rule(rules) else {
        return Ok(());
    };
    Err(format!(
        "rule {}: coverage report {} matches none of the scanned files (wrong path prefix, or a \
         report of another tree)",
        rule.id,
        report.describe()
    ))
}

/// The first coverage rule in the set, which is the one an error names.
fn first_coverage_rule(rules: &[CompiledRule]) -> Option<&CompiledRule> {
    rules
        .iter()
        .find(|rule| matches!(rule.payload, CompiledPayload::Coverage { .. }))
}

/// Run every coverage rule over the scanned tree. Findings are returned in
/// canonical order: path, then rule id. A finding's fingerprint is derived from
/// the rule and the path alone, so it is stable while coverage moves and the
/// finding stays baselineable.
pub fn scan_coverage(
    rules: &[CompiledRule],
    resolved: &BTreeMap<String, FileCoverage>,
    scanned_paths: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        let CompiledPayload::Coverage { min } = &rule.payload else {
            continue;
        };

        for path in scanned_paths {
            if !applies(rule, path, None) {
                continue;
            }
            let Some(coverage) = resolved.get(path.as_str()) else {
                continue;
            };
            let percent = coverage.percent();
            if percent >= *min {
                continue;
            }

            let matched = format!(
                "{}/{} lines ({percent:.1}%)",
                coverage.lines_covered, coverage.lines_total
            );
            findings.push(Finding {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                message: rule.message.clone(),
                path: path.clone(),
                line: 1,
                // A coverage finding is about a whole file, not a span in it.
                column: 1,
                column_utf16: 1,
                matched,
                // The measured value is deliberately out of the fingerprint:
                // it moves on every test run, and a fingerprint that moves
                // with it could never be baselined or ratcheted. Rule and path
                // are the identity of a coverage finding.
                fingerprint: fingerprint(&rule.id, path, "", 0),
            });
        }
    }

    findings.sort_by(|a, b| {
        a.path
            .as_bytes()
            .cmp(b.path.as_bytes())
            .then(a.rule_id.as_bytes().cmp(b.rule_id.as_bytes()))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::load_str;

    const LCOV: &str = "\
TN:suite
SF:/home/u/repo/src/a.rs
DA:1,1
DA:2,0
DA:3,5
LF:4
LH:2
end_of_record
SF:src\\b.rs
DA:1,0
DA:2,0
end_of_record
SF:/home/u/repo/src/c.rs
DA:1,3
end_of_record
";

    const COBERTURA: &str = r#"<?xml version="1.0" ?>
<coverage line-rate="0.5" version="1.9">
  <sources><source>/home/u/repo</source></sources>
  <packages>
    <package name="pkg">
      <classes>
        <class filename="src/a.py" name="A">
          <methods>
            <method name="m">
              <lines><line number="9" hits="1"/></lines>
            </method>
          </methods>
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="0"/>
          </lines>
        </class>
        <class filename="src/a.py" name="B">
          <lines><line number="3" hits="4"/></lines>
        </class>
        <class filename="src\b.py" name="C">
          <lines>
            <line number="1" hits="0"/>
            <line number="2" hits="0"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
"#;

    fn write(body: &str, name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, body).unwrap();
        (dir, path)
    }

    fn cov(covered: u64, total: u64) -> FileCoverage {
        FileCoverage {
            lines_total: total,
            lines_covered: covered,
        }
    }

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    const COVERAGE_RULE: &str = r#"
version: 1
rules:
  - id: cov.min
    severity: warning
    message: line coverage below threshold
    paths:
      include: ["src/**"]
    coverage:
      min: 80
"#;

    #[test]
    fn parses_lcov_with_multiple_files() {
        let (_dir, path) = write(LCOV, "lcov.info");
        let report = parse(&path).expect("should parse");

        assert_eq!(
            report.files.keys().collect::<Vec<_>>(),
            vec!["/home/u/repo/src/a.rs", "/home/u/repo/src/c.rs", "src/b.rs"]
        );
        // LF/LH win over the DA tally.
        assert_eq!(report.files["/home/u/repo/src/a.rs"], cov(2, 4));
        // No LF/LH: DA entries are counted.
        assert_eq!(report.files["src/b.rs"], cov(0, 2));
        assert_eq!(report.files["/home/u/repo/src/c.rs"], cov(1, 1));
    }

    #[test]
    fn lcov_unions_repeated_records() {
        let (_dir, path) = write(
            "SF:src/a.rs\nDA:1,0\nDA:2,1\nend_of_record\nSF:src/a.rs\nDA:1,3\nDA:3,0\nend_of_record\n",
            "lcov.info",
        );
        let report = parse(&path).expect("should parse");
        assert_eq!(report.files["src/a.rs"], cov(2, 3));
    }

    #[test]
    fn parses_cobertura_aggregating_classes_per_file() {
        let (_dir, path) = write(COBERTURA, "coverage.xml");
        let report = parse(&path).expect("should parse");

        assert_eq!(
            report.files.keys().collect::<Vec<_>>(),
            vec!["src/a.py", "src/b.py"]
        );
        // Two classes union to lines 1..=3; the method-level line 9 is ignored.
        assert_eq!(report.files["src/a.py"], cov(2, 3));
        assert_eq!(report.files["src/b.py"], cov(0, 2));
    }

    #[test]
    fn unknown_format_is_an_error() {
        let (_dir, path) = write("total coverage: 42%\n", "report.txt");
        let err = parse(&path).unwrap_err();
        assert!(err.contains("unrecognized coverage format"), "{err}");
    }

    #[test]
    fn xml_without_a_coverage_root_is_an_error() {
        let (_dir, path) = write("<report><class filename=\"a\"/></report>\n", "report.xml");
        assert!(parse(&path).is_err());
    }

    #[test]
    fn missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(parse(&dir.path().join("absent.info")).is_err());
    }

    #[test]
    fn percent_handles_empty_and_full_files() {
        assert_eq!(cov(0, 0).percent(), 100.0);
        assert_eq!(cov(0, 4).percent(), 0.0);
        assert_eq!(cov(4, 4).percent(), 100.0);
        assert_eq!(cov(1, 4).percent(), 25.0);
    }

    #[test]
    fn resolve_prefers_exact_then_suffix() {
        let report = CoverageReport {
            files: BTreeMap::from([
                ("src/exact.rs".to_string(), cov(1, 2)),
                ("/home/u/repo/src/abs.rs".to_string(), cov(3, 4)),
            ]),
            source: String::new(),
        };
        let scanned = vec!["src/exact.rs".to_string(), "src/abs.rs".to_string()];

        let resolved = resolve(&report, &scanned);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved["src/exact.rs"], cov(1, 2));
        assert_eq!(resolved["src/abs.rs"], cov(3, 4));
    }

    #[test]
    fn resolve_matches_reports_relative_to_a_source_root() {
        let report = CoverageReport {
            files: BTreeMap::from([("app/main.py".to_string(), cov(1, 2))]),
            source: String::new(),
        };
        let scanned = vec!["backend/app/main.py".to_string()];

        assert_eq!(resolve(&report, &scanned)["backend/app/main.py"], cov(1, 2));
    }

    #[test]
    fn resolve_drops_report_entries_matching_several_scanned_paths() {
        let report = CoverageReport {
            files: BTreeMap::from([("/build/lib/util.rs".to_string(), cov(1, 2))]),
            source: String::new(),
        };
        let scanned = vec!["a/lib/util.rs".to_string(), "b/lib/util.rs".to_string()];

        assert!(resolve(&report, &scanned).is_empty());
    }

    #[test]
    fn resolve_drops_scanned_paths_claimed_by_several_reports() {
        let report = CoverageReport {
            files: BTreeMap::from([
                ("/build/one/src/a.rs".to_string(), cov(1, 2)),
                ("/build/two/src/a.rs".to_string(), cov(2, 2)),
            ]),
            source: String::new(),
        };
        let scanned = vec!["src/a.rs".to_string()];

        assert!(resolve(&report, &scanned).is_empty());
    }

    #[test]
    fn resolve_drops_unmatched_report_entries() {
        let report = CoverageReport {
            files: BTreeMap::from([("/build/src/gone.rs".to_string(), cov(1, 2))]),
            source: String::new(),
        };
        assert!(resolve(&report, &["src/kept.rs".to_string()]).is_empty());
    }

    #[test]
    fn resolve_does_not_suffix_match_partial_segments() {
        let report = CoverageReport {
            files: BTreeMap::from([("/build/src/main.rs".to_string(), cov(1, 2))]),
            source: String::new(),
        };
        assert!(resolve(&report, &["ain.rs".to_string()]).is_empty());
    }

    #[test]
    fn engine_reports_only_files_below_the_threshold() {
        let compiled = rules(COVERAGE_RULE);
        let resolved = BTreeMap::from([
            ("src/low.rs".to_string(), cov(5, 10)),
            ("src/high.rs".to_string(), cov(9, 10)),
            ("src/exact.rs".to_string(), cov(8, 10)),
        ]);
        let scanned = vec![
            "src/low.rs".to_string(),
            "src/high.rs".to_string(),
            "src/exact.rs".to_string(),
            // No coverage data: not a violation.
            "src/unknown.rs".to_string(),
        ];

        let found = scan_coverage(&compiled, &resolved, &scanned);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "src/low.rs");
        assert_eq!(found[0].rule_id, "cov.min");
        assert_eq!((found[0].line, found[0].column), (1, 1));
        assert_eq!(found[0].message, "line coverage below threshold");
        assert_eq!(
            found[0].fingerprint,
            fingerprint("cov.min", "src/low.rs", "", 0)
        );
    }

    #[test]
    fn engine_fingerprint_survives_a_change_in_coverage() {
        let compiled = rules(COVERAGE_RULE);
        let scanned = vec!["src/a.rs".to_string()];

        let low = scan_coverage(
            &compiled,
            &BTreeMap::from([("src/a.rs".to_string(), cov(1, 10))]),
            &scanned,
        );
        let higher = scan_coverage(
            &compiled,
            &BTreeMap::from([("src/a.rs".to_string(), cov(7, 10))]),
            &scanned,
        );

        assert_eq!(low.len(), 1);
        assert_eq!(higher.len(), 1);
        assert_ne!(low[0].matched, higher[0].matched);
        assert_eq!(low[0].fingerprint, higher[0].fingerprint);
    }

    #[test]
    fn engine_fingerprint_varies_by_rule_and_path() {
        let compiled = rules(COVERAGE_RULE);
        let resolved = BTreeMap::from([
            ("src/a.rs".to_string(), cov(0, 10)),
            ("src/b.rs".to_string(), cov(0, 10)),
        ]);
        let scanned = vec!["src/a.rs".to_string(), "src/b.rs".to_string()];

        let found = scan_coverage(&compiled, &resolved, &scanned);
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
    }

    #[test]
    fn engine_matched_string_is_deterministic() {
        let compiled = rules(COVERAGE_RULE);
        let resolved = BTreeMap::from([
            ("src/a.rs".to_string(), cov(1, 3)),
            ("src/b.rs".to_string(), cov(0, 7)),
        ]);
        let scanned = vec!["src/a.rs".to_string(), "src/b.rs".to_string()];

        let found = scan_coverage(&compiled, &resolved, &scanned);
        assert_eq!(found[0].matched, "1/3 lines (33.3%)");
        assert_eq!(found[1].matched, "0/7 lines (0.0%)");
        assert_eq!(found, scan_coverage(&compiled, &resolved, &scanned));
    }

    #[test]
    fn engine_honours_path_gating_and_skips_other_payloads() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: cov.min
    severity: warning
    message: m
    paths:
      include: ["src/**"]
      exclude: ["**/generated/**"]
    coverage:
      min: 80
  - id: other.regex
    severity: info
    message: m
    regex:
      pattern: 'needle'
"#,
        );
        let resolved = BTreeMap::from([
            ("src/a.rs".to_string(), cov(0, 10)),
            ("src/generated/b.rs".to_string(), cov(0, 10)),
            ("docs/c.rs".to_string(), cov(0, 10)),
        ]);
        let scanned = vec![
            "src/a.rs".to_string(),
            "src/generated/b.rs".to_string(),
            "docs/c.rs".to_string(),
        ];

        let found = scan_coverage(&compiled, &resolved, &scanned);
        assert_eq!(
            found.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(),
            vec!["src/a.rs"]
        );
    }

    #[test]
    fn engine_findings_are_in_canonical_order() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: cov.strict
    severity: error
    message: m
    coverage:
      min: 90
  - id: cov.loose
    severity: warning
    message: m
    coverage:
      min: 50
"#,
        );
        let resolved = BTreeMap::from([
            ("src/b.rs".to_string(), cov(0, 10)),
            ("src/a.rs".to_string(), cov(0, 10)),
        ]);
        let scanned = vec!["src/b.rs".to_string(), "src/a.rs".to_string()];

        let found = scan_coverage(&compiled, &resolved, &scanned);
        assert_eq!(
            found
                .iter()
                .map(|f| (f.path.as_str(), f.rule_id.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("src/a.rs", "cov.loose"),
                ("src/a.rs", "cov.strict"),
                ("src/b.rs", "cov.loose"),
                ("src/b.rs", "cov.strict"),
            ]
        );
    }

    #[test]
    fn a_coverage_rule_without_a_report_is_refused_by_name() {
        let compiled = rules(COVERAGE_RULE);
        let err = require_report(&compiled, None).unwrap_err();

        assert!(err.contains("cov.min"), "{err}");
        assert!(err.contains("coverage report"), "{err}");
    }

    #[test]
    fn a_coverage_rule_with_a_report_is_accepted() {
        let compiled = rules(COVERAGE_RULE);
        let report = CoverageReport::default();

        assert_eq!(require_report(&compiled, Some(&report)), Ok(()));
    }

    /// A report is not evidence on its own: one that resolves onto nothing
    /// leaves the gate measuring nothing, which is the case `require_report`
    /// exists to refuse with a file in the way of seeing it.
    #[test]
    fn a_coverage_report_matching_no_scanned_file_is_refused_by_name() {
        let compiled = rules(COVERAGE_RULE);
        let report = CoverageReport {
            files: BTreeMap::from([("other/tree/src/gone.rs".to_string(), cov(0, 4))]),
            source: "/tmp/lcov.info".to_string(),
        };
        let resolved = resolve(&report, &["src/a.rs".to_string()]);

        let err = require_resolved(&compiled, &report, &resolved).unwrap_err();
        assert!(err.contains("cov.min"), "{err}");
        assert!(err.contains("/tmp/lcov.info"), "{err}");
        assert!(err.contains("none of the scanned files"), "{err}");
    }

    /// The report a caller built rather than parsed has no path to name, and
    /// still gets refused rather than waved through on a missing string.
    #[test]
    fn a_report_with_no_source_is_still_refused_by_name() {
        let compiled = rules(COVERAGE_RULE);
        let report = CoverageReport::default();

        let err = require_resolved(&compiled, &report, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("cov.min"), "{err}");
        assert!(err.contains("supplied coverage report"), "{err}");
    }

    /// The legitimate case, which this must not break: a report that covers
    /// some scanned files and not others. Files with no coverage data are not
    /// violations by design, and a partial report is the normal shape of one.
    #[test]
    fn a_report_covering_only_some_scanned_files_is_accepted() {
        let compiled = rules(COVERAGE_RULE);
        let report = CoverageReport {
            files: BTreeMap::from([("src/a.rs".to_string(), cov(1, 4))]),
            source: "lcov.info".to_string(),
        };
        let scanned = vec!["src/a.rs".to_string(), "src/b.rs".to_string()];
        let resolved = resolve(&report, &scanned);

        assert_eq!(require_resolved(&compiled, &report, &resolved), Ok(()));
    }

    /// And with no coverage rule loaded there is no gate to be silent, so an
    /// unrelated report that matches nothing is not an error.
    #[test]
    fn an_unmatched_report_without_a_coverage_rule_is_not_an_error() {
        let report = CoverageReport::default();
        assert_eq!(require_resolved(&[], &report, &BTreeMap::new()), Ok(()));
    }

    #[test]
    fn rules_without_a_coverage_payload_need_no_report() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: other.regex
    severity: info
    message: m
    regex:
      pattern: 'needle'
"#,
        );

        assert_eq!(require_report(&compiled, None), Ok(()));
        assert_eq!(require_report(&[], None), Ok(()));
    }

    #[test]
    fn engine_treats_files_without_lines_as_covered() {
        let compiled = rules(COVERAGE_RULE);
        let resolved = BTreeMap::from([("src/empty.rs".to_string(), cov(0, 0))]);
        let scanned = vec!["src/empty.rs".to_string()];

        assert!(scan_coverage(&compiled, &resolved, &scanned).is_empty());
    }
}
