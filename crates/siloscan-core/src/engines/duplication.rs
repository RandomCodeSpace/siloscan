//! Duplication gate engine.
//!
//! Duplication itself is measured once, by the metrics pass; this engine only
//! reads those per-file counts back and decides whether a rule's budget was
//! exceeded. Density is `duplicated_lines / lines * 100` over a set of files,
//! and which files are in the set is what the rule's scope selects: the whole
//! matched set (`scan`), each matched file on its own (`file`), or each silo
//! the matched files belong to (`silo`). The rule envelope's path filter is
//! what decides which files count at all.
//!
//! A gate finding's measured value is deliberately kept out of its fingerprint.
//! Density moves on nearly every commit, and a fingerprint that moved with it
//! could never be baselined; the rule plus what it is reporting about (the
//! path, or the silo name) is the identity of a gate finding.

use std::collections::{BTreeMap, BTreeSet};

use super::applies;
use crate::findings::{Finding, fingerprint};
use crate::metrics::Metrics;
use crate::rules::{CompiledPayload, CompiledRule, DuplicationScope};

/// Resolves a repo-relative path to the silo owning it, or `None` when no silo
/// claims it. Only `silo` scope consults it.
pub type SiloOf<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Run every duplication rule over the metrics of a scan. Findings are returned
/// in canonical order: path, then rule id, then the reported value, which is
/// what separates the several findings a `silo` scope rule reports at `.`.
///
/// `silo_of` may be `None` only when no configuration was loaded; a `silo`
/// scope rule in that case is a scan setup error, raised before this engine
/// runs, and is reported here as nothing rather than as a passing gate.
pub fn scan_duplication(
    rules: &[CompiledRule],
    metrics: &Metrics,
    silo_of: Option<SiloOf<'_>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        let CompiledPayload::Duplication { max_percent, scope } = &rule.payload else {
            continue;
        };

        let matched: BTreeSet<String> = metrics
            .files
            .keys()
            .filter(|path| applies(rule, path.as_str(), None))
            .cloned()
            .collect();

        findings.extend(evaluate_gate(
            rule,
            *max_percent,
            *scope,
            metrics,
            silo_of,
            &matched,
        ));
    }

    findings.sort_by(|a, b| {
        a.path
            .as_bytes()
            .cmp(b.path.as_bytes())
            .then(a.rule_id.as_bytes().cmp(b.rule_id.as_bytes()))
            .then(a.matched.as_bytes().cmp(b.matched.as_bytes()))
    });
    findings
}

/// Evaluate one duplication gate over `matched_paths`, the files the rule's
/// path filter selected. Paths that carry no metrics are ignored: a file with
/// no line counts contributes neither duplication nor a denominator.
pub fn evaluate_gate(
    rule: &CompiledRule,
    max_percent: f64,
    scope: DuplicationScope,
    metrics: &Metrics,
    silo_of: Option<SiloOf<'_>>,
    matched_paths: &BTreeSet<String>,
) -> Vec<Finding> {
    match scope {
        DuplicationScope::Scan => scan_scope(rule, max_percent, metrics, matched_paths),
        DuplicationScope::File => file_scope(rule, max_percent, metrics, matched_paths),
        DuplicationScope::Silo => match silo_of {
            Some(silo_of) => silo_scope(rule, max_percent, metrics, silo_of, matched_paths),
            None => Vec::new(),
        },
    }
}

fn scan_scope(
    rule: &CompiledRule,
    max_percent: f64,
    metrics: &Metrics,
    matched_paths: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut totals = Totals::default();
    for path in matched_paths {
        totals.add(metrics, path);
    }

    let density = totals.density();
    if density <= max_percent {
        return Vec::new();
    }

    vec![finding(
        rule,
        ".",
        format!("density {density:.1}% (max {max_percent:.1}%)"),
        "",
    )]
}

fn file_scope(
    rule: &CompiledRule,
    max_percent: f64,
    metrics: &Metrics,
    matched_paths: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // `matched_paths` is a `BTreeSet`, so the findings come out sorted by path.
    for path in matched_paths {
        let mut totals = Totals::default();
        if !totals.add(metrics, path) {
            continue;
        }
        let density = totals.density();
        if density <= max_percent {
            continue;
        }
        findings.push(finding(
            rule,
            path,
            format!("density {density:.1}% (max {max_percent:.1}%)"),
            "",
        ));
    }

    findings
}

fn silo_scope(
    rule: &CompiledRule,
    max_percent: f64,
    metrics: &Metrics,
    silo_of: SiloOf<'_>,
    matched_paths: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut silos: BTreeMap<String, Totals> = BTreeMap::new();
    for path in matched_paths {
        // A file no silo claims belongs to no silo's budget.
        let Some(silo) = silo_of(path) else {
            continue;
        };
        silos.entry(silo).or_default().add(metrics, path);
    }

    let mut findings = Vec::new();
    // `BTreeMap` iterates in key order, so the findings come out sorted by silo.
    for (silo, totals) in silos {
        let density = totals.density();
        if density <= max_percent {
            continue;
        }
        findings.push(finding(
            rule,
            ".",
            format!("silo {silo}: density {density:.1}% (max {max_percent:.1}%)"),
            &format!("silo {silo}"),
        ));
    }

    findings
}

/// Line counts accumulated as `f64`: every use of them is a ratio, and the
/// counts a scan produces are far below the point where that loses precision.
#[derive(Debug, Clone, Copy, Default)]
struct Totals {
    lines: f64,
    duplicated: f64,
}

impl Totals {
    /// Adds one file's counts. `false` means the file carries no metrics and
    /// nothing was added.
    fn add(&mut self, metrics: &Metrics, path: &str) -> bool {
        let Some(file) = metrics.files.get(path) else {
            return false;
        };
        self.lines += file.lines as f64;
        self.duplicated += file.duplicated_lines as f64;
        true
    }

    /// Duplicated share of the counted lines, in percent. A set with no lines
    /// has no duplication rather than an undefined density.
    fn density(&self) -> f64 {
        if self.lines <= 0.0 {
            return 0.0;
        }
        (self.duplicated / self.lines) * 100.0
    }
}

/// A gate finding at the head of `path`. `identity` is the fingerprint's
/// stand-in for the matched text, which holds the measured density and so must
/// not take part.
fn finding(rule: &CompiledRule, path: &str, matched: String, identity: &str) -> Finding {
    Finding {
        rule_id: rule.id.clone(),
        severity: rule.severity,
        message: rule.message.clone(),
        path: path.to_string(),
        line: 1,
        column: 1,
        matched,
        fingerprint: fingerprint(&rule.id, path, identity, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::FileMetrics;
    use crate::rules::load_str;

    /// A file's metrics: total lines and duplicated lines. Everything else the
    /// metrics carry is irrelevant to a gate.
    macro_rules! file_metrics {
        ($lines:expr, $duplicated:expr) => {
            FileMetrics {
                lines: $lines,
                duplicated_lines: $duplicated,
                ..Default::default()
            }
        };
    }

    fn metrics(files: Vec<(&str, FileMetrics)>) -> Metrics {
        Metrics {
            files: files
                .into_iter()
                .map(|(path, file)| (path.to_string(), file))
                .collect(),
            ..Default::default()
        }
    }

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    fn gate(scope: &str, max_percent: &str) -> Vec<CompiledRule> {
        rules(&format!(
            "version: 1\nrules:\n  - id: quality.duplication\n    severity: warning\n    message: duplication over budget\n    duplication: {{ max_percent: {max_percent}, scope: {scope} }}\n"
        ))
    }

    fn reported(findings: &[Finding]) -> Vec<(&str, &str)> {
        findings
            .iter()
            .map(|f| (f.path.as_str(), f.matched.as_str()))
            .collect()
    }

    #[test]
    fn scan_scope_reports_the_whole_matched_set() {
        let compiled = gate("scan", "10");
        let found = scan_duplication(
            &compiled,
            &metrics(vec![
                ("src/a.rs", file_metrics!(100, 20)),
                ("src/b.rs", file_metrics!(100, 10)),
            ]),
            None,
        );

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, ".");
        assert_eq!(found[0].rule_id, "quality.duplication");
        assert_eq!((found[0].line, found[0].column), (1, 1));
        assert_eq!(found[0].message, "duplication over budget");
        assert_eq!(found[0].matched, "density 15.0% (max 10.0%)");
        assert_eq!(
            found[0].fingerprint,
            fingerprint("quality.duplication", ".", "", 0)
        );
    }

    #[test]
    fn scan_scope_stays_quiet_at_or_under_the_budget() {
        let compiled = gate("scan", "10");
        // Exactly at the budget is not over it.
        assert!(
            scan_duplication(
                &compiled,
                &metrics(vec![("src/a.rs", file_metrics!(100, 10))]),
                None
            )
            .is_empty()
        );
        assert!(
            scan_duplication(
                &compiled,
                &metrics(vec![("src/a.rs", file_metrics!(100, 9))]),
                None
            )
            .is_empty()
        );
        // No files, and no lines, are not violations either.
        assert!(scan_duplication(&compiled, &metrics(vec![]), None).is_empty());
        assert!(
            scan_duplication(
                &compiled,
                &metrics(vec![("src/a.rs", file_metrics!(0, 0))]),
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn scan_scope_counts_only_the_files_the_path_filter_matched() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: quality.duplication
    severity: warning
    message: m
    paths:
      include: ["src/**"]
      exclude: ["**/generated/**"]
    duplication:
      max_percent: 10
"#,
        );
        // Only src/a.rs counts: 20/100. The excluded and unmatched files would
        // have diluted the density below the budget.
        let found = scan_duplication(
            &compiled,
            &metrics(vec![
                ("src/a.rs", file_metrics!(100, 20)),
                ("src/generated/b.rs", file_metrics!(900, 0)),
                ("docs/c.md", file_metrics!(900, 0)),
            ]),
            None,
        );

        assert_eq!(reported(&found), vec![(".", "density 20.0% (max 10.0%)")]);
    }

    #[test]
    fn file_scope_reports_every_offender_sorted_by_path() {
        let compiled = gate("file", "25");
        let found = scan_duplication(
            &compiled,
            &metrics(vec![
                ("src/c.rs", file_metrics!(100, 40)),
                ("src/a.rs", file_metrics!(100, 90)),
                ("src/b.rs", file_metrics!(100, 25)),
                ("src/d.rs", file_metrics!(0, 0)),
            ]),
            None,
        );

        assert_eq!(
            reported(&found),
            vec![
                ("src/a.rs", "density 90.0% (max 25.0%)"),
                ("src/c.rs", "density 40.0% (max 25.0%)"),
            ]
        );
        assert!(found.iter().all(|f| (f.line, f.column) == (1, 1)));
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
        assert_eq!(
            found[0].fingerprint,
            fingerprint("quality.duplication", "src/a.rs", "", 0)
        );
    }

    #[test]
    fn silo_scope_reports_every_offending_silo() {
        let compiled = gate("silo", "10");
        let silo_of = |path: &str| -> Option<String> {
            match path.split('/').next() {
                Some("api") => Some("api".to_string()),
                Some("core") => Some("core".to_string()),
                Some("web") => Some("web".to_string()),
                _ => None,
            }
        };

        let found = scan_duplication(
            &compiled,
            &metrics(vec![
                // web: 30/100 over two files.
                ("web/a.ts", file_metrics!(50, 20)),
                ("web/b.ts", file_metrics!(50, 10)),
                // api: 5/100, under budget.
                ("api/a.rs", file_metrics!(100, 5)),
                // core: 40/100, over budget.
                ("core/a.rs", file_metrics!(100, 40)),
                // Unsiloed, and heavily duplicated: counts for no silo.
                ("scripts/x.sh", file_metrics!(100, 100)),
            ]),
            Some(&silo_of),
        );

        assert_eq!(
            reported(&found),
            vec![
                (".", "silo core: density 40.0% (max 10.0%)"),
                (".", "silo web: density 30.0% (max 10.0%)"),
            ]
        );
        assert!(found.iter().all(|f| (f.line, f.column) == (1, 1)));
        // Both sit at ".", so the silo name has to be their identity.
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
        assert_eq!(
            found[0].fingerprint,
            fingerprint("quality.duplication", ".", "silo core", 0)
        );
    }

    #[test]
    fn silo_scope_without_a_silo_resolver_reports_nothing() {
        let compiled = gate("silo", "10");
        assert!(
            scan_duplication(
                &compiled,
                &metrics(vec![("src/a.rs", file_metrics!(100, 100))]),
                None,
            )
            .is_empty()
        );
    }

    #[test]
    fn density_is_reported_to_one_decimal() {
        // 1/3 -> 33.333..., 2/3 -> 66.666..., 1/7 -> 14.285...
        for (lines, duplicated, expected) in [
            (3, 1, "density 33.3% (max 1.0%)"),
            (3, 2, "density 66.7% (max 1.0%)"),
            (7, 1, "density 14.3% (max 1.0%)"),
        ] {
            let compiled = gate("file", "1");
            let found = scan_duplication(
                &compiled,
                &metrics(vec![("src/a.rs", file_metrics!(lines, duplicated))]),
                None,
            );
            assert_eq!(reported(&found), vec![("src/a.rs", expected)]);
        }
    }

    #[test]
    fn the_budget_is_reported_to_one_decimal_too() {
        let compiled = gate("scan", "3.26");
        let found = scan_duplication(
            &compiled,
            &metrics(vec![("src/a.rs", file_metrics!(100, 50))]),
            None,
        );
        assert_eq!(reported(&found), vec![(".", "density 50.0% (max 3.3%)")]);
    }

    #[test]
    fn other_payloads_are_skipped() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: other.regex
    severity: info
    message: m
    regex:
      pattern: 'needle'
  - id: other.coverage
    severity: info
    message: m
    coverage:
      min: 80
"#,
        );
        assert!(
            scan_duplication(
                &compiled,
                &metrics(vec![("src/a.rs", file_metrics!(100, 100))]),
                None,
            )
            .is_empty()
        );
    }

    #[test]
    fn findings_are_ordered_and_repeatable() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: quality.strict
    severity: error
    message: m
    duplication:
      max_percent: 1
      scope: file
  - id: quality.loose
    severity: warning
    message: m
    duplication:
      max_percent: 5
      scope: file
"#,
        );
        let metrics = metrics(vec![
            ("src/b.rs", file_metrics!(100, 40)),
            ("src/a.rs", file_metrics!(100, 40)),
        ]);

        let found = scan_duplication(&compiled, &metrics, None);
        assert_eq!(
            found
                .iter()
                .map(|f| (f.path.as_str(), f.rule_id.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("src/a.rs", "quality.loose"),
                ("src/a.rs", "quality.strict"),
                ("src/b.rs", "quality.loose"),
                ("src/b.rs", "quality.strict"),
            ]
        );
        assert_eq!(found, scan_duplication(&compiled, &metrics, None));
    }

    #[test]
    fn a_gate_fingerprint_survives_a_change_in_density() {
        let compiled = gate("file", "10");
        let low = scan_duplication(
            &compiled,
            &metrics(vec![("src/a.rs", file_metrics!(100, 20))]),
            None,
        );
        let high = scan_duplication(
            &compiled,
            &metrics(vec![("src/a.rs", file_metrics!(100, 60))]),
            None,
        );

        assert_eq!(low.len(), 1);
        assert_eq!(high.len(), 1);
        assert_ne!(low[0].matched, high[0].matched);
        assert_eq!(low[0].fingerprint, high[0].fingerprint);
    }
}
