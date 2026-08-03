use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use globset::GlobSet;
use serde::Serialize;

use crate::findings::Finding;
use crate::rules::{CompiledPayload, RuleSet};
use crate::walk::{self, FileKind};

#[derive(Debug, Clone, Serialize)]
pub struct SkippedFile {
    /// Repo-relative path using forward slashes.
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Actionable findings: neither suppressed inline nor covered by the baseline.
    pub findings: Vec<Finding>,
    pub baselined: Vec<Finding>,
    pub suppressed: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
    /// Per-file semantic facts for every file that produced a parse tree.
    pub graph: crate::graph::Graph,
    /// Every boundary violation as `(from silo, to silo, fingerprint)`, sorted.
    /// The finding itself is in `findings`, `baselined` or `suppressed`
    /// depending on how it was partitioned, and is identified by fingerprint.
    pub boundary_edges: Vec<(String, String, String)>,
}

/// Optional inputs to a scan. Defaults to no baseline, cache, config or
/// coverage report, which is exactly what [`scan`] and [`scan_with_progress`]
/// pass.
#[derive(Default)]
pub struct ScanOptions<'a> {
    pub baseline: Option<&'a crate::baseline::Baseline>,
    pub cache: Option<&'a crate::cache::Cache>,
    /// Repository config. Boundary rules are inert without one: silo
    /// membership is defined by the config and nowhere else.
    pub config: Option<&'a crate::config::Config>,
    /// Parsed coverage report. Coverage rules are inert without one: absence
    /// of data is not evidence of an uncovered file.
    pub coverage: Option<&'a crate::coverage::CoverageReport>,
}

/// Scan progress snapshot. `findings` counts raw matches as scanned, before
/// inline suppression and baseline partitioning, so it only ever grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Progress {
    pub files_total: usize,
    pub files_done: usize,
    pub findings: usize,
}

pub fn scan(
    root: &Path,
    rules: &RuleSet,
    baseline: Option<&crate::baseline::Baseline>,
) -> ScanReport {
    scan_with_progress(root, rules, baseline, &mut |_| {})
}

/// Same scan, with a callback invoked once after the walk (`files_done = 0`,
/// total known) and once after each file.
pub fn scan_with_progress(
    root: &Path,
    rules: &RuleSet,
    baseline: Option<&crate::baseline::Baseline>,
    on_progress: &mut dyn FnMut(Progress),
) -> ScanReport {
    let options = ScanOptions {
        baseline,
        ..ScanOptions::default()
    };
    // Silo validation is the only fallible step and needs a config, which the
    // default options do not carry, so this path cannot fail.
    run(root, rules, &options, None, on_progress)
}

/// The scanner proper. Every file is read once, parsed at most once, and run
/// through every engine; a cache hit replaces the read-to-engine step only.
///
/// Fails when a boundary rule names a silo the config does not define, and when
/// boundary rules would run against a scan root below the directory holding the
/// config: a typo or a partial scan would otherwise silently disable the rule.
pub fn scan_opts(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    on_progress: &mut dyn FnMut(Progress),
) -> Result<ScanReport, String> {
    let silo_sets = boundary_setup(root, rules, options.config)?;
    Ok(run(root, rules, options, silo_sets, on_progress))
}

/// Compiled silo globs, once it is established that at least one boundary rule
/// and a config defining silos are both present. `None` disables the boundary
/// engine for this scan.
fn boundary_setup(
    root: &Path,
    rules: &RuleSet,
    config: Option<&crate::config::Config>,
) -> Result<Option<Vec<(String, GlobSet)>>, String> {
    let Some(config) = config else {
        return Ok(None);
    };

    let mut any = false;
    for rule in &rules.rules {
        let CompiledPayload::Boundary { from, deny } = &rule.payload else {
            continue;
        };
        any = true;
        for silo in std::iter::once(from).chain(deny) {
            if !config.silos.contains_key(silo) {
                return Err(format!("rule {}: unknown silo: {silo}", rule.id));
            }
        }
    }

    if !any || config.silos.is_empty() {
        return Ok(None);
    }
    require_config_root(root)?;
    config.silo_sets().map(Some)
}

/// Silo globs are relative to the directory holding the config, while scanned
/// paths are relative to the scan root. Scanning below the config's directory
/// would match every file against the wrong path and report nothing at all, so
/// it is refused rather than silently passed. A config that is not on disk
/// (built in memory by a caller) cannot be located and is trusted.
fn require_config_root(root: &Path) -> Result<(), String> {
    let Some(dir) =
        crate::config::discover(root).and_then(|path| path.parent().map(Path::to_owned))
    else {
        return Ok(());
    };
    if same_dir(&dir, root) {
        return Ok(());
    }
    Err(format!(
        "boundary rules are relative to {}, the directory holding {}: scan it instead of {}",
        dir.display(),
        crate::config::CONFIG_NAME,
        root.display()
    ))
}

fn same_dir(a: &Path, b: &Path) -> bool {
    let canonical = |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    canonical(a) == canonical(b)
}

fn run(
    root: &Path,
    rules: &RuleSet,
    options: &ScanOptions,
    silo_sets: Option<Vec<(String, GlobSet)>>,
    on_progress: &mut dyn FnMut(Progress),
) -> ScanReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut suppressed: Vec<Finding> = Vec::new();
    let mut skipped: Vec<SkippedFile> = Vec::new();
    let mut graph = crate::graph::Graph::default();
    // Repo-relative path -> the file it came from, for every scannable file.
    let mut scanned: BTreeMap<String, PathBuf> = BTreeMap::new();

    let files = walk::collect_files(root);
    let files_total = files.len();
    let mut raw_findings = 0usize;
    on_progress(Progress {
        files_total,
        files_done: 0,
        findings: 0,
    });

    for (index, path) in files.into_iter().enumerate() {
        let path_rel = relative(root, &path);
        match walk::read_text(&path) {
            // Binary files are not scannable input, not a failure to report.
            FileKind::Binary => {}
            FileKind::Unreadable(reason) => skipped.push(SkippedFile {
                path: path_rel,
                reason,
            }),
            FileKind::Text(content) => {
                let entry = scan_text(rules, options, &path, &path_rel, &content);

                if let Some(facts) = entry.facts {
                    graph.files.insert(path_rel.clone(), facts);
                }
                scanned.insert(path_rel, path.clone());

                raw_findings += entry.findings.len();
                let (kept, ignored) = crate::suppress::partition(&content, entry.findings);
                findings.extend(kept);
                suppressed.extend(ignored);
            }
        }

        on_progress(Progress {
            files_total,
            files_done: index + 1,
            findings: raw_findings,
        });
    }

    // The boundary and coverage engines need the whole tree, so they run once
    // the walk is done. Their findings join the others before suppression and
    // baseline partitioning, so markers and baselines apply to them like any
    // other finding.
    let paths: Vec<String> = scanned.keys().cloned().collect();
    let mut whole_tree: Vec<Finding> = Vec::new();
    let mut boundary_edges: Vec<(String, String, String)> = Vec::new();

    if let (Some(config), Some(sets)) = (options.config, &silo_sets) {
        let modules = crate::engines::boundary::go_modules(&go_mod_sources(&scanned));
        for violation in
            crate::engines::boundary::scan_graph(&rules.rules, &graph, config, sets, &modules)
        {
            boundary_edges.push((
                violation.from,
                violation.to,
                violation.finding.fingerprint.clone(),
            ));
            whole_tree.push(violation.finding);
        }
    }
    if let Some(coverage) = options.coverage {
        let resolved = crate::coverage::resolve(coverage, &paths);
        whole_tree.extend(crate::coverage::scan_coverage(
            &rules.rules,
            &resolved,
            &paths,
        ));
    }

    let (kept, ignored) = suppress_whole_tree(&scanned, whole_tree);
    findings.extend(kept);
    suppressed.extend(ignored);
    boundary_edges.sort();
    boundary_edges.dedup();

    sort_findings(&mut findings);
    sort_findings(&mut suppressed);
    skipped.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    // Partitioning preserves input order, so both halves stay canonical.
    let (findings, baselined) = match options.baseline {
        Some(baseline) => crate::baseline::partition(baseline, findings),
        None => (findings, Vec::new()),
    };

    ScanReport {
        findings,
        baselined,
        suppressed,
        skipped,
        graph,
        boundary_edges,
    }
}

/// Contents of every `go.mod` in the scanned tree, keyed by repo-relative path.
/// They are read again after the walk, as inline suppression does, since the
/// walk keeps no file contents; an unreadable `go.mod` declares no module.
fn go_mod_sources(scanned: &BTreeMap<String, PathBuf>) -> BTreeMap<String, String> {
    let mut sources = BTreeMap::new();
    for (path_rel, path) in scanned {
        if path_rel != "go.mod" && !path_rel.ends_with("/go.mod") {
            continue;
        }
        if let FileKind::Text(content) = walk::read_text(path) {
            sources.insert(path_rel.clone(), content);
        }
    }
    sources
}

/// Apply inline suppression to findings produced after the walk. Their file
/// content is no longer in memory, so the files they landed on are read again;
/// a file that has become unreadable since the walk suppresses nothing.
fn suppress_whole_tree(
    scanned: &BTreeMap<String, PathBuf>,
    findings: Vec<Finding>,
) -> (Vec<Finding>, Vec<Finding>) {
    let mut by_path: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for finding in findings {
        by_path
            .entry(finding.path.clone())
            .or_default()
            .push(finding);
    }

    let mut kept: Vec<Finding> = Vec::new();
    let mut ignored: Vec<Finding> = Vec::new();
    for (path, group) in by_path {
        match scanned.get(&path).map(|file| walk::read_text(file)) {
            Some(FileKind::Text(content)) => {
                let (in_force, marked) = crate::suppress::partition(&content, group);
                kept.extend(in_force);
                ignored.extend(marked);
            }
            _ => kept.extend(group),
        }
    }

    (kept, ignored)
}

/// Engine results for one text file, from the cache when possible.
///
/// The cache holds raw engine output: findings as the engines produced them,
/// before inline suppression. Suppression is re-applied to every retrieved
/// entry. The content hash covers the markers either way, so this is a wash for
/// correctness and keeps the stored payload engine-pure.
fn scan_text(
    rules: &RuleSet,
    options: &ScanOptions,
    path: &Path,
    path_rel: &str,
    content: &str,
) -> crate::cache::CachedFile {
    let hash = options.cache.map(|_| entry_hash(path_rel, content));

    if let (Some(cache), Some(hash)) = (options.cache, &hash)
        && let Some(entry) = cache.get(hash, content)
    {
        return entry;
    }

    let language = crate::lang::detect(path, content);
    let tree = language.and_then(|lang| crate::parsers::parse(lang, content));

    let mut file_findings =
        crate::engines::regex::scan_file(&rules.rules, path_rel, language, content);
    file_findings.extend(crate::engines::secret::scan_file(
        &rules.rules,
        path_rel,
        language,
        content,
    ));
    file_findings.extend(crate::engines::ast::scan_file(
        &rules.rules,
        path_rel,
        language,
        content,
        tree.as_ref(),
    ));

    let facts = match (language, &tree) {
        (Some(lang), Some(tree)) => Some(crate::graph::extract(lang, content, tree)),
        _ => None,
    };

    let entry = crate::cache::CachedFile {
        findings: file_findings,
        facts,
    };
    if let (Some(cache), Some(hash)) = (options.cache, &hash) {
        cache.put(hash, &entry);
    }
    entry
}

/// Cache entries are keyed by path and content together: a finding carries its
/// repo-relative path, and its fingerprint is derived from it, so two identical
/// files at different paths are not interchangeable.
fn entry_hash(path_rel: &str, content: &str) -> String {
    let mut buf = Vec::with_capacity(path_rel.len() + content.len() + 1);
    buf.extend_from_slice(path_rel.as_bytes());
    buf.push(0);
    buf.extend_from_slice(content.as_bytes());
    crate::cache::content_hash(&buf)
}

/// Canonical order: path (bytewise), line, column, rule id.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.path
            .as_bytes()
            .cmp(b.path.as_bytes())
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.rule_id.as_bytes().cmp(b.rule_id.as_bytes()))
    });
}

/// Scan-root-relative, forward-slash path. Fingerprints incorporate this
/// value, so it must depend only on the scanned tree, never on anything
/// above the scan root. A file scan root reports its file name so the path
/// is never empty.
fn relative(root: &Path, path: &Path) -> String {
    let tail = path.strip_prefix(root).unwrap_or(path);
    let joined = join_slashes(tail);
    if joined.is_empty() {
        join_slashes(Path::new(path.file_name().unwrap_or(path.as_os_str())))
    } else {
        joined
    }
}

fn join_slashes(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<String>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use crate::rules::load_str;

    const RULES: &str = r#"
version: 1
rules:
  - id: test.needle
    severity: warning
    message: "needle found"
    regex:
      pattern: "needle"
"#;

    const SECRET_RULES: &str = r#"
version: 1
rules:
  - id: test.token
    severity: error
    message: "token found"
    secret:
      pattern: "tok_[a-z0-9]+"
"#;

    fn ruleset() -> RuleSet {
        RuleSet {
            rules: load_str(RULES, "test").expect("rules should load"),
            sources: vec![("test".to_string(), RULES.to_string())],
        }
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Mark `dir` as a repository root the way git does, so `config::discover`
    /// may walk above it.
    fn git_root(dir: &Path) {
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    fn write(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    #[test]
    fn scans_a_tree_end_to_end() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let x = 1;\nlet needle = 2;\n");
        write(dir.path(), "src/deep/b.rs", b"// nothing here\n");

        let report = scan(dir.path(), &ruleset(), None);

        assert!(report.skipped.is_empty());
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "test.needle");
        assert_eq!(finding.path, "src/a.rs");
        assert_eq!(finding.line, 2);
        assert_eq!(finding.column, 5);
        assert_eq!(finding.matched, "needle");
        assert_eq!(finding.fingerprint.len(), 64);
    }

    #[test]
    fn findings_are_in_canonical_order() {
        let dir = tempdir();
        // Created in non-sorted order on purpose.
        write(dir.path(), "z.rs", b"needle\nfiller\nneedle\n");
        write(dir.path(), "src/m.rs", b"needle needle\n");
        write(dir.path(), "a.rs", b"filler\nneedle\n");

        let report = scan(dir.path(), &ruleset(), None);

        let order: Vec<(&str, u64, u64)> = report
            .findings
            .iter()
            .map(|f| (f.path.as_str(), f.line, f.column))
            .collect();
        assert_eq!(
            order,
            vec![
                ("a.rs", 2, 1),
                ("src/m.rs", 1, 1),
                ("src/m.rs", 1, 8),
                ("z.rs", 1, 1),
                ("z.rs", 3, 1),
            ]
        );
    }

    #[test]
    fn file_scan_root_still_reports_a_path() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"needle\n");

        let report = scan(&dir.path().join("src/a.rs"), &ruleset(), None);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "a.rs");
    }

    #[test]
    fn paths_are_relative_to_the_scan_root() {
        let dir = tempdir();
        write(dir.path(), "sub/b.rs", b"needle\n");

        let from_root = scan(dir.path(), &ruleset(), None);
        let from_sub = scan(&dir.path().join("sub"), &ruleset(), None);

        assert_eq!(from_root.findings.len(), 1);
        assert_eq!(from_root.findings[0].path, "sub/b.rs");
        assert_eq!(from_sub.findings.len(), 1);
        assert_eq!(from_sub.findings[0].path, "b.rs");
        // Paths never reach above the scan root, wherever the tree lives.
        assert!(!from_root.findings[0].path.contains(".."));
    }

    #[test]
    fn binary_file_is_skipped_silently() {
        let dir = tempdir();
        write(dir.path(), "blob.bin", b"needle\0\0\0needle");
        write(dir.path(), "ok.txt", b"needle\n");

        let report = scan(dir.path(), &ruleset(), None);

        assert!(report.skipped.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "ok.txt");
    }

    #[test]
    fn secret_rules_run_alongside_regex_rules() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"let key = \"tok_abc123\";\n");

        let rules = RuleSet {
            rules: load_str(RULES, "regex")
                .unwrap()
                .into_iter()
                .chain(load_str(SECRET_RULES, "secret").unwrap())
                .collect(),
            ..Default::default()
        };
        let report = scan(dir.path(), &rules, None);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "test.token");
        assert_eq!(report.findings[0].matched, "tok_abc123");
    }

    #[test]
    fn inline_markers_move_findings_to_suppressed() {
        let dir = tempdir();
        write(
            dir.path(),
            "a.rs",
            b"// siloscan-ignore: test.needle\nlet a = needle;\nlet b = 2;\n",
        );
        write(dir.path(), "b.rs", b"needle\n");

        let report = scan(dir.path(), &ruleset(), None);

        // The marker line itself matches the rule; line 2 is suppressed.
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.suppressed.len(), 1);
        assert_eq!(report.suppressed[0].path, "a.rs");
        assert_eq!(report.suppressed[0].line, 2);
    }

    #[test]
    fn baseline_moves_known_findings_out_of_findings() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "b.rs", b"needle\n");

        let first = scan(dir.path(), &ruleset(), None);
        let baseline = crate::baseline::Baseline {
            version: 1,
            entries: vec![crate::baseline::BaselineEntry {
                fingerprint: first.findings[0].fingerprint.clone(),
                rule_id: first.findings[0].rule_id.clone(),
                path: first.findings[0].path.clone(),
            }],
        };

        let report = scan(dir.path(), &ruleset(), Some(&baseline));

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "b.rs");
        assert_eq!(report.baselined.len(), 1);
        assert_eq!(report.baselined[0].path, "a.rs");
    }

    fn collect_progress(root: &Path, rules: &RuleSet) -> (ScanReport, Vec<Progress>) {
        let mut events = Vec::new();
        let report = scan_with_progress(root, rules, None, &mut |p| events.push(p));
        (report, events)
    }

    #[test]
    fn progress_is_emitted_once_per_file_plus_one() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle needle\n");
        write(dir.path(), "src/c.rs", b"nothing\n");

        let (_report, events) = collect_progress(dir.path(), &ruleset());

        assert_eq!(events.len(), 4);
        assert_eq!(
            events[0],
            Progress {
                files_total: 3,
                files_done: 0,
                findings: 0,
            }
        );
        let last = events.last().unwrap();
        assert_eq!(last.files_done, 3);
        assert_eq!(last.files_total, 3);
        assert_eq!(last.findings, 3);
    }

    #[test]
    fn progress_counters_are_monotonic() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "b.rs", b"filler\n");
        write(dir.path(), "c.rs", b"needle\nneedle\n");

        let (_report, events) = collect_progress(dir.path(), &ruleset());

        for pair in events.windows(2) {
            assert_eq!(pair[1].files_done, pair[0].files_done + 1);
            assert!(pair[1].findings >= pair[0].findings);
            assert_eq!(pair[1].files_total, pair[0].files_total);
            assert!(pair[1].files_done <= pair[1].files_total);
        }
    }

    #[test]
    fn progress_counts_raw_matches_before_suppression() {
        let dir = tempdir();
        write(
            dir.path(),
            "a.rs",
            b"// siloscan-ignore: test.needle\nlet a = needle;\n",
        );

        let (report, events) = collect_progress(dir.path(), &ruleset());

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suppressed.len(), 1);
        assert_eq!(events.last().unwrap().findings, 2);
    }

    #[test]
    fn progress_scan_matches_plain_scan() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle\nneedle\n");
        write(dir.path(), "blob.bin", b"needle\0\0needle");

        let first = scan(dir.path(), &ruleset(), None);
        let baseline = crate::baseline::Baseline {
            version: 1,
            entries: vec![crate::baseline::BaselineEntry {
                fingerprint: first.findings[0].fingerprint.clone(),
                rule_id: first.findings[0].rule_id.clone(),
                path: first.findings[0].path.clone(),
            }],
        };

        let plain = scan(dir.path(), &ruleset(), Some(&baseline));
        let tracked = scan_with_progress(dir.path(), &ruleset(), Some(&baseline), &mut |_| {});

        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            serde_json::to_string(&tracked).unwrap()
        );
    }

    fn cached_scan(root: &Path, rules: &RuleSet, cache: &crate::cache::Cache) -> ScanReport {
        let options = ScanOptions {
            cache: Some(cache),
            ..ScanOptions::default()
        };
        scan_opts(root, rules, &options, &mut |_| {}).expect("no config, no failure")
    }

    #[test]
    fn cache_hit_reproduces_the_uncached_report() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle needle\n");

        let rules = ruleset();
        let cache = crate::cache::Cache::open(dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        assert_eq!(
            serde_json::to_string(&cold).unwrap(),
            serde_json::to_string(&warm).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&scan(dir.path(), &rules, None)).unwrap(),
            serde_json::to_string(&warm).unwrap()
        );
    }

    #[test]
    fn edited_content_invalidates_the_cached_entry() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");

        let rules = ruleset();
        let cache = crate::cache::Cache::open(dir.path(), &rules);
        assert_eq!(cached_scan(dir.path(), &rules, &cache).findings.len(), 1);

        write(
            dir.path(),
            "a.rs",
            b"// siloscan-ignore: test.needle\nneedle\n",
        );
        let report = cached_scan(dir.path(), &rules, &cache);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suppressed.len(), 1);
    }

    #[test]
    fn identical_content_at_two_paths_keeps_its_own_findings() {
        let dir = tempdir();
        write(dir.path(), "a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle\n");

        let rules = ruleset();
        let cache = crate::cache::Cache::open(dir.path(), &rules);
        cached_scan(dir.path(), &rules, &cache);
        let report = cached_scan(dir.path(), &rules, &cache);

        let paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["a.rs", "src/b.rs"]);
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn graph_facts_are_collected_cached_or_not() {
        let dir = tempdir();
        write(
            dir.path(),
            "src/a.rs",
            b"use std::io::Read;\n\nfn main() {}\n",
        );
        write(dir.path(), "notes.txt", b"needle\n");

        let rules = ruleset();
        let cache = crate::cache::Cache::open(dir.path(), &rules);
        let cold = cached_scan(dir.path(), &rules, &cache);
        let warm = cached_scan(dir.path(), &rules, &cache);

        assert_eq!(cold.graph, warm.graph);
        assert_eq!(cold.graph, scan(dir.path(), &rules, None).graph);
        let facts = cold.graph.files.get("src/a.rs").expect("facts");
        assert_eq!(facts.language, "rust");
        assert_eq!(
            facts
                .imports
                .iter()
                .map(|i| i.raw.as_str())
                .collect::<Vec<_>>(),
            vec!["std::io::Read"]
        );
        assert!(!cold.graph.files.contains_key("notes.txt"));
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn ast_rules_run_alongside_regex_rules() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"fn main() {\n    dbg!(1);\n}\n");

        let src = r#"
version: 1
rules:
  - id: rust.dbg-macro
    severity: warning
    message: "leftover dbg"
    ast:
      rust: '(macro_invocation macro: (identifier) @report (#eq? @report "dbg"))'
"#;
        let rules = RuleSet {
            rules: load_str(src, "ast").unwrap(),
            sources: vec![("ast".to_string(), src.to_string())],
        };

        let report = scan(dir.path(), &rules, None);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "rust.dbg-macro");
        assert_eq!((report.findings[0].line, report.findings[0].column), (2, 5));
    }

    const BOUNDARY_RULES: &str = r#"
version: 1
rules:
  - id: arch.api-must-not-import-db
    severity: error
    message: "api must not import db"
    boundary:
      from: api
      deny: ["db"]
"#;

    const COVERAGE_RULES: &str = r#"
version: 1
rules:
  - id: cov.min
    severity: warning
    message: "line coverage below threshold"
    coverage:
      min: 80
"#;

    fn boundary_rules() -> RuleSet {
        RuleSet {
            rules: load_str(BOUNDARY_RULES, "boundary").unwrap(),
            sources: vec![("boundary".to_string(), BOUNDARY_RULES.to_string())],
        }
    }

    fn silo_config(src: &str) -> crate::config::Config {
        toml::from_str(src).expect("config should parse")
    }

    const SILOS: &str = r#"
[silos]
api = ["src/api/**"]
db = ["src/db/**"]
"#;

    /// Two javascript files across a denied boundary.
    fn boundary_tree(dir: &Path) {
        write(
            dir,
            "src/api/handler.js",
            b"import x from '../db/client';\n",
        );
        write(dir, "src/db/client.js", b"export const x = 1;\n");
    }

    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn boundary_findings_join_the_report_with_their_edge() {
        let dir = tempdir();
        boundary_tree(dir.path());

        let config = silo_config(SILOS);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report =
            scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {}).expect("valid silos");

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "arch.api-must-not-import-db");
        assert_eq!(finding.path, "src/api/handler.js");
        assert_eq!(
            report.boundary_edges,
            vec![(
                "api".to_string(),
                "db".to_string(),
                finding.fingerprint.clone()
            )]
        );
    }

    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn inline_markers_suppress_boundary_findings() {
        let dir = tempdir();
        write(
            dir.path(),
            "src/api/handler.js",
            b"// siloscan-ignore: arch.api-must-not-import-db\nimport x from '../db/client';\n",
        );
        write(dir.path(), "src/db/client.js", b"export const x = 1;\n");

        let config = silo_config(SILOS);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {}).unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.suppressed.len(), 1);
        // The edge is reported whichever partition its finding landed in.
        assert_eq!(report.boundary_edges.len(), 1);
    }

    #[test]
    fn boundary_rules_are_inert_without_a_config() {
        let dir = tempdir();
        boundary_tree(dir.path());

        let report = scan(dir.path(), &boundary_rules(), None);

        assert!(report.findings.is_empty());
        assert!(report.boundary_edges.is_empty());
    }

    #[test]
    fn a_boundary_rule_naming_an_unknown_silo_is_an_error() {
        let dir = tempdir();
        boundary_tree(dir.path());

        let config = silo_config("[silos]\napi = [\"src/api/**\"]\n");
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let err = scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {}).unwrap_err();

        assert!(err.contains("unknown silo: db"), "{err}");
    }

    #[test]
    fn a_scan_root_below_the_config_is_an_error() {
        let dir = tempdir();
        git_root(dir.path());
        write(dir.path(), "siloscan.toml", SILOS.as_bytes());
        boundary_tree(dir.path());

        let config = silo_config(SILOS);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let err = scan_opts(
            &dir.path().join("src/api"),
            &boundary_rules(),
            &options,
            &mut |_| {},
        )
        .unwrap_err();

        assert!(err.contains("boundary rules are relative to"), "{err}");
        assert!(err.contains("siloscan.toml"), "{err}");
    }

    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn the_config_directory_is_a_valid_scan_root() {
        let dir = tempdir();
        git_root(dir.path());
        write(dir.path(), "siloscan.toml", SILOS.as_bytes());
        boundary_tree(dir.path());

        let config = silo_config(SILOS);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &boundary_rules(), &options, &mut |_| {}).unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "src/api/handler.js");
    }

    #[cfg(feature = "tree-sitter-go")]
    #[test]
    fn go_imports_resolve_through_the_module_declared_by_go_mod() {
        let go_silos = "[silos]\napi = [\"api/**\"]\ndb = [\"db/**\"]\n";
        let local = tempdir();
        write(local.path(), "go.mod", b"module example.com/app\n");
        write(
            local.path(),
            "api/server.go",
            b"package api\n\nimport \"example.com/app/db\"\n",
        );
        write(local.path(), "db/client.go", b"package db\n");

        // The same tree, differing only in the import path: an import of
        // another module must not resolve onto the local `db` package.
        let external = tempdir();
        write(external.path(), "go.mod", b"module example.com/app\n");
        write(
            external.path(),
            "api/server.go",
            b"package api\n\nimport \"github.com/vendor/otherproject/db\"\n",
        );
        write(external.path(), "db/client.go", b"package db\n");

        let config = silo_config(go_silos);
        let options = ScanOptions {
            config: Some(&config),
            ..ScanOptions::default()
        };

        let hit = scan_opts(local.path(), &boundary_rules(), &options, &mut |_| {}).unwrap();
        assert_eq!(hit.findings.len(), 1);
        assert_eq!(hit.findings[0].path, "api/server.go");

        let miss = scan_opts(external.path(), &boundary_rules(), &options, &mut |_| {}).unwrap();
        assert!(miss.findings.is_empty());
        assert!(miss.boundary_edges.is_empty());
    }

    #[test]
    fn coverage_findings_join_the_report() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"let x = 1;\n");
        write(dir.path(), "src/b.rs", b"let y = 2;\n");

        let rules = RuleSet {
            rules: load_str(COVERAGE_RULES, "coverage").unwrap(),
            sources: vec![("coverage".to_string(), COVERAGE_RULES.to_string())],
        };
        let coverage = crate::coverage::CoverageReport {
            files: std::collections::BTreeMap::from([(
                "src/a.rs".to_string(),
                crate::coverage::FileCoverage {
                    lines_total: 10,
                    lines_covered: 1,
                },
            )]),
        };
        let options = ScanOptions {
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &rules, &options, &mut |_| {}).unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "cov.min");
        assert_eq!(report.findings[0].path, "src/a.rs");
        // No coverage data for src/b.rs is not a violation.
        assert!(report.boundary_edges.is_empty());
    }

    #[test]
    fn whole_tree_findings_sort_with_the_rest() {
        let dir = tempdir();
        write(dir.path(), "src/a.rs", b"needle\n");
        write(dir.path(), "src/b.rs", b"needle\n");

        let mut rules = ruleset();
        rules
            .rules
            .extend(load_str(COVERAGE_RULES, "coverage").unwrap());
        rules
            .sources
            .push(("coverage".to_string(), COVERAGE_RULES.to_string()));

        let coverage = crate::coverage::CoverageReport {
            files: std::collections::BTreeMap::from([(
                "src/b.rs".to_string(),
                crate::coverage::FileCoverage {
                    lines_total: 4,
                    lines_covered: 0,
                },
            )]),
        };
        let options = ScanOptions {
            coverage: Some(&coverage),
            ..ScanOptions::default()
        };
        let report = scan_opts(dir.path(), &rules, &options, &mut |_| {}).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .map(|f| (f.path.as_str(), f.rule_id.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("src/a.rs", "test.needle"),
                ("src/b.rs", "cov.min"),
                ("src/b.rs", "test.needle"),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_is_counted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        write(dir.path(), "secret.txt", b"needle\n");
        write(dir.path(), "ok.txt", b"needle\n");

        let locked = dir.path().join("secret.txt");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&locked).is_ok() {
            // Privileged run: the mode bits are ignored, so there is nothing to assert.
            return;
        }

        let report = scan(dir.path(), &ruleset(), None);

        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, "secret.txt");
        assert!(!report.skipped[0].reason.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "ok.txt");

        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
    }
}
