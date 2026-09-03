//! Measures the embedded profile documents against the committed profile
//! corpus, and holds every document to the load rules the profiles contract.
//!
//! The documents are the ones in [`siloscan_core::profiles::REGISTRY`], loaded
//! through `rules::load_str` under their own identity - the same call
//! `plan::resolve` makes in a real scan - and run over
//! `tests/profiles-corpus/tree/<language>` through `scan::scan`, so the harness
//! measures the product's own path rather than a re-implementation of it.
//!
//! The registry is empty until the rule matrix lands documents, and everything
//! here passes over zero of them. That is exactly why
//! `the_harness_measures_an_in_test_document` exists: it builds a document and
//! a corpus in a temporary directory and runs the same measurement over them,
//! so an empty registry cannot hide a harness that measures nothing.
//!
//! Three numbers, three shapes:
//!
//! - **Recall is per language.** The family is the language directory, which is
//!   what lets Rust ship while Ruby is still being tuned.
//! - **The false-positive budget is per rule.** Removal is a per-rule decision:
//!   a global number says the profile is noisy and not which rule to delete.
//! - **Coverage is per rule.** A document may not ship a rule the corpus does
//!   not measure, and that is a separate test so a language can land one rule
//!   at a time.
//!
//! Nothing here touches the network. The pinned external noise set is measured
//! by `scripts/profile_noise.py`, against the same `noise/limits.tsv`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use siloscan_core::lang;
use siloscan_core::profiles::{self, Profile};
use siloscan_core::rules::{CompiledPayload, CompiledRule, RuleSet, Severity, load_str};
use siloscan_core::scan;

/// The committed corpus this file measures the shipped registry against.
const CORPUS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/profiles-corpus");

/// Where a shipped document's file lives. Read only to prove that every file
/// under it is registered: a document on disk that no `Profile` names is
/// shipped by nobody and measured by nothing.
const PROFILES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/rules/profiles");

/// Severities a profile rule may carry. A profile is advisory - it reports
/// judgement calls about code that compiles and passes its tests - so it never
/// raises the severity that fails a build.
const ALLOWED_SEVERITIES: [Severity; 2] = [Severity::Warning, Severity::Info];

// ------------------------------------------------------------- expectations

#[derive(Debug, PartialEq, Eq)]
enum Expect {
    /// The profiles must report nothing on this line.
    Nothing,
    /// The profiles must report one of these rule ids on this line. Listing
    /// several says every one of them is an acceptable owner of the shape.
    OneOf(Vec<String>),
}

impl Expect {
    fn is_positive(&self) -> bool {
        matches!(self, Expect::OneOf(_))
    }

    fn satisfied_by(&self, reported: &BTreeSet<String>) -> bool {
        match self {
            Expect::Nothing => reported.is_empty(),
            Expect::OneOf(ids) => ids.iter().any(|id| reported.contains(id)),
        }
    }

    fn describe(&self) -> String {
        match self {
            Expect::Nothing => "NONE".to_string(),
            Expect::OneOf(ids) => ids.join("|"),
        }
    }
}

struct Row {
    /// Path under `tree/`, forward slashes. The first segment is the language.
    path: String,
    line: u64,
    expect: Expect,
    justification: String,
}

impl Row {
    /// The language directory this row sits in, which is also its recall
    /// family. `None` for a path with no directory, which the agreement test
    /// refuses.
    fn language(&self) -> Option<&str> {
        self.path.split_once('/').map(|(first, _)| first)
    }
}

/// One rule's noise budget, in both places a budget is spent.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Limit {
    /// Findings this rule may leave on `NONE` rows of the manifest.
    max_corpus: usize,
    /// Findings per thousand code lines it may leave on one noise repository.
    /// Parsed here so the file has one parser and one shape;
    /// `scripts/profile_noise.py` is what enforces it, against the pinned
    /// noise set this harness never clones.
    max_per_kloc: f64,
}

/// What a rule with no row in `limits.tsv` is held to.
const DEFAULT_LIMIT: Limit = Limit {
    max_corpus: 0,
    max_per_kloc: 0.0,
};

// ------------------------------------------------------------------ corpus

struct Corpus {
    root: PathBuf,
    rows: Vec<Row>,
    /// Recall floor per language directory.
    floors: BTreeMap<String, f64>,
    limits: BTreeMap<String, Limit>,
    /// Line count of every file under `tree/`, keyed by path under `tree/`.
    lines_per_file: BTreeMap<String, u64>,
}

impl Corpus {
    fn load(root: &Path) -> Self {
        Corpus {
            root: root.to_path_buf(),
            rows: load_manifest(&root.join("manifest.tsv")),
            floors: load_floors(&root.join("floors.tsv")),
            limits: load_limits(&root.join("noise").join("limits.tsv")),
            lines_per_file: measure_files(&root.join("tree")),
        }
    }

    fn floor(&self, language: &str) -> f64 {
        *self.floors.get(language).unwrap_or_else(|| {
            panic!("language {language} carries positives but has no row in floors.tsv")
        })
    }

    fn limit(&self, rule_id: &str) -> Limit {
        self.limits.get(rule_id).copied().unwrap_or(DEFAULT_LIMIT)
    }
}

/// Every data line of a tab-separated corpus file, as field vectors, with the
/// 1-based file line each came from. Comments, blank lines and the header are
/// dropped; the field count is checked here so no reader repeats it.
fn data_rows(path: &Path, header: &str, fields: usize) -> Vec<(usize, Vec<String>)> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    let mut rows = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        if raw.trim().is_empty() || raw.starts_with('#') || raw.starts_with(header) {
            continue;
        }
        let values: Vec<String> = raw.split('\t').map(str::to_string).collect();
        assert_eq!(
            values.len(),
            fields,
            "{} line {number} has {} tab-separated fields, expected {fields}",
            path.display(),
            values.len()
        );
        rows.push((number, values));
    }
    rows
}

fn load_manifest(path: &Path) -> Vec<Row> {
    data_rows(path, "path\t", 4)
        .into_iter()
        .map(|(number, fields)| {
            let line: u64 = fields[1].parse().unwrap_or_else(|_| {
                panic!(
                    "{} line {number} has a non-numeric line number",
                    path.display()
                )
            });
            let expect = if fields[2] == "NONE" {
                Expect::Nothing
            } else {
                Expect::OneOf(fields[2].split('|').map(str::to_string).collect())
            };
            assert!(
                !fields[3].trim().is_empty(),
                "{} line {number} carries no justification",
                path.display()
            );
            Row {
                path: fields[0].clone(),
                line,
                expect,
                justification: fields[3].clone(),
            }
        })
        .collect()
}

fn load_floors(path: &Path) -> BTreeMap<String, f64> {
    let mut floors = BTreeMap::new();
    for (number, fields) in data_rows(path, "language\t", 4) {
        let floor: f64 = fields[1].parse().unwrap_or_else(|_| {
            panic!(
                "{} line {number} has a non-numeric recall floor",
                path.display()
            )
        });
        assert!(
            (0.0..=1.0).contains(&floor),
            "{} line {number} has a recall floor outside 0..=1",
            path.display()
        );
        assert!(
            floors.insert(fields[0].clone(), floor).is_none(),
            "{} names {} twice",
            path.display(),
            fields[0]
        );
    }
    floors
}

fn load_limits(path: &Path) -> BTreeMap<String, Limit> {
    let mut limits = BTreeMap::new();
    for (number, fields) in data_rows(path, "rule_id\t", 5) {
        let max_corpus: usize = fields[1].parse().unwrap_or_else(|_| {
            panic!(
                "{} line {number} has a non-numeric max_corpus",
                path.display()
            )
        });
        let max_per_kloc: f64 = fields[2].parse().unwrap_or_else(|_| {
            panic!(
                "{} line {number} has a non-numeric max_per_kloc",
                path.display()
            )
        });
        assert!(
            max_per_kloc >= 0.0,
            "{} line {number} has a negative max_per_kloc",
            path.display()
        );
        assert!(
            limits
                .insert(
                    fields[0].clone(),
                    Limit {
                        max_corpus,
                        max_per_kloc,
                    },
                )
                .is_none(),
            "{} names {} twice",
            path.display(),
            fields[0]
        );
    }
    limits
}

/// Line count of every file under `tree`, keyed by its path relative to it.
/// A missing `tree` is a corpus of no files, which is what ships until the
/// first language lands.
fn measure_files(tree: &Path) -> BTreeMap<String, u64> {
    let mut found = BTreeMap::new();
    if tree.is_dir() {
        collect(tree, tree, &mut found);
    }
    found
}

fn collect(root: &Path, dir: &Path, found: &mut BTreeMap<String, u64>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("{} is readable: {error}", dir.display()));
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("{} enumerates: {error}", dir.display()))
                .path()
        })
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect(root, &path, found);
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("corpus paths sit under the corpus root")
            .to_string_lossy()
            .replace('\\', "/");
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} is readable UTF-8: {error}", path.display()));
        found.insert(relative, content.lines().count() as u64);
    }
}

// --------------------------------------------------------------- documents

/// A registry entry with its identity taken apart and its rules loaded.
struct Document {
    identity: &'static str,
    /// The `<profile>` half of `<profile>-<language>@<n>`.
    profile: String,
    /// The `<language>` half, which must equal the entry's own language.
    language: String,
    rules: Vec<CompiledRule>,
    source: &'static str,
}

/// Splits `<profile>-<language>@<n>`. `Err` carries what is wrong with it.
///
/// Split at the last `-` before the `@`: a profile name may carry a hyphen and
/// no language name does, so the tail is unambiguous.
fn split_identity(identity: &str) -> Result<(String, String), String> {
    let (name, generation) = identity
        .rsplit_once('@')
        .ok_or_else(|| format!("{identity}: no @<n> generation suffix"))?;
    if generation.is_empty() || !generation.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "{identity}: {generation} is not a generation number"
        ));
    }
    let (profile, language) = name
        .rsplit_once('-')
        .ok_or_else(|| format!("{identity}: no <profile>-<language> stem"))?;
    if profile.is_empty() || language.is_empty() {
        return Err(format!("{identity}: empty profile or language"));
    }
    Ok((profile.to_string(), language.to_string()))
}

/// Loads every registry entry the way `plan::resolve` does. Panics naming the
/// identity when a document does not load, because a document that does not
/// load scans less than it promises.
fn documents(registry: &[Profile]) -> Vec<Document> {
    registry
        .iter()
        .map(|profile| {
            let rules = load_str(profile.document(), profile.identity())
                .unwrap_or_else(|error| panic!("{} loads: {error}", profile.identity()));
            let (name, language) = split_identity(profile.identity())
                .unwrap_or_else(|error| panic!("malformed profile identity: {error}"));
            Document {
                identity: profile.identity(),
                profile: name,
                language,
                rules,
                source: profile.document(),
            }
        })
        .collect()
}

// ------------------------------------------------------------- measurement

struct Measurement {
    /// Rule ids reported per corpus line, keyed by path under `tree/`.
    reported: BTreeMap<(String, u64), BTreeSet<String>>,
    corpus: Corpus,
    documents: Vec<Document>,
}

/// Loads every document and scans the corpus files of its language with it.
///
/// One scan per document over one language directory: a document covers
/// exactly one language, and scanning the whole tree with it would only add
/// files no rule in it can match.
fn measure(corpus: Corpus, registry: &[Profile]) -> Measurement {
    let documents = documents(registry);
    let mut reported: BTreeMap<(String, u64), BTreeSet<String>> = BTreeMap::new();

    for document in &documents {
        let dir = corpus.root.join("tree").join(&document.language);
        if !dir.is_dir() {
            continue;
        }
        let rules = RuleSet {
            rules: document.rules.clone(),
            sources: vec![(document.identity.to_string(), document.source.to_string())],
        };
        let report = scan::scan(&dir, &rules, None)
            .unwrap_or_else(|error| panic!("{} scans its corpus: {error}", document.identity));
        for finding in report.findings {
            reported
                .entry((
                    format!("{}/{}", document.language, finding.path),
                    finding.line,
                ))
                .or_default()
                .insert(finding.rule_id);
        }
    }

    Measurement {
        reported,
        corpus,
        documents,
    }
}

/// What a line nothing reported hits with. A `static` so `hits` can hand out a
/// reference without allocating an empty set per call.
static NO_HITS: BTreeSet<String> = BTreeSet::new();

impl Measurement {
    fn hits(&self, path: &str, line: u64) -> &BTreeSet<String> {
        self.reported
            .get(&(path.to_string(), line))
            .unwrap_or(&NO_HITS)
    }

    /// Every rule id every shipped document carries, in document order.
    fn shipped_rule_ids(&self) -> Vec<(&str, &str)> {
        self.documents
            .iter()
            .flat_map(|document| {
                document
                    .rules
                    .iter()
                    .map(move |rule| (document.identity, rule.id.as_str()))
            })
            .collect()
    }

    /// Positives the profiles failed to report.
    fn misses(&self) -> Vec<String> {
        self.corpus
            .rows
            .iter()
            .filter(|row| row.expect.is_positive())
            .filter(|row| !row.expect.satisfied_by(self.hits(&row.path, row.line)))
            .map(|row| {
                format!(
                    "  MISS {}:{} expected {} got {:?} - {}",
                    row.path,
                    row.line,
                    row.expect.describe(),
                    self.hits(&row.path, row.line),
                    row.justification
                )
            })
            .collect()
    }

    /// Per language: (positives, positives reported).
    fn recall_by_language(&self) -> BTreeMap<&str, (usize, usize)> {
        let mut stats: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for row in &self.corpus.rows {
            if !row.expect.is_positive() {
                continue;
            }
            let Some(language) = row.language() else {
                continue;
            };
            let entry = stats.entry(language).or_insert((0, 0));
            entry.0 += 1;
            if row.expect.satisfied_by(self.hits(&row.path, row.line)) {
                entry.1 += 1;
            }
        }
        stats
    }

    /// Per rule id: every `NONE` row it reported, as printable lines.
    fn false_positives(&self) -> BTreeMap<&str, Vec<String>> {
        let mut spent: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for row in &self.corpus.rows {
            if row.expect.is_positive() {
                continue;
            }
            for rule_id in self.hits(&row.path, row.line) {
                spent.entry(rule_id).or_default().push(format!(
                    "  FALSE POSITIVE {}:{} reported {rule_id} - {}",
                    row.path, row.line, row.justification
                ));
            }
        }
        spent
    }

    /// Findings on lines the manifest does not classify. Not a failure - a
    /// rule may legitimately report a line the corpus does not measure - but
    /// printed so a new one cannot hide.
    fn unclassified(&self) -> Vec<String> {
        self.reported
            .iter()
            .filter(|((path, line), _)| {
                !self
                    .corpus
                    .rows
                    .iter()
                    .any(|row| row.path == *path && row.line == *line)
            })
            .map(|((path, line), ids)| format!("  UNCLASSIFIED {path}:{line} reported {ids:?}"))
            .collect()
    }

    fn report(&self) -> String {
        let positives = self
            .corpus
            .rows
            .iter()
            .filter(|row| row.expect.is_positive())
            .count();
        let mut out = format!(
            "\nprofile corpus: {} documents, {} files, {} positives, {} negatives\n",
            self.documents.len(),
            self.corpus.lines_per_file.len(),
            positives,
            self.corpus.rows.len() - positives
        );
        out.push_str("LANGUAGE             RECALL   REPORTED  POSITIVES  FLOOR\n");
        for (language, (positives, reported)) in self.recall_by_language() {
            let recall = reported as f64 / positives as f64;
            let floor = self.corpus.floor(language);
            out.push_str(&format!(
                "{language:<20} {recall:<8.4} {reported:<9} {positives:<10} {floor:.4}\n"
            ));
        }
        for line in self.misses() {
            out.push_str(&line);
            out.push('\n');
        }
        for lines in self.false_positives().values() {
            for line in lines {
                out.push_str(line);
                out.push('\n');
            }
        }
        for line in self.unclassified() {
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

fn shipped() -> Measurement {
    measure(Corpus::load(Path::new(CORPUS_DIR)), profiles::REGISTRY)
}

// ---------------------------------------------------------- load strictness

/// Everything wrong with one document's shape, as printable lines.
fn strictness_failures(document: &Document, registered_language: &str) -> Vec<String> {
    let identity = document.identity;
    let mut failures = Vec::new();

    if document.language != registered_language {
        failures.push(format!(
            "{identity}: identity says language {} but the registry entry says {registered_language}",
            document.language
        ));
    }

    let prefix = format!("{}.{}.", document.profile, document.language);
    for rule in &document.rules {
        if !ALLOWED_SEVERITIES.contains(&rule.severity) {
            failures.push(format!(
                "{identity}: rule {} has severity {}, expected warning or info",
                rule.id, rule.severity
            ));
        }
        let segments: Vec<&str> = rule.id.split('.').collect();
        if segments.len() != 3 || !rule.id.starts_with(&prefix) {
            failures.push(format!(
                "{identity}: rule id {} is not {prefix}<check>",
                rule.id
            ));
        }
        failures.extend(unimplemented_predicates(identity, rule));
    }

    failures
}

/// Predicates a rule's AST queries use that the engine does not implement.
///
/// `engines::ast` runs `QueryCursor::matches`, which applies the text
/// predicates tree-sitter parses - `eq?`, `match?`, `any-of?` and their
/// negations - and nothing else. Anything else is parsed into the query's
/// general predicates, or into its property predicates and settings, all three
/// of which the match loop never reads. A rule narrowed by one of those is not
/// narrowed at all: it matches every node its pattern reaches. So it is refused
/// here, at load, rather than shipped as a rule that means something other than
/// what it says.
fn unimplemented_predicates(identity: &str, rule: &CompiledRule) -> Vec<String> {
    let CompiledPayload::Ast { queries } = &rule.payload else {
        return Vec::new();
    };
    let mut failures = Vec::new();
    for ast in queries {
        let (language, query) = (&ast.language, &ast.query);
        for pattern in 0..query.pattern_count() {
            for predicate in query.general_predicates(pattern) {
                failures.push(format!(
                    "{identity}: rule {} query for {language} pattern {pattern} uses #{}, \
                     which the engine ignores at match time",
                    rule.id, predicate.operator
                ));
            }
            for (property, _) in query.property_predicates(pattern) {
                failures.push(format!(
                    "{identity}: rule {} query for {language} pattern {pattern} uses #is? {}, \
                     which the engine ignores at match time",
                    rule.id, property.key
                ));
            }
            for property in query.property_settings(pattern) {
                failures.push(format!(
                    "{identity}: rule {} query for {language} pattern {pattern} uses #set! {}, \
                     which the engine ignores at match time",
                    rule.id, property.key
                ));
            }
        }
    }
    failures
}

/// Every `*.yaml` / `*.yml` file under `rules/profiles`, as paths relative to
/// it. Absent until the first document lands, which is not a failure.
fn profile_document_files() -> Vec<String> {
    let root = Path::new(PROFILES_DIR);
    if !root.is_dir() {
        return Vec::new();
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
        .into_keys()
        .filter(|path| path.ends_with(".yaml") || path.ends_with(".yml"))
        .collect()
}

// -------------------------------------------------------------------- tests

/// The corpus and its manifest have to agree before either number means
/// anything: a row pointing at a line that does not exist measures nothing, a
/// duplicated row counts one case twice, and a file in the wrong language
/// directory is measured by a document that can never reach it.
#[test]
fn the_corpus_and_its_manifest_agree() {
    let corpus = Corpus::load(Path::new(CORPUS_DIR));

    let mut seen: BTreeSet<(&str, u64)> = BTreeSet::new();
    for row in &corpus.rows {
        let lines = corpus
            .lines_per_file
            .get(&row.path)
            .unwrap_or_else(|| panic!("manifest names {}, which is not in the corpus", row.path));
        assert!(
            row.line >= 1 && row.line <= *lines,
            "manifest points at {}:{}, which has {lines} lines",
            row.path,
            row.line
        );
        assert!(
            row.language().is_some(),
            "manifest names {}, which sits outside a language directory",
            row.path
        );
        assert!(
            seen.insert((row.path.as_str(), row.line)),
            "manifest carries {}:{} twice",
            row.path,
            row.line
        );
        if let Expect::OneOf(ids) = &row.expect {
            for id in ids {
                assert!(
                    id.contains('.')
                        && id.bytes().all(|byte| byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'.'
                            || byte == b'-'),
                    "manifest row {}:{} expects {id}, which is not a rule id",
                    row.path,
                    row.line
                );
            }
        }
    }

    for path in corpus.lines_per_file.keys() {
        let (language, _) = path
            .split_once('/')
            .unwrap_or_else(|| panic!("{path} sits directly under tree/, not in a language"));
        let absolute = corpus.root.join("tree").join(path);
        let content = fs::read_to_string(&absolute).expect("a corpus file is readable UTF-8");
        let detected = lang::detect(&absolute, &content);
        assert_eq!(
            detected,
            Some(language),
            "{path} sits in the {language} directory but is detected as {detected:?}"
        );
    }
}

/// Every shipped document loads, and loads under the rules a profile document
/// contracts: an identity of `<profile>-<language>@<n>`, rule ids of
/// `<profile>.<language>.<check>`, an advisory severity, and no AST predicate
/// the engine does not implement.
#[test]
fn every_shipped_document_loads_strictly() {
    let documents = documents(profiles::REGISTRY);
    let mut failures = Vec::new();
    for (document, profile) in documents.iter().zip(profiles::REGISTRY) {
        failures.extend(strictness_failures(document, profile.language()));
    }
    assert!(
        failures.is_empty(),
        "{} shipped documents are not loadable as profiles:\n{}",
        failures.len(),
        failures.join("\n")
    );

    // A document on disk that no registry entry names is shipped by nobody and
    // measured by nothing, which reads exactly like a passing corpus.
    let registered: BTreeSet<&str> = profiles::REGISTRY
        .iter()
        .map(|profile| profile.document())
        .collect();
    for path in profile_document_files() {
        let absolute = Path::new(PROFILES_DIR).join(&path);
        let source = fs::read_to_string(&absolute).expect("a profile document is readable UTF-8");
        assert!(
            registered.contains(source.as_str()),
            "rules/profiles/{path} is not in profiles::REGISTRY, so nothing loads or measures it"
        );
    }
}

/// A document may not ship a rule the corpus does not measure. Separate from
/// the recall test so a language can land one rule at a time: this one names
/// the rule id that arrived without a row.
#[test]
fn every_shipped_rule_has_a_positive_row() {
    let measurement = shipped();
    let measured: BTreeSet<&str> = measurement
        .corpus
        .rows
        .iter()
        .filter_map(|row| match &row.expect {
            Expect::OneOf(ids) => Some(ids),
            Expect::Nothing => None,
        })
        .flatten()
        .map(String::as_str)
        .collect();

    let uncovered: Vec<String> = measurement
        .shipped_rule_ids()
        .into_iter()
        .filter(|(_, id)| !measured.contains(id))
        .map(|(identity, id)| format!("  {identity} ships {id}, which has no positive row"))
        .collect();

    assert!(
        uncovered.is_empty(),
        "{} shipped rules are not measured by the corpus:\n{}",
        uncovered.len(),
        uncovered.join("\n")
    );
}

/// Recall is held per language, because the languages are not equal: one may
/// ship a tuned set while the next is still contracting a known gap. One global
/// number would let a regression in a strong language hide behind a fix in a
/// weak one.
#[test]
fn profile_recall_meets_its_floor_per_language() {
    let measurement = shipped();
    let stats = measurement.recall_by_language();
    println!("{}", measurement.report());

    for language in measurement.corpus.floors.keys() {
        assert!(
            stats.contains_key(language.as_str()),
            "floors.tsv names {language}, which has no positives in the manifest"
        );
    }

    let failures: Vec<String> = stats
        .iter()
        .filter_map(|(language, (positives, reported))| {
            let recall = *reported as f64 / *positives as f64;
            let floor = measurement.corpus.floor(language);
            (recall < floor).then(|| {
                format!(
                    "language {language}: recall {recall:.4} is below its floor {floor:.4} \
                     ({reported} of {positives} positives reported)"
                )
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{}\n{}",
        measurement.report(),
        failures.join("\n")
    );
}

/// The false-positive budget is per rule and defaults to zero. Per rule
/// because removal is a per-rule decision: a rule that exceeds its limit is
/// not widened or given a bigger number, it is removed from the profile on the
/// second consecutive breach.
#[test]
fn no_rule_exceeds_its_false_positive_limit() {
    let measurement = shipped();
    let spent = measurement.false_positives();

    let mut failures = Vec::new();
    for (rule_id, lines) in &spent {
        let limit = measurement.corpus.limit(rule_id).max_corpus;
        if lines.len() > limit {
            failures.push(format!(
                "rule {rule_id}: {} findings on NONE rows, limit {limit}\n{}",
                lines.len(),
                lines.join("\n")
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{}\n{}",
        measurement.report(),
        failures.join("\n")
    );
}

const IDENTITY: &str = "reliability-rust@1";

const DOCUMENT: &str = r#"
version: 1
rules:
  - id: reliability.rust.self-comparison
    severity: warning
    message: both operands of this comparison are the same identifier
    ast:
      rust: '((binary_expression left: (identifier) @l operator: "==" right: (identifier) @r) @report (#eq? @l @r))'
"#;

/// A rule that reports the negative as well as the positive: every comparison,
/// whatever its operands. What a false-positive limit is for.
const NOISY_DOCUMENT: &str = r#"
version: 1
rules:
  - id: reliability.rust.self-comparison
    severity: warning
    message: a comparison
    ast:
      rust: '(binary_expression left: (identifier) operator: "==" right: (identifier)) @report'
"#;

/// A two-row Rust corpus in a temporary directory: one positive the strict
/// document reports, one negative it leaves alone.
fn in_test_corpus(limits: &str) -> tempfile::TempDir {
    const POSITIVE: &str = "fn f(a: i32) -> bool {\n    a == a\n}\n";
    const NEGATIVE: &str = "fn f(a: i32, b: i32) -> bool {\n    a == b\n}\n";

    let dir = tempfile::tempdir().expect("a temporary directory");
    let root = dir.path();
    fs::create_dir_all(root.join("tree/rust")).expect("the corpus tree is creatable");
    fs::create_dir_all(root.join("noise")).expect("the noise directory is creatable");
    fs::write(root.join("tree/rust/positive.rs"), POSITIVE).expect("the positive is writable");
    fs::write(root.join("tree/rust/negative.rs"), NEGATIVE).expect("the negative is writable");
    fs::write(
        root.join("manifest.tsv"),
        "path\tline\texpect\tjustification\n\
         rust/positive.rs\t2\treliability.rust.self-comparison\tboth operands are the same identifier\n\
         rust/negative.rs\t2\tNONE\tthe operands are two different identifiers\n",
    )
    .expect("the manifest is writable");
    fs::write(
        root.join("floors.tsv"),
        "language\trecall_floor\tmeasured_at\tticket\nrust\t1.0\t2026-09-03\tP3\n",
    )
    .expect("the floors file is writable");
    fs::write(root.join("noise/limits.tsv"), limits).expect("the limits file is writable");
    dir
}

/// The shipped registry is empty until the rule matrix lands documents, so
/// every test above passes over nothing. This one builds a document and a
/// corpus in a temporary directory and runs the identical measurement over
/// them, which is what stops the harness from being an assertion that zero
/// equals zero.
#[test]
fn the_harness_measures_an_in_test_document() {
    let registry = [Profile::new(IDENTITY, "rust", DOCUMENT)];
    let dir = in_test_corpus("rule_id\tmax_corpus\tmax_per_kloc\tmeasured_at\tticket\n");

    let measurement = measure(Corpus::load(dir.path()), &registry);
    println!("{}", measurement.report());

    assert_eq!(
        measurement.recall_by_language(),
        BTreeMap::from([("rust", (1, 1))]),
        "the in-test document reports its positive"
    );
    assert!(
        measurement.false_positives().is_empty(),
        "the in-test document leaves its negative alone"
    );
    assert!(measurement.misses().is_empty(), "{}", measurement.report());
    assert_eq!(
        measurement.shipped_rule_ids(),
        [(IDENTITY, "reliability.rust.self-comparison")]
    );
    assert!(
        strictness_failures(&documents(&registry)[0], "rust").is_empty(),
        "the in-test document is strict"
    );
}

/// The other half of the same argument: a rule that reports a `NONE` row is
/// counted against that rule's own limit, and the limit defaults to zero. The
/// shipped corpus has no negatives to spend, so the counting is proved here.
#[test]
fn the_harness_counts_a_false_positive_against_its_limit() {
    const RULE: &str = "reliability.rust.self-comparison";
    let registry = [Profile::new(IDENTITY, "rust", NOISY_DOCUMENT)];

    let default = in_test_corpus("rule_id\tmax_corpus\tmax_per_kloc\tmeasured_at\tticket\n");
    let measurement = measure(Corpus::load(default.path()), &registry);
    let spent = measurement.false_positives();
    assert_eq!(
        spent.get(RULE).map(Vec::len),
        Some(1),
        "{}",
        measurement.report()
    );
    assert_eq!(
        measurement.corpus.limit(RULE),
        DEFAULT_LIMIT,
        "a rule with no row in limits.tsv is held to zero"
    );

    let granted = in_test_corpus(&format!(
        "rule_id\tmax_corpus\tmax_per_kloc\tmeasured_at\tticket\n{RULE}\t1\t0.5\t2026-09-03\tP3\n"
    ));
    let measurement = measure(Corpus::load(granted.path()), &registry);
    assert_eq!(
        measurement.corpus.limit(RULE),
        Limit {
            max_corpus: 1,
            max_per_kloc: 0.5,
        },
        "a declared limit is what the rule is held to"
    );
}

/// The strictness test has to be able to fail. Each of these is a document the
/// registry must never carry, and each one is refused for its own reason.
#[test]
fn strictness_refuses_what_it_is_there_to_refuse() {
    let cases: [(&str, &str, &str, &str); 4] = [
        (
            "severity",
            "reliability-rust@1",
            "rust",
            "version: 1\nrules:\n  - id: reliability.rust.x\n    severity: error\n    message: m\n    regex:\n      pattern: 'x'\n",
        ),
        (
            "rule id",
            "reliability-rust@1",
            "rust",
            "version: 1\nrules:\n  - id: reliability.x\n    severity: info\n    message: m\n    regex:\n      pattern: 'x'\n",
        ),
        (
            "unimplemented predicate",
            "reliability-rust@1",
            "rust",
            "version: 1\nrules:\n  - id: reliability.rust.x\n    severity: info\n    message: m\n    ast:\n      rust: '((identifier) @report (#is-uppercase? @report))'\n",
        ),
        (
            "registry disagreement",
            "reliability-rust@1",
            "python",
            "version: 1\nrules:\n  - id: reliability.rust.x\n    severity: info\n    message: m\n    regex:\n      pattern: 'x'\n",
        ),
    ];

    for (why, identity, language, source) in cases {
        let rules = load_str(source, identity).expect("the case loads; only its shape is wrong");
        let (profile, identity_language) =
            split_identity(identity).expect("a well-formed identity");
        let document = Document {
            identity,
            profile,
            language: identity_language,
            rules,
            source,
        };
        assert!(
            !strictness_failures(&document, language).is_empty(),
            "a document with a bad {why} is refused"
        );
    }

    for identity in [
        "reliability-rust",
        "reliabilityrust@1",
        "reliability-rust@x",
    ] {
        assert!(
            split_identity(identity).is_err(),
            "{identity} is not <profile>-<language>@<n>"
        );
    }
}
