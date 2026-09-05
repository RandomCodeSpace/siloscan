use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tree_sitter::Query;

use crate::parsers;

const SUPPORTED_VERSION: u32 = 1;

/// Compiled-program budget for a rule's pattern, raised from the `regex`
/// crate's 10 MiB default.
///
/// The default is a library's conservatism about patterns from untrusted
/// input. A rule pattern is not that: it ships in the pack or is written by
/// whoever runs the scan. Two gitleaks patterns - `pypi-upload-token` and
/// `vault-batch-token` - are wide bounded repetitions (`{50,1000}`,
/// `{138,300}`) whose programs are valid and past the default, and that was
/// the only reason they were not translated.
///
/// Measured, on the two, at the spelling each is written in upstream: with
/// Rust's Unicode `\w`, vault's program needs 16 MiB and pypi's 64 MiB, and
/// pypi takes seconds to build. 32 MiB is the budget: it admits a pattern of
/// that shape, and it stops short of the size where compiling one stops being
/// free. The one that did not fit is not what the upstream rule means -
/// gitleaks reads `\w` as ASCII - so the converter ships both with the ASCII
/// class, at which point each program measures 1 MiB and builds in single-digit
/// milliseconds. That is what
/// `the_widest_pack_patterns_compile_inside_the_size_limit` records.
///
/// The cost is paid per pattern that actually has to match, and only up to
/// what that pattern needs: the limit is a ceiling, not an allocation.
/// `oversized_pattern_loads_and_fails_at_first_use` holds the other end - a
/// pattern past even this limit is refused, not truncated.
const PATTERN_SIZE_LIMIT: usize = 32 * 1024 * 1024;

/// Build one rule pattern under [`PATTERN_SIZE_LIMIT`]. Every regex a rule
/// carries is built here - eagerly for a regex payload, on first use for a
/// secret one - so no two paths can disagree about the budget or about the
/// error a pattern past it reports.
fn build_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .build()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("{origin}: io error: {detail}")]
    Io { origin: String, detail: String },

    #[error("{origin}: yaml parse error: {detail}")]
    Yaml { origin: String, detail: String },

    #[error("{origin}: unsupported rule file version: {detail}")]
    UnsupportedVersion { origin: String, detail: String },

    #[error("{origin}: invalid rule id: {detail}")]
    BadId { origin: String, detail: String },

    #[error("{origin}: duplicate rule id: {detail}")]
    DuplicateId { origin: String, detail: String },

    #[error("{origin}: reserved rule id: {detail}")]
    ReservedId { origin: String, detail: String },

    #[error("{origin}: rule has no payload: {detail}")]
    NoPayload { origin: String, detail: String },

    #[error("{origin}: rule has multiple payloads: {detail}")]
    MultiplePayloads { origin: String, detail: String },

    #[error("{origin}: invalid regex pattern: {detail}")]
    BadPattern { origin: String, detail: String },

    #[error("{origin}: invalid capture group: {detail}")]
    BadGroup { origin: String, detail: String },

    #[error("{origin}: invalid glob: {detail}")]
    BadGlob { origin: String, detail: String },

    #[error("{origin}: invalid entropy threshold: {detail}")]
    BadEntropy { origin: String, detail: String },

    #[error("{origin}: ast rule must not set languages: {detail}")]
    AstLanguages { origin: String, detail: String },

    #[error("{origin}: unknown or disabled ast language: {detail}")]
    BadAstLanguage { origin: String, detail: String },

    #[error("{origin}: invalid ast query: {detail}")]
    BadAstQuery { origin: String, detail: String },

    #[error("{origin}: {kind} rule must not set languages: {detail}")]
    PayloadLanguages {
        origin: String,
        kind: String,
        detail: String,
    },

    #[error("{origin}: invalid silo name: {detail}")]
    BadSilo { origin: String, detail: String },

    #[error("{origin}: boundary rule has an empty deny list: {detail}")]
    EmptyDeny { origin: String, detail: String },

    #[error("{origin}: invalid coverage minimum: {detail}")]
    BadCoverageMin { origin: String, detail: String },

    #[error("{origin}: invalid duplication threshold: {detail}")]
    BadDuplicationMax { origin: String, detail: String },

    #[error("{origin}: unknown duplication scope: {detail}")]
    BadDuplicationScope { origin: String, detail: String },

    #[error("{origin}: unknown metric measure: {detail}")]
    BadMetricMeasure { origin: String, detail: String },

    #[error("{origin}: invalid metric maximum: {detail}")]
    BadMetricMax { origin: String, detail: String },

    #[error("{origin}: metric language has no node-kind table: {detail}")]
    BadMetricLanguage { origin: String, detail: String },
}

// Raw schema. `deny_unknown_fields` does not compose with `serde(flatten)`, so
// every payload variant is a plain optional field instead.

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    pub version: u32,
    pub rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,
    pub severity: Severity,
    pub message: String,
    pub languages: Option<Vec<String>>,
    pub paths: Option<RawPaths>,
    pub metadata: Option<RawMetadata>,
    pub regex: Option<RawRegex>,
    pub secret: Option<RawSecret>,
    /// Language name -> tree-sitter query source. `BTreeMap` so the compiled
    /// order is deterministic regardless of the order written in YAML.
    pub ast: Option<BTreeMap<String, String>>,
    pub boundary: Option<RawBoundary>,
    pub coverage: Option<RawCoverage>,
    pub duplication: Option<RawDuplication>,
    pub metric: Option<RawMetric>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPaths {
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    /// Match `include` and `exclude` without regard to case. Absent means
    /// false, so every rule written before this field keeps the exact matching
    /// it was written against.
    ///
    /// Opt-in per rule rather than global because case sensitivity is a
    /// property of what the rule describes, not of the scanner: `Makefile` and
    /// `makefile` are different files, while a `.P12` keystore is a keystore.
    /// The translated gitleaks rules set it because their upstream path
    /// constraints are `(?i)` regexes.
    pub case_insensitive: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMetadata {
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRegex {
    pub pattern: String,
    pub group: Option<usize>,
    /// Withhold the match text from JSON, SARIF and the terminal, exactly as a
    /// secret rule's is. Absent means false: most regex rules match code, and
    /// their match text is the point of the finding.
    pub redact: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSecret {
    pub pattern: String,
    pub group: Option<usize>,
    pub entropy: Option<f64>,
    pub keywords: Option<Vec<String>>,
    pub allowlist: Option<RawAllowlist>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBoundary {
    /// Silo the rule constrains.
    pub from: String,
    /// Silos `from` must not import. Never empty.
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCoverage {
    /// Minimum line coverage percentage, 0..=100.
    pub min: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDuplication {
    /// Maximum duplicated-line percentage, 0 < max_percent <= 100.
    pub max_percent: f64,
    /// `scan`, `file` or `silo`. Absent means `scan`. Kept as a string so an
    /// unknown value reports a scope error naming the rule rather than a
    /// generic deserialization failure.
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMetric {
    /// `function-length`, `parameter-count`, `nesting-depth` or
    /// `cyclomatic-complexity`. Kept as a string so an unknown value reports a
    /// measure error naming the rule rather than a generic deserialization
    /// failure, exactly as a duplication scope does.
    pub measure: String,
    /// Threshold the measure must exceed to report. Signed so a negative value
    /// reports a range error naming the rule instead of a serde type error.
    pub max: i64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAllowlist {
    pub patterns: Option<Vec<String>>,
    pub paths: Option<Vec<String>>,
    pub stopwords: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
    /// `(origin, raw source)` for every rule document that produced `rules`, in
    /// load order. Callers that assemble a `RuleSet` by hand should record the
    /// same pairs, otherwise the set has no identity to hash.
    pub sources: Vec<(String, String)>,
}

impl RuleSet {
    /// Stable digest of the rule sources in load order. Any change to a rule
    /// document, its origin, or the order they were loaded in changes the
    /// digest, which is what makes it usable as a cache key component.
    pub fn source_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for (origin, source) in &self.sources {
            hasher.update((origin.len() as u64).to_le_bytes());
            hasher.update(origin.as_bytes());
            hasher.update((source.len() as u64).to_le_bytes());
            hasher.update(source.as_bytes());
        }
        let digest = hasher.finalize();

        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub severity: Severity,
    pub message: String,
    pub languages: Option<Vec<String>>,
    pub include: Option<GlobSet>,
    pub exclude: Option<GlobSet>,
    pub payload: CompiledPayload,
}

/// A deferred pattern that passed load-time validation but could not be
/// compiled when the rule first had to match.
///
/// This is a scan error, not a load error: it is raised from the engine that
/// asked for the regex, and it aborts the scan rather than dropping the rule.
/// A disabled secret rule reports nothing, and a scan that reports nothing is
/// indistinguishable from a clean one, so there is no safe way to continue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rule {rule_id}: regex compile failed at first use: {detail}")]
pub struct RegexCompileError {
    /// Id of the rule the pattern belongs to.
    pub rule_id: String,
    /// The `regex` crate's error, prefixed by the pattern's context.
    pub detail: String,
}

/// A secret rule's pattern: source text plus the regex it compiles to, built on
/// first use.
///
/// The built-in pack carries ~200 gitleaks-derived patterns. Compiling them all
/// costs seconds of wall time and hundreds of megabytes of resident memory
/// before a single file is read, and the keyword prefilter means most of them
/// never run against a given repository. So the pattern is validated at load
/// with `regex_syntax` - the same parser the `regex` crate uses - and the regex
/// itself is built the first time a rule actually has to match.
///
/// Trade-off: syntax errors and out-of-range capture groups still fail the load
/// with the same errors and the same messages as an eager compile. The one
/// class that moves is `CompiledTooBig`: a syntactically valid pattern whose
/// compiled program exceeds the regex size limit is discovered at first use
/// instead of at load. It is still reported - `get` hands the caller a
/// `RegexCompileError` naming the rule, which the engine turns into a failed
/// scan. Only when the failure is raised moves; a bad pattern never silently
/// disables its rule, and nothing about a pattern's meaning changes.
///
/// The outcome is memoized either way, so a pattern is compiled at most once
/// per rule and every later call reports the identical error.
///
/// Every field here is carried by each of the pack's ~200 rules and sits inside
/// `CompiledPayload`, so the identity is stored as narrowly as it can be: a
/// boxed id, a static context, and a boxed error that only exists on the
/// failure path.
pub struct LazyRegex {
    /// Rule this pattern belongs to, named in a compile failure.
    rule_id: Box<str>,
    /// Prefix for a compile failure's detail, e.g. `"allowlist: "`.
    context: &'static str,
    pattern: String,
    /// Records the outcome, failure included, so a pattern is attempted once
    /// rather than per file.
    compiled: OnceLock<Result<Regex, Box<RegexCompileError>>>,
}

impl LazyRegex {
    /// Wraps a pattern whose syntax has already been validated. Callers that
    /// skip validation only move the failure to first use, where it surfaces as
    /// a `RegexCompileError` instead of a `LoadError`.
    pub fn new(rule_id: &str, context: &'static str, pattern: String) -> Self {
        LazyRegex {
            rule_id: rule_id.into(),
            context,
            pattern,
            compiled: OnceLock::new(),
        }
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// The compiled regex, building it on first call. `Err` means the pattern
    /// parses but cannot be compiled - in practice, not within the regex size
    /// limit - and the caller must fail rather than skip the rule.
    pub fn get(&self) -> Result<&Regex, &RegexCompileError> {
        match self.compiled.get_or_init(|| {
            build_regex(&self.pattern).map_err(|e| {
                Box::new(RegexCompileError {
                    rule_id: self.rule_id.to_string(),
                    detail: format!("{}{e}", self.context),
                })
            })
        }) {
            Ok(regex) => Ok(regex),
            Err(error) => Err(error),
        }
    }

    /// Whether the compile has been attempted yet. Load must leave this
    /// `false`.
    pub fn is_compiled(&self) -> bool {
        self.compiled.get().is_some()
    }
}

impl Clone for LazyRegex {
    fn clone(&self) -> Self {
        let compiled = OnceLock::new();
        if let Some(outcome) = self.compiled.get() {
            let _ = compiled.set(outcome.clone());
        }
        LazyRegex {
            rule_id: self.rule_id.clone(),
            context: self.context,
            pattern: self.pattern.clone(),
            compiled,
        }
    }
}

impl fmt::Debug for LazyRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyRegex")
            .field("rule_id", &self.rule_id)
            .field("pattern", &self.pattern)
            .field("compiled", &self.is_compiled())
            .finish()
    }
}

/// The set a duplication gate measures its density over.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DuplicationScope {
    /// The whole set of files the rule's path filter matched.
    #[default]
    Scan,
    /// Each matched file on its own.
    File,
    /// Each silo the matched files belong to.
    Silo,
}

impl DuplicationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            DuplicationScope::Scan => "scan",
            DuplicationScope::File => "file",
            DuplicationScope::Silo => "silo",
        }
    }

    /// Parses a scope as written in a rule document. `None` means the value is
    /// not one of the three scopes.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "scan" => Some(DuplicationScope::Scan),
            "file" => Some(DuplicationScope::File),
            "silo" => Some(DuplicationScope::Silo),
            _ => None,
        }
    }
}

impl fmt::Display for DuplicationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a metric rule measures over one function-like node.
///
/// The definitions live with the engine that computes them, in
/// [`crate::engines::metric`]; this is only the name a rule document writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Measure {
    /// Lines the function node spans, first and last included.
    FunctionLength,
    /// Parameters in the function's parameter list.
    ParameterCount,
    /// Deepest run of nesting constructs inside the function.
    NestingDepth,
    /// One plus the branch points inside the function.
    CyclomaticComplexity,
}

impl Measure {
    pub fn as_str(self) -> &'static str {
        match self {
            Measure::FunctionLength => "function-length",
            Measure::ParameterCount => "parameter-count",
            Measure::NestingDepth => "nesting-depth",
            Measure::CyclomaticComplexity => "cyclomatic-complexity",
        }
    }

    /// Parses a measure as written in a rule document. `None` means the value
    /// is not one of the four measures.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "function-length" => Some(Measure::FunctionLength),
            "parameter-count" => Some(Measure::ParameterCount),
            "nesting-depth" => Some(Measure::NestingDepth),
            "cyclomatic-complexity" => Some(Measure::CyclomaticComplexity),
            _ => None,
        }
    }
}

impl fmt::Display for Measure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One language's tree-sitter query for an ast rule.
///
/// The `source` is kept next to the compiled query because the engine builds
/// one combined query per language out of every applicable rule's patterns, and
/// tree-sitter has no way to merge two compiled queries.
#[derive(Debug, Clone)]
pub struct AstQuery {
    pub language: String,
    pub source: String,
    pub query: Arc<Query>,
}

#[derive(Debug, Clone)]
pub enum CompiledPayload {
    Regex {
        regex: Regex,
        group: Option<usize>,
        /// Opt-in redaction of this rule's match text. See
        /// `crate::output::redacts_match` for what reads it.
        redact: bool,
    },
    Secret {
        pattern: LazyRegex,
        group: Option<usize>,
        entropy: Option<f64>,
        /// Lowercased at compile time; callers compare against lowercased input.
        keywords: Vec<String>,
        allow_patterns: Vec<LazyRegex>,
        allow_paths: Option<GlobSet>,
        /// Lowercased at compile time.
        stopwords: Vec<String>,
    },
    Ast {
        /// Sorted by language; queries are shared, never mutated.
        queries: Vec<AstQuery>,
    },
    Boundary {
        /// Silo names are format-checked at load; whether they exist is
        /// checked at scan setup against the repository config.
        from: String,
        deny: Vec<String>,
    },
    Coverage {
        min: f64,
    },
    Duplication {
        /// Density above which the gate reports, in percent.
        max_percent: f64,
        scope: DuplicationScope,
    },
    Metric {
        measure: Measure,
        /// A function reports when its measure is strictly greater than this.
        max: u32,
    },
    /// The file existing at a matching path is the whole finding. Carries no
    /// data: everything it reports - the id, the severity, the message and the
    /// `paths` envelope that selects the files - already sits on the rule.
    ///
    /// Written as a rule with a `paths.include` and no payload block. A
    /// committed keystore is a finding because of what it is, not because of
    /// anything readable inside it, which is also why this is the one rule
    /// shape that reports on a file the scan never read as text.
    Presence,
}

fn id_pattern() -> &'static Regex {
    static ID: OnceLock<Regex> = OnceLock::new();
    ID.get_or_init(|| Regex::new(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$").expect("static id pattern"))
}

/// Load every `*.yaml` / `*.yml` rule file under each directory, in a
/// deterministic (bytewise path) order, and reject duplicate ids across files.
pub fn load_dirs(dirs: &[PathBuf]) -> Result<RuleSet, LoadError> {
    let mut files = Vec::new();
    for dir in dirs {
        collect_rule_files(dir, &mut files)?;
    }
    files.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });

    let mut rules: Vec<CompiledRule> = Vec::new();
    let mut sources: Vec<(String, String)> = Vec::new();
    let mut seen: HashMap<String, String> = HashMap::new();

    for file in &files {
        let origin = file.display().to_string();
        let src = fs::read_to_string(file).map_err(|e| LoadError::Io {
            origin: origin.clone(),
            detail: e.to_string(),
        })?;
        sources.push((origin.clone(), src.clone()));
        for rule in load_str(&src, &origin)? {
            if let Some(first) = seen.get(&rule.id) {
                return Err(LoadError::DuplicateId {
                    origin: origin.clone(),
                    detail: format!("{} (already defined in {first})", rule.id),
                });
            }
            seen.insert(rule.id.clone(), origin.clone());
            rules.push(rule);
        }
    }

    Ok(RuleSet { rules, sources })
}

fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), LoadError> {
    let entries = fs::read_dir(dir).map_err(|e| LoadError::Io {
        origin: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| LoadError::Io {
            origin: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_rule_files(&path, out)?;
        } else if is_yaml(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_yaml(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"),
        None => false,
    }
}

pub fn load_str(src: &str, origin: &str) -> Result<Vec<CompiledRule>, LoadError> {
    let file: RuleFile = serde_norway::from_str(src).map_err(|e| LoadError::Yaml {
        origin: origin.to_string(),
        detail: e.to_string(),
    })?;

    if file.version != SUPPORTED_VERSION {
        return Err(LoadError::UnsupportedVersion {
            origin: origin.to_string(),
            detail: file.version.to_string(),
        });
    }

    let workers = compile_workers(file.rules.len());
    let results = compile_rules(file.rules, origin, workers);

    let mut compiled = Vec::with_capacity(results.len());
    let mut seen: HashMap<String, ()> = HashMap::new();

    // Results are consumed in rule order, and a rule's own error is raised
    // before its id is checked, so the first error reported is the one a
    // sequential compile would have reported.
    for result in results {
        let rule = result?;
        if seen.insert(rule.id.clone(), ()).is_some() {
            return Err(LoadError::DuplicateId {
                origin: origin.to_string(),
                detail: rule.id,
            });
        }
        compiled.push(rule);
    }

    Ok(compiled)
}

/// Rules per worker below which spawning threads costs more than it saves.
const RULES_PER_COMPILE_WORKER: usize = 16;

/// Compile every rule of one document across `workers` threads. The returned
/// results are in rule order whatever the worker count is; deciding what to do
/// with them is the caller's job.
fn compile_rules(
    raws: Vec<RawRule>,
    origin: &str,
    workers: usize,
) -> Vec<Result<CompiledRule, LoadError>> {
    if workers < 2 {
        return raws
            .into_iter()
            .map(|raw| compile_rule(raw, origin))
            .collect();
    }

    // Each worker owns a disjoint slice and takes the rules out of it, so the
    // rules move exactly once and stay in order.
    let mut slots: Vec<Option<RawRule>> = raws.into_iter().map(Some).collect();
    let per_worker = slots.len().div_ceil(workers);
    let mut parts: Vec<Vec<Result<CompiledRule, LoadError>>> = Vec::with_capacity(workers);

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for chunk in slots.chunks_mut(per_worker) {
            handles.push(scope.spawn(move || {
                chunk
                    .iter_mut()
                    .map(|slot| {
                        let raw = slot.take().expect("every slot is taken exactly once");
                        compile_rule(raw, origin)
                    })
                    .collect::<Vec<_>>()
            }));
        }
        for handle in handles {
            match handle.join() {
                Ok(part) => parts.push(part),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
    });

    parts.into_iter().flatten().collect()
}

fn compile_workers(rules: usize) -> usize {
    if rules < RULES_PER_COMPILE_WORKER * 2 {
        return 1;
    }
    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    available.min(rules.div_ceil(RULES_PER_COMPILE_WORKER))
}

fn compile_rule(raw: RawRule, origin: &str) -> Result<CompiledRule, LoadError> {
    if !id_pattern().is_match(&raw.id) {
        return Err(LoadError::BadId {
            origin: origin.to_string(),
            detail: raw.id,
        });
    }

    // The scanner emits findings under this id itself, so a rule claiming it
    // would produce two unrelated kinds of finding under one identity.
    if raw.id == crate::metrics::DUPLICATE_BLOCK_RULE_ID {
        return Err(LoadError::ReservedId {
            origin: origin.to_string(),
            detail: format!("{} is emitted by the duplication metrics", raw.id),
        });
    }

    let mut kinds: Vec<&'static str> = Vec::new();
    if raw.regex.is_some() {
        kinds.push("regex");
    }
    if raw.secret.is_some() {
        kinds.push("secret");
    }
    if raw.ast.is_some() {
        kinds.push("ast");
    }
    if raw.boundary.is_some() {
        kinds.push("boundary");
    }
    if raw.coverage.is_some() {
        kinds.push("coverage");
    }
    if raw.duplication.is_some() {
        kinds.push("duplication");
    }
    if raw.metric.is_some() {
        kinds.push("metric");
    }

    match kinds.len() {
        0 => {
            // A rule with no payload block is a presence rule: the file
            // existing at a path the envelope selects is the finding. The
            // envelope is therefore the whole rule, and a rule without one
            // would either report every file in the tree or, with only an
            // `exclude`, be a rule nobody can read the intent of. Both are a
            // missing payload rather than a rule shape, so this is still the
            // no-payload error, with a detail that says what is missing.
            if !has_include(raw.paths.as_ref()) {
                return Err(LoadError::NoPayload {
                    origin: origin.to_string(),
                    detail: format!(
                        "{}: a rule with no payload is a presence rule and must set paths.include",
                        raw.id
                    ),
                });
            }
            kinds.push("presence");
        }
        1 => {}
        _ => {
            return Err(LoadError::MultiplePayloads {
                origin: origin.to_string(),
                detail: format!("{}: {}", raw.id, kinds.join(", ")),
            });
        }
    }

    if raw.ast.is_some() && raw.languages.is_some() {
        return Err(LoadError::AstLanguages {
            origin: origin.to_string(),
            detail: raw.id,
        });
    }

    // Boundary, coverage and duplication rules are evaluated per silo, per
    // report and per metrics set, not per source language, so a `languages`
    // filter would be meaningless. A presence rule reports a file the scan
    // never read, and a language is detected from content, so a `languages`
    // filter on one could only ever match nothing.
    if raw.languages.is_some()
        && let Some(kind) = ["boundary", "coverage", "duplication", "presence"]
            .into_iter()
            .find(|k| kinds.contains(k))
    {
        return Err(LoadError::PayloadLanguages {
            origin: origin.to_string(),
            kind: kind.to_string(),
            detail: raw.id,
        });
    }

    let mut languages = raw.languages;
    let payload = if let Some(spec) = raw.regex {
        compile_regex(&raw.id, spec, origin)?
    } else if let Some(spec) = raw.secret {
        compile_secret(&raw.id, spec, origin)?
    } else if let Some(spec) = raw.ast {
        let queries = compile_ast(&raw.id, spec, origin)?;
        // An ast rule's language coverage is exactly its query map keys.
        languages = Some(queries.iter().map(|q| q.language.clone()).collect());
        CompiledPayload::Ast { queries }
    } else if let Some(spec) = raw.boundary {
        compile_boundary(&raw.id, spec, origin)?
    } else if let Some(spec) = raw.coverage {
        compile_coverage(&raw.id, spec, origin)?
    } else if let Some(spec) = raw.duplication {
        compile_duplication(&raw.id, spec, origin)?
    } else if let Some(spec) = raw.metric {
        // A metric rule's `languages` is the ordinary rule-level filter, so it
        // needs no envelope of its own; what it does need is that every name it
        // carries is a language the engine has a node-kind table for.
        if let Some(languages) = &languages {
            for lang in languages {
                if !crate::engines::metric::has_kinds(lang) {
                    return Err(LoadError::BadMetricLanguage {
                        origin: origin.to_string(),
                        detail: format!("{}: {lang}", raw.id),
                    });
                }
            }
        }
        compile_metric(&raw.id, spec, origin)?
    } else {
        // The only payload left: the count was checked above, and a zero count
        // with an include was turned into `presence` there.
        CompiledPayload::Presence
    };

    let (include, exclude) = match raw.paths {
        Some(paths) => {
            let fold_case = paths.case_insensitive.unwrap_or(false);
            (
                compile_globs(paths.include, origin, fold_case)?,
                compile_globs(paths.exclude, origin, fold_case)?,
            )
        }
        None => (None, None),
    };

    Ok(CompiledRule {
        id: raw.id,
        severity: raw.severity,
        message: raw.message,
        languages,
        include,
        exclude,
        payload,
    })
}

fn compile_regex(id: &str, spec: RawRegex, origin: &str) -> Result<CompiledPayload, LoadError> {
    let regex = compile_pattern(id, &spec.pattern, origin)?;
    check_group(id, &regex, spec.group, origin)?;

    Ok(CompiledPayload::Regex {
        regex,
        group: spec.group,
        redact: spec.redact.unwrap_or(false),
    })
}

fn compile_secret(id: &str, spec: RawSecret, origin: &str) -> Result<CompiledPayload, LoadError> {
    let pattern = lazy_pattern(id, spec.pattern, spec.group, origin, "")?;

    if let Some(entropy) = spec.entropy
        && (!entropy.is_finite() || entropy < 0.0)
    {
        return Err(LoadError::BadEntropy {
            origin: origin.to_string(),
            detail: format!("{id}: {entropy}"),
        });
    }

    let allowlist = spec.allowlist.unwrap_or_default();

    let mut allow_patterns = Vec::new();
    for pattern in allowlist.patterns.unwrap_or_default() {
        allow_patterns.push(lazy_pattern(id, pattern, None, origin, "allowlist: ")?);
    }

    // Case-sensitive, always: an allowlist path is written by whoever wrote the
    // rule, and the rule-level `case_insensitive` is about the shapes an
    // upstream constraint describes, not about how this rule's own exemptions
    // are spelled.
    let allow_paths = compile_globs(allowlist.paths, origin, false)?;

    Ok(CompiledPayload::Secret {
        pattern,
        group: spec.group,
        entropy: spec.entropy,
        keywords: lowercased(spec.keywords),
        allow_patterns,
        allow_paths,
        stopwords: lowercased(allowlist.stopwords),
    })
}

fn compile_boundary(
    id: &str,
    spec: RawBoundary,
    origin: &str,
) -> Result<CompiledPayload, LoadError> {
    if spec.deny.is_empty() {
        return Err(LoadError::EmptyDeny {
            origin: origin.to_string(),
            detail: id.to_string(),
        });
    }

    for name in std::iter::once(&spec.from).chain(spec.deny.iter()) {
        if !crate::config::is_silo_name(name) {
            return Err(LoadError::BadSilo {
                origin: origin.to_string(),
                detail: format!("{id}: {name}"),
            });
        }
    }

    Ok(CompiledPayload::Boundary {
        from: spec.from,
        deny: spec.deny,
    })
}

fn compile_coverage(
    id: &str,
    spec: RawCoverage,
    origin: &str,
) -> Result<CompiledPayload, LoadError> {
    if !spec.min.is_finite() || !(0.0..=100.0).contains(&spec.min) {
        return Err(LoadError::BadCoverageMin {
            origin: origin.to_string(),
            detail: format!("{id}: {}", spec.min),
        });
    }

    Ok(CompiledPayload::Coverage { min: spec.min })
}

fn compile_duplication(
    id: &str,
    spec: RawDuplication,
    origin: &str,
) -> Result<CompiledPayload, LoadError> {
    // A threshold of zero would report any duplication at all through a gate
    // whose whole purpose is to carry a budget, so the range is exclusive at
    // the bottom.
    if !spec.max_percent.is_finite() || spec.max_percent <= 0.0 || spec.max_percent > 100.0 {
        return Err(LoadError::BadDuplicationMax {
            origin: origin.to_string(),
            detail: format!("{id}: {}", spec.max_percent),
        });
    }

    let scope = match spec.scope.as_deref() {
        None => DuplicationScope::Scan,
        Some(value) => {
            DuplicationScope::parse(value).ok_or_else(|| LoadError::BadDuplicationScope {
                origin: origin.to_string(),
                detail: format!("{id}: {value} (expected scan, file or silo)"),
            })?
        }
    };

    Ok(CompiledPayload::Duplication {
        max_percent: spec.max_percent,
        scope,
    })
}

fn compile_metric(id: &str, spec: RawMetric, origin: &str) -> Result<CompiledPayload, LoadError> {
    let measure = Measure::parse(&spec.measure).ok_or_else(|| LoadError::BadMetricMeasure {
        origin: origin.to_string(),
        detail: format!(
            "{id}: {} (expected function-length, parameter-count, nesting-depth or \
             cyclomatic-complexity)",
            spec.measure
        ),
    })?;

    let max = u32::try_from(spec.max).map_err(|_| LoadError::BadMetricMax {
        origin: origin.to_string(),
        detail: format!("{id}: {}", spec.max),
    })?;

    Ok(CompiledPayload::Metric { measure, max })
}

fn compile_ast(
    id: &str,
    spec: BTreeMap<String, String>,
    origin: &str,
) -> Result<Vec<AstQuery>, LoadError> {
    if spec.is_empty() {
        return Err(LoadError::NoPayload {
            origin: origin.to_string(),
            detail: format!("{id}: ast has no languages"),
        });
    }

    let mut queries = Vec::with_capacity(spec.len());
    // `BTreeMap` iterates in key order, so `queries` is sorted by language.
    for (lang, source) in spec {
        let language = parsers::language(&lang).ok_or_else(|| LoadError::BadAstLanguage {
            origin: origin.to_string(),
            detail: format!("{id}: {lang}"),
        })?;
        let query = Query::new(&language, &source).map_err(|e| LoadError::BadAstQuery {
            origin: origin.to_string(),
            detail: format!("{id}: {lang}: {e}"),
        })?;
        queries.push(AstQuery {
            language: lang,
            source,
            query: Arc::new(query),
        });
    }

    Ok(queries)
}

/// Whether a `paths` envelope names at least one include glob. A presence rule
/// is exactly the rule that needs one.
fn has_include(paths: Option<&RawPaths>) -> bool {
    paths
        .and_then(|paths| paths.include.as_ref())
        .is_some_and(|include| !include.is_empty())
}

fn lowercased(values: Option<Vec<String>>) -> Vec<String> {
    values
        .unwrap_or_default()
        .iter()
        .map(|v| v.to_lowercase())
        .collect()
}

fn compile_pattern(id: &str, pattern: &str, origin: &str) -> Result<Regex, LoadError> {
    build_regex(pattern).map_err(|e| LoadError::BadPattern {
        origin: origin.to_string(),
        detail: format!("{id}: {e}"),
    })
}

/// Validate a pattern without compiling it, and hand back the deferred regex.
///
/// `regex_syntax::Parser` is the parser `Regex::new` runs first, with the same
/// default configuration, so every error it reports - and the message it
/// reports it with - is the one an eager compile would have produced. The HIR
/// also carries the exact capture count, so the group check is unchanged.
/// `context` prefixes the error detail, e.g. `"allowlist: "`, both here and in
/// the compile error the returned `LazyRegex` may raise later.
fn lazy_pattern(
    id: &str,
    pattern: String,
    group: Option<usize>,
    origin: &str,
    context: &'static str,
) -> Result<LazyRegex, LoadError> {
    let hir = regex_syntax::Parser::new()
        .parse(&pattern)
        .map_err(|e| LoadError::BadPattern {
            origin: origin.to_string(),
            detail: format!("{id}: {context}{e}"),
        })?;

    // `captures_len` counts the implicit whole-match group; the HIR does not.
    let captures_len = hir.properties().explicit_captures_len() + 1;
    check_group_count(id, captures_len, group, origin)?;

    Ok(LazyRegex::new(id, context, pattern))
}

fn check_group(
    id: &str,
    regex: &Regex,
    group: Option<usize>,
    origin: &str,
) -> Result<(), LoadError> {
    check_group_count(id, regex.captures_len(), group, origin)
}

fn check_group_count(
    id: &str,
    captures_len: usize,
    group: Option<usize>,
    origin: &str,
) -> Result<(), LoadError> {
    if let Some(group) = group
        && group >= captures_len
    {
        return Err(LoadError::BadGroup {
            origin: origin.to_string(),
            detail: format!("{id}: group {group} out of range (pattern has {captures_len} groups)"),
        });
    }
    Ok(())
}

fn compile_globs(
    patterns: Option<Vec<String>>,
    origin: &str,
    case_insensitive: bool,
) -> Result<Option<GlobSet>, LoadError> {
    let patterns = match patterns {
        Some(p) => p,
        None => return Ok(None),
    };

    let mut builder = GlobSetBuilder::new();
    for pattern in &patterns {
        // Matched against forward-slash relative paths on every platform, so
        // the syntax is pinned too: `\` escapes everywhere, not globset's
        // Windows default of treating it as a separator.
        let glob = GlobBuilder::new(pattern)
            .backslash_escape(true)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|e| LoadError::BadGlob {
                origin: origin.to_string(),
                detail: e.to_string(),
            })?;
        builder.add(glob);
    }

    let set = builder.build().map_err(|e| LoadError::BadGlob {
        origin: origin.to_string(),
        detail: e.to_string(),
    })?;
    Ok(Some(set))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
version: 1
rules:
  - id: rust.unwrap-used
    severity: warning
    message: "avoid unwrap"
    languages: ["rust"]
    paths:
      include: ["**/*.rs"]
      exclude: ["**/tests/**"]
    metadata:
      description: "unwrap panics"
      references: ["https://example.invalid"]
      tags: ["reliability"]
    regex:
      pattern: "\\.unwrap\\(\\)"
"#;

    #[test]
    fn severity_orders_and_renders() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(
            serde_json::to_string(&Severity::Warning).unwrap(),
            "\"warning\""
        );
    }

    #[test]
    fn valid_regex_rule_loads() {
        let rules = load_str(VALID, "test").expect("should load");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.id, "rust.unwrap-used");
        assert_eq!(rule.severity, Severity::Warning);
        assert_eq!(rule.languages.as_deref(), Some(&["rust".to_string()][..]));
        assert!(rule.include.as_ref().unwrap().is_match("src/main.rs"));
        assert!(rule.exclude.as_ref().unwrap().is_match("src/tests/a.rs"));
        match &rule.payload {
            CompiledPayload::Regex {
                regex,
                group,
                redact,
            } => {
                assert!(regex.is_match("x.unwrap()"));
                assert_eq!(*group, None);
                assert!(!redact, "redact defaults to false");
            }
            other => panic!("expected a regex payload, got {other:?}"),
        }
    }

    #[test]
    fn valid_secret_rule_loads() {
        let src = r#"
version: 1
rules:
  - id: aws.access-key
    severity: error
    message: "aws key"
    secret:
      pattern: '(AKIA[0-9A-Z]{16})'
      group: 1
      entropy: 3.5
      keywords: ["AKIA", "Aws"]
      allowlist:
        patterns: ["EXAMPLE$"]
        paths: ["**/testdata/**"]
        stopwords: ["Sample", "FAKE"]
"#;
        let rules = load_str(src, "test").expect("should load");
        assert_eq!(rules.len(), 1);
        match &rules[0].payload {
            CompiledPayload::Secret {
                pattern,
                group,
                entropy,
                keywords,
                allow_patterns,
                allow_paths,
                stopwords,
            } => {
                assert!(
                    pattern
                        .get()
                        .expect("compiles")
                        .is_match("AKIAIOSFODNN7EXAMPLE")
                );
                assert_eq!(*group, Some(1));
                assert_eq!(*entropy, Some(3.5));
                assert_eq!(keywords, &["akia".to_string(), "aws".to_string()]);
                assert_eq!(allow_patterns.len(), 1);
                assert!(
                    allow_patterns[0]
                        .get()
                        .expect("compiles")
                        .is_match("AKIAIOSFODNN7EXAMPLE")
                );
                assert!(allow_paths.as_ref().unwrap().is_match("src/testdata/a.tf"));
                assert_eq!(stopwords, &["sample".to_string(), "fake".to_string()]);
            }
            other => panic!("expected a secret payload, got {other:?}"),
        }
    }

    #[test]
    fn secret_defaults_are_empty() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret: { pattern: "x" }
"#;
        let rules = load_str(src, "test").expect("should load");
        match &rules[0].payload {
            CompiledPayload::Secret {
                group,
                entropy,
                keywords,
                allow_patterns,
                allow_paths,
                stopwords,
                ..
            } => {
                assert_eq!(*group, None);
                assert_eq!(*entropy, None);
                assert!(keywords.is_empty());
                assert!(allow_patterns.is_empty());
                assert!(allow_paths.is_none());
                assert!(stopwords.is_empty());
            }
            other => panic!("expected a secret payload, got {other:?}"),
        }
    }

    /// A pattern that is valid but expensive to compile: the point of deferring
    /// the compile is that a rule like this costs nothing until it runs.
    const HEAVY: &str = r"needle-[A-Za-z0-9]{200,400}(?:-[A-Za-z0-9]{50,100}){0,8}";

    fn secret_payload(rule: &CompiledRule) -> (&LazyRegex, &Vec<LazyRegex>) {
        match &rule.payload {
            CompiledPayload::Secret {
                pattern,
                allow_patterns,
                ..
            } => (pattern, allow_patterns),
            other => panic!("expected a secret payload, got {other:?}"),
        }
    }

    #[test]
    fn secret_patterns_are_not_compiled_at_load() {
        let src = format!(
            "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    secret:\n      pattern: '{HEAVY}'\n      keywords: ['needle-']\n      allowlist:\n        patterns: ['-DEMO$']\n"
        );
        let rules = load_str(&src, "test").expect("should load");
        let (pattern, allow) = secret_payload(&rules[0]);
        assert!(!pattern.is_compiled(), "load must not compile the pattern");
        assert_eq!(pattern.pattern(), HEAVY);
        assert!(!allow[0].is_compiled(), "load must not compile allowlist");

        // A file the keyword prefilter rejects still must not compile it.
        let none = crate::engines::secret::scan_file(&rules, "f.txt", None, "haystack\n")
            .expect("no rule ran");
        assert!(none.is_empty());
        let (pattern, _) = secret_payload(&rules[0]);
        assert!(!pattern.is_compiled(), "a filtered rule must not compile");

        // Only a rule that actually has to match pays for its pattern.
        let hit = format!("needle-{}\n", "Aa1Bb2Cc3D".repeat(25));
        let found =
            crate::engines::secret::scan_file(&rules, "f.txt", None, &hit).expect("compiles");
        assert_eq!(found.len(), 1);
        let (pattern, allow) = secret_payload(&rules[0]);
        assert!(pattern.is_compiled());
        assert!(allow[0].is_compiled(), "a match consults the allowlist");
    }

    /// Valid syntax, but the compiled program is far past
    /// [`PATTERN_SIZE_LIMIT`], never mind the crate default under it.
    /// `regex_syntax` accepts it, so it survives load and only fails when a
    /// rule actually needs it.
    const OVERSIZED: &str = r"needle-(?:[A-Za-z0-9]{1000}){1000}";

    fn oversized_rules() -> Vec<CompiledRule> {
        let src = format!(
            "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    secret:\n      pattern: '{OVERSIZED}'\n      keywords: ['needle-']\n"
        );
        load_str(&src, "test").expect("an oversized pattern still loads")
    }

    #[test]
    fn oversized_pattern_loads_and_fails_at_first_use() {
        // The eager path rejects it outright; the deferred path must not lose
        // that rejection, only move it. Both are measured against the pack's
        // raised limit, not the crate default: a raised limit must still be a
        // limit.
        assert!(build_regex(OVERSIZED).is_err());

        let rules = oversized_rules();
        let (pattern, _) = secret_payload(&rules[0]);
        assert!(!pattern.is_compiled(), "load must not compile the pattern");

        let err = pattern.get().expect_err("oversized pattern cannot compile");
        assert_eq!(err.rule_id, "a.b");
        assert_eq!(
            err.detail,
            build_regex(OVERSIZED).unwrap_err().to_string(),
            "the detail must be the error an eager compile reports"
        );
        assert!(
            err.to_string().contains("a.b"),
            "the message must name the rule: {err}"
        );
    }

    /// The two widest patterns in the shipped pack, as translated: bounded
    /// repetitions of a character class wide enough that the crate's default
    /// 10 MiB program limit refused them. They are what
    /// [`PATTERN_SIZE_LIMIT`] was raised for, so what they actually cost is
    /// measured rather than assumed.
    const WIDE_PACK_PATTERNS: [(&str, &str); 2] = [
        (
            "secrets.pypi-upload-token",
            r"pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,1000}",
        ),
        (
            "secrets.vault-batch-token",
            r#"\b(hvb\.[0-9A-Za-z_-]{138,300})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
    ];

    /// The smallest compiled-program budget `pattern` builds inside, to the
    /// nearest MiB. This is the crate's own accounting of the program's size:
    /// it refuses to build past the limit it is given, so the smallest limit
    /// that succeeds is the size.
    fn program_size_mib(pattern: &str) -> usize {
        (1..=256)
            .find(|mib| {
                RegexBuilder::new(pattern)
                    .size_limit(mib * 1024 * 1024)
                    .build()
                    .is_ok()
            })
            .unwrap_or_else(|| panic!("{pattern} does not compile inside 256 MiB"))
    }

    /// The measurement behind [`PATTERN_SIZE_LIMIT`]: both of the patterns it
    /// was raised for build well inside it, and quickly. The bound asserted is
    /// the program size, which is deterministic; the compile time is printed
    /// because it depends on the machine, and the decision it fed was that
    /// neither is worth rewriting the rules over.
    #[test]
    fn the_widest_pack_patterns_compile_inside_the_size_limit() {
        for (id, pattern) in WIDE_PACK_PATTERNS {
            let start = std::time::Instant::now();
            let compiled = build_regex(pattern);
            let elapsed = start.elapsed();
            assert!(compiled.is_ok(), "{id} does not compile: {pattern}");

            let mib = program_size_mib(pattern);
            println!("{id}: {mib} MiB program, compiled in {elapsed:?}");
            assert!(
                mib * 1024 * 1024 <= PATTERN_SIZE_LIMIT / 2,
                "{id} needs {mib} MiB, over half the {} MiB budget",
                PATTERN_SIZE_LIMIT / (1024 * 1024)
            );
        }
    }

    /// The pack's two widest patterns are ASCII by construction. Rust's `\w`
    /// is Unicode-aware, and a thousand repetitions of it is a program two
    /// orders of magnitude past any size limit worth setting; RE2's `\w`,
    /// which the upstream rules are written against, is `[0-9A-Za-z_]`. The
    /// converter therefore ships the ASCII spelling, and this is the check
    /// that the spelling it ships is the one the pack carries.
    #[test]
    fn the_pack_ships_the_measured_spelling_of_its_widest_patterns() {
        let rules = load_str(crate::default_pack::default_rules(), "default-pack")
            .expect("the default pack loads");
        for (id, pattern) in WIDE_PACK_PATTERNS {
            let rule = rules
                .iter()
                .find(|rule| rule.id == id)
                .unwrap_or_else(|| panic!("{id} is missing from the pack"));
            let (shipped, _) = secret_payload(rule);
            assert_eq!(
                shipped.pattern(),
                pattern,
                "{id} ships a pattern other than the one measured above"
            );
        }
    }

    #[test]
    fn a_compile_failure_is_memoized_and_repeats_identically() {
        let rules = oversized_rules();
        let (pattern, _) = secret_payload(&rules[0]);

        let first = pattern.get().expect_err("first use fails").clone();
        assert!(pattern.is_compiled(), "the outcome is recorded");
        let second = pattern.get().expect_err("later uses fail the same way");
        assert_eq!(&first, second);

        // A clone carries the recorded failure rather than retrying it.
        let clone = pattern.clone();
        assert!(clone.is_compiled());
        assert_eq!(clone.get().expect_err("clone fails too"), &first);
    }

    #[test]
    fn an_allowlist_compile_failure_names_the_rule_and_its_context() {
        let src = format!(
            "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    secret:\n      pattern: 'needle-[a-z]+'\n      allowlist:\n        patterns: ['{OVERSIZED}']\n"
        );
        let rules = load_str(&src, "test").expect("should load");
        let (_, allow) = secret_payload(&rules[0]);

        let err = allow[0].get().expect_err("oversized allowlist pattern");
        assert_eq!(err.rule_id, "a.b");
        assert!(
            err.detail.starts_with("allowlist: "),
            "the detail must say which pattern failed: {}",
            err.detail
        );
    }

    #[test]
    fn an_oversized_rule_fails_the_scan_when_its_keywords_match() {
        let rules = oversized_rules();

        // No keyword in the file: the rule never runs, so it never compiles and
        // the scan is clean. Laziness is the point and must survive the fix.
        let clean = crate::engines::secret::scan_file(&rules, "f.txt", None, "haystack\n")
            .expect("a rule that never runs cannot fail");
        assert!(clean.is_empty());
        let (pattern, _) = secret_payload(&rules[0]);
        assert!(!pattern.is_compiled());

        // Keyword present: the rule has to match, cannot compile, and the scan
        // fails instead of quietly reporting nothing.
        let err = crate::engines::secret::scan_file(&rules, "f.txt", None, "needle-abc\n")
            .expect_err("an unusable rule must not be skipped");
        assert_eq!(err.rule_id, "a.b");

        // Same input, same error: the failure does not depend on run order.
        let again = crate::engines::secret::scan_file(&rules, "f.txt", None, "needle-abc\n")
            .expect_err("still fails");
        assert_eq!(err, again);
    }

    #[test]
    fn lazy_regex_clone_keeps_the_compiled_state() {
        let lazy = LazyRegex::new("a.b", "", "a+".to_string());
        assert!(!lazy.clone().is_compiled());
        assert!(lazy.get().expect("compiles").is_match("aaa"));
        let clone = lazy.clone();
        assert!(clone.is_compiled());
        assert!(clone.get().expect("compiles").is_match("aaa"));
    }

    #[test]
    fn secret_bad_pattern_reports_what_an_eager_compile_reports() {
        for pattern in ["(", "[z-a]", r"\p{Nope}", "a{2,1}", "(?P<1>a)"] {
            let src = format!(
                "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    secret: {{ pattern: '{pattern}' }}\n"
            );
            let err = load_str(&src, "test").unwrap_err();
            let eager = Regex::new(pattern).unwrap_err().to_string();
            assert_eq!(
                err.to_string(),
                format!("test: invalid regex pattern: a.b: {eager}")
            );
        }
    }

    #[test]
    fn secret_bad_pattern_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret: { pattern: "(" }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadPattern { .. })
        ));
    }

    #[test]
    fn secret_out_of_range_group_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret: { pattern: "(x)", group: 2 }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadGroup { .. })
        ));
    }

    #[test]
    fn secret_bad_allowlist_pattern_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret:
      pattern: "x"
      allowlist:
        patterns: ["("]
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::BadPattern { .. }));
        assert!(err.to_string().contains("allowlist"));
    }

    /// `case_insensitive` is opt-in, so the same globs decide differently
    /// depending on nothing but that flag. Both directions are asserted: a rule
    /// written before the field existed must keep matching exactly.
    #[test]
    fn paths_fold_case_only_when_the_rule_asks() {
        let rule = |flag: &str| {
            format!(
                "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    paths:\n{flag}      include: ['**/*.p12']\n      exclude: ['**/testdata/*.p12']\n    secret:\n      pattern: 'x'\n"
            )
        };

        let folded = load_str(&rule("      case_insensitive: true\n"), "test").expect("loads");
        let include = folded[0].include.as_ref().expect("include");
        let exclude = folded[0].exclude.as_ref().expect("exclude");
        assert!(include.is_match("certs/server.P12"));
        assert!(include.is_match("certs/server.p12"));
        // The flag covers both halves of the envelope, or an exclusion written
        // beside a folded include would stop covering what it names.
        assert!(exclude.is_match("testdata/Server.P12"));

        let exact = load_str(&rule(""), "test").expect("loads");
        let include = exact[0].include.as_ref().expect("include");
        assert!(!include.is_match("certs/server.P12"));
        assert!(include.is_match("certs/server.p12"));
    }

    #[test]
    fn a_rule_with_no_payload_and_an_include_is_a_presence_rule() {
        let src = r#"
version: 1
rules:
  - id: a.keystore
    severity: error
    message: a committed keystore
    paths:
      include: ['**/*.p12']
"#;
        let rules = load_str(src, "test").expect("a presence rule loads");
        assert!(matches!(rules[0].payload, CompiledPayload::Presence));
        assert!(
            rules[0]
                .include
                .as_ref()
                .expect("include")
                .is_match("a.p12")
        );
    }

    /// The envelope is the whole rule, so a rule without one is the payload
    /// error it has always been - with a detail that says what is missing.
    #[test]
    fn a_rule_with_no_payload_and_no_include_is_fatal() {
        for paths in ["", "    paths:\n      exclude: ['**/*.p12']\n"] {
            let src = format!(
                "version: 1\nrules:\n  - id: a.keystore\n    severity: error\n    message: m\n{paths}"
            );
            let err = load_str(&src, "test").expect_err("no payload, no include");
            assert!(matches!(err, LoadError::NoPayload { .. }));
            assert!(
                err.to_string().contains("paths.include"),
                "the message must name what is missing: {err}"
            );
        }
    }

    /// A language is detected from content, and a presence rule reports files
    /// nothing read. A `languages` filter on one could only ever match nothing,
    /// so it is refused at load rather than silently disabling the rule.
    #[test]
    fn a_presence_rule_may_not_carry_languages() {
        let src = r#"
version: 1
rules:
  - id: a.keystore
    severity: error
    message: m
    languages: ["rust"]
    paths:
      include: ['**/*.p12']
"#;
        let err = load_str(src, "test").expect_err("languages on a presence rule");
        assert!(matches!(err, LoadError::PayloadLanguages { .. }));
        assert!(err.to_string().contains("presence"), "{err}");
    }

    #[test]
    fn secret_bad_allowlist_path_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret:
      pattern: "x"
      allowlist:
        paths: ["a[b"]
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadGlob { .. })
        ));
    }

    #[test]
    fn secret_negative_entropy_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret: { pattern: "x", entropy: -1.0 }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadEntropy { .. })
        ));
    }

    #[test]
    fn secret_non_finite_entropy_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret: { pattern: "x", entropy: .nan }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadEntropy { .. })
        ));
    }

    #[test]
    fn secret_unknown_key_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret: { pattern: "x", nonsense: true }
"#;
        assert!(matches!(load_str(src, "test"), Err(LoadError::Yaml { .. })));
    }

    #[test]
    fn secret_unknown_allowlist_key_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    secret:
      pattern: "x"
      allowlist: { nonsense: true }
"#;
        assert!(matches!(load_str(src, "test"), Err(LoadError::Yaml { .. })));
    }

    #[test]
    fn duplicate_id_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    regex: { pattern: "x" }
  - id: a.b
    severity: info
    message: m
    regex: { pattern: "y" }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::DuplicateId { .. })
        ));
    }

    #[test]
    fn unknown_key_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    nonsense: true
    regex: { pattern: "x" }
"#;
        assert!(matches!(load_str(src, "test"), Err(LoadError::Yaml { .. })));
    }

    #[test]
    fn zero_payloads_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::NoPayload { .. })
        ));
    }

    #[test]
    fn two_payloads_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    regex: { pattern: "x" }
    secret: { pattern: "y" }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::MultiplePayloads { .. })
        ));
    }

    #[test]
    fn bad_id_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: NotADottedId
    severity: info
    message: m
    regex: { pattern: "x" }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadId { .. })
        ));
    }

    #[test]
    fn valid_boundary_rule_loads() {
        let src = r#"
version: 1
rules:
  - id: arch.api-must-not-import-db
    severity: error
    message: "api must not import db"
    boundary:
      from: api
      deny: ["db", "infra-2"]
"#;
        let rules = load_str(src, "test").expect("should load");
        match &rules[0].payload {
            CompiledPayload::Boundary { from, deny } => {
                assert_eq!(from, "api");
                assert_eq!(deny, &["db".to_string(), "infra-2".to_string()]);
            }
            other => panic!("expected a boundary payload, got {other:?}"),
        }
    }

    #[test]
    fn boundary_empty_deny_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    boundary: { from: api, deny: [] }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::EmptyDeny { .. })
        ));
    }

    #[test]
    fn boundary_bad_silo_name_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    boundary: { from: Api, deny: [db] }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadSilo { .. })
        ));

        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    boundary: { from: api, deny: ["db layer"] }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadSilo { .. })
        ));
    }

    #[test]
    fn boundary_unknown_key_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    boundary: { from: api, to: db }
"#;
        assert!(matches!(load_str(src, "test"), Err(LoadError::Yaml { .. })));
    }

    #[test]
    fn boundary_with_languages_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    languages: ["rust"]
    boundary: { from: api, deny: [db] }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::PayloadLanguages { .. }));
        assert!(err.to_string().contains("boundary rule must not set"));
    }

    #[test]
    fn valid_coverage_rule_loads() {
        let src = r#"
version: 1
rules:
  - id: quality.line-coverage
    severity: warning
    message: "coverage below threshold"
    coverage: { min: 80 }
"#;
        let rules = load_str(src, "test").expect("should load");
        match &rules[0].payload {
            CompiledPayload::Coverage { min } => assert_eq!(*min, 80.0),
            other => panic!("expected a coverage payload, got {other:?}"),
        }
    }

    #[test]
    fn coverage_out_of_range_is_fatal() {
        for min in ["-1", "100.5", ".nan"] {
            let src = format!(
                "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    coverage: {{ min: {min} }}\n"
            );
            assert!(
                matches!(
                    load_str(&src, "test"),
                    Err(LoadError::BadCoverageMin { .. })
                ),
                "min {min} should be rejected"
            );
        }
    }

    #[test]
    fn coverage_with_languages_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    languages: ["rust"]
    coverage: { min: 50 }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::PayloadLanguages { .. }));
        assert!(err.to_string().contains("coverage rule must not set"));
    }

    #[test]
    fn valid_duplication_rule_loads() {
        let src = r#"
version: 1
rules:
  - id: quality.duplication
    severity: warning
    message: "too much duplication"
    paths:
      include: ["src/**"]
    duplication:
      max_percent: 3.5
      scope: file
"#;
        let rules = load_str(src, "test").expect("should load");
        match &rules[0].payload {
            CompiledPayload::Duplication { max_percent, scope } => {
                assert_eq!(*max_percent, 3.5);
                assert_eq!(*scope, DuplicationScope::File);
            }
            other => panic!("expected a duplication payload, got {other:?}"),
        }
    }

    #[test]
    fn the_duplicate_block_rule_id_is_reserved() {
        let src = format!(
            "version: 1\nrules:\n  - id: {}\n    severity: info\n    message: m\n    regex:\n      pattern: 'x'\n",
            crate::metrics::DUPLICATE_BLOCK_RULE_ID
        );
        let err = load_str(&src, "test").unwrap_err();
        assert!(matches!(err, LoadError::ReservedId { .. }), "{err}");
        assert!(
            err.to_string()
                .contains(crate::metrics::DUPLICATE_BLOCK_RULE_ID),
            "{err}"
        );
    }

    #[test]
    fn duplication_scope_defaults_to_scan() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    duplication: { max_percent: 5 }
"#;
        let rules = load_str(src, "test").expect("should load");
        match &rules[0].payload {
            CompiledPayload::Duplication { max_percent, scope } => {
                assert_eq!(*max_percent, 5.0);
                assert_eq!(*scope, DuplicationScope::Scan);
                assert_eq!(scope.to_string(), "scan");
            }
            other => panic!("expected a duplication payload, got {other:?}"),
        }
    }

    #[test]
    fn duplication_accepts_every_scope() {
        for (value, expected) in [
            ("scan", DuplicationScope::Scan),
            ("file", DuplicationScope::File),
            ("silo", DuplicationScope::Silo),
        ] {
            let src = format!(
                "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    duplication: {{ max_percent: 5, scope: {value} }}\n"
            );
            let rules = load_str(&src, "test").expect("should load");
            match &rules[0].payload {
                CompiledPayload::Duplication { scope, .. } => {
                    assert_eq!(*scope, expected);
                    assert_eq!(scope.as_str(), value);
                }
                other => panic!("expected a duplication payload, got {other:?}"),
            }
        }
    }

    #[test]
    fn duplication_out_of_range_max_percent_is_fatal() {
        for max in ["0", "0.0", "-1", "100.5", ".nan", ".inf"] {
            let src = format!(
                "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    duplication: {{ max_percent: {max} }}\n"
            );
            let err = load_str(&src, "test").unwrap_err();
            assert!(
                matches!(err, LoadError::BadDuplicationMax { .. }),
                "max {max} should be rejected, got {err}"
            );
            assert!(err.to_string().contains("a.b"), "{err}");
        }
    }

    #[test]
    fn duplication_boundary_max_percent_loads() {
        for max in ["0.1", "100"] {
            let src = format!(
                "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    duplication: {{ max_percent: {max} }}\n"
            );
            assert!(load_str(&src, "test").is_ok(), "max {max} should load");
        }
    }

    #[test]
    fn duplication_unknown_scope_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    duplication: { max_percent: 5, scope: repo }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::BadDuplicationScope { .. }));
        assert!(err.to_string().contains("a.b: repo"), "{err}");
    }

    #[test]
    fn duplication_unknown_key_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    duplication: { max_percent: 5, nonsense: true }
"#;
        assert!(matches!(load_str(src, "test"), Err(LoadError::Yaml { .. })));
    }

    #[test]
    fn duplication_missing_max_percent_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    duplication: { scope: file }
"#;
        assert!(matches!(load_str(src, "test"), Err(LoadError::Yaml { .. })));
    }

    #[test]
    fn duplication_with_languages_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    languages: ["rust"]
    duplication: { max_percent: 5 }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::PayloadLanguages { .. }));
        assert!(err.to_string().contains("duplication rule must not set"));
    }

    #[test]
    fn duplication_with_another_payload_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    coverage: { min: 50 }
    duplication: { max_percent: 5 }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::MultiplePayloads { .. }));
        assert!(err.to_string().contains("coverage, duplication"), "{err}");
    }

    #[test]
    fn metric_accepts_every_measure() {
        for (value, expected) in [
            ("function-length", Measure::FunctionLength),
            ("parameter-count", Measure::ParameterCount),
            ("nesting-depth", Measure::NestingDepth),
            ("cyclomatic-complexity", Measure::CyclomaticComplexity),
        ] {
            let src = format!(
                "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    metric: {{ measure: {value}, max: 15 }}\n"
            );
            let rules = load_str(&src, "test").expect("should load");
            match &rules[0].payload {
                CompiledPayload::Metric { measure, max } => {
                    assert_eq!(*measure, expected);
                    assert_eq!(measure.as_str(), value);
                    assert_eq!(measure.to_string(), value);
                    assert_eq!(*max, 15);
                }
                other => panic!("expected a metric payload, got {other:?}"),
            }
            // No `languages` means every language with a node-kind table.
            assert!(rules[0].languages.is_none());
        }
    }

    #[test]
    fn metric_unknown_measure_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    metric: { measure: halstead, max: 15 }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::BadMetricMeasure { .. }));
        assert!(err.to_string().contains("a.b: halstead"), "{err}");
    }

    #[test]
    fn metric_negative_max_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    metric: { measure: nesting-depth, max: -1 }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::BadMetricMax { .. }));
        assert!(err.to_string().contains("a.b: -1"), "{err}");
    }

    #[test]
    fn metric_missing_key_is_fatal() {
        for payload in [
            "{ measure: nesting-depth }",
            "{ max: 3 }",
            "{ measure: nesting-depth, max: 1.5 }",
        ] {
            let src = format!(
                "version: 1\nrules:\n  - id: a.b\n    severity: info\n    message: m\n    metric: {payload}\n"
            );
            assert!(matches!(
                load_str(&src, "test"),
                Err(LoadError::Yaml { .. })
            ));
        }
    }

    /// A metric rule's `languages` is the ordinary rule-level filter, which is
    /// why the ast rejection does not apply to it. What it must name is a
    /// language the engine has a node-kind table for.
    #[test]
    fn metric_keeps_its_languages_filter() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    languages: ["rust", "python"]
    metric: { measure: cyclomatic-complexity, max: 15 }
"#;
        let rules = load_str(src, "test").expect("should load");
        assert_eq!(
            rules[0].languages.as_deref(),
            Some(["rust".to_string(), "python".to_string()].as_slice())
        );
    }

    #[test]
    fn metric_with_an_untabled_language_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    languages: ["rust", "cobol"]
    metric: { measure: cyclomatic-complexity, max: 15 }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::BadMetricLanguage { .. }));
        assert!(err.to_string().contains("a.b: cobol"), "{err}");
    }

    #[test]
    fn metric_with_another_payload_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    coverage: { min: 50 }
    metric: { measure: nesting-depth, max: 3 }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::MultiplePayloads { .. }));
        assert!(err.to_string().contains("coverage, metric"), "{err}");
    }

    #[test]
    fn boundary_and_coverage_together_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    boundary: { from: api, deny: [db] }
    coverage: { min: 50 }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::MultiplePayloads { .. })
        ));
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn valid_ast_rule_loads() {
        let src = r#"
version: 1
rules:
  - id: rust.unwrap-call
    severity: warning
    message: "avoid unwrap"
    ast:
      rust: '(call_expression function: (field_expression field: (field_identifier) @m (#eq? @m "unwrap")))'
"#;
        let rules = load_str(src, "test").expect("should load");
        assert_eq!(rules.len(), 1);
        // Coverage is derived from the query map, not the envelope.
        assert_eq!(
            rules[0].languages.as_deref(),
            Some(&["rust".to_string()][..])
        );
        match &rules[0].payload {
            CompiledPayload::Ast { queries } => {
                assert_eq!(queries.len(), 1);
                assert_eq!(queries[0].language, "rust");
                assert_eq!(queries[0].query.pattern_count(), 1);
            }
            other => panic!("expected an ast payload, got {other:?}"),
        }
    }

    #[cfg(all(feature = "tree-sitter-rust", feature = "tree-sitter-python"))]
    #[test]
    fn multi_language_ast_rule_is_sorted() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    ast:
      rust: "(call_expression) @c"
      python: "(call) @c"
"#;
        let rules = load_str(src, "test").expect("should load");
        match &rules[0].payload {
            CompiledPayload::Ast { queries } => {
                let langs: Vec<&str> = queries.iter().map(|q| q.language.as_str()).collect();
                assert_eq!(langs, vec!["python", "rust"]);
            }
            other => panic!("expected an ast payload, got {other:?}"),
        }
        assert_eq!(
            rules[0].languages.as_deref(),
            Some(&["python".to_string(), "rust".to_string()][..])
        );
    }

    #[test]
    fn ast_unknown_language_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    ast:
      klingon: "(call) @c"
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadAstLanguage { .. })
        ));
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn ast_bad_query_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    ast:
      rust: "(call_expression"
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadAstQuery { .. })
        ));
    }

    #[test]
    fn ast_empty_map_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    ast: {}
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::NoPayload { .. }));
        assert!(err.to_string().contains("ast has no languages"));
    }

    #[test]
    fn ast_with_languages_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    languages: ["rust"]
    ast:
      rust: "(call_expression) @c"
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::AstLanguages { .. })
        ));
    }

    #[test]
    fn ast_non_string_query_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    ast: { kind: [call] }
"#;
        assert!(matches!(load_str(src, "test"), Err(LoadError::Yaml { .. })));
    }

    #[test]
    fn version_two_is_fatal() {
        let src = r#"
version: 2
rules: []
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn bad_pattern_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    regex: { pattern: "(" }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadPattern { .. })
        ));
    }

    #[test]
    fn out_of_range_group_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    regex: { pattern: "(x)", group: 2 }
"#;
        assert!(matches!(
            load_str(src, "test"),
            Err(LoadError::BadGroup { .. })
        ));
    }

    /// `count` regex rules, with a bad pattern at each index in `bad`.
    fn rule_doc(count: usize, bad: &[usize]) -> String {
        let mut src = String::from("version: 1\nrules:\n");
        for i in 0..count {
            let pattern = if bad.contains(&i) { "(" } else { "x" };
            let _ = write!(
                src,
                "  - id: r.{i}\n    severity: info\n    message: m\n    regex: {{ pattern: '{pattern}' }}\n"
            );
        }
        src
    }

    fn compile_doc(src: &str, workers: usize) -> Vec<Result<CompiledRule, LoadError>> {
        let file: RuleFile = serde_norway::from_str(src).expect("doc parses");
        compile_rules(file.rules, "test", workers)
    }

    fn first_error(results: &[Result<CompiledRule, LoadError>]) -> Option<String> {
        results
            .iter()
            .find_map(|r| r.as_ref().err())
            .map(|e| e.to_string())
    }

    #[test]
    fn parallel_compile_reports_the_same_first_error_as_sequential() {
        // Two bad rules, and the earlier one has to win no matter which worker
        // reached it first.
        let src = rule_doc(64, &[9, 40]);
        let sequential = compile_doc(&src, 1);
        let parallel = compile_doc(&src, 8);

        let expected = "test: invalid regex pattern: r.9: regex parse error";
        let seq_err = first_error(&sequential).expect("sequential fails");
        assert!(seq_err.starts_with(expected), "got {seq_err}");
        assert_eq!(first_error(&parallel), Some(seq_err));

        // And the same holds through the public entry point.
        let err = load_str(&src, "test").unwrap_err().to_string();
        assert!(err.starts_with(expected), "got {err}");
    }

    #[test]
    fn parallel_compile_keeps_rule_order() {
        let src = rule_doc(70, &[]);
        for workers in [1, 3, 8, 70] {
            let ids: Vec<String> = compile_doc(&src, workers)
                .into_iter()
                .map(|r| r.expect("all rules are valid").id)
                .collect();
            let expected: Vec<String> = (0..70).map(|i| format!("r.{i}")).collect();
            assert_eq!(ids, expected, "worker count {workers}");
        }
    }

    #[test]
    fn a_rule_error_beats_a_later_duplicate_id() {
        // Sequential compile raised the bad pattern at index 9 before it ever
        // reached the duplicate at index 63; the parallel path must too.
        let mut src = rule_doc(64, &[9]);
        src.push_str(
            "  - id: r.0\n    severity: info\n    message: m\n    regex: { pattern: 'x' }\n",
        );
        assert!(matches!(
            load_str(&src, "test"),
            Err(LoadError::BadPattern { .. })
        ));
    }

    #[test]
    fn load_dirs_is_ordered_and_rejects_cross_file_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("b.yaml"),
            "version: 1\nrules:\n  - id: b.rule\n    severity: error\n    message: m\n    regex: { pattern: \"b\" }\n",
        )
        .unwrap();
        fs::create_dir(dir.path().join("nested")).unwrap();
        fs::write(
            dir.path().join("nested/a.yml"),
            "version: 1\nrules:\n  - id: a.rule\n    severity: info\n    message: m\n    regex: { pattern: \"a\" }\n",
        )
        .unwrap();
        fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

        let set = load_dirs(&[dir.path().to_path_buf()]).unwrap();
        // "b.yaml" sorts before "nested/a.yml" bytewise.
        assert_eq!(
            set.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["b.rule", "a.rule"]
        );

        fs::write(
            dir.path().join("c.yaml"),
            "version: 1\nrules:\n  - id: b.rule\n    severity: info\n    message: m\n    regex: { pattern: \"c\" }\n",
        )
        .unwrap();
        assert!(matches!(
            load_dirs(&[dir.path().to_path_buf()]),
            Err(LoadError::DuplicateId { .. })
        ));
    }
}
