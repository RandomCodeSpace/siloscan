use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tree_sitter::Query;

use crate::parsers;

const SUPPORTED_VERSION: u32 = 1;

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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPaths {
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
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
            Regex::new(&self.pattern).map_err(|e| {
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

#[derive(Debug, Clone)]
pub enum CompiledPayload {
    Regex {
        regex: Regex,
        group: Option<usize>,
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
        queries: Vec<(String, Arc<Query>)>,
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

    match kinds.len() {
        0 => {
            return Err(LoadError::NoPayload {
                origin: origin.to_string(),
                detail: raw.id,
            });
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
    // filter would be meaningless.
    if raw.languages.is_some()
        && let Some(kind) = ["boundary", "coverage", "duplication"]
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
        languages = Some(queries.iter().map(|(lang, _)| lang.clone()).collect());
        CompiledPayload::Ast { queries }
    } else if let Some(spec) = raw.boundary {
        compile_boundary(&raw.id, spec, origin)?
    } else if let Some(spec) = raw.coverage {
        compile_coverage(&raw.id, spec, origin)?
    } else if let Some(spec) = raw.duplication {
        compile_duplication(&raw.id, spec, origin)?
    } else {
        // Unreachable: the payload count was checked above.
        return Err(LoadError::NoPayload {
            origin: origin.to_string(),
            detail: raw.id,
        });
    };

    let (include, exclude) = match raw.paths {
        Some(paths) => (
            compile_globs(paths.include, origin)?,
            compile_globs(paths.exclude, origin)?,
        ),
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

    let allow_paths = compile_globs(allowlist.paths, origin)?;

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

fn compile_ast(
    id: &str,
    spec: BTreeMap<String, String>,
    origin: &str,
) -> Result<Vec<(String, Arc<Query>)>, LoadError> {
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
        queries.push((lang, Arc::new(query)));
    }

    Ok(queries)
}

fn lowercased(values: Option<Vec<String>>) -> Vec<String> {
    values
        .unwrap_or_default()
        .iter()
        .map(|v| v.to_lowercase())
        .collect()
}

fn compile_pattern(id: &str, pattern: &str, origin: &str) -> Result<Regex, LoadError> {
    Regex::new(pattern).map_err(|e| LoadError::BadPattern {
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
) -> Result<Option<GlobSet>, LoadError> {
    let patterns = match patterns {
        Some(p) => p,
        None => return Ok(None),
    };

    let mut builder = GlobSetBuilder::new();
    for pattern in &patterns {
        let glob = Glob::new(pattern).map_err(|e| LoadError::BadGlob {
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
            CompiledPayload::Regex { regex, group } => {
                assert!(regex.is_match("x.unwrap()"));
                assert_eq!(*group, None);
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

    /// Valid syntax, but the compiled program is far past the regex size limit.
    /// `regex_syntax` accepts it, so it survives load and only fails when a rule
    /// actually needs it.
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
        // that rejection, only move it.
        assert!(Regex::new(OVERSIZED).is_err());

        let rules = oversized_rules();
        let (pattern, _) = secret_payload(&rules[0]);
        assert!(!pattern.is_compiled(), "load must not compile the pattern");

        let err = pattern.get().expect_err("oversized pattern cannot compile");
        assert_eq!(err.rule_id, "a.b");
        assert_eq!(
            err.detail,
            Regex::new(OVERSIZED).unwrap_err().to_string(),
            "the detail must be the error an eager compile reports"
        );
        assert!(
            err.to_string().contains("a.b"),
            "the message must name the rule: {err}"
        );
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
                assert_eq!(queries[0].0, "rust");
                assert_eq!(queries[0].1.pattern_count(), 1);
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
                let langs: Vec<&str> = queries.iter().map(|(l, _)| l.as_str()).collect();
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
