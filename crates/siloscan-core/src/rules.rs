use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};

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

    #[error("{origin}: rule has no payload: {detail}")]
    NoPayload { origin: String, detail: String },

    #[error("{origin}: rule has multiple payloads: {detail}")]
    MultiplePayloads { origin: String, detail: String },

    #[error("{origin}: payload not supported yet: {detail}")]
    UnsupportedPayload { origin: String, detail: String },

    #[error("{origin}: invalid regex pattern: {detail}")]
    BadPattern { origin: String, detail: String },

    #[error("{origin}: invalid capture group: {detail}")]
    BadGroup { origin: String, detail: String },

    #[error("{origin}: invalid glob: {detail}")]
    BadGlob { origin: String, detail: String },

    #[error("{origin}: invalid entropy threshold: {detail}")]
    BadEntropy { origin: String, detail: String },
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
    pub ast: Option<serde_norway::Value>,
    pub boundary: Option<serde_norway::Value>,
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAllowlist {
    pub patterns: Option<Vec<String>>,
    pub paths: Option<Vec<String>>,
    pub stopwords: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
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

#[derive(Debug, Clone)]
pub enum CompiledPayload {
    Regex {
        regex: Regex,
        group: Option<usize>,
    },
    Secret {
        regex: Regex,
        group: Option<usize>,
        entropy: Option<f64>,
        /// Lowercased at compile time; callers compare against lowercased input.
        keywords: Vec<String>,
        allow_patterns: Vec<Regex>,
        allow_paths: Option<GlobSet>,
        /// Lowercased at compile time.
        stopwords: Vec<String>,
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
    let mut seen: HashMap<String, String> = HashMap::new();

    for file in &files {
        let origin = file.display().to_string();
        let src = fs::read_to_string(file).map_err(|e| LoadError::Io {
            origin: origin.clone(),
            detail: e.to_string(),
        })?;
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

    Ok(RuleSet { rules })
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

    let mut compiled = Vec::with_capacity(file.rules.len());
    let mut seen: HashMap<String, ()> = HashMap::new();

    for raw in file.rules {
        let rule = compile_rule(raw, origin)?;
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

fn compile_rule(raw: RawRule, origin: &str) -> Result<CompiledRule, LoadError> {
    if !id_pattern().is_match(&raw.id) {
        return Err(LoadError::BadId {
            origin: origin.to_string(),
            detail: raw.id,
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

    let payload = if let Some(spec) = raw.regex {
        compile_regex(&raw.id, spec, origin)?
    } else if let Some(spec) = raw.secret {
        compile_secret(&raw.id, spec, origin)?
    } else {
        return Err(LoadError::UnsupportedPayload {
            origin: origin.to_string(),
            detail: kinds[0].to_string(),
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
        languages: raw.languages,
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
    let regex = compile_pattern(id, &spec.pattern, origin)?;
    check_group(id, &regex, spec.group, origin)?;

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
        allow_patterns.push(Regex::new(&pattern).map_err(|e| LoadError::BadPattern {
            origin: origin.to_string(),
            detail: format!("{id}: allowlist: {e}"),
        })?);
    }

    let allow_paths = compile_globs(allowlist.paths, origin)?;

    Ok(CompiledPayload::Secret {
        regex,
        group: spec.group,
        entropy: spec.entropy,
        keywords: lowercased(spec.keywords),
        allow_patterns,
        allow_paths,
        stopwords: lowercased(allowlist.stopwords),
    })
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

fn check_group(
    id: &str,
    regex: &Regex,
    group: Option<usize>,
    origin: &str,
) -> Result<(), LoadError> {
    if let Some(group) = group
        && group >= regex.captures_len()
    {
        return Err(LoadError::BadGroup {
            origin: origin.to_string(),
            detail: format!(
                "{id}: group {group} out of range (pattern has {} groups)",
                regex.captures_len()
            ),
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
                regex,
                group,
                entropy,
                keywords,
                allow_patterns,
                allow_paths,
                stopwords,
            } => {
                assert!(regex.is_match("AKIAIOSFODNN7EXAMPLE"));
                assert_eq!(*group, Some(1));
                assert_eq!(*entropy, Some(3.5));
                assert_eq!(keywords, &["akia".to_string(), "aws".to_string()]);
                assert_eq!(allow_patterns.len(), 1);
                assert!(allow_patterns[0].is_match("AKIAIOSFODNN7EXAMPLE"));
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
    fn unsupported_payload_is_fatal() {
        let src = r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    ast: { kind: call }
"#;
        let err = load_str(src, "test").unwrap_err();
        assert!(matches!(err, LoadError::UnsupportedPayload { .. }));
        assert!(err.to_string().contains("payload not supported yet: ast"));
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
