//! Optional repository configuration (`siloscan.toml`).
//!
//! The config is discovered from the scan root upwards and never from the user
//! environment: no home-directory config, no environment variables. A scan of
//! the same tree therefore resolves the same config on every machine.
//!
//! A root config may pull in module-level configs with `include`. An included
//! file contributes silos, source roots and rule directories and nothing else,
//! and every path it declares is relative to the included file itself; `load`
//! rewrites those paths so that the merged [`Config`] speaks one convention:
//! forward-slash paths relative to the directory holding the root config.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

pub const CONFIG_NAME: &str = "siloscan.toml";

const fn default_min_lines() -> usize {
    10
}

/// The directory every path a scan reports is relative to.
///
/// One convention holds for a whole scan: fingerprints, displayed paths, JSON
/// and SARIF output, baseline entries and metrics keys all use the same
/// anchor, so a fingerprint never depends on where the scan was started from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Anchor {
    /// Paths are relative to the scan root. The default, and the only
    /// behaviour before this key existed.
    #[default]
    ScanRoot,
    /// Paths are relative to the directory holding the root config file, so a
    /// module scan and a whole-repository scan agree on every path.
    Config,
}

impl Anchor {
    /// The spelling used in config files and in the JSON report.
    pub const fn as_str(self) -> &'static str {
        match self {
            Anchor::ScanRoot => "scan-root",
            Anchor::Config => "config",
        }
    }
}

/// Duplication detection settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicationConfig {
    #[serde(default = "default_min_lines")]
    pub min_lines: usize,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        DuplicationConfig { min_lines: 10 }
    }
}

/// Repository configuration. Every section is optional; the default value is a
/// config that changes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Silo name -> path globs, matched against repo-relative forward-slash
    /// paths.
    #[serde(default)]
    pub silos: BTreeMap<String, Vec<String>>,

    /// Directories that import resolution may anchor to, repo-relative. Empty
    /// means the repository root only.
    #[serde(default)]
    pub source_roots: Vec<String>,

    /// File extension (without the dot) -> language name override.
    #[serde(default)]
    pub languages: BTreeMap<String, String>,

    /// Extra rule directories, relative to the directory holding the config
    /// file.
    #[serde(default)]
    pub rules: Vec<String>,

    /// Duplication detection settings. Root-only key.
    #[serde(default)]
    pub duplication: DuplicationConfig,

    /// The directory every reported path is relative to. Root-only key.
    #[serde(default)]
    pub anchor: Anchor,

    /// Config files to merge, relative to the directory holding this file.
    /// Root-only key: an included file may not include further files.
    #[serde(default)]
    pub include: Vec<String>,

    /// Directory holding the root config file. Not a config key: [`load`]
    /// fills it in, and every relative path above resolves against it.
    #[serde(skip)]
    pub config_dir: PathBuf,
}

/// The keys an included config may set. Everything else - `anchor`,
/// `duplication`, `languages`, `include`, and every root-only key added later -
/// is rejected by `deny_unknown_fields` with the offending key in the message.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIncludedConfig {
    #[serde(default)]
    silos: BTreeMap<String, Vec<String>>,

    #[serde(default)]
    source_roots: Vec<String>,

    #[serde(default)]
    rules: Vec<String>,

    /// Accepted only so that a nested `include` gets a message about the
    /// single-level rule instead of a bare "unknown field".
    #[serde(default)]
    include: Option<Vec<String>>,
}

/// True when `name` is a well-formed silo name (`^[a-z0-9-]+$`).
pub fn is_silo_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Nearest `siloscan.toml` at or above `scan_root`.
///
/// A config in the scan root itself always counts. Ascending above the scan
/// root requires evidence that the scan root is part of a repository, so an
/// ancestor's config is adopted only once a `.git` entry is found at or above
/// it; the walk stops there. Without a VCS marker nothing above the scan root
/// is read, which keeps a stray config in `$HOME` or `/` out of the scan.
pub fn discover(scan_root: &Path) -> Option<PathBuf> {
    let start = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());

    let mut found: Option<PathBuf> = None;
    let mut dir = start.as_path();
    loop {
        if found.is_none() {
            let candidate = dir.join(CONFIG_NAME);
            if candidate.is_file() {
                if dir == start.as_path() {
                    return Some(candidate);
                }
                found = Some(candidate);
            }
        }
        if is_repo_root(dir) {
            return found;
        }
        dir = dir.parent()?;
    }
}

/// True when `dir` is the root of a git repository: a `.git` directory holding
/// a `HEAD`, or the `.git` file a worktree or submodule uses. An empty `.git`
/// directory is not a repository, and treating it as one would let a stray
/// entry (`/tmp/.git` is a real example) turn an unrelated ancestor into a
/// repository root.
fn is_repo_root(dir: &Path) -> bool {
    let git = dir.join(".git");
    match git.metadata() {
        Ok(meta) if meta.is_dir() => git.join("HEAD").exists(),
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Read and validate a config file, merging every file it includes. Errors
/// carry the path of the file that holds the mistake.
pub fn load(path: &Path) -> Result<Config, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut config: Config =
        toml::from_str(&src).map_err(|e| format!("{}: {e}", path.display()))?;
    config.config_dir = config_dir_of(path);

    check_silo_names(config.silos.keys(), path)?;

    if config.duplication.min_lines < 2 {
        return Err(format!(
            "{}: duplication.min_lines must be at least 2, got {}",
            path.display(),
            config.duplication.min_lines
        ));
    }

    // Silo origins, so a collision can name both declaring files.
    let mut origins: BTreeMap<String, PathBuf> = config
        .silos
        .keys()
        .map(|name| (name.clone(), path.to_path_buf()))
        .collect();

    let includes = config.include.clone();
    let mut merged: Vec<PathBuf> = Vec::with_capacity(includes.len());
    for entry in &includes {
        merge_include(&mut config, path, entry, &mut origins, &mut merged)?;
    }

    // Compiling the sets is the glob validation, for merged silos too.
    config
        .silo_sets()
        .map_err(|e| format!("{}: {e}", path.display()))?;

    Ok(config)
}

/// The directory holding `path`, as a directory that can be joined against and
/// measured from. `Path::parent` of a bare filename is `Some("")`, which names
/// no directory at all: `--config siloscan.toml` would otherwise leave the
/// config root empty and `anchor = "config"` would refuse a config that loaded
/// perfectly well.
fn config_dir_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Reject silo names that are not `^[a-z0-9-]+$`, naming the declaring file.
fn check_silo_names<'a>(
    names: impl Iterator<Item = &'a String>,
    file: &Path,
) -> Result<(), String> {
    for name in names {
        if !is_silo_name(name) {
            return Err(format!(
                "{}: invalid silo name: {name} (expected ^[a-z0-9-]+$)",
                file.display()
            ));
        }
    }
    Ok(())
}

/// Read one included config and merge its contributions into `config`.
///
/// `root_path` is the root config file, which is the one that got the include
/// wrong when the entry itself is unusable; mistakes inside the included file
/// are reported against that file.
fn merge_include(
    config: &mut Config,
    root_path: &Path,
    entry: &str,
    origins: &mut BTreeMap<String, PathBuf>,
    merged: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let prefix = include_prefix(root_path, entry)?;
    let file = config.config_dir.join(entry);

    if merged.contains(&file) {
        return Err(format!(
            "{}: include {entry:?} is listed more than once",
            root_path.display()
        ));
    }
    merged.push(file.clone());

    let src = fs::read_to_string(&file).map_err(|e| {
        format!(
            "{}: cannot read included config {}: {e}",
            root_path.display(),
            file.display()
        )
    })?;
    let raw: RawIncludedConfig = toml::from_str(&src).map_err(|e| {
        format!(
            "{}: {e} (an included config may set only silos, source_roots and rules)",
            file.display()
        )
    })?;

    if raw.include.is_some() {
        return Err(format!(
            "{}: include is not allowed in an included config (include is single level)",
            file.display()
        ));
    }

    check_silo_names(raw.silos.keys(), &file)?;
    for (name, patterns) in raw.silos {
        if let Some(first) = origins.get(&name) {
            return Err(format!(
                "{}: duplicate silo name: {name} (declared in {} and in {})",
                root_path.display(),
                first.display(),
                file.display()
            ));
        }
        let mut globs = Vec::with_capacity(patterns.len());
        for pattern in &patterns {
            globs.push(rebase(
                &prefix,
                pattern,
                &file,
                "silo glob",
                Rebased::SiloGlob,
            )?);
        }
        origins.insert(name.clone(), file.clone());
        config.silos.insert(name, globs);
    }

    for source_root in &raw.source_roots {
        config.source_roots.push(rebase(
            &prefix,
            source_root,
            &file,
            "source root",
            Rebased::Path,
        )?);
    }

    // Rule directories are filesystem paths rather than match patterns, so one
    // outside the config root (a shared rule pack next to the repository) is
    // legitimate and stays as a relative path with leading `..`.
    for dir in &raw.rules {
        config.rules.push(rebase(
            &prefix,
            dir,
            &file,
            "rules directory",
            Rebased::EscapingPath,
        )?);
    }

    Ok(())
}

/// The directory of an included file, as forward-slash path components
/// relative to the root config directory.
fn include_prefix(root_path: &Path, entry: &str) -> Result<Vec<String>, String> {
    if Path::new(entry).is_absolute() {
        return Err(format!(
            "{}: include {entry:?} must be a relative path",
            root_path.display()
        ));
    }

    let mut segments: Vec<&str> = entry.split(['/', '\\']).collect();
    let name = segments.pop().unwrap_or("");
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!(
            "{}: include {entry:?} must name a config file",
            root_path.display()
        ));
    }

    let mut parts: Vec<String> = Vec::new();
    for segment in segments {
        match segment {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| last != "..") {
                    parts.pop();
                } else {
                    parts.push("..".to_string());
                }
            }
            other => parts.push(other.to_string()),
        }
    }
    Ok(parts)
}

/// What an entry contributed by an included file is, which decides how it
/// splits into segments and whether it may climb above the config root.
#[derive(Clone, Copy, PartialEq)]
enum Rebased {
    /// A silo glob. Splits on `/` only: `\` is globset's escape character, so
    /// treating it as a separator would rewrite the pattern - `a\[0\].rs` would
    /// become `a/[0/].rs`, a silently different glob.
    SiloGlob,
    /// A filesystem path that must stay inside the config root.
    Path,
    /// A filesystem path that may point outside the config root.
    EscapingPath,
}

impl Rebased {
    /// Separators that split an entry of this kind into segments.
    fn separators(self) -> &'static [char] {
        match self {
            Rebased::SiloGlob => &['/'],
            Rebased::Path | Rebased::EscapingPath => &['/', '\\'],
        }
    }

    /// Whether the result may climb above the config root.
    fn allows_escape(self) -> bool {
        self == Rebased::EscapingPath
    }
}

/// Join `prefix` with a path declared inside an included file, resolving `.`
/// and `..` lexically. Unless `kind` allows escaping, a result that climbs above
/// the config root is an error: such a path could never match a
/// repository-relative path, and silently keeping it would be a rule that never
/// fires.
fn rebase(
    prefix: &[String],
    rel: &str,
    file: &Path,
    subject: &str,
    kind: Rebased,
) -> Result<String, String> {
    let allow_escape = kind.allows_escape();
    let escaped = |rel: &str| {
        format!(
            "{}: {subject} {rel:?} resolves outside the config root",
            file.display()
        )
    };

    let mut parts: Vec<&str> = prefix.iter().map(String::as_str).collect();
    for segment in rel.split(kind.separators()) {
        match segment {
            "" | "." => {}
            ".." => match parts.last() {
                Some(&last) if last != ".." => {
                    parts.pop();
                }
                _ if allow_escape => parts.push(".."),
                _ => return Err(escaped(rel)),
            },
            other => parts.push(other),
        }
    }

    if !allow_escape && parts.first() == Some(&"..") {
        return Err(escaped(rel));
    }
    if parts.is_empty() {
        return Ok(".".to_string());
    }
    Ok(parts.join("/"))
}

impl Config {
    /// Directory holding the root config file. Every relative path in the
    /// merged config resolves against it, and it is the anchor directory when
    /// [`Config::anchor`] is [`Anchor::Config`].
    pub fn config_root(&self) -> &Path {
        &self.config_dir
    }

    /// Extra rule directories, resolved against the config root. Directories
    /// contributed by an included file are already rebased onto it.
    pub fn rule_dirs(&self) -> Vec<PathBuf> {
        self.rules
            .iter()
            .map(|rel| self.config_dir.join(rel))
            .collect()
    }

    /// Compiled silo globs, sorted by silo name.
    pub fn silo_sets(&self) -> Result<Vec<(String, GlobSet)>, String> {
        let mut sets = Vec::with_capacity(self.silos.len());
        // `BTreeMap` iterates in key order, so `sets` is sorted by name.
        for (name, patterns) in &self.silos {
            let mut builder = GlobSetBuilder::new();
            for pattern in patterns {
                let glob = Glob::new(pattern)
                    .map_err(|e| format!("silo {name}: invalid glob {pattern:?}: {e}"))?;
                builder.add(glob);
            }
            let set = builder
                .build()
                .map_err(|e| format!("silo {name}: invalid globs: {e}"))?;
            sets.push((name.clone(), set));
        }
        Ok(sets)
    }

    /// The silo owning `path_rel`, or `None` when no silo matches. `sets` must
    /// come from [`Config::silo_sets`]; overlapping silos resolve to the
    /// alphabetically first matching name, which makes the assignment
    /// deterministic rather than dependent on config file order.
    pub fn silo_of<'a>(&self, sets: &'a [(String, GlobSet)], path_rel: &str) -> Option<&'a str> {
        sets.iter()
            .find(|(_, set)| set.is_match(path_rel))
            .map(|(name, _)| name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
source_roots = ["src", "lib"]
rules = ["rules/local"]

[silos]
api = ["crates/api/**"]
core = ["crates/core/**", "crates/shared/**"]

[languages]
mjs = "javascript"
"#;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        path
    }

    /// Mark `dir` as a repository root the way git does.
    fn git_root(dir: &Path) {
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    #[test]
    fn parses_every_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, SAMPLE);
        let config = load(&path).expect("should load");

        assert_eq!(config.silos.keys().collect::<Vec<_>>(), vec!["api", "core"]);
        assert_eq!(config.silos["core"].len(), 2);
        assert_eq!(config.source_roots, vec!["src", "lib"]);
        assert_eq!(config.languages["mjs"], "javascript");
        assert_eq!(config.rules, vec!["rules/local"]);
    }

    #[test]
    fn empty_config_is_default_apart_from_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        let expected = Config {
            config_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        assert_eq!(load(&path).unwrap(), expected);
    }

    #[test]
    fn config_root_is_the_directory_of_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "rules = [\"rules/local\"]\n");
        let config = load(&path).expect("should load");

        assert_eq!(config.config_root(), dir.path());
        assert_eq!(config.rule_dirs(), vec![dir.path().join("rules/local")]);
    }

    #[test]
    fn config_root_of_a_bare_filename_is_the_current_directory() {
        // `Path::parent` of a bare filename is `Some("")`, which anchoring
        // cannot measure from: `--config siloscan.toml` must still name a
        // directory.
        assert_eq!(config_dir_of(Path::new(CONFIG_NAME)), Path::new("."));
        assert_eq!(
            config_dir_of(Path::new("modules/api/siloscan.toml")),
            Path::new("modules/api")
        );
    }

    #[test]
    fn unknown_key_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "nonsense = true\n");
        assert!(load(&path).is_err());
    }

    #[test]
    fn bad_silo_name_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "[silos]\n\"Api Layer\" = [\"a/**\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("invalid silo name"), "{err}");
    }

    #[test]
    fn bad_glob_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[silos]\napi = [\"a[b\"]\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("invalid glob"), "{err}");
    }

    #[test]
    fn discover_walks_up_to_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("repo/src/deep")).unwrap();
        git_root(&root.join("repo"));
        let expected = write(&root.join("repo"), CONFIG_NAME, "");

        let found = discover(&root.join("repo/src/deep")).expect("should discover");
        assert_eq!(found, expected.canonicalize().unwrap());
    }

    #[test]
    fn discover_stops_at_the_git_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("repo/src")).unwrap();
        git_root(&root.join("repo"));
        // Config lives above the repository: out of reach.
        write(root, CONFIG_NAME, "");

        assert_eq!(discover(&root.join("repo/src")), None);
    }

    #[test]
    fn discover_finds_a_config_in_the_scan_root_without_a_vcs_marker() {
        let dir = tempfile::tempdir().unwrap();
        let expected = write(dir.path(), CONFIG_NAME, "");

        let found = discover(dir.path()).expect("should discover");
        assert_eq!(found, expected.canonicalize().unwrap());
    }

    #[test]
    fn discover_ignores_an_ancestor_config_without_a_vcs_marker() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("repo/src")).unwrap();
        // No `.git` anywhere: nothing above the scan root is in reach.
        write(root, CONFIG_NAME, "");

        assert_eq!(discover(&root.join("repo")), None);
        assert_eq!(discover(&root.join("repo/src")), None);
    }

    #[test]
    fn silo_of_prefers_the_alphabetically_first_match() {
        let config: Config = toml::from_str(
            r#"
[silos]
zulu = ["src/**"]
alpha = ["src/**"]
"#,
        )
        .unwrap();
        let sets = config.silo_sets().unwrap();

        assert_eq!(
            sets.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "zulu"]
        );
        assert_eq!(config.silo_of(&sets, "src/main.rs"), Some("alpha"));
        assert_eq!(config.silo_of(&sets, "docs/readme.md"), None);
    }

    #[test]
    fn duplication_absent_defaults_to_10() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        let config = load(&path).expect("should load");
        assert_eq!(config.duplication.min_lines, 10);
    }

    #[test]
    fn duplication_explicit_value_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[duplication]\nmin_lines = 5\n");
        let config = load(&path).expect("should load");
        assert_eq!(config.duplication.min_lines, 5);
    }

    #[test]
    fn duplication_min_lines_zero_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[duplication]\nmin_lines = 0\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("min_lines must be at least 2"), "{err}");
        assert!(err.contains("0"), "{err}");
    }

    #[test]
    fn duplication_min_lines_one_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "[duplication]\nmin_lines = 1\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("min_lines must be at least 2"), "{err}");
        assert!(err.contains("1"), "{err}");
    }

    /// Root config plus a module config two directories down.
    fn with_include(dir: &Path, root_body: &str, module_body: &str) -> PathBuf {
        fs::create_dir_all(dir.join("modules/api")).unwrap();
        write(&dir.join("modules/api"), CONFIG_NAME, module_body);
        write(dir, CONFIG_NAME, root_body)
    }

    #[test]
    fn include_contributes_paths_relative_to_the_included_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\nrules = [\"rules/root\"]\n",
            r#"
source_roots = ["src"]
rules = ["../../rules/shared", "./rules/api"]

[silos]
api = ["src/**", "tests/**"]
"#,
        );
        let config = load(&path).expect("should load");

        assert_eq!(
            config.silos["api"],
            vec!["modules/api/src/**", "modules/api/tests/**"]
        );
        assert_eq!(config.source_roots, vec!["modules/api/src"]);
        assert_eq!(
            config.rules,
            vec!["rules/root", "rules/shared", "modules/api/rules/api"]
        );
        assert_eq!(
            config.rule_dirs(),
            vec![
                dir.path().join("rules/root"),
                dir.path().join("rules/shared"),
                dir.path().join("modules/api/rules/api"),
            ]
        );
    }

    #[test]
    fn include_silo_globs_match_config_root_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n\n[silos]\ncore = [\"crates/core/**\"]\n",
            "[silos]\napi = [\"src/**\"]\n",
        );
        let config = load(&path).expect("should load");
        let sets = config.silo_sets().expect("globs should compile");

        assert_eq!(
            config.silo_of(&sets, "modules/api/src/main.rs"),
            Some("api")
        );
        assert_eq!(config.silo_of(&sets, "crates/core/lib.rs"), Some("core"));
        assert_eq!(config.silo_of(&sets, "src/main.rs"), None);
    }

    #[test]
    fn include_silo_glob_keeps_globset_escapes_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            r#"[silos]
api = ["src/a\\[0\\].rs"]
"#,
        );
        let config = load(&path).expect("should load");

        // `\` escapes the bracket for globset: the pattern survives the rebase
        // byte for byte under its new prefix.
        assert_eq!(config.silos["api"], vec![r"modules/api/src/a\[0\].rs"]);
        let sets = config.silo_sets().expect("globs should compile");
        assert_eq!(
            config.silo_of(&sets, "modules/api/src/a[0].rs"),
            Some("api")
        );
    }

    #[test]
    fn include_rejects_root_only_keys() {
        for (key, body) in [
            ("anchor", "anchor = \"config\"\n"),
            ("duplication", "[duplication]\nmin_lines = 4\n"),
            ("languages", "[languages]\nmjs = \"javascript\"\n"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = with_include(
                dir.path(),
                "include = [\"modules/api/siloscan.toml\"]\n",
                body,
            );
            let err = load(&path).unwrap_err();
            assert!(err.contains(key), "{key}: {err}");
            assert!(err.contains("modules/api"), "{key}: {err}");
        }
    }

    #[test]
    fn include_inside_an_included_config_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            "include = [\"../core/siloscan.toml\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("single level"), "{err}");
        assert!(err.contains("modules/api"), "{err}");
    }

    #[test]
    fn silo_collision_between_root_and_include_names_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n\n[silos]\napi = [\"legacy/**\"]\n",
            "[silos]\napi = [\"src/**\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("duplicate silo name: api"), "{err}");
        assert!(err.contains("modules/api/siloscan.toml"), "{err}");
        assert!(
            err.contains(&dir.path().join(CONFIG_NAME).display().to_string()),
            "{err}"
        );
    }

    #[test]
    fn silo_collision_between_two_includes_names_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("modules/one")).unwrap();
        fs::create_dir_all(root.join("modules/two")).unwrap();
        write(
            &root.join("modules/one"),
            CONFIG_NAME,
            "[silos]\napi = [\"src/**\"]\n",
        );
        write(
            &root.join("modules/two"),
            CONFIG_NAME,
            "[silos]\napi = [\"src/**\"]\n",
        );
        let path = write(
            root,
            CONFIG_NAME,
            "include = [\"modules/one/siloscan.toml\", \"modules/two/siloscan.toml\"]\n",
        );

        let err = load(&path).unwrap_err();
        assert!(err.contains("duplicate silo name: api"), "{err}");
        assert!(err.contains("modules/one/siloscan.toml"), "{err}");
        assert!(err.contains("modules/two/siloscan.toml"), "{err}");
    }

    #[test]
    fn missing_include_file_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "include = [\"modules/api/siloscan.toml\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("cannot read included config"), "{err}");
        assert!(err.contains("modules/api/siloscan.toml"), "{err}");
    }

    #[test]
    fn include_listed_twice_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\", \"modules/api/siloscan.toml\"]\n",
            "rules = [\"rules\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn include_must_be_a_relative_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "include = [\"/etc/siloscan.toml\"]\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("must be a relative path"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "include = [\"modules/\"]\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("must name a config file"), "{err}");
    }

    #[test]
    fn include_silo_glob_leaving_the_config_root_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            "[silos]\napi = [\"../../../elsewhere/**\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("silo glob"), "{err}");
        assert!(err.contains("outside the config root"), "{err}");
    }

    #[test]
    fn include_bad_silo_name_names_the_included_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = with_include(
            dir.path(),
            "include = [\"modules/api/siloscan.toml\"]\n",
            "[silos]\n\"API\" = [\"src/**\"]\n",
        );
        let err = load(&path).unwrap_err();

        assert!(err.contains("invalid silo name"), "{err}");
        assert!(err.contains("modules/api/siloscan.toml"), "{err}");
    }

    #[test]
    fn anchor_defaults_to_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        assert_eq!(load(&path).unwrap().anchor, Anchor::ScanRoot);
        assert_eq!(Anchor::default(), Anchor::ScanRoot);
    }

    #[test]
    fn anchor_parses_both_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "anchor = \"scan-root\"\n");
        assert_eq!(load(&path).unwrap().anchor, Anchor::ScanRoot);

        let path = write(dir.path(), "other.toml", "anchor = \"config\"\n");
        assert_eq!(load(&path).unwrap().anchor, Anchor::Config);
    }

    #[test]
    fn unknown_anchor_value_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "anchor = \"repo\"\n");
        let err = load(&path).unwrap_err();
        assert!(err.contains("repo"), "{err}");
        assert!(err.contains("scan-root"), "{err}");
    }

    #[test]
    fn anchor_round_trips_through_its_spelling() {
        assert_eq!(Anchor::ScanRoot.as_str(), "scan-root");
        assert_eq!(Anchor::Config.as_str(), "config");
    }

    #[test]
    fn duplication_unknown_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            CONFIG_NAME,
            "[duplication]\nmin_lines = 10\nwrongkey = true\n",
        );
        let err = load(&path).unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
    }
}
