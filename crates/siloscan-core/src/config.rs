//! Optional repository configuration (`siloscan.toml`).
//!
//! The config is discovered from the scan root upwards and never from the user
//! environment: no home-directory config, no environment variables. A scan of
//! the same tree therefore resolves the same config on every machine.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;

pub const CONFIG_NAME: &str = "siloscan.toml";

const fn default_min_lines() -> usize {
    10
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

    /// Duplication detection settings.
    #[serde(default)]
    pub duplication: DuplicationConfig,
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

/// Read and validate a config file. Errors carry the file path.
pub fn load(path: &Path) -> Result<Config, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config: Config = toml::from_str(&src).map_err(|e| format!("{}: {e}", path.display()))?;

    for name in config.silos.keys() {
        if !is_silo_name(name) {
            return Err(format!(
                "{}: invalid silo name: {name} (expected ^[a-z0-9-]+$)",
                path.display()
            ));
        }
    }

    // Compiling the sets is the glob validation.
    config
        .silo_sets()
        .map_err(|e| format!("{}: {e}", path.display()))?;

    if config.duplication.min_lines < 2 {
        return Err(format!(
            "{}: duplication.min_lines must be at least 2, got {}",
            path.display(),
            config.duplication.min_lines
        ));
    }

    Ok(config)
}

impl Config {
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
    fn empty_config_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), CONFIG_NAME, "");
        assert_eq!(load(&path).unwrap(), Config::default());
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
