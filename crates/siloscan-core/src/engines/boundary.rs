//! Silo boundary engine.
//!
//! A violation is a single resolved, repository-internal import edge: a file in
//! the rule's `from` silo importing a file whose silo is on the rule's deny
//! list. Import resolution is a best-effort, purely lexical mapping from an
//! import as written to a repo-relative path; a candidate counts only when it
//! is a key of the scanned file set, so no filesystem access is involved and an
//! unresolved import (an external dependency) is never a violation. Go is the
//! exception to "purely lexical": its imports are module paths, so they are
//! anchored to the `go.mod` files found in the scanned tree.

use std::collections::BTreeMap;

use globset::GlobSet;

use super::{Occurrences, applies};
use crate::config::Config;
use crate::findings::{Finding, fingerprint};
use crate::graph::Graph;
use crate::rules::{CompiledPayload, CompiledRule};

/// A boundary violation: the finding plus the edge that produced it. The silo
/// pair is not recoverable from the finding alone, and consumers that draw the
/// silo graph need it, so it is reported alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub finding: Finding,
    /// Silo of the importing file.
    pub from: String,
    /// Silo of the imported file.
    pub to: String,
}

/// A Go module declared inside the scanned tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoModule {
    /// Repo-relative directory holding the `go.mod`; empty at the repo root.
    pub dir: String,
    /// Module path as declared, e.g. `example.com/app`.
    pub path: String,
}

/// Module declarations for the scanned tree, from `go.mod` path -> content.
/// Longest module path first, so a nested module wins over the module that
/// contains it; ties break bytewise, which keeps resolution deterministic.
pub fn go_modules(sources: &BTreeMap<String, String>) -> Vec<GoModule> {
    let mut modules: Vec<GoModule> = sources
        .iter()
        .filter_map(|(path, content)| parse_go_mod(path, content))
        .collect();
    modules.sort_by(|a, b| {
        b.path
            .len()
            .cmp(&a.path.len())
            .then(a.path.as_bytes().cmp(b.path.as_bytes()))
            .then(a.dir.as_bytes().cmp(b.dir.as_bytes()))
    });
    modules
}

/// The module declared by a `go.mod` at repo-relative `path`: the first
/// `module <path>` directive, ignoring comments and quoting.
fn parse_go_mod(path: &str, content: &str) -> Option<GoModule> {
    let dir = parent(path).to_string();
    for line in content.lines() {
        let line = line.split("//").next().unwrap_or(line).trim();
        let Some(rest) = line.strip_prefix("module") else {
            continue;
        };
        let module = rest.trim().trim_matches('"').trim_matches('/');
        if !rest.starts_with(char::is_whitespace) || module.is_empty() {
            continue;
        }
        return Some(GoModule {
            dir,
            path: module.to_string(),
        });
    }
    None
}

/// Run every boundary rule over the semantic graph. Violations are ordered by
/// file (graph order), then by import order within the file, then by rule
/// order. `go_modules` anchors Go import paths; without it no Go import
/// resolves, since a Go import is a module path and nothing else says which
/// module paths belong to this repository.
pub fn scan_graph(
    rules: &[CompiledRule],
    graph: &Graph,
    config: &Config,
    silo_sets: &[(String, GlobSet)],
    go_modules: &[GoModule],
) -> Vec<Violation> {
    let mut findings = Vec::new();

    for (path, facts) in &graph.files {
        let Some(from_silo) = config.silo_of(silo_sets, path) else {
            continue;
        };

        let active: Vec<&CompiledRule> = rules
            .iter()
            .filter(|rule| match &rule.payload {
                CompiledPayload::Boundary { from, .. } => {
                    from == from_silo && applies(rule, path, None)
                }
                _ => false,
            })
            .collect();
        if active.is_empty() {
            continue;
        }

        let mut occurrences = Occurrences::new();
        for import in &facts.imports {
            let Some(target) = resolve(
                graph,
                config,
                go_modules,
                path,
                &facts.language,
                &import.raw,
            ) else {
                continue;
            };
            let Some(target_silo) = config.silo_of(silo_sets, &target) else {
                continue;
            };

            for rule in &active {
                let CompiledPayload::Boundary { deny, .. } = &rule.payload else {
                    continue;
                };
                if !deny.iter().any(|silo| silo == target_silo) {
                    continue;
                }

                let occurrence = occurrences.next(rule.id.as_str(), &import.raw);
                findings.push(Violation {
                    finding: Finding {
                        rule_id: rule.id.clone(),
                        severity: rule.severity,
                        message: rule.message.clone(),
                        path: path.clone(),
                        line: import.line,
                        column: import.column,
                        matched: import.raw.clone(),
                        fingerprint: fingerprint(&rule.id, path, &import.raw, occurrence),
                    },
                    from: from_silo.to_string(),
                    to: target_silo.to_string(),
                });
            }
        }
    }

    findings
}

/// The scanned file an import refers to, or `None` when nothing in the scanned
/// set matches.
fn resolve(
    graph: &Graph,
    config: &Config,
    go_modules: &[GoModule],
    from_path: &str,
    language: &str,
    raw: &str,
) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let mut bases = Vec::new();
    candidates(config, go_modules, from_path, language, raw, &mut bases);
    bases
        .into_iter()
        .find_map(|base| lookup(graph, language, &base))
}

/// Candidate repo-relative paths, without a file extension, in priority order.
fn candidates(
    config: &Config,
    go_modules: &[GoModule],
    from_path: &str,
    language: &str,
    raw: &str,
    out: &mut Vec<String>,
) {
    let dir = parent(from_path);

    match language {
        "javascript" | "typescript" => {
            if raw.starts_with("./") || raw.starts_with("../") {
                push(out, join(dir, raw));
            }
        }
        // Quoted and angled includes are indistinguishable after import
        // normalization, so both are tried against the includer's directory
        // first and the configured roots after.
        "c" | "cpp" | "ruby" => {
            push(out, join(dir, raw));
            for anchor in anchors(config) {
                push(out, join(&anchor, raw));
            }
        }
        "python" => python_candidates(config, dir, raw, out),
        "rust" => rust_candidates(from_path, raw, out),
        "go" => go_candidates(go_modules, raw, out),
        "java" | "csharp" => dotted_candidates(config, raw, out),
        _ => {}
    }
}

fn python_candidates(config: &Config, dir: &str, raw: &str, out: &mut Vec<String>) {
    let dots = raw.bytes().take_while(|b| *b == b'.').count();
    if dots > 0 {
        let rest = raw[dots..].replace('.', "/");
        let Some(base) = ascend(dir, dots - 1) else {
            return;
        };
        if rest.is_empty() {
            push(out, Some(base));
        } else {
            push(out, join(&base, &rest));
        }
        return;
    }

    let rest = raw.replace('.', "/");
    for anchor in anchors(config) {
        push(out, join(&anchor, &rest));
    }
}

fn rust_candidates(from_path: &str, raw: &str, out: &mut Vec<String>) {
    let head = raw.split('{').next().unwrap_or(raw);
    let segments: Vec<&str> = head
        .split("::")
        .map(str::trim)
        .filter(|segment| !segment.is_empty() && *segment != "*")
        .collect();

    let (base, rest) = match segments.first().copied() {
        Some("crate") => (crate_src(from_path), &segments[1..]),
        Some("self") => (module_dir(from_path), &segments[1..]),
        Some("super") => {
            let supers = segments
                .iter()
                .take_while(|segment| **segment == "super")
                .count();
            let Some(base) = ascend(&module_dir(from_path), supers) else {
                return;
            };
            (base, &segments[supers..])
        }
        // Anything else names an external crate or a re-export root.
        _ => return,
    };

    // The tail of a `use` path names an item, not a module, so shorter
    // prefixes are tried after the full path.
    for len in (1..=rest.len()).rev() {
        push(out, join(&base, &rest[..len].join("/")));
    }
}

/// A Go import is a module path. It names something in this repository only
/// when it is inside a module declared by a `go.mod` in the scanned tree, so
/// the declared module path is stripped and the remainder resolved against the
/// module's directory. An import matching no declared module is an external
/// dependency and yields no candidate.
fn go_candidates(go_modules: &[GoModule], raw: &str, out: &mut Vec<String>) {
    let raw = raw.trim_matches('/');
    for module in go_modules {
        let rest = if raw == module.path {
            ""
        } else {
            match raw
                .strip_prefix(module.path.as_str())
                .and_then(|rest| rest.strip_prefix('/'))
            {
                Some(rest) => rest,
                None => continue,
            }
        };
        push(out, join(&module.dir, rest));
    }
}

/// Java packages and C# namespaces map onto directories by convention only, so
/// resolution is a heuristic: the full dotted path first, then the path without
/// its last segment for static and member imports.
fn dotted_candidates(config: &Config, raw: &str, out: &mut Vec<String>) {
    let segments: Vec<&str> = raw
        .split('.')
        .map(str::trim)
        .filter(|segment| !segment.is_empty() && *segment != "*")
        .collect();
    if segments.is_empty() {
        return;
    }

    let shortest = segments.len().saturating_sub(1).max(1);
    for len in (shortest..=segments.len()).rev() {
        let path = segments[..len].join("/");
        for anchor in anchors(config) {
            push(out, join(&anchor, &path));
        }
    }
}

/// The scanned file for an extensionless candidate path.
fn lookup(graph: &Graph, language: &str, base: &str) -> Option<String> {
    if graph.files.contains_key(base) {
        return Some(base.to_string());
    }

    for suffix in extensions(language) {
        let candidate = format!("{base}{suffix}");
        if graph.files.contains_key(&candidate) {
            return Some(candidate);
        }
    }

    // Go packages and C# namespaces name a directory; any file directly inside
    // it stands in for the package's silo.
    match language {
        "go" => first_in_dir(graph, base, ".go"),
        "csharp" => first_in_dir(graph, base, ".cs"),
        _ => None,
    }
}

/// Suffixes appended to a candidate path, in priority order. C and C++ includes
/// carry their own extension and get none.
fn extensions(language: &str) -> &'static [&'static str] {
    match language {
        "javascript" | "typescript" => &[
            ".js",
            ".ts",
            ".tsx",
            ".mjs",
            "/index.js",
            "/index.ts",
            "/index.tsx",
            "/index.mjs",
        ],
        "python" => &[".py", "/__init__.py"],
        "rust" => &[".rs", "/mod.rs"],
        "go" => &[".go"],
        "java" => &[".java"],
        "csharp" => &[".cs"],
        "ruby" => &[".rb"],
        _ => &[],
    }
}

/// The first scanned file directly inside `dir` with extension `ext`, in graph
/// order.
fn first_in_dir(graph: &Graph, dir: &str, ext: &str) -> Option<String> {
    let prefix = format!("{dir}/");
    graph
        .files
        .range(prefix.clone()..)
        .map(|(key, _)| key)
        .take_while(|key| key.starts_with(&prefix))
        .find(|key| {
            let name = &key[prefix.len()..];
            !name.contains('/') && name.ends_with(ext)
        })
        .cloned()
}

/// Directories import resolution anchors to: the configured source roots, then
/// the repository root.
fn anchors(config: &Config) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(config.source_roots.len() + 1);
    for root in &config.source_roots {
        let root = root.trim_matches('/').to_string();
        if !out.contains(&root) {
            out.push(root);
        }
    }
    if !out.iter().any(|root| root.is_empty()) {
        out.push(String::new());
    }
    out
}

/// The `src` directory of the crate owning `from_path`.
fn crate_src(from_path: &str) -> String {
    match from_path.rfind("/src/") {
        Some(index) => from_path[..index + 4].to_string(),
        None => "src".to_string(),
    }
}

/// The directory holding the child modules of the module defined by
/// `from_path`.
fn module_dir(from_path: &str) -> String {
    let dir = parent(from_path);
    let stem = from_path
        .rsplit('/')
        .next()
        .unwrap_or(from_path)
        .trim_end_matches(".rs");

    if matches!(stem, "mod" | "lib" | "main") {
        return dir.to_string();
    }
    if dir.is_empty() {
        return stem.to_string();
    }
    format!("{dir}/{stem}")
}

fn parent(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((dir, _)) => dir,
        None => "",
    }
}

/// `dir` with `count` trailing components removed; `None` when that walks above
/// the repository root.
fn ascend(dir: &str, count: usize) -> Option<String> {
    let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < count {
        return None;
    }
    parts.truncate(parts.len() - count);
    Some(parts.join("/"))
}

/// Normalized `base/rel`, with `.` and `..` resolved; `None` when the result
/// escapes the repository root or is empty.
fn join(base: &str, rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for segment in base.split('/').chain(rel.split('/')) {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }

    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

fn push(out: &mut Vec<String>, candidate: Option<String>) {
    if let Some(candidate) = candidate
        && !out.contains(&candidate)
    {
        out.push(candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{FileFacts, Import};
    use crate::rules::{Severity, load_str};

    fn config(src: &str) -> (Config, Vec<(String, GlobSet)>) {
        let config: Config = toml::from_str(src).expect("config should parse");
        let sets = config.silo_sets().expect("globs should compile");
        (config, sets)
    }

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    /// The findings of [`scan_graph`], for the cases the silo pair is not what
    /// is under test.
    fn findings(
        rules: &[CompiledRule],
        graph: &Graph,
        config: &Config,
        silo_sets: &[(String, GlobSet)],
    ) -> Vec<Finding> {
        findings_in_modules(rules, graph, config, silo_sets, &[])
    }

    fn findings_in_modules(
        rules: &[CompiledRule],
        graph: &Graph,
        config: &Config,
        silo_sets: &[(String, GlobSet)],
        modules: &[GoModule],
    ) -> Vec<Finding> {
        scan_graph(rules, graph, config, silo_sets, modules)
            .into_iter()
            .map(|violation| violation.finding)
            .collect()
    }

    fn go_module(dir: &str, path: &str) -> GoModule {
        GoModule {
            dir: dir.to_string(),
            path: path.to_string(),
        }
    }

    fn file(language: &str, imports: &[(&str, u64, u64)]) -> FileFacts {
        FileFacts {
            language: language.to_string(),
            imports: imports
                .iter()
                .map(|(raw, line, column)| Import {
                    raw: (*raw).to_string(),
                    line: *line,
                    column: *column,
                })
                .collect(),
            decls: Vec::new(),
        }
    }

    fn graph(files: &[(&str, FileFacts)]) -> Graph {
        let mut out = Graph::default();
        for (path, facts) in files {
            out.files.insert((*path).to_string(), facts.clone());
        }
        out
    }

    const API_DENIES_DB: &str = r#"
version: 1
rules:
  - id: arch.api-must-not-import-db
    severity: error
    message: "api must not import db"
    boundary:
      from: api
      deny: ["db"]
"#;

    const SILOS: &str = r#"
[silos]
api = ["src/api/**"]
db = ["src/db/**"]
util = ["src/util/**"]
"#;

    #[test]
    fn javascript_relative_import_across_silos_is_reported() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/handler.js",
                file("javascript", &[("../db/client", 3, 20)]),
            ),
            ("src/db/client.js", file("javascript", &[])),
        ]);

        let found = findings(&compiled, &files, &config, &sets);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "arch.api-must-not-import-db");
        assert_eq!(found[0].severity, Severity::Error);
        assert_eq!(found[0].message, "api must not import db");
        assert_eq!(found[0].path, "src/api/handler.js");
        assert_eq!((found[0].line, found[0].column), (3, 20));
        assert_eq!(found[0].matched, "../db/client");
        assert_eq!(
            found[0].fingerprint,
            fingerprint(
                "arch.api-must-not-import-db",
                "src/api/handler.js",
                "../db/client",
                0
            )
        );
    }

    #[test]
    fn a_violation_carries_the_silo_pair_of_its_edge() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/handler.js",
                file("javascript", &[("../db/client", 3, 20)]),
            ),
            ("src/db/client.js", file("javascript", &[])),
        ]);

        let found = scan_graph(&compiled, &files, &config, &sets, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].from, "api");
        assert_eq!(found[0].to, "db");
        assert_eq!(found[0].finding.path, "src/api/handler.js");
    }

    #[test]
    fn javascript_directory_import_resolves_to_index() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            ("src/api/handler.ts", file("typescript", &[("../db", 1, 1)])),
            ("src/db/index.ts", file("typescript", &[])),
        ]);

        assert_eq!(findings(&compiled, &files, &config, &sets).len(), 1);
    }

    #[test]
    fn python_module_import_across_silos_is_reported() {
        let (config, sets) = config(
            r#"
source_roots = ["src"]

[silos]
api = ["src/app/api/**"]
db = ["src/app/db/**"]
"#,
        );
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/app/api/views.py",
                file("python", &[("app.db.client", 2, 1)]),
            ),
            ("src/app/db/client.py", file("python", &[])),
        ]);

        let found = findings(&compiled, &files, &config, &sets);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "src/app/api/views.py");
        assert_eq!(found[0].line, 2);
    }

    #[test]
    fn python_package_import_resolves_to_init() {
        let (config, sets) = config(
            r#"
[silos]
api = ["app/api/**"]
db = ["app/db/**"]
"#,
        );
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            ("app/api/views.py", file("python", &[("app.db", 1, 1)])),
            ("app/db/__init__.py", file("python", &[])),
        ]);

        assert_eq!(findings(&compiled, &files, &config, &sets).len(), 1);
    }

    #[test]
    fn rust_crate_path_resolves_under_src() {
        let (config, sets) = config(
            r#"
[silos]
api = ["src/api/**"]
db = ["src/db/**"]
"#,
        );
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/handler.rs",
                file("rust", &[("crate::db::client::Pool", 4, 5)]),
            ),
            ("src/db/client.rs", file("rust", &[])),
        ]);

        let found = findings(&compiled, &files, &config, &sets);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "crate::db::client::Pool");
        assert_eq!((found[0].line, found[0].column), (4, 5));
    }

    #[test]
    fn rust_crate_path_resolves_to_a_module_root() {
        let (config, sets) = config(
            r#"
[silos]
api = ["crates/app/src/api/**"]
db = ["crates/app/src/db/**"]
"#,
        );
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "crates/app/src/api/handler.rs",
                file("rust", &[("crate::db::{Pool, Row}", 1, 5)]),
            ),
            ("crates/app/src/db/mod.rs", file("rust", &[])),
        ]);

        assert_eq!(findings(&compiled, &files, &config, &sets).len(), 1);
    }

    #[test]
    fn rust_super_path_resolves_relative_to_the_parent_module() {
        let (config, sets) = config(
            r#"
[silos]
api = ["src/api/**"]
db = ["src/db/**"]
"#,
        );
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/handler.rs",
                file("rust", &[("super::super::db::client::Pool", 1, 5)]),
            ),
            ("src/db/client.rs", file("rust", &[])),
        ]);

        assert_eq!(findings(&compiled, &files, &config, &sets).len(), 1);
    }

    const GO_SILOS: &str = r#"
[silos]
api = ["internal/api/**"]
db = ["internal/db/**"]
"#;

    #[test]
    fn go_package_import_resolves_to_a_file_in_the_directory() {
        let (config, sets) = config(GO_SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "internal/api/server.go",
                file("go", &[("example.com/app/internal/db", 3, 2)]),
            ),
            ("internal/db/client.go", file("go", &[])),
        ]);
        let modules = [go_module("", "example.com/app")];

        assert_eq!(
            findings_in_modules(&compiled, &files, &config, &sets, &modules).len(),
            1
        );
    }

    #[test]
    fn go_import_of_another_module_does_not_resolve_locally() {
        let (config, sets) = config(GO_SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "internal/api/server.go",
                file(
                    "go",
                    &[
                        ("github.com/vendor/otherproject/internal/db", 3, 8),
                        ("example.com/appextra/internal/db", 4, 8),
                    ],
                ),
            ),
            ("internal/db/client.go", file("go", &[])),
        ]);
        let modules = [go_module("", "example.com/app")];

        assert!(findings_in_modules(&compiled, &files, &config, &sets, &modules).is_empty());
    }

    #[test]
    fn go_imports_do_not_resolve_without_a_go_mod() {
        let (config, sets) = config(GO_SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "internal/api/server.go",
                file("go", &[("internal/db", 3, 8)]),
            ),
            ("internal/db/client.go", file("go", &[])),
        ]);

        assert!(findings(&compiled, &files, &config, &sets).is_empty());
    }

    #[test]
    fn go_nested_module_wins_over_the_module_containing_it() {
        let (config, sets) = config(
            r#"
[silos]
api = ["svc/internal/api/**"]
db = ["svc/internal/db/**"]
"#,
        );
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "svc/internal/api/server.go",
                file("go", &[("example.com/app/svc/internal/db", 3, 8)]),
            ),
            ("svc/internal/db/client.go", file("go", &[])),
        ]);
        let modules = go_modules(&BTreeMap::from([
            (
                "go.mod".to_string(),
                "module example.com/app\n\ngo 1.22\n".to_string(),
            ),
            (
                "svc/go.mod".to_string(),
                "module example.com/app/svc\n".to_string(),
            ),
        ]));

        assert_eq!(
            modules,
            vec![
                go_module("svc", "example.com/app/svc"),
                go_module("", "example.com/app"),
            ]
        );
        // The nested module claims `example.com/app/svc/...` first, but its own
        // directory is `svc`, so the path is the same either way.
        assert_eq!(
            findings_in_modules(&compiled, &files, &config, &sets, &modules).len(),
            1
        );
    }

    #[test]
    fn go_mod_parsing_ignores_comments_and_other_directives() {
        let modules = go_modules(&BTreeMap::from([
            (
                "a/go.mod".to_string(),
                "// module not.this/one\nmodule \"example.com/a\" // trailing\n".to_string(),
            ),
            (
                "b/go.mod".to_string(),
                "go 1.22\nrequire x v1\n".to_string(),
            ),
            ("c/go.mod".to_string(), "modulefoo bar\n".to_string()),
        ]));

        assert_eq!(modules, vec![go_module("a", "example.com/a")]);
    }

    #[test]
    fn java_import_resolves_by_package_path() {
        let (config, sets) = config(
            r#"
source_roots = ["src/main/java"]

[silos]
api = ["src/main/java/com/example/api/**"]
db = ["src/main/java/com/example/db/**"]
"#,
        );
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/main/java/com/example/api/Handler.java",
                file("java", &[("com.example.db.Pool", 1, 1)]),
            ),
            ("src/main/java/com/example/db/Pool.java", file("java", &[])),
        ]);

        assert_eq!(findings(&compiled, &files, &config, &sets).len(), 1);
    }

    #[test]
    fn c_quoted_include_resolves_relative_to_the_includer() {
        let (config, sets) = config(
            r#"
[silos]
api = ["src/api/**"]
db = ["src/db/**"]
"#,
        );
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/server.c",
                file("c", &[("../db/client.h", 1, 10), ("stdio.h", 2, 10)]),
            ),
            ("src/db/client.h", file("c", &[])),
        ]);

        let found = findings(&compiled, &files, &config, &sets);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "../db/client.h");
    }

    #[test]
    fn ruby_require_relative_resolves() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/handler.rb",
                file("ruby", &[("../db/client", 1, 1), ("json", 2, 1)]),
            ),
            ("src/db/client.rb", file("ruby", &[])),
        ]);

        assert_eq!(findings(&compiled, &files, &config, &sets).len(), 1);
    }

    #[test]
    fn unresolved_external_imports_are_silent() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[(
            "src/api/handler.js",
            file(
                "javascript",
                &[("lodash", 1, 1), ("node:fs", 2, 1), ("../missing/db", 3, 1)],
            ),
        )]);

        assert!(findings(&compiled, &files, &config, &sets).is_empty());
    }

    #[test]
    fn imports_into_an_allowed_silo_are_silent() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/handler.js",
                file(
                    "javascript",
                    &[("../util/log", 1, 1), ("../db/client", 2, 1)],
                ),
            ),
            ("src/db/client.js", file("javascript", &[])),
            ("src/util/log.js", file("javascript", &[])),
        ]);

        let found = findings(&compiled, &files, &config, &sets);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "../db/client");
    }

    #[test]
    fn same_silo_imports_are_silent() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/handler.js",
                file("javascript", &[("./routes", 1, 1)]),
            ),
            ("src/api/routes.js", file("javascript", &[])),
        ]);

        assert!(findings(&compiled, &files, &config, &sets).is_empty());
    }

    #[test]
    fn files_outside_the_from_silo_are_silent() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/util/log.js",
                file("javascript", &[("../db/client", 1, 1)]),
            ),
            ("src/db/client.js", file("javascript", &[])),
        ]);

        assert!(findings(&compiled, &files, &config, &sets).is_empty());
    }

    #[test]
    fn path_filters_gate_the_importing_file() {
        let (config, sets) = config(SILOS);
        let compiled = rules(
            r#"
version: 1
rules:
  - id: arch.api-must-not-import-db
    severity: error
    message: m
    paths:
      exclude: ["**/legacy/**"]
    boundary:
      from: api
      deny: ["db"]
"#,
        );
        let files = graph(&[
            (
                "src/api/legacy/handler.js",
                file("javascript", &[("../../db/client", 1, 1)]),
            ),
            (
                "src/api/handler.js",
                file("javascript", &[("../db/client", 1, 1)]),
            ),
            ("src/db/client.js", file("javascript", &[])),
        ]);

        let found = findings(&compiled, &files, &config, &sets);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "src/api/handler.js");
    }

    #[test]
    fn findings_follow_file_then_import_order_and_repeat() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/z.js",
                file("javascript", &[("../db/client", 9, 1)]),
            ),
            (
                "src/api/a.js",
                file(
                    "javascript",
                    &[("../db/pool", 2, 1), ("../db/client", 1, 1)],
                ),
            ),
            ("src/db/client.js", file("javascript", &[])),
            ("src/db/pool.js", file("javascript", &[])),
        ]);

        let first = findings(&compiled, &files, &config, &sets);
        assert_eq!(
            first
                .iter()
                .map(|f| (f.path.as_str(), f.matched.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("src/api/a.js", "../db/pool"),
                ("src/api/a.js", "../db/client"),
                ("src/api/z.js", "../db/client"),
            ]
        );
        assert_eq!(first, findings(&compiled, &files, &config, &sets));
    }

    #[test]
    fn repeated_identical_imports_get_increasing_occurrence_index() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[
            (
                "src/api/handler.js",
                file(
                    "javascript",
                    &[("../db/client", 1, 1), ("../db/client", 5, 1)],
                ),
            ),
            ("src/db/client.js", file("javascript", &[])),
        ]);

        let found = findings(&compiled, &files, &config, &sets);
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].fingerprint,
            fingerprint(
                "arch.api-must-not-import-db",
                "src/api/handler.js",
                "../db/client",
                0
            )
        );
        assert_eq!(
            found[1].fingerprint,
            fingerprint(
                "arch.api-must-not-import-db",
                "src/api/handler.js",
                "../db/client",
                1
            )
        );
    }

    #[test]
    fn non_boundary_rules_are_ignored() {
        let (config, sets) = config(SILOS);
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.b
    severity: info
    message: m
    regex: { pattern: "db" }
"#,
        );
        let files = graph(&[
            (
                "src/api/handler.js",
                file("javascript", &[("../db/client", 1, 1)]),
            ),
            ("src/db/client.js", file("javascript", &[])),
        ]);

        assert!(findings(&compiled, &files, &config, &sets).is_empty());
    }

    #[test]
    fn escaping_relative_imports_do_not_resolve() {
        let (config, sets) = config(SILOS);
        let compiled = rules(API_DENIES_DB);
        let files = graph(&[(
            "src/api/handler.js",
            file("javascript", &[("../../../db/client", 1, 1)]),
        )]);

        assert!(findings(&compiled, &files, &config, &sets).is_empty());
    }
}
