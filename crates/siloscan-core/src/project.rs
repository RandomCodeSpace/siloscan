use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use globset::GlobBuilder;
use serde::Serialize;

use crate::config::Config;
use crate::walk::{FileKind, WalkResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DetectionStatus {
    Generic,
    Complete,
    Partial,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct Evidence {
    pub(crate) ecosystem: String,
    pub(crate) kind: String,
    pub(crate) path: String,
    pub(crate) status: DetectionStatus,
    pub(crate) parser: String,
    pub(crate) facts: Vec<String>,
    pub(crate) reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct ProjectUnit {
    pub(crate) ecosystem: String,
    pub(crate) kind: String,
    pub(crate) root: String,
    pub(crate) evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct WorkspaceRelation {
    pub(crate) ecosystem: String,
    pub(crate) kind: String,
    pub(crate) workspace: String,
    pub(crate) member: String,
    pub(crate) evidence: String,
    pub(crate) declaration_index: Option<usize>,
    pub(crate) status: String,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct SourceRootHint {
    pub(crate) ecosystem: String,
    pub(crate) kind: String,
    pub(crate) path: String,
    pub(crate) evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProjectFacts {
    pub(crate) status: DetectionStatus,
    pub(crate) generic_fallback: bool,
    pub(crate) evidence: Vec<Evidence>,
    pub(crate) units: Vec<ProjectUnit>,
    pub(crate) workspace_relations: Vec<WorkspaceRelation>,
    pub(crate) languages: Vec<String>,
    pub(crate) source_roots: Vec<SourceRootHint>,
}

/// Derive normalized project facts from the exact inventory admitted by the
/// scan. This function never traverses `root`; package 4 will retain the same
/// `WalkResult` and pass it to the prepared scanner after resolution.
pub(crate) fn detect(root: &Path, inventory: &WalkResult, config: Option<&Config>) -> ProjectFacts {
    let inventory = Inventory::new(root, inventory, config);
    let mut facts = ProjectFacts {
        status: DetectionStatus::Generic,
        generic_fallback: true,
        evidence: Vec::new(),
        units: Vec::new(),
        workspace_relations: Vec::new(),
        languages: inventory.languages(),
        source_roots: Vec::new(),
    };

    detect_cargo(&inventory, &mut facts);
    detect_go(&inventory, &mut facts);
    detect_javascript(&inventory, &mut facts);
    detect_python(&inventory, &mut facts);
    detect_maven(&inventory, &mut facts);
    detect_gradle(&inventory, &mut facts);
    detect_cmake(&inventory, &mut facts);
    detect_dotnet(&inventory, &mut facts);
    detect_ruby(&inventory, &mut facts);
    attach_setup_metadata(&inventory, &mut facts);
    normalize(&mut facts);
    facts
}

struct Inventory {
    files: BTreeMap<String, PathBuf>,
    max_parse_bytes: u64,
    language_overrides: BTreeMap<String, String>,
}

impl Inventory {
    fn new(root: &Path, walk: &WalkResult, config: Option<&Config>) -> Self {
        let files = walk
            .files
            .iter()
            .map(|path| (relative(root, path), path.clone()))
            .collect();
        let max_parse_bytes = config
            .map(|config| config.limits.max_parse_bytes)
            .unwrap_or(crate::config::DEFAULT_MAX_PARSE_BYTES);
        let language_overrides = config
            .map(|config| config.languages.clone())
            .unwrap_or_default();
        Self {
            files,
            max_parse_bytes,
            language_overrides,
        }
    }

    fn languages(&self) -> Vec<String> {
        let mut languages = BTreeSet::new();
        for path in self.files.values() {
            let language = if path.extension().is_some() {
                crate::lang::detect_configured(path, "", Some(&self.language_overrides))
            } else {
                match crate::walk::read_text(path) {
                    FileKind::Text(content) => crate::lang::detect_configured(
                        path,
                        &content,
                        Some(&self.language_overrides),
                    ),
                    FileKind::Binary | FileKind::Unreadable(_) => None,
                }
            };
            if let Some(language) = language {
                languages.insert(language.to_string());
            }
        }
        languages.into_iter().collect()
    }

    fn named(&self, name: &str) -> Vec<String> {
        self.files
            .keys()
            .filter(|path| file_name(path) == name)
            .cloned()
            .collect()
    }

    fn ending(&self, suffix: &str) -> Vec<String> {
        self.files
            .keys()
            .filter(|path| path.ends_with(suffix))
            .cloned()
            .collect()
    }

    fn read(&self, relative: &str) -> Result<String, ReadProblem> {
        let path = self
            .files
            .get(relative)
            .expect("detectors only read admitted inventory paths");
        let size = fs::metadata(path)
            .map_err(|error| ReadProblem(format!("metadata unavailable: {error}")))?
            .len();
        if size > self.max_parse_bytes {
            return Err(ReadProblem(format!(
                "exceeds max_parse_bytes ({size} > {})",
                self.max_parse_bytes
            )));
        }
        match crate::walk::read_text(path) {
            FileKind::Text(content) => Ok(content),
            FileKind::Binary => Err(ReadProblem("binary evidence is not parsed".into())),
            FileKind::Unreadable(reason) => Err(ReadProblem(reason)),
        }
    }

    fn has_under(&self, root: &str, child: &str) -> bool {
        let prefix = join_relative(root, child);
        self.files
            .keys()
            .any(|path| path == &prefix || path.starts_with(&(prefix.clone() + "/")))
    }
}

struct ReadProblem(String);

struct CargoDocument {
    path: String,
    root: String,
    value: Option<toml::Value>,
    problem: Option<(DetectionStatus, String)>,
}

fn detect_go(inventory: &Inventory, facts: &mut ProjectFacts) {
    let mut modules = BTreeMap::new();
    for path in inventory.named("go.mod") {
        let root = parent(&path);
        let mut evidence = Evidence {
            ecosystem: "go".into(),
            kind: "go-module".into(),
            path: path.clone(),
            status: DetectionStatus::Complete,
            parser: "go-mod@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        match inventory.read(&path) {
            Err(ReadProblem(reason)) => {
                evidence.status = DetectionStatus::Partial;
                evidence.reasons.push(reason);
            }
            Ok(content) => match parse_go_mod(&content) {
                Err(reason) => {
                    evidence.status = DetectionStatus::Invalid;
                    evidence.reasons.push(reason);
                }
                Ok((module, go_version)) => {
                    evidence.facts.push(format!("module:{module}"));
                    if let Some(go_version) = go_version {
                        evidence.facts.push(format!("go:{go_version}"));
                    }
                    modules.insert(root.clone(), path.clone());
                    facts.units.push(ProjectUnit {
                        ecosystem: "go".into(),
                        kind: "module".into(),
                        root: root.clone(),
                        evidence: path.clone(),
                    });
                    facts.source_roots.push(SourceRootHint {
                        ecosystem: "go".into(),
                        kind: "module-root".into(),
                        path: root,
                        evidence: path.clone(),
                    });
                }
            },
        }
        facts.evidence.push(evidence);
    }

    for path in inventory.named("go.work") {
        let workspace = parent(&path);
        let mut evidence = Evidence {
            ecosystem: "go".into(),
            kind: "go-workspace".into(),
            path: path.clone(),
            status: DetectionStatus::Complete,
            parser: "go-work@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        match inventory.read(&path) {
            Err(ReadProblem(reason)) => {
                evidence.status = DetectionStatus::Partial;
                evidence.reasons.push(reason);
            }
            Ok(content) => match parse_go_work(&content) {
                Err(reason) => {
                    evidence.status = DetectionStatus::Invalid;
                    evidence.reasons.push(reason);
                }
                Ok((go_version, uses)) => {
                    evidence.facts.push(format!("go:{go_version}"));
                    for (declaration_index, declared) in uses.into_iter().enumerate() {
                        match resolve_relative(&workspace, &declared) {
                            Err(reason) => {
                                mark_partial(&mut evidence, format!("use {declared:?} {reason}"));
                                facts.workspace_relations.push(WorkspaceRelation {
                                    ecosystem: "go".into(),
                                    kind: "workspace-use".into(),
                                    workspace: workspace.clone(),
                                    member: declared,
                                    evidence: path.clone(),
                                    declaration_index: Some(declaration_index),
                                    status: "refused".into(),
                                    reason: Some(reason.into()),
                                });
                            }
                            Ok(member) if modules.contains_key(&member) => {
                                evidence.facts.push(format!("member:{member}"));
                                facts.workspace_relations.push(WorkspaceRelation {
                                    ecosystem: "go".into(),
                                    kind: "workspace-use".into(),
                                    workspace: workspace.clone(),
                                    member,
                                    evidence: path.clone(),
                                    declaration_index: Some(declaration_index),
                                    status: "member".into(),
                                    reason: None,
                                });
                            }
                            Ok(member) => {
                                let reason = "go.mod is absent from the admitted inventory";
                                mark_partial(&mut evidence, format!("use {declared:?}: {reason}"));
                                facts.workspace_relations.push(WorkspaceRelation {
                                    ecosystem: "go".into(),
                                    kind: "workspace-use".into(),
                                    workspace: workspace.clone(),
                                    member,
                                    evidence: path.clone(),
                                    declaration_index: Some(declaration_index),
                                    status: "unresolved".into(),
                                    reason: Some(reason.into()),
                                });
                            }
                        }
                    }
                }
            },
        }
        facts.evidence.push(evidence);
    }
}

fn parse_go_mod(content: &str) -> Result<(String, Option<String>), String> {
    let mut modules = Vec::new();
    let mut go_versions = Vec::new();
    for line in content.lines() {
        let line = line.split_once("//").map(|(line, _)| line).unwrap_or(line);
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("module") => {
                let module = fields
                    .next()
                    .ok_or_else(|| "module directive has no path".to_string())?;
                if fields.next().is_some() {
                    return Err("module directive has unexpected trailing fields".into());
                }
                modules.push(unquote(module));
            }
            Some("go") => {
                let version = fields
                    .next()
                    .ok_or_else(|| "go directive has no version".to_string())?;
                go_versions.push(version.to_string());
            }
            _ => {}
        }
    }
    if modules.len() != 1 {
        return Err(format!(
            "expected exactly one module directive, found {}",
            modules.len()
        ));
    }
    if go_versions.len() > 1 {
        return Err("duplicate go directives".into());
    }
    Ok((modules.remove(0), go_versions.pop()))
}

fn parse_go_work(content: &str) -> Result<(String, Vec<String>), String> {
    let mut go_versions = Vec::new();
    let mut uses = Vec::new();
    let mut in_use_block = false;
    for line in content.lines() {
        let line = line.split_once("//").map(|(line, _)| line).unwrap_or(line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if in_use_block {
            if line == ")" {
                in_use_block = false;
                continue;
            }
            if line == "(" || line.contains(char::is_whitespace) {
                return Err(format!("invalid go.work use entry {line:?}"));
            }
            uses.push(unquote(line));
            continue;
        }
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("go") => {
                let version = fields
                    .next()
                    .ok_or_else(|| "go directive has no version".to_string())?;
                if fields.next().is_some() {
                    return Err("go directive has unexpected trailing fields".into());
                }
                go_versions.push(version.to_string());
            }
            Some("use") => match fields.next() {
                Some("(") if fields.next().is_none() => in_use_block = true,
                Some(path) if fields.next().is_none() => uses.push(unquote(path)),
                _ => return Err(format!("invalid go.work use directive {line:?}")),
            },
            Some("toolchain" | "replace") => {}
            Some(_) | None => {}
        }
    }
    if in_use_block {
        return Err("unterminated go.work use block".into());
    }
    if go_versions.len() != 1 {
        return Err(format!(
            "expected exactly one go directive, found {}",
            go_versions.len()
        ));
    }
    Ok((go_versions.remove(0), uses))
}

fn unquote(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

struct JsonDocument {
    path: String,
    root: String,
    object: Option<serde_json::Map<String, serde_json::Value>>,
    problem: Option<(DetectionStatus, String)>,
}

fn detect_javascript(inventory: &Inventory, facts: &mut ProjectFacts) {
    let documents: Vec<JsonDocument> = inventory
        .named("package.json")
        .into_iter()
        .map(|path| {
            let root = parent(&path);
            match inventory.read(&path) {
                Err(ReadProblem(reason)) => JsonDocument {
                    path,
                    root,
                    object: None,
                    problem: Some((DetectionStatus::Partial, reason)),
                },
                Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(serde_json::Value::Object(object)) => JsonDocument {
                        path,
                        root,
                        object: Some(object),
                        problem: None,
                    },
                    Ok(_) => JsonDocument {
                        path,
                        root,
                        object: None,
                        problem: Some((
                            DetectionStatus::Invalid,
                            "package.json must contain a JSON object".into(),
                        )),
                    },
                    Err(error) => JsonDocument {
                        path,
                        root,
                        object: None,
                        problem: Some((DetectionStatus::Invalid, bounded(error.to_string()))),
                    },
                },
            }
        })
        .collect();
    let package_roots: BTreeSet<String> = documents
        .iter()
        .filter(|document| document.object.is_some())
        .map(|document| document.root.clone())
        .collect();

    for document in documents {
        let mut evidence = Evidence {
            ecosystem: "javascript-typescript".into(),
            kind: "package-json".into(),
            path: document.path.clone(),
            status: DetectionStatus::Complete,
            parser: "json@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        if let Some((status, reason)) = document.problem {
            evidence.status = status;
            evidence.reasons.push(reason);
            facts.evidence.push(evidence);
            continue;
        }
        let object = document.object.expect("valid package object");
        facts.units.push(ProjectUnit {
            ecosystem: "javascript-typescript".into(),
            kind: "package".into(),
            root: document.root.clone(),
            evidence: document.path.clone(),
        });
        facts.source_roots.push(SourceRootHint {
            ecosystem: "javascript-typescript".into(),
            kind: "package-root".into(),
            path: document.root.clone(),
            evidence: document.path.clone(),
        });
        for field in ["name", "version", "type"] {
            if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                evidence.facts.push(format!("{field}:{value}"));
            }
        }
        if let Some(workspaces) = object.get("workspaces") {
            let patterns = match workspaces.as_array() {
                Some(array) => {
                    let mut patterns = Vec::new();
                    for value in array {
                        match value.as_str() {
                            Some(pattern) => patterns.push(pattern.to_string()),
                            None => mark_partial(
                                &mut evidence,
                                "workspaces contains a non-string entry".into(),
                            ),
                        }
                    }
                    patterns
                }
                None => {
                    mark_partial(
                        &mut evidence,
                        "workspaces must be an array of strings".into(),
                    );
                    Vec::new()
                }
            };
            let mut seen = BTreeSet::new();
            for (declaration_index, pattern) in patterns.iter().enumerate() {
                for member in expand_pattern(&document.root, pattern, &package_roots, &mut evidence)
                {
                    if !seen.insert(member.clone()) {
                        continue;
                    }
                    evidence.facts.push(format!("member:{member}"));
                    facts.workspace_relations.push(WorkspaceRelation {
                        ecosystem: "javascript-typescript".into(),
                        kind: "npm-workspace".into(),
                        workspace: document.root.clone(),
                        member,
                        evidence: document.path.clone(),
                        declaration_index: Some(declaration_index),
                        status: "member".into(),
                        reason: None,
                    });
                }
            }
        }
        facts.evidence.push(evidence);
    }

    for name in ["tsconfig.json", "jsconfig.json"] {
        for path in inventory.named(name) {
            let mut evidence = Evidence {
                ecosystem: "javascript-typescript".into(),
                kind: "typescript-config".into(),
                path: path.clone(),
                status: DetectionStatus::Partial,
                parser: "presence@1".into(),
                facts: vec!["project-config".into()],
                reasons: vec!["JSONC project semantics are not evaluated".into()],
            };
            if let Err(ReadProblem(reason)) = inventory.read(&path) {
                evidence.reasons.push(reason);
            }
            facts.evidence.push(evidence);
        }
    }
}

struct PythonDocument {
    path: String,
    root: String,
    value: Option<toml::Value>,
    problem: Option<(DetectionStatus, String)>,
}

fn detect_python(inventory: &Inventory, facts: &mut ProjectFacts) {
    let documents: Vec<PythonDocument> = inventory
        .named("pyproject.toml")
        .into_iter()
        .map(|path| {
            let root = parent(&path);
            match inventory.read(&path) {
                Err(ReadProblem(reason)) => PythonDocument {
                    path,
                    root,
                    value: None,
                    problem: Some((DetectionStatus::Partial, reason)),
                },
                Ok(content) => match toml::from_str::<toml::Value>(&content) {
                    Ok(value) => PythonDocument {
                        path,
                        root,
                        value: Some(value),
                        problem: None,
                    },
                    Err(error) => PythonDocument {
                        path,
                        root,
                        value: None,
                        problem: Some((DetectionStatus::Invalid, bounded(error.to_string()))),
                    },
                },
            }
        })
        .collect();
    let pyproject_roots: BTreeSet<String> = documents
        .iter()
        .filter(|document| document.value.is_some())
        .map(|document| document.root.clone())
        .collect();

    for document in documents {
        let mut evidence = Evidence {
            ecosystem: "python".into(),
            kind: "pyproject".into(),
            path: document.path.clone(),
            status: DetectionStatus::Complete,
            parser: "toml@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        if let Some((status, reason)) = document.problem {
            evidence.status = status;
            evidence.reasons.push(reason);
            facts.evidence.push(evidence);
            continue;
        }
        let value = document.value.expect("parsed pyproject");
        let is_package = value
            .get("project")
            .and_then(toml::Value::as_table)
            .is_some()
            || value
                .get("build-system")
                .and_then(toml::Value::as_table)
                .is_some();
        let workspace = value
            .get("tool")
            .and_then(toml::Value::as_table)
            .and_then(|tool| tool.get("uv"))
            .and_then(toml::Value::as_table)
            .and_then(|uv| uv.get("workspace"))
            .and_then(toml::Value::as_table);

        if is_package {
            evidence.facts.push("package".into());
            facts.units.push(ProjectUnit {
                ecosystem: "python".into(),
                kind: "package".into(),
                root: document.root.clone(),
                evidence: document.path.clone(),
            });
            if inventory.has_under(&document.root, "src")
                && inventory.files.keys().any(|path| {
                    path.starts_with(&join_relative(&document.root, "src/"))
                        && path.ends_with(".py")
                })
            {
                facts.source_roots.push(SourceRootHint {
                    ecosystem: "python".into(),
                    kind: "conventional".into(),
                    path: join_relative(&document.root, "src"),
                    evidence: document.path.clone(),
                });
            }
        } else if workspace.is_none() {
            evidence.status = DetectionStatus::Partial;
            evidence.facts.push("tooling".into());
            evidence
                .reasons
                .push("no [project] or [build-system] table".into());
        }

        if let Some(workspace) = workspace {
            evidence.facts.push("uv-workspace".into());
            if !is_package {
                facts.units.push(ProjectUnit {
                    ecosystem: "python".into(),
                    kind: "workspace-root".into(),
                    root: document.root.clone(),
                    evidence: document.path.clone(),
                });
            }
            evidence.facts.push(format!("member:{}", document.root));
            let members = string_array(
                workspace.get("members"),
                "tool.uv.workspace.members",
                &mut evidence,
            );
            let excludes = string_array(
                workspace.get("exclude"),
                "tool.uv.workspace.exclude",
                &mut evidence,
            );
            let excluded =
                expand_patterns(&document.root, &excludes, &pyproject_roots, &mut evidence);
            let mut seen = BTreeSet::new();
            for (declaration_index, pattern) in members.iter().enumerate() {
                for member in
                    expand_pattern(&document.root, pattern, &pyproject_roots, &mut evidence)
                {
                    if excluded.contains(&member) || !seen.insert(member.clone()) {
                        continue;
                    }
                    evidence.facts.push(format!("member:{member}"));
                    facts.workspace_relations.push(WorkspaceRelation {
                        ecosystem: "python".into(),
                        kind: "uv-workspace".into(),
                        workspace: document.root.clone(),
                        member,
                        evidence: document.path.clone(),
                        declaration_index: Some(declaration_index),
                        status: "member".into(),
                        reason: None,
                    });
                }
            }
        }
        facts.evidence.push(evidence);
    }

    for name in ["setup.py", "setup.cfg"] {
        for path in inventory.named(name) {
            let root = parent(&path);
            let mut evidence = Evidence {
                ecosystem: "python".into(),
                kind: "legacy-config".into(),
                path: path.clone(),
                status: DetectionStatus::Partial,
                parser: "presence@1".into(),
                facts: vec!["legacy-package".into()],
                reasons: vec!["legacy package configuration is not evaluated".into()],
            };
            if let Err(ReadProblem(reason)) = inventory.read(&path) {
                evidence.reasons.push(reason);
            } else {
                facts.units.push(ProjectUnit {
                    ecosystem: "python".into(),
                    kind: "legacy-package".into(),
                    root,
                    evidence: path.clone(),
                });
            }
            facts.evidence.push(evidence);
        }
    }
}

struct XmlDocument {
    path: String,
    root: String,
    content: Option<String>,
    problem: Option<(DetectionStatus, String)>,
}

fn detect_maven(inventory: &Inventory, facts: &mut ProjectFacts) {
    let documents: Vec<XmlDocument> = inventory
        .named("pom.xml")
        .into_iter()
        .map(|path| {
            let root = parent(&path);
            match inventory.read(&path) {
                Err(ReadProblem(reason)) => XmlDocument {
                    path,
                    root,
                    content: None,
                    problem: Some((DetectionStatus::Partial, reason)),
                },
                Ok(content) => match roxmltree::Document::parse(&content) {
                    Err(error) => XmlDocument {
                        path,
                        root,
                        content: None,
                        problem: Some((DetectionStatus::Invalid, bounded(error.to_string()))),
                    },
                    Ok(document) if document.root_element().tag_name().name() != "project" => {
                        XmlDocument {
                            path,
                            root,
                            content: None,
                            problem: Some((
                                DetectionStatus::Invalid,
                                "pom.xml root element must be project".into(),
                            )),
                        }
                    }
                    Ok(_) => XmlDocument {
                        path,
                        root,
                        content: Some(content),
                        problem: None,
                    },
                },
            }
        })
        .collect();
    let valid_roots: BTreeSet<String> = documents
        .iter()
        .filter(|document| document.content.is_some())
        .map(|document| document.root.clone())
        .collect();

    for document in documents {
        let mut evidence = Evidence {
            ecosystem: "maven".into(),
            kind: "pom".into(),
            path: document.path.clone(),
            status: DetectionStatus::Complete,
            parser: "xml@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        if let Some((status, reason)) = document.problem {
            evidence.status = status;
            evidence.reasons.push(reason);
            facts.evidence.push(evidence);
            continue;
        }
        let content = document.content.as_ref().expect("valid Maven XML");
        let xml = roxmltree::Document::parse(content).expect("validated Maven XML");
        let project = xml.root_element();
        facts.units.push(ProjectUnit {
            ecosystem: "maven".into(),
            kind: "project".into(),
            root: document.root.clone(),
            evidence: document.path.clone(),
        });
        evidence.facts.push("project".into());
        maven_parent(&document, project, &valid_roots, &mut evidence);

        if project
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "profiles")
            .any(|profiles| {
                profiles
                    .descendants()
                    .any(|node| node.is_element() && node.tag_name().name() == "module")
            })
        {
            mark_partial(
                &mut evidence,
                "profile-controlled modules are not evaluated".into(),
            );
        }

        if let Some(modules) = project
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "modules")
        {
            for (declaration_index, module) in modules
                .children()
                .filter(|node| node.is_element() && node.tag_name().name() == "module")
                .enumerate()
            {
                let declared = module.text().unwrap_or("").trim();
                if declared.is_empty() || declared.contains("${") {
                    mark_partial(
                        &mut evidence,
                        format!("module {declared:?} is not an unconditional literal path"),
                    );
                    continue;
                }
                add_manifest_relation(
                    "maven",
                    "aggregator-module",
                    &document,
                    declared,
                    "pom.xml",
                    declaration_index,
                    &valid_roots,
                    &mut evidence,
                    facts,
                );
            }
        }

        let build = project
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "build");
        let mut declared_source = false;
        if let Some(build) = build {
            for (name, kind) in [
                ("sourceDirectory", "declared-main"),
                ("testSourceDirectory", "declared-test"),
            ] {
                let Some(node) = build
                    .children()
                    .find(|node| node.is_element() && node.tag_name().name() == name)
                else {
                    continue;
                };
                declared_source = true;
                let declared = node.text().unwrap_or("").trim();
                if declared.contains("${") {
                    mark_partial(
                        &mut evidence,
                        format!("{name} contains an unresolved property"),
                    );
                    continue;
                }
                match resolve_relative(&document.root, declared) {
                    Ok(path) if inventory.has_under(&path, ".") => {
                        facts.source_roots.push(SourceRootHint {
                            ecosystem: "maven".into(),
                            kind: kind.into(),
                            path,
                            evidence: document.path.clone(),
                        });
                    }
                    Ok(_) => mark_partial(
                        &mut evidence,
                        format!("{name} {declared:?} is absent from the admitted inventory"),
                    ),
                    Err(reason) => {
                        mark_partial(&mut evidence, format!("{name} {declared:?} {reason}"))
                    }
                }
            }
        }
        if !declared_source {
            for (path, kind) in [
                ("src/main/java", "conventional-main"),
                ("src/test/java", "conventional-test"),
            ] {
                if inventory.has_under(&document.root, path) {
                    facts.source_roots.push(SourceRootHint {
                        ecosystem: "maven".into(),
                        kind: kind.into(),
                        path: join_relative(&document.root, path),
                        evidence: document.path.clone(),
                    });
                }
            }
        }
        facts.evidence.push(evidence);
    }
}

fn maven_parent(
    document: &XmlDocument,
    project: roxmltree::Node<'_, '_>,
    valid_roots: &BTreeSet<String>,
    evidence: &mut Evidence,
) {
    let Some(parent_node) = project
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "parent")
    else {
        return;
    };
    let relative = parent_node
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "relativePath");
    let declared = match relative {
        Some(relative) => {
            let declared = relative.text().unwrap_or("").trim();
            if declared.is_empty() {
                mark_partial(
                    evidence,
                    "parent disables local relativePath and may require external resolution".into(),
                );
                return;
            }
            declared
        }
        None => "../pom.xml",
    };
    if declared.contains("${") {
        mark_partial(
            evidence,
            "parent relativePath contains an unresolved property".into(),
        );
        return;
    }
    match resolve_relative(&document.root, declared) {
        Err(reason) => mark_partial(
            evidence,
            format!("parent relativePath {declared:?} {reason}"),
        ),
        Ok(path) if file_name(&path) == "pom.xml" && valid_roots.contains(&parent(&path)) => {
            evidence.facts.push(format!("parent:{path}"));
        }
        Ok(_) => mark_partial(
            evidence,
            format!(
                "parent relativePath {declared:?} is absent or invalid in the admitted inventory"
            ),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn add_manifest_relation(
    ecosystem: &str,
    kind: &str,
    document: &XmlDocument,
    declared: &str,
    manifest_name: &str,
    declaration_index: usize,
    valid_roots: &BTreeSet<String>,
    evidence: &mut Evidence,
    facts: &mut ProjectFacts,
) {
    match resolve_relative(&document.root, declared) {
        Err(reason) => {
            mark_partial(evidence, format!("member {declared:?} {reason}"));
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: ecosystem.into(),
                kind: kind.into(),
                workspace: document.root.clone(),
                member: declared.into(),
                evidence: document.path.clone(),
                declaration_index: Some(declaration_index),
                status: "refused".into(),
                reason: Some(reason.into()),
            });
        }
        Ok(member) if valid_roots.contains(&member) => {
            evidence.facts.push(format!("member:{member}"));
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: ecosystem.into(),
                kind: kind.into(),
                workspace: document.root.clone(),
                member,
                evidence: document.path.clone(),
                declaration_index: Some(declaration_index),
                status: "member".into(),
                reason: None,
            });
        }
        Ok(member) => {
            let reason = format!("{manifest_name} is absent or invalid in the admitted inventory");
            mark_partial(evidence, format!("member {declared:?}: {reason}"));
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: ecosystem.into(),
                kind: kind.into(),
                workspace: document.root.clone(),
                member,
                evidence: document.path.clone(),
                declaration_index: Some(declaration_index),
                status: "unresolved".into(),
                reason: Some(reason),
            });
        }
    }
}

fn detect_gradle(inventory: &Inventory, facts: &mut ProjectFacts) {
    let mut settings = BTreeMap::new();
    for name in ["settings.gradle", "settings.gradle.kts"] {
        for path in inventory.named(name) {
            let root = parent(&path);
            settings.entry(root.clone()).or_insert_with(|| path.clone());
            let mut evidence = Evidence {
                ecosystem: "gradle".into(),
                kind: "settings-script".into(),
                path: path.clone(),
                status: DetectionStatus::Partial,
                parser: "presence@1".into(),
                facts: vec!["settings".into()],
                reasons: vec!["Gradle scripts are not evaluated".into()],
            };
            if let Err(ReadProblem(reason)) = inventory.read(&path) {
                evidence.reasons.push(reason);
            }
            facts.evidence.push(evidence);
        }
    }

    let mut builds = BTreeMap::new();
    for name in ["build.gradle", "build.gradle.kts"] {
        for path in inventory.named(name) {
            let root = parent(&path);
            builds.entry(root.clone()).or_insert_with(|| path.clone());
            let mut evidence = Evidence {
                ecosystem: "gradle".into(),
                kind: "build-script".into(),
                path: path.clone(),
                status: DetectionStatus::Partial,
                parser: "presence@1".into(),
                facts: vec!["build".into()],
                reasons: vec!["Gradle scripts are not evaluated".into()],
            };
            if let Err(ReadProblem(reason)) = inventory.read(&path) {
                evidence.reasons.push(reason);
            }
            facts.evidence.push(evidence);
        }
    }

    for (root, path) in &builds {
        facts.units.push(ProjectUnit {
            ecosystem: "gradle".into(),
            kind: "project".into(),
            root: root.clone(),
            evidence: path.clone(),
        });
        for (source, kind) in [
            ("src/main/java", "conventional-main"),
            ("src/test/java", "conventional-test"),
        ] {
            if inventory.has_under(root, source) {
                facts.source_roots.push(SourceRootHint {
                    ecosystem: "gradle".into(),
                    kind: kind.into(),
                    path: join_relative(root, source),
                    evidence: path.clone(),
                });
            }
        }
        let nearest = settings
            .keys()
            .filter(|settings_root| {
                settings_root.as_str() != root.as_str() && is_ancestor(settings_root, root)
            })
            .max_by_key(|settings_root| settings_root.len());
        if let Some(workspace) = nearest {
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: "gradle".into(),
                kind: "settings-containment".into(),
                workspace: workspace.clone(),
                member: root.clone(),
                evidence: settings
                    .get(workspace)
                    .expect("settings path exists")
                    .clone(),
                declaration_index: None,
                status: "hint".into(),
                reason: Some("containment only; Gradle settings were not evaluated".into()),
            });
        }
    }
}

fn is_ancestor(ancestor: &str, descendant: &str) -> bool {
    ancestor == "."
        || descendant
            .strip_prefix(ancestor)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn detect_cmake(inventory: &Inventory, facts: &mut ProjectFacts) {
    let mut projects = BTreeMap::new();
    for path in inventory.named("CMakeLists.txt") {
        let root = parent(&path);
        projects.entry(root.clone()).or_insert_with(|| path.clone());
        let mut evidence = Evidence {
            ecosystem: "cmake".into(),
            kind: "cmake-script".into(),
            path: path.clone(),
            status: DetectionStatus::Partial,
            parser: "presence@1".into(),
            facts: vec!["project".into()],
            reasons: vec!["CMake scripts are not evaluated".into()],
        };
        if let Err(ReadProblem(reason)) = inventory.read(&path) {
            evidence.reasons.push(reason);
        }
        facts.evidence.push(evidence);
    }

    for (root, path) in &projects {
        facts.units.push(ProjectUnit {
            ecosystem: "cmake".into(),
            kind: "project".into(),
            root: root.clone(),
            evidence: path.clone(),
        });
        let nearest = projects
            .keys()
            .filter(|ancestor| ancestor.as_str() != root.as_str() && is_ancestor(ancestor, root))
            .max_by_key(|ancestor| ancestor.len());
        if let Some(workspace) = nearest {
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: "cmake".into(),
                kind: "cmake-containment".into(),
                workspace: workspace.clone(),
                member: root.clone(),
                evidence: projects
                    .get(workspace)
                    .expect("ancestor CMake evidence exists")
                    .clone(),
                declaration_index: None,
                status: "hint".into(),
                reason: Some("containment only; CMake was not evaluated".into()),
            });
        }
    }

    for name in ["CMakePresets.json", "compile_commands.json"] {
        for path in inventory.named(name) {
            let root = parent(&path);
            if !projects
                .keys()
                .any(|project| project == &root || is_ancestor(project, &root))
            {
                continue;
            }
            let mut evidence = Evidence {
                ecosystem: "cmake".into(),
                kind: "setup-metadata".into(),
                path: path.clone(),
                status: DetectionStatus::Partial,
                parser: "presence@1".into(),
                facts: vec![format!("metadata:{name}")],
                reasons: vec!["CMake setup metadata does not establish project scope".into()],
            };
            if let Err(ReadProblem(reason)) = inventory.read(&path) {
                evidence.reasons.push(reason);
            }
            facts.evidence.push(evidence);
        }
    }
}

fn detect_dotnet(inventory: &Inventory, facts: &mut ProjectFacts) {
    let mut projects = BTreeMap::new();
    for path in inventory.ending(".csproj") {
        let root = parent(&path);
        let mut evidence = Evidence {
            ecosystem: "dotnet".into(),
            kind: "csproj".into(),
            path: path.clone(),
            status: DetectionStatus::Complete,
            parser: "xml@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        match inventory.read(&path) {
            Err(ReadProblem(reason)) => {
                evidence.status = DetectionStatus::Partial;
                evidence.reasons.push(reason);
            }
            Ok(content) => match roxmltree::Document::parse(&content) {
                Err(error) => {
                    evidence.status = DetectionStatus::Invalid;
                    evidence.reasons.push(bounded(error.to_string()));
                }
                Ok(document) if document.root_element().tag_name().name() != "Project" => {
                    evidence.status = DetectionStatus::Invalid;
                    evidence
                        .reasons
                        .push(".csproj root element must be Project".into());
                }
                Ok(document) => {
                    let project = document.root_element();
                    evidence.facts.push("project".into());
                    projects.insert(path.clone(), root.clone());
                    facts.units.push(ProjectUnit {
                        ecosystem: "dotnet".into(),
                        kind: "project".into(),
                        root: root.clone(),
                        evidence: path.clone(),
                    });
                    let sdk = project.attribute("Sdk").is_some()
                        || project
                            .children()
                            .any(|node| node.is_element() && node.tag_name().name() == "Sdk");
                    let default_compile_disabled = project.descendants().any(|node| {
                        node.is_element()
                            && node.tag_name().name() == "EnableDefaultCompileItems"
                            && node
                                .text()
                                .is_some_and(|text| text.trim().eq_ignore_ascii_case("false"))
                    });
                    if sdk {
                        evidence.facts.push("sdk-style".into());
                    }
                    if sdk && !default_compile_disabled {
                        facts.source_roots.push(SourceRootHint {
                            ecosystem: "dotnet".into(),
                            kind: "sdk-default-compile".into(),
                            path: root,
                            evidence: path.clone(),
                        });
                    }
                }
            },
        }
        facts.evidence.push(evidence);
    }

    for path in inventory.ending(".sln") {
        let mut evidence = Evidence {
            ecosystem: "dotnet".into(),
            kind: "solution".into(),
            path: path.clone(),
            status: DetectionStatus::Complete,
            parser: "sln@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        match inventory.read(&path) {
            Err(ReadProblem(reason)) => {
                evidence.status = DetectionStatus::Partial;
                evidence.reasons.push(reason);
            }
            Ok(content) => match parse_sln(&content) {
                Err(reason) => {
                    evidence.status = DetectionStatus::Invalid;
                    evidence.reasons.push(reason);
                }
                Ok(project_paths) => {
                    add_solution_relations(&path, project_paths, &projects, &mut evidence, facts)
                }
            },
        }
        facts.evidence.push(evidence);
    }

    for path in inventory.ending(".slnx") {
        let mut evidence = Evidence {
            ecosystem: "dotnet".into(),
            kind: "solution-xml".into(),
            path: path.clone(),
            status: DetectionStatus::Complete,
            parser: "slnx@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        match inventory.read(&path) {
            Err(ReadProblem(reason)) => {
                evidence.status = DetectionStatus::Partial;
                evidence.reasons.push(reason);
            }
            Ok(content) => match parse_slnx(&content) {
                Err(reason) => {
                    evidence.status = DetectionStatus::Invalid;
                    evidence.reasons.push(reason);
                }
                Ok(project_paths) => {
                    add_solution_relations(&path, project_paths, &projects, &mut evidence, facts)
                }
            },
        }
        facts.evidence.push(evidence);
    }
}

fn parse_sln(content: &str) -> Result<Vec<String>, String> {
    if !content
        .lines()
        .next()
        .is_some_and(|line| line.starts_with("Microsoft Visual Studio Solution File"))
    {
        return Err("solution header is missing".into());
    }
    let mut projects = Vec::new();
    for line in content.lines().filter(|line| line.starts_with("Project(")) {
        let (_, fields) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid solution project line {line:?}"))?;
        let fields: Vec<&str> = fields.split(',').map(str::trim).collect();
        if fields.len() < 3 {
            return Err(format!("invalid solution project line {line:?}"));
        }
        let path = fields[1].trim_matches('"');
        if path.to_ascii_lowercase().ends_with(".csproj") {
            projects.push(path.to_string());
        }
    }
    Ok(projects)
}

fn parse_slnx(content: &str) -> Result<Vec<String>, String> {
    let document =
        roxmltree::Document::parse(content).map_err(|error| bounded(error.to_string()))?;
    if document.root_element().tag_name().name() != "Solution" {
        return Err(".slnx root element must be Solution".into());
    }
    Ok(document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "Project")
        .filter_map(|node| node.attribute("Path"))
        .map(str::to_string)
        .collect())
}

fn add_solution_relations(
    solution_path: &str,
    declared_projects: Vec<String>,
    projects: &BTreeMap<String, String>,
    evidence: &mut Evidence,
    facts: &mut ProjectFacts,
) {
    let solution_root = parent(solution_path);
    for (declaration_index, declared) in declared_projects.into_iter().enumerate() {
        match resolve_relative(&solution_root, &declared) {
            Err(reason) => {
                mark_partial(evidence, format!("project {declared:?} {reason}"));
                facts.workspace_relations.push(WorkspaceRelation {
                    ecosystem: "dotnet".into(),
                    kind: "solution-project".into(),
                    workspace: solution_root.clone(),
                    member: declared,
                    evidence: solution_path.into(),
                    declaration_index: Some(declaration_index),
                    status: "refused".into(),
                    reason: Some(reason.into()),
                });
            }
            Ok(project_path) => match projects.get(&project_path) {
                Some(member) => {
                    evidence.facts.push(format!("project:{member}"));
                    facts.workspace_relations.push(WorkspaceRelation {
                        ecosystem: "dotnet".into(),
                        kind: "solution-project".into(),
                        workspace: solution_root.clone(),
                        member: member.clone(),
                        evidence: solution_path.into(),
                        declaration_index: Some(declaration_index),
                        status: "member".into(),
                        reason: None,
                    });
                }
                None => {
                    let reason = ".csproj is absent or invalid in the admitted inventory";
                    mark_partial(evidence, format!("project {declared:?}: {reason}"));
                    facts.workspace_relations.push(WorkspaceRelation {
                        ecosystem: "dotnet".into(),
                        kind: "solution-project".into(),
                        workspace: solution_root.clone(),
                        member: project_path,
                        evidence: solution_path.into(),
                        declaration_index: Some(declaration_index),
                        status: "unresolved".into(),
                        reason: Some(reason.into()),
                    });
                }
            },
        }
    }
}

fn detect_ruby(inventory: &Inventory, facts: &mut ProjectFacts) {
    let mut gems = BTreeMap::new();
    for path in inventory.ending(".gemspec") {
        let root = parent(&path);
        let primary = gems.entry(root.clone()).or_insert_with(|| path.clone());
        let mut evidence = Evidence {
            ecosystem: "ruby".into(),
            kind: "gemspec".into(),
            path: path.clone(),
            status: DetectionStatus::Partial,
            parser: "presence@1".into(),
            facts: vec!["gem".into()],
            reasons: vec!["Ruby gemspec code is not evaluated".into()],
        };
        if let Err(ReadProblem(reason)) = inventory.read(&path) {
            evidence.reasons.push(reason);
        }
        if primary == &path {
            facts.units.push(ProjectUnit {
                ecosystem: "ruby".into(),
                kind: "gem".into(),
                root: root.clone(),
                evidence: path.clone(),
            });
            if inventory.has_under(&root, "lib") {
                facts.source_roots.push(SourceRootHint {
                    ecosystem: "ruby".into(),
                    kind: "conventional".into(),
                    path: join_relative(&root, "lib"),
                    evidence: path.clone(),
                });
            }
        }
        facts.evidence.push(evidence);
    }

    let mut gemfiles = BTreeMap::new();
    for path in inventory.named("Gemfile") {
        let root = parent(&path);
        gemfiles.entry(root.clone()).or_insert_with(|| path.clone());
        let mut evidence = Evidence {
            ecosystem: "ruby".into(),
            kind: "gemfile".into(),
            path: path.clone(),
            status: DetectionStatus::Partial,
            parser: "presence@1".into(),
            facts: vec!["application-environment".into()],
            reasons: vec!["Ruby Gemfile code is not evaluated".into()],
        };
        if let Err(ReadProblem(reason)) = inventory.read(&path) {
            evidence.reasons.push(reason);
        } else if !gems.contains_key(&root) {
            facts.units.push(ProjectUnit {
                ecosystem: "ruby".into(),
                kind: "application".into(),
                root,
                evidence: path.clone(),
            });
        }
        facts.evidence.push(evidence);
    }

    for root in gems.keys() {
        let nearest = gemfiles
            .keys()
            .filter(|gemfile_root| {
                gemfile_root.as_str() != root.as_str() && is_ancestor(gemfile_root, root)
            })
            .max_by_key(|gemfile_root| gemfile_root.len());
        if let Some(workspace) = nearest {
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: "ruby".into(),
                kind: "gemfile-containment".into(),
                workspace: workspace.clone(),
                member: root.clone(),
                evidence: gemfiles
                    .get(workspace)
                    .expect("Gemfile evidence exists")
                    .clone(),
                declaration_index: None,
                status: "hint".into(),
                reason: Some("containment only; Ruby code was not evaluated".into()),
            });
        }
    }
}

fn detect_cargo(inventory: &Inventory, facts: &mut ProjectFacts) {
    let documents: Vec<CargoDocument> = inventory
        .named("Cargo.toml")
        .into_iter()
        .map(|path| {
            let root = parent(&path);
            match inventory.read(&path) {
                Err(ReadProblem(reason)) => CargoDocument {
                    path,
                    root,
                    value: None,
                    problem: Some((DetectionStatus::Partial, reason)),
                },
                Ok(content) => match toml::from_str::<toml::Value>(&content) {
                    Ok(value) => CargoDocument {
                        path,
                        root,
                        value: Some(value),
                        problem: None,
                    },
                    Err(error) => CargoDocument {
                        path,
                        root,
                        value: None,
                        problem: Some((DetectionStatus::Invalid, bounded(error.to_string()))),
                    },
                },
            }
        })
        .collect();

    let package_roots: BTreeSet<String> = documents
        .iter()
        .filter(|document| {
            document
                .value
                .as_ref()
                .and_then(|value| value.get("package"))
                .and_then(toml::Value::as_table)
                .is_some()
        })
        .map(|document| document.root.clone())
        .collect();
    let workspace_roots: BTreeSet<String> = documents
        .iter()
        .filter(|document| {
            document
                .value
                .as_ref()
                .and_then(|value| value.get("workspace"))
                .and_then(toml::Value::as_table)
                .is_some()
        })
        .map(|document| document.root.clone())
        .collect();

    for document in &documents {
        let mut evidence = Evidence {
            ecosystem: "rust".into(),
            kind: "cargo-manifest".into(),
            path: document.path.clone(),
            status: DetectionStatus::Complete,
            parser: "toml@1".into(),
            facts: Vec::new(),
            reasons: Vec::new(),
        };
        if let Some((status, reason)) = &document.problem {
            evidence.status = *status;
            evidence.reasons.push(reason.clone());
            facts.evidence.push(evidence);
            continue;
        }
        let value = document.value.as_ref().expect("parsed Cargo document");
        let package = value.get("package").and_then(toml::Value::as_table);
        let workspace = value.get("workspace").and_then(toml::Value::as_table);
        if package.is_none() && workspace.is_none() {
            evidence.status = DetectionStatus::Partial;
            evidence
                .reasons
                .push("no [package] or [workspace] table".into());
            facts.evidence.push(evidence);
            continue;
        }

        if let Some(package) = package {
            evidence.facts.push("package".into());
            if let Some(name) = package.get("name").and_then(toml::Value::as_str) {
                evidence.facts.push(format!("name:{name}"));
            }
            facts.units.push(ProjectUnit {
                ecosystem: "rust".into(),
                kind: "package".into(),
                root: document.root.clone(),
                evidence: document.path.clone(),
            });
            let autolib = package
                .get("autolib")
                .and_then(toml::Value::as_bool)
                .unwrap_or(true);
            let autobins = package
                .get("autobins")
                .and_then(toml::Value::as_bool)
                .unwrap_or(true);
            if (autolib || autobins) && inventory.has_under(&document.root, "src") {
                facts.source_roots.push(SourceRootHint {
                    ecosystem: "rust".into(),
                    kind: "conventional".into(),
                    path: join_relative(&document.root, "src"),
                    evidence: document.path.clone(),
                });
            }
            cargo_target_roots(inventory, document, value, &mut evidence, facts);
            cargo_declared_workspace(document, package, &workspace_roots, &mut evidence, facts);
        }

        cargo_path_dependencies(document, value, &package_roots, &mut evidence, facts);

        if let Some(workspace) = workspace {
            evidence.facts.push("workspace".into());
            cargo_workspace(document, workspace, &package_roots, &mut evidence, facts);
        }
        facts.evidence.push(evidence);
    }
}

fn cargo_declared_workspace(
    document: &CargoDocument,
    package: &toml::map::Map<String, toml::Value>,
    workspace_roots: &BTreeSet<String>,
    evidence: &mut Evidence,
    facts: &mut ProjectFacts,
) {
    let Some(declared) = package.get("workspace") else {
        return;
    };
    let Some(declared) = declared.as_str() else {
        mark_partial(evidence, "package.workspace must be a string".into());
        return;
    };
    match resolve_relative(&document.root, declared) {
        Err(reason) => {
            mark_partial(evidence, format!("package.workspace {declared:?} {reason}"));
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: "rust".into(),
                kind: "declared-workspace".into(),
                workspace: declared.into(),
                member: document.root.clone(),
                evidence: document.path.clone(),
                declaration_index: None,
                status: "refused".into(),
                reason: Some(reason.into()),
            });
        }
        Ok(workspace) if workspace_roots.contains(&workspace) => {
            evidence
                .facts
                .push(format!("declared-workspace:{workspace}"));
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: "rust".into(),
                kind: "declared-workspace".into(),
                workspace,
                member: document.root.clone(),
                evidence: document.path.clone(),
                declaration_index: None,
                status: "member".into(),
                reason: None,
            });
        }
        Ok(workspace) => {
            let reason = "workspace Cargo.toml is absent or invalid in the admitted inventory";
            mark_partial(
                evidence,
                format!("package.workspace {declared:?}: {reason}"),
            );
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: "rust".into(),
                kind: "declared-workspace".into(),
                workspace,
                member: document.root.clone(),
                evidence: document.path.clone(),
                declaration_index: None,
                status: "unresolved".into(),
                reason: Some(reason.into()),
            });
        }
    }
}

fn cargo_path_dependencies(
    document: &CargoDocument,
    value: &toml::Value,
    package_roots: &BTreeSet<String>,
    evidence: &mut Evidence,
    facts: &mut ProjectFacts,
) {
    let mut declarations = Vec::new();
    collect_cargo_path_dependencies(value.as_table(), "", &mut declarations, evidence);
    if let Some(workspace) = value.get("workspace").and_then(toml::Value::as_table) {
        collect_cargo_path_dependencies(Some(workspace), "workspace.", &mut declarations, evidence);
    }
    if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
        for (target, value) in targets {
            let prefix = format!("target.{target}.");
            collect_cargo_path_dependencies(value.as_table(), &prefix, &mut declarations, evidence);
        }
    }
    declarations.sort();
    declarations.dedup();

    for (field, name, declared) in declarations {
        match resolve_relative(&document.root, &declared) {
            Err(reason) => {
                mark_partial(
                    evidence,
                    format!("{field}.{name} path {declared:?} {reason}"),
                );
                facts.workspace_relations.push(WorkspaceRelation {
                    ecosystem: "rust".into(),
                    kind: "path-dependency".into(),
                    workspace: document.root.clone(),
                    member: declared,
                    evidence: document.path.clone(),
                    declaration_index: None,
                    status: "refused".into(),
                    reason: Some(reason.into()),
                });
            }
            Ok(member) if package_roots.contains(&member) => {
                evidence
                    .facts
                    .push(format!("path-dependency:{name}:{member}"));
                facts.workspace_relations.push(WorkspaceRelation {
                    ecosystem: "rust".into(),
                    kind: "path-dependency".into(),
                    workspace: document.root.clone(),
                    member,
                    evidence: document.path.clone(),
                    declaration_index: None,
                    status: "member".into(),
                    reason: None,
                });
            }
            Ok(member) => {
                let reason = "package Cargo.toml is absent or invalid in the admitted inventory";
                mark_partial(
                    evidence,
                    format!("{field}.{name} path {declared:?}: {reason}"),
                );
                facts.workspace_relations.push(WorkspaceRelation {
                    ecosystem: "rust".into(),
                    kind: "path-dependency".into(),
                    workspace: document.root.clone(),
                    member,
                    evidence: document.path.clone(),
                    declaration_index: None,
                    status: "unresolved".into(),
                    reason: Some(reason.into()),
                });
            }
        }
    }
}

fn collect_cargo_path_dependencies(
    table: Option<&toml::map::Map<String, toml::Value>>,
    prefix: &str,
    declarations: &mut Vec<(String, String, String)>,
    evidence: &mut Evidence,
) {
    let Some(table) = table else {
        return;
    };
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(dependencies) = table.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, dependency) in dependencies {
            let Some(dependency) = dependency.as_table() else {
                continue;
            };
            let Some(path) = dependency.get("path") else {
                continue;
            };
            match path.as_str() {
                Some(path) => declarations.push((
                    format!("{prefix}{section}"),
                    name.clone(),
                    path.to_string(),
                )),
                None => mark_partial(
                    evidence,
                    format!("{prefix}{section}.{name}.path must be a string"),
                ),
            }
        }
    }
}

fn cargo_workspace(
    document: &CargoDocument,
    workspace: &toml::map::Map<String, toml::Value>,
    package_roots: &BTreeSet<String>,
    evidence: &mut Evidence,
    facts: &mut ProjectFacts,
) {
    let members = string_array(workspace.get("members"), "workspace.members", evidence);
    let excludes = string_array(workspace.get("exclude"), "workspace.exclude", evidence);
    let excluded = expand_patterns(&document.root, &excludes, package_roots, evidence);
    for root in &excluded {
        evidence.facts.push(format!("excluded:{root}"));
    }
    let mut seen = BTreeSet::new();
    for (declaration_index, pattern) in members.iter().enumerate() {
        for member in expand_pattern(&document.root, pattern, package_roots, evidence) {
            if excluded.contains(&member) || !seen.insert(member.clone()) {
                continue;
            }
            evidence.facts.push(format!("member:{member}"));
            facts.workspace_relations.push(WorkspaceRelation {
                ecosystem: "rust".into(),
                kind: "workspace-member".into(),
                workspace: document.root.clone(),
                member,
                evidence: document.path.clone(),
                declaration_index: Some(declaration_index),
                status: "member".into(),
                reason: None,
            });
        }
    }
}

fn string_array(value: Option<&toml::Value>, field: &str, evidence: &mut Evidence) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(array) = value.as_array() else {
        mark_partial(evidence, format!("{field} must be an array of strings"));
        return Vec::new();
    };
    let mut strings = Vec::new();
    for value in array {
        match value.as_str() {
            Some(value) => strings.push(value.to_string()),
            None => mark_partial(evidence, format!("{field} contains a non-string entry")),
        }
    }
    strings
}

fn expand_patterns(
    base: &str,
    patterns: &[String],
    candidates: &BTreeSet<String>,
    evidence: &mut Evidence,
) -> BTreeSet<String> {
    patterns
        .iter()
        .flat_map(|pattern| expand_pattern(base, pattern, candidates, evidence))
        .collect()
}

fn expand_pattern(
    base: &str,
    pattern: &str,
    candidates: &BTreeSet<String>,
    evidence: &mut Evidence,
) -> Vec<String> {
    if pattern.contains("**")
        || pattern
            .bytes()
            .any(|byte| matches!(byte, b'[' | b']' | b'{' | b'}' | b'$'))
    {
        mark_partial(
            evidence,
            format!("unsupported workspace pattern {pattern:?}"),
        );
        return Vec::new();
    }
    let normalized = match resolve_relative(base, pattern) {
        Ok(normalized) => normalized,
        Err(reason) => {
            mark_partial(evidence, format!("workspace path {pattern:?} {reason}"));
            return Vec::new();
        }
    };
    let glob = match GlobBuilder::new(&normalized)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
    {
        Ok(glob) => glob.compile_matcher(),
        Err(error) => {
            mark_partial(
                evidence,
                format!("invalid workspace pattern {pattern:?}: {error}"),
            );
            return Vec::new();
        }
    };
    candidates
        .iter()
        .filter(|candidate| glob.is_match(candidate))
        .cloned()
        .collect()
}

fn cargo_target_roots(
    inventory: &Inventory,
    document: &CargoDocument,
    value: &toml::Value,
    evidence: &mut Evidence,
    facts: &mut ProjectFacts,
) {
    for key in ["lib", "bin", "example", "test", "bench"] {
        let Some(target) = value.get(key) else {
            continue;
        };
        let tables: Vec<&toml::map::Map<String, toml::Value>> = match target {
            toml::Value::Table(table) => vec![table],
            toml::Value::Array(array) => array.iter().filter_map(toml::Value::as_table).collect(),
            _ => Vec::new(),
        };
        for table in tables {
            let Some(path) = table.get("path").and_then(toml::Value::as_str) else {
                continue;
            };
            match resolve_relative(&document.root, path) {
                Ok(target) if inventory.files.contains_key(&target) => {
                    let root = parent(&target);
                    facts.source_roots.push(SourceRootHint {
                        ecosystem: "rust".into(),
                        kind: "declared-target".into(),
                        path: root,
                        evidence: document.path.clone(),
                    });
                }
                Ok(_) => mark_partial(
                    evidence,
                    format!("declared target {path:?} is absent from the admitted inventory"),
                ),
                Err(reason) => mark_partial(evidence, format!("declared target {path:?} {reason}")),
            }
        }
    }
}

fn attach_setup_metadata(inventory: &Inventory, facts: &mut ProjectFacts) {
    for (ecosystem, path) in [
        ("rust", "Cargo.lock"),
        ("go", "go.sum"),
        ("go", "go.work.sum"),
        ("javascript-typescript", "package-lock.json"),
        ("javascript-typescript", "npm-shrinkwrap.json"),
        ("javascript-typescript", "yarn.lock"),
        ("javascript-typescript", "pnpm-lock.yaml"),
        ("python", "uv.lock"),
        ("python", "poetry.lock"),
        ("python", "Pipfile.lock"),
        ("dotnet", "global.json"),
        ("ruby", "Gemfile.lock"),
    ] {
        if !has_primary_evidence(facts, ecosystem) {
            continue;
        }
        for path in inventory.named(path) {
            add_setup_metadata(facts, ecosystem, path);
        }
    }

    for (ecosystem, names, suffix) in [
        (
            "maven",
            &["mvnw", "mvnw.cmd"][..],
            ".mvn/wrapper/maven-wrapper.properties",
        ),
        (
            "gradle",
            &["gradlew", "gradlew.bat"][..],
            "gradle/wrapper/gradle-wrapper.properties",
        ),
    ] {
        if !has_primary_evidence(facts, ecosystem) {
            continue;
        }
        let paths: Vec<String> = inventory
            .files
            .keys()
            .filter(|path| names.contains(&file_name(path)) || path.ends_with(suffix))
            .cloned()
            .collect();
        for path in paths {
            add_setup_metadata(facts, ecosystem, path);
        }
    }
}

fn has_primary_evidence(facts: &ProjectFacts, ecosystem: &str) -> bool {
    if facts.units.iter().any(|unit| unit.ecosystem == ecosystem) {
        return true;
    }
    facts.evidence.iter().any(|evidence| {
        if evidence.ecosystem != ecosystem || evidence.status == DetectionStatus::Invalid {
            return false;
        }
        match ecosystem {
            "rust" => {
                evidence.kind == "cargo-manifest"
                    && evidence
                        .facts
                        .iter()
                        .any(|fact| matches!(fact.as_str(), "package" | "workspace"))
            }
            "go" => evidence.kind == "go-workspace" && !evidence.facts.is_empty(),
            "gradle" => matches!(evidence.kind.as_str(), "settings-script" | "build-script"),
            "dotnet" => matches!(
                evidence.kind.as_str(),
                "csproj" | "solution" | "solution-xml"
            ),
            _ => false,
        }
    })
}

fn add_setup_metadata(facts: &mut ProjectFacts, ecosystem: &str, path: String) {
    facts.evidence.push(Evidence {
        ecosystem: ecosystem.into(),
        kind: "setup-metadata".into(),
        path: path.clone(),
        status: DetectionStatus::Complete,
        parser: "presence@1".into(),
        facts: vec![format!("metadata:{}", file_name(&path))],
        reasons: Vec::new(),
    });
}

fn normalize(facts: &mut ProjectFacts) {
    for evidence in &mut facts.evidence {
        evidence.facts.sort();
        evidence.facts.dedup();
        evidence.reasons.sort();
        evidence.reasons.dedup();
    }
    facts.evidence.sort_by(|left, right| {
        (&left.path, &left.ecosystem, &left.kind).cmp(&(&right.path, &right.ecosystem, &right.kind))
    });
    facts.units.sort_by(|left, right| {
        (&left.root, &left.ecosystem, &left.evidence).cmp(&(
            &right.root,
            &right.ecosystem,
            &right.evidence,
        ))
    });
    facts.units.dedup();
    facts.workspace_relations.sort_by(|left, right| {
        (
            &left.workspace,
            &left.member,
            &left.ecosystem,
            &left.kind,
            &left.evidence,
        )
            .cmp(&(
                &right.workspace,
                &right.member,
                &right.ecosystem,
                &right.kind,
                &right.evidence,
            ))
    });
    facts.workspace_relations.dedup();
    facts.source_roots.sort_by(|left, right| {
        (&left.path, &left.ecosystem, &left.evidence, &left.kind).cmp(&(
            &right.path,
            &right.ecosystem,
            &right.evidence,
            &right.kind,
        ))
    });
    facts.source_roots.dedup();
    facts.status = if facts.evidence.is_empty() {
        DetectionStatus::Generic
    } else if facts
        .evidence
        .iter()
        .any(|evidence| evidence.status == DetectionStatus::Invalid)
    {
        DetectionStatus::Invalid
    } else if facts
        .evidence
        .iter()
        .any(|evidence| evidence.status == DetectionStatus::Partial)
    {
        DetectionStatus::Partial
    } else {
        DetectionStatus::Complete
    };
}

fn mark_partial(evidence: &mut Evidence, reason: String) {
    if evidence.status != DetectionStatus::Invalid {
        evidence.status = DetectionStatus::Partial;
    }
    evidence.reasons.push(reason);
}

fn relative(root: &Path, path: &Path) -> String {
    let tail = path.strip_prefix(root).unwrap_or(path);
    let joined = slash_path(tail);
    if joined.is_empty() {
        path.file_name()
            .map(Path::new)
            .map(slash_path)
            .unwrap_or_else(|| ".".into())
    } else {
        joined
    }
}

fn slash_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn parent(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_else(|| ".".into())
}

fn join_relative(root: &str, child: &str) -> String {
    if root == "." || root.is_empty() {
        child.trim_matches('/').to_string()
    } else if child == "." || child.is_empty() {
        root.to_string()
    } else {
        format!("{}/{}", root.trim_end_matches('/'), child.trim_matches('/'))
    }
}

fn resolve_relative(base: &str, declared: &str) -> Result<String, &'static str> {
    let declared = declared.replace('\\', "/");
    if declared.starts_with('/')
        || declared.starts_with("//")
        || declared.as_bytes().get(1) == Some(&b':')
    {
        return Err("is absolute and was refused");
    }
    let mut components: Vec<&str> = if base == "." || base.is_empty() {
        Vec::new()
    } else {
        base.split('/').collect()
    };
    for component in declared.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err("leaves the scan root and was refused");
                }
            }
            component => components.push(component),
        }
    }
    Ok(if components.is_empty() {
        ".".into()
    } else {
        components.join("/")
    })
}

fn bounded(mut message: String) -> String {
    const LIMIT: usize = 240;
    if message.len() > LIMIT {
        message.truncate(LIMIT);
    }
    message
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;
    use crate::walk::{self, IgnoreOptions};

    fn write(root: &Path, relative: &str, body: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture file has a parent")).unwrap();
        fs::write(path, body).unwrap();
    }

    fn detect_deterministically(
        root: &Path,
        inventory: walk::WalkResult,
        config: Option<&crate::config::Config>,
    ) -> ProjectFacts {
        let first = detect(root, &inventory, config);
        let mut reversed_files = inventory.files.clone();
        reversed_files.reverse();
        let reversed = walk::WalkResult {
            files: reversed_files,
            ignored: inventory.ignored,
            symlinks: inventory.symlinks.clone(),
        };
        let second = detect(root, &reversed, config);
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap(),
            "normalized facts changed with inventory scheduling"
        );
        first
    }

    #[test]
    fn explicit_scope_does_not_promote_to_an_ancestor_manifest() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "Cargo.toml",
            "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
        );
        write(
            repository.path(),
            "services/api/src/main.rs",
            "fn main() {}\n",
        );
        write(
            repository.path(),
            "services/api/Cargo.lock",
            "version = 3\n",
        );
        let root = repository.path().join("services/api");
        let inventory = walk::collect_files_counted(&root, &IgnoreOptions::default());

        let facts = detect_deterministically(&root, inventory, None);

        assert_eq!(facts.status, DetectionStatus::Generic);
        assert!(facts.evidence.is_empty());
        assert!(facts.units.is_empty());
        assert_eq!(facts.languages, vec!["rust"]);
        assert!(facts.generic_fallback);
    }

    #[test]
    fn repository_root_reports_detected_units_without_changing_scope() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "Cargo.toml",
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
        );
        write(repository.path(), "Cargo.lock", "version = 3\n");
        write(
            repository.path(),
            "src/lib.rs",
            "pub fn answer() -> u8 { 42 }\n",
        );
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(
            facts.status,
            DetectionStatus::Complete,
            "{:#?}",
            facts.evidence
        );
        assert_eq!(
            facts.units,
            vec![ProjectUnit {
                ecosystem: "rust".into(),
                kind: "package".into(),
                root: ".".into(),
                evidence: "Cargo.toml".into(),
            }]
        );
        assert_eq!(facts.languages, vec!["rust"]);
        assert!(facts.evidence.iter().any(|evidence| {
            evidence.ecosystem == "rust"
                && evidence.kind == "setup-metadata"
                && evidence.path == "Cargo.lock"
        }));
        assert_eq!(
            facts.source_roots,
            vec![SourceRootHint {
                ecosystem: "rust".into(),
                kind: "conventional".into(),
                path: "src".into(),
                evidence: "Cargo.toml".into(),
            }]
        );
    }

    #[test]
    fn rust_workspace_members_are_sorted_and_exclusions_remain_standalone() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/hidden\"]\n",
        );
        for name in ["zeta", "alpha", "hidden"] {
            let extra = match name {
                "alpha" => "\n[dependencies]\nzeta = { path = \"../zeta\" }\n",
                "hidden" => "workspace = \"../..\"\n",
                _ => "",
            };
            write(
                repository.path(),
                &format!("crates/{name}/Cargo.toml"),
                &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n{extra}"),
            );
            write(
                repository.path(),
                &format!("crates/{name}/src/lib.rs"),
                "pub fn marker() {}\n",
            );
        }
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(
            facts
                .units
                .iter()
                .map(|unit| unit.root.as_str())
                .collect::<Vec<_>>(),
            vec!["crates/alpha", "crates/hidden", "crates/zeta"]
        );
        assert_eq!(
            facts
                .workspace_relations
                .iter()
                .filter(|relation| relation.kind == "workspace-member")
                .map(|relation| relation.member.as_str())
                .collect::<Vec<_>>(),
            vec!["crates/alpha", "crates/zeta"]
        );
        assert!(facts.evidence.iter().any(|evidence| {
            evidence.path == "Cargo.toml"
                && evidence
                    .facts
                    .iter()
                    .any(|fact| fact == "excluded:crates/hidden")
        }));
        assert!(facts.workspace_relations.iter().any(|relation| {
            relation.kind == "path-dependency"
                && relation.workspace == "crates/alpha"
                && relation.member == "crates/zeta"
        }));
        assert!(facts.workspace_relations.iter().any(|relation| {
            relation.kind == "declared-workspace"
                && relation.workspace == "."
                && relation.member == "crates/hidden"
        }));
    }

    #[test]
    fn go_workspace_groups_in_root_modules_and_refuses_outside_uses() {
        let fixture = tempfile::tempdir().unwrap();
        let repository = fixture.path().join("repository");
        write(
            &repository,
            "go.work",
            "go 1.23\nuse (\n  ./modules/api\n  ../outside\n)\n",
        );
        write(
            &repository,
            "modules/api/go.mod",
            "module example.test/api\n\ngo 1.23\n",
        );
        write(&repository, "modules/api/main.go", "package main\n");
        write(
            fixture.path(),
            "outside/go.mod",
            "this file must never be read by project detection\n",
        );
        let inventory = walk::collect_files_counted(&repository, &IgnoreOptions::default());

        let facts = detect_deterministically(&repository, inventory, None);

        assert_eq!(facts.status, DetectionStatus::Partial);
        assert_eq!(
            facts.units,
            vec![ProjectUnit {
                ecosystem: "go".into(),
                kind: "module".into(),
                root: "modules/api".into(),
                evidence: "modules/api/go.mod".into(),
            }]
        );
        assert!(
            facts.workspace_relations.iter().any(|relation| {
                relation.member == "modules/api" && relation.status == "member"
            })
        );
        assert!(
            facts.workspace_relations.iter().any(|relation| {
                relation.member == "../outside" && relation.status == "refused"
            })
        );
        assert!(
            facts
                .evidence
                .iter()
                .all(|evidence| !evidence.path.contains("outside"))
        );
    }

    #[test]
    fn npm_workspace_keeps_declaration_indices_and_sorts_final_units() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "package.json",
            r#"{"name":"root","private":true,"workspaces":["packages/*","tools/*"]}"#,
        );
        for (directory, source) in [
            ("packages/zeta", "index.js"),
            ("packages/alpha", "index.ts"),
            ("tools/build", "build.js"),
        ] {
            write(
                repository.path(),
                &format!("{directory}/package.json"),
                &format!(r#"{{"name":"{}"}}"#, directory.replace('/', "-")),
            );
            write(
                repository.path(),
                &format!("{directory}/{source}"),
                "export {};\n",
            );
        }
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Complete);
        assert_eq!(
            facts
                .units
                .iter()
                .filter(|unit| unit.ecosystem == "javascript-typescript")
                .map(|unit| unit.root.as_str())
                .collect::<Vec<_>>(),
            vec![".", "packages/alpha", "packages/zeta", "tools/build"]
        );
        assert_eq!(
            facts
                .workspace_relations
                .iter()
                .map(|relation| (relation.member.as_str(), relation.declaration_index))
                .collect::<Vec<_>>(),
            vec![
                ("packages/alpha", Some(0)),
                ("packages/zeta", Some(0)),
                ("tools/build", Some(1)),
            ]
        );
        assert_eq!(facts.languages, vec!["javascript", "typescript"]);
    }

    #[test]
    fn tool_only_pyproject_records_setup_without_inventing_a_package() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "pyproject.toml",
            "[tool.ruff]\nline-length = 88\n",
        );
        write(repository.path(), "src/example.py", "print('hello')\n");
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Partial);
        assert_eq!(facts.languages, vec!["python"]);
        assert!(facts.units.iter().all(|unit| unit.ecosystem != "python"));
        assert!(facts.evidence.iter().any(|evidence| {
            evidence.path == "pyproject.toml"
                && evidence.status == DetectionStatus::Partial
                && evidence.facts.iter().any(|fact| fact == "tooling")
        }));
    }

    #[test]
    fn maven_resolves_unconditional_modules_and_marks_profile_modules_partial() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "pom.xml",
            r#"<project><modelVersion>4.0.0</modelVersion><modules><module>api</module></modules><profiles><profile><id>extra</id><modules><module>hidden</module></modules></profile></profiles></project>"#,
        );
        for name in ["api", "hidden"] {
            let parent = if name == "api" {
                "<parent><relativePath>../../outside/pom.xml</relativePath></parent>"
            } else {
                ""
            };
            write(
                repository.path(),
                &format!("{name}/pom.xml"),
                &format!("<project><modelVersion>4.0.0</modelVersion>{parent}</project>"),
            );
            write(
                repository.path(),
                &format!("{name}/src/main/java/App.java"),
                "class App {}\n",
            );
        }
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Partial);
        assert_eq!(
            facts
                .units
                .iter()
                .filter(|unit| unit.ecosystem == "maven")
                .map(|unit| unit.root.as_str())
                .collect::<Vec<_>>(),
            vec![".", "api", "hidden"]
        );
        assert!(facts.workspace_relations.iter().any(|relation| {
            relation.ecosystem == "maven" && relation.member == "api" && relation.status == "member"
        }));
        assert!(
            facts
                .workspace_relations
                .iter()
                .all(|relation| { relation.ecosystem != "maven" || relation.member != "hidden" })
        );
        assert!(facts.evidence.iter().any(|evidence| {
            evidence.path == "api/pom.xml"
                && evidence.status == DetectionStatus::Partial
                && evidence
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("parent"))
        }));
        assert_eq!(facts.languages, vec!["java"]);
    }

    #[test]
    fn gradle_scripts_remain_partial_and_do_not_claim_conditional_members() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "settings.gradle",
            "if (false) { include(':ghost') }\n",
        );
        write(repository.path(), "build.gradle", "plugins { id 'java' }\n");
        write(
            repository.path(),
            "service/build.gradle.kts",
            "plugins { java }\n",
        );
        write(
            repository.path(),
            "service/src/main/java/Service.java",
            "class Service {}\n",
        );
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Partial);
        assert_eq!(
            facts
                .units
                .iter()
                .filter(|unit| unit.ecosystem == "gradle")
                .map(|unit| unit.root.as_str())
                .collect::<Vec<_>>(),
            vec![".", "service"]
        );
        assert!(facts.workspace_relations.iter().any(|relation| {
            relation.ecosystem == "gradle"
                && relation.workspace == "."
                && relation.member == "service"
                && relation.status == "hint"
        }));
        assert!(
            facts
                .workspace_relations
                .iter()
                .all(|relation| relation.member != "ghost")
        );
        assert!(facts.generic_fallback);
    }

    #[test]
    fn cmake_scripts_remain_partial_while_c_and_cpp_files_stay_detected() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "CMakeLists.txt",
            "set(CHILD lib)\nif(ENABLE_CHILD)\n  add_subdirectory(${CHILD})\nendif()\n",
        );
        write(
            repository.path(),
            "lib/CMakeLists.txt",
            "add_library(example example.cpp)\n",
        );
        write(
            repository.path(),
            "src/main.c",
            "int main(void) { return 0; }\n",
        );
        write(
            repository.path(),
            "lib/example.cpp",
            "int example() { return 1; }\n",
        );
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Partial);
        assert_eq!(
            facts
                .units
                .iter()
                .filter(|unit| unit.ecosystem == "cmake")
                .map(|unit| unit.root.as_str())
                .collect::<Vec<_>>(),
            vec![".", "lib"]
        );
        assert!(facts.workspace_relations.iter().any(|relation| {
            relation.ecosystem == "cmake"
                && relation.workspace == "."
                && relation.member == "lib"
                && relation.status == "hint"
        }));
        assert_eq!(facts.languages, vec!["c", "cpp"]);
    }

    #[test]
    fn dotnet_projects_are_deduplicated_and_keep_every_solution_relation() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "App/App.csproj",
            r#"<Project Sdk="Microsoft.NET.Sdk"></Project>"#,
        );
        write(repository.path(), "App/Program.cs", "class Program {}\n");
        write(
            repository.path(),
            "Legacy/Legacy.csproj",
            r#"<Project><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup></Project>"#,
        );
        write(repository.path(), "Legacy/Legacy.cs", "class Legacy {}\n");
        write(
            repository.path(),
            "all.sln",
            "Microsoft Visual Studio Solution File, Format Version 12.00\nProject(\"{A}\") = \"App\", \"App\\App.csproj\", \"{B}\"\nEndProject\nProject(\"{A}\") = \"Legacy\", \"Legacy\\Legacy.csproj\", \"{C}\"\nEndProject\n",
        );
        write(
            repository.path(),
            "app.slnx",
            r#"<Solution><Project Path="App/App.csproj" /></Solution>"#,
        );
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Complete);
        assert_eq!(
            facts
                .units
                .iter()
                .filter(|unit| unit.ecosystem == "dotnet")
                .map(|unit| unit.root.as_str())
                .collect::<Vec<_>>(),
            vec!["App", "Legacy"]
        );
        assert_eq!(
            facts
                .workspace_relations
                .iter()
                .filter(|relation| relation.ecosystem == "dotnet")
                .count(),
            3
        );
        assert_eq!(
            facts
                .source_roots
                .iter()
                .filter(|root| root.ecosystem == "dotnet")
                .map(|root| root.path.as_str())
                .collect::<Vec<_>>(),
            vec!["App"]
        );
        assert_eq!(facts.languages, vec!["csharp"]);
    }

    #[test]
    fn ruby_code_is_never_evaluated_and_workspace_links_stay_hints() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "Gemfile",
            "raise 'detector executed Ruby'\nDir['gems/*'].each { |path| gem path, path: path }\n",
        );
        for name in ["alpha", "beta"] {
            write(
                repository.path(),
                &format!("gems/{name}/{name}.gemspec"),
                "raise 'detector executed gemspec'\n",
            );
            write(
                repository.path(),
                &format!("gems/{name}/lib/{name}.rb"),
                &format!("module {}\nend\n", name.to_ascii_uppercase()),
            );
        }
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Partial);
        assert_eq!(
            facts
                .units
                .iter()
                .filter(|unit| unit.ecosystem == "ruby")
                .map(|unit| (unit.kind.as_str(), unit.root.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("application", "."),
                ("gem", "gems/alpha"),
                ("gem", "gems/beta"),
            ]
        );
        assert_eq!(
            facts
                .workspace_relations
                .iter()
                .filter(|relation| relation.ecosystem == "ruby")
                .map(|relation| (relation.member.as_str(), relation.status.as_str()))
                .collect::<Vec<_>>(),
            vec![("gems/alpha", "hint"), ("gems/beta", "hint")]
        );
        assert_eq!(facts.languages, vec!["ruby"]);
    }

    #[test]
    fn malformed_manifest_does_not_erase_valid_rust_or_go_facts() {
        let repository = tempfile::tempdir().unwrap();
        write(repository.path(), "package.json", "{not valid json\n");
        write(
            repository.path(),
            "Cargo.toml",
            "[package]\nname = \"valid-rust\"\nversion = \"0.1.0\"\n",
        );
        write(repository.path(), "src/lib.rs", "pub fn valid() {}\n");
        write(
            repository.path(),
            "service/go.mod",
            "module example.test/service\n\ngo 1.23\n",
        );
        write(repository.path(), "service/main.go", "package service\n");
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Invalid);
        assert!(facts.evidence.iter().any(|evidence| {
            evidence.path == "package.json" && evidence.status == DetectionStatus::Invalid
        }));
        assert_eq!(
            facts
                .units
                .iter()
                .map(|unit| (unit.ecosystem.as_str(), unit.root.as_str()))
                .collect::<Vec<_>>(),
            vec![("rust", "."), ("go", "service")]
        );
        assert_eq!(facts.languages, vec!["go", "rust"]);
        assert!(facts.generic_fallback);
    }

    #[test]
    fn ignored_manifest_never_enters_the_project_model() {
        let repository = tempfile::tempdir().unwrap();
        write(repository.path(), ".gitignore", "ignored/\n");
        write(
            repository.path(),
            "ignored/package.json",
            r#"{"name":"must-not-appear"}"#,
        );
        write(repository.path(), "ignored/index.js", "export {};\n");
        write(repository.path(), "src/main.rs", "fn main() {}\n");
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());
        assert!(
            inventory
                .files
                .iter()
                .all(|path| !path.ends_with("package.json"))
        );

        let facts = detect_deterministically(repository.path(), inventory, None);

        assert_eq!(facts.status, DetectionStatus::Generic);
        assert!(facts.evidence.is_empty());
        assert_eq!(facts.languages, vec!["rust"]);
    }

    #[test]
    fn normalized_facts_are_identical_across_repeated_inventory_schedules() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "Cargo.toml",
            "[package]\nname = \"mixed\"\nversion = \"0.1.0\"\n",
        );
        write(repository.path(), "package.json", r#"{"name":"mixed"}"#);
        write(
            repository.path(),
            "service/go.mod",
            "module example.test/service\n\ngo 1.23\n",
        );
        write(repository.path(), "src/lib.rs", "pub fn rust() {}\n");
        write(repository.path(), "web/index.ts", "export {};\n");
        write(repository.path(), "service/main.go", "package service\n");
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());
        let expected = serde_json::to_vec(&detect(repository.path(), &inventory, None)).unwrap();

        for shift in 0..inventory.files.len() {
            let mut files = inventory.files.clone();
            files.rotate_left(shift);
            let scheduled = walk::WalkResult {
                files,
                ignored: inventory.ignored,
                symlinks: inventory.symlinks.clone(),
            };
            assert_eq!(
                serde_json::to_vec(&detect(repository.path(), &scheduled, None)).unwrap(),
                expected,
                "schedule rotation {shift} changed normalized facts"
            );
        }
    }

    #[test]
    fn detected_source_hints_do_not_rewrite_empty_config_source_roots() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "Cargo.toml",
            "[package]\nname = \"root-only\"\nversion = \"0.1.0\"\n",
        );
        write(repository.path(), "src/lib.rs", "pub fn source() {}\n");
        let config = crate::config::Config::default();
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());

        let facts = detect_deterministically(repository.path(), inventory, Some(&config));

        assert!(config.source_roots.is_empty());
        assert!(facts.source_roots.iter().any(|root| root.path == "src"));
    }

    #[test]
    fn empty_rules_remain_empty_when_project_evidence_is_present() {
        let repository = tempfile::tempdir().unwrap();
        write(
            repository.path(),
            "Cargo.toml",
            "[package]\nname = \"no-defaults\"\nversion = \"0.1.0\"\n",
        );
        write(
            repository.path(),
            "src/lib.rs",
            "const TOKEN: &str = \"secret\";\n",
        );
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());
        let facts = detect_deterministically(repository.path(), inventory, None);
        let report = crate::scan::scan_opts(
            repository.path(),
            &crate::rules::RuleSet::default(),
            &crate::scan::ScanOptions::default(),
            &mut |_| {},
        )
        .unwrap();

        assert_eq!(facts.status, DetectionStatus::Complete);
        assert!(facts.generic_fallback);
        assert!(report.findings.is_empty());
        assert!(report.baselined.is_empty());
        assert!(report.suppressed.is_empty());
    }

    #[test]
    fn configured_language_changes_only_files_with_the_mapped_extension() {
        const RULES: &str = r#"
version: 1
rules:
  - id: test.all
    severity: warning
    message: "needle"
    regex:
      pattern: "needle"
  - id: test.ruby
    severity: warning
    message: "ruby needle"
    languages: [ruby]
    regex:
      pattern: "needle"
"#;
        let repository = tempfile::tempdir().unwrap();
        write(repository.path(), "mapped.tmpl", "needle\n# comment\n");
        write(repository.path(), "existing.py", "needle\n# comment\n");
        write(repository.path(), "unrelated.rs", "needle\n// comment\n");
        let rules = crate::rules::RuleSet {
            rules: crate::rules::load_str(RULES, "configured-language").unwrap(),
            sources: vec![("configured-language".into(), RULES.into())],
        };
        let base_config = crate::config::Config::default();
        let mapped_config: crate::config::Config =
            toml::from_str("[languages]\ntmpl = \"ruby\"\n").unwrap();
        let cache_root = tempfile::tempdir().unwrap();
        let cache = crate::cache::Cache::open_in(
            cache_root.path(),
            repository.path(),
            &rules,
            &crate::cache::PathScope::ScanRoot,
        );

        let old = crate::scan::scan_opts(
            repository.path(),
            &rules,
            &crate::scan::ScanOptions {
                config: Some(&base_config),
                cache: Some(&cache),
                ..crate::scan::ScanOptions::default()
            },
            &mut |_| {},
        )
        .unwrap();
        let new = crate::scan::scan_opts(
            repository.path(),
            &rules,
            &crate::scan::ScanOptions {
                config: Some(&mapped_config),
                cache: Some(&cache),
                ..crate::scan::ScanOptions::default()
            },
            &mut |_| {},
        )
        .unwrap();
        let inventory = walk::collect_files_counted(repository.path(), &IgnoreOptions::default());
        let facts = detect_deterministically(repository.path(), inventory, Some(&mapped_config));

        assert_eq!(facts.languages, vec!["python", "ruby", "rust"]);
        let mut expected_findings = old.findings.clone();
        expected_findings.push(
            new.findings
                .iter()
                .find(|finding| finding.path == "mapped.tmpl" && finding.rule_id == "test.ruby")
                .expect("mapped file gets the configured language rule")
                .clone(),
        );
        expected_findings.sort_by(|left, right| {
            (&left.path, left.line, left.column, &left.rule_id).cmp(&(
                &right.path,
                right.line,
                right.column,
                &right.rule_id,
            ))
        });
        assert_eq!(new.findings, expected_findings);
        assert_eq!(new.baselined, old.baselined);
        assert_eq!(new.suppressed, old.suppressed);
        assert_eq!(new.skipped.len(), old.skipped.len());
        assert_eq!(new.ignored, old.ignored);
        assert_eq!(new.graph, old.graph);
        assert_eq!(new.boundary_edges, old.boundary_edges);
        assert_eq!(new.warnings, old.warnings);
        for path in ["existing.py", "unrelated.rs"] {
            assert_eq!(new.metrics.files[path], old.metrics.files[path], "{path}");
        }
        assert_eq!(old.metrics.files["mapped.tmpl"].code_lines, None);
        assert_eq!(new.metrics.files["mapped.tmpl"].code_lines, Some(1));
    }

    #[test]
    fn an_unknown_language_name_in_a_mapping_matches_nothing() {
        const RULES: &str = r#"
version: 1
rules:
  - id: test.all
    severity: warning
    message: "needle all"
    regex:
      pattern: "needle"
  - id: test.rust
    severity: warning
    message: "needle rust"
    languages: [rust]
    regex:
      pattern: "needle"
"#;
        let repository = tempfile::tempdir().unwrap();
        write(repository.path(), "mapped.cobol", "needle\n");
        write(repository.path(), "target.rs", "needle\n");
        let rules = crate::rules::RuleSet {
            rules: crate::rules::load_str(RULES, "unknown-language").unwrap(),
            sources: vec![("unknown-language".into(), RULES.into())],
        };
        let mapped_config: crate::config::Config =
            toml::from_str("[languages]\ncobol = \"cobol\"\n").unwrap();
        let cache_root = tempfile::tempdir().unwrap();
        let cache = crate::cache::Cache::open_in(
            cache_root.path(),
            repository.path(),
            &rules,
            &crate::cache::PathScope::ScanRoot,
        );

        let report = crate::scan::scan_opts(
            repository.path(),
            &rules,
            &crate::scan::ScanOptions {
                config: Some(&mapped_config),
                cache: Some(&cache),
                ..crate::scan::ScanOptions::default()
            },
            &mut |_| {},
        )
        .unwrap();

        // The file mapped to "cobol" produces the regex finding (all languages),
        // not the rust-specific finding, because "cobol" is not a known language.
        let mapped_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.path == "mapped.cobol")
            .collect();
        assert_eq!(mapped_findings.len(), 1);
        assert_eq!(mapped_findings[0].rule_id, "test.all");

        // The rust file produces both findings: the all-languages and the rust-specific.
        let rust_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.path == "target.rs")
            .collect();
        assert_eq!(rust_findings.len(), 2);
        assert!(rust_findings.iter().any(|f| f.rule_id == "test.all"));
        assert!(rust_findings.iter().any(|f| f.rule_id == "test.rust"));
    }
}
