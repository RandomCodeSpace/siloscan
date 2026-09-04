//! The automatic journey, one ecosystem at a time.
//!
//! A bare `siloscan` in a repository is the whole v2 product: it detects what
//! the tree is, scans it with the unchanged embedded pack, prints the finding,
//! saves one report and says how to reopen it. This suite runs that journey
//! through both binary names over the ten fixture shapes the acceptance plan
//! names, and asserts the printed lines rather than only the exit code, because
//! those lines are the approved human output and nothing else guards them.
//!
//! # The wording is the contract
//!
//! The two bare-mode lines are asserted whole:
//!
//! ```text
//! setup: 1 project unit; languages: rust; rules: default-secrets@1, maintainability-rust@1, reliability-rust@1
//! capabilities: cache enabled; coverage not configured; ...
//! ```
//!
//! Freezing them here is the point of the lane. A capability that silently
//! stops being reported, a rule pack that starts calling itself something else,
//! or a detector that stops naming a language would otherwise change what every
//! user sees with no test failing.
//!
//! # The profiles are part of the bare contract
//!
//! Since 2.1.0 a bare run resolves `ProfileSelection::Auto`, so the `rules:`
//! clause names the profile documents for the languages the fixture detected
//! and the `profiles` capability appears on the line below. Both are computed
//! from the fixture's own `languages` against the shipped registry rather than
//! listed per fixture, so the assertions stay whole-line equalities: what is
//! frozen is that a bare run in a Rust tree loads the Rust profiles and nothing
//! else, not that some line matched some pattern. An explicit `PATH` still
//! loads none of them, which is `v2_oracle_harness`'s job.
//!
//! # The credential
//!
//! Every fixture plants one credential, generated when the test runs, so no
//! credential-shaped literal lives in the repository and every fixture reaches
//! the same error-severity rule and therefore the same exit status.
//!
//! # Where the report is
//!
//! By the `Report:` line the run printed, never by searching the state
//! directory: only Linux resolves its state root from the environment.
//! `v2_persistence` has the long version of that argument.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use siloscan_core::serde_json::Value;
use tempfile::TempDir;

#[path = "common/isolation.rs"]
mod isolation;

const BINARIES: [(&str, &str); 2] = [
    ("siloscan", env!("CARGO_BIN_EXE_siloscan")),
    ("ss", env!("CARGO_BIN_EXE_ss")),
];

/// The embedded pack's published identity, and the rule count v2.0.0 ships. No
/// ecosystem add-on exists, so this number is the same for every fixture below.
const EMBEDDED_PACK: &str = "default-secrets@1";
const EMBEDDED_RULES: usize = 220;

/// The four fields that make a report a v2 resolved report.
const MARKERS: [&str; 4] = ["report_kind", "scope", "outcome", "setup"];

/// Where the planted credential goes in a fixture file.
const CREDENTIAL: &str = "@CREDENTIAL@";

/// The rule the planted credential matches: error severity, so every fixture
/// exits 1, and a secret rule, so the report redacts the value.
const PLANTED_RULE: &str = "secrets.gitlab-ptt";

/// One fixture repository and everything the journey must say about it.
struct Ecosystem {
    /// Names the fixture in failure messages.
    name: &'static str,
    /// The tree, with [`CREDENTIAL`] standing in for the planted token.
    files: &'static [(&'static str, &'static str)],
    /// The file the credential is planted in, as the report names it.
    finding_path: &'static str,
    /// How many project units detection must find.
    units: usize,
    /// The languages the setup line lists, already in the order it prints them.
    languages: &'static str,
    /// The aggregate detection status, derived from the evidence the report
    /// carries. `complete` for a fixture whose manifests are all parsed,
    /// `partial` where the ecosystem's manifest is code this scanner refuses to
    /// evaluate, `generic` for a tree with no manifest at all.
    status: &'static str,
}

const RUST: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "src/main.rs",
        "fn main() {\n    let token = \"@CREDENTIAL@\";\n    println!(\"{token}\");\n}\n",
    ),
];

const GO: &[(&str, &str)] = &[
    ("go.mod", "module example.com/demo\n\ngo 1.22\n"),
    (
        "main.go",
        "package main\n\nconst token = \"@CREDENTIAL@\"\n",
    ),
];

const JAVASCRIPT: &[(&str, &str)] = &[
    (
        "package.json",
        "{\"name\":\"demo\",\"version\":\"0.1.0\"}\n",
    ),
    ("src/index.js", "export const name = \"demo\";\n"),
    (
        "src/client.ts",
        "export const token: string = \"@CREDENTIAL@\";\n",
    ),
];

const PYTHON: &[(&str, &str)] = &[
    (
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    ),
    ("src/demo/__init__.py", "TOKEN = \"@CREDENTIAL@\"\n"),
];

const MAVEN: &[(&str, &str)] = &[
    (
        "pom.xml",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
         \x20 <modelVersion>4.0.0</modelVersion>\n\
         \x20 <groupId>com.example</groupId>\n\
         \x20 <artifactId>demo</artifactId>\n\
         \x20 <version>0.1.0</version>\n\
         </project>\n",
    ),
    (
        "src/main/java/com/example/App.java",
        "package com.example;\n\n\
         public class App {\n\
         \x20   static final String TOKEN = \"@CREDENTIAL@\";\n\
         }\n",
    ),
];

const GRADLE: &[(&str, &str)] = &[
    ("settings.gradle", "rootProject.name = 'demo'\n"),
    ("build.gradle", "plugins { id 'java' }\n"),
    (
        "src/main/java/com/example/App.java",
        "package com.example;\n\n\
         public class App {\n\
         \x20   static final String TOKEN = \"@CREDENTIAL@\";\n\
         }\n",
    ),
];

const CMAKE: &[(&str, &str)] = &[
    (
        "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(demo C CXX)\nadd_executable(demo src/main.cpp)\n",
    ),
    (
        "src/main.cpp",
        "const char *token = \"@CREDENTIAL@\";\nint main() { return 0; }\n",
    ),
    ("src/support.c", "int support(void) { return 0; }\n"),
];

const DOTNET: &[(&str, &str)] = &[
    (
        "Demo.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n\
         \x20 <PropertyGroup>\n\
         \x20   <TargetFramework>net8.0</TargetFramework>\n\
         \x20 </PropertyGroup>\n\
         </Project>\n",
    ),
    (
        "Program.cs",
        "class Program {\n    const string Token = \"@CREDENTIAL@\";\n}\n",
    ),
];

const RUBY: &[(&str, &str)] = &[
    ("Gemfile", "source 'https://rubygems.org'\n"),
    (
        "demo.gemspec",
        "Gem::Specification.new do |s|\n  s.name = 'demo'\nend\n",
    ),
    ("lib/demo.rb", "TOKEN = \"@CREDENTIAL@\"\n"),
];

const MIXED: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("src/main.rs", "fn main() {}\n"),
    (
        "web/package.json",
        "{\"name\":\"demo-web\",\"version\":\"0.1.0\"}\n",
    ),
    ("web/index.js", "export const token = \"@CREDENTIAL@\";\n"),
    ("service/go.mod", "module example.com/service\n\ngo 1.22\n"),
    ("service/main.go", "package main\n"),
];

const GENERIC: &[(&str, &str)] = &[
    ("notes.txt", "deployment notes\n@CREDENTIAL@\n"),
    ("run.sh", "#!/bin/sh\necho hello\n"),
];

/// The ten fixtures the plan's automatic-journey gate names.
///
/// Gradle, CMake and Ruby are `partial` rather than `complete` because their
/// manifests are programs: `build.gradle`, `CMakeLists.txt`, a `Gemfile` and a
/// gemspec are only evaluated by running them, and detection never runs a
/// project tool. The status says so instead of pretending to a completeness the
/// scanner did not establish.
const ECOSYSTEMS: &[Ecosystem] = &[
    Ecosystem {
        name: "rust",
        files: RUST,
        finding_path: "src/main.rs",
        units: 1,
        languages: "rust",
        status: "complete",
    },
    Ecosystem {
        name: "go",
        files: GO,
        finding_path: "main.go",
        units: 1,
        languages: "go",
        status: "complete",
    },
    Ecosystem {
        name: "javascript",
        files: JAVASCRIPT,
        finding_path: "src/client.ts",
        units: 1,
        languages: "javascript, typescript",
        status: "complete",
    },
    Ecosystem {
        name: "python",
        files: PYTHON,
        finding_path: "src/demo/__init__.py",
        units: 1,
        languages: "python",
        status: "complete",
    },
    Ecosystem {
        name: "maven",
        files: MAVEN,
        finding_path: "src/main/java/com/example/App.java",
        units: 1,
        languages: "java",
        status: "complete",
    },
    Ecosystem {
        name: "gradle",
        files: GRADLE,
        finding_path: "src/main/java/com/example/App.java",
        units: 1,
        languages: "java",
        status: "partial",
    },
    Ecosystem {
        name: "cmake",
        files: CMAKE,
        finding_path: "src/main.cpp",
        units: 1,
        languages: "c, cpp",
        status: "partial",
    },
    Ecosystem {
        name: "dotnet",
        files: DOTNET,
        finding_path: "Program.cs",
        units: 1,
        languages: "csharp",
        status: "complete",
    },
    Ecosystem {
        name: "ruby",
        files: RUBY,
        finding_path: "lib/demo.rb",
        units: 1,
        languages: "ruby",
        status: "partial",
    },
    Ecosystem {
        name: "mixed",
        files: MIXED,
        finding_path: "web/index.js",
        units: 3,
        languages: "go, javascript, rust",
        status: "complete",
    },
    Ecosystem {
        name: "generic",
        files: GENERIC,
        finding_path: "notes.txt",
        units: 0,
        languages: "none",
        status: "generic",
    },
];

/// One isolated machine with one fixture repository in it.
struct Host {
    _dir: TempDir,
    state: PathBuf,
    home: PathBuf,
    cache: PathBuf,
    tree: PathBuf,
}

impl Host {
    fn new(ecosystem: &Ecosystem) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = dir.path().join("state");
        let home = dir.path().join("home");
        let cache = dir.path().join("cache");
        let tree = dir.path().join("tree");
        for path in [&state, &home, &cache, &tree] {
            fs::create_dir_all(path).expect("fixture directory");
        }
        let credential = credential();
        for (name, body) in ecosystem.files {
            let path = tree.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent directory");
            }
            fs::write(&path, body.replace(CREDENTIAL, &credential)).expect("fixture file");
        }
        Self {
            _dir: dir,
            state,
            home,
            cache,
            tree,
        }
    }

    fn run(&self, binary: &str, args: &[&str]) -> Output {
        let mut command = Command::new(binary);
        command.current_dir(&self.tree);
        isolation::isolate(&mut command, &self.cache, &self.state, &self.home)
            .args(args)
            .output()
            .expect("binary should run")
    }
}

/// A GitLab pipeline trigger token, generated per fixture.
///
/// Forty lowercase hex digits after the vendor prefix, which is what the rule
/// matches, taken from a digest of this process and this call so two fixtures
/// in one run never plant the same value.
fn credential() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_nanos();
    let seed = format!(
        "{nanos}:{}:{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let digest = siloscan_core::cache::content_hash(seed.as_bytes());
    format!("glptt-{}", &digest[..40])
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be UTF-8")
}

/// The report a run says it wrote, from stdout for human output and from stderr
/// for machine output.
fn saved_line(output: &Output) -> Option<PathBuf> {
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        if let Some(path) = text.lines().find_map(|line| line.strip_prefix("Report: ")) {
            return Some(PathBuf::from(path));
        }
    }
    None
}

fn document(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    siloscan_core::serde_json::from_slice(&bytes).expect("the saved report should be JSON")
}

/// The languages the fixture's setup line lists, as the detector reports them.
///
/// The `languages:` clause is the list, comma-joined; `none` is the empty list
/// and not a language.
fn detected_languages(ecosystem: &Ecosystem) -> Vec<&'static str> {
    match ecosystem.languages {
        "none" => Vec::new(),
        list => list.split(", ").collect(),
    }
}

/// The profile identities a bare run in this fixture loads.
///
/// Exactly what `ProfileSelection::Auto` resolves: every registry entry whose
/// language the detector reported, ordered by identity. Derived from the
/// fixture's own languages rather than listed per fixture, so a registry that
/// grows a family or a language is reflected here without a second edit - and
/// a fixture whose detected languages change fails on the `languages:` clause
/// of the same line.
fn profile_identities(ecosystem: &Ecosystem) -> Vec<&'static str> {
    let languages = detected_languages(ecosystem);
    let mut identities: Vec<&'static str> = siloscan_core::profiles::REGISTRY
        .iter()
        .filter(|profile| languages.contains(&profile.language()))
        .map(|profile| profile.identity())
        .collect();
    identities.sort_unstable();
    identities
}

/// The setup line a fixture must print, built the way the binary builds it.
///
/// `rules:` names the embedded pack and then every selected profile document,
/// which is the order `setup.rule_sources` puts them in: embedded first, then
/// by id, and `default-secrets@1` sorts before both families.
fn setup_line(ecosystem: &Ecosystem) -> String {
    let units = match ecosystem.units {
        0 => "no project units".to_string(),
        1 => "1 project unit".to_string(),
        count => format!("{count} project units"),
    };
    let mut rules = vec![EMBEDDED_PACK];
    rules.extend(profile_identities(ecosystem));
    format!(
        "setup: {units}; languages: {}; rules: {}",
        ecosystem.languages,
        rules.join(", ")
    )
}

/// The capability line a fixture must print.
///
/// Every capability this scanner has, in the order the report sorts them. Two
/// of them differ between fixtures, and for the same reason: a tree with no
/// manifest configures nothing for detection to read, and a tree whose detected
/// languages ship no profile document has no profile to load. They are not the
/// same condition - a detected language without documents would enable one and
/// not the other - so each is derived from what it actually depends on.
fn capability_line(ecosystem: &Ecosystem) -> String {
    let detection = match ecosystem.units {
        0 => "not configured",
        _ => "enabled",
    };
    let profiles = match profile_identities(ecosystem).is_empty() {
        true => "not configured",
        false => "enabled",
    };
    format!(
        "capabilities: cache enabled; coverage not configured; embedded-rules enabled; \
         profiles {profiles}; project-detection {detection}; \
         repository-config not configured; \
         rule-directories not configured; scan-baseline not configured; \
         symlink-following not configured"
    )
}

/// The aggregate detection status, derived from the evidence the report carries.
///
/// The setup report records a status per piece of evidence rather than one for
/// the tree, so the tree's status is derived here by the detector's own rule:
/// no evidence at all is generic, any invalid evidence is invalid, any partial
/// evidence is partial, and everything else is complete.
fn detection_status(setup: &Value) -> String {
    let evidence = setup["evidence"]
        .as_array()
        .expect("the setup report lists its evidence");
    let statuses: Vec<&str> = evidence
        .iter()
        .map(|item| item["status"].as_str().expect("an evidence status"))
        .collect();
    if statuses.is_empty() {
        return "generic".to_string();
    }
    for status in ["invalid", "partial"] {
        if statuses.contains(&status) {
            return status.to_string();
        }
    }
    "complete".to_string()
}

// ---------------------------------------------------------------------------
// The journey
// ---------------------------------------------------------------------------

/// The bare journey, over every fixture and through both binary names.
#[test]
fn the_bare_journey_detects_scans_saves_and_says_how_to_review() {
    for ecosystem in ECOSYSTEMS {
        for (name, binary) in BINARIES {
            let case = format!("{}/{name}", ecosystem.name);
            let host = Host::new(ecosystem);

            let output = host.run(binary, &[]);

            // One planted credential of error severity, so the gate fails.
            assert_eq!(output.status.code(), Some(1), "{case}: {}", stderr(&output));

            let text = stdout(&output);
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(
                lines.first().copied(),
                Some(setup_line(ecosystem).as_str()),
                "{case}"
            );
            assert_eq!(
                lines.get(1).copied(),
                Some(capability_line(ecosystem).as_str()),
                "{case}"
            );

            let findings: Vec<&&str> = lines
                .iter()
                .filter(|line| line.contains(&format!(" error {PLANTED_RULE} ")))
                .collect();
            assert_eq!(findings.len(), 1, "{case}: {text}");
            assert!(
                findings[0].starts_with(&format!("{}:", ecosystem.finding_path)),
                "{case}: {}",
                findings[0]
            );
            assert!(
                lines.iter().any(|line| line.starts_with("metrics: ")),
                "{case}: {text}"
            );

            let report = saved_line(&output).unwrap_or_else(|| panic!("{case}: {text}"));
            assert!(report.is_file(), "{case}: {}", report.display());
            assert_eq!(
                lines.get(lines.len() - 2).copied(),
                Some(format!("Report: {}", report.display()).as_str()),
                "{case}"
            );
            assert_eq!(
                lines.last().copied(),
                Some(format!("Review: {name} review").as_str()),
                "{case}"
            );

            let saved = document(&report);
            for marker in MARKERS {
                assert!(!saved[marker].is_null(), "{case}: {marker} is missing");
            }
            assert_eq!(saved["report_kind"], "scan", "{case}");

            let setup = &saved["setup"];
            assert_eq!(detection_status(setup), ecosystem.status, "{case}");
            assert_eq!(
                setup["units"].as_array().map(Vec::len),
                Some(ecosystem.units),
                "{case}"
            );
            let mut expected_sources = vec![siloscan_core::serde_json::json!(
                { "id": EMBEDDED_PACK, "origin": "embedded" }
            )];
            expected_sources.extend(profile_identities(ecosystem).into_iter().map(|identity| {
                siloscan_core::serde_json::json!({ "id": identity, "origin": "embedded" })
            }));
            assert_eq!(
                setup["rule_sources"],
                Value::Array(expected_sources),
                "{case}: the embedded pack and the detected languages' profiles load"
            );
        }
    }
}

/// The embedded pack the `rules:` line names still carries every rule v2 ships.
///
/// The report names the pack; this counts what that name resolves to, so a pack
/// that lost or gained rules cannot pass the journey above by still calling
/// itself the same thing.
#[test]
fn the_named_pack_is_the_unchanged_220_rule_pack() {
    let rules = siloscan_core::rules::load_str(
        siloscan_core::default_pack::default_rules(),
        "default-pack",
    )
    .expect("the embedded pack should load");
    assert_eq!(rules.len(), EMBEDDED_RULES);
}

/// An explicit machine-format scan puts one document on stdout and nothing else.
///
/// The publication lines are the risk: they are English, and a consumer parsing
/// stdout would choke on them. An explicit scan saves nothing at all, so there
/// are none to route anywhere.
#[test]
fn explicit_machine_formats_keep_stdout_to_one_document() {
    for format in ["json", "sarif"] {
        for (name, binary) in BINARIES {
            let host = Host::new(&ECOSYSTEMS[0]);

            let output = host.run(binary, &[".", "--format", format]);

            let case = format!("{name} {format}");
            assert_eq!(output.status.code(), Some(1), "{case}: {}", stderr(&output));
            let text = stdout(&output);
            let parsed: Result<Value, _> = siloscan_core::serde_json::from_str(&text);
            assert!(parsed.is_ok(), "{case}: {text}");
            for line in ["Report: ", "Review: ", "setup: ", "capabilities: "] {
                assert!(!text.contains(line), "{case}: {text}");
                assert!(
                    !stderr(&output).contains(line),
                    "{case}: {}",
                    stderr(&output)
                );
            }
            assert_eq!(saved_line(&output), None, "{case}");
        }
    }
}

/// `--no-save` keeps the bare summary and drops the publication lines, because
/// there is no report for them to point at.
#[test]
fn a_bare_run_with_no_save_prints_no_report_line() {
    for (name, binary) in BINARIES {
        let host = Host::new(&ECOSYSTEMS[0]);

        let output = host.run(binary, &["--no-save"]);

        assert_eq!(output.status.code(), Some(1), "{name}: {}", stderr(&output));
        let text = stdout(&output);
        assert!(text.starts_with("setup: "), "{name}: {text}");
        assert!(!text.contains("Report: "), "{name}: {text}");
        assert!(!text.contains("Review: "), "{name}: {text}");
        assert_eq!(saved_line(&output), None, "{name}");
    }
}
