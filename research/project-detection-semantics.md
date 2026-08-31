# Deterministic project and workspace detection

- Status: recommended decision
- Date: 2026-08-31
- Compatibility oracle: `880d211a463e97eb3c188f957e5592d88f36dcf8`
- Wayfinder ticket: [Choose deterministic project and workspace detection semantics](https://github.com/RandomCodeSpace/siloscan/issues/59)

Security hardening is outside this decision.

## Decision

Keep the current file walker as the sole authority over scan scope. Run project detection over that same ordered inventory. Detection may add project units, setup metadata, source-root hints, capability explanations, and versioned embedded profiles. It must never remove a file, follow a path outside the scan root, or turn a partial project model into a clean result.

Use exact facts from declarative formats. Treat executable build formats as partial evidence unless a fact follows from the file's location alone. A malformed or partly dynamic setup produces a visible diagnostic and the generic scan still runs.

This is the smallest contract that improves the no-argument journey without sacrificing v1.5.1 behavior. It also leaves no reason to introduce a plugin system or run a project tool.

## Why this boundary fits Siloscan

The pinned CLI defaults `PATH` to `.` and passes that path through configuration, baseline, cache, walk, and report handling. An explicit path therefore owns more than discovery. It owns fingerprints and state identity too. [The current CLI contract](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan/src/main.rs#L165-L169) and [scan pipeline](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan/src/main.rs#L422-L471) make automatic root promotion a compatibility break, not a convenience.

Configuration already has a deliberate, bounded ancestor search. It accepts a config in the scan root, and it adopts an ancestor only inside a repository identified by `.git`. Without that boundary, an unrelated file in a parent directory could change a scan. [Config discovery contract](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/config.rs#L1-L30) and [implementation](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/config.rs#L214-L256).

The walker already provides the useful invariant. It honors only in-root ignore files by default, stays inside the scan root, reports ignored and skipped work, and sorts paths bytewise after collection. [Walker boundary and ordering](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/walk.rs#L1-L63), [single collected inventory](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/walk.rs#L620-L678), and [bytewise sort](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/walk.rs#L1044-L1049).

Project detection should inherit those rules rather than perform a second recursive search. One inventory prevents ignored dependencies, generated trees, symlink targets, and worker order from changing the project model independently of the scan.

## Scan root and ownership

The scan root stays simple:

- An explicit `PATH` is the scan root exactly as it is in v1.5.1.
- An omitted `PATH` means the current directory, exactly as it does today.
- Detection does not promote either form to a Git root, workspace root, manifest directory, or common ancestor.
- A single-file scan remains a single-file scan. It gets language facts and the generic profile, but no invented workspace.
- Project manifests above the scan root are not read. Existing `siloscan.toml` discovery is the only bounded ancestor lookup.

This means a user who wants the whole repository runs `siloscan` at its root. Running inside `services/api` scans `services/api`. The report must print the selected scan root so the scope is not left to inference.

Within that boundary, ownership is plural:

- A project unit is identified by ecosystem, normalized unit root, and primary evidence path.
- A workspace is a relation between units. It is not a replacement scan root.
- Every valid unclaimed nested manifest remains a standalone unit. A missing workspace declaration must not make real code disappear from the model.
- A unit may belong to more than one grouping, such as a C# project listed by two solution files.
- A directory may contain units from several ecosystems. There is no primary-language election.

## Precedence

Apply inputs in this order:

1. Explicit CLI inputs retain their current meaning. This includes `PATH`, `--config`, `--rules`, `--no-default-rules`, coverage input, cache options, ignore options, symlink handling, severity thresholds, and output format.
2. Load and validate `siloscan.toml` with the current discovery, ownership, include, anchoring, and error rules. A malformed Siloscan config remains fatal.
3. Detect project facts from the files the walk admitted.
4. Fill only facts that no stronger input supplied.
5. Run the generic fallback whether detection is complete, partial, invalid, or empty.

Detection must not reinterpret existing configuration defaults. In particular:

- Configured `source_roots`, including the current empty value that means repository root only, continue to control boundary resolution. Detected roots are report facts and profile hints, not an implicit rewrite of `Config`.
- Configured silos, rules, duplication settings, limits, and anchor remain authoritative.
- `--no-default-rules` disables every embedded default, including a project profile.
- Explicit and configured rule directories keep their current load order and duplicate-id failure behavior.
- A detected profile is additive to the built-in pack. It cannot disable or weaken a current rule, metric, baseline, suppression, cache entry, or report field.

The auto journey may select detected embedded profiles when the positional path is omitted. `siloscan PATH` remains the compatibility form for existing explicit scans. Detection metadata itself is safe to include in both forms because it does not change findings.

The pinned config accepts `languages` mappings, but the current language detector does not consume them. [Accepted config field](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/config.rs#L140-L155) and [hard-coded runtime detector](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/lang.rs#L3-L26). Detection must not hide that mismatch by treating the mapping as active. The owning compatibility decision must either route valid mappings into runtime detection or reject the key. Once that contract works, an explicit mapping takes precedence over an inferred language.

## Common detector contract

Every detector receives the scan root and the walk's sorted file inventory. It returns facts only. It does not perform its own filesystem traversal.

Each evidence record contains:

- ecosystem and evidence kind;
- normalized scan-root-relative path using `/` separators;
- status: `complete`, `partial`, or `invalid`;
- parser or rule version;
- facts accepted from the file;
- a reason for every fact it could not resolve.

Each unit and workspace relation cites its evidence record. Guesses without provenance do not enter the resolved scan plan.

The parser rules are shared:

- Read only inventory files that match exact supported names or suffixes.
- Apply the existing parse-size limit. Oversized evidence is `partial`, not absent.
- Require valid UTF-8 where the format requires text.
- Use strict TOML, JSON, and XML parsing through the crates already present in `siloscan-core`.
- Parse the small line-oriented Go and `.sln` grammars directly.
- Never evaluate Groovy, Kotlin, CMake, Ruby, Python, MSBuild targets, shell, or package scripts.
- Resolve relative paths against the declaring file.
- Reject absolute paths and every normalized path that leaves the scan root.
- Resolve workspace members only against candidate manifests already present in the walk inventory.
- Preserve raw declarations and declaration indices as evidence.
- Sort final evidence, units, roots, and relations by normalized path, then ecosystem, then evidence kind. Declaration order remains separate metadata where a project tool gives it meaning.

Workspace patterns use one documented Siloscan subset across Cargo, npm, and uv: literal relative paths plus `*` and `?` within a path segment. Match against normalized candidate unit directories. Sort matches within each pattern, retain the first declaration index while deduplicating, and mark `**`, character classes, braces, variables, and other dialect-specific syntax `partial`. Recursive manifest discovery still finds those units as standalone units, so the unsupported grouping syntax cannot reduce scan coverage.

## Evidence matrix

| Ecosystem | Primary evidence | Exact workspace facts | Safe source-root facts | Facts Siloscan refuses to claim |
| --- | --- | --- | --- | --- |
| Rust | `Cargo.toml` with `[package]` or `[workspace]` | Root package, supported `members` and `exclude` patterns, in-root literal path dependencies, literal `package.workspace` | Package root, existing conventional `src`, parent of literal target paths | Cargo's complete effective graph when unsupported globs or external paths participate |
| Go | Strict `go.mod`; strict `go.work` | Direct `use` entries only; each nested `go.mod` is otherwise an independent module | Directory containing `go.mod` | Environment-selected `GOWORK`, downloaded modules, replacements outside the scan root |
| JavaScript and TypeScript | Valid object `package.json`; TS/JS files from current language detection; `tsconfig.json` and `jsconfig.json` as partial setup evidence | Supported npm `workspaces` entries | Package directory as structural root; no TS compiler root inferred in launch contract | Published `files` as scan filter, scripts, dependency installs, exact TS project references without a JSONC parser |
| Python | `pyproject.toml` with `[project]` or `[build-system]`; readable legacy `setup.py` or `setup.cfg` as partial evidence | Static `[tool.uv.workspace]` members and excludes | Unit root; existing `src` is a conventional hint only | A universal Python workspace, backend-specific package discovery, executable `setup.py` results |
| Java and Maven | Well-formed `pom.xml` with Maven model root | Unconditional literal `<modules>` entries | Literal in-root build source directories, otherwise existing Maven conventional roots | Activated profiles, fetched parents, plugin effects, unresolved properties |
| Java and Gradle | `settings.gradle(.kts)` and `build.gradle(.kts)` | None claimed from script contents; nested build scripts remain discovered partial units | Existing Java plugin conventional roots as hints | Exact subprojects, composites, remaps, source sets, or plugin effects without running Gradle |
| C and C++ | `CMakeLists.txt`; C/C++ files from current language detection | Nested CMake files are partial units, not proven `add_subdirectory` members | No exact root from CMake script; unit directory is a hint | Configured targets, conditional subdirectories, variables, generator expressions, includes, compiler database state |
| C# and .NET | Well-formed `.csproj`; valid `.sln` or `.slnx` | Literal in-root project paths listed by solutions | SDK-style project directory under default compile items | Effective MSBuild after imports, properties, conditions, SDK logic, environment, or custom item evaluation |
| Ruby | Readable `Gemfile` and `.gemspec` files | Every in-root gemspec is a unit; no exact workspace relation from Ruby code | Existing `lib` under a gem is a conventional hint | Evaluated Gemfile, gemspec, `eval_gemfile`, path blocks, computed file lists, custom `require_paths` |

Lockfiles and tool selectors attach setup metadata only after primary evidence exists. `Cargo.lock`, `go.sum`, `go.work.sum`, npm-family lockfiles, Python lockfiles, Maven and Gradle wrappers, `CMakePresets.json`, `global.json`, and `Gemfile.lock` never create a unit or expand scan scope by themselves.

## Ecosystem details

### Rust and Cargo

Cargo defines a package or workspace through `Cargo.toml`. A workspace may contain a root package or use a virtual manifest. Its root manifest declares `members`, `exclude`, and `default-members`; `default-members` is a command-selection default, not the complete workspace. [Cargo workspace reference](https://doc.rust-lang.org/cargo/reference/workspaces.html).

Parse each candidate with the existing TOML crate. Count it as Rust project evidence only when it has `[package]` or `[workspace]`. Expand the supported `members` and `exclude` pattern subset against valid in-inventory Cargo package directories. Add a root package when `[package]` and `[workspace]` coexist. Add in-root literal path dependencies and literal `package.workspace` relations when their target manifest is also in the inventory. Unsupported or external relations make the workspace partial but do not invalidate its already proven members.

Cargo target paths are relative to the package manifest. Cargo otherwise discovers conventional targets such as `src/lib.rs`, `src/main.rs`, and `src/bin`. [Cargo target reference](https://doc.rust-lang.org/cargo/reference/cargo-targets.html). Record the parent of an existing literal target path as declared evidence. Record `src` only when it exists and the relevant auto-discovery switch is not false. Neither root filters the scan.

### Go

Go defines a module root as the directory containing `go.mod`. A `go.work` file declares a workspace through direct `use` entries, and each entry names one module directory rather than recursively adding nested modules. [Go modules and workspace reference](https://go.dev/ref/mod).

Strictly parse one `module` directive per `go.mod` and the required `go` directive plus `use` blocks in `go.work`. Do not inspect `GOWORK`; ambient environment must not select a different workspace. Resolve only in-root `use` paths whose `go.mod` appears in the inventory. Discover every other valid in-root `go.mod` as an independent module.

The module directory is both unit root and source-root fact. Package directories remain a result of the existing file inventory and language detection. No `go list`, module download, replacement lookup, or VCS access occurs.

### JavaScript and TypeScript

Node defines a package as the tree rooted at a directory containing `package.json`, stopping at another package or `node_modules` boundary. The nearest `package.json` also controls the module interpretation of `.js` through its `type` field. [Node package reference](https://nodejs.org/api/packages.html). npm defines local workspaces in the root package's `workspaces` property, and npm command order follows declaration order. [npm workspace reference](https://docs.npmjs.com/cli/using-npm/workspaces/).

Require `package.json` to parse as a JSON object. `name` and `version` are metadata, not validity gates for a private application. Expand array-valued workspace entries with the common pattern subset. Preserve npm's declaration index, but use normalized path order in the Siloscan report.

Do not use `main`, `exports`, or npm's `files` field to limit the scan. They describe runtime or publication entry points, not every file worth scanning.

The current scanner already detects JavaScript and TypeScript from file extensions and supports both grammars. [Language detection](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/lang.rs#L3-L26) and [available parsers](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/parsers.rs#L3-L42). A `tsconfig.json` marks a TypeScript project root, but its inheritance and input rules need TypeScript-compatible JSON-with-comments parsing. [TypeScript project configuration](https://www.typescriptlang.org/docs/handbook/tsconfig-json.html). The launch detector records the file as partial setup evidence and uses actual `.ts` and `.tsx` inventory files for the language fact. It does not hand-write a partial JSONC parser or pretend strict JSON is compatible.

### Python

The standard `pyproject.toml` format defines `[build-system]`, `[project]`, and tool-owned tables. A file may legitimately contain tool configuration without describing a package. [Python `pyproject.toml` specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/).

Parse it as TOML. Confirm a Python package unit when `[project]` or `[build-system]` exists. A tool-only document is setup evidence, not proof of a distributable package. The standard format has no universal workspace or source-root field. Keep the unit directory as the structural root. Record an existing `src` containing Python files as a conventional hint, never a filter.

Support uv's static `[tool.uv.workspace]` member and exclude arrays with the common pattern subset. Each resolved member must contain an in-inventory `pyproject.toml`; the root remains a member. [uv workspace reference](https://docs.astral.sh/uv/concepts/projects/workspaces/). Do not infer Poetry, PDM, Hatch, or other backend semantics from unrelated keys in the first contract.

`setup.py` and `setup.cfg` remain valid legacy configuration, but `setup.py` is executable Python and neither file belongs to the standard `pyproject.toml` schema. [Python packaging migration guidance](https://packaging.python.org/en/latest/guides/modernize-setup-py-project/). Their readable presence may mark a partial legacy unit. Never import or run them. Actual `.py` inventory files keep language detection useful when the package model is partial.

### Java, Maven, and Gradle

Maven uses `pom.xml`. An aggregator lists modules as paths relative to the aggregator directory, and profiles may add other modules. The POM also permits environment and other properties. [Maven POM reference](https://maven.apache.org/pom.html). Parse the XML and accept only unconditional literal `<modules>` entries that resolve to in-inventory POMs. A property, profile-controlled module, external parent, or outside path makes the relation partial. It does not erase the unit.

Maven's conventional Java roots are `src/main/java` and `src/test/java`, and the POM can override them. [Maven standard layout](https://maven.apache.org/guides/introduction/introduction-to-the-standard-directory-layout). Accept direct literal in-root `<sourceDirectory>` and `<testSourceDirectory>` values. Otherwise record existing conventional roots as hints.

Gradle's root marker is `settings.gradle` or `settings.gradle.kts`; a settings file is optional for a single-project build and required for a multi-project build. [Gradle settings reference](https://docs.gradle.org/current/userguide/settings_file_basics.html). These files are Groovy or Kotlin scripts that Gradle evaluates, and build scripts execute statements against Gradle objects. [Gradle build-script reference](https://docs.gradle.org/current/userguide/writing_build_scripts.html). A literal `include("api")` inside a false branch is still text. Static extraction would call it a project when Gradle would not.

Record settings and build scripts as partial evidence. Treat each in-inventory build-script directory as a partial unit and group nested units under the nearest settings directory only as a containment hint. Do not claim exact `include`, `projectDir`, `includeBuild`, source-set, or plugin results. Existing `src/main/java` and `src/test/java` directories may be conventional hints. Maven and Gradle evidence may coexist; detection must report both.

### C and C++

C and C++ have no single project manifest. The launch profile recognizes CMake and always retains extension-based language detection for other build systems.

CMake's top-level entry point is `CMakeLists.txt`, and `add_subdirectory` causes another `CMakeLists.txt` to be processed. [CMake language reference](https://cmake.org/cmake/help/latest/manual/cmake-language.7.html) and [`add_subdirectory` reference](https://cmake.org/cmake/help/latest/command/add_subdirectory.html). CMake is a programming language with variables, conditions, loops, functions, macros, includes, and environment references. Do not derive an exact target graph or workspace membership from its text.

Record every in-inventory `CMakeLists.txt` directory as a partial CMake unit. A nearest-ancestor CMake relation is a containment hint, not proof that `add_subdirectory` executed. Actual `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hh`, and `.hpp` files drive language facts through the current detector. `compile_commands.json` and CMake presets may attach setup metadata if already in inventory, but neither establishes a root or adds files.

### C# and .NET

.NET project files such as `.csproj` use MSBuild XML. Solution files `.sln` and `.slnx` list projects. Microsoft's `.slnx` schema stores paths in `Project` elements, and `dotnet sln` operates on both formats. [Microsoft `.slnx` schema](https://github.com/microsoft/vs-solutionpersistence/blob/main/src/Microsoft.VisualStudio.SolutionPersistence/Serializer/Xml/Slnx.xsd) and [`dotnet sln` reference](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-sln).

Require `.csproj` to be well-formed XML with a `Project` root. Parse relative `.csproj` paths from valid solution files and resolve only in-inventory projects. A project remains an independent unit when no solution lists it. Multiple solutions may cite the same unit.

SDK-style projects include `**/*.cs` by default and exclude normal project metadata plus `bin` and `obj`; projects can disable or alter those items. [.NET SDK project defaults](https://learn.microsoft.com/en-us/dotnet/core/project-sdk/overview). Record the project directory as a conventional source-root hint only when the file declares an SDK and does not statically disable default compile items.

MSBuild combines imports, properties, conditions, environment values, and SDK logic during evaluation. [MSBuild evaluation reference](https://learn.microsoft.com/en-us/visualstudio/msbuild/build-process-overview). Do not claim the effective item graph, imported `Directory.Build.*` behavior, or condition results. Never run `dotnet` or MSBuild.

### Ruby

A gemspec describes a gem and a Gemfile describes an application's dependency environment. [RubyGems Gemfile and gemspec guide](https://guides.rubygems.org/gemfile-and-gemspec/). Both are Ruby code. Bundler explicitly evaluates Gemfile as Ruby, and gemspecs can compute their file lists. [Bundler Gemfile reference](https://guides.rubygems.org/gemfile/) and [RubyGems specification reference](https://guides.rubygems.org/specification-reference/).

Never evaluate either file. Every readable in-inventory `.gemspec` identifies a partial gem unit at its directory. A Gemfile directory with no gemspec identifies a partial application unit. A root Gemfile and nested gemspecs are a containment hint, not a proven workspace relation. RubyGems documents `lib` as the conventional gem code directory, so an existing `lib` may be recorded as a hint. [RubyGems project layout](https://guides.rubygems.org/creating_gem/).

Ruby monorepos commonly wire local gems through path sources in a shared Gemfile. Those calls remain arbitrary Ruby and must not be interpreted as exact membership. Recursive bounded discovery finds the gemspecs without running them. [RubyGems monorepo guide](https://guides.rubygems.org/monorepo/).

## Mixed repositories

A mixed repository produces a union, not a winner:

- Aggregate languages from every admitted text file using current `lang::detect` behavior.
- Build each ecosystem's units independently.
- Add workspace relations only where evidence proves them.
- Stable-dedupe source-root hints by normalized path while preserving all provenance.
- Select every applicable low-noise embedded profile. Profile rule IDs must be globally unique at build time.
- Scan every file once through the existing engines. A file may contribute to several project units, but it does not get scanned once per unit.

If a root contains `Cargo.toml`, `package.json`, and `pyproject.toml`, the report says Rust, JavaScript or TypeScript, and Python. Choosing one as primary would hide setup rather than detect it.

## Malformed and unresolved evidence

Project detection errors are report data, not scan failure, with one exception: existing `siloscan.toml` errors retain their current fatal behavior.

For other evidence:

- A syntax error is `invalid` and includes the evidence path plus a bounded parser message.
- A valid file with dynamic or unsupported structure is `partial` and names the unresolved field or construct.
- A referenced member outside the scan root is recorded as refused and never read.
- A referenced member absent from the walk inventory is unresolved. Detection does not bypass ignore rules to open it.
- An unreadable, non-UTF-8, binary, or oversized evidence file follows existing skipped-file reporting and leaves the detector partial.
- One bad manifest does not invalidate unrelated manifests or ecosystems.
- No valid project evidence means `generic`, not `clean` and not an error.

The human summary should say, for example, `Detected Rust workspace (3 units); Gradle setup partial (script evaluation disabled); 1 invalid package.json; generic scan still applied.` JSON records the same states without relying on prose.

## Generic fallback

Generic fallback is unconditional:

- Keep the current embedded default pack.
- Keep current file-language detection, all six engines, all available AST grammars, metrics, baselines, suppressions, cache behavior, output formats, and exit codes.
- Run duplication and other current always-on metrics exactly once.
- Do not require a manifest for scanning.
- Do not lower severity, exclude directories, or suppress findings because a detector is partial.
- Report which project-aware capabilities were enabled, skipped, unavailable, or not configured, with a reason for every non-enabled state.

This gives a plain source tree, an old Make project, a malformed monorepo, and a fully declared workspace the same minimum scan they receive today. Better project evidence can add checks. Bad evidence cannot subtract them.

## Explicit refusal list

The detector does not:

- run Cargo, Go, npm, Node, Python, Maven, Gradle, CMake, compilers, `dotnet`, MSBuild, Ruby, Bundler, Git, repository scripts, wrappers, or tests;
- inspect installed SDKs, package caches, environment-selected workspaces, global configuration, IDE state, or shell state;
- access the network;
- read a workspace member or imported config outside the scan root;
- infer architecture silos, coverage thresholds, baselines, suppressions, organization policy, or generated-code exclusions;
- treat dependency, publication, target, solution-filter, or source-set declarations as scan allowlists;
- choose one ecosystem for a polyglot repository;
- make a scripted build model look complete through regex extraction;
- add a plugin framework for nine fixed launch detectors.

## Implementation shape

One `project` module in `siloscan-core` is sufficient. It owns a fixed detector table, evidence records, unit records, workspace relations, normalized path helpers, and deterministic merge logic.

Reuse current dependencies:

- `toml` for Cargo, Python, and uv;
- `serde_json` for `package.json` and optional setup metadata;
- `roxmltree` for Maven, `.csproj`, and `.slnx`;
- the current walker inventory, language detector, and `globset` machinery;
- small direct parsers for `go.mod`, `go.work`, and `.sln`.

Do not add a crate, interpreter, subprocess layer, plugin registry, package-manager adapter, or second walker for this contract. JSONC-backed TypeScript project references can be a later detector extension after a dependency decision; they are not worth a hand-written parser in the launch path.

## Acceptance cases

The implementation plan should require fixtures that prove these outcomes:

| Fixture | Required result |
| --- | --- |
| Explicit `siloscan services/api` from a larger repository | Scan root and admitted file set match v1.5.1; no ancestor promotion |
| `siloscan` from repository root | Current directory remains scan root; detected units and profiles are explained |
| Rust workspace using `crates/*` plus an exclusion | Members resolve in normalized path order; excluded crate remains scanned and may appear as a standalone unit |
| `go.work` with one in-root and one outside `use` | In-root module grouped; outside entry refused and unread |
| npm workspaces in declaration order with multiple matches | Declaration indices preserved; final units sorted by normalized path |
| Tool-only `pyproject.toml` plus Python files | Python language detected; tooling evidence recorded; no package falsely confirmed |
| Maven aggregator with a profile-only module | Unconditional units resolved; workspace marked partial; all files scanned |
| Gradle script with conditional `include` | Gradle evidence partial; no false exact member claim; generic scan runs |
| CMake file with variables and conditional subdirectories | CMake evidence partial; C/C++ files still detected and scanned |
| SDK and non-SDK C# projects in two solutions | Projects deduplicated; both solution relations retained; source-root hints carry provenance |
| Ruby Gemfile with computed path sources | Gemfile and nested gemspecs detected; workspace relation stays partial; no Ruby executed |
| Malformed package manifest beside valid Cargo and Go manifests | Invalid evidence visible; valid units retained; generic scan and findings unchanged |
| Ignored nested manifest | It does not enter the project model because it is absent from the scan inventory |
| Same fixture under repeated worker scheduling | Byte-identical normalized project-plan JSON |
| Explicit config with empty `source_roots` | Boundary resolution remains repository-root-only; detected hints do not rewrite it |
| Explicit `--no-default-rules` | Generic and detected embedded profiles are both disabled as requested |

The compatibility test should compare the v1.5.1 oracle and v2 explicit-path run for admitted paths, findings, fingerprints, baselined and suppressed partitions, metrics, skipped and ignored accounting, exit code, JSON, and SARIF. Project metadata may be added to versioned output, but existing fields cannot drift.

## Final recommendation

Implement fixed, additive detectors in Rust over the existing walk inventory. Keep the scan root untouched. Parse declarative facts strictly, label dynamic build formats partial, preserve all ecosystems in mixed repositories, and always run the generic scan.

That route makes `siloscan` more useful when project evidence is good and no less useful when the repository is unusual, old, malformed, or deliberately clever. The alternative, pretending every build language is a manifest, would make the report look smarter while making it less true.
