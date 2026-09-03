use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use siloscan_core::cache::content_hash;
use siloscan_core::serde_json::{self, Value};
use tempfile::TempDir;

const REFERENCE_COMMIT: &str = "880d211a463e97eb3c188f957e5592d88f36dcf8";
const CANDIDATE_SILOSCAN: &str = env!("CARGO_BIN_EXE_siloscan");
const CANDIDATE_SS: &str = env!("CARGO_BIN_EXE_ss");

struct ReferenceBuild {
    _temp: TempDir,
    siloscan: PathBuf,
    ss: PathBuf,
}

type JsonNormalizer = fn(&[u8]) -> Result<(Value, Vec<u8>), String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root should be readable")
}

fn oracle_root() -> PathBuf {
    repo_root().join("research/oracle-v1.5.1")
}

fn command_output(command: &mut Command, context: &str) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("{context}: {error}"))
}

fn checked_command(command: &mut Command, context: &str) -> Output {
    let output = command_output(command, context);
    assert!(
        output.status.success(),
        "{context} failed with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn build_reference(repo: &Path) -> ReferenceBuild {
    let object = format!("{REFERENCE_COMMIT}^{{commit}}");
    let common_dir_output = checked_command(
        Command::new("git").current_dir(repo).args([
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ]),
        "resolve Git common directory",
    );
    let common_dir = PathBuf::from(
        String::from_utf8(common_dir_output.stdout)
            .expect("Git common directory should be UTF-8")
            .trim(),
    );

    checked_command(
        Command::new("git")
            .arg("--git-dir")
            .arg(&common_dir)
            .args(["cat-file", "-e", &object]),
        "find the pinned v1.5.1 reference object; CI checkouts must include full history",
    );

    let temp = tempfile::tempdir().expect("reference temp dir should be creatable");
    let source = temp.path().join("reference");
    let target = temp.path().join("reference-target");
    let empty_hooks = temp.path().join("empty-hooks");
    fs::create_dir(&empty_hooks).expect("empty hooks directory should be creatable");

    checked_command(
        Command::new("git")
            .args([
                "clone",
                "--quiet",
                "--no-checkout",
                "--local",
                "--no-hardlinks",
                "--no-tags",
            ])
            .arg(&common_dir)
            .arg(&source),
        "clone the local reference object store",
    );
    checked_command(
        Command::new("git")
            .arg("-c")
            .arg(format!("core.hooksPath={}", empty_hooks.display()))
            .arg("-C")
            .arg(&source)
            .args(["checkout", "--detach", "--force", REFERENCE_COMMIT]),
        "check out the pinned v1.5.1 reference",
    );

    let head = checked_command(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["rev-parse", "HEAD"]),
        "read reference HEAD",
    );
    assert_eq!(
        String::from_utf8(head.stdout)
            .expect("reference HEAD should be UTF-8")
            .trim(),
        REFERENCE_COMMIT,
        "reference checkout moved"
    );

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let rustc_version =
        checked_command(Command::new(rustc).arg("-vV"), "read the host Rust target");
    let rustc_version =
        String::from_utf8(rustc_version.stdout).expect("rustc version output should be UTF-8");
    let host = rustc_version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc -vV should report its host target");

    checked_command(
        Command::new(env!("CARGO"))
            .env_remove("CARGO_BUILD_TARGET")
            .env_remove("CARGO_TARGET_DIR")
            .args([
                "build",
                "--locked",
                "--offline",
                "--release",
                "--manifest-path",
            ])
            .arg(source.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .args(["--target", host, "-p", "siloscan", "--bins"]),
        "build the pinned v1.5.1 reference offline",
    );

    let status = checked_command(
        Command::new("git").arg("-C").arg(&source).args([
            "status",
            "--porcelain",
            "--untracked-files=all",
        ]),
        "inspect the reference checkout",
    );
    assert!(
        status.stdout.is_empty(),
        "reference build modified its checkout:\n{}",
        String::from_utf8_lossy(&status.stdout)
    );

    let release = target.join(host).join("release");
    let siloscan = release.join(format!("siloscan{}", std::env::consts::EXE_SUFFIX));
    let ss = release.join(format!("ss{}", std::env::consts::EXE_SUFFIX));
    assert!(siloscan.is_file(), "missing {}", siloscan.display());
    assert!(ss.is_file(), "missing {}", ss.display());

    ReferenceBuild {
        _temp: temp,
        siloscan,
        ss,
    }
}

fn manifest_entries(path: &Path) -> Vec<(String, String)> {
    let manifest =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    manifest
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (digest, relative) = line.split_once("  ").unwrap_or_else(|| {
                panic!("{}:{} is not a sha256sum entry", path.display(), index + 1)
            });
            assert!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{}:{} has an invalid SHA-256 digest",
                path.display(),
                index + 1
            );
            Some((digest.to_ascii_lowercase(), relative.to_owned()))
        })
        .collect()
}

fn verify_manifest(root: &Path, manifest: &Path) -> Vec<String> {
    let entries = manifest_entries(manifest);
    for (expected, relative) in &entries {
        let path = root.join(relative);
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("read checksum input {}: {error}", path.display()));
        assert_eq!(
            content_hash(&bytes),
            *expected,
            "checksum mismatch for {}",
            path.display()
        );
    }
    entries.into_iter().map(|(_, path)| path).collect()
}

fn slash_path(path: &Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn collect_files(root: &Path, current: &Path, files: &mut BTreeSet<String>) {
    let entries = fs::read_dir(current)
        .unwrap_or_else(|error| panic!("read oracle directory {}: {error}", current.display()));
    for entry in entries {
        let path = entry
            .expect("oracle directory entry should be readable")
            .path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else if path.is_file() {
            files.insert(slash_path(
                path.strip_prefix(root)
                    .expect("oracle file should remain under its root"),
            ));
        } else {
            panic!("oracle contains a non-regular file: {}", path.display());
        }
    }
}

fn verify_oracle_bundle(oracle: &Path) {
    assert!(
        oracle.join("CAPTURES.sha256").is_file(),
        "frozen v1.5.1 oracle is missing at {}",
        oracle.display()
    );

    let captures = verify_manifest(oracle, &oracle.join("CAPTURES.sha256"));
    let mixed = verify_manifest(&oracle.join("mixed"), &oracle.join("mixed.manifest.sha256"));
    let inputs = verify_manifest(
        &oracle.join("inputs"),
        &oracle.join("inputs.manifest.sha256"),
    );

    let mut expected = BTreeSet::from(["CAPTURES.sha256".to_owned()]);
    expected.extend(captures);
    expected.extend(
        mixed
            .into_iter()
            .map(|path| format!("mixed/{}", path.trim_start_matches("./"))),
    );
    expected.extend(
        inputs
            .into_iter()
            .map(|path| format!("inputs/{}", path.trim_start_matches("./"))),
    );

    let mut actual = BTreeSet::new();
    collect_files(oracle, oracle, &mut actual);
    assert_eq!(
        actual, expected,
        "oracle import differs from the frozen file set"
    );
}

fn failure_dir(case: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("v2-oracle-harness")
        .join(case)
}

#[allow(clippy::too_many_arguments)]
fn fail_comparison(
    case: &str,
    expected_raw: &[u8],
    actual_raw: &[u8],
    expected_normalized: &[u8],
    actual_normalized: &[u8],
    actual_stderr: &[u8],
    status: Option<i32>,
    reason: &str,
) -> ! {
    let dir = failure_dir(case);
    fs::create_dir_all(&dir)
        .unwrap_or_else(|error| panic!("create failure artifact dir {}: {error}", dir.display()));
    fs::write(dir.join("expected.raw"), expected_raw).expect("write expected raw artifact");
    fs::write(dir.join("actual.raw"), actual_raw).expect("write actual raw artifact");
    fs::write(dir.join("expected.normalized"), expected_normalized)
        .expect("write expected normalized artifact");
    fs::write(dir.join("actual.normalized"), actual_normalized)
        .expect("write actual normalized artifact");
    fs::write(dir.join("actual.stderr"), actual_stderr).expect("write stderr artifact");
    fs::write(
        dir.join("result.txt"),
        format!("status={status:?}\nreason={reason}\n"),
    )
    .expect("write result artifact");

    let diff = command_output(
        Command::new("git")
            .args(["diff", "--no-index", "--text", "--no-ext-diff", "--"])
            .arg(dir.join("expected.raw"))
            .arg(dir.join("actual.raw")),
        "create raw oracle diff",
    );
    let mut diff_bytes = diff.stdout;
    diff_bytes.extend_from_slice(&diff.stderr);
    fs::write(dir.join("raw.diff"), diff_bytes).expect("write raw diff artifact");

    let diff = command_output(
        Command::new("git")
            .args(["diff", "--no-index", "--text", "--no-ext-diff", "--"])
            .arg(dir.join("expected.normalized"))
            .arg(dir.join("actual.normalized")),
        "create normalized oracle diff",
    );
    let mut normalized_diff = diff.stdout;
    normalized_diff.extend_from_slice(&diff.stderr);
    fs::write(dir.join("normalized.diff"), &normalized_diff)
        .expect("write normalized diff artifact");

    panic!(
        "{case}: {reason}; artifacts retained at {}\nnormalized diff:\n{}",
        dir.display(),
        String::from_utf8_lossy(&normalized_diff)
    );
}

fn assert_process(case: &str, output: &Output, expected_status: i32) {
    if output.status.code() != Some(expected_status) || !output.stderr.is_empty() {
        fail_comparison(
            case,
            &[],
            &output.stdout,
            &[],
            &output.stdout,
            &output.stderr,
            output.status.code(),
            &format!(
                "expected status {expected_status} and empty stderr, got {:?}",
                output.status.code()
            ),
        );
    }
}

fn normalize_text_line_endings(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"\r\n") {
            normalized.push(b'\n');
            index += 2;
        } else {
            normalized.push(bytes[index]);
            index += 1;
        }
    }
    normalized
}

fn assert_bytes(case: &str, expected: &[u8], output: &Output, expected_status: i32) {
    assert_process(case, output, expected_status);
    let expected_normalized = normalize_text_line_endings(expected);
    let actual_normalized = normalize_text_line_endings(&output.stdout);
    if actual_normalized != expected_normalized {
        fail_comparison(
            case,
            expected,
            &output.stdout,
            &expected_normalized,
            &actual_normalized,
            &output.stderr,
            output.status.code(),
            "stdout bytes differ",
        );
    }
}

fn normalize_report(bytes: &[u8]) -> Result<(Value, Vec<u8>), String> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if value.get("schema_version") != Some(&Value::String("1.2".to_owned())) {
        return Err("report schema_version is not 1.2".to_owned());
    }
    let object = value
        .as_object_mut()
        .ok_or_else(|| "report is not a JSON object".to_owned())?;
    if !object
        .remove("version")
        .is_some_and(|version| version.is_string())
    {
        return Err("report has no string product version".to_owned());
    }

    // The four resolved markers are the only fields a candidate report may add,
    // and they are removed rather than compared: a v2 scan report carries them
    // whether or not it was saved, and everything else in the document has to be
    // the reference's bytes.
    for marker in ["report_kind", "scope", "outcome", "setup"] {
        object.remove(marker);
    }

    let normalized = serde_json::to_vec_pretty(&value).expect("normalized report should serialize");
    Ok((value, normalized))
}

fn normalize_sarif(bytes: &[u8]) -> Result<(Value, Vec<u8>), String> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let driver = value
        .pointer_mut("/runs/0/tool/driver")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "SARIF tool driver is missing".to_owned())?;
    if !driver
        .remove("version")
        .is_some_and(|version| version.is_string())
    {
        return Err("SARIF tool driver has no string version".to_owned());
    }
    let normalized = serde_json::to_vec_pretty(&value).expect("normalized SARIF should serialize");
    Ok((value, normalized))
}

fn assert_json(
    case: &str,
    expected: &[u8],
    output: &Output,
    expected_status: i32,
    normalize: JsonNormalizer,
) -> Value {
    assert_process(case, output, expected_status);
    let expected_value = normalize(expected)
        .unwrap_or_else(|error| panic!("{case}: frozen expected document is invalid: {error}"));
    let actual_value = normalize(&output.stdout).unwrap_or_else(|error| {
        fail_comparison(
            case,
            expected,
            &output.stdout,
            &expected_value.1,
            &output.stdout,
            &output.stderr,
            output.status.code(),
            &format!("candidate document is invalid: {error}"),
        )
    });
    if actual_value.0 != expected_value.0 {
        fail_comparison(
            case,
            expected,
            &output.stdout,
            &expected_value.1,
            &actual_value.1,
            &output.stderr,
            output.status.code(),
            "normalized document differs",
        );
    }
    actual_value.0
}

fn assert_json_pair(
    case: &str,
    reference: &Output,
    candidate: &Output,
    expected_status: i32,
) -> Value {
    assert_process(&format!("{case}-reference"), reference, expected_status);
    assert_process(&format!("{case}-candidate"), candidate, expected_status);
    let expected = normalize_report(&reference.stdout)
        .unwrap_or_else(|error| panic!("{case}: reference report is invalid: {error}"));
    let actual = normalize_report(&candidate.stdout).unwrap_or_else(|error| {
        fail_comparison(
            case,
            &reference.stdout,
            &candidate.stdout,
            &expected.1,
            &candidate.stdout,
            &candidate.stderr,
            candidate.status.code(),
            &format!("candidate report is invalid: {error}"),
        )
    });
    if actual.0 != expected.0 {
        fail_comparison(
            case,
            &reference.stdout,
            &candidate.stdout,
            &expected.1,
            &actual.1,
            &candidate.stderr,
            candidate.status.code(),
            "candidate report differs from reference",
        );
    }
    actual.0
}

fn assert_stable(case: &str, first: &Output, second: &Output) {
    if first.stdout != second.stdout {
        fail_comparison(
            case,
            &first.stdout,
            &second.stdout,
            &first.stdout,
            &second.stdout,
            &second.stderr,
            second.status.code(),
            "repeated serialization is not byte-stable",
        );
    }
}

/// Two invocations that have to produce the same report, compared after the
/// resolved markers are removed.
///
/// A cached run and a `--no-cache` run describe different setups, and the
/// candidate's `setup` block says so - that is what it is for. The report they
/// produce is still one document, and that is what this asserts.
fn assert_stable_report(case: &str, first: &Output, second: &Output) {
    let expected = normalize_report(&first.stdout)
        .unwrap_or_else(|error| panic!("{case}: first document is invalid: {error}"));
    let actual = normalize_report(&second.stdout)
        .unwrap_or_else(|error| panic!("{case}: second document is invalid: {error}"));
    if expected.0 != actual.0 {
        fail_comparison(
            case,
            &first.stdout,
            &second.stdout,
            &expected.1,
            &actual.1,
            &second.stderr,
            second.status.code(),
            "the two invocations report different documents",
        );
    }
}

fn normalize_help(bytes: &[u8], binary_name: &str) -> Result<Vec<u8>, String> {
    let normalized = normalize_text_line_endings(bytes);
    let text = std::str::from_utf8(&normalized).map_err(|error| error.to_string())?;
    let windows_name = format!("{binary_name}.exe");
    let usage_name = format!("Usage: {windows_name}");
    let usage_continuation = format!("       {windows_name}");
    Ok(text
        .split('\n')
        .map(|line| {
            let line = line.trim_end_matches([' ', '\t']);
            if let Some(suffix) = line.strip_prefix(&usage_name)
                && (suffix.is_empty() || suffix.starts_with(' '))
            {
                return format!("Usage: {binary_name}{suffix}");
            }
            if let Some(suffix) = line.strip_prefix(&usage_continuation)
                && (suffix.is_empty() || suffix.starts_with(' '))
            {
                return format!("       {binary_name}{suffix}");
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes())
}

fn assert_help(
    case: &str,
    binary_name: &str,
    golden: &[u8],
    reference: &Output,
    candidate: &Output,
) {
    assert_process(&format!("{case}-reference"), reference, 0);
    assert_process(&format!("{case}-candidate"), candidate, 0);
    let golden = normalize_help(golden, binary_name)
        .unwrap_or_else(|error| panic!("{case}: invalid golden help: {error}"));
    let reference_help = normalize_help(&reference.stdout, binary_name)
        .unwrap_or_else(|error| panic!("{case}: invalid reference help: {error}"));
    if reference_help != golden {
        fail_comparison(
            &format!("{case}-reference"),
            &golden,
            &reference.stdout,
            &golden,
            &reference_help,
            &reference.stderr,
            reference.status.code(),
            "reference help differs from its capture",
        );
    }

    // The candidate's help may gain approved lines - the `review` subcommand and
    // the persistence controls - but it may not drop or reword one the frozen
    // surface documents. Every golden line must still be there, in order.
    let candidate_help = normalize_help(&candidate.stdout, binary_name)
        .unwrap_or_else(|error| panic!("{case}: invalid candidate help: {error}"));
    if let Some(dropped) = first_dropped_line(&golden, &candidate_help) {
        fail_comparison(
            &format!("{case}-candidate"),
            &golden,
            &candidate.stdout,
            &golden,
            &candidate_help,
            &candidate.stderr,
            candidate.status.code(),
            &format!("candidate help no longer documents {dropped:?}"),
        );
    }
}

/// The first line of `golden` that `candidate` does not carry, in order.
///
/// Additions are allowed anywhere; a removal, a reordering or a reworded line is
/// not, and this names the exact line that went missing.
fn first_dropped_line(golden: &[u8], candidate: &[u8]) -> Option<String> {
    let golden = String::from_utf8_lossy(golden);
    let candidate = String::from_utf8_lossy(candidate);
    let mut remaining = candidate.split('\n');
    for line in golden.split('\n') {
        if !remaining.any(|actual| actual == line) {
            return Some(line.to_owned());
        }
    }
    None
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) {
        let Ok(children) = fs::read_dir(path) else {
            return;
        };
        for child in children.flatten() {
            let path = child.path();
            if path.is_dir() {
                visit(&path, files);
            } else {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    visit(root, &mut files);
    files.sort();
    files
}

fn isolated_run(binary: &Path, args: &[OsString], cache: Option<&Path>) -> Output {
    let isolation = tempfile::tempdir().expect("invocation temp dir should be creatable");
    let default_cache = isolation.path().join("cache");
    let state = isolation.path().join("state");
    let platform_state = isolation.path().join("platform-state");
    let home = isolation.path().join("home");
    fs::create_dir_all(&default_cache).expect("cache root should be creatable");
    fs::create_dir_all(&state).expect("state root should be creatable");
    fs::create_dir_all(&platform_state).expect("platform state root should be creatable");
    fs::create_dir_all(&home).expect("home root should be creatable");

    let mut command = Command::new(binary);
    command.args(args);
    if let Some(cache) = cache {
        command.arg("--cache-dir").arg(cache);
    }
    let output = command_output(
        command
            .env("XDG_CACHE_HOME", &default_cache)
            .env("LOCALAPPDATA", &platform_state)
            .env("XDG_STATE_HOME", &state)
            .env("HOME", &home)
            .env("USERPROFILE", &home),
        &format!("run {}", binary.display()),
    );

    let unexpected_state = [&default_cache, &state, &platform_state, &home]
        .into_iter()
        .flat_map(|root| files_under(root))
        .collect::<Vec<_>>();
    assert!(
        unexpected_state.is_empty(),
        "explicit invocation wrote automatic state: {unexpected_state:?}"
    );
    output
}

fn mixed_args(oracle: &Path, format: &str, no_cache: bool) -> Vec<OsString> {
    let mut args = vec![
        oracle.join("mixed").into_os_string(),
        OsString::from("--rules"),
        oracle.join("inputs/rules").into_os_string(),
        OsString::from("--no-default-rules"),
        OsString::from("--coverage-report"),
        oracle.join("inputs/coverage.lcov").into_os_string(),
    ];
    if no_cache {
        args.push(OsString::from("--no-cache"));
    }
    args.extend([OsString::from("--format"), OsString::from(format)]);
    args
}

fn default_pack_args(oracle: &Path) -> Vec<OsString> {
    vec![
        oracle.join("default-pack").into_os_string(),
        OsString::from("--no-cache"),
        OsString::from("--format"),
        OsString::from("json"),
    ]
}

fn baseline_args(oracle: &Path, fixture: &Path) -> Vec<OsString> {
    vec![
        OsString::from("baseline"),
        fixture.as_os_str().to_owned(),
        OsString::from("--rules"),
        oracle.join("inputs/rules").into_os_string(),
        OsString::from("--no-default-rules"),
        OsString::from("--coverage-report"),
        oracle.join("inputs/coverage.lcov").into_os_string(),
        OsString::from("--no-cache"),
    ]
}

fn fixture_scan_args(oracle: &Path, fixture: &Path) -> Vec<OsString> {
    vec![
        fixture.as_os_str().to_owned(),
        OsString::from("--rules"),
        oracle.join("inputs/rules").into_os_string(),
        OsString::from("--no-default-rules"),
        OsString::from("--coverage-report"),
        oracle.join("inputs/coverage.lcov").into_os_string(),
        OsString::from("--no-cache"),
        OsString::from("--format"),
        OsString::from("json"),
    ]
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("create fixture copy {}: {error}", destination.display()));
    for entry in fs::read_dir(source)
        .unwrap_or_else(|error| panic!("read fixture source {}: {error}", source.display()))
    {
        let entry = entry.expect("fixture entry should be readable");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "copy fixture {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        }
    }
}

fn cache_entries(cache: &Path) -> Vec<PathBuf> {
    files_under(cache)
        .into_iter()
        .filter(|path| path.extension() == Some(OsStr::new("json")))
        .collect()
}

fn check_cli_inventory(oracle: &Path, reference: &ReferenceBuild) {
    let candidate_siloscan = Path::new(CANDIDATE_SILOSCAN);
    let candidate_ss = Path::new(CANDIDATE_SS);
    let binaries = [
        ("siloscan", reference.siloscan.as_path(), candidate_siloscan),
        ("ss", reference.ss.as_path(), candidate_ss),
    ];
    let help_commands: [(&str, &[&str]); 5] = [
        ("help", &["--help"]),
        ("baseline-help", &["baseline", "--help"]),
        ("test-help", &["test", "--help"]),
        ("cache-help", &["cache", "--help"]),
        ("cache-prune-help", &["cache", "prune", "--help"]),
    ];

    for (binary_name, reference_binary, candidate_binary) in binaries {
        for &(capture_name, raw_args) in &help_commands {
            let case = format!("{binary_name}-{capture_name}");
            let args: Vec<_> = raw_args.iter().map(|arg| OsString::from(*arg)).collect();
            let reference_output = isolated_run(reference_binary, &args, None);
            let candidate_output = isolated_run(candidate_binary, &args, None);
            let golden = fs::read(oracle.join("golden").join(format!("{case}.stdout")))
                .expect("help capture should be readable");
            assert_help(
                &case,
                binary_name,
                &golden,
                &reference_output,
                &candidate_output,
            );
        }
    }

    for (name, reference_binary, candidate_binary, capture) in [
        (
            "siloscan-version",
            reference.siloscan.as_path(),
            candidate_siloscan,
            "siloscan-version.stdout",
        ),
        (
            "ss-version",
            reference.ss.as_path(),
            candidate_ss,
            "ss-version.stdout",
        ),
    ] {
        let args = vec![OsString::from("--version")];
        let reference_output = isolated_run(reference_binary, &args, None);
        let candidate_output = isolated_run(candidate_binary, &args, None);
        let golden = fs::read(oracle.join("golden").join(capture))
            .expect("version capture should be readable");
        assert_bytes(&format!("{name}-reference"), &golden, &reference_output, 0);
        let expected_candidate = format!("siloscan {}\n", env!("CARGO_PKG_VERSION"));
        assert_bytes(
            &format!("{name}-candidate"),
            expected_candidate.as_bytes(),
            &candidate_output,
            0,
        );
    }
}

fn check_mixed_formats(oracle: &Path, reference: &ReferenceBuild) {
    let human = fs::read(oracle.join("golden/human.stdout")).expect("human golden should exist");
    let json = fs::read(oracle.join("golden/report.json")).expect("JSON golden should exist");
    let sarif =
        fs::read(oracle.join("golden/report.sarif.json")).expect("SARIF golden should exist");

    let human_args = mixed_args(oracle, "human", true);
    let reference_human = isolated_run(&reference.siloscan, &human_args, None);
    let candidate_human = isolated_run(Path::new(CANDIDATE_SILOSCAN), &human_args, None);
    assert_bytes("mixed-human-reference", &human, &reference_human, 1);
    assert_bytes("mixed-human-candidate", &human, &candidate_human, 1);

    let json_args = mixed_args(oracle, "json", true);
    let reference_json = isolated_run(&reference.siloscan, &json_args, None);
    let candidate_json = isolated_run(Path::new(CANDIDATE_SILOSCAN), &json_args, None);
    let candidate_json_repeat = isolated_run(Path::new(CANDIDATE_SILOSCAN), &json_args, None);
    assert_json(
        "mixed-json-reference",
        &json,
        &reference_json,
        1,
        normalize_report,
    );
    assert_json(
        "mixed-json-candidate",
        &json,
        &candidate_json,
        1,
        normalize_report,
    );
    assert_process("mixed-json-candidate-repeat", &candidate_json_repeat, 1);
    assert_stable(
        "mixed-json-candidate-stability",
        &candidate_json,
        &candidate_json_repeat,
    );

    let sarif_args = mixed_args(oracle, "sarif", true);
    let reference_sarif = isolated_run(&reference.siloscan, &sarif_args, None);
    let candidate_sarif = isolated_run(Path::new(CANDIDATE_SILOSCAN), &sarif_args, None);
    let candidate_sarif_repeat = isolated_run(Path::new(CANDIDATE_SILOSCAN), &sarif_args, None);
    assert_json(
        "mixed-sarif-reference",
        &sarif,
        &reference_sarif,
        1,
        normalize_sarif,
    );
    assert_json(
        "mixed-sarif-candidate",
        &sarif,
        &candidate_sarif,
        1,
        normalize_sarif,
    );
    assert_process("mixed-sarif-candidate-repeat", &candidate_sarif_repeat, 1);
    assert_stable(
        "mixed-sarif-candidate-stability",
        &candidate_sarif,
        &candidate_sarif_repeat,
    );
}

fn check_default_pack(oracle: &Path, reference: &ReferenceBuild) {
    let golden = fs::read(oracle.join("golden/default-pack.json"))
        .expect("default-pack golden should exist");
    let args = default_pack_args(oracle);
    let mut candidate_outputs = Vec::new();

    for (name, binary) in [
        (
            "default-pack-reference-siloscan",
            reference.siloscan.as_path(),
        ),
        ("default-pack-reference-ss", reference.ss.as_path()),
    ] {
        let output = isolated_run(binary, &args, None);
        assert_json(name, &golden, &output, 1, normalize_report);
    }
    for (name, binary) in [
        (
            "default-pack-candidate-siloscan",
            Path::new(CANDIDATE_SILOSCAN),
        ),
        ("default-pack-candidate-ss", Path::new(CANDIDATE_SS)),
    ] {
        let output = isolated_run(binary, &args, None);
        assert_json(name, &golden, &output, 1, normalize_report);
        candidate_outputs.push(output);
    }
    assert_stable(
        "default-pack-alias-stability",
        &candidate_outputs[0],
        &candidate_outputs[1],
    );
}

fn assert_partition(case: &str, output: &Output, new: usize, baselined: usize, suppressed: usize) {
    let parsed = normalize_report(&output.stdout)
        .unwrap_or_else(|error| panic!("{case}: invalid report: {error}"));
    let counts = [
        ("findings", new),
        ("baselined", baselined),
        ("suppressed", suppressed),
    ];
    for (field, expected) in counts {
        let actual = parsed.0[field].as_array().map(Vec::len);
        if actual != Some(expected) {
            let expected_summary =
                format!("findings={new}\nbaselined={baselined}\nsuppressed={suppressed}\n");
            fail_comparison(
                case,
                expected_summary.as_bytes(),
                &output.stdout,
                expected_summary.as_bytes(),
                &parsed.1,
                &output.stderr,
                output.status.code(),
                &format!("{field} count is {actual:?}, expected {expected}"),
            );
        }
    }
}

fn check_baseline_interop(oracle: &Path, reference: &ReferenceBuild) {
    let temp = tempfile::tempdir().expect("baseline temp dir should be creatable");
    let reference_fixture = temp.path().join("reference-baseline");
    let candidate_fixture = temp.path().join("candidate-baseline");
    copy_tree(&oracle.join("mixed"), &reference_fixture);
    copy_tree(&oracle.join("mixed"), &candidate_fixture);

    let reference_write = isolated_run(
        &reference.siloscan,
        &baseline_args(oracle, &reference_fixture),
        None,
    );
    assert_bytes(
        "baseline-write-reference",
        b"baseline written: 23 entries\n",
        &reference_write,
        0,
    );
    let candidate_write = isolated_run(
        Path::new(CANDIDATE_SILOSCAN),
        &baseline_args(oracle, &candidate_fixture),
        None,
    );
    assert_bytes(
        "baseline-write-candidate",
        b"baseline written: 23 entries\n",
        &candidate_write,
        0,
    );

    let golden =
        fs::read(oracle.join("golden/baseline.json")).expect("baseline golden should be readable");
    let reference_baseline = fs::read(reference_fixture.join(".siloscan/baseline.json"))
        .expect("reference baseline should be written");
    let candidate_baseline = fs::read(candidate_fixture.join(".siloscan/baseline.json"))
        .expect("candidate baseline should be written");
    if reference_baseline != golden {
        fail_comparison(
            "baseline-bytes-reference",
            &golden,
            &reference_baseline,
            &golden,
            &reference_baseline,
            &[],
            Some(0),
            "reference baseline differs from the frozen capture",
        );
    }
    if candidate_baseline != golden {
        fail_comparison(
            "baseline-bytes-candidate",
            &golden,
            &candidate_baseline,
            &golden,
            &candidate_baseline,
            &[],
            Some(0),
            "candidate baseline differs from the frozen capture",
        );
    }

    for (name, fixture) in [
        ("reference-baseline", reference_fixture.as_path()),
        ("candidate-baseline", candidate_fixture.as_path()),
    ] {
        let args = fixture_scan_args(oracle, fixture);
        let reference_scan = isolated_run(&reference.siloscan, &args, None);
        let candidate_scan = isolated_run(Path::new(CANDIDATE_SILOSCAN), &args, None);
        let report = assert_json_pair(
            &format!("baseline-cross-read-{name}"),
            &reference_scan,
            &candidate_scan,
            0,
        );
        assert_partition(
            &format!("baseline-partition-{name}"),
            &candidate_scan,
            0,
            23,
            1,
        );
        assert_eq!(report["findings"].as_array().map(Vec::len), Some(0));
    }

    let marker_path = reference_fixture.join("src/markers.txt");
    let markers = fs::read_to_string(&marker_path).expect("marker fixture should be readable");
    let changed = markers.replacen("ORACLE_REGEX\n", "\n", 1);
    assert_ne!(
        markers, changed,
        "marker fixture should contain the frozen marker"
    );
    fs::write(&marker_path, changed).expect("marker fixture should be mutable");
    fs::write(
        reference_fixture.join("src/moved-marker.txt"),
        "ORACLE_REGEX\n",
    )
    .expect("moved marker fixture should be writable");
    let args = fixture_scan_args(oracle, &reference_fixture);
    let reference_changed = isolated_run(&reference.siloscan, &args, None);
    let candidate_changed = isolated_run(Path::new(CANDIDATE_SILOSCAN), &args, None);
    let report = assert_json_pair(
        "baseline-one-changed-finding",
        &reference_changed,
        &candidate_changed,
        1,
    );
    assert_partition(
        "baseline-one-changed-partition",
        &candidate_changed,
        1,
        22,
        1,
    );
    assert_eq!(report["findings"][0]["rule_id"], "oracle.regex");
}

fn check_cache_modes(oracle: &Path, reference: &ReferenceBuild) {
    let golden = fs::read(oracle.join("golden/report.json")).expect("JSON golden should exist");
    let cached_args = mixed_args(oracle, "json", false);
    let uncached_args = mixed_args(oracle, "json", true);

    for (name, binary) in [
        ("reference", reference.siloscan.as_path()),
        ("candidate", Path::new(CANDIDATE_SILOSCAN)),
    ] {
        let cache = tempfile::tempdir().expect("cache temp dir should be creatable");
        let no_cache = tempfile::tempdir().expect("no-cache temp dir should be creatable");
        let cold = isolated_run(binary, &cached_args, Some(cache.path()));
        assert_json(
            &format!("cache-{name}-cold"),
            &golden,
            &cold,
            1,
            normalize_report,
        );
        let entries = cache_entries(cache.path());
        assert!(
            !entries.is_empty(),
            "{name} cold scan should populate the cache"
        );

        let warm = isolated_run(binary, &cached_args, Some(cache.path()));
        assert_json(
            &format!("cache-{name}-warm"),
            &golden,
            &warm,
            1,
            normalize_report,
        );
        assert_stable(&format!("cache-{name}-cold-warm"), &cold, &warm);
        assert_eq!(
            cache_entries(cache.path()),
            entries,
            "{name} warm scan changed the cache entry set"
        );

        let uncached = isolated_run(binary, &uncached_args, Some(no_cache.path()));
        assert_json(
            &format!("cache-{name}-disabled"),
            &golden,
            &uncached,
            1,
            normalize_report,
        );
        assert_stable_report(&format!("cache-{name}-disabled-output"), &cold, &uncached);
        assert!(
            files_under(no_cache.path()).is_empty(),
            "{name} --no-cache wrote cache files"
        );
    }
}

#[test]
fn explicit_v1_compatibility() {
    assert_eq!(
        normalize_help(
            b"Usage: siloscan.exe [OPTIONS]\r\n       siloscan.exe <COMMAND>\r\n",
            "siloscan",
        )
        .expect("Windows help sample should normalize"),
        b"Usage: siloscan [OPTIONS]\n       siloscan <COMMAND>\n"
    );

    let oracle = oracle_root();
    verify_oracle_bundle(&oracle);

    let reference = build_reference(&repo_root());
    check_cli_inventory(&oracle, &reference);
    check_mixed_formats(&oracle, &reference);
    check_default_pack(&oracle, &reference);
    check_baseline_interop(&oracle, &reference);
    check_cache_modes(&oracle, &reference);
}
