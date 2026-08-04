//! Enumerating the files a scan reads, and reading them.
//!
//! # Which ignore sources a scan consults
//!
//! A scan must be a function of the tree it was pointed at. Anything else means
//! two machines scanning the same commit can disagree about whether a secret is
//! there, and the disagreement is silent: an ignored file produces no finding
//! and no skipped-file record, so the report says "clean" rather than "did not
//! look". [`IgnoreOptions`] makes every ignore source an explicit, named
//! decision instead of an inherited default.
//!
//! ## Deliberate behavior change (1.1.2)
//!
//! Up to 1.1.1 the walker enabled the `ignore` crate's standard filters, which
//! turned on *every* ignore source git knows. Three of them read files outside
//! the scan root, and each could erase findings with no trace in the report:
//!
//! - a `.gitignore` in any *parent* directory of the scan root,
//! - `.git/info/exclude`, which is untracked and so invisible to review,
//! - git's global `core.excludesFile`, which belongs to whoever invoked the
//!   scan, not to the repository being scanned.
//!
//! All three now default to **off** ([`IgnoreOptions::respect_parent_ignores`],
//! [`IgnoreOptions::respect_git_exclude`],
//! [`IgnoreOptions::respect_global_gitignore`]). A scan is therefore
//! self-contained: it depends on the scan root's contents and nothing above or
//! outside it, and the same tree scanned in CI, in a container, and on a
//! developer's laptop yields the same files.
//!
//! Consequence worth stating plainly: a repository that relied on a parent
//! `.gitignore` or on `.git/info/exclude` to keep files out of a scan will see
//! those files scanned from 1.1.2 on, and may see new findings. That is the
//! point - those findings were always there. Callers that want the old,
//! environment-dependent behavior can opt back into each source individually.
//!
//! Ignore files *inside* the scan root are unchanged: `.gitignore` and
//! `.ignore` are still honored by default, because they are part of the tree
//! under review. [`IgnoreOptions::respect_gitignore`] and
//! [`IgnoreOptions::respect_dot_ignore`] exist so a caller can turn even those
//! off - a one-line `.gitignore` must not be able to hide a live secret with no
//! way to look past it - and [`IgnoreOptions::all_files`] turns off the lot.
//!
//! Walk order is unaffected by any of this: results are sorted bytewise by
//! path after collection.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

pub enum FileKind {
    Text(String),
    Binary,
    Unreadable(String),
}

/// Version-control internals, excluded by name at every depth.
///
/// Hidden files are scanned, so nothing else keeps the walker out of `.git`,
/// and a repository's object store is thousands of files with no source in
/// them. A submodule or worktree checkout has `.git` as a file rather than a
/// directory, so the name is matched regardless of entry type.
///
/// `.jj` and `.bzr` are here for the same reason: a jujutsu repository
/// colocated with git keeps a second object store under `.jj`, and scanning it
/// would double the walk over content that is not source.
const VCS_DIR_NAMES: [&str; 5] = [".git", ".hg", ".svn", ".jj", ".bzr"];

/// siloscan's own state directory, excluded for the same reason.
///
/// It holds the cache and the baseline, and it appears - along with the
/// `.gitignore` marker written beside the cache - only after a scan has run.
/// Scanning it would make a warm run's output differ from a cold run's, which
/// is exactly the determinism the tool promises not to break.
const STATE_DIR_NAME: &str = ".siloscan";

fn is_excluded_name(name: &OsStr) -> bool {
    name == OsStr::new(STATE_DIR_NAME) || VCS_DIR_NAMES.iter().any(|vcs| name == OsStr::new(vcs))
}

/// Which ignore sources a walk consults.
///
/// Every field is a decision about whether some file may remove other files
/// from the scan. See the [module docs](self) for why the defaults are what
/// they are; the short version is that a scan depends on the scan root and
/// nothing above or outside it.
///
/// [`Default`] is the shipped behavior. Constructing this struct literally is
/// deliberate: adding a field is a breaking change for anyone who did, which is
/// the right amount of friction for "a new way to not scan something".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgnoreOptions {
    /// Honor `.gitignore` files found inside the scan root. Default `true`.
    pub respect_gitignore: bool,
    /// Honor `.ignore` files found inside the scan root. Default `true`.
    ///
    /// Same format as `.gitignore`, understood by ripgrep and friends. It is
    /// separate from `respect_gitignore` only so that turning off one does not
    /// silently leave the other hiding files.
    pub respect_dot_ignore: bool,
    /// Honor git's global `core.excludesFile`. Default `false`.
    ///
    /// That file belongs to whoever invoked the scan, not to the repository
    /// under review, so honoring it makes results differ between machines
    /// scanning the same commit.
    pub respect_global_gitignore: bool,
    /// Honor ignore files in directories *above* the scan root. Default
    /// `false`.
    ///
    /// A file outside the tree siloscan was told to scan must not be able to
    /// remove findings from inside it.
    pub respect_parent_ignores: bool,
    /// Honor `<root>/.git/info/exclude`. Default `false`.
    ///
    /// It is untracked, so it never appears in review, and it is per-clone, so
    /// it is not part of the repository's own definition of what to skip.
    pub respect_git_exclude: bool,
}

impl Default for IgnoreOptions {
    fn default() -> Self {
        IgnoreOptions {
            respect_gitignore: true,
            respect_dot_ignore: true,
            respect_global_gitignore: false,
            respect_parent_ignores: false,
            respect_git_exclude: false,
        }
    }
}

impl IgnoreOptions {
    /// Every ignore source off: nothing but the walker's own exclusions
    /// (version-control internals, siloscan's state directory) keeps a file out
    /// of the scan.
    ///
    /// This is what a `--no-ignore` style flag wants. It does not re-enable the
    /// out-of-root sources - "scan everything under the root" is not a reason
    /// to start reading files above it.
    pub fn all_files() -> Self {
        IgnoreOptions {
            respect_gitignore: false,
            respect_dot_ignore: false,
            respect_global_gitignore: false,
            respect_parent_ignores: false,
            respect_git_exclude: false,
        }
    }
}

/// Walk root directory using the ignore crate, with the default
/// [`IgnoreOptions`].
///
/// Equivalent to [`collect_files_with`] passing `&IgnoreOptions::default()`.
pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    collect_files_with(root, &IgnoreOptions::default())
}

/// Walk root directory using the ignore crate: honors the ignore sources
/// `opts` selects, scans hidden files and directories, excludes version-control
/// internals (`.git`, `.hg`, `.svn`, `.jj`, `.bzr`) and siloscan's own
/// `.siloscan` state directory anywhere below the scan root.
/// Files only, sorted bytewise by path, walk errors silently skipped.
///
/// hidden(false): dotfiles carry secrets as often as any other file - `.env`,
/// `.npmrc`, `.github/workflows/` - so skipping them would silently hide the
/// findings this scanner exists to report. Ignore-file semantics are unchanged
/// by this: a dotfile listed in a respected `.gitignore` stays ignored.
///
/// require_git(false): `.gitignore` inside the root is honored whether or not a
/// `.git` entry exists, so a scan of an exported tree sees what a scan of the
/// checkout sees. This knob does not widen where ignore files are read from -
/// that is `respect_parent_ignores`, which is off by default.
pub fn collect_files_with(root: &Path, opts: &IgnoreOptions) -> Vec<PathBuf> {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(opts.respect_parent_ignores)
        .ignore(opts.respect_dot_ignore)
        .git_ignore(opts.respect_gitignore)
        .git_global(opts.respect_global_gitignore)
        .git_exclude(opts.respect_git_exclude)
        .require_git(false)
        .filter_entry(|entry| !is_excluded_name(entry.file_name()));
    let walker = builder.build();

    let mut files = Vec::new();
    for entry in walker.flatten() {
        if entry.file_type().is_some_and(|ft| ft.is_file()) {
            files.push(entry.path().to_path_buf());
        }
    }

    files.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });

    files
}

/// Read file contents. Returns Binary if first 8000 bytes contain NUL.
/// IO errors and invalid UTF-8 return Unreadable with reason.
pub fn read_text(path: &Path) -> FileKind {
    match fs::read(path) {
        Ok(bytes) => {
            let check_len = bytes.len().min(8000);
            if bytes[..check_len].contains(&0) {
                return FileKind::Binary;
            }

            match String::from_utf8(bytes) {
                Ok(text) => FileKind::Text(text),
                Err(_) => FileKind::Unreadable("not valid UTF-8".to_string()),
            }
        }
        Err(e) => FileKind::Unreadable(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paths relative to `root`, forward-slashed, in walk order.
    fn relative_names(root: &Path) -> Vec<String> {
        names_with(root, &IgnoreOptions::default())
    }

    /// As [`relative_names`], under an explicit ignore policy.
    fn names_with(root: &Path, opts: &IgnoreOptions) -> Vec<String> {
        collect_files_with(root, opts)
            .iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn gitignored_file_excluded() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(dir.path().join("ignored.txt"), "content").unwrap();

        let files = collect_files(dir.path());
        let names: Vec<_> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();

        assert!(!names.contains(&"ignored.txt"));
        assert!(names.contains(&"main.rs"));
    }

    #[test]
    fn nul_byte_detected_as_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.bin");
        let mut bytes = vec![0x89, 0x50, 0x4E, 0x47];
        bytes.push(0);
        fs::write(&path, bytes).unwrap();

        match read_text(&path) {
            FileKind::Binary => {}
            _ => panic!("expected Binary"),
        }
    }

    #[test]
    fn invalid_utf8_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.txt");
        fs::write(&path, b"\xff\xfe").unwrap();

        match read_text(&path) {
            FileKind::Unreadable(reason) => {
                assert_eq!(reason, "not valid UTF-8");
            }
            _ => panic!("expected Unreadable"),
        }
    }

    #[test]
    fn io_error_unreadable() {
        let path = Path::new("/nonexistent/dir/file.txt");
        match read_text(path) {
            FileKind::Unreadable(reason) => {
                assert!(!reason.is_empty());
            }
            _ => panic!("expected Unreadable"),
        }
    }

    #[test]
    fn text_file_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        let content = "hello world";
        fs::write(&path, content).unwrap();

        match read_text(&path) {
            FileKind::Text(text) => {
                assert_eq!(text, content);
            }
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn sort_order_stable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("z.txt"), "z").unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("m.txt"), "m").unwrap();

        let files = collect_files(dir.path());
        let names: Vec<_> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();

        assert_eq!(names, vec!["a.txt", "m.txt", "z.txt"]);
    }

    #[test]
    fn hidden_files_and_directories_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let workflows = dir.path().join(".github/workflows");
        fs::create_dir_all(&workflows).unwrap();
        fs::write(workflows.join("ci.yml"), "on: push\n").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();
        fs::write(dir.path().join(".npmrc"), "//registry/:_authToken=x\n").unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("visible.js"), "const a = 1;\n").unwrap();

        let names = relative_names(dir.path());

        assert!(names.contains(&".env".to_string()), "{names:?}");
        assert!(names.contains(&".npmrc".to_string()), "{names:?}");
        assert!(
            names.contains(&".github/workflows/ci.yml".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"src/visible.js".to_string()), "{names:?}");
    }

    #[test]
    fn vcs_internals_excluded() {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        fs::create_dir_all(git.join("objects/ab")).unwrap();
        fs::write(git.join("config"), "[core]\n").unwrap();
        fs::write(git.join("objects/ab/cdef"), "blob").unwrap();
        for vcs in [".hg", ".svn", ".bzr"] {
            let root = dir.path().join(vcs);
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("internal"), "state").unwrap();
        }
        // A jujutsu repo colocated with git: its own store under `.jj`.
        let jj = dir.path().join(".jj/repo/store/git/objects/ab");
        fs::create_dir_all(&jj).unwrap();
        fs::write(jj.join("cdef"), "blob").unwrap();
        fs::write(dir.path().join(".jj/working_copy"), "state").unwrap();
        // A vendored submodule keeps its own VCS directory below the root.
        let vendored = dir.path().join("vendor/dep/.git");
        fs::create_dir_all(&vendored).unwrap();
        fs::write(vendored.join("config"), "[core]\n").unwrap();
        fs::write(dir.path().join("vendor/dep/lib.rs"), "fn f() {}").unwrap();

        let names = relative_names(dir.path());

        assert_eq!(names, vec!["vendor/dep/lib.rs".to_string()], "{names:?}");
    }

    #[test]
    fn vcs_gitlink_file_excluded() {
        // A worktree or submodule checkout has `.git` as a file, not a
        // directory.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".git"), "gitdir: /elsewhere/.git\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(dir.path());

        assert_eq!(names, vec!["main.rs".to_string()], "{names:?}");
    }

    #[test]
    fn own_state_directory_excluded() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".siloscan/cache/ab");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("entry.json"), "{}").unwrap();
        fs::write(dir.path().join(".siloscan/.gitignore"), "cache/\n").unwrap();
        fs::write(dir.path().join(".siloscan/baseline.json"), "{}").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(dir.path());

        assert_eq!(names, vec!["main.rs".to_string()], "{names:?}");
    }

    #[test]
    fn gitignored_dotfile_still_excluded() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), ".env.local\nsecrets/\n").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();
        fs::write(dir.path().join(".env.local"), "TOKEN=local\n").unwrap();
        fs::create_dir(dir.path().join("secrets")).unwrap();
        fs::write(dir.path().join("secrets/.keys"), "TOKEN=deep\n").unwrap();

        let names = relative_names(dir.path());

        assert!(names.contains(&".env".to_string()), "{names:?}");
        assert!(names.contains(&".gitignore".to_string()), "{names:?}");
        assert!(!names.contains(&".env.local".to_string()), "{names:?}");
        assert!(!names.contains(&"secrets/.keys".to_string()), "{names:?}");
    }

    #[test]
    fn walk_order_deterministic_with_hidden_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
        fs::create_dir_all(dir.path().join(".circleci")).unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();
        fs::write(dir.path().join(".github/workflows/ci.yml"), "on: push\n").unwrap();
        fs::write(dir.path().join(".circleci/config.yml"), "version: 2\n").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();
        fs::write(dir.path().join("src/visible.js"), "const a = 1;\n").unwrap();
        fs::write(dir.path().join("README.md"), "# readme\n").unwrap();

        let expected = vec![
            ".circleci/config.yml".to_string(),
            ".env".to_string(),
            ".github/workflows/ci.yml".to_string(),
            "README.md".to_string(),
            "src/visible.js".to_string(),
        ];

        for _ in 0..5 {
            assert_eq!(relative_names(dir.path()), expected);
        }
    }

    /// A `.gitignore` above the scan root used to erase findings from inside
    /// it, with nothing in the report to say so.
    #[test]
    fn parent_gitignore_does_not_suppress_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir(&root).unwrap();
        fs::write(dir.path().join(".gitignore"), "secret.txt\n").unwrap();
        fs::write(root.join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(&root);
        assert!(names.contains(&"secret.txt".to_string()), "{names:?}");

        // The setup does suppress once the walk is told to read upward, which
        // is what 1.1.1 did unconditionally.
        let opted_in = IgnoreOptions {
            respect_parent_ignores: true,
            ..IgnoreOptions::default()
        };
        let names = names_with(&root, &opted_in);
        assert!(!names.contains(&"secret.txt".to_string()), "{names:?}");
    }

    /// `.git/info/exclude` is untracked and per-clone, so it never shows up in
    /// review. It no longer removes files from a scan unless asked.
    #[test]
    fn git_info_exclude_does_not_suppress_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let info = dir.path().join(".git/info");
        fs::create_dir_all(&info).unwrap();
        fs::write(info.join("exclude"), "secret.txt\n").unwrap();
        fs::write(dir.path().join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(dir.path());
        assert!(names.contains(&"secret.txt".to_string()), "{names:?}");
        // The `.git` directory itself is still not walked.
        assert!(!names.iter().any(|n| n.starts_with(".git/")), "{names:?}");

        let opted_in = IgnoreOptions {
            respect_git_exclude: true,
            ..IgnoreOptions::default()
        };
        let names = names_with(dir.path(), &opted_in);
        assert!(!names.contains(&"secret.txt".to_string()), "{names:?}");
    }

    /// Marks the re-executed child of the test below, and carries the repo it
    /// is to walk. Set with `Command::env` on a child process, never on this one.
    const GLOBAL_IGNORE_CHILD: &str = "SILOSCAN_TEST_GLOBAL_IGNORE_ROOT";

    /// Printed by the child and required by the parent, so a filter that
    /// matched no test fails the parent instead of passing it vacuously.
    const CHILD_RAN: &str = "global-ignore child ran";

    /// Git's global `core.excludesFile` belongs to the invoking user, not to
    /// the repository, so a scan must not consult it.
    ///
    /// The behaviour is exercised in a child process, and the reason is that
    /// the `ignore` crate leaves no other way in. It resolves the global
    /// excludes path from the environment alone - `GIT_CONFIG_GLOBAL`, then
    /// `$HOME/.gitconfig`, then the XDG and system files
    /// (`ignore::gitignore::global`) - and `WalkBuilder` exposes `git_global`
    /// as a bool with no path beside it. Pointing it at a fixture in-process
    /// therefore means `std::env::set_var`, which is `unsafe` for a reason:
    /// it races every concurrent `getenv` in the process, and the sibling tests
    /// in this binary call `tempfile::tempdir`, which reads `TMPDIR`. That race
    /// is a real one, and it can take the whole suite down rather than fail a
    /// test.
    ///
    /// `Command::env` sets the variable on a process that does not exist yet,
    /// which races nothing. The child re-runs this same test with the fixture
    /// path handed to it, takes the other branch, and asserts both directions
    /// for real. The parent requires [`CHILD_RAN`] on the child's stdout: a
    /// renamed test would otherwise filter to zero tests, exit 0, and quietly
    /// assert nothing.
    #[test]
    fn global_excludes_file_does_not_suppress_by_default() {
        let Some(root) = std::env::var_os(GLOBAL_IGNORE_CHILD) else {
            return spawn_global_ignore_child();
        };

        // Child: `GIT_CONFIG_GLOBAL` is already in this process's environment,
        // inherited at spawn. Nothing here mutates it.
        let root = PathBuf::from(root);
        let default_names = relative_names(&root);
        let opted_in = IgnoreOptions {
            respect_global_gitignore: true,
            ..IgnoreOptions::default()
        };
        let opted_in_names = names_with(&root, &opted_in);

        assert!(
            default_names.contains(&"secret.txt".to_string()),
            "the user's global excludes must not reach a default scan: {default_names:?}"
        );
        // The setup does suppress once the walk is told to read the user's
        // config, which is what 1.1.1 did unconditionally. Without this the
        // test above would pass on a fixture that never worked.
        assert!(
            !opted_in_names.contains(&"secret.txt".to_string()),
            "--respect-global-gitignore must reach the walker: {opted_in_names:?}"
        );
        println!("{CHILD_RAN}");
    }

    /// Build the fixture, then re-run this test binary against just the test
    /// above with `GIT_CONFIG_GLOBAL` pointed at it.
    fn spawn_global_ignore_child() {
        let dir = tempfile::tempdir().unwrap();
        let global_ignore = dir.path().join("global_ignore");
        fs::write(&global_ignore, "secret.txt\n").unwrap();
        let gitconfig = dir.path().join("gitconfig");
        fs::write(
            &gitconfig,
            format!("[core]\nexcludesFile = {}\n", global_ignore.display()),
        )
        .unwrap();

        let root = dir.path().join("repo");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "walk::tests::global_excludes_file_does_not_suppress_by_default",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(GLOBAL_IGNORE_CHILD, &root)
            .env("GIT_CONFIG_GLOBAL", &gitconfig)
            .output()
            .expect("re-running the test binary");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "child failed:\n{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(CHILD_RAN),
            "the child never ran the test - has it been renamed?\n{stdout}"
        );
    }

    /// An ignore file inside the root is part of the tree under review, so it
    /// keeps its say by default.
    #[test]
    fn in_root_ignore_files_still_suppress_by_default() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "hidden_by_git.txt\n").unwrap();
        fs::write(dir.path().join(".ignore"), "hidden_by_dot.txt\n").unwrap();
        fs::write(dir.path().join("hidden_by_git.txt"), "a").unwrap();
        fs::write(dir.path().join("hidden_by_dot.txt"), "b").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(dir.path());

        assert!(
            !names.contains(&"hidden_by_git.txt".to_string()),
            "{names:?}"
        );
        assert!(
            !names.contains(&"hidden_by_dot.txt".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"main.rs".to_string()), "{names:?}");
    }

    /// A one-line ignore file must not be able to hide a live secret with no
    /// way to look past it.
    #[test]
    fn all_files_scans_ignored_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "hidden_by_git.txt\n").unwrap();
        fs::write(dir.path().join(".ignore"), "hidden_by_dot.txt\n").unwrap();
        fs::write(dir.path().join("hidden_by_git.txt"), "a").unwrap();
        fs::write(dir.path().join("hidden_by_dot.txt"), "b").unwrap();

        let names = names_with(dir.path(), &IgnoreOptions::all_files());

        assert!(
            names.contains(&"hidden_by_git.txt".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"hidden_by_dot.txt".to_string()),
            "{names:?}"
        );
    }

    /// Turning off one in-root source leaves the other alone.
    #[test]
    fn gitignore_and_dot_ignore_toggle_independently() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "hidden_by_git.txt\n").unwrap();
        fs::write(dir.path().join(".ignore"), "hidden_by_dot.txt\n").unwrap();
        fs::write(dir.path().join("hidden_by_git.txt"), "a").unwrap();
        fs::write(dir.path().join("hidden_by_dot.txt"), "b").unwrap();

        let no_git = IgnoreOptions {
            respect_gitignore: false,
            ..IgnoreOptions::default()
        };
        let names = names_with(dir.path(), &no_git);
        assert!(
            names.contains(&"hidden_by_git.txt".to_string()),
            "{names:?}"
        );
        assert!(
            !names.contains(&"hidden_by_dot.txt".to_string()),
            "{names:?}"
        );

        let no_dot = IgnoreOptions {
            respect_dot_ignore: false,
            ..IgnoreOptions::default()
        };
        let names = names_with(dir.path(), &no_dot);
        assert!(
            !names.contains(&"hidden_by_git.txt".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"hidden_by_dot.txt".to_string()),
            "{names:?}"
        );
    }

    /// The exclusions the walker owns are policy, not ignore rules: they hold
    /// even when every ignore source is off.
    #[test]
    fn all_files_still_excludes_vcs_and_state_directories() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git/objects")).unwrap();
        fs::write(dir.path().join(".git/objects/blob"), "x").unwrap();
        fs::create_dir_all(dir.path().join(".siloscan/cache")).unwrap();
        fs::write(dir.path().join(".siloscan/cache/entry.json"), "{}").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = names_with(dir.path(), &IgnoreOptions::all_files());

        assert_eq!(names, vec!["main.rs".to_string()], "{names:?}");
    }

    /// Walk order is a property of the sort, not of the ignore policy.
    #[test]
    fn walk_order_deterministic_under_every_policy() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/b.rs"), "b").unwrap();
        fs::write(dir.path().join("src/a.rs"), "a").unwrap();
        fs::write(dir.path().join("README.md"), "r").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();

        let expected = vec![
            ".env".to_string(),
            "README.md".to_string(),
            "src/a.rs".to_string(),
            "src/b.rs".to_string(),
        ];

        for opts in [IgnoreOptions::default(), IgnoreOptions::all_files()] {
            for _ in 0..5 {
                assert_eq!(names_with(dir.path(), &opts), expected, "{opts:?}");
            }
        }
    }
}
