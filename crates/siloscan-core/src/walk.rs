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

/// Walk root directory using the ignore crate: respects `.gitignore` and
/// `.ignore`, scans hidden files and directories, excludes version-control
/// internals (`.git`, `.hg`, `.svn`, `.jj`, `.bzr`) and siloscan's own
/// `.siloscan` state directory anywhere below the scan root.
/// Files only, sorted bytewise by path, walk errors silently skipped.
///
/// hidden(false): dotfiles carry secrets as often as any other file - `.env`,
/// `.npmrc`, `.github/workflows/` - so skipping them would silently hide the
/// findings this scanner exists to report. Ignore-file semantics are unchanged
/// by this: a dotfile listed in `.gitignore` stays ignored.
///
/// require_git(false): .gitignore is honored whether or not a .git entry
/// exists, so output never depends on the environment around the scan root.
pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    let walker = ignore::WalkBuilder::new(root)
        .standard_filters(true)
        .hidden(false)
        .require_git(false)
        .filter_entry(|entry| !is_excluded_name(entry.file_name()))
        .build();

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
        collect_files(root)
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
}
