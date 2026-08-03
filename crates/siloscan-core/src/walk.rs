use std::fs;
use std::path::{Path, PathBuf};

pub enum FileKind {
    Text(String),
    Binary,
    Unreadable(String),
}

/// Walk root directory using ignore crate with standard VCS filters:
/// respects .gitignore, .ignore, excludes .git, skips hidden files.
/// Files only, sorted bytewise by path, walk errors silently skipped.
/// require_git(false): .gitignore is honored whether or not a .git entry
/// exists, so output never depends on the environment around the scan root.
pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    let walker = ignore::WalkBuilder::new(root)
        .standard_filters(true)
        .hidden(true)
        .require_git(false)
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
}
