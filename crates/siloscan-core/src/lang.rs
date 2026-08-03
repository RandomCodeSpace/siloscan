use std::path::Path;

/// Detect programming language from file path or content.
/// The extension map decides for any file that has an extension; the shebang is
/// consulted only for extensionless files.
pub fn detect(path: &Path, content: &str) -> Option<&'static str> {
    if path.extension().is_some() {
        return detect_by_extension(path);
    }
    detect_by_shebang(content)
}

fn detect_by_extension(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    match ext.as_str() {
        "rs" => Some("rust"),
        "py" => Some("python"),
        "js" | "mjs" | "cjs" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"),
        "go" => Some("go"),
        "java" => Some("java"),
        "c" | "h" => Some("c"),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" => Some("cpp"),
        "cs" => Some("csharp"),
        "rb" => Some("ruby"),
        _ => None,
    }
}

fn detect_by_shebang(content: &str) -> Option<&'static str> {
    let first_line = content.lines().next()?;
    if !first_line.starts_with("#!") {
        return None;
    }

    if first_line.contains("python") {
        Some("python")
    } else if first_line.contains("node") {
        Some("javascript")
    } else if first_line.contains("ruby") {
        Some("ruby")
    } else if first_line.contains("bash") || first_line.contains("sh") {
        Some("shell")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_extension_rust() {
        let path = PathBuf::from("main.rs");
        assert_eq!(detect(&path, ""), Some("rust"));
    }

    #[test]
    fn test_extension_python() {
        let path = PathBuf::from("script.py");
        assert_eq!(detect(&path, ""), Some("python"));
    }

    #[test]
    fn test_extension_javascript_js() {
        let path = PathBuf::from("app.js");
        assert_eq!(detect(&path, ""), Some("javascript"));
    }

    #[test]
    fn test_extension_javascript_mjs() {
        let path = PathBuf::from("module.mjs");
        assert_eq!(detect(&path, ""), Some("javascript"));
    }

    #[test]
    fn test_extension_javascript_cjs() {
        let path = PathBuf::from("compat.cjs");
        assert_eq!(detect(&path, ""), Some("javascript"));
    }

    #[test]
    fn test_extension_typescript_ts() {
        let path = PathBuf::from("main.ts");
        assert_eq!(detect(&path, ""), Some("typescript"));
    }

    #[test]
    fn test_extension_typescript_tsx() {
        let path = PathBuf::from("component.tsx");
        assert_eq!(detect(&path, ""), Some("typescript"));
    }

    #[test]
    fn test_extension_go() {
        let path = PathBuf::from("main.go");
        assert_eq!(detect(&path, ""), Some("go"));
    }

    #[test]
    fn test_extension_java() {
        let path = PathBuf::from("Main.java");
        assert_eq!(detect(&path, ""), Some("java"));
    }

    #[test]
    fn test_extension_c() {
        let path = PathBuf::from("main.c");
        assert_eq!(detect(&path, ""), Some("c"));
    }

    #[test]
    fn test_extension_h() {
        let path = PathBuf::from("header.h");
        assert_eq!(detect(&path, ""), Some("c"));
    }

    #[test]
    fn test_extension_cpp() {
        let path = PathBuf::from("main.cpp");
        assert_eq!(detect(&path, ""), Some("cpp"));
    }

    #[test]
    fn test_extension_cc() {
        let path = PathBuf::from("main.cc");
        assert_eq!(detect(&path, ""), Some("cpp"));
    }

    #[test]
    fn test_extension_cxx() {
        let path = PathBuf::from("main.cxx");
        assert_eq!(detect(&path, ""), Some("cpp"));
    }

    #[test]
    fn test_extension_hpp() {
        let path = PathBuf::from("header.hpp");
        assert_eq!(detect(&path, ""), Some("cpp"));
    }

    #[test]
    fn test_extension_hh() {
        let path = PathBuf::from("header.hh");
        assert_eq!(detect(&path, ""), Some("cpp"));
    }

    #[test]
    fn test_extension_csharp() {
        let path = PathBuf::from("Program.cs");
        assert_eq!(detect(&path, ""), Some("csharp"));
    }

    #[test]
    fn test_extension_ruby() {
        let path = PathBuf::from("script.rb");
        assert_eq!(detect(&path, ""), Some("ruby"));
    }

    #[test]
    fn test_extension_uppercase() {
        let path = PathBuf::from("main.RS");
        assert_eq!(detect(&path, ""), Some("rust"));
    }

    #[test]
    fn test_extension_mixed_case() {
        let path = PathBuf::from("main.Py");
        assert_eq!(detect(&path, ""), Some("python"));
    }

    #[test]
    fn test_unknown_extension() {
        let path = PathBuf::from("file.xyz");
        assert_eq!(detect(&path, ""), None);
    }

    #[test]
    fn test_no_extension() {
        let path = PathBuf::from("Makefile");
        assert_eq!(detect(&path, ""), None);
    }

    #[test]
    fn test_shebang_python() {
        let path = PathBuf::from("script");
        let content = "#!/usr/bin/env python\nprint('hello')";
        assert_eq!(detect(&path, content), Some("python"));
    }

    #[test]
    fn test_shebang_python3() {
        let path = PathBuf::from("script");
        let content = "#!/usr/bin/python3\nprint('hello')";
        assert_eq!(detect(&path, content), Some("python"));
    }

    #[test]
    fn test_shebang_node() {
        let path = PathBuf::from("script");
        let content = "#!/usr/bin/env node\nconsole.log('hello')";
        assert_eq!(detect(&path, content), Some("javascript"));
    }

    #[test]
    fn test_shebang_ruby() {
        let path = PathBuf::from("script");
        let content = "#!/usr/bin/env ruby\nputs 'hello'";
        assert_eq!(detect(&path, content), Some("ruby"));
    }

    #[test]
    fn test_shebang_bash() {
        let path = PathBuf::from("script");
        let content = "#!/bin/bash\necho hello";
        assert_eq!(detect(&path, content), Some("shell"));
    }

    #[test]
    fn test_shebang_sh() {
        let path = PathBuf::from("script");
        let content = "#!/bin/sh\necho hello";
        assert_eq!(detect(&path, content), Some("shell"));
    }

    #[test]
    fn test_no_shebang() {
        let path = PathBuf::from("script");
        let content = "echo hello";
        assert_eq!(detect(&path, content), None);
    }

    #[test]
    fn test_extension_beats_shebang() {
        let path = PathBuf::from("script.py");
        let content = "#!/usr/bin/env node\nconsole.log('hello')";
        assert_eq!(detect(&path, content), Some("python"));
    }

    #[test]
    fn test_extension_beats_shebang_js() {
        let path = PathBuf::from("test.js");
        let content = "#!/usr/bin/env python\nprint('hello')";
        assert_eq!(detect(&path, content), Some("javascript"));
    }

    #[test]
    fn test_shebang_unknown() {
        let path = PathBuf::from("script");
        let content = "#!/usr/bin/unknown-interpreter\ncode here";
        assert_eq!(detect(&path, content), None);
    }

    #[test]
    fn test_unknown_extension_ignores_shebang() {
        let path = PathBuf::from("thing.txt");
        let content = "#!/usr/bin/env python\nprint('hello')";
        assert_eq!(detect(&path, content), None);
    }

    #[test]
    fn test_dotfile_with_shebang_uses_shebang() {
        // A leading-dot name has no extension, so the shebang still applies.
        let path = PathBuf::from(".bashrc");
        let content = "#!/bin/bash\necho hello";
        assert_eq!(detect(&path, content), Some("shell"));
    }

    #[test]
    fn test_empty_file() {
        let path = PathBuf::from("file.txt");
        assert_eq!(detect(&path, ""), None);
    }

    #[test]
    fn test_multiple_extensions() {
        let path = PathBuf::from("archive.tar.gz");
        assert_eq!(detect(&path, ""), None);
    }
}
