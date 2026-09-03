use std::collections::BTreeMap;
use std::path::Path;

/// Detect programming language from file path or content.
/// The extension map decides for any file that has an extension, except `.h`,
/// which is C or C++ by its content; the shebang is consulted only for
/// extensionless files.
pub fn detect(path: &Path, content: &str) -> Option<&'static str> {
    if let Some(extension) = path.extension().and_then(|extension| extension.to_str()) {
        if extension.eq_ignore_ascii_case("h") {
            return Some(if is_cpp_header(content) { "cpp" } else { "c" });
        }
        return detect_by_extension(path);
    }
    detect_by_shebang(content)
}

/// Whether a `.h` header is C++ rather than C.
///
/// Comments are removed first, so prose that mentions a C++ keyword cannot
/// decide the file, and every signal is then anchored at the start of the
/// remaining code on the line, so an identifier or a string that happens to
/// contain one of these words cannot decide it either. A line that opens one of
/// these declarations is C++ and nothing else:
///
/// - `namespace `
/// - `class `
/// - `template<` or `template <`
/// - `public:`, `private:`, `protected:`
/// - `extern "C++"`
///
/// Deliberately absent: `nullptr` and `constexpr` are C23 keywords, and `::`
/// appears in C23 attributes such as `[[gnu::unused]]`, so none of the three
/// separates the two languages. An empty header, and any header that declares
/// only C constructs, stays C.
fn is_cpp_header(content: &str) -> bool {
    let mut code = String::new();
    let mut in_block_comment = false;
    for line in content.lines() {
        code.clear();
        let mut rest = line;
        loop {
            if in_block_comment {
                match rest.find("*/") {
                    Some(end) => {
                        rest = &rest[end + 2..];
                        in_block_comment = false;
                    }
                    None => break,
                }
            } else {
                match (rest.find("/*"), rest.find("//")) {
                    (Some(block), line_comment)
                        if line_comment.is_none_or(|slash| block < slash) =>
                    {
                        code.push_str(&rest[..block]);
                        rest = &rest[block + 2..];
                        in_block_comment = true;
                    }
                    (_, Some(slash)) => {
                        code.push_str(&rest[..slash]);
                        break;
                    }
                    _ => {
                        code.push_str(rest);
                        break;
                    }
                }
            }
        }
        if opens_cpp_declaration(code.trim()) {
            return true;
        }
    }
    false
}

/// Whether one comment-free, trimmed line opens a C++-only declaration.
fn opens_cpp_declaration(line: &str) -> bool {
    const PREFIXES: [&str; 8] = [
        "namespace ",
        "class ",
        "template<",
        "template <",
        "public:",
        "private:",
        "protected:",
        "extern \"C++\"",
    ];
    PREFIXES.iter().any(|prefix| line.starts_with(prefix))
}

/// Apply an accepted config extension mapping before the built-in detector.
/// The map keys omit the dot, matching [`crate::config::Config::languages`].
pub(crate) fn detect_configured<'a>(
    path: &Path,
    content: &str,
    languages: Option<&'a BTreeMap<String, String>>,
) -> Option<&'a str> {
    if let Some(extension) = path.extension().and_then(|extension| extension.to_str()) {
        let extension = extension.to_ascii_lowercase();
        if let Some(language) = languages.and_then(|languages| languages.get(&extension)) {
            return Some(language);
        }
    }
    detect(path, content)
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
        // `h` is not here: `detect` decides it from the file's content.
        "c" => Some("c"),
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
    fn test_header_c_stays_c() {
        let path = PathBuf::from("header.h");
        let content = "#ifndef WIDGET_H\n#define WIDGET_H\nstruct widget { int id; };\nvoid widget_init(struct widget *w);\n#endif\n";
        assert_eq!(detect(&path, content), Some("c"));
    }

    #[test]
    fn test_header_with_class_is_cpp() {
        let path = PathBuf::from("header.h");
        let content = "#pragma once\nclass Widget {\npublic:\n  int id() const;\n};\n";
        assert_eq!(detect(&path, content), Some("cpp"));
    }

    #[test]
    fn test_header_with_namespace_is_cpp() {
        let path = PathBuf::from("header.h");
        let content = "#pragma once\nnamespace widget {\nint id();\n}\n";
        assert_eq!(detect(&path, content), Some("cpp"));
    }

    #[test]
    fn test_header_comment_mentioning_namespace_stays_c() {
        let path = PathBuf::from("header.h");
        let content = "/*\n * namespace foo is not a thing here, and neither is\n * class bar or template <typename T>.\n */\n// namespace again\nint widget_id(void);\n";
        assert_eq!(detect(&path, content), Some("c"));
    }

    #[test]
    fn test_header_empty_stays_c() {
        let path = PathBuf::from("header.h");
        assert_eq!(detect(&path, ""), Some("c"));
    }

    #[test]
    fn test_header_code_after_block_comment_is_cpp() {
        let path = PathBuf::from("header.h");
        let content = "/* a leading comment */ template <typename T> class Widget;\n";
        assert_eq!(detect(&path, content), Some("cpp"));
    }

    #[test]
    fn test_header_uppercase_extension_reads_content() {
        let path = PathBuf::from("Header.H");
        assert_eq!(detect(&path, "namespace widget {}\n"), Some("cpp"));
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
