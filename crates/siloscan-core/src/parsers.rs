use tree_sitter::{Language, Parser, Tree};

/// Every language this crate can support, sorted; the ones actually available
/// depend on the enabled grammar features.
const KNOWN: [&str; 10] = [
    "c",
    "cpp",
    "csharp",
    "go",
    "java",
    "javascript",
    "python",
    "ruby",
    "rust",
    "typescript",
];

/// Map a language name emitted by [`crate::lang::detect`] to its grammar.
/// Returns `None` for unknown names and for grammars whose feature is off.
pub fn language(lang: &str) -> Option<Language> {
    match lang {
        #[cfg(feature = "tree-sitter-c")]
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-cpp")]
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-c-sharp")]
        "csharp" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-go")]
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-java")]
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-javascript")]
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-python")]
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-ruby")]
        "ruby" => Some(tree_sitter_ruby::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-rust")]
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        #[cfg(feature = "tree-sitter-typescript")]
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        _ => None,
    }
}

/// Parse `content` as `lang`. Returns `None` when the language is unavailable
/// or the parser fails outright; a tree containing error nodes is still a tree.
pub fn parse(lang: &str, content: &str) -> Option<Tree> {
    let language = language(lang)?;
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    parser.parse(content, None)
}

/// The languages available in this build, sorted.
pub fn supported_languages() -> Vec<&'static str> {
    KNOWN
        .into_iter()
        .filter(|lang| language(lang).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_language_has_no_grammar() {
        assert!(language("klingon").is_none());
        assert!(language("").is_none());
        assert!(parse("klingon", "fn main() {}").is_none());
    }

    #[test]
    fn supported_languages_is_sorted_and_known() {
        let langs = supported_languages();
        let mut sorted = langs.clone();
        sorted.sort_unstable();
        assert_eq!(langs, sorted);
        assert!(langs.iter().all(|lang| KNOWN.contains(lang)));
    }

    #[test]
    fn supported_languages_all_parse() {
        for lang in supported_languages() {
            assert!(parse(lang, "").is_some(), "{lang} failed to parse");
        }
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn parses_rust() {
        let tree = parse("rust", "fn main() { let x = 1; }").expect("rust tree");
        assert_eq!(tree.root_node().kind(), "source_file");
        assert!(!tree.root_node().has_error());
    }

    #[cfg(feature = "tree-sitter-python")]
    #[test]
    fn parses_python() {
        let tree = parse("python", "def f():\n    return 1\n").expect("python tree");
        assert_eq!(tree.root_node().kind(), "module");
        assert!(!tree.root_node().has_error());
    }

    #[cfg(feature = "tree-sitter-typescript")]
    #[test]
    fn parses_typescript_not_tsx() {
        let tree = parse("typescript", "const x: number = 1;").expect("typescript tree");
        assert!(!tree.root_node().has_error());
        // A type assertion is typescript-only syntax; the tsx grammar rejects it.
        let tree = parse("typescript", "const y = <number>x;").expect("typescript tree");
        assert!(!tree.root_node().has_error());
    }

    #[cfg(feature = "tree-sitter-go")]
    #[test]
    fn parses_go() {
        let tree = parse("go", "package main\n\nfunc main() {}\n").expect("go tree");
        assert!(!tree.root_node().has_error());
    }
}
