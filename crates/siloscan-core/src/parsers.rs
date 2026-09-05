use std::path::Path;

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

/// Map a language name emitted by [`crate::lang::detect`], or an internal
/// grammar name returned by [`grammar_name`], to its grammar. Returns `None`
/// for unknown names and for grammars whose feature is off.
///
/// `"tsx"` is one of those internal names. It is a grammar, not a language: it
/// is deliberately absent from `KNOWN` and from [`supported_languages`], so
/// nothing user-visible - a report, `--profiles auto`, a metrics row, a corpus
/// directory - ever names it.
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
        #[cfg(feature = "tree-sitter-typescript")]
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}

/// The grammar `path` has to be parsed with, given the language detected for
/// it. Every language but TypeScript is its own grammar and comes back
/// unchanged; a `.tsx` file comes back as `"tsx"`.
///
/// tree-sitter-typescript ships two grammars because neither dialect contains
/// the other: `<T>x` is a type assertion in `.ts` and the opening of a JSX
/// element in `.tsx`, so a grammar that parses one has to reject the other.
/// Choosing by extension is what lets the language label stay `typescript`
/// everywhere while `.tsx` files are still read by a grammar that knows JSX.
pub fn grammar_name<'a>(lang: &'a str, path: &Path) -> &'a str {
    let tsx = lang == "typescript"
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("tsx"));
    match tsx {
        true => "tsx",
        false => lang,
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

/// Parse `content`, read from `path`, as `lang`, with the grammar
/// [`grammar_name`] picks for that path. Prefer this to [`parse`] wherever the
/// file's path is in hand.
pub fn parse_file(lang: &str, path: &Path, content: &str) -> Option<Tree> {
    parse(grammar_name(lang, path), content)
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
    fn tsx_is_a_grammar_and_not_a_language() {
        assert!(language("tsx").is_some());
        assert!(!KNOWN.contains(&"tsx"));
        assert!(!supported_languages().contains(&"tsx"));
    }

    #[cfg(feature = "tree-sitter-typescript")]
    #[test]
    fn the_grammar_follows_the_extension() {
        assert_eq!(grammar_name("typescript", Path::new("a/b.tsx")), "tsx");
        assert_eq!(grammar_name("typescript", Path::new("a/b.TSX")), "tsx");
        assert_eq!(
            grammar_name("typescript", Path::new("a/b.ts")),
            "typescript"
        );
        assert_eq!(grammar_name("typescript", Path::new("b")), "typescript");
        // Only typescript has two grammars; nothing else is redirected.
        assert_eq!(
            grammar_name("javascript", Path::new("a/b.tsx")),
            "javascript"
        );
    }

    /// The two grammars are disjoint, which is why the path has to pick one.
    #[cfg(feature = "tree-sitter-typescript")]
    #[test]
    fn jsx_parses_in_a_tsx_path_and_not_in_a_ts_one() {
        let jsx = "const App = () => <div className=\"a\">{x}</div>;\n";
        let tree = parse_file("typescript", Path::new("src/App.tsx"), jsx).expect("tsx tree");
        assert!(!tree.root_node().has_error());

        let tree = parse_file("typescript", Path::new("src/App.ts"), jsx).expect("ts tree");
        assert!(tree.root_node().has_error());

        // And the type assertion the tsx grammar cannot read still parses when
        // the path says `.ts`.
        let tree = parse_file(
            "typescript",
            Path::new("src/a.ts"),
            "const y = <number>x;\n",
        )
        .expect("tree");
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
