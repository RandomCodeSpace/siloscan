//! Per-file semantic facts extracted from tree-sitter parses.
//!
//! Extraction is query driven: one query yields import references, another
//! yields declarations whose capture name is the declaration kind. Results are
//! reported in source order so identical input produces identical facts.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tree_sitter::{Query, QueryCursor, StreamingIterator, Tree};

/// A module, package, or header referenced by a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    /// Import target as written, normalized per language (quotes, brackets and
    /// directive keywords removed).
    pub raw: String,
    /// 1-based line number.
    pub line: u64,
    /// 1-based byte offset within the line.
    pub column: u64,
    /// 1-based UTF-16 code unit offset within the line. Carried alongside the
    /// byte column because a boundary violation is reported at its import, and
    /// SARIF measures that column in UTF-16 units; the importing file's bytes
    /// are in hand here and nowhere downstream.
    pub column_utf16: u64,
}

/// A named declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decl {
    pub name: String,
    /// Lowercase noun: `function`, `struct`, `class`, `method`, `type`, `const`, ...
    pub kind: String,
    /// 1-based line number.
    pub line: u64,
}

/// Facts extracted from a single file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFacts {
    pub language: String,
    pub imports: Vec<Import>,
    pub decls: Vec<Decl>,
}

/// Facts for a set of files, keyed by repo-relative path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Graph {
    pub files: BTreeMap<String, FileFacts>,
}

/// Extract facts for `content`, already parsed as `lang` into `tree`, with no
/// path to choose a grammar by. Unknown or unavailable languages yield empty
/// facts.
///
/// TypeScript is the one language with two grammars, so for every other
/// language this is [`extract_file`]. A `.tsx` file has to go through
/// [`extract_file`] to be read by the grammar it was parsed with.
pub fn extract(lang: &str, content: &str, tree: &Tree) -> FileFacts {
    extract_file(lang, Path::new(""), content, tree)
}

/// Extract facts for `content`, read from `path` and already parsed as `lang`
/// into `tree` by [`crate::parsers::parse_file`].
///
/// The queries are selected by `crate::parsers::grammar_name`, so they are
/// compiled against the same grammar the tree was parsed with; the facts still
/// carry the language, which is `typescript` for a `.tsx` file.
pub fn extract_file(lang: &str, path: &Path, content: &str, tree: &Tree) -> FileFacts {
    let mut facts = FileFacts {
        language: lang.to_string(),
        imports: Vec::new(),
        decls: Vec::new(),
    };

    let Some(compiled) = compiled(crate::parsers::grammar_name(lang, path)) else {
        return facts;
    };

    for capture in captures(content, tree, &compiled.imports) {
        let raw = normalize_import(lang, &capture.text);
        if raw.is_empty() {
            continue;
        }
        facts.imports.push(Import {
            raw,
            line: capture.line,
            column: capture.column,
            column_utf16: capture.column_utf16,
        });
    }

    for capture in captures(content, tree, &compiled.decls) {
        facts.decls.push(Decl {
            name: capture.text,
            kind: capture.name,
            line: capture.line,
        });
    }

    facts
}

struct Capture {
    name: String,
    text: String,
    start: usize,
    line: u64,
    column: u64,
    column_utf16: u64,
}

/// Run `query` over `tree`, returning captures in source order. Captures whose
/// name starts with `_` are predicate helpers and are dropped, as are
/// duplicates produced by overlapping patterns.
fn captures(source: &str, tree: &Tree, query: &Query) -> Vec<Capture> {
    let names = query.capture_names();
    let bytes = source.as_bytes();

    let mut out: Vec<Capture> = Vec::new();
    let mut cursor = QueryCursor::new();
    // Both columns are measured from the capture's byte offset against the
    // line it falls on, rather than read off the node's `start_position`, whose
    // column is bytes only. One source for line and both columns is what stops
    // them from disagreeing.
    let mut lines = crate::engines::LineIndex::new(source);
    let mut matches = cursor.matches(query, tree.root_node(), bytes);
    while let Some(matched) = matches.next() {
        for capture in matched.captures {
            let name = names[capture.index as usize];
            if name.starts_with('_') {
                continue;
            }
            let Ok(text) = capture.node.utf8_text(bytes) else {
                continue;
            };
            let start = capture.node.start_byte();
            let at = lines.position(start);
            out.push(Capture {
                name: name.to_string(),
                text: text.to_string(),
                start,
                line: at.line,
                column: at.column,
                column_utf16: at.column_utf16,
            });
        }
    }

    out.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.text.cmp(&b.text))
    });
    out.dedup_by(|a, b| a.start == b.start && a.name == b.name && a.text == b.text);
    out
}

fn normalize_import(lang: &str, text: &str) -> String {
    match lang {
        "java" => strip_directive(text, &["import", "static"]),
        "csharp" => strip_directive(text, &["global", "using", "static", "unsafe"]),
        "c" | "cpp" | "go" | "javascript" | "typescript" | "ruby" => strip_quotes(text),
        _ => text.trim().to_string(),
    }
}

/// Strip string quoting and include brackets: `"foo"`, `'foo'`, `` `foo` ``
/// and `<foo>` all become `foo`.
fn strip_quotes(text: &str) -> String {
    text.trim()
        .trim_start_matches(['"', '\'', '`', '<'])
        .trim_end_matches(['"', '\'', '`', '>'])
        .to_string()
}

/// Reduce a whole import/using directive to its target by dropping the leading
/// keywords and the terminating semicolon.
fn strip_directive(text: &str, keywords: &[&str]) -> String {
    let body = text.trim().trim_end_matches(';');
    let kept: Vec<&str> = body
        .split_whitespace()
        .filter(|token| !keywords.contains(token))
        .collect();
    kept.join(" ").trim_end_matches(';').to_string()
}

/// The compiled query pair for one language. Compiling a query is an order of
/// magnitude more expensive than parsing a file, so each pair is built once per
/// process and shared by every file of that language.
struct Compiled {
    imports: Query,
    decls: Query,
}

impl Compiled {
    /// `None` when the grammar is not in this build or a query fails to
    /// compile, which yields empty facts instead of failing the scan.
    fn new(grammar: &str) -> Option<Compiled> {
        let language = crate::parsers::language(grammar)?;
        let (imports, decls) = queries(grammar)?;
        Some(Compiled {
            imports: Query::new(&language, imports).ok()?,
            decls: Query::new(&language, decls).ok()?,
        })
    }
}

/// Grammars that have queries, sorted; one cache slot each. A grammar that is
/// not in this build simply never produces a `Compiled`. These are grammar
/// names rather than language names: `tsx` is the second grammar of
/// `typescript` and never appears as a language anywhere.
const LANGUAGES: [&str; 11] = [
    "c",
    "cpp",
    "csharp",
    "go",
    "java",
    "javascript",
    "python",
    "ruby",
    "rust",
    "tsx",
    "typescript",
];

/// The compiled queries for `grammar`, compiled on first use and kept for the
/// rest of the process.
fn compiled(grammar: &str) -> Option<&'static Compiled> {
    static COMPILED: [OnceLock<Option<Compiled>>; LANGUAGES.len()] =
        [const { OnceLock::new() }; LANGUAGES.len()];

    let index = LANGUAGES.iter().position(|known| *known == grammar)?;
    COMPILED[index]
        .get_or_init(|| Compiled::new(grammar))
        .as_ref()
}

/// The `(imports, decls)` query sources for `grammar`, when it is compiled in.
/// `tsx` shares typescript's: the two grammars disagree about `<T>x` and about
/// nothing an import or a declaration is written with.
fn queries(grammar: &str) -> Option<(&'static str, &'static str)> {
    match grammar {
        #[cfg(feature = "tree-sitter-c")]
        "c" => Some((C_IMPORTS, C_DECLS)),
        #[cfg(feature = "tree-sitter-cpp")]
        "cpp" => Some((CPP_IMPORTS, CPP_DECLS)),
        #[cfg(feature = "tree-sitter-c-sharp")]
        "csharp" => Some((CSHARP_IMPORTS, CSHARP_DECLS)),
        #[cfg(feature = "tree-sitter-go")]
        "go" => Some((GO_IMPORTS, GO_DECLS)),
        #[cfg(feature = "tree-sitter-java")]
        "java" => Some((JAVA_IMPORTS, JAVA_DECLS)),
        #[cfg(feature = "tree-sitter-javascript")]
        "javascript" => Some((JAVASCRIPT_IMPORTS, JAVASCRIPT_DECLS)),
        #[cfg(feature = "tree-sitter-python")]
        "python" => Some((PYTHON_IMPORTS, PYTHON_DECLS)),
        #[cfg(feature = "tree-sitter-ruby")]
        "ruby" => Some((RUBY_IMPORTS, RUBY_DECLS)),
        #[cfg(feature = "tree-sitter-rust")]
        "rust" => Some((RUST_IMPORTS, RUST_DECLS)),
        #[cfg(feature = "tree-sitter-typescript")]
        "typescript" | "tsx" => Some((TYPESCRIPT_IMPORTS, TYPESCRIPT_DECLS)),
        _ => None,
    }
}

#[cfg(feature = "tree-sitter-rust")]
const RUST_IMPORTS: &str = r#"(use_declaration argument: (_) @import)"#;

#[cfg(feature = "tree-sitter-rust")]
const RUST_DECLS: &str = r#"
(function_item name: (identifier) @function)
(function_signature_item name: (identifier) @function)
(struct_item name: (type_identifier) @struct)
(union_item name: (type_identifier) @struct)
(enum_item name: (type_identifier) @enum)
(trait_item name: (type_identifier) @trait)
(type_item name: (type_identifier) @type)
(const_item name: (identifier) @const)
(static_item name: (identifier) @const)
"#;

#[cfg(feature = "tree-sitter-python")]
const PYTHON_IMPORTS: &str = r#"
(import_statement name: (dotted_name) @import)
(import_statement name: (aliased_import name: (dotted_name) @import))
(import_from_statement module_name: (dotted_name) @import)
(import_from_statement module_name: (relative_import) @import)
"#;

#[cfg(feature = "tree-sitter-python")]
const PYTHON_DECLS: &str = r#"
(function_definition name: (identifier) @function)
(class_definition name: (identifier) @class)
"#;

#[cfg(feature = "tree-sitter-javascript")]
const JAVASCRIPT_IMPORTS: &str = r#"
(import_statement source: (string) @import)
(export_statement source: (string) @import)
(call_expression
  function: (identifier) @_callee
  arguments: (arguments (string) @import)
  (#eq? @_callee "require"))
"#;

#[cfg(feature = "tree-sitter-javascript")]
const JAVASCRIPT_DECLS: &str = r#"
(function_declaration name: (identifier) @function)
(generator_function_declaration name: (identifier) @function)
(class_declaration name: (identifier) @class)
(method_definition name: (property_identifier) @method)
(lexical_declaration kind: "const" (variable_declarator name: (identifier) @const))
"#;

#[cfg(feature = "tree-sitter-typescript")]
const TYPESCRIPT_IMPORTS: &str = r#"
(import_statement source: (string) @import)
(export_statement source: (string) @import)
(call_expression
  function: (identifier) @_callee
  arguments: (arguments (string) @import)
  (#eq? @_callee "require"))
"#;

#[cfg(feature = "tree-sitter-typescript")]
const TYPESCRIPT_DECLS: &str = r#"
(function_declaration name: (identifier) @function)
(generator_function_declaration name: (identifier) @function)
(class_declaration name: (type_identifier) @class)
(abstract_class_declaration name: (type_identifier) @class)
(interface_declaration name: (type_identifier) @interface)
(type_alias_declaration name: (type_identifier) @type)
(enum_declaration name: (identifier) @enum)
(method_definition name: (property_identifier) @method)
(lexical_declaration kind: "const" (variable_declarator name: (identifier) @const))
"#;

#[cfg(feature = "tree-sitter-go")]
const GO_IMPORTS: &str = r#"
(import_spec path: (interpreted_string_literal) @import)
(import_spec path: (raw_string_literal) @import)
"#;

#[cfg(feature = "tree-sitter-go")]
const GO_DECLS: &str = r#"
(function_declaration name: (identifier) @function)
(method_declaration name: (field_identifier) @method)
(type_spec name: (type_identifier) @struct type: (struct_type))
(type_spec name: (type_identifier) @interface type: (interface_type))
(type_spec
  name: (type_identifier) @type
  type: [
    (array_type)
    (channel_type)
    (function_type)
    (generic_type)
    (map_type)
    (negated_type)
    (parenthesized_type)
    (pointer_type)
    (qualified_type)
    (slice_type)
    (type_identifier)
  ])
(type_alias name: (type_identifier) @type)
(const_spec name: (identifier) @const)
"#;

#[cfg(feature = "tree-sitter-java")]
const JAVA_IMPORTS: &str = r#"(import_declaration) @import"#;

#[cfg(feature = "tree-sitter-java")]
const JAVA_DECLS: &str = r#"
(class_declaration name: (identifier) @class)
(record_declaration name: (identifier) @class)
(interface_declaration name: (identifier) @interface)
(annotation_type_declaration name: (identifier) @interface)
(enum_declaration name: (identifier) @enum)
(method_declaration name: (identifier) @method)
(constructor_declaration name: (identifier) @method)
"#;

#[cfg(feature = "tree-sitter-c")]
const C_IMPORTS: &str = r#"
(preproc_include path: (string_literal) @import)
(preproc_include path: (system_lib_string) @import)
"#;

#[cfg(feature = "tree-sitter-c")]
const C_DECLS: &str = r#"
(function_definition declarator: (function_declarator declarator: (identifier) @function))
(function_definition
  declarator: (pointer_declarator
    declarator: (function_declarator declarator: (identifier) @function)))
(struct_specifier name: (type_identifier) @struct)
(union_specifier name: (type_identifier) @struct)
(enum_specifier name: (type_identifier) @enum)
(type_definition declarator: (type_identifier) @type)
(preproc_def name: (identifier) @const)
"#;

#[cfg(feature = "tree-sitter-cpp")]
const CPP_IMPORTS: &str = r#"
(preproc_include path: (string_literal) @import)
(preproc_include path: (system_lib_string) @import)
"#;

#[cfg(feature = "tree-sitter-cpp")]
const CPP_DECLS: &str = r#"
(function_definition declarator: (function_declarator declarator: (identifier) @function))
(function_definition
  declarator: (pointer_declarator
    declarator: (function_declarator declarator: (identifier) @function)))
(function_definition declarator: (function_declarator declarator: (field_identifier) @method))
(field_declaration declarator: (function_declarator declarator: (field_identifier) @method))
(class_specifier name: (type_identifier) @class)
(struct_specifier name: (type_identifier) @struct)
(union_specifier name: (type_identifier) @struct)
(enum_specifier name: (type_identifier) @enum)
(type_definition declarator: (type_identifier) @type)
(alias_declaration name: (type_identifier) @type)
(preproc_def name: (identifier) @const)
"#;

#[cfg(feature = "tree-sitter-c-sharp")]
const CSHARP_IMPORTS: &str = r#"(using_directive) @import"#;

#[cfg(feature = "tree-sitter-c-sharp")]
const CSHARP_DECLS: &str = r#"
(class_declaration name: (identifier) @class)
(record_declaration name: (identifier) @class)
(struct_declaration name: (identifier) @struct)
(interface_declaration name: (identifier) @interface)
(enum_declaration name: (identifier) @enum)
(delegate_declaration name: (identifier) @type)
(method_declaration name: (identifier) @method)
(constructor_declaration name: (identifier) @method)
"#;

#[cfg(feature = "tree-sitter-ruby")]
const RUBY_IMPORTS: &str = r#"
(call
  method: (identifier) @_callee
  arguments: (argument_list (string) @import)
  (#any-of? @_callee "require" "require_relative"))
"#;

#[cfg(feature = "tree-sitter-ruby")]
const RUBY_DECLS: &str = r#"
(class name: (constant) @class)
(module name: (constant) @module)
(method name: (identifier) @method)
(singleton_method name: (identifier) @method)
(assignment left: (constant) @const)
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(lang: &str, source: &str) -> FileFacts {
        let tree = crate::parsers::parse(lang, source).expect("tree");
        extract(lang, source, &tree)
    }

    fn imports(facts: &FileFacts) -> Vec<&str> {
        facts.imports.iter().map(|i| i.raw.as_str()).collect()
    }

    fn decls(facts: &FileFacts) -> Vec<(&str, &str)> {
        facts
            .decls
            .iter()
            .map(|d| (d.name.as_str(), d.kind.as_str()))
            .collect()
    }

    #[test]
    fn every_query_compiles() {
        for lang in crate::parsers::supported_languages() {
            let language = crate::parsers::language(lang).expect("language");
            let (import_query, decl_query) = queries(lang).expect("queries");
            Query::new(&language, import_query)
                .unwrap_or_else(|err| panic!("{lang} imports: {err}"));
            Query::new(&language, decl_query).unwrap_or_else(|err| panic!("{lang} decls: {err}"));
            assert!(compiled(lang).is_some(), "{lang} not cached");
        }
    }

    #[test]
    fn compiled_queries_are_shared_across_calls() {
        for lang in crate::parsers::supported_languages() {
            let first = compiled(lang).expect("compiled") as *const Compiled;
            let second = compiled(lang).expect("compiled") as *const Compiled;
            assert_eq!(first, second, "{lang} recompiled");
        }
    }

    #[test]
    fn unknown_language_has_no_queries() {
        assert!(queries("klingon").is_none());
        assert!(compiled("klingon").is_none());
    }

    #[cfg(feature = "tree-sitter-rust")]
    #[test]
    fn extracts_rust() {
        let source = "\
use std::io::Read;
use crate::graph::{Decl, Import};

pub const LIMIT: u32 = 4;

pub struct Node;

pub enum Kind {
    A,
}

pub trait Visit {
    fn visit(&self);
}

pub type Alias = Node;

pub fn main() {}
";
        let facts = facts("rust", source);
        assert_eq!(
            imports(&facts),
            ["std::io::Read", "crate::graph::{Decl, Import}"]
        );
        assert_eq!(
            decls(&facts),
            [
                ("LIMIT", "const"),
                ("Node", "struct"),
                ("Kind", "enum"),
                ("Visit", "trait"),
                ("visit", "function"),
                ("Alias", "type"),
                ("main", "function"),
            ]
        );
        assert_eq!(facts.imports[0].line, 1);
        assert_eq!(facts.imports[0].column, 5);
    }

    #[cfg(feature = "tree-sitter-python")]
    #[test]
    fn extracts_python() {
        let source = "\
import os
import json as j
from pkg.mod import thing
from . import sibling


class Widget:
    def render(self):
        return 1


def main():
    return Widget()
";
        let facts = facts("python", source);
        assert_eq!(imports(&facts), ["os", "json", "pkg.mod", "."]);
        assert_eq!(
            decls(&facts),
            [
                ("Widget", "class"),
                ("render", "function"),
                ("main", "function"),
            ]
        );
    }

    #[cfg(feature = "tree-sitter-javascript")]
    #[test]
    fn extracts_javascript() {
        let source = "\
import fs from 'node:fs';
const path = require(\"node:path\");

export class Store {
  read() {}
}

function main() {}
";
        let facts = facts("javascript", source);
        assert_eq!(imports(&facts), ["node:fs", "node:path"]);
        assert_eq!(
            decls(&facts),
            [
                ("path", "const"),
                ("Store", "class"),
                ("read", "method"),
                ("main", "function"),
            ]
        );
    }

    #[cfg(feature = "tree-sitter-typescript")]
    #[test]
    fn extracts_typescript() {
        let source = "\
import { Client } from './client';
const os = require('node:os');

export interface Options {
  depth: number;
}

export type Id = string;

export enum Mode {
  Fast,
}

export class Runner {
  run(): void {}
}

export function main(): void {}
";
        let facts = facts("typescript", source);
        assert_eq!(imports(&facts), ["./client", "node:os"]);
        assert_eq!(
            decls(&facts),
            [
                ("os", "const"),
                ("Options", "interface"),
                ("Id", "type"),
                ("Mode", "enum"),
                ("Runner", "class"),
                ("run", "method"),
                ("main", "function"),
            ]
        );
    }

    /// A `.tsx` file is a typescript file read by the tsx grammar. Under the
    /// plain typescript grammar the JSX below is a broken type assertion whose
    /// recovery eats the `require` on the line after it.
    #[cfg(feature = "tree-sitter-typescript")]
    #[test]
    fn extracts_tsx() {
        let source = "\
import { Client } from './client';

export function Badge({ label }: { label: string }) {
  const icon = <img src=\"/icon.png\" alt=\"\" />;
  const os = require('node:os');
  return <span className=\"badge\">{icon}{label}{os.type()}</span>;
}
";
        let path = Path::new("src/Badge.tsx");
        let tree = crate::parsers::parse_file("typescript", path, source).expect("tree");
        assert!(!tree.root_node().has_error());

        let facts = extract_file("typescript", path, source, &tree);
        assert_eq!(facts.language, "typescript");
        assert_eq!(imports(&facts), ["./client", "node:os"]);
        assert_eq!(
            decls(&facts),
            [("Badge", "function"), ("icon", "const"), ("os", "const")]
        );
    }

    #[cfg(feature = "tree-sitter-go")]
    #[test]
    fn extracts_go() {
        let source = "\
package main

import (
\t\"fmt\"
\th \"net/http\"
)

const Limit = 4

type Server struct{}

type Handler interface{}

type Alias = Server

func (s *Server) Serve() {}

func main() {
\tfmt.Println(h.StatusOK)
}
";
        let facts = facts("go", source);
        assert_eq!(imports(&facts), ["fmt", "net/http"]);
        assert_eq!(
            decls(&facts),
            [
                ("Limit", "const"),
                ("Server", "struct"),
                ("Handler", "interface"),
                ("Alias", "type"),
                ("Serve", "method"),
                ("main", "function"),
            ]
        );
    }

    #[cfg(feature = "tree-sitter-java")]
    #[test]
    fn extracts_java() {
        let source = "\
import java.util.List;
import java.util.*;
import static java.util.Objects.requireNonNull;

interface Visitor {}

enum Mode {
    FAST
}

public class Widget {
    Widget() {}

    public void render() {}
}
";
        let facts = facts("java", source);
        assert_eq!(
            imports(&facts),
            [
                "java.util.List",
                "java.util.*",
                "java.util.Objects.requireNonNull",
            ]
        );
        assert_eq!(
            decls(&facts),
            [
                ("Visitor", "interface"),
                ("Mode", "enum"),
                ("Widget", "class"),
                ("Widget", "method"),
                ("render", "method"),
            ]
        );
    }

    #[cfg(feature = "tree-sitter-c")]
    #[test]
    fn extracts_c() {
        let source = "\
#include <stdio.h>
#include \"local.h\"

#define LIMIT 4

struct Node {
    int value;
};

enum Kind { A };

typedef struct Point Alias;

int main(void) { return 0; }
";
        let facts = facts("c", source);
        assert_eq!(imports(&facts), ["stdio.h", "local.h"]);
        assert_eq!(
            decls(&facts),
            [
                ("LIMIT", "const"),
                ("Node", "struct"),
                ("Kind", "enum"),
                ("Point", "struct"),
                ("Alias", "type"),
                ("main", "function"),
            ]
        );
    }

    #[cfg(feature = "tree-sitter-cpp")]
    #[test]
    fn extracts_cpp() {
        let source = "\
#include <vector>
#include \"widget.hpp\"

class Widget {
public:
    void render();
};

struct Point {
    int x;
};

using Alias = Point;

int main() { return 0; }
";
        let facts = facts("cpp", source);
        assert_eq!(imports(&facts), ["vector", "widget.hpp"]);
        assert_eq!(
            decls(&facts),
            [
                ("Widget", "class"),
                ("render", "method"),
                ("Point", "struct"),
                ("Alias", "type"),
                ("main", "function"),
            ]
        );
    }

    #[cfg(feature = "tree-sitter-c-sharp")]
    #[test]
    fn extracts_csharp() {
        let source = "\
using System;
using System.IO;
using static System.Math;

namespace App
{
    interface IVisitor {}

    enum Mode { Fast }

    struct Point {}

    public class Widget
    {
        public Widget() {}

        public void Render() {}
    }
}
";
        let facts = facts("csharp", source);
        assert_eq!(imports(&facts), ["System", "System.IO", "System.Math"]);
        assert_eq!(
            decls(&facts),
            [
                ("IVisitor", "interface"),
                ("Mode", "enum"),
                ("Point", "struct"),
                ("Widget", "class"),
                ("Widget", "method"),
                ("Render", "method"),
            ]
        );
    }

    #[cfg(feature = "tree-sitter-ruby")]
    #[test]
    fn extracts_ruby() {
        let source = "\
require 'json'
require_relative \"../lib/widget\"

LIMIT = 4

module App
  class Widget
    def render
      1
    end

    def self.build
      new
    end
  end
end
";
        let facts = facts("ruby", source);
        assert_eq!(imports(&facts), ["json", "../lib/widget"]);
        assert_eq!(
            decls(&facts),
            [
                ("LIMIT", "const"),
                ("App", "module"),
                ("Widget", "class"),
                ("render", "method"),
                ("build", "method"),
            ]
        );
    }
}
