//! ts.rs — rewrite of `internal/cbm/ts_runtime.c` + the language-factory
//! half of `lang_specs.c` (C cbm_ts_language).
//!
//! The C vendored the tree-sitter runtime and 162 grammar_*.c glue files,
//! each compiled as a separate unit to dodge conflicting static symbols;
//! Rust resolves grammars through crates.io crates by [`LanguageSpec`]'s
//! `ts_crate` name. Grammar crates are wired incrementally (the languages
//! in active use first); [`language_for`] reports which are compiled in.

use crate::lang_specs::{lang_spec, LanguageSpec};
use crate::Language;

/// Parse a source slice with the grammar for `lang`.
/// Returns `None` when the language has no compiled grammar in this build.
pub fn parse(lang: Language, source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    let ts_lang = ts_language(lang)?;
    parser.set_language(&ts_lang).ok()?;
    parser.parse(source, None)
}

/// Parse with a previous tree for incremental reparsing.
pub fn parse_incremental(
    lang: Language,
    source: &str,
    old_tree: &tree_sitter::Tree,
) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    let ts_lang = ts_language(lang)?;
    parser.set_language(&ts_lang).ok()?;
    parser.parse(source, Some(old_tree))
}

/// The compiled tree-sitter language for `lang`, or None when that grammar
/// crate is not linked in this build (mirrors the C's NULL return).
pub fn ts_language(lang: Language) -> Option<tree_sitter::Language> {
    let spec: &LanguageSpec = lang_spec(lang);
    let crate_name = spec.ts_crate?;
    resolve_grammar(crate_name)
}

/// Grammar registry — the compiled-in crates. C resolved these at link
/// time to grammar symbols; Rust resolves through this match, extended as
/// grammar crates are added to Cargo.toml.
fn resolve_grammar(crate_name: &str) -> Option<tree_sitter::Language> {
    match crate_name {
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "jinja2" => Some(tree_sitter_jinja2::LANGUAGE.into()),
        "yaml" => Some(tree_sitter_yaml::LANGUAGE.into()),
        _ => None,
    }
}

/// Does this build have a compiled grammar for `lang`?
pub fn has_grammar(lang: Language) -> bool {
    ts_language(lang).is_some()
}

/// Count of languages with linked grammars (diagnostics).
pub fn grammar_count() -> usize {
    Language::ALL.iter().filter(|l| has_grammar(**l)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_and_python_parse() {
        let tree = parse(Language::GO, "package main\nfunc main() {}\n").expect("go grammar");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(!root.has_error());

        let tree = parse(Language::PYTHON, "def f():\n    pass\n").expect("py grammar");
        assert_eq!(tree.root_node().kind(), "module");
    }

    #[test]
    fn unsupported_language_is_none() {
        // A language whose grammar crate is not linked yet.
        assert!(parse(Language::HASKELL, "main = ()").is_none());
    }

    #[test]
    fn syntax_error_is_reported_by_tree() {
        let tree = parse(Language::PYTHON, "def f(:\n").expect("grammar");
        assert!(tree.root_node().has_error());
    }

    #[test]
    fn grammar_count_matches_registry() {
        assert!(grammar_count() >= 2);
        assert!(has_grammar(Language::GO));
        assert!(has_grammar(Language::PYTHON));
        assert!(!has_grammar(Language::HASKELL));
    }

    #[test]
    fn incremental_reparse() {
        let src1 = "def a():\n    pass\n";
        let t1 = parse(Language::PYTHON, src1).unwrap();
        let src2 = "def a():\n    pass\ndef b():\n    pass\n";
        let t2 = parse_incremental(Language::PYTHON, src2, &t1).expect("reparse");
        assert_eq!(t2.root_node().kind(), "module");
    }
}
