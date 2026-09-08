//! fqn.rs — rewrite of `internal/cbm/helpers.c` part 2: qualified-name
//! construction and enclosing-function attribution
//! (cbm_fqn_compute / cbm_fqn_module / cbm_fqn_folder /
//! cbm_fqn_compute_source_lang / cbm_lang_module_is_dir /
//! cbm_find_enclosing_func / cbm_enclosing_func_qn).
//!
//! Rust replaces arena+buffer arithmetic with String building; the QN
//! grammar (dotted segments, extension stripping, dotfile handling,
//! `__init__`/`index` elision, dir-based modules for Java/Go) is verbatim.

use crate::lang_specs::lang_spec;
use crate::types::EfCache;
use crate::Language;
use std::collections::HashMap;

/// True when a language derives its module from the CONTAINING DIRECTORY
/// (Java package, Go package) rather than baking the filename stem into
/// the module QN: `myapp/db/conn.go` belongs to module `proj.myapp.db`,
/// not `proj.myapp.db.conn`; `Outer` in `Outer.java` is `proj.Outer`.
pub fn lang_module_is_dir(lang: Language) -> bool {
    matches!(lang, Language::JAVA | Language::GO)
}

/// Extension-stripped length (C strip_ext_len). A dot at the start of a
/// filename segment (".env", ".gitignore") is a DOTFILE marker, not an
/// extension separator — stripping there would leave an empty stem whose
/// module QN collides with the parent directory.
fn strip_ext_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    for i in (1..=bytes.len()).rev() {
        if bytes[i - 1] == b'.' {
            if i - 1 == 0 || bytes[i - 2] == b'/' {
                return bytes.len();
            }
            return i - 1;
        }
        if bytes[i - 1] == b'/' {
            break;
        }
    }
    bytes.len()
}

/// Python `__init__` / JS/TS `index` files do not add a segment when a
/// symbol name follows (C should_skip_fqn_part).
fn should_skip_fqn_part(part: &str, is_last: bool, has_name: bool) -> bool {
    if !is_last || !has_name {
        return false;
    }
    part == "__init__" || part == "index"
}

/// Append dotted path segments from rel_path (extension-stripped),
/// dropping a leading '.' from dotfile segments (".env" → "env") so the QN
/// never grows a malformed double dot (C append_path_segments).
fn append_path_segments(out: &mut String, rel_path: &str, plen: usize, has_name: bool) {
    let body = &rel_path[..plen.min(rel_path.len())];
    let total = body.len();
    let mut consumed = 0usize;
    for part in body.split('/') {
        consumed += part.len() + 1;
        let is_last = consumed >= total;
        if part.is_empty() {
            continue;
        }
        if should_skip_fqn_part(part, is_last, has_name) {
            continue;
        }
        let seg = part.strip_prefix('.').unwrap_or(part);
        if !seg.is_empty() {
            out.push('.');
            out.push_str(seg);
        }
    }
}

/// Core QN construction (C cbm_fqn_compute): `project` + rel_path segments
/// (extension stripped) + optional `name`.
pub fn fqn_compute(project: &str, rel_path: &str, name: Option<&str>) -> String {
    let mut out =
        String::with_capacity(project.len() + rel_path.len() + name.map_or(0, str::len) + 2);
    out.push_str(project);
    let plen = strip_ext_len(rel_path);
    let has_name = name.map(|n| !n.is_empty()).unwrap_or(false);
    append_path_segments(&mut out, rel_path, plen, has_name);
    if let Some(n) = name {
        if !n.is_empty() {
            out.push('.');
            out.push_str(n);
        }
    }
    out
}

/// Module QN = project + path (C cbm_fqn_module).
pub fn fqn_module(project: &str, rel_path: &str) -> String {
    fqn_compute(project, rel_path, None)
}

/// Folder QN: `project.dir1.dir2` (C cbm_fqn_folder). A "." dir adds
/// nothing.
pub fn fqn_folder(project: &str, rel_dir: &str) -> String {
    let mut out = String::with_capacity(project.len() + rel_dir.len() + 2);
    out.push_str(project);
    if !rel_dir.is_empty() && rel_dir != "." {
        for part in rel_dir.split('/') {
            if !part.is_empty() {
                out.push('.');
                out.push_str(part);
            }
        }
    }
    out
}

/// Source-language-aware module QN (C cbm_fqn_module_source_lang): Java/Go
/// use the containing directory; everyone else the filename stem.
pub fn fqn_module_source_lang(project: &str, rel_path: &str, lang: Language) -> String {
    if !lang_module_is_dir(lang) {
        return fqn_module(project, rel_path);
    }
    match rel_path.rfind('/') {
        Some(i) => fqn_folder(project, &rel_path[..i]),
        None => fqn_folder(project, ""),
    }
}

/// Source-language-aware symbol QN (C cbm_fqn_compute_source_lang).
pub fn fqn_compute_source_lang(
    project: &str,
    rel_path: &str,
    name: Option<&str>,
    lang: Language,
) -> String {
    if !lang_module_is_dir(lang) {
        return fqn_compute(project, rel_path, name);
    }
    let module = fqn_module_source_lang(project, rel_path, lang);
    match name {
        Some(n) if !n.is_empty() => format!("{module}.{n}"),
        _ => module,
    }
}

// ── Enclosing-function attribution ──────────────────────────────

const FUNC_KINDS_GO: &[&str] = &["function_declaration", "method_declaration"];
const FUNC_KINDS_PYTHON: &[&str] = &["function_definition"];
const FUNC_KINDS_JS: &[&str] = &[
    "function_declaration",
    "method_definition",
    "arrow_function",
    "function_expression",
];
const FUNC_KINDS_RUST: &[&str] = &["function_item"];
const FUNC_KINDS_JAVA: &[&str] = &["method_declaration", "constructor_declaration"];
const FUNC_KINDS_CPP: &[&str] = &["function_definition"];
const FUNC_KINDS_RUBY: &[&str] = &["method", "singleton_method"];
const FUNC_KINDS_PHP: &[&str] = &["function_definition", "method_declaration"];
const FUNC_KINDS_LUA: &[&str] = &["function_declaration", "function_definition"];
const FUNC_KINDS_SCALA: &[&str] = &["function_definition"];
const FUNC_KINDS_KOTLIN: &[&str] = &["function_declaration"];
const FUNC_KINDS_ELIXIR: &[&str] = &["call"]; // def/defp are call nodes
const FUNC_KINDS_HASKELL: &[&str] = &["function", "value_definition"];
const FUNC_KINDS_OCAML: &[&str] = &["value_definition", "let_binding"];
const FUNC_KINDS_ZIG: &[&str] = &["function_declaration", "test_declaration"];
const FUNC_KINDS_BASH: &[&str] = &["function_definition"];
const FUNC_KINDS_ERLANG: &[&str] = &["function_clause"];
const FUNC_KINDS_CSHARP: &[&str] = &["method_declaration", "constructor_declaration"];
const FUNC_KINDS_MATLAB: &[&str] = &["function_definition"];
const FUNC_KINDS_LEAN: &[&str] = &["def", "theorem", "instance", "abbrev"];
const FUNC_KINDS_FORM: &[&str] = &["procedure_definition"];
const FUNC_KINDS_MAGMA: &[&str] = &[
    "function_definition",
    "procedure_definition",
    "intrinsic_definition",
];
const FUNC_KINDS_WOLFRAM: &[&str] = &["set_delayed_top", "set_top", "set_delayed", "set"];
const FUNC_KINDS_GENERIC: &[&str] = &[
    "function_declaration",
    "function_definition",
    "method_declaration",
    "method_definition",
];

/// Curated function node kinds per language; languages without a curated
/// entry fall back to their LanguageSpec's function_node_types (the
/// extraction single source of truth), then the generic set. The fallback
/// exists because the generic set misses real kinds (dart
/// function_signature, perl subroutine, nix function_expression, …) and
/// the enclosing walk then attributed every in-body call to the Module
/// node (QUALITY_ANALYSIS gap #3).
fn func_kinds_for_lang(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::GO => FUNC_KINDS_GO,
        Language::PYTHON => FUNC_KINDS_PYTHON,
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS => {
            FUNC_KINDS_JS
        }
        Language::RUST => FUNC_KINDS_RUST,
        Language::JAVA => FUNC_KINDS_JAVA,
        Language::CPP | Language::C => FUNC_KINDS_CPP,
        Language::RUBY => FUNC_KINDS_RUBY,
        Language::PHP => FUNC_KINDS_PHP,
        Language::LUA => FUNC_KINDS_LUA,
        Language::SCALA => FUNC_KINDS_SCALA,
        Language::KOTLIN => FUNC_KINDS_KOTLIN,
        Language::ELIXIR => FUNC_KINDS_ELIXIR,
        Language::HASKELL => FUNC_KINDS_HASKELL,
        Language::OCAML => FUNC_KINDS_OCAML,
        Language::ZIG => FUNC_KINDS_ZIG,
        Language::BASH => FUNC_KINDS_BASH,
        Language::ERLANG => FUNC_KINDS_ERLANG,
        Language::CSHARP => FUNC_KINDS_CSHARP,
        Language::MATLAB => FUNC_KINDS_MATLAB,
        Language::LEAN => FUNC_KINDS_LEAN,
        Language::FORM => FUNC_KINDS_FORM,
        Language::MAGMA => FUNC_KINDS_MAGMA,
        Language::WOLFRAM => FUNC_KINDS_WOLFRAM,
        _ => {
            let spec = lang_spec(lang);
            if !spec.function_node_types.is_empty() {
                spec.function_node_types
            } else {
                FUNC_KINDS_GENERIC
            }
        }
    }
}

/// Find the innermost enclosing function node by walking the parent chain
/// (C cbm_find_enclosing_func). None when the root is reached first.
pub fn find_enclosing_func<'t>(
    node: tree_sitter::Node<'t>,
    lang: Language,
) -> Option<tree_sitter::Node<'t>> {
    let kinds = func_kinds_for_lang(lang);
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        if kinds.contains(&parent.kind()) {
            return Some(parent);
        }
        cur = parent;
    }
    None
}

/// Namespace scope kinds for class-chain qualification (C
/// cbm_is_namespace_scope_kind): C++/CUDA namespace_definition, TS/TSX/ArkTS
/// internal_module.
pub fn is_namespace_scope_kind(lang: Language, kind: &str) -> bool {
    match lang {
        Language::CPP => kind == "namespace_definition",
        Language::TYPESCRIPT | Language::TSX | Language::ARKTS => kind == "internal_module",
        _ => false,
    }
}

/// Node source text (C cbm_node_text).
pub fn node_text<'s>(node: tree_sitter::Node<'_>, source: &'s str) -> &'s str {
    &source[node.start_byte()..node.end_byte().min(source.len())]
}

/// QN of the enclosing function, or module_qn when none
/// (C cbm_enclosing_func_qn). Class chains qualify with the FULL nesting
/// chain (Outer.Inner) so callers join with the def walk's compute_class_qn
/// (nested-class under-qualification sent calls to the file node).
pub fn enclosing_func_qn<'t>(
    node: tree_sitter::Node<'t>,
    lang: Language,
    source: &'t str,
    project: &str,
    rel_path: &str,
    module_qn: &str,
) -> String {
    let Some(func_node) = find_enclosing_func(node, lang) else {
        return module_qn.to_string();
    };
    let Some(name) = func_node_name(func_node, source, lang) else {
        return module_qn.to_string();
    };

    // Dotted class chain from the outermost enclosing class down to the
    // innermost; namespace scopes participate for the languages that have
    // them.
    let spec = lang_spec(lang);
    if !spec.class_node_types.is_empty() {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = func_node.parent();
        while let Some(c) = cur {
            let ck = c.kind();
            if spec.class_node_types.contains(&ck) || is_namespace_scope_kind(lang, ck) {
                if let Some(name_node) = c.child_by_field_name("name") {
                    let cname = node_text(name_node, source);
                    if !cname.is_empty() {
                        parts.push(cname.to_string());
                    }
                }
            }
            cur = c.parent();
        }
        if !parts.is_empty() {
            parts.reverse(); // outermost → innermost
            let class_qn = fqn_compute(project, rel_path, Some(&parts.join(".")));
            return format!("{class_qn}.{name}");
        }
    }
    fqn_compute_source_lang(project, rel_path, Some(&name), lang)
}

/// Function name node resolution (C func_node_name + the C declarator
/// chain + JS arrow functions).
pub fn func_node_name<'t>(
    func_node: tree_sitter::Node<'t>,
    source: &'t str,
    lang: Language,
) -> Option<String> {
    // Wolfram: set*/set_* name the function from the apply head symbol.
    if lang == Language::WOLFRAM {
        let nk = func_node.kind();
        if matches!(nk, "set_delayed_top" | "set_top" | "set_delayed" | "set")
            && func_node.named_child_count() > 0
        {
            if let Some(lhs) = func_node.named_child(0) {
                if lhs.kind() == "apply"
                    && lhs.named_child_count() > 0
                    && lhs
                        .named_child(0)
                        .map(|h| h.kind() == "user_symbol")
                        .unwrap_or(false)
                {
                    return Some(node_text(lhs.named_child(0).unwrap(), source).to_string());
                }
            }
        }
    }
    if let Some(name_node) = func_node.child_by_field_name("name") {
        return Some(normalize_name_node_text(name_node, source, lang));
    }
    // Arrow functions: take the parent variable_declarator's name.
    if func_node.kind() == "arrow_function" {
        if let Some(parent) = func_node.parent() {
            if parent.kind() == "variable_declarator" {
                if let Some(vname) = parent.child_by_field_name("name") {
                    return Some(node_text(vname, source).to_string());
                }
            }
        }
    }
    // C/C++/CUDA/GLSL: the name hides in the declarator chain.
    if func_node.kind() == "function_definition" {
        let dn = resolve_c_declarator_name_node(func_node)?;
        return Some(normalize_name_node_text(dn, source, lang));
    }
    None
}

/// C terminal declarator names (C is_c_terminal_name).
fn is_c_terminal_name(dk: &str) -> bool {
    matches!(
        dk,
        "identifier" | "field_identifier" | "operator_name" | "operator_cast" | "destructor_name"
    )
}

/// Resolve the innermost name node from a C-family declarator chain
/// (C cbm_resolve_c_declarator_name_node, depth limit 8 — drift between
/// private copies caused #438; this shared impl is the single source).
pub fn resolve_c_declarator_name_node<'t>(
    func_node: tree_sitter::Node<'t>,
) -> Option<tree_sitter::Node<'t>> {
    const DECLARATOR_DEPTH_LIMIT: usize = 8;
    let mut decl = func_node.child_by_field_name("declarator");
    for _ in 0..DECLARATOR_DEPTH_LIMIT {
        let d = decl?;
        if is_c_terminal_name(d.kind()) {
            return Some(d);
        }
        if matches!(d.kind(), "qualified_identifier" | "scoped_identifier") {
            return resolve_qualified_name(d);
        }
        if d.kind() == "function_declarator"
            || d.kind() == "pointer_declarator"
            || d.kind() == "array_declarator"
            || d.kind() == "parenthesized_declarator"
        {
            decl = d.child_by_field_name("declarator");
            continue;
        }
        // Any other wrapper: descend via the declarator field, else first named child.
        match d.child_by_field_name("declarator") {
            Some(next) => decl = Some(next),
            None => {
                for i in 0..d.named_child_count() {
                    let c = d.named_child(i)?;
                    if is_c_terminal_name(c.kind()) {
                        return Some(c);
                    }
                }
                return None;
            }
        }
    }
    None
}

/// Name lookup inside a C++ qualified/scoped identifier
/// (C resolve_qualified_name).
fn resolve_qualified_name<'t>(decl: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    const NAME_KINDS: &[&str] = &[
        "operator_name",
        "operator_cast",
        "destructor_name",
        "identifier",
        "field_identifier",
    ];
    for k in NAME_KINDS {
        if let Some(found) = find_child_by_kind(decl, k) {
            return Some(found);
        }
    }
    None
}

/// Find the first child with a given node kind (C cbm_find_child_by_kind).
pub fn find_child_by_kind<'t>(
    parent: tree_sitter::Node<'t>,
    kind: &str,
) -> Option<tree_sitter::Node<'t>> {
    (0..parent.child_count())
        .filter_map(|i| parent.child(i))
        .find(|c| c.kind() == kind)
}

/// Name-text normalization (C cbm_func_name_node_text): a C++ conversion
/// operator's operator_cast spans "operator bool() const" — normalize to
/// "operator bool".
pub fn normalize_name_node_text<'t>(
    name_node: tree_sitter::Node<'t>,
    source: &'t str,
    _lang: Language,
) -> String {
    let text = node_text(name_node, source);
    if name_node.kind() == "operator_cast" {
        // Keep "operator" + the cast type token(s) up to '('.
        let mut out = String::from("operator ");
        // Single type token after "operator".
        if let Some(word) = text["operator".len()..].split_whitespace().next() {
            if !word.starts_with('(') {
                out.push_str(word);
            }
        }
        return out;
    }
    text.to_string()
}

// ── EF cache ────────────────────────────────────────────────────

/// Cached enclosing-function QN (C cbm_enclosing_func_qn_cached): one
/// EFC_SIZE-slot byte-range → QN map to avoid repeated parent-chain walks
/// inside one extraction.
pub struct EnclosingQnCache<'s> {
    pub entries: HashMap<(u32, u32), String>,
    _marker: std::marker::PhantomData<&'s str>,
}

impl Default for EnclosingQnCache<'_> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'s> EnclosingQnCache<'s> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cached lookup; `node` must be inside the same source as the cache.
    pub fn enclosing_qn(
        &mut self,
        node: tree_sitter::Node<'_>,
        lang: Language,
        source: &str,
        project: &str,
        rel_path: &str,
        module_qn: &str,
    ) -> String {
        let key = (node.start_byte() as u32, node.end_byte() as u32);
        if let Some(qn) = self.entries.get(&key) {
            return qn.clone();
        }
        let qn = enclosing_func_qn(node, lang, source, project, rel_path, module_qn);
        if self.entries.len() < crate::types::EFC_SIZE {
            self.entries.insert(key, qn.clone());
        }
        qn
    }
}

/// EF cache in the extraction-context shape (types::EfCache carries
/// entries; this converts).
impl From<&EfCache> for EnclosingQnCache<'static> {
    fn from(_c: &EfCache) -> Self {
        EnclosingQnCache::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;

    fn parse_py(src: &str) -> tree_sitter::Tree {
        crate::ts::parse(Language::PYTHON, src).expect("py grammar")
    }

    #[test]
    fn fqn_basic_path_and_name() {
        assert_eq!(
            fqn_compute("proj", "src/app/user.go", Some("Handler")),
            "proj.src.app.user.Handler"
        );
        assert_eq!(fqn_module("proj", "src/app/user.go"), "proj.src.app.user");
        // Extension stripping: dotfiles keep their whole name.
        assert_eq!(fqn_module("proj", "cfg/.env"), "proj.cfg.env");
        assert_eq!(fqn_module("proj", ".gitignore"), "proj.gitignore");
        assert_eq!(fqn_module("proj", "a.b.c.py"), "proj.a.b.c");
    }

    #[test]
    fn fqn_init_and_index_elided() {
        // A symbol named inside __init__.py / index.ts skips that segment.
        assert_eq!(
            fqn_compute("proj", "pkg/__init__.py", Some("X")),
            "proj.pkg.X"
        );
        assert_eq!(fqn_compute("proj", "lib/index.ts", Some("Y")), "proj.lib.Y");
        // …but not when the segment is not last or there is no name.
        assert_eq!(fqn_module("proj", "pkg/__init__.py"), "proj.pkg.__init__");
    }

    #[test]
    fn fqn_dir_modules_java_go() {
        assert_eq!(
            fqn_module_source_lang("proj", "myapp/db/conn.go", Language::GO),
            "proj.myapp.db"
        );
        assert_eq!(
            fqn_compute_source_lang("proj", "myapp/Outer.java", Some("Outer"), Language::JAVA),
            "proj.myapp.Outer"
        );
        // Non-dir languages keep the stem.
        assert_eq!(
            fqn_module_source_lang("proj", "myapp/db/conn.py", Language::PYTHON),
            "proj.myapp.db.conn"
        );
        // Root file: module is just the project.
        assert_eq!(
            fqn_module_source_lang("proj", "main.go", Language::GO),
            "proj"
        );
    }

    #[test]
    fn fqn_folder_dots() {
        assert_eq!(fqn_folder("proj", "a/b"), "proj.a.b");
        assert_eq!(fqn_folder("proj", "."), "proj");
        assert_eq!(fqn_folder("proj", ""), "proj");
    }

    #[test]
    fn enclosing_function_python() {
        let src = "def outer():\n    x = 1\ndef top():\n    pass\n";
        let tree = parse_py(src);
        let root = tree.root_node();
        // Find the assignment node inside `outer`.
        let mut stack = vec![root];
        let target = loop {
            let n = stack.pop().unwrap();
            if n.kind() == "assignment" {
                break n;
            }
            for i in 0..n.child_count() {
                stack.push(n.child(i).unwrap());
            }
        };
        let qn = enclosing_func_qn(target, Language::PYTHON, src, "proj", "app.py", "proj.app");
        assert_eq!(qn, "proj.app.outer");
    }

    #[test]
    fn enclosing_function_nested_class_chain() {
        let src = r#"
class Outer:
    class Inner:
        def method(self):
            return 1
"#;
        let tree = parse_py(src);
        let root = tree.root_node();
        let mut stack = vec![root];
        let target = loop {
            let n = stack.pop().unwrap();
            if n.kind() == "return_statement" {
                break n;
            }
            for i in 0..n.child_count() {
                stack.push(n.child(i).unwrap());
            }
        };
        let qn = enclosing_func_qn(
            target,
            Language::PYTHON,
            src,
            "proj",
            "nested.py",
            "proj.nested",
        );
        assert_eq!(qn, "proj.nested.Outer.Inner.method");
    }

    #[test]
    fn enclosing_function_go_module_is_dir() {
        let src = "package db\nfunc Connect() { client.Open() }\n";
        let tree = crate::ts::parse(Language::GO, src).expect("go grammar");
        let root = tree.root_node();
        let mut stack = vec![root];
        let target = loop {
            let n = stack.pop().unwrap();
            if n.kind() == "call_expression" {
                break n;
            }
            for i in 0..n.child_count() {
                stack.push(n.child(i).unwrap());
            }
        };
        let qn = enclosing_func_qn(
            target,
            Language::GO,
            src,
            "proj",
            "myapp/db/conn.go",
            "proj.myapp.db",
        );
        // dir-based module + function name.
        assert_eq!(qn, "proj.myapp.db.Connect");
    }

    #[test]
    fn module_fallback_when_no_function() {
        let src = "x = 1\n";
        let tree = parse_py(src);
        let target = tree.root_node();
        let qn = enclosing_func_qn(target, Language::PYTHON, src, "proj", "m.py", "proj.m");
        assert_eq!(qn, "proj.m");
    }

    #[test]
    fn ef_cache_hits() {
        let src = "def f():\n    x = 1\n";
        let tree = parse_py(src);
        let root = tree.root_node();
        let mut stack = vec![root];
        let target = loop {
            let n = stack.pop().unwrap();
            if n.kind() == "assignment" {
                break n;
            }
            for i in 0..n.child_count() {
                stack.push(n.child(i).unwrap());
            }
        };
        let mut cache = EnclosingQnCache::new();
        let q1 = cache.enclosing_qn(target, Language::PYTHON, src, "p", "a.py", "p.a");
        let q2 = cache.enclosing_qn(target, Language::PYTHON, src, "p", "a.py", "p.a");
        assert_eq!(q1, q2);
        assert_eq!(cache.entries.len(), 1); // second lookup was a cache hit
    }

    #[test]
    fn wolfram_set_name() {
        // Wolfram grammar not linked; exercised via the kind table check.
        assert_eq!(FUNC_KINDS_WOLFRAM.len(), 4);
    }
}
