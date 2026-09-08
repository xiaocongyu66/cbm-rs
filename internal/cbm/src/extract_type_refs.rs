//! extract_type_refs.rs — 1:1 rewrite of
//! `internal/cbm/extract_type_refs.c` (361 lines).
//!
//! Type-reference extraction for USES_TYPE edges: parameter types, return
//! types, and body-level references (casts, type assertions, generics,
//! typed variables) per language. Builtin types never generate edges.

use crate::extract_env_accesses::ExtractCtx;
use crate::lang_specs::LanguageSpec;
use crate::types::TypeRef;
use crate::Language;
use std::collections::HashSet;

/// Builtin types that should not generate USES_TYPE edges
/// (C is_builtin_type).
fn is_builtin_type(name: &str) -> bool {
    if name.is_empty() || name.len() <= 1 {
        return true;
    }
    matches!(
        name,
        "int"
            | "string"
            | "bool"
            | "float"
            | "float32"
            | "float64"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uintptr"
            | "byte"
            | "rune"
            | "void"
            | "char"
            | "double"
            | "long"
            | "short"
            | "unsigned"
            | "error"
            | "any"
            | "interface"
            | "object"
            | "Object"
            | "None"
            | "nil"
            | "null"
            | "undefined"
            | "number"
            | "boolean"
            | "str"
            | "dict"
            | "list"
            | "tuple"
            | "set"
            | "complex128"
            | "complex64"
    )
}

/// Strip pointer/reference/slice/optional markers and generic arguments
/// (C clean_type_name): skip leading `*`, `&`, `?`, `[`, `]`; cut at the
/// first `<` or `[`; drop a trailing `?`.
fn clean_type_name(name: &str) -> &str {
    let s = name.trim_start_matches(['*', '&', '?', '[', ']']);
    if s.is_empty() {
        return "";
    }
    if let Some(i) = s.find(['<', '[']) {
        return &s[..i];
    }
    s.strip_suffix('?').unwrap_or(s)
}

/// Extract the type name from a type-annotation node, unwrapping wrapper
/// nodes up to 8 levels (C extract_type_text).
fn extract_type_text<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> String {
    let mut node = node;
    const MAX_UNWRAP: usize = 8;
    for _ in 0..MAX_UNWRAP {
        let kind = node.kind();
        if matches!(
            kind,
            "type_identifier" | "identifier" | "simple_identifier" | "name"
        ) {
            return clean_type_name(crate::fqn::node_text(node, source)).to_string();
        }
        if matches!(kind, "generic_type" | "parameterized_type") && node.child_count() > 0 {
            return clean_type_name(crate::fqn::node_text(node.child(0).unwrap(), source))
                .to_string();
        }
        if matches!(
            kind,
            "pointer_type" | "reference_type" | "slice_type" | "array_type"
        ) {
            if let Some(elem) = node.child_by_field_name("element") {
                node = elem;
                continue;
            }
            if let Some(t) = node.child_by_field_name("type") {
                node = t;
                continue;
            }
        }
        break;
    }
    clean_type_name(crate::fqn::node_text(node, source)).to_string()
}

/// Add a type reference for a function (C add_type_ref).
fn add_type_ref(ctx: &mut ExtractCtx<'_>, type_name: &str, func_qn: &str) {
    if type_name.is_empty() {
        return;
    }
    let cleaned = clean_type_name(type_name);
    if cleaned.is_empty() || is_builtin_type(cleaned) {
        return;
    }
    ctx.result.type_refs.push(TypeRef {
        type_name: cleaned.to_string(),
        enclosing_func_qn: func_qn.to_string(),
    });
}

/// Parameter types from a parameters/formal_parameters node
/// (C extract_param_type_refs).
fn extract_param_type_refs(ctx: &mut ExtractCtx<'_>, params: tree_sitter::Node<'_>, func_qn: &str) {
    for i in 0..params.child_count() {
        let child = params.child(i).unwrap();
        if let Some(type_node) = child.child_by_field_name("type") {
            let tname = extract_type_text(type_node, ctx.source);
            add_type_ref(ctx, &tname, func_qn);
        }
    }
}

/// Return type references: first present field among result/return_type/type
/// (C extract_return_type_refs).
fn extract_return_type_refs(
    ctx: &mut ExtractCtx<'_>,
    func_node: tree_sitter::Node<'_>,
    func_qn: &str,
) {
    for f in ["result", "return_type", "type"] {
        if let Some(rt) = func_node.child_by_field_name(f) {
            let tname = extract_type_text(rt, ctx.source);
            add_type_ref(ctx, &tname, func_qn);
            break;
        }
    }
}

/// Type ref from a node whose "type" field holds the type
/// (C extract_type_field_ref).
fn extract_type_field_ref(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, func_qn: &str) {
    if let Some(type_node) = node.child_by_field_name("type") {
        let tname = extract_type_text(type_node, ctx.source);
        add_type_ref(ctx, &tname, func_qn);
    }
}

/// TS/JS body refs: as_expression / satisfies_expression / type_arguments /
/// variable_declarator type annotations (C extract_ts_body_type_refs).
fn extract_ts_body_type_refs(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    kind: &str,
    func_qn: &str,
) {
    if matches!(kind, "as_expression" | "satisfies_expression") {
        extract_type_field_ref(ctx, node, func_qn);
    } else if kind == "type_arguments" {
        for i in 0..node.child_count() {
            let child = node.child(i).unwrap();
            if matches!(child.kind(), "type_identifier" | "identifier") {
                add_type_ref(ctx, crate::fqn::node_text(child, ctx.source), func_qn);
            }
        }
    } else if kind == "variable_declarator" {
        for i in 0..node.child_count() {
            let child = node.child(i).unwrap();
            if child.kind() == "type_annotation" && child.child_count() > 0 {
                let inner = child.child(child.child_count() - 1).unwrap();
                let tname = extract_type_text(inner, ctx.source);
                add_type_ref(ctx, &tname, func_qn);
            }
        }
    }
}

/// Java body refs: generic_type children (C extract_java_body_type_refs).
fn extract_java_body_type_refs(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    kind: &str,
    func_qn: &str,
) {
    if kind == "generic_type" {
        for i in 0..node.named_child_count() {
            let child = node.named_child(i).unwrap();
            add_type_ref(ctx, crate::fqn::node_text(child, ctx.source), func_qn);
        }
    }
}

/// Body-level type reference for one node (C process_body_type_ref).
fn process_body_type_ref(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, func_qn: &str) {
    let kind = node.kind();
    match ctx.language {
        Language::GO => {
            if matches!(
                kind,
                "var_spec" | "type_assertion" | "type_conversion_expression" | "composite_literal"
            ) {
                extract_type_field_ref(ctx, node, func_qn);
            }
        }
        Language::TYPESCRIPT | Language::TSX | Language::ARKTS => {
            extract_ts_body_type_refs(ctx, node, kind, func_qn);
        }
        Language::JAVA => {
            extract_java_body_type_refs(ctx, node, kind, func_qn);
        }
        Language::PYTHON => {
            if kind == "assignment" {
                if let Some(type_node) = node.child_by_field_name("type") {
                    add_type_ref(ctx, crate::fqn::node_text(type_node, ctx.source), func_qn);
                }
            }
        }
        Language::RUST => {
            if matches!(kind, "let_declaration" | "type_cast_expression") {
                extract_type_field_ref(ctx, node, func_qn);
            }
        }
        _ => {}
    }
}

/// Walk a function body for type references (C walk_body_type_refs).
fn walk_body_type_refs(ctx: &mut ExtractCtx<'_>, root: tree_sitter::Node<'_>, func_qn: &str) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        process_body_type_ref(ctx, node, func_qn);
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

/// Process one function node: signature + body (C process_func_type_refs).
fn process_func_type_refs(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let func_name = crate::fqn::node_text(name_node, ctx.source);
    if func_name.is_empty() {
        return;
    }
    let func_qn = crate::fqn::fqn_compute(ctx.project, ctx.rel_path, Some(func_name));
    if let Some(params) = node.child_by_field_name("parameters") {
        extract_param_type_refs(ctx, params, &func_qn);
    }
    extract_return_type_refs(ctx, node, &func_qn);
    let body = node
        .child_by_field_name("body")
        .or_else(|| node.child_by_field_name("block"));
    if let Some(body) = body {
        walk_body_type_refs(ctx, body, &func_qn);
    }
}

/// Walk the AST for function nodes (C walk_type_refs).
pub fn extract_type_refs(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    if spec.function_node_types.is_empty() {
        return;
    }
    // Signature-only handling for nested functions would double-walk
    // bodies via the outer walk (C: `continue` prevents descending into
    // function children).
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        if spec.function_node_types.contains(&node.kind()) {
            process_func_type_refs(ctx, node);
            continue;
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

/// Dedup helper for tests: unique type names seen.
#[cfg(test)]
pub fn unique_type_names(refs: &[TypeRef]) -> HashSet<&str> {
    refs.iter().map(|r| r.type_name.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_env_accesses::ExtractCtx;

    fn run(lang: Language, src: &str) -> Vec<TypeRef> {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", "a.go");
        let spec = crate::lang_specs::lang_spec(lang);
        extract_type_refs(&mut ctx, spec);
        ctx.result.type_refs
    }

    #[test]
    fn builtin_types_filtered() {
        assert!(is_builtin_type("int"));
        assert!(is_builtin_type("string"));
        assert!(is_builtin_type("Object"));
        assert!(is_builtin_type("nil"));
        // Single-char names filtered by length too.
        assert!(is_builtin_type("T"));
        assert!(!is_builtin_type("UserService"));
        assert!(!is_builtin_type("MyStruct"));
    }

    #[test]
    fn clean_type_name_markers() {
        assert_eq!(clean_type_name("*User"), "User");
        assert_eq!(clean_type_name("[]byte"), "byte"); // builtin filter catches later
        assert_eq!(clean_type_name("&Config"), "Config");
        assert_eq!(clean_type_name("Vec<User>"), "Vec");
        assert_eq!(clean_type_name("str?"), "str");
        assert_eq!(clean_type_name(""), "");
    }

    #[test]
    fn probe_refs() {
        let src = "package app\nfunc Process(u *User, repo Repo) (*Result, error) {\n    return nil, nil\n}\n";
        let refs = run(Language::GO, src);
        for r in &refs {
            eprintln!("DBG {:?} @ {}", r.type_name, r.enclosing_func_qn);
        }
    }

    #[test]
    fn go_param_and_return_types() {
        let src = r#"
package app

func Process(u *User, repo Repo) (*Result, error) {
    return nil, nil
}
"#;
        let refs = run(Language::GO, src);
        let names = unique_type_names(&refs);
        assert!(names.contains("User"), "got {names:?}");
        assert!(names.contains("Repo"));
        // error/nil builtins filtered.
        assert!(!names.contains("error"));
        // error/nil builtins filtered; the result tuple extracts under the
        // same function QN (blob text may clean to a partial name).
        assert!(refs
            .iter()
            .all(|r| r.enclosing_func_qn.starts_with("proj.a.Process")));
    }

    #[test]
    fn go_body_type_refs() {
        let src = r#"
package app

func Run(v interface{}) {
    u := v.(*User)
    var cfg Config
    _ = u
    _ = cfg
}
"#;
        let refs = run(Language::GO, src);
        let names = unique_type_names(&refs);
        // NOTE: the C table matches kind "type_assertion", but
        // tree-sitter-go's node is "type_assertion_expression" — the same
        // drift exists upstream, so v.(*User) extracts nothing here. The
        // var_spec path does fire.
        assert!(names.contains("Config"), "var_spec — got {names:?}");
        assert!(
            !names.contains("User"),
            "upstream kind drift preserved — got {names:?}"
        );
        // interface{} passes through (C's builtin list has "interface" but
        // the grammar produces the compound "interface{}").
        assert!(names.contains("interface{}"), "got {names:?}");
    }
}
