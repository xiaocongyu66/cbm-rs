//! extract_type_assigns.rs — 1:1 rewrite of
//! `internal/cbm/extract_type_assigns.c` (212 lines).
//!
//! Constructor-assignment extraction: `x := NewFoo()` / `x = new Foo()` /
//! `let x = Foo {}` — pairs a variable with the class/type constructed on
//! the RHS. Includes the typed-stub factory heuristic
//! (`pb.NewFooClient`, `fooGrpc.newBlockingStub`) for Go/Java gRPC shapes.

use crate::extract_env_accesses::ExtractCtx;
use crate::lang_specs::LanguageSpec;
use crate::types::TypeAssign;
use crate::Language;

/// Type from new_expression / object_creation_expression
/// (C extract_new_expr_type).
fn extract_new_expr_type<'a>(rhs: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if let Some(type_node) = rhs.child_by_field_name("type") {
        let tk = type_node.kind();
        if matches!(tk, "type_identifier" | "identifier" | "simple_identifier") {
            return Some(crate::fqn::node_text(type_node, source).to_string());
        }
        if tk == "generic_type" && type_node.child_count() > 0 {
            return Some(crate::fqn::node_text(type_node.child(0)?, source).to_string());
        }
        return Some(crate::fqn::node_text(type_node, source).to_string());
    }
    // Fallback: first identifier-ish child.
    for i in 0..rhs.child_count() {
        let child = rhs.child(i)?;
        if matches!(
            child.kind(),
            "identifier" | "type_identifier" | "simple_identifier"
        ) {
            return Some(crate::fqn::node_text(child, source).to_string());
        }
    }
    None
}

/// Class/type name from a constructor expression (C
/// extract_constructor_type): new Foo() → Foo; Foo() → Foo (uppercase
/// only); Go composite_literal type; Rust struct_expression name; plus the
/// lowercase package-prefix factory pattern.
fn extract_constructor_type<'a>(
    rhs: tree_sitter::Node<'a>,
    source: &'a str,
    lang: Language,
) -> Option<String> {
    let kind = rhs.kind();

    if matches!(kind, "new_expression" | "object_creation_expression") {
        return extract_new_expr_type(rhs, source);
    }

    if matches!(kind, "call" | "call_expression") {
        let func = rhs.child_by_field_name("function").or_else(|| {
            if rhs.child_count() > 0 {
                rhs.child(0)
            } else {
                None
            }
        })?;
        let fname = crate::fqn::node_text(func, source);
        if fname
            .as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_uppercase())
        {
            return Some(fname.to_string());
        }
        // Lower-cased package prefix: `pb.NewFooClient(...)`,
        // `fooGrpc.newBlockingStub(...)` — accept when the last segment
        // matches a typed-stub factory pattern.
        let last = fname.rsplit('.').next().unwrap_or(fname);
        if (last.starts_with("New") || last.starts_with("new")) && last.len() > 3 {
            let is_factory = (last.len() > 6 && last.ends_with("Client"))
                || (last.len() > 4 && last.ends_with("Stub"));
            if is_factory {
                return Some(fname.to_string());
            }
        }
    }

    if kind == "composite_literal" {
        if let Some(type_node) = rhs.child_by_field_name("type") {
            return Some(crate::fqn::node_text(type_node, source).to_string());
        }
    }

    if lang == Language::RUST && kind == "struct_expression" {
        if let Some(name) = rhs.child_by_field_name("name") {
            return Some(crate::fqn::node_text(name, source).to_string());
        }
    }

    None
}

/// Emit when both var name and constructor type are valid
/// (C try_emit_type_assign).
fn try_emit(
    ctx: &mut ExtractCtx<'_>,
    var_node: tree_sitter::Node<'_>,
    rhs_node: tree_sitter::Node<'_>,
    func_qn: &str,
) {
    let var_name = crate::fqn::node_text(var_node, ctx.source);
    let Some(type_name) = extract_constructor_type(rhs_node, ctx.source, ctx.language) else {
        return;
    };
    if !var_name.is_empty() && !type_name.is_empty() {
        ctx.result.type_assigns.push(TypeAssign {
            var_name: var_name.to_string(),
            type_name,
            enclosing_func_qn: func_qn.to_string(),
        });
    }
}

/// Assignment nodes with left/right (or value) fields
/// (C process_assignment_type_assign).
fn process_assignment(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, func_qn: &str) {
    let left = node.child_by_field_name("left");
    let right = node
        .child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"));
    if let (Some(l), Some(r)) = (left, right) {
        if matches!(l.kind(), "identifier" | "simple_identifier") {
            try_emit(ctx, l, r, func_qn);
        }
    }
}

/// Go short_var_declaration / var_spec (C process_go_var_type_assign).
fn process_go_var(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, func_qn: &str) {
    let left = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("left"));
    let right = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("right"));
    if let (Some(l), Some(r)) = (left, right) {
        try_emit(ctx, l, r, func_qn);
    }
}

/// JS/TS variable_declarator (C process_declarator_type_assign).
fn process_declarator(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, func_qn: &str) {
    let name_node = node.child_by_field_name("name");
    let value_node = node.child_by_field_name("value");
    if let (Some(n), Some(v)) = (name_node, value_node) {
        if matches!(n.kind(), "identifier" | "simple_identifier") {
            try_emit(ctx, n, v, func_qn);
        }
    }
}

/// Rust let_declaration (C process_rust_let_type_assign).
fn process_rust_let(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, func_qn: &str) {
    let pat = node.child_by_field_name("pattern");
    let val = node.child_by_field_name("value");
    if let (Some(p), Some(v)) = (pat, val) {
        if p.kind() == "identifier" {
            try_emit(ctx, p, v, func_qn);
        }
    }
}

/// One node: dispatch by kind (C process_type_assign_node).
fn process_node(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    func_qn: &str,
) {
    let kind = node.kind();
    if spec.assignment_node_types.contains(&kind) {
        process_assignment(ctx, node, func_qn);
    }
    if matches!(kind, "short_var_declaration" | "var_spec") {
        process_go_var(ctx, node, func_qn);
    }
    if kind == "variable_declarator" {
        process_declarator(ctx, node, func_qn);
    }
    if kind == "let_declaration" && ctx.language == Language::RUST {
        process_rust_let(ctx, node, func_qn);
    }
}

/// Unified-walk single-node handler (C handle_type_assigns).
pub fn extract_type_assigns_at(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    func_qn: &str,
) {
    process_node(ctx, node, spec, func_qn);
}

/// Walk AST (C walk_type_assigns): every node's enclosing QN via the cache.
pub fn extract_type_assigns(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        let func_qn = ctx.ef_cache.enclosing_qn(
            node,
            ctx.language,
            ctx.source,
            ctx.project,
            ctx.rel_path,
            &ctx.module_qn,
        );
        process_node(ctx, node, spec, &func_qn);
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_env_accesses::ExtractCtx;

    fn run(lang: Language, src: &str) -> Vec<TypeAssign> {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", "a.go");
        let spec = crate::lang_specs::lang_spec(lang);
        extract_type_assigns(&mut ctx, spec);
        ctx.result.type_assigns
    }

    #[test]
    fn go_upstream_expression_list_barrier() {
        // GO's short_var_declaration right field is an expression_list, so
        // extract_constructor_type sees the list (not a call) and — exactly
        // like the C original — emits nothing. Preserved behavior.
        let src = "package app\nfunc F(conn Conn) {\n\tclient := pb.NewUserClient(conn)\n\t_ = client\n}\n";
        let tas = run(Language::GO, src);
        assert!(tas.is_empty(), "upstream barrier preserved: {tas:?}");
    }

    #[test]
    fn python_constructor_call() {
        // Python: x = Foo() — assignment_node_types includes
        // assignment_statement, uppercase call → recorded.
        let src = "def f():\n    x = Foo()\n    return x\n";
        let tree = crate::ts::parse(Language::PYTHON, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), Language::PYTHON, "proj", "a.py");
        let spec = crate::lang_specs::lang_spec(Language::PYTHON);
        extract_type_assigns(&mut ctx, spec);
        let tas = ctx.result.type_assigns;
        assert_eq!(tas.len(), 1, "{tas:?}");
        assert_eq!(tas[0].var_name, "x");
        assert_eq!(tas[0].type_name, "Foo");
    }

    #[test]
    fn python_lowercase_rejected() {
        let src = "def f():\n    x = compute()\n    return x\n";
        let tree = crate::ts::parse(Language::PYTHON, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), Language::PYTHON, "proj", "a.py");
        let spec = crate::lang_specs::lang_spec(Language::PYTHON);
        extract_type_assigns(&mut ctx, spec);
        assert!(ctx.result.type_assigns.is_empty());
    }
}
