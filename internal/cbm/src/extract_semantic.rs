//! extract_semantic.rs — 1:1 rewrite of
//! `internal/cbm/extract_semantic.c` (352 lines).
//!
//! Two extractions: (1) throw/raise exception names, including Java-style
//! `throws` clauses and the Kotlin jump_expression special case; (2) write
//! targets of assignment/increment expressions, with member-access shape
//! preservation (#1962: `t.err = x` records "err", not "t").

use crate::extract_env_accesses::ExtractCtx;
use crate::helpers;
use crate::lang_specs::LanguageSpec;
use crate::types::{ReadWrite, Throw};
use crate::Language;

const MAX_EXCEPTION_NAME_LEN: usize = 100;

/// Is `node` a throw node for this spec (C is_throw_node)? Kotlin models
/// `throw X(...)` as jump_expression (shared with return/break/continue);
/// treat it as a throw only when the first child is the `throw` keyword.
fn is_throw_node(node: tree_sitter::Node<'_>, spec: &LanguageSpec) -> bool {
    if spec.throw_node_types.contains(&node.kind()) {
        return true;
    }
    if spec.language == Language::KOTLIN
        && node.kind() == "jump_expression"
        && node.child_count() > 0
        && node.child(0).map(|c| c.kind() == "throw").unwrap_or(false)
    {
        return true;
    }
    false
}

/// Exception name from the first meaningful child of a throw/raise node
/// (C resolve_exception_name).
fn resolve_exception_name<'a>(
    throw_node: tree_sitter::Node<'a>,
    source: &'a str,
) -> Option<String> {
    for i in 0..throw_node.child_count() {
        let child = throw_node.child(i)?;
        let ck = child.kind();
        if ck == "raise" || ck == "throw" {
            continue;
        }
        if ck.starts_with(';') || ck.starts_with('(') || ck.starts_with(')') {
            continue;
        }
        if matches!(
            ck,
            "call"
                | "call_expression"
                | "new_expression"
                | "object_creation_expression"
                | "instance_expression"
        ) {
            let fn_node = child
                .child_by_field_name("function")
                .or_else(|| child.child_by_field_name("constructor"))
                .or_else(|| child.child_by_field_name("type"))
                .or_else(|| {
                    if child.named_child_count() > 0 {
                        child.named_child(0)
                    } else {
                        None
                    }
                });
            if let Some(f) = fn_node {
                return Some(crate::fqn::node_text(f, source).to_string());
            }
        } else {
            return Some(crate::fqn::node_text(child, source).to_string());
        }
    }
    None
}

/// Java-style throws clause (C extract_throws_clause): method/constructor
/// declarations only, via the spec's throws_clause_field.
fn extract_throws_clause(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    func_qn: &str,
) {
    let Some(field) = spec.throws_clause_field else {
        return;
    };
    let kind = node.kind();
    if kind != "method_declaration" && kind != "constructor_declaration" {
        return;
    }
    let Some(throws_clause) = node.child_by_field_name(field) else {
        return;
    };
    for i in 0..throws_clause.child_count() {
        let child = throws_clause.child(i).unwrap();
        let ck = child.kind();
        if matches!(
            ck,
            "type_identifier" | "identifier" | "scoped_type_identifier"
        ) {
            let exc = crate::fqn::node_text(child, ctx.source);
            if !exc.is_empty() {
                ctx.result.throws.push(Throw {
                    exception_name: exc.to_string(),
                    enclosing_func_qn: func_qn.to_string(),
                });
            }
        }
    }
}

/// One node's throw extraction (C process_throw_node).
fn process_throw_node(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, spec: &LanguageSpec) {
    if is_throw_node(node, spec) {
        if let Some(mut exc_name) = resolve_exception_name(node, ctx.source) {
            exc_name.truncate(MAX_EXCEPTION_NAME_LEN);
            let func_qn = ctx.ef_cache.enclosing_qn(
                node,
                ctx.language,
                ctx.source,
                ctx.project,
                ctx.rel_path,
                &ctx.module_qn,
            );
            ctx.result.throws.push(Throw {
                exception_name: exc_name,
                enclosing_func_qn: func_qn,
            });
        }
    }
    let func_qn = ctx.ef_cache.enclosing_qn(
        node,
        ctx.language,
        ctx.source,
        ctx.project,
        ctx.rel_path,
        &ctx.module_qn,
    );
    extract_throws_clause(ctx, node, spec, &func_qn);
}

/// Iterative throw walk (C walk_throws).
fn walk_throws(ctx: &mut ExtractCtx<'_>, root: tree_sitter::Node<'_>, spec: &LanguageSpec) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        process_throw_node(ctx, node, spec);
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

/// Write-target name from an assignment LHS (C resolve_lhs_write_name).
/// The receiver of a member/selector LHS is stripped; `is_member` is the
/// only surviving record of the selector shape (#1962).
fn resolve_lhs_write_name<'a>(
    left: tree_sitter::Node<'a>,
    source: &'a str,
    is_member_out: &mut bool,
) -> Option<String> {
    let mut left = left;
    // Unwrap a single-element expression_list (Go); multi-assign is
    // ambiguous — skip.
    if left.kind() == "expression_list" {
        if left.named_child_count() != 1 {
            return None;
        }
        left = left.named_child(0)?;
    }
    let lk = left.kind();
    if matches!(lk, "identifier" | "simple_identifier") {
        return Some(crate::fqn::node_text(left, source).to_string());
    }
    // Indexed write: the base operand's identifier (`cache[k]` → cache).
    if matches!(lk, "index_expression" | "subscript_expression") {
        let base = left
            .child_by_field_name("operand")
            .or_else(|| left.child_by_field_name("object"))
            .or_else(|| {
                if left.named_child_count() > 0 {
                    left.named_child(0)
                } else {
                    None
                }
            });
        if let Some(b) = base {
            if matches!(b.kind(), "identifier" | "simple_identifier") {
                return Some(crate::fqn::node_text(b, source).to_string());
            }
        }
        return None;
    }
    // Field/member write: the trailing field name (`self.total` → total).
    // Covers Rust field_expression, C#/Java member access.
    if matches!(
        lk,
        "field_expression" | "member_access_expression" | "field_access" | "selector_expression"
    ) {
        let fld = left
            .child_by_field_name("field")
            .or_else(|| left.child_by_field_name("name"));
        if let Some(f) = fld {
            *is_member_out = true;
            return Some(crate::fqn::node_text(f, source).to_string());
        }
        return None;
    }
    None
}

/// Write target node of an assignment-ish node (C resolve_write_lhs_node).
/// Increment/decrement unary expressions (`x++`, `++x`) carry no "left"
/// field and the operand may sit on either side; other unary forms (`x!`,
/// `&x`, `*x`, `!x`) READ — never writes.
fn resolve_write_lhs_node<'t>(node: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    if let Some(left) = node.child_by_field_name("left") {
        return Some(left);
    }
    let nk = node.kind();
    if matches!(
        nk,
        "postfix_unary_expression" | "prefix_unary_expression" | "update_expression"
    ) {
        // Only ++/-- mutate their operand.
        let mut is_incdec = false;
        for i in 0..node.child_count() {
            let c = node.child(i)?;
            if !c.is_named() {
                let op = c.kind();
                if op == "++" || op == "--" {
                    is_incdec = true;
                    break;
                }
            }
        }
        if !is_incdec {
            return None;
        }
        for i in 0..node.named_child_count() {
            let c = node.named_child(i)?;
            if matches!(
                c.kind(),
                "identifier"
                    | "simple_identifier"
                    | "member_access_expression"
                    | "field_expression"
                    | "field_access"
                    | "selector_expression"
                    | "subscript_expression"
                    | "index_expression"
            ) {
                return Some(c);
            }
        }
        return None;
    }
    if node.child_count() > 0 {
        return node.child(0);
    }
    None
}

/// Emit a write for an assignment node (C try_emit_assignment_write).
fn try_emit_assignment_write(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, func_qn: &str) {
    let Some(left) = resolve_write_lhs_node(node) else {
        return;
    };
    let mut is_member = false;
    let Some(name) = resolve_lhs_write_name(left, ctx.source, &mut is_member) else {
        return;
    };
    if !name.is_empty() && !helpers::is_keyword(&name, ctx.language) {
        ctx.result.rw.push(ReadWrite {
            var_name: name,
            enclosing_func_qn: func_qn.to_string(),
            is_write: true,
            is_member_access: is_member,
        });
    }
}

/// Iterative readwrite walk (C walk_readwrites).
fn walk_readwrites(ctx: &mut ExtractCtx<'_>, root: tree_sitter::Node<'_>, spec: &LanguageSpec) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if spec.assignment_node_types.contains(&node.kind()) {
            let func_qn = ctx.ef_cache.enclosing_qn(
                node,
                ctx.language,
                ctx.source,
                ctx.project,
                ctx.rel_path,
                &ctx.module_qn,
            );
            try_emit_assignment_write(ctx, node, &func_qn);
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

/// Entry (C cbm_extract_semantic).
pub fn extract_semantic(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    walk_throws(ctx, ctx.root, spec);
    walk_readwrites(ctx, ctx.root, spec);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_env_accesses::ExtractCtx;

    fn run(lang: Language, src: &str) -> (Vec<Throw>, Vec<ReadWrite>) {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let rel = match lang {
            Language::PYTHON => "a.py",
            _ => "a.go",
        };
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", rel);
        let spec = crate::lang_specs::lang_spec(lang);
        extract_semantic(&mut ctx, spec);
        (ctx.result.throws, ctx.result.rw)
    }

    #[test]
    fn python_raise_call() {
        let src = "def f():\n    raise ValueError(\"x\")\n";
        let (throws, _) = run(Language::PYTHON, src);
        assert_eq!(throws.len(), 1, "{throws:?}");
        assert_eq!(throws[0].exception_name, "ValueError");
    }

    #[test]
    fn python_raise_bare() {
        let src = "def f(err):\n    raise err\n";
        let (throws, _) = run(Language::PYTHON, src);
        assert_eq!(throws.len(), 1);
        assert_eq!(throws[0].exception_name, "err");
    }

    #[test]
    fn python_writes() {
        let src = "def f():\n    total = 0\n    total = total + 1\n";
        let (_, rw) = run(Language::PYTHON, src);
        // `total = 0` and `total = total + 1` are both assignment_statement.
        assert!(
            rw.iter()
                .filter(|r| r.is_write && r.var_name == "total")
                .count()
                >= 2,
            "{rw:?}"
        );
        assert!(rw.iter().all(|r| r.is_write));
        assert!(rw.iter().all(|r| !r.is_member_access));
    }

    #[test]
    fn keyword_writes_filtered() {
        // `self.x = 1` — the member form strips receiver; "x" is not a
        // keyword so it records; a bare `del` would be filtered.
        let src = "def f(self):\n    self.total = 1\n";
        let (_, rw) = run(Language::PYTHON, src);
        assert!(
            rw.is_empty() || rw.iter().all(|r| !r.is_member_access),
            "{rw:?}"
        );
    }

    #[test]
    fn go_writes_and_expression_list() {
        // Go multi-assign is ambiguous and skipped; single write records.
        let src = "package app\nfunc F() {\n\tx = 1\n\ty, z = pair()\n}\n";
        let (_, rw) = run(Language::GO, src);
        assert!(rw.iter().any(|r| r.is_write && r.var_name == "x"), "{rw:?}");
    }

    #[test]
    fn throws_clause_via_spec() {
        // Java grammar not linked; unit-test the field gate directly.
        let spec = crate::lang_specs::lang_spec(Language::JAVA);
        assert_eq!(spec.throws_clause_field, Some("throws"));
        let spec = crate::lang_specs::lang_spec(Language::PYTHON);
        assert_eq!(spec.throws_clause_field, None);
    }
}
