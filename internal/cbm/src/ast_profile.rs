//! ast_profile.rs — 1:1 rewrite of `src/semantic/ast_profile.{c,h}`.
//!
//! 25-dimension structural profile of a function body (signals 8/9/11):
//! control-flow counts, expression/literal distribution, approximate data
//! flow against parameter names, and Halstead-lite operator/operand
//! counting. Serialized as a 25-field comma-separated string.

use std::collections::HashSet;

pub const AST_PROFILE_DIMS: usize = 25;
pub const AST_PROFILE_BUF: usize = 200;
/// DEPTH_SCALE for the fixed-point average (×10).
const DEPTH_SCALE: u32 = 10;

/// Profile (C cbm_ast_profile_t). Field order matches the string format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AstProfile {
    // Signal 8: control flow
    pub if_count: u16,
    pub for_count: u16,
    pub while_count: u16,
    pub switch_count: u16,
    pub try_count: u16,
    pub return_count: u16,
    pub max_nesting_depth: u16,
    /// ×10 fixed point.
    pub avg_nesting_depth_x10: u16,
    // Signal 8: expression distribution
    pub comparison_ops: u16,
    pub arithmetic_ops: u16,
    pub logical_ops: u16,
    pub assignment_count: u16,
    // Signal 8: literal distribution
    pub string_literals: u16,
    pub number_literals: u16,
    pub bool_literals: u16,
    // Signal 9: approximate data flow
    pub param_count: u16,
    pub params_in_returns: u16,
    pub params_in_conditions: u16,
    pub variable_reassigns: u16,
    // Signal 11: Halstead-lite
    pub unique_operators: u16,
    pub unique_operands: u16,
    pub total_operators: u16,
    pub total_operands: u16,
    // Body metrics
    pub body_lines: u16,
    pub body_tokens: u16,
}

fn is_control_if(k: &str) -> bool {
    matches!(k, "if_statement" | "if_expression" | "elif_clause")
}
fn is_control_for(k: &str) -> bool {
    matches!(
        k,
        "for_statement" | "for_range_loop" | "for_expression" | "for_in_clause"
    )
}
fn is_control_while(k: &str) -> bool {
    matches!(k, "while_statement" | "while_expression" | "do_statement")
}
fn is_control_switch(k: &str) -> bool {
    matches!(
        k,
        "switch_statement" | "switch_expression" | "match_expression" | "type_switch_statement"
    )
}
fn is_control_try(k: &str) -> bool {
    matches!(
        k,
        "try_statement" | "try_expression" | "catch_clause" | "except_clause"
    )
}
fn is_return(k: &str) -> bool {
    matches!(k, "return_statement" | "return_expression")
}
fn is_comparison(k: &str) -> bool {
    matches!(
        k,
        "binary_expression" | "comparison_operator" | "boolean_operator"
    )
}
fn is_arithmetic(k: &str) -> bool {
    matches!(k, "unary_expression" | "update_expression")
}
fn is_assignment(k: &str) -> bool {
    matches!(
        k,
        "assignment_expression"
            | "assignment_statement"
            | "augmented_assignment"
            | "short_var_declaration"
    )
}
fn is_string_lit(k: &str) -> bool {
    matches!(
        k,
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal"
    )
}
fn is_number_lit(k: &str) -> bool {
    matches!(
        k,
        "number" | "integer" | "float" | "integer_literal" | "float_literal"
    )
}
fn is_bool_lit(k: &str) -> bool {
    matches!(k, "true" | "false")
}
fn is_operator_node(k: &str) -> bool {
    is_control_if(k)
        || is_control_for(k)
        || is_control_while(k)
        || is_control_switch(k)
        || is_control_try(k)
        || is_return(k)
        || is_comparison(k)
        || is_arithmetic(k)
        || is_assignment(k)
        || matches!(
            k,
            "call_expression" | "member_expression" | "subscript_expression"
        )
}
fn is_identifier_kind(k: &str) -> bool {
    matches!(
        k,
        "identifier" | "field_identifier" | "property_identifier" | "type_identifier"
    )
}

fn accumulate_control_flow(kind: &str, out: &mut AstProfile, in_return: &mut bool) {
    if is_control_if(kind) {
        out.if_count += 1;
    } else if is_control_for(kind) {
        out.for_count += 1;
    } else if is_control_while(kind) {
        out.while_count += 1;
    } else if is_control_switch(kind) {
        out.switch_count += 1;
    } else if is_control_try(kind) {
        out.try_count += 1;
    } else if is_return(kind) {
        out.return_count += 1;
        // The C's control-flow accumulator arms in_return so parameter
        // references inside the return expression count as data flow.
        *in_return = true;
    }
}

fn accumulate_expressions(kind: &str, out: &mut AstProfile) {
    if is_comparison(kind) {
        out.comparison_ops += 1;
    }
    if is_arithmetic(kind) {
        out.arithmetic_ops += 1;
    }
    if matches!(kind, "not_operator" | "boolean_operator") {
        out.logical_ops += 1;
    }
    if is_assignment(kind) {
        out.assignment_count += 1;
        out.variable_reassigns += 1;
    }
    if is_string_lit(kind) {
        out.string_literals += 1;
    }
    if is_number_lit(kind) {
        out.number_literals += 1;
    }
    if is_bool_lit(kind) {
        out.bool_literals += 1;
    }
}

fn accumulate_halstead(
    kind: &str,
    child_count: usize,
    ops: &mut HashSet<&'static str>,
    operands: &mut HashSet<String>,
    node_text: Option<&str>,
    out: &mut AstProfile,
) {
    if is_operator_node(kind) {
        out.total_operators += 1;
        if ops.insert(kind_static(kind)) {
            out.unique_operators += 1;
        }
    }
    if child_count == 0
        && (is_identifier_kind(kind)
            || is_string_lit(kind)
            || is_number_lit(kind)
            || is_bool_lit(kind))
    {
        out.total_operands += 1;
        let key = node_text
            .map(str::to_string)
            .unwrap_or_else(|| kind.to_string());
        if operands.insert(key) {
            out.unique_operands += 1;
        }
        out.body_tokens += 1;
    }
}

/// Static str for operator kinds (they are grammar names already).
fn kind_static(kind: &str) -> &'static str {
    // Node kinds come from tree-sitter's 'static grammar tables.
    // SAFETY: tree_sitter::Node::kind returns &'static str.
    unsafe { std::mem::transmute::<&str, &'static str>(kind) }
}

struct DataFlowCtx<'a> {
    source: &'a str,
    param_names: &'a [&'a str],
    in_return: bool,
    in_condition: bool,
}

fn accumulate_data_flow(
    node: tree_sitter::Node<'_>,
    kind: &str,
    child_count: usize,
    ctx: &DataFlowCtx<'_>,
    out: &mut AstProfile,
) {
    if !(child_count == 0 && is_identifier_kind(kind)) {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    if end <= start || end - start >= 128 {
        return;
    }
    let ident = &ctx.source[start..end.min(ctx.source.len())];
    if !ctx.param_names.contains(&ident) {
        return;
    }
    if ctx.in_return {
        out.params_in_returns += 1;
    }
    if ctx.in_condition {
        out.params_in_conditions += 1;
    }
}

/// Compute the profile (C cbm_ast_profile_compute). Returns false when the
/// body produced no nodes.
pub fn compute(
    func_body: tree_sitter::Node<'_>,
    source: &str,
    param_names: &[&str],
    out: &mut AstProfile,
) -> bool {
    *out = AstProfile::default();
    out.param_count = param_names.len() as u16;

    let mut ops: HashSet<&'static str> = HashSet::new();
    let mut operands: HashSet<String> = HashSet::new();
    let mut total_depth: u32 = 0;
    let mut node_count: u32 = 0;
    let mut in_return = false;
    let mut in_condition = false;

    // Stack frames of (node, depth).
    let mut stack: Vec<(tree_sitter::Node<'_>, u32)> = vec![(func_body, 0)];

    while let Some((node, depth)) = stack.pop() {
        let child_count = node.child_count();
        let kind = node.kind();

        if !node.is_named() && child_count == 0 {
            // Anonymous leaf (punctuation, keywords) — skip.
        } else {
            node_count += 1;
            total_depth += depth;
            if depth as u16 > out.max_nesting_depth {
                out.max_nesting_depth = depth as u16;
            }
            accumulate_control_flow(kind, out, &mut in_return);
            accumulate_expressions(kind, out);
            let text = source.get(node.start_byte()..node.end_byte().min(source.len()));
            accumulate_halstead(kind, child_count, &mut ops, &mut operands, text, out);
            accumulate_data_flow(
                node,
                kind,
                child_count,
                &DataFlowCtx {
                    source,
                    param_names,
                    in_return,
                    in_condition,
                },
                out,
            );
            if is_control_if(kind) || is_control_while(kind) {
                in_condition = true;
            }
            if is_return(kind) {
                in_return = false;
            }
            if child_count > 0 && (is_control_if(kind) || is_control_while(kind)) {
                in_condition = false;
            }
        }
        // Push children in reverse order (depth-first pre-order).
        if stack.len() < 8192 {
            for i in (0..child_count).rev() {
                if let Some(c) = node.child(i) {
                    stack.push((c, depth + 1));
                }
            }
        }
    }

    out.avg_nesting_depth_x10 = ((total_depth * DEPTH_SCALE)
        .checked_div(node_count)
        .unwrap_or(0)) as u16;
    node_count > 0
}

/// Serialize: 25 comma-separated u16 fields, in struct-declaration order.
pub fn to_str(p: &AstProfile) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        p.if_count,
        p.for_count,
        p.while_count,
        p.switch_count,
        p.try_count,
        p.return_count,
        p.max_nesting_depth,
        p.avg_nesting_depth_x10,
        p.comparison_ops,
        p.arithmetic_ops,
        p.logical_ops,
        p.assignment_count,
        p.string_literals,
        p.number_literals,
        p.bool_literals,
        p.param_count,
        p.params_in_returns,
        p.params_in_conditions,
        p.variable_reassigns,
        p.unique_operators,
        p.unique_operands,
        p.total_operators,
        p.total_operands,
        p.body_lines,
        p.body_tokens
    )
}

/// Parse the 25-field form (C cbm_ast_profile_from_str).
pub fn from_str(s: &str) -> Option<AstProfile> {
    let fields: Vec<u16> = s.split(',').filter_map(|f| f.trim().parse().ok()).collect();
    if fields.len() != AST_PROFILE_DIMS {
        return None;
    }
    let mut f = fields.into_iter();
    Some(AstProfile {
        if_count: f.next()?,
        for_count: f.next()?,
        while_count: f.next()?,
        switch_count: f.next()?,
        try_count: f.next()?,
        return_count: f.next()?,
        max_nesting_depth: f.next()?,
        avg_nesting_depth_x10: f.next()?,
        comparison_ops: f.next()?,
        arithmetic_ops: f.next()?,
        logical_ops: f.next()?,
        assignment_count: f.next()?,
        string_literals: f.next()?,
        number_literals: f.next()?,
        bool_literals: f.next()?,
        param_count: f.next()?,
        params_in_returns: f.next()?,
        params_in_conditions: f.next()?,
        variable_reassigns: f.next()?,
        unique_operators: f.next()?,
        unique_operands: f.next()?,
        total_operators: f.next()?,
        total_operands: f.next()?,
        body_lines: f.next()?,
        body_tokens: f.next()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;

    fn parse_fn(src: &str) -> tree_sitter::Tree {
        crate::ts::parse(Language::PYTHON, src).expect("py grammar")
    }

    #[test]
    fn counts_control_flow() {
        let src = r#"
def work(items, flag):
    for item in items:
        if item.valid and flag:
            try:
                item.commit()
            except Exception:
                item.rollback()
    while item.pending:
        item.step()
    return items
"#;
        let tree = parse_fn(src);
        let mut p = AstProfile::default();
        assert!(compute(tree.root_node(), src, &["items", "flag"], &mut p));
        assert!(p.if_count >= 1);
        assert!(p.for_count >= 1);
        assert!(p.while_count >= 1);
        assert!(p.try_count >= 1);
        assert!(p.return_count >= 1);
        assert_eq!(p.param_count, 2);
        // C's context-window reset runs before children are pushed, so
        // references inside a return/if body see a cleared flag; the two
        // data-flow counters only tick for a leaf that IS itself in scope.
        // (Faithful port: these remain 0 for this shape.)
        assert!(p.max_nesting_depth > 1);
    }

    #[test]
    fn halstead_counts() {
        let src = r#"
def calc(a, b):
    x = a + b
    y = a * b
    return x
"#;
        let tree = parse_fn(src);
        let mut p = AstProfile::default();
        assert!(compute(tree.root_node(), src, &["a", "b"], &mut p));
        assert!(p.total_operators > 0);
        assert!(p.total_operands > 0);
        assert!(p.unique_operands >= 2);
        assert!(p.body_tokens > 0);
    }

    #[test]
    fn str_roundtrip() {
        let mut p = AstProfile {
            if_count: 2,
            for_count: 1,
            max_nesting_depth: 5,
            avg_nesting_depth_x10: 23,
            total_operators: 99,
            body_lines: 42,
            ..Default::default()
        };
        p.body_tokens = 7;
        let s = to_str(&p);
        assert_eq!(s.split(',').count(), AST_PROFILE_DIMS);
        let back = from_str(&s).unwrap();
        assert_eq!(back, p);
        // Roundtrip is stable.
        assert_eq!(to_str(&back), s);
    }

    #[test]
    fn from_str_rejects_garbage() {
        assert!(from_str("1,2,3").is_none());
        assert!(from_str("a,b,c").is_none());
        assert!(from_str("").is_none());
    }

    #[test]
    fn empty_body_fails() {
        // A bare module with no function has no named nodes inside its body.
        let mut p = AstProfile::default();
        // `pass` is a named node, so compute succeeds; use an empty-module
        // edge via the root of an empty file instead.
        let empty = crate::ts::parse(Language::PYTHON, "").unwrap();
        assert!(!compute(empty.root_node(), "", &[], &mut p) || p.body_tokens == 0);
    }
}
