//! extract_defs.rs — 1:1 rewrite of `internal/cbm/extract_defs.c`
//! (8046 lines), part 1: complexity computation (C cbm_compute_complexity),
//! the function-name resolver (C cbm_resolve_func_name main paths), the
//! Go-method receiver type, module def creation, walk_defs dispatch, and
//! extract_func_def for the linked-grammar languages.
//!
//! Later parts: extract_class_def/methods/fields, variables, per-language
//! special extractors (lisp/cfml/gotemplate/macro/kotlin-recovery…).

use crate::extract_env_accesses::ExtractCtx;
use crate::helpers;
use crate::lang_specs::LanguageSpec;
use crate::minhash;
use crate::types::{Definition, SourceOrigin};
use crate::Language;
use std::collections::HashSet;

// ── Complexity (C cbm_complexity_t + cbm_compute_complexity) ────

/// Per-function structural complexity, one AST walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Complexity {
    /// Branching-node count (matches def.complexity).
    pub cyclomatic: i32,
    /// Nesting-weighted flow-break count (Campbell-style approximation).
    pub cognitive: i32,
    /// Total loop constructs in the body.
    pub loop_count: i32,
    /// Maximum nested-loop depth — structural bottleneck proxy.
    pub loop_depth: i32,
    /// Deepest chained member/subscript access (a.b.c.d → 4).
    pub max_access_depth: i32,
}

/// Chained member/subscript access node kinds (C is_member_access_node):
/// structural access-depth smell only; unmatched grammars report 0.
fn is_member_access_node(kind: &str) -> bool {
    matches!(
        kind,
        "member_expression"
            | "field_expression"
            | "selector_expression"
            | "field_access"
            | "member_access_expression"
            | "navigation_expression"
            | "attribute"
            | "subscript_expression"
            | "subscript"
            | "index_expression"
            | "element_access_expression"
            | "scoped_identifier"
    )
}

/// One-traversal complexity (C cbm_compute_complexity). Cognitive adds
/// `1 + branch_depth` per branch (nesting penalty). Loops must be NAMED
/// nodes: anonymous `for`/`while` keyword tokens would otherwise double
/// count and inflate depth.
pub fn compute_complexity(
    node: tree_sitter::Node<'_>,
    branching_types: &[&str],
    out: &mut Complexity,
) {
    *out = Complexity::default();
    if branching_types.is_empty() {
        return;
    }
    struct CxFrame<'t> {
        node: tree_sitter::Node<'t>,
        bdepth: i32,
        ldepth: i32,
        adepth: i32,
    }
    let mut stack: Vec<CxFrame<'_>> = vec![CxFrame {
        node,
        bdepth: 0,
        ldepth: 0,
        adepth: 0,
    }];
    while let Some(f) = stack.pop() {
        let kind = f.node.kind();
        let is_branch = branching_types.contains(&kind);
        let mut child_b = f.bdepth;
        let mut child_l = f.ldepth;
        // Chained access: a.b.c.d nests as access(access(access(a))); each
        // consecutive access node deepens the chain, non-access resets it.
        let mut child_a = 0;
        if f.node.is_named() && is_member_access_node(kind) {
            child_a = f.adepth + 1;
            if child_a > out.max_access_depth {
                out.max_access_depth = child_a;
            }
        }
        if is_branch {
            out.cyclomatic += 1;
            out.cognitive += 1 + f.bdepth;
            child_b = f.bdepth + 1;
        }
        if f.node.is_named() && crate::extract_unified::is_loop_node_type(kind) {
            out.loop_count += 1;
            let d = f.ldepth + 1;
            if d > out.loop_depth {
                out.loop_depth = d;
            }
            child_l = d;
        }
        for i in (0..f.node.child_count()).rev() {
            if let Some(c) = f.node.child(i) {
                if stack.len() < 4096 {
                    stack.push(CxFrame {
                        node: c,
                        bdepth: child_b,
                        ldepth: child_l,
                        adepth: child_a,
                    });
                }
            }
        }
    }
}

// ── Function-name resolution (C cbm_resolve_func_name) ──────────

const TEMPLATE_DEPTH_LIMIT: usize = 4;
const FUNC_PARENT_CLIMB_LIMIT: usize = 4;

fn is_cpp_template_inner_kind(kind: &str) -> bool {
    matches!(kind, "function_definition" | "declaration" | "field_declaration")
}

/// C++/CUDA: find the inner function/declaration inside
/// template_declaration (C find_cpp_template_inner_node).
fn find_cpp_template_inner_node<'t>(
    node: tree_sitter::Node<'t>,
    lang: Language,
) -> Option<tree_sitter::Node<'t>> {
    if !matches!(lang, Language::CPP | Language::CUDA) || node.kind() != "template_declaration" {
        return Some(node);
    }
    for i in 0..node.named_child_count() {
        let ch = node.named_child(i)?;
        let ck = ch.kind();
        if is_cpp_template_inner_kind(ck) {
            return Some(ch);
        }
        if ck == "template_declaration" {
            if let Some(nested) = find_cpp_template_inner_node(ch, lang) {
                if nested != ch {
                    return Some(nested);
                }
            }
        }
    }
    None
}

/// Arrow-function name via parent variable_declarator / object-literal
/// property — the factory-returning-actions-slice pattern (#341)
/// (C resolve_toplevel_arrow_name).
fn resolve_toplevel_arrow_name<'t>(
    node: tree_sitter::Node<'t>,
    kind: &str,
) -> Option<tree_sitter::Node<'t>> {
    if kind != "arrow_function" {
        return None;
    }
    let parent = node.parent()?;
    match parent.kind() {
        // `const f = () => {}` and the class-field form `f = () => {}` both
        // name the arrow via the parent's `name` child.
        "variable_declarator" | "public_field_definition" => parent.child_by_field_name("name"),
        "field_definition" => parent.child_by_field_name("property"),
        "pair" => parent.child_by_field_name("key"),
        _ => None,
    }
}

/// C-family declarator name / template unwrap (C resolve_func_name_c_family).
/// Returns (name_node, unwrapped_node) — a Some((None, Some(inner))) means
/// "retry on inner" (template unwrapped).
fn resolve_func_name_c_family<'t>(
    node: tree_sitter::Node<'t>,
    lang: Language,
    kind: &str,
) -> Option<(Option<tree_sitter::Node<'t>>, Option<tree_sitter::Node<'t>>)> {
    if matches!(lang, Language::CPP | Language::CUDA) && kind == "template_declaration" {
        let inner = find_cpp_template_inner_node(node, lang)?;
        if inner != node {
            return Some((None, Some(inner))); // retry signal
        }
        return Some((None, None));
    }
    if matches!(
        lang,
        Language::C
            | Language::CPP
            | Language::CUDA
            | Language::GLSL
            | Language::HLSL
            | Language::ISPC
            | Language::SLANG
            | Language::OBJC
    ) && kind == "function_definition"
    {
        // Objective-C top-level C functions share the C declarator structure;
        // without this they are dropped and calls never resolve.
        return Some((crate::fqn::resolve_c_declarator_name_node(node), None));
    }
    Some((None, None))
}

/// Resolve the function-name node (C cbm_resolve_func_name): the `name`
/// field plus per-language fallbacks, template unwrap retry loop, arrow /
/// scripting / FP / C-family resolvers in order.
pub fn resolve_func_name<'t>(
    mut node: tree_sitter::Node<'t>,
    lang: Language,
) -> Option<tree_sitter::Node<'t>> {
    loop {
        // Direct `name` field; Protobuf rpc carries rpc_name instead.
        if let Some(name) = node.child_by_field_name("name") {
            return Some(name);
        }
        if let Some(rpc) = crate::fqn::find_child_by_kind(node, "rpc_name") {
            return Some(rpc);
        }
        let kind = node.kind();
        // Lua: anonymous function assignment name from the parent's
        // variables list.
        if lang == Language::LUA && kind == "function_definition" {
            if let Some(n) = resolve_lua_func_name(node) {
                return Some(n);
            }
        }
        // Julia: first identifier among named children (depth 4).
        if lang == Language::JULIA && kind == "function_definition" {
            if let Some(n) = resolve_julia_func_name(node) {
                return Some(n);
            }
        }
        // OCaml: value_definition name from let_binding→pattern.
        if lang == Language::OCAML && kind == "value_definition" {
            if let Some(n) = resolve_ocaml_func_name(node) {
                return Some(n);
            }
        }
        // F#: function_or_value_defn names its value_declaration_left child.
        if lang == Language::FSHARP && kind == "function_or_value_defn" {
            let lhs = crate::fqn::find_child_by_kind(node, "function_declaration_left")
                .or_else(|| crate::fqn::find_child_by_kind(node, "value_declaration_left"));
            if let Some(lhs) = lhs {
                let nm = crate::fqn::find_child_by_kind(lhs, "identifier")
                    .or_else(|| crate::fqn::find_child_by_kind(lhs, "long_identifier"));
                if let Some(nm) = nm {
                    return Some(nm);
                }
            }
        }
        // Groovy: top-level function_definition names via `function` field.
        if lang == Language::GROOVY && kind == "function_definition" {
            let fn_node = node
                .child_by_field_name("function")
                .or_else(|| crate::fqn::find_child_by_kind(node, "identifier"));
            if let Some(f) = fn_node {
                return Some(f);
            }
        }
        // Agda: only the type-signature line carries a function_name alias.
        if lang == Language::AGDA && kind == "function" {
            if let Some(lhs) = crate::fqn::find_child_by_kind(node, "lhs") {
                if let Some(f) = crate::fqn::find_child_by_kind(lhs, "function_name") {
                    return Some(f);
                }
            }
        }
        // Pony: first plain identifier child.
        if lang == Language::PONY
            && matches!(kind, "method" | "constructor" | "ffi_method")
        {
            if let Some(id) = crate::fqn::find_child_by_kind(node, "identifier") {
                return Some(id);
            }
        }
        // COBOL: identification_division > program_name.
        if lang == Language::COBOL && kind == "program_definition" {
            if let Some(iddiv) = crate::fqn::find_child_by_kind(node, "identification_division") {
                if let Some(pname) = crate::fqn::find_child_by_kind(iddiv, "program_name") {
                    return Some(pname);
                }
            }
        }
        // Pascal defProc: name on the header (declProc) child.
        if lang == Language::PASCAL && kind == "defProc" {
            if let Some(hdr) = node.child_by_field_name("header") {
                if let Some(nm) = hdr.child_by_field_name("name") {
                    return Some(nm);
                }
            }
        }
        // Just recipe: name on the recipe_header.
        if lang == Language::JUST && kind == "recipe" {
            if let Some(hdr) = crate::fqn::find_child_by_kind(node, "recipe_header") {
                if let Some(nm) = hdr.child_by_field_name("name") {
                    return Some(nm);
                }
            }
        }
        // ReScript: arrow names via the enclosing let_binding's pattern.
        if lang == Language::RESCRIPT && kind == "function" {
            if let Some(parent) = node.parent() {
                if parent.kind() == "let_binding" {
                    if let Some(pat) = parent.child_by_field_name("pattern") {
                        return Some(pat);
                    }
                }
            }
        }
        // Nickel: fun_expr's name on the enclosing let_binding's `pat`
        // (climbing the term/uni_term chain, limit 4).
        if lang == Language::NICKEL && kind == "fun_expr" {
            let mut parent = node.parent();
            for _ in 0..FUNC_PARENT_CLIMB_LIMIT {
                let Some(p) = parent else { break };
                if p.kind() == "let_binding" {
                    if let Some(pat) = p.child_by_field_name("pat") {
                        let inner = pat.child_by_field_name("pat");
                        return Some(inner.unwrap_or(pat));
                    }
                    break;
                }
                parent = p.parent();
            }
        }
        // Arrow function top-level resolution (variable_declarator /
        // field_definition / pair).
        if let Some(r) = resolve_toplevel_arrow_name(node, kind) {
            return Some(r);
        }
        // C-family declarator / template unwrap; a template unwrap signals
        // a retry on the inner node.
        let prev = node;
        if let Some((name, unwrapped)) = resolve_func_name_c_family(node, lang, kind) {
            if let Some(n) = name {
                return Some(n);
            }
            if let Some(inner) = unwrapped {
                node = inner;
            }
        }
        if node == prev {
            break;
        }
    }
    None
}

fn resolve_lua_func_name<'t>(node: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    let mut parent = node.parent()?;
    if parent.kind() == "expression_list" {
        parent = parent.parent()?;
    }
    if parent.kind() != "assignment_statement" {
        return None;
    }
    let vars = parent.child_by_field_name("variables").or_else(|| {
        (0..parent.child_count()).find_map(|i| {
            let c = parent.child(i)?;
            (c.kind() == "variable_list").then_some(c)
        })
    })?;
    if vars.child_count() > 0 {
        return vars.child(0);
    }
    None
}

fn resolve_julia_func_name<'t>(node: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    let mut current = node;
    for _ in 0..TEMPLATE_DEPTH_LIMIT {
        if current.named_child_count() == 0 {
            break;
        }
        let first = current.named_child(0)?;
        if matches!(first.kind(), "identifier" | "operator_identifier") {
            return Some(first);
        }
        current = first;
    }
    None
}

fn resolve_ocaml_func_name<'t>(node: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    // value_definition → let_binding → pattern (function or parameter group).
    for i in 0..node.named_child_count() {
        let lb = node.named_child(i)?;
        if lb.kind() != "let_binding" {
            continue;
        }
        if let Some(pat) = lb.child_by_field_name("pattern") {
            if let Some(f) = crate::fqn::find_child_by_kind(pat, "function") {
                return Some(f);
            }
            return Some(pat);
        }
    }
    None
}

// ── Go receiver type (C go_receiver_type_name) ──────────────────

/// `(s *OrderService)` / `(s Order)` → "OrderService" (C
/// go_receiver_type_name): walks the parameter_declaration's `type`,
/// unwrapping pointer/generic wrappers (depth 4).
fn go_receiver_type_name<'a>(recv: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    for i in 0..recv.child_count() {
        let child = recv.child(i)?;
        if child.kind() != "parameter_declaration" {
            continue;
        }
        let mut tn = child.child_by_field_name("type");
        for _ in 0..4 {
            let t = tn?;
            match t.kind() {
                "type_identifier" => {
                    return Some(crate::fqn::node_text(t, source).to_string());
                }
                "pointer_type" | "generic_type" => {
                    // Descend to the type_identifier inside.
                    let mut inner = None;
                    for j in 0..t.named_child_count() {
                        let c = t.named_child(j)?;
                        if c.kind() == "type_identifier" {
                            inner = Some(c);
                            break;
                        }
                        // one more unwrap level
                        if matches!(c.kind(), "pointer_type" | "generic_type") {
                            for k in 0..c.named_child_count() {
                                if let Some(gc) = c.named_child(k) {
                                    if gc.kind() == "type_identifier" {
                                        inner = Some(gc);
                                        break;
                                    }
                                }
                            }
                        }
                        if inner.is_some() {
                            break;
                        }
                    }
                    return inner.map(|n| crate::fqn::node_text(n, source).to_string());
                }
                _ => {
                    tn = t.child_by_field_name("type");
                }
            }
        }
    }
    None
}

// ── Module def (C cbm_extract_definitions head) ─────────────────

/// Create the Module node (always the first definition).
pub fn push_module_def(ctx: &mut ExtractCtx<'_>) {
    let end_line = ctx.root.end_position().row as u32 + 1; // TS_LINE_OFFSET
    let mut def = Definition {
        name: ctx.rel_path.to_string(), // refined by the Go layer
        qualified_name: ctx.module_qn.clone(),
        label: "Module".to_string(),
        file_path: ctx.rel_path.to_string(),
        start_line: 1,
        end_line,
        is_exported: true,
        ..Default::default()
    };
    def.is_test = ctx.result.is_test_file;
    // #519: index what a config file declares itself to be.
    def.docstring = extract_config_module_description(ctx.root, ctx.source);
    ctx.result.definitions.push(def);
}

/// Config-file self-description: a top-level `description`/`name`-style
/// key (C extract_config_module_description, conservative subset —
/// YAML/TOML top-level description keys).
fn extract_config_module_description(root: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    // YAML: top-level `description:` mapping key.
    for i in 0..root.named_child_count() {
        let child = root.named_child(i)?;
        if child.kind() == "block_mapping_pair" || child.kind() == "flow_pair" {
            if let Some(key) = child.child_by_field_name("key") {
                let key_text = crate::fqn::node_text(key, source);
                if matches!(key_text, "description" | "summary") {
                    if let Some(val) = child.child_by_field_name("value") {
                        let v = crate::fqn::node_text(val, source);
                        let v = v.trim().trim_matches(['"', '\'']).trim();
                        if !v.is_empty() {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

// ── extract_func_def (C, linked-grammar languages) ──────────────

/// Makefile special targets (.PHONY, …) are directives, not defs.
fn is_makefile_special_target(name: &str) -> bool {
    name.starts_with('.')
}

fn is_cpp_test_macro(name: &str) -> bool {
    matches!(name, "TEST" | "TEST_F" | "TEST_P" | "TYPED_TEST" | "TEST_SUITE")
}

/// GoogleTest macro name → `Suite.Name` derived from macro args (#1266).
fn resolve_cpp_test_macro_name<'a>(
    name: &str,
    node: tree_sitter::Node<'a>,
    source: &'a str,
) -> Option<String> {
    // Locate the macro argument list textually: "(Suite, Test)".
    let text = crate::fqn::node_text(node, source);
    let open = text.find('(')?;
    let close = text[open..].find(')')? + open;
    let args: Vec<&str> = text[open + 1..close]
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if args.len() < 2 {
        return None;
    }
    Some(format!("{}.{}", args[0], args[1]).replace(&format!("{name}."), name).trim().to_string())
}

/// Free function inside a namespace keeps the namespace QN (C++
/// /C#/PHP/TS-family/Nix): `ns::serialize` is `proj.file.ns.serialize`.
fn qualifies_by_enclosing_scope(lang: Language) -> bool {
    matches!(
        lang,
        Language::CPP
            | Language::CUDA
            | Language::TYPESCRIPT
            | Language::TSX
            | Language::ARKTS
            | Language::NIX
    )
}

/// JS/TS export detection (C is_js_exported): the function's parent chain
/// has an export_statement wrapper.
fn is_js_exported(node: tree_sitter::Node<'_>) -> bool {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == "export_statement" {
            return true;
        }
        if matches!(
            p.kind(),
            "program" | "source_file" | "class_body" | "statement_block"
        ) {
            return false;
        }
        cur = p.parent();
    }
    false
}

/// Function definition extraction (C extract_func_def, main path).
pub fn extract_func_def(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
) {
    let Some(name_node) = resolve_func_name(node, ctx.language) else {
        return;
    };
    let mut name = crate::fqn::normalize_name_node_text(name_node, ctx.source, ctx.language);
    if name.is_empty() || name == "function" {
        return;
    }
    // Makefile dot-targets are directives (also protects the QN from "..").
    if ctx.language == Language::MAKEFILE && is_makefile_special_target(&name) {
        return;
    }
    // C++/CUDA GoogleTest macros: derive unique per-case names (#1266).
    if matches!(ctx.language, Language::CPP | Language::CUDA)
        && is_cpp_test_macro(&name)
    {
        if let Some(gtest_name) = resolve_cpp_test_macro_name(&name, node, ctx.source) {
            name = gtest_name;
        }
    }
    // Nix interpolated attrpath has no statically knowable name — an absent
    // node is the honest answer.
    if ctx.language == Language::NIX
        && crate::fqn::node_text(name_node, ctx.source).contains("${")
    {
        return;
    }
    let qn_name = name.clone(); // Nix attrpath scoping lands with Nix part
    let mut def = Definition {
        name: name.clone(),
        qualified_name: crate::fqn::fqn_compute_source_lang(
            ctx.project,
            ctx.rel_path,
            Some(&qn_name),
            ctx.language,
        ),
        label: "Function".to_string(),
        file_path: ctx.rel_path.to_string(),
        ..Default::default()
    };
    // Namespace-scoped free function (see the C comment: the call-scope gate
    // must move together with this).
    if let Some(enclosing) = &ctx.result.namespace_name {
        if qualifies_by_enclosing_scope(ctx.language) {
            def.qualified_name = format!("{enclosing}.{qn_name}");
        }
    }
    def.start_line = node.start_position().row as u32 + 1;
    def.end_line = node.end_position().row as u32 + 1;
    def.lines = (def.end_line - def.start_line + 1) as i32;
    def.is_exported = helpers::is_exported(&name, ctx.language);
    // Rust trait fn signatures are abstract.
    if ctx.language == Language::RUST && node.kind() == "function_signature_item" {
        def.is_abstract = true;
    }
    // Parameters.
    if let Some(params) = find_function_params(node, ctx.language) {
        def.signature = Some(crate::fqn::node_text(params, ctx.source).to_string());
        extract_param_names_types(params, ctx.source, ctx.language, &mut def);
    }
    // Return type.
    for f in ["result", "return_type", "type"] {
        if let Some(rt) = node.child_by_field_name(f) {
            def.return_type = Some(crate::fqn::node_text(rt, ctx.source).to_string());
            break;
        }
    }
    // Go method receiver.
    if let Some(recv) = node.child_by_field_name("receiver") {
        def.receiver = Some(crate::fqn::node_text(recv, ctx.source).to_string());
        def.label = "Method".to_string();
        if let Some(recv_type) = go_receiver_type_name(recv, ctx.source) {
            def.parent_class = Some(crate::fqn::fqn_compute_source_lang(
                ctx.project,
                ctx.rel_path,
                Some(&recv_type),
                ctx.language,
            ));
        }
    }
    def.is_test = helpers::is_test_file(ctx.rel_path, ctx.language)
        || ctx.result.is_test_file;
    def.docstring = extract_docstring(node, ctx.source, ctx.language);
    // Complexity.
    if !spec.branching_node_types.is_empty() {
        let body = node.child_by_field_name("body").unwrap_or(node);
        let mut cx = crate::extract_defs::Complexity::default();
        compute_complexity(body, spec.branching_node_types, &mut cx);
        def.complexity = cx.cyclomatic;
        def.cognitive = cx.cognitive;
        def.loop_count = cx.loop_count;
        def.loop_depth = cx.loop_depth;
        def.max_access_depth = cx.max_access_depth;
    }
    // MinHash fingerprint + body tokens (body field or the whole node).
    let body = node.child_by_field_name("body").unwrap_or(node);
    def.body_tokens = extract_body_ident_tokens(body, ctx.source);
    if let Some(fp) = minhash::compute(body) {
        def.fingerprint = fp.values.to_vec();
    }
    // JS/TS export entry points.
    if matches!(
        ctx.language,
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS
    ) && is_js_exported(node)
    {
        def.is_entry_point = true;
    }
    if name == "main" {
        def.is_entry_point = true;
    }
    ctx.result.definitions.push(def);
}

/// Function parameter node (C find_function_params): parameters /
/// formal_parameters / parameter_list kinds by shape.
fn find_function_params<'t>(
    func_node: tree_sitter::Node<'t>,
    _lang: Language,
) -> Option<tree_sitter::Node<'t>> {
    func_node
        .child_by_field_name("parameters")
        .or_else(|| func_node.child_by_field_name("params"))
        .or_else(|| {
            (0..func_node.child_count()).find_map(|i| {
                let c = func_node.child(i)?;
                matches!(
                    c.kind(),
                    "formal_parameters" | "parameter_list" | "parameters"
                )
                .then_some(c)
            })
        })
}

/// Parameter names + types, per shape (C extract_param_names/_types
/// common case: parameter_declaration / formal_parameter children with
/// optional `type` field).
fn extract_param_names_types(
    params: tree_sitter::Node<'_>,
    source: &str,
    _lang: Language,
    def: &mut Definition,
) {
    for i in 0..params.named_child_count() {
        let Some(child) = params.named_child(i) else {
            continue;
        };
        let ck = child.kind();
        if matches!(ck, "(" | ")" | ",") || !child.is_named() {
            continue;
        }
        // Name: identifier descendant (or the node itself for bare
        // identifiers); Type: `type` field.
        let name = child
            .child_by_field_name("name")
            .map(|n| crate::fqn::node_text(n, source).to_string())
            .or_else(|| {
                if ck == "identifier" {
                    Some(crate::fqn::node_text(child, source).to_string())
                } else {
                    crate::fqn::find_child_by_kind(child, "identifier")
                        .map(|n| crate::fqn::node_text(n, source).to_string())
                }
            });
        if let Some(n) = name {
            def.param_names.push(n);
        }
        if let Some(t) = child.child_by_field_name("type") {
            def.param_types.push(crate::fqn::node_text(t, source).to_string());
        }
    }
}

/// Docstring: the first preceding comment block (C extract_docstring,
/// common shape: a `comment` previous sibling of the def).
fn extract_docstring(node: tree_sitter::Node<'_>, source: &str, lang: Language) -> Option<String> {
    let comment_kind = match lang {
        Language::PYTHON => "string", // docstrings are string statements in the body
        _ => "comment",
    };
    if lang == Language::PYTHON {
        // Python: body's first statement is a bare string expression.
        let body = node.child_by_field_name("body")?;
        let first = body.named_child(0)?;
        if first.kind() == "expression_statement" {
            if let Some(s) = first.named_child(0) {
                if s.kind() == "string" {
                    let text = crate::fqn::node_text(s, source);
                    let text = text.trim().trim_matches(['"', '\'']).trim();
                    if !text.is_empty() {
                        return Some(text.to_string());
                    }
                }
            }
        }
        return None;
    }
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == comment_kind {
            let text = crate::fqn::node_text(p, source);
            // Strip comment markers; keep the inner text.
            let cleaned: String = text
                .lines()
                .map(|l| {
                    let l = l.trim();
                    l.trim_start_matches('/')
                        .trim_start_matches('*')
                        .trim_start_matches('/')
                        .trim()
                })
                .filter(|l| !l.is_empty() && *l != "*/")
                .collect::<Vec<_>>()
                .join(" ");
            if !cleaned.is_empty() {
                return Some(cleaned.chars().take(500).collect());
            }
            return None;
        }
        if p.kind() != comment_kind {
            break;
        }
        prev = p.prev_sibling();
    }
    None
}

/// Body identifier tokens as a space-separated string (C
/// extract_body_ident_tokens): the first 128 unique identifier-like leaves.
fn extract_body_ident_tokens(body: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    const MAX_IDENTS: usize = 128;
    let mut seen: HashSet<&str> = HashSet::new();
    let mut out = String::new();
    let mut count = 0;
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if count >= MAX_IDENTS {
            break;
        }
        if n.child_count() == 0 {
            let k = n.kind();
            if matches!(
                k,
                "identifier"
                    | "field_identifier"
                    | "property_identifier"
                    | "type_identifier"
                    | "objectscript_identifier"
                    | "objectscript_identifier_special"
                    | "identifier_segment_immediate"
                    | "identifier_segment_immediate_special"
                    | "class_name"
                    | "method_name"
                    | "routine_name"
                    | "quote_permitting_identifier"
            ) {
                let s = n.start_byte();
                let len = n.end_byte() - s;
                if len > 0 && len < 64 && s < source.len() {
                    let text = &source[s..(s + len).min(source.len())];
                    if seen.insert(text) {
                        if !out.is_empty() {
                            out.push(' ');
                        }
                        out.push_str(text);
                        count += 1;
                    }
                }
            }
        } else {
            for i in (0..n.child_count()).rev() {
                if let Some(c) = n.child(i) {
                    stack.push(c);
                }
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

// ── Module-level variable extraction (C extract_variables, main shape) ──

/// Module-level variables: top-level variable-declaration children whose
/// variable_declarator binds a name (C extract_variables main loop).
pub fn extract_variables(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    if spec.variable_node_types.is_empty() {
        return;
    }
    for i in 0..ctx.root.named_child_count() {
        let Some(child) = ctx.root.named_child(i) else {
            continue;
        };
        let ck = child.kind();
        if !spec.variable_node_types.contains(&ck) {
            continue;
        }
        // Decl container → its variable_declarator / declarator children.
        let declarators: Vec<tree_sitter::Node<'_>> = if matches!(
            ck,
            "lexical_declaration" | "variable_declaration" | "const_declaration"
        ) {
            (0..child.named_child_count())
                .filter_map(|j| child.named_child(j))
                .filter(|d| d.kind() == "variable_declarator" || d.kind() == "init_declarator")
                .collect()
        } else {
            vec![child]
        };
        for d in declarators {
            let Some(name_node) = d.child_by_field_name("name") else {
                continue;
            };
            let name = crate::fqn::node_text(name_node, ctx.source);
            if name.is_empty() {
                continue;
            }
            let mut def = Definition {
                name: name.to_string(),
                label: "Variable".to_string(),
                file_path: ctx.rel_path.to_string(),
                ..Default::default()
            };
            def.qualified_name = crate::fqn::fqn_compute_source_lang(
                ctx.project,
                ctx.rel_path,
                Some(&name),
                ctx.language,
            );
            def.start_line = d.start_position().row as u32 + 1;
            def.end_line = d.end_position().row as u32 + 1;
            def.is_exported = helpers::is_exported(&name, ctx.language);
            ctx.result.definitions.push(def);
        }
    }
}

// ── walk_defs (C, main-language dispatch) ───────────────────────

/// Walk the AST extracting function/class/variable definitions
/// (C walk_defs, main-language dispatch; the long-tail language
/// special-casers land in part 2).
pub fn walk_defs(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    struct Frame<'t> {
        node: tree_sitter::Node<'t>,
        next_child: usize,
    }
    let mut stack = vec![Frame {
        node: ctx.root,
        next_child: 0,
    }];
    while let Some(frame) = stack.last_mut() {
        if frame.next_child == 0 {
            let node = frame.node;
            let kind = node.kind();
            if !spec.function_node_types.is_empty()
                && spec.function_node_types.contains(&kind)
            {
                extract_func_def(ctx, node, spec);
                // Most languages stop; JS/TS-family descend for nested named
                // defs (factory-actions pattern, #341).
                let descend = matches!(
                    ctx.language,
                    Language::TYPESCRIPT
                        | Language::JAVASCRIPT
                        | Language::TSX
                        | Language::ARKTS
                );
                if !descend {
                    stack.pop();
                    continue;
                }
            } else if !spec.class_node_types.is_empty()
                && spec.class_node_types.contains(&kind)
            {
                extract_class_def_shallow(ctx, node, spec);
                stack.pop();
                continue;
            }
        }
        let count = frame.node.child_count();
        if frame.next_child < count {
            let child = frame.node.child(frame.next_child);
            frame.next_child += 1;
            if let Some(c) = child {
                stack.push(Frame {
                    node: c,
                    next_child: 0,
                });
            }
        } else {
            stack.pop();
        }
    }
}

/// Class extraction, part-1 shallow shape: the class node itself plus its
/// `name`-field methods (extract_class_methods comes with part 2's
/// class-body traversal).
fn extract_class_def_shallow(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    _spec: &LanguageSpec,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = crate::fqn::node_text(name_node, ctx.source);
    if name.is_empty() {
        return;
    }
    let qn = crate::fqn::fqn_compute_source_lang(
        ctx.project,
        ctx.rel_path,
        Some(&name),
        ctx.language,
    );
    let mut def = Definition {
        name: name.to_string(),
        qualified_name: qn.clone(),
        label: "Class".to_string(),
        file_path: ctx.rel_path.to_string(),
        ..Default::default()
    };
    def.start_line = node.start_position().row as u32 + 1;
    def.end_line = node.end_position().row as u32 + 1;
    // Base classes：JS 的 extends 在 `class_heritage` 命名子节点（无字段名），
    // Java/TS 的 `superclass` 有字段。两者都扫。
    let bases = node
        .child_by_field_name("superclass")
        .or_else(|| crate::fqn::find_child_by_kind(node, "class_heritage"));
    if let Some(bases) = bases {
        let push = |n: tree_sitter::Node<'_>, def: &mut Definition| {
            if matches!(
                n.kind(),
                "type_identifier" | "identifier" | "class" | "superclass" | "member_expression"
            ) {
                def.base_classes
                    .push(crate::fqn::node_text(n, ctx.source).to_string());
            }
        };
        push(bases, &mut def);
        for i in 0..bases.named_child_count() {
            if let Some(b) = bases.named_child(i) {
                push(b, &mut def);
            }
        }
    }
    def.docstring = extract_docstring(node, ctx.source, ctx.language);
    let mut cx = Complexity::default();
    if let Some(body) = node.child_by_field_name("body") {
        compute_complexity(body, &[], &mut cx);
    }
    ctx.result.definitions.push(def);
}

/// Full extraction without the Module node (C
/// cbm_extract_definitions_without_module).
pub fn extract_definitions_without_module(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    walk_defs(ctx, spec);
    extract_variables(ctx, spec);
}

/// Full extraction: Module node first, then the walk (C
/// cbm_extract_definitions).
pub fn extract_definitions(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    push_module_def(ctx);
    extract_definitions_without_module(ctx, spec);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_env_accesses::ExtractCtx;

    fn run(lang: Language, src: &str, rel: &str) -> Vec<Definition> {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", rel);
        let spec = crate::lang_specs::lang_spec(lang);
        extract_definitions(&mut ctx, spec);
        ctx.result.definitions
    }

    #[test]
    fn complexity_counts_branches_and_loops() {
        let tree = crate::ts::parse(Language::PYTHON, "def f():\n    pass\n").unwrap();
        let src = r#"
def work(items, flag):
    for item in items:
        if item.valid and flag:
            item.commit()
        elif item.retry:
            item.resend()
    while item.pending:
        item.step()
"#;
        let tree = crate::ts::parse(Language::PYTHON, src).unwrap();
        let mut stack = vec![tree.root_node()];
        let body = loop {
            let n = stack.pop().unwrap();
            if n.kind() == "block" {
                break n;
            }
            for i in 0..n.child_count() {
                stack.push(n.child(i).unwrap());
            }
        };
        let mut cx = Complexity::default();
        compute_complexity(body, &["if_statement", "elif_clause", "for_statement", "while_statement"], &mut cx);
        assert!(cx.cyclomatic >= 4, "{cx:?}");
        assert!(cx.cognitive > cx.cyclomatic, "nesting penalty — {cx:?}");
        assert!(cx.loop_count >= 2);
        assert!(cx.loop_depth >= 1);
    }

    #[test]
    fn module_node_first() {
        let defs = run(Language::PYTHON, "def f():\n    pass\n", "app.py");
        assert_eq!(defs[0].label, "Module");
        assert_eq!(defs[0].qualified_name, "proj.app");
        assert!(defs[0].is_exported);
        // The function follows.
        assert!(defs.iter().any(|d| d.name == "f" && d.label == "Function"));
    }

    #[test]
    fn python_function_def() {
        let src = "def process(alpha, beta: str) -> bool:\n    return True\n";
        let defs = run(Language::PYTHON, src, "app.py");
        let f = defs.iter().find(|d| d.name == "process").expect("def");
        assert_eq!(f.label, "Function");
        assert_eq!(f.qualified_name, "proj.app.process");
        assert_eq!(f.start_line, 1);
        assert!(f.param_names.contains(&"alpha".to_string()));
        assert_eq!(f.return_type.as_deref(), Some("bool"));
        // Python docstring.
        let with_doc = run(Language::PYTHON, "def g():\n    \"\"\"Does things.\"\"\"\n", "app.py");
        let g = with_doc.iter().find(|d| d.name == "g").unwrap();
        assert!(g.docstring.as_deref().unwrap_or("").contains("Does things"));
    }

    #[test]
    fn go_function_dir_module() {
        let src = "package db\nfunc Connect() error {\n\treturn nil\n}\n";
        let defs = run(Language::GO, src, "myapp/db/conn.go");
        let f = defs.iter().find(|d| d.name == "Connect").expect("def");
        // Directory-based module (Java/Go): proj.myapp.db.Connect.
        assert_eq!(f.qualified_name, "proj.myapp.db.Connect");
    }

    #[test]
    fn go_method_receiver() {
        let src = "package app\ntype Svc struct{}\nfunc (s *Svc) Start() error {\n\treturn nil\n}\n";
        let defs = run(Language::GO, src, "a.go");
        let m = defs.iter().find(|d| d.name == "Start").expect("def");
        assert_eq!(m.label, "Method");
        assert_eq!(m.parent_class.as_deref(), Some("proj.Svc")); // a.go 无目录 → module=proj
    }

    #[test]
    fn main_is_entry_point() {
        let defs = run(Language::GO, "package main\nfunc main() {}\n", "main.go");
        let m = defs.iter().find(|d| d.name == "main").expect("def");
        assert!(m.is_entry_point);
    }

    #[test]
    fn js_export_entry_point() {
        let src = "export function helper() {}\n";
        let defs = run(Language::JAVASCRIPT, src, "a.js");
        let h = defs.iter().find(|d| d.name == "helper").expect("def");
        assert!(h.is_entry_point);
    }

    #[test]
    fn makefile_dot_targets_skipped() {
        assert!(is_makefile_special_target(".PHONY"));
        assert!(!is_makefile_special_target("build"));
    }

    #[test]
    fn module_variables() {
        let src = "const MAX = 5\nvar name = \"x\"\n";
        let defs = run(Language::JAVASCRIPT, src, "a.js");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        assert!(vars.contains(&"MAX"), "{defs:?}");
        assert!(vars.contains(&"name"));
    }

    #[test]
    fn class_def() {
        let src = "class UserService extends Base {\n  method() {}\n}\n";
        let defs = run(Language::JAVASCRIPT, src, "a.js");
        let c = defs.iter().find(|d| d.name == "UserService").expect("def");
        assert_eq!(c.label, "Class");
        assert!(c.base_classes.iter().any(|b| b.contains("Base")));
    }

    #[test]
    fn fingerprint_present_on_substantial_body() {
        let src = r#"
def process(items):
    total = 0
    results = []
    for item in items:
        if item.valid:
            value = item.count * item.weight + item.offset
            total = total + value
            results.append(item.transform(total, item.flags))
        elif item.retry:
            for attempt in range(item.retries):
                item.resend(item.payload)
    return results
"#;
        let defs = run(Language::PYTHON, src, "a.py");
        let f = defs.iter().find(|d| d.name == "process").expect("def");
        assert_eq!(f.fingerprint.len(), minhash::MINHASH_K);
    }
}
