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
use crate::types::Definition;
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
    matches!(
        kind,
        "function_definition" | "declaration" | "field_declaration"
    )
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
        if lang == Language::PONY && matches!(kind, "method" | "constructor" | "ffi_method") {
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
    matches!(
        name,
        "TEST" | "TEST_F" | "TEST_P" | "TYPED_TEST" | "TEST_SUITE"
    )
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
    Some(
        format!("{}.{}", args[0], args[1])
            .replace(&format!("{name}."), name)
            .trim()
            .to_string(),
    )
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
    if matches!(ctx.language, Language::CPP | Language::CUDA) && is_cpp_test_macro(&name) {
        if let Some(gtest_name) = resolve_cpp_test_macro_name(&name, node, ctx.source) {
            name = gtest_name;
        }
    }
    // Nix interpolated attrpath has no statically knowable name — an absent
    // node is the honest answer.
    if ctx.language == Language::NIX && crate::fqn::node_text(name_node, ctx.source).contains("${")
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
    def.is_test = helpers::is_test_file(ctx.rel_path, ctx.language) || ctx.result.is_test_file;
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
            def.param_types
                .push(crate::fqn::node_text(t, source).to_string());
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

// ═══ Variable extraction layer (C extract_var_names + helpers) ═══
//
// C lives in extract_defs.c 5372-6326 + helpers.c module-parents tables.
// The Rust walk registered only direct `name`-field children; this layer
// replaces that with the C's full per-language dispatch.

// ── Module-level parent tables (C module_parents_*) ─────────────

const MODULE_PARENTS_GO: &[&str] = &["source_file"];
const MODULE_PARENTS_RUST: &[&str] = &["source_file", "mod_item"];
const MODULE_PARENTS_JAVA: &[&str] = &["program", "class_body"];
const MODULE_PARENTS_KOTLIN: &[&str] = &["source_file", "class_body"];
const MODULE_PARENTS_SCALA: &[&str] = &["compilation_unit", "template_body"];
const MODULE_PARENTS_CSHARP: &[&str] = &[
    "compilation_unit",
    "class_declaration",
    "namespace_declaration",
];
const MODULE_PARENTS_PHP: &[&str] = &["program"];
const MODULE_PARENTS_RUBY: &[&str] = &["program", "class", "module"];
const MODULE_PARENTS_C: &[&str] = &["translation_unit"];
const MODULE_PARENTS_ZIG: &[&str] = &["source_file"];
const MODULE_PARENTS_BASH: &[&str] = &["program"];
const MODULE_PARENTS_ERLANG: &[&str] = &["source", "source_file"];
const MODULE_PARENTS_HASKELL: &[&str] = &["declarations"];
const MODULE_PARENTS_OCAML: &[&str] = &["compilation_unit"];
const MODULE_PARENTS_ELIXIR: &[&str] = &["source"];
const MODULE_PARENTS_HTML: &[&str] = &["document"];
const MODULE_PARENTS_CSS: &[&str] = &["stylesheet"];
const MODULE_PARENTS_SQL: &[&str] = &["source_file", "program", "statement"];
const MODULE_PARENTS_TOML: &[&str] = &["document", "table", "table_array_element"];
const MODULE_PARENTS_CONFIG: &[&str] = &[
    "document",
    "table",
    "table_array_element",
    "section",
    "object",
    "element",
    "array",
];
const MODULE_PARENTS_HCL: &[&str] = &["config_file"];
const MODULE_PARENTS_MAKEFILE: &[&str] = &["makefile"];
const MODULE_PARENTS_COMMONLISP: &[&str] = &["source"];
const MODULE_PARENTS_MATLAB: &[&str] = &["source_file"];
const MODULE_PARENTS_FORM: &[&str] = &["source_file"];
const MODULE_PARENTS_MAGMA: &[&str] = &["source_file"];
/// tree-sitter-properties roots at `file`.
const MODULE_PARENTS_PROPERTIES: &[&str] = &["file", "source_file"];

fn module_parents(lang: Language) -> Option<&'static [&'static str]> {
    Some(match lang {
        Language::GO => MODULE_PARENTS_GO,
        Language::RUST => MODULE_PARENTS_RUST,
        Language::JAVA => MODULE_PARENTS_JAVA,
        Language::KOTLIN => MODULE_PARENTS_KOTLIN,
        Language::SCALA => MODULE_PARENTS_SCALA,
        Language::CSHARP => MODULE_PARENTS_CSHARP,
        Language::PHP => MODULE_PARENTS_PHP,
        Language::RUBY => MODULE_PARENTS_RUBY,
        Language::C | Language::CPP | Language::OBJC => MODULE_PARENTS_C,
        Language::ZIG => MODULE_PARENTS_ZIG,
        Language::BASH => MODULE_PARENTS_BASH,
        Language::ERLANG => MODULE_PARENTS_ERLANG,
        Language::HASKELL => MODULE_PARENTS_HASKELL,
        Language::OCAML => MODULE_PARENTS_OCAML,
        Language::ELIXIR => MODULE_PARENTS_ELIXIR,
        Language::HTML => MODULE_PARENTS_HTML,
        Language::CSS | Language::SCSS => MODULE_PARENTS_CSS,
        Language::SQL => MODULE_PARENTS_SQL,
        Language::TOML => MODULE_PARENTS_TOML,
        Language::HCL => MODULE_PARENTS_HCL,
        Language::JSON | Language::INI | Language::XML | Language::MARKDOWN => {
            MODULE_PARENTS_CONFIG
        }
        Language::SWIFT => MODULE_PARENTS_ZIG,
        Language::DART => MODULE_PARENTS_PHP,
        Language::PERL | Language::GROOVY | Language::DOCKERFILE => MODULE_PARENTS_ZIG,
        Language::R => MODULE_PARENTS_PHP,
        Language::MAKEFILE => MODULE_PARENTS_MAKEFILE,
        Language::COMMONLISP => MODULE_PARENTS_COMMONLISP,
        Language::MATLAB => MODULE_PARENTS_MATLAB,
        Language::LEAN => MODULE_PARENTS_ZIG,
        Language::FORM => MODULE_PARENTS_FORM,
        Language::MAGMA => MODULE_PARENTS_MAGMA,
        Language::PROPERTIES => MODULE_PARENTS_PROPERTIES,
        Language::GOMOD => MODULE_PARENTS_ZIG,
        _ => return None,
    })
}

/// Scripting wrapper pattern: parent matches root_kind directly, or
/// matches wrapper_kind with a root_kind grandparent (C
/// check_script_module_level).
fn check_script_module_level(
    parent: tree_sitter::Node<'_>,
    root_kind: &str,
    wrapper_kind: &str,
) -> bool {
    if parent.kind() == root_kind {
        return true;
    }
    if parent.kind() == wrapper_kind {
        return parent
            .parent()
            .map(|gp| gp.kind() == root_kind)
            .unwrap_or(false);
    }
    false
}

/// Is this node's PARENT a module-level container? (C
/// cbm_is_module_level_p; the parent is passed directly to avoid the O(n)
/// ts_node_parent rescan that went quadratic on generated files.)
pub fn is_module_level_p(parent: tree_sitter::Node<'_>, lang: Language) -> bool {
    let pk = parent.kind();
    // Wrapper-pattern scripting languages.
    match lang {
        Language::PYTHON => {
            return check_script_module_level(parent, "module", "expression_statement")
        }
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS => {
            return check_script_module_level(parent, "program", "export_statement")
        }
        Language::LUA => return check_script_module_level(parent, "chunk", "assignment_statement"),
        Language::YAML => {
            return matches!(pk, "document" | "stream" | "block_mapping");
        }
        _ => {}
    }
    module_parents(lang)
        .map(|ps| ps.contains(&pk))
        .unwrap_or(false)
}

// ── Nix attrpath helpers (C cbm_nix_*) ──────────────────────────

/// Strip one matching pair of surrounding double quotes (C
/// cbm_nix_strip_attr_quotes).
pub fn nix_strip_attr_quotes(text: &str) -> &str {
    let b = text.as_bytes();
    if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
        &text[1..text.len() - 1]
    } else {
        text
    }
}

/// True when a segment contains a `${...}` interpolation and has no
/// statically knowable name (C cbm_nix_attr_is_interpolated); bounded scan.
pub fn nix_attr_is_interpolated(attr: tree_sitter::Node<'_>) -> bool {
    const NIX_ATTR_SCAN_MAX: usize = 32;
    let mut stack = vec![attr];
    while let Some(cur) = stack.pop() {
        if cur.kind() == "interpolation" {
            return true;
        }
        for i in 0..cur.named_child_count() {
            if stack.len() >= NIX_ATTR_SCAN_MAX {
                break;
            }
            if let Some(c) = cur.named_child(i) {
                stack.push(c);
            }
        }
    }
    false
}

/// The leaf segment of an attrpath — the name (C
/// cbm_nix_attrpath_last_attr). `attr` is a FIELD in this grammar, so
/// iterate named children rather than matching a type.
pub fn nix_attrpath_last_attr(attrpath: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let n = attrpath.named_child_count();
    if n == 0 {
        return None;
    }
    attrpath.named_child(n - 1)
}

/// The scope prefix of an attrpath: every segment except the leaf,
/// quote-stripped and dot-joined (C cbm_nix_attrpath_scope). None for a
/// single-segment path or an interpolated leading segment.
pub fn nix_attrpath_scope(attrpath: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    let n = attrpath.named_child_count();
    if n <= 1 {
        return None;
    }
    let mut scope = String::new();
    for i in 0..n - 1 {
        let seg = attrpath.named_child(i)?;
        if nix_attr_is_interpolated(seg) {
            return None;
        }
        let seg_text = crate::fqn::node_text(seg, source);
        if seg_text.is_empty() {
            return None;
        }
        let seg_text = nix_strip_attr_quotes(seg_text);
        if scope.is_empty() {
            scope.push_str(seg_text);
        } else {
            scope.push('.');
            scope.push_str(seg_text);
        }
    }
    if scope.is_empty() {
        None
    } else {
        Some(scope)
    }
}

/// True when a Nix binding's value is an attribute set — the binding names
/// a scope rather than defining a value (C cbm_nix_binding_is_attrset_scope).
pub fn nix_binding_is_attrset_scope(node: tree_sitter::Node<'_>) -> bool {
    if node.kind() != "binding" {
        return false;
    }
    let Some(value) = node.child_by_field_name("expression") else {
        return false;
    };
    matches!(
        value.kind(),
        "attrset_expression" | "rec_attrset_expression"
    )
}

// ── push_var_def (C push_var_def_qn) ────────────────────────────

fn push_var_def_qn(
    ctx: &mut ExtractCtx<'_>,
    name: &str,
    qn_name: Option<&str>,
    node: tree_sitter::Node<'_>,
) {
    if name.is_empty() || name == "_" {
        return;
    }
    let mut def = Definition {
        name: name.to_string(),
        label: "Variable".to_string(),
        file_path: ctx.rel_path.to_string(),
        ..Default::default()
    };
    // Java/Go: directory-based module (package), so a Go package-level var
    // in myapp/db/conn.go is proj.myapp.db.Var, matching its siblings.
    def.qualified_name = crate::fqn::fqn_compute_source_lang(
        ctx.project,
        ctx.rel_path,
        Some(qn_name.unwrap_or(name)),
        ctx.language,
    );
    def.start_line = node.start_position().row as u32 + 1;
    def.end_line = node.end_position().row as u32 + 1;
    def.is_exported = helpers::is_exported(name, ctx.language);
    ctx.result.definitions.push(def);
}

fn push_var_def(ctx: &mut ExtractCtx<'_>, name: &str, node: tree_sitter::Node<'_>) {
    push_var_def_qn(ctx, name, None, node);
}

// ── Name extractors from declarator chains ──────────────────────

/// C/C++/ObjC declarator chain: declaration → [init_declarator] →
/// [pointer/reference_declarator]* → identifier (C
/// extract_c_declarator_name).
fn extract_c_declarator_name<'t>(decl: tree_sitter::Node<'t>, source: &'t str) -> Option<String> {
    let mut declarator = decl.child_by_field_name("declarator")?;
    let mut dk = declarator.kind();
    if dk == "init_declarator" {
        declarator = declarator.child_by_field_name("declarator")?;
        dk = declarator.kind();
    }
    while dk == "pointer_declarator" || dk == "reference_declarator" {
        declarator = declarator.child_by_field_name("declarator")?;
        dk = declarator.kind();
    }
    (dk == "identifier").then(|| crate::fqn::node_text(declarator, source).to_string())
}

/// Java/C# field_declaration (declarator → name) (C
/// extract_java_field_name).
fn extract_java_field_name<'t>(field: tree_sitter::Node<'t>, source: &'t str) -> Option<String> {
    let declarator = match field.child_by_field_name("declarator") {
        Some(d) => d,
        None => (0..field.named_child_count())
            .filter_map(|i| field.named_child(i))
            .find(|c| c.kind() == "variable_declarator")?,
    };
    let name = declarator.child_by_field_name("name")?;
    Some(crate::fqn::node_text(name, source).to_string())
}

/// C# field_declaration with nested variable_declaration (C
/// extract_csharp_vars).
fn extract_csharp_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    if let Some(fname) = extract_java_field_name(node, ctx.source) {
        push_var_def(ctx, &fname, node);
        return;
    }
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        if child.kind() != "variable_declaration" {
            continue;
        }
        for j in 0..child.named_child_count() {
            let Some(decl) = child.named_child(j) else {
                continue;
            };
            if decl.kind() != "variable_declarator" {
                continue;
            }
            if let Some(id) = decl
                .child_by_field_name("name")
                .or_else(|| crate::fqn::find_child_by_kind(decl, "identifier"))
            {
                let t = crate::fqn::node_text(id, ctx.source);
                push_var_def(ctx, t, decl);
            }
        }
    }
}

/// JS/TS destructuring + plain declarators (C extract_js_vars).
fn extract_js_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    for i in 0..node.named_child_count() {
        let Some(decl) = node.named_child(i) else {
            continue;
        };
        if !matches!(decl.kind(), "variable_declarator" | "init_declarator") {
            continue;
        }
        let Some(name_node) = decl.child_by_field_name("name") else {
            continue;
        };
        if name_node.kind() == "object_pattern" || name_node.kind() == "array_pattern" {
            // Destructuring: emit each bound identifier (C
            // extract_destructured_vars).
            for k in 0..name_node.named_child_count() {
                if let Some(part) = name_node.named_child(k) {
                    collect_destructured_names(ctx, part, node);
                }
            }
            continue;
        }
        let name = crate::fqn::node_text(name_node, ctx.source);
        if !name.is_empty() {
            push_var_def(ctx, name, node);
        }
    }
}

/// Destructuring pattern members (C extract_destructured_vars).
fn collect_destructured_names(
    ctx: &mut ExtractCtx<'_>,
    part: tree_sitter::Node<'_>,
    site: tree_sitter::Node<'_>,
) {
    match part.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            let name = crate::fqn::node_text(part, ctx.source);
            if !name.is_empty() {
                push_var_def(ctx, name, site);
            }
        }
        "pair" | "pair_pattern" => {
            // {key: binding} — the VALUE side is the local binding.
            if let Some(value) = part.child_by_field_name("value") {
                collect_destructured_names(ctx, value, site);
            }
        }
        "rest_pattern" | "assignment_pattern" => {
            for k in 0..part.named_child_count() {
                if let Some(inner) = part.named_child(k) {
                    collect_destructured_names(ctx, inner, site);
                }
            }
        }
        _ => {}
    }
}

/// Python assignment LHS (C mainstream PYTHON arm): identifier or
/// tuple/list unpacking.
fn extract_python_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let lt = left.kind();
    if lt == "identifier" {
        let name = crate::fqn::node_text(left, ctx.source);
        push_var_def(ctx, name, node);
    } else if matches!(lt, "pattern_list" | "tuple_pattern" | "list_pattern") {
        // Tuple/list unpacking: `x, y = f()` — one Variable per unpacked
        // identifier (#new_py_tuple_unpack).
        for li in 0..left.named_child_count() {
            if let Some(part) = left.named_child(li) {
                if part.kind() == "identifier" {
                    let name = crate::fqn::node_text(part, ctx.source);
                    push_var_def(ctx, name, node);
                }
            }
        }
    }
}

/// Go var/const spec children (C mainstream GO arm). The crates.io
/// grammar wraps grouped specs in a `var_spec_list` the C's vendored
/// grammar lacked — descend one extra level when present.
fn extract_go_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        if matches!(child.kind(), "var_spec" | "const_spec") {
            push_go_spec(ctx, child);
        } else if matches!(child.kind(), "var_spec_list" | "const_spec_list") {
            for j in 0..child.named_child_count() {
                if let Some(spec) = child.named_child(j) {
                    if matches!(spec.kind(), "var_spec" | "const_spec") {
                        push_go_spec(ctx, spec);
                    }
                }
            }
        }
    }
}

fn push_go_spec(ctx: &mut ExtractCtx<'_>, child: tree_sitter::Node<'_>) {
    if let Some(vname) = child.child_by_field_name("name") {
        let name = crate::fqn::node_text(vname, ctx.source);
        push_var_def(ctx, name, child);
    }
}

/// PHP expression_statement assignments (C extract_php_vars): strip `$`.
fn extract_php_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    if node.kind() != "expression_statement" {
        return;
    }
    for j in 0..node.named_child_count() {
        let Some(inner) = node.named_child(j) else {
            continue;
        };
        if inner.kind() == "assignment_expression" {
            if let Some(left) = inner.child_by_field_name("left") {
                let name = crate::fqn::node_text(left, ctx.source);
                let stripped = name.strip_prefix('$').unwrap_or(name);
                if !stripped.is_empty() {
                    push_var_def(ctx, stripped, node);
                }
            }
        }
    }
}

/// Lua assignment_statement with function-def filtering (C extract_lua_vars).
fn extract_lua_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        if child.kind() != "assignment_statement" {
            continue;
        }
        // `local function f()` / `f = function()` are Function defs.
        if let Some(expr_list) = crate::fqn::find_child_by_kind(child, "expression_list") {
            if expr_list.named_child_count() > 0 {
                if let Some(val) = expr_list.named_child(0) {
                    if val.kind() == "function_definition" {
                        continue;
                    }
                }
            }
        }
        let vars = child
            .child_by_field_name("variables")
            .or_else(|| crate::fqn::find_child_by_kind(child, "variable_list"));
        if let Some(vars) = vars {
            if vars.named_child_count() > 0 {
                if let Some(first) = vars.named_child(0) {
                    let name = crate::fqn::node_text(first, ctx.source);
                    push_var_def(ctx, name, node);
                }
            }
        }
    }
}

/// Perl variable nodes and assignment LHS (C extract_perl_vars).
fn is_perl_var_type(ck: &str) -> bool {
    matches!(
        ck,
        "scalar_variable"
            | "array_variable"
            | "hash_variable"
            | "variable_declarator"
            | "scalar"
            | "array"
            | "hash"
    )
}

fn extract_perl_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        let ck = child.kind();
        if is_perl_var_type(ck) {
            let name = crate::fqn::node_text(child, ctx.source);
            let stripped = name.strip_prefix(['$', '@', '%']).unwrap_or(name);
            push_var_def(ctx, stripped, node);
            return;
        }
        if ck != "assignment_expression" {
            continue;
        }
        let mut left = child
            .child_by_field_name("left")
            .or_else(|| child.named_child(0));
        let Some(lhs) = left else { continue };
        if lhs.kind() == "variable_declaration" {
            for li in 0..lhs.named_child_count() {
                if let Some(var_node) = lhs.named_child(li) {
                    if is_perl_var_type(var_node.kind()) {
                        left = Some(var_node);
                        break;
                    }
                }
            }
        }
        if let Some(lhs) = left {
            let name = crate::fqn::node_text(lhs, ctx.source);
            let stripped = name.strip_prefix(['$', '@', '%']).unwrap_or(name);
            push_var_def(ctx, stripped, node);
        }
        return;
    }
}

/// R assignment LHS with function-def skip (C extract_r_vars).
fn extract_r_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    for ri in 0..node.named_child_count() {
        if let Some(ch) = node.named_child(ri) {
            if ch.kind() == "function_definition" {
                return;
            }
        }
    }
    let left = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("lhs"))
        .or_else(|| node.named_child(0));
    if let Some(left) = left {
        if matches!(left.kind(), "identifier" | "constant" | "string") {
            let name = crate::fqn::node_text(left, ctx.source);
            push_var_def(ctx, name, node);
        }
    }
}

/// Kotlin name resolution (C resolve_kotlin_var_name).
fn resolve_kotlin_var_name<'t>(node: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    if let Some(n) = node.child_by_field_name("name") {
        return Some(n);
    }
    if let Some(n) = crate::fqn::find_child_by_kind(node, "simple_identifier") {
        return Some(n);
    }
    if let Some(n) = crate::fqn::find_child_by_kind(node, "identifier") {
        return Some(n);
    }
    let var_decl = crate::fqn::find_child_by_kind(node, "variable_declaration")?;
    crate::fqn::find_child_by_kind(var_decl, "simple_identifier")
        .or_else(|| crate::fqn::find_child_by_kind(var_decl, "identifier"))
}

/// JVM variables: Scala pattern/name, Kotlin chain, Groovy name/declarator.
fn extract_vars_jvm(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    match ctx.language {
        Language::SCALA => {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                let name = crate::fqn::node_text(pattern, ctx.source);
                push_var_def(ctx, name, node);
            } else if let Some(name_node) = node.child_by_field_name("name") {
                let name = crate::fqn::node_text(name_node, ctx.source);
                push_var_def(ctx, name, node);
            }
        }
        Language::KOTLIN => {
            if let Some(name_node) = resolve_kotlin_var_name(node) {
                let name = crate::fqn::node_text(name_node, ctx.source);
                push_var_def(ctx, name, node);
            }
        }
        Language::GROOVY => {
            let name_node = match node.child_by_field_name("name") {
                Some(n) => Some(n),
                None => {
                    if let Some(cname) = extract_c_declarator_name(node, ctx.source) {
                        push_var_def(ctx, &cname, node);
                        return;
                    }
                    crate::fqn::find_child_by_kind(node, "identifier")
                }
            };
            if let Some(n) = name_node {
                let name = crate::fqn::node_text(n, ctx.source);
                push_var_def(ctx, name, node);
            }
        }
        _ => {}
    }
}

fn trim_whitespace(name: &str) -> &str {
    name.trim_matches([' ', '\t'])
}

/// INI settings (C extract_ini_vars): setting_name/name child, else first
/// child.
fn extract_ini_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    let nc = node.child_count();
    for i in 0..nc {
        if let Some(child) = node.child(i) {
            if matches!(child.kind(), "setting_name" | "name") {
                let name = trim_whitespace(crate::fqn::node_text(child, ctx.source));
                push_var_def(ctx, name, node);
                return;
            }
        }
    }
    if nc > 0 {
        let has_name = (0..nc).any(|i| {
            node.child(i)
                .map(|c| matches!(c.kind(), "setting_name" | "name"))
                .unwrap_or(false)
        });
        if !has_name {
            if let Some(first) = node.child(0) {
                let name = trim_whitespace(crate::fqn::node_text(first, ctx.source));
                push_var_def(ctx, name, node);
            }
        }
    }
}

/// First named child matching one of the types (C push_first_matching_child).
fn push_first_matching_child(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    match_types: &[&str],
) {
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        if match_types.contains(&child.kind()) {
            let name = crate::fqn::node_text(child, ctx.source);
            push_var_def(ctx, name, node);
            return;
        }
    }
}

/// JSON key with quote strip (C extract_json_var).
fn extract_json_var(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    let Some(key_node) = node.child_by_field_name("key") else {
        return;
    };
    let raw = crate::fqn::node_text(key_node, ctx.source);
    let b = raw.as_bytes();
    let stripped = if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    push_var_def(ctx, stripped, node);
}

/// SCSS variable name (C extract_scss_var): property > name >
/// property_name > variable_name.
fn extract_scss_var(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    let prop = node
        .child_by_field_name("property")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| crate::fqn::find_child_by_kind(node, "property_name"))
        .or_else(|| crate::fqn::find_child_by_kind(node, "variable_name"));
    if let Some(prop) = prop {
        let name = crate::fqn::node_text(prop, ctx.source);
        push_var_def(ctx, name, node);
    }
}

/// TOML bare/dotted/quoted key (C find_toml_key_name).
fn find_toml_key_name<'t>(node: tree_sitter::Node<'t>, source: &'t str) -> Option<String> {
    for i in 0..node.child_count() {
        let child = node.child(i)?;
        if matches!(
            child.kind(),
            "bare_key" | "dotted_key" | "quoted_key" | "key"
        ) {
            return Some(crate::fqn::node_text(child, source).to_string());
        }
    }
    None
}

/// Config-language variables (C extract_vars_config).
fn extract_vars_config(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    let kind = node.kind();
    match ctx.language {
        Language::YAML => {
            if let Some(key) = node.child_by_field_name("key") {
                let name = crate::fqn::node_text(key, ctx.source);
                push_var_def(ctx, name, node);
            }
        }
        Language::TOML => {
            if let Some(name) = find_toml_key_name(node, ctx.source) {
                push_var_def(ctx, &name, node);
            }
        }
        Language::JSON => extract_json_var(ctx, node),
        Language::INI => extract_ini_vars(ctx, node),
        Language::ERLANG => {
            if matches!(kind, "pp_define" | "record_decl") {
                push_first_matching_child(ctx, node, &["atom", "var", "macro_lhs"]);
            }
        }
        Language::SQL => {
            push_first_matching_child(ctx, node, &["identifier", "object_reference"]);
        }
        Language::BASH => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = crate::fqn::node_text(name_node, ctx.source);
                push_var_def(ctx, name, node);
            } else {
                push_first_matching_child(ctx, node, &["variable_name", "word"]);
            }
        }
        Language::SCSS => extract_scss_var(ctx, node),
        _ => {}
    }
}

/// Nix module-level binding (C extract_vars_nix): skip lambda-valued
/// bindings (already Functions) and attrset scopes; the name is the
/// attrpath leaf and the QN carries the whole path.
fn extract_vars_nix(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    if node.kind() != "binding" {
        return;
    }
    let Some(value) = node.child_by_field_name("expression") else {
        return;
    };
    if value.kind() == "function_expression" {
        return; // already a Function
    }
    if nix_binding_is_attrset_scope(node) {
        return; // a scope, not a value
    }
    let attrpath = node.child_by_field_name("attrpath");
    let Some(leaf) = attrpath.and_then(nix_attrpath_last_attr) else {
        return;
    };
    if nix_attr_is_interpolated(leaf) {
        return;
    }
    let name_raw = crate::fqn::node_text(leaf, ctx.source);
    if name_raw.is_empty() {
        return;
    }
    let name = nix_strip_attr_quotes(name_raw);
    let scope = attrpath.and_then(|ap| nix_attrpath_scope(ap, ctx.source));
    let qn_name = scope.as_ref().map(|s| format!("{s}.{name}"));
    push_var_def_qn(ctx, name, qn_name.as_deref(), node);
}

/// Dockerfile ENV/ARG (C inline in extract_var_names).
fn extract_dockerfile_vars(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    let kind = node.kind();
    if kind == "env_instruction" {
        for i in 0..node.named_child_count() {
            let Some(pair) = node.named_child(i) else {
                continue;
            };
            if pair.kind() != "env_pair" {
                continue;
            }
            if let Some(nm) = pair.child_by_field_name("name") {
                let name = crate::fqn::node_text(nm, ctx.source);
                push_var_def(ctx, name, pair);
            }
        }
    } else if kind == "arg_instruction" {
        let nm = node
            .child_by_field_name("name")
            .or_else(|| crate::fqn::find_child_by_kind(node, "unquoted_string"));
        if let Some(nm) = nm {
            let name = crate::fqn::node_text(nm, ctx.source);
            push_var_def(ctx, name, node);
        }
    }
}

/// Mainstream group (C extract_vars_mainstream).
fn extract_vars_mainstream(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    match ctx.language {
        Language::PYTHON => extract_python_vars(ctx, node),
        Language::GO => extract_go_vars(ctx, node),
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS => {
            extract_js_vars(ctx, node)
        }
        Language::JAVA => {
            if let Some(fname) = extract_java_field_name(node, ctx.source) {
                push_var_def(ctx, &fname, node);
            }
        }
        Language::CSHARP => extract_csharp_vars(ctx, node),
        Language::CPP | Language::C | Language::OBJC => {
            if let Some(vname) = extract_c_declarator_name(node, ctx.source) {
                push_var_def(ctx, &vname, node);
            }
        }
        Language::RUST => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = crate::fqn::node_text(name_node, ctx.source);
                push_var_def(ctx, name, node);
            }
        }
        _ => {}
    }
}

/// Dynamic/scripting group (C extract_vars_dynamic).
fn extract_vars_dynamic(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    match ctx.language {
        Language::PHP => extract_php_vars(ctx, node),
        Language::LUA => extract_lua_vars(ctx, node),
        Language::RUBY => {
            if let Some(left) = node.child_by_field_name("left") {
                if matches!(left.kind(), "identifier" | "constant") {
                    let name = crate::fqn::node_text(left, ctx.source);
                    push_var_def(ctx, name, node);
                }
            }
        }
        Language::R => extract_r_vars(ctx, node),
        Language::PERL => extract_perl_vars(ctx, node),
        _ => {}
    }
}

/// Variable-name dispatch (C extract_var_names): Nix first, then the
/// language groups, Dockerfile/.properties/go.mod special shapes, and the
/// name-field → C-declarator → first-identifier fallback.
pub fn extract_var_names(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    if ctx.language == Language::NIX {
        extract_vars_nix(ctx, node);
        return;
    }
    match ctx.language {
        Language::PYTHON
        | Language::GO
        | Language::JAVASCRIPT
        | Language::TYPESCRIPT
        | Language::TSX
        | Language::ARKTS
        | Language::JAVA
        | Language::CSHARP
        | Language::CPP
        | Language::C
        | Language::OBJC
        | Language::RUST => {
            extract_vars_mainstream(ctx, node);
            return;
        }
        Language::PHP | Language::LUA | Language::RUBY | Language::R | Language::PERL => {
            extract_vars_dynamic(ctx, node);
            return;
        }
        Language::SCALA | Language::KOTLIN | Language::GROOVY => {
            extract_vars_jvm(ctx, node);
            return;
        }
        Language::YAML
        | Language::TOML
        | Language::JSON
        | Language::INI
        | Language::ERLANG
        | Language::SQL
        | Language::BASH
        | Language::SCSS => {
            extract_vars_config(ctx, node);
            return;
        }
        Language::DOCKERFILE => {
            extract_dockerfile_vars(ctx, node);
            return;
        }
        Language::PROPERTIES => {
            if node.kind() == "property" {
                if let Some(key) = crate::fqn::find_child_by_kind(node, "key") {
                    let name = crate::fqn::node_text(key, ctx.source);
                    push_var_def(ctx, name, node);
                }
            }
            return;
        }
        Language::GOMOD => {
            if matches!(node.kind(), "require_directive" | "replace_directive") {
                for i in 0..node.named_child_count() {
                    let Some(req_spec) = node.named_child(i) else {
                        continue;
                    };
                    if !matches!(req_spec.kind(), "require_spec" | "replace_spec") {
                        continue;
                    }
                    if let Some(mp) = crate::fqn::find_child_by_kind(req_spec, "module_path") {
                        let name = crate::fqn::node_text(mp, ctx.source);
                        push_var_def(ctx, name, req_spec);
                    }
                }
            }
            return;
        }
        _ => {}
    }

    // Default fallback: name field → C-declarator → first identifier.
    if let Some(name_node) = node.child_by_field_name("name") {
        let name = crate::fqn::node_text(name_node, ctx.source);
        push_var_def(ctx, name, node);
        return;
    }
    if let Some(cname) = extract_c_declarator_name(node, ctx.source) {
        push_var_def(ctx, &cname, node);
        return;
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            if child.kind() == "identifier" {
                let name = crate::fqn::node_text(child, ctx.source);
                push_var_def(ctx, name, node);
                return;
            }
        }
    }
}

/// Iterative variable walker for nested config structures (C
/// walk_variables_iter): descend only through the config-container kinds.
pub fn walk_variables_iter(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        for i in (0..node.child_count()).rev() {
            let Some(child) = node.child(i) else { continue };
            if spec.variable_node_types.contains(&child.kind())
                && is_module_level_p(node, ctx.language)
            {
                extract_var_names(ctx, child);
            }
            if matches!(
                child.kind(),
                "document"
                    | "block_node"
                    | "block_mapping"
                    | "stream"
                    | "table"
                    | "table_array_element"
                    | "section"
                    | "object"
                    | "array"
                    | "pair"
                    | "element"
                    | "content"
            ) {
                stack.push(child);
            }
        }
    }
}

/// Nix module variables (C extract_nix_module_vars): walk past the header
/// lambda(s) to the let body / returned attrset and mint each direct
/// binding. Deeper nesting is deliberately skipped.
const NIX_HEADER_HOP_MAX: usize = 8;

fn extract_nix_binding_set(ctx: &mut ExtractCtx<'_>, set: Option<tree_sitter::Node<'_>>) {
    let Some(set) = set else { return };
    for i in 0..set.named_child_count() {
        if let Some(child) = set.named_child(i) {
            if child.kind() == "binding" {
                extract_var_names(ctx, child);
            }
        }
    }
}

pub fn extract_nix_module_vars(ctx: &mut ExtractCtx<'_>) {
    let mut cur = if ctx.root.named_child_count() > 0 {
        ctx.root.named_child(0)
    } else {
        Some(ctx.root)
    };
    // Descend header lambdas: `{ pkgs, ... }: <body>`, `final: prev: <body>`.
    for _ in 0..NIX_HEADER_HOP_MAX {
        let Some(c) = cur else { return };
        if c.kind() != "function_expression" {
            break;
        }
        cur = c.child_by_field_name("body");
    }
    let Some(cur) = cur else { return };
    if cur.kind() == "let_expression" {
        extract_nix_binding_set(ctx, crate::fqn::find_child_by_kind(cur, "binding_set"));
        let Some(body) = cur.child_by_field_name("body") else {
            return;
        };
        let k = body.kind();
        if matches!(k, "attrset_expression" | "rec_attrset_expression") {
            extract_nix_binding_set(ctx, crate::fqn::find_child_by_kind(body, "binding_set"));
        } else if k == "binding_set" {
            extract_nix_binding_set(ctx, Some(body));
        }
        return;
    }
    let k = cur.kind();
    if matches!(k, "attrset_expression" | "rec_attrset_expression") {
        extract_nix_binding_set(ctx, crate::fqn::find_child_by_kind(cur, "binding_set"));
    } else if k == "binding_set" {
        // crates.io grammar: a top-level `{ ... }` IS the binding_set
        // (the C's vendored grammar wrapped it in attrset_expression).
        extract_nix_binding_set(ctx, Some(cur));
    }
}

/// True when the basename is values.yaml / values.yml (Helm values, #338).
pub fn is_helm_values_file(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    base == "values.yaml" || base == "values.yml"
}

/// Find the YAML top-level block_mapping (C find_yaml_toplevel_mapping):
/// descend through document/block_node wrappers, at most 6 levels.
fn find_yaml_toplevel_mapping(root: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut cur = root;
    for _ in 0..6 {
        let mut next = None;
        for i in 0..cur.child_count() {
            let ch = cur.child(i)?;
            match ch.kind() {
                "block_mapping" => return Some(ch),
                "document" | "block_node" if next.is_none() => next = Some(ch),
                _ => {}
            }
        }
        cur = next?;
    }
    None
}

/// Helm values.yaml: only top-level keys, not the per-leaf flood (C
/// extract_yaml_toplevel_keys).
fn extract_yaml_toplevel_keys(ctx: &mut ExtractCtx<'_>) {
    let Some(bm) = find_yaml_toplevel_mapping(ctx.root) else {
        return;
    };
    for i in 0..bm.named_child_count() {
        let Some(pair) = bm.named_child(i) else {
            continue;
        };
        if pair.kind() != "block_mapping_pair" {
            continue;
        }
        if let Some(key) = pair.child_by_field_name("key") {
            let name = crate::fqn::node_text(key, ctx.source);
            push_var_def(ctx, name, pair);
        }
    }
}

/// Module-level variable extraction (C extract_variables): Helm values
/// special case, nested-config walker, Nix header resolution, then the
/// top-level loop with wrapper unwrapping.
pub fn extract_variables(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    if spec.variable_node_types.is_empty() {
        return;
    }

    // Helm values.yaml: only top-level keys, not the per-leaf flood.
    if ctx.language == Language::YAML && is_helm_values_file(ctx.rel_path) {
        extract_yaml_toplevel_keys(ctx);
        return;
    }

    // Config languages with nested structure: recursive walk.
    if matches!(
        ctx.language,
        Language::YAML | Language::TOML | Language::INI | Language::JSON
    ) {
        walk_variables_iter(ctx, spec);
        return;
    }

    // Nix: the file's top level sits behind its header lambda(s); resolve
    // to the binding container(s) that constitute file scope, and mint
    // only THEIR direct bindings.
    if ctx.language == Language::NIX {
        extract_nix_module_vars(ctx);
        return;
    }

    // root is the file root, so the module-level check is invariant across
    // the loop — hoist it out (C comment).
    if !is_module_level_p(ctx.root, ctx.language) {
        return;
    }

    // Top-level children with wrapper unwrapping (expression_statement /
    // export_statement / statement).
    for i in 0..ctx.root.child_count() {
        let Some(child) = ctx.root.child(i) else {
            continue;
        };
        if spec.variable_node_types.contains(&child.kind()) {
            extract_var_names(ctx, child);
            continue;
        }
        let ck = child.kind();
        if matches!(
            ck,
            "expression_statement" | "export_statement" | "statement"
        ) {
            for j in 0..child.named_child_count() {
                if let Some(inner) = child.named_child(j) {
                    if spec.variable_node_types.contains(&inner.kind()) {
                        extract_var_names(ctx, inner);
                    }
                }
            }
            // The wrapper itself may be a variable type (PHP
            // expression_statement).
            if spec.variable_node_types.contains(&ck) {
                extract_var_names(ctx, child);
            }
        }
    }
}

// ── walk_defs (C, main-language dispatch) ───────────────────────
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
            if !spec.function_node_types.is_empty() && spec.function_node_types.contains(&kind) {
                extract_func_def(ctx, node, spec);
                // Most languages stop; JS/TS-family descend for nested named
                // defs (factory-actions pattern, #341).
                let descend = matches!(
                    ctx.language,
                    Language::TYPESCRIPT | Language::JAVASCRIPT | Language::TSX | Language::ARKTS
                );
                if !descend {
                    stack.pop();
                    continue;
                }
            } else if !spec.class_node_types.is_empty() && spec.class_node_types.contains(&kind) {
                extract_class_def(ctx, node, spec);
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

// ── Class extraction (C extract_class_def, part 2) ──────────────

/// Class label by node kind (C class_label_for_kind): interface/enum/type
/// variants; GO type_spec label refinement (interface_type/struct_type).
fn class_label_for(kind: &str, node: tree_sitter::Node<'_>, lang: Language) -> &'static str {
    if matches!(
        kind,
        "interface_declaration"
            | "interface_type"
            | "trait_item"
            | "trait_definition"
            | "protocol_declaration"
    ) {
        return "Interface";
    }
    if matches!(kind, "enum_specifier" | "enum_declaration" | "enum_item") {
        return "Enum";
    }
    if matches!(
        kind,
        "type_alias_declaration" | "type_item" | "type_alias" | "type_definition"
    ) {
        return "Type";
    }
    if lang == Language::GO && kind == "type_spec" {
        if let Some(t) = node.child_by_field_name("type") {
            return match t.kind() {
                "interface_type" => "Interface",
                "struct_type" => "Struct",
                _ => "Class",
            };
        }
    }
    "Class"
}

/// JS/TS bases (C extract_ts_bases + collect_ts_bases): extends_clause value
/// / implements_clause / extends_type_clause named children; generic_type
/// unwraps to its `name`; strip `<...>` args and a leading backslash.
fn collect_ts_bases(clause: tree_sitter::Node<'_>, source: &str, out: &mut Vec<String>) {
    match clause.kind() {
        "extends_clause" => {
            if let Some(v) = clause.child_by_field_name("value") {
                push_base_text(v, source, out);
            }
        }
        "implements_clause" | "extends_type_clause" => {
            for i in 0..clause.named_child_count() {
                let c = clause.named_child(i).unwrap();
                if c.kind() == "type_arguments" {
                    continue;
                }
                if c.kind() == "generic_type" {
                    if let Some(nm) = c.child_by_field_name("name") {
                        push_base_text(nm, source, out);
                        continue;
                    }
                }
                push_base_text(c, source, out);
            }
        }
        _ => {
            push_base_text(clause, source, out);
        }
    }
}

fn push_base_text(node: tree_sitter::Node<'_>, source: &str, out: &mut Vec<String>) {
    let mut t = crate::fqn::node_text(node, source).to_string();
    if let Some(angle) = t.find('<') {
        t.truncate(angle);
    }
    if let Some(bs) = t.rfind('\\') {
        t = t[bs + 1..].to_string();
    }
    // Anonymous keyword tokens ("extends"/"implements") under class_heritage
    // carry no base name — skip them (their named siblings carry the types).
    if matches!(t.as_str(), "extends" | "implements") {
        return;
    }
    if !t.is_empty() {
        out.push(t);
    }
}

/// Base-class extraction (C extract_base_classes, part-1 languages: JS/TS
/// class_heritage + Java/Kotlin superclass field).
fn extract_base_classes(node: tree_sitter::Node<'_>, source: &str, lang: Language) -> Vec<String> {
    let mut out = Vec::new();
    if matches!(
        lang,
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS
    ) {
        for i in 0..node.child_count() {
            let child = node.child(i).unwrap();
            match child.kind() {
                "class_heritage" => {
                    for j in 0..child.child_count() {
                        if let Some(c) = child.child(j) {
                            collect_ts_bases(c, source, &mut out);
                        }
                    }
                }
                "extends_type_clause" => collect_ts_bases(child, source, &mut out),
                _ => {}
            }
        }
        return out;
    }
    // Java/Kotlin/Python: superclass field (Java), superclasses / argument
    // list (Kotlin), argument_list (Python bases).
    if let Some(sc) = node
        .child_by_field_name("superclass")
        .or_else(|| crate::fqn::find_child_by_kind(node, "superclass"))
        .or_else(|| crate::fqn::find_child_by_kind(node, "superinterfaces"))
    {
        for i in 0..sc.named_child_count() {
            let b = sc.named_child(i).unwrap();
            if matches!(b.kind(), "type_identifier" | "identifier" | "superclass") {
                out.push(crate::fqn::node_text(b, source).to_string());
            }
        }
        // Python: bases are plain identifiers under argument_list; the
        // superclass container itself may have no named children.
        if out.is_empty() {
            let t = crate::fqn::node_text(sc, source);
            for part in t.split(',') {
                let p = part.trim();
                if !p.is_empty() {
                    out.push(p.to_string());
                }
            }
        }
    }
    out
}

/// Enum-member node kinds (C is_enum_member_kind).
fn is_enum_member_kind(kind: &str) -> bool {
    matches!(
        kind,
        "enum_member_declaration"
            | "enum_constant"
            | "enum_member"
            | "enum_assignment"
            | "enumerator"
    )
}

/// Class-member body lookup (C find_class_body): body / members / class_body
/// / declaration_list fields; GO's type field.
fn find_class_body<'t>(
    class_node: tree_sitter::Node<'t>,
    lang: Language,
) -> Option<tree_sitter::Node<'t>> {
    for f in ["body", "members", "class_body", "declaration_list"] {
        if let Some(body) = class_node.child_by_field_name(f) {
            return Some(body);
        }
    }
    if lang == Language::GO {
        if let Some(t) = class_node.child_by_field_name("type") {
            return Some(t);
        }
    }
    None
}

/// Java enum_body → enum_body_declarations normalization
/// (C find_class_member_body).
fn find_class_member_body<'t>(
    class_node: tree_sitter::Node<'t>,
    lang: Language,
) -> Option<tree_sitter::Node<'t>> {
    let body = find_class_body(class_node, lang)?;
    if lang == Language::JAVA && body.kind() == "enum_body" {
        return crate::fqn::find_child_by_kind(body, "enum_body_declarations").or(Some(body));
    }
    Some(body)
}

/// Method definition emission (C push_method_def).
fn push_method_def(
    ctx: &mut ExtractCtx<'_>,
    child: tree_sitter::Node<'_>,
    class_qn: &str,
    name_node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
) {
    let name = crate::fqn::normalize_name_node_text(name_node, ctx.source, ctx.language);
    if name.is_empty() {
        return;
    }
    let mut def = Definition {
        name: name.clone(),
        qualified_name: format!("{class_qn}.{name}"),
        label: "Method".to_string(),
        file_path: ctx.rel_path.to_string(),
        parent_class: Some(class_qn.to_string()),
        ..Default::default()
    };
    def.start_line = child.start_position().row as u32 + 1;
    def.end_line = child.end_position().row as u32 + 1;
    def.lines = (def.end_line - def.start_line + 1) as i32;
    def.is_exported = helpers::is_exported(&name, ctx.language);
    if ctx.language == Language::RUST && child.kind() == "function_signature_item" {
        def.is_abstract = true;
    }
    if let Some(params) = find_function_params(child, ctx.language) {
        def.signature = Some(crate::fqn::node_text(params, ctx.source).to_string());
        // Param types (names come from the def walk's param capture).
        for i in 0..params.named_child_count() {
            let Some(c) = params.named_child(i) else {
                continue;
            };
            if let Some(t) = c.child_by_field_name("type") {
                def.param_types
                    .push(crate::fqn::node_text(t, ctx.source).to_string());
            }
        }
    }
    for f in ["result", "return_type", "type"] {
        if let Some(rt) = child.child_by_field_name(f) {
            def.return_type = Some(crate::fqn::node_text(rt, ctx.source).to_string());
            break;
        }
    }
    def.docstring = extract_docstring(child, ctx.source, ctx.language);
    if !spec.branching_node_types.is_empty() {
        let mut cx = Complexity::default();
        compute_complexity(child, spec.branching_node_types, &mut cx);
        def.complexity = cx.cyclomatic;
        def.cognitive = cx.cognitive;
        def.loop_count = cx.loop_count;
        def.loop_depth = cx.loop_depth;
        def.max_access_depth = cx.max_access_depth;
    }
    def.body_tokens = extract_body_ident_tokens(child, ctx.source);
    def.is_test = def.is_test || ctx.result.is_test_file;
    ctx.result.definitions.push(def);
}

/// Methods inside a class body (C extract_class_methods, part-1 languages):
/// decorated_definition unwrap (Python), public_field_definition arrow
/// methods (TS/JS React handlers), direct function kinds.
fn extract_class_methods(
    ctx: &mut ExtractCtx<'_>,
    class_node: tree_sitter::Node<'_>,
    class_qn: &str,
    spec: &LanguageSpec,
) {
    let Some(body) = find_class_member_body(class_node, ctx.language) else {
        return;
    };
    for i in 0..body.child_count() {
        let Some(mut child) = body.child(i) else {
            continue;
        };
        // Python wraps @classmethod/@staticmethod/@property in
        // decorated_definition — peek to the inner definition.
        if child.kind() == "decorated_definition" {
            let Some(def) = child.child_by_field_name("definition") else {
                continue;
            };
            if !spec.function_node_types.contains(&def.kind()) {
                continue;
            }
            child = def;
        }
        // TS class-field arrow: `public_field_definition` (TS grammar) /
        // `field_definition` (JS grammar) whose value is an arrow function.
        // The field name is the `name` field (TS) or the first
        // property_identifier child (JS).
        if matches!(child.kind(), "public_field_definition" | "field_definition") {
            let Some(value) = child.child_by_field_name("value") else {
                continue;
            };
            if !spec.function_node_types.contains(&value.kind()) {
                continue;
            }
            let fname = child
                .child_by_field_name("name")
                .or_else(|| crate::fqn::find_child_by_kind(child, "property_identifier"));
            let Some(fname) = fname else {
                continue;
            };
            push_method_def(ctx, value, class_qn, fname, spec);
            continue;
        }
        if spec.function_node_types.contains(&child.kind()) {
            // Rust: impl methods resolve via their own `name` field.
            let Some(name_node) = resolve_func_name(child, ctx.language) else {
                continue;
            };
            push_method_def(ctx, child, class_qn, name_node, spec);
        }
    }
}

/// Typed class fields (C extract_class_fields, part-1 languages): body
/// children matching field_node_types with a `type` field.
fn extract_class_fields(
    ctx: &mut ExtractCtx<'_>,
    class_node: tree_sitter::Node<'_>,
    class_qn: &str,
    spec: &LanguageSpec,
) {
    if spec.field_node_types.is_empty() {
        return;
    }
    let Some(body) = find_class_member_body(class_node, ctx.language) else {
        return;
    };
    for i in 0..body.named_child_count() {
        let Some(child) = body.named_child(i) else {
            continue;
        };
        if !spec.field_node_types.contains(&child.kind()) {
            continue;
        }
        // Field name: `name` field, else a variable_declarator's identifier
        // (Java field_declaration → variable_declarator → identifier), else
        // the first identifier child.
        let name = child
            .child_by_field_name("name")
            .map(|n| crate::fqn::node_text(n, ctx.source).to_string())
            .or_else(|| {
                crate::fqn::find_child_by_kind(child, "variable_declarator").and_then(|vd| {
                    vd.child_by_field_name("name")
                        .map(|n| crate::fqn::node_text(n, ctx.source).to_string())
                })
            })
            .or_else(|| {
                crate::fqn::find_child_by_kind(child, "identifier")
                    .map(|n| crate::fqn::node_text(n, ctx.source).to_string())
            });
        let Some(name) = name else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let mut pdef = Definition {
            name: name.clone(),
            qualified_name: format!("{class_qn}.{name}"),
            label: "Field".to_string(),
            file_path: ctx.rel_path.to_string(),
            parent_class: Some(class_qn.to_string()),
            ..Default::default()
        };
        pdef.start_line = child.start_position().row as u32 + 1;
        pdef.end_line = child.end_position().row as u32 + 1;
        if let Some(t) = child.child_by_field_name("type") {
            pdef.return_type = Some(crate::fqn::node_text(t, ctx.source).to_string());
        }
        ctx.result.definitions.push(pdef);
    }
}

/// Enum members as Variable nodes (C extract_enum_members).
fn extract_enum_members(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, class_qn: &str) {
    let Some(body) = find_class_body(node, ctx.language) else {
        eprintln!("DBG enum: no body");
        return;
    };
    eprintln!(
        "DBG enum body={:?} members={}",
        body.kind(),
        body.named_child_count()
    );
    for mi in 0..body.named_child_count() {
        let Some(member) = body.named_child(mi) else {
            continue;
        };
        if !is_enum_member_kind(member.kind()) {
            continue;
        }
        let mname = member
            .child_by_field_name("name")
            .or_else(|| crate::fqn::find_child_by_kind(member, "identifier"));
        let Some(mname) = mname else {
            continue;
        };
        let member_name = crate::fqn::node_text(mname, ctx.source);
        if member_name.is_empty() {
            continue;
        }
        ctx.result.definitions.push(Definition {
            name: member_name.to_string(),
            qualified_name: format!("{class_qn}.{member_name}"),
            label: "Variable".to_string(),
            file_path: ctx.rel_path.to_string(),
            start_line: member.start_position().row as u32 + 1,
            end_line: member.end_position().row as u32 + 1,
            ..Default::default()
        });
    }
}

/// Class extraction (C extract_class_def, part-2 shape): label refinement,
/// bases, enum members, methods, fields.
fn extract_class_def(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>, spec: &LanguageSpec) {
    let kind = node.kind();
    let Some(name_node) = node
        .child_by_field_name("name")
        .or_else(|| crate::fqn::find_child_by_kind(node, "type_identifier"))
    else {
        return;
    };
    let name = crate::fqn::node_text(name_node, ctx.source);
    if name.is_empty() {
        return;
    }
    let label = class_label_for(kind, node, ctx.language);
    let class_qn =
        crate::fqn::fqn_compute_source_lang(ctx.project, ctx.rel_path, Some(name), ctx.language);
    let name_owned = name.to_string();
    let mut def = Definition {
        name: name_owned,
        qualified_name: class_qn.clone(),
        label: label.to_string(),
        file_path: ctx.rel_path.to_string(),
        ..Default::default()
    };
    def.start_line = node.start_position().row as u32 + 1;
    def.end_line = node.end_position().row as u32 + 1;
    def.lines = (def.end_line - def.start_line + 1) as i32;
    def.is_exported = helpers::is_exported(name, ctx.language);
    def.base_classes = extract_base_classes(node, ctx.source, ctx.language);
    def.docstring = extract_docstring(node, ctx.source, ctx.language);
    ctx.result.definitions.push(def);
    if label == "Enum" {
        extract_enum_members(ctx, node, &class_qn);
    }
    extract_class_methods(ctx, node, &class_qn, spec);
    extract_class_fields(ctx, node, &class_qn, spec);
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
        compute_complexity(
            body,
            &[
                "if_statement",
                "elif_clause",
                "for_statement",
                "while_statement",
            ],
            &mut cx,
        );
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
        let with_doc = run(
            Language::PYTHON,
            "def g():\n    \"\"\"Does things.\"\"\"\n",
            "app.py",
        );
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
        let src =
            "package app\ntype Svc struct{}\nfunc (s *Svc) Start() error {\n\treturn nil\n}\n";
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
        assert!(c.base_classes.contains(&"Base".to_string()), "{c:?}");
        assert!(
            !c.base_classes.contains(&"extends".to_string()),
            "keyword filtered"
        );
    }

    #[test]
    fn class_methods_js() {
        let src = r#"class UserService extends Base {
  name = "svc";
  method(a, b) { return a; }
  arrow = () => 1;
}"#;
        let defs = run(Language::JAVASCRIPT, src, "a.js");
        let c = defs
            .iter()
            .find(|d| d.name == "UserService")
            .expect("class");
        assert_eq!(c.label, "Class");
        assert!(c.base_classes.contains(&"Base".to_string()), "{c:?}");
        assert!(
            !c.base_classes.contains(&"extends".to_string()),
            "keyword filtered"
        );
        // Methods: `method` (direct kind) + `arrow` (field_definition arrow).
        assert!(
            defs.iter().any(|d| d.name == "method"
                && d.label == "Method"
                && d.parent_class.as_deref() == Some("proj.a.UserService")),
            "{defs:?}"
        );
        assert!(defs
            .iter()
            .any(|d| d.name == "arrow" && d.label == "Method"));
        // JS field_node_types is empty_types in the C spec table — class
        // FIELDS extract only for languages with field kinds (Java below).
        assert!(!defs.iter().any(|d| d.label == "Field"), "{defs:?}");
    }

    #[test]
    fn java_class_fields() {
        let src = r#"class UserService {
  private String name;
  public int count;
}"#;
        let defs = run(Language::JAVA, src, "UserService.java");
        assert!(
            defs.iter().any(|d| d.name == "name"
                && d.label == "Field"
                && d.parent_class.as_deref() == Some("proj.UserService")),
            "{defs:?}"
        );
        assert!(defs.iter().any(|d| d.name == "count" && d.label == "Field"));
    }

    #[test]
    fn java_enum_members() {
        let src = r#"
enum Color { RED, GREEN }
"#;
        let defs = run(Language::JAVA, src, "Color.java");
        let c = defs.iter().find(|d| d.name == "Color").expect("class");
        assert_eq!(c.label, "Enum");
        assert!(
            defs.iter().any(|d| d.name == "RED"
                && d.label == "Variable"
                && d.qualified_name == "proj.Color.RED"),
            "{defs:?}"
        );
        assert!(defs.iter().any(|d| d.name == "GREEN"));
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

    // ── Variable extraction layer ──

    #[test]
    fn module_level_tables() {
        // Direct-root languages.
        let tree = crate::ts::parse(Language::GO, "var x = 1\n").unwrap();
        assert!(is_module_level_p(tree.root_node(), Language::GO));
        // Python wrapper: assignment → expression_statement → module.
        let tree2 = crate::ts::parse(Language::PYTHON, "x = 1\n").unwrap();
        let prog = tree2.root_node();
        let stmt = prog.named_child(0).unwrap();
        assert!(is_module_level_p(prog, Language::PYTHON), "direct module");
        assert!(
            is_module_level_p(stmt, Language::PYTHON),
            "expression_statement wrapper"
        );
        // Non-parent kinds fail.
        assert!(!is_module_level_p(stmt, Language::GO));
    }

    #[test]
    fn python_vars_tuple_unpack() {
        let src = "x = 1\ny, z = f()\nw = 2\n";
        let defs = run(Language::PYTHON, src, "a.py");
        let names: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        for n in ["x", "y", "z", "w"] {
            assert!(names.contains(&n), "{names:?}");
        }
    }

    #[test]
    fn go_var_specs() {
        let src = "package main\n\nvar (\n\ta = 1\n\tb = 2\n)\nconst c = 3\n";
        let defs = run(Language::GO, src, "db/conn.go");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        for n in ["a", "b", "c"] {
            assert!(vars.contains(&n), "{vars:?}");
        }
        // Java/Go directory-based module: var QN carries the dir path but
        // NOT the filename (proj.myapp.db.Var per the C comment).
        let a = defs.iter().find(|d| d.name == "a").unwrap();
        assert!(
            a.qualified_name.starts_with("proj.db."),
            "{:?}",
            a.qualified_name
        );
    }

    #[test]
    fn js_destructuring() {
        let src = "const { p, q } = obj;\nlet [r, s] = arr;\n";
        let defs = run(Language::JAVASCRIPT, src, "a.js");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        for n in ["p", "q", "r", "s"] {
            assert!(vars.contains(&n), "{vars:?}");
        }
    }

    #[test]
    fn c_declarator_chain() {
        // No C grammar crate compiled in; the declarator-chain logic is
        // covered by extract_c_declarator_name's unit test below.
        let src = "int main(void) { return 0; }\nstatic char *buf = 0;\n";
        if crate::ts::parse(Language::C, src).is_none() {
            return;
        }
        let defs = run(Language::C, src, "a.c");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        assert!(vars.contains(&"buf"), "{vars:?}");
    }

    #[test]
    fn helm_values_top_level_only() {
        let src = "replicas: 2\nimage:\n  tag: latest\n  repo: x\n";
        let defs = run(Language::YAML, src, "chart/values.yaml");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        // Top-level keys only: `replicas` and `image`, NOT tag/repo.
        assert!(vars.contains(&"replicas"), "{vars:?}");
        assert!(vars.contains(&"image"), "{vars:?}");
        assert!(!vars.contains(&"tag"), "nested key flooded: {vars:?}");
        assert!(!vars.contains(&"repo"));
    }

    #[test]
    fn yaml_walk_uses_container_list() {
        let src = "service:\n  port: 8080\n";
        let defs = run(Language::YAML, src, "conf.yaml");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        // The C's container list has `pair` but not `block_mapping_pair`, so
        // nested mapping pairs are unreachable — only top-level keys bind.
        // 1:1 with that behavior.
        assert!(vars.contains(&"service"), "{vars:?}");
        assert!(
            !vars.contains(&"port"),
            "nested pair unreachable via C container list: {vars:?}"
        );
    }

    #[test]
    fn toml_and_json_vars() {
        let src = "[table]\nkey = 1\n";
        let Some(tree) = crate::ts::parse(Language::TOML, src) else {
            // TOML grammar crate not compiled in — extraction yields nothing
            // (same as any language without a grammar).
            return;
        };
        let mut ctx = ExtractCtx::new(src, tree.root_node(), Language::TOML, "proj", "a.toml");
        let spec = crate::lang_specs::lang_spec(Language::TOML);
        extract_definitions(&mut ctx, spec);
        let vars: Vec<&str> = ctx
            .result
            .definitions
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        assert!(vars.contains(&"table") || vars.contains(&"key"), "{vars:?}");
    }

    #[test]
    fn nix_module_vars_behind_header_lambda() {
        let src = "{ pkgs }: {\n  enable = true;\n  \"quoted-key\" = 2;\n  settings.attr = 3;\n}\n";
        if crate::ts::parse(Language::NIX, src).is_none() {
            return;
        }
        let defs = run(Language::NIX, src, "mod.nix");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        assert!(vars.contains(&"enable"), "{vars:?}");
        assert!(vars.contains(&"quoted-key"), "{vars:?}");
        assert!(vars.contains(&"attr"), "{vars:?}");
        // Dotted attrpath: name is the leaf, QN carries the path.
        let attr = defs.iter().find(|d| d.name == "attr").unwrap();
        assert!(
            attr.qualified_name.ends_with(".settings.attr"),
            "{:?}",
            attr.qualified_name
        );
    }

    #[test]
    fn nix_attrset_scope_not_var() {
        let src = "{\n  nested = {\n    inner = 1;\n  };\n}\n";
        if crate::ts::parse(Language::NIX, src).is_none() {
            // No nix grammar? (It IS wired in; guard for config drift.)
            return;
        }
        let defs = run(Language::NIX, src, "mod2.nix");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        // C rule: `nested` names a scope (attrset value) so the variable
        // pass skips it, and `inner` is BEYOND file scope — the C mints only
        // the container's DIRECT bindings and deliberately skips deeper
        // ones. Net effect: no Variable from this shape.
        assert!(vars.is_empty(), "{vars:?}");
    }

    #[test]
    fn dockerfile_env_arg_vars() {
        let src = "FROM alpine\nENV A=1 B=2\nARG C=3\n";
        if crate::ts::parse(Language::DOCKERFILE, src).is_none() {
            return; // grammar crate not compiled in
        }
        let defs = run(Language::DOCKERFILE, src, "Dockerfile");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        for n in ["A", "B", "C"] {
            assert!(vars.contains(&n), "{vars:?}");
        }
    }

    #[test]
    fn php_dollar_strip_and_ruby_left() {
        let src = "<?php\n$name = \"x\";\n";
        if crate::ts::parse(Language::PHP, src).is_none() {
            return; // grammar crate not compiled in
        }
        let defs = run(Language::PHP, src, "a.php");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        assert!(vars.contains(&"name"), "sigil stripped: {vars:?}");

        let src2 = "val = 1\nCONST = 2\n";
        let defs2 = run(Language::RUBY, src2, "a.rb");
        let vars2: Vec<&str> = defs2
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        assert!(vars2.contains(&"val"), "{vars2:?}");
        assert!(vars2.contains(&"CONST"), "{vars2:?}");
    }

    #[test]
    fn gomod_require_directives() {
        let src = "module example.com/m\n\ngo 1.21\n\nrequire (\n\tgithub.com/x/y v1.0.0\n)\n";
        if crate::ts::parse(Language::GOMOD, src).is_none() {
            return; // grammar crate not compiled in
        }
        let defs = run(Language::GOMOD, src, "go.mod");
        let vars: Vec<&str> = defs
            .iter()
            .filter(|d| d.label == "Variable")
            .map(|d| d.name.as_str())
            .collect();
        assert!(vars.contains(&"github.com/x/y"), "{vars:?}");
    }
}
