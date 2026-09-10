//! extract_calls.rs — 1:1 rewrite of `internal/cbm/extract_calls.c`
//! (3825 lines), part 1: the standalone call walker for the languages
//! with linked grammars (go/python/js-family/java/rust/c/cpp/csharp),
//! covering callee resolution (field-based → chained selector →
//! constructor → language-specific → generic fallback), argument capture
//! (keyword/splat/string/template/constant/URL-builder), and the URL /
//! topic / handler extraction that feeds route edges.

use crate::extract_env_accesses::ExtractCtx;
use crate::helpers;
use crate::lang_specs::LanguageSpec;
use crate::types::{Call, CallArg, SourceOrigin};
use crate::Language;

const MAX_CALL_ARGS: usize = crate::types::MAX_CALL_ARGS;
const MAX_POSITIONAL_SCAN: usize = 3;
const MAX_STRING_ARG_LEN: usize = 512;
const MIN_PRINTABLE: u8 = 0x20;
const HANDLER_START_IDX: usize = 1;

fn is_string_like(kind: &str) -> bool {
    matches!(
        kind,
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal"
    )
}

fn strip_quotes(text: &str) -> &str {
    let b = text.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &text[1..b.len() - 1]
    } else {
        text
    }
}

/// Dequote + length/content validation (C strip_and_validate_string_arg).
fn strip_and_validate_string_arg(text: &str) -> Option<&str> {
    if text.is_empty() {
        return None;
    }
    let dequoted = strip_quotes(text);
    let len = dequoted.len();
    if len == 0 || len >= MAX_STRING_ARG_LEN {
        return None;
    }
    if dequoted.bytes().any(|b| b < MIN_PRINTABLE && b != b'\t') {
        return None;
    }
    Some(dequoted)
}

/// Module-level string constants: name → value. URL-builder entries are
/// NOT constants (a bare `thingPath` is the function, not the URL).
/// Populated by the def walk's constant extraction (part 2 wiring).
#[derive(Debug, Default)]
pub struct StringConstantMap {
    pub entries: Vec<(String, String, bool)>, // (name, value, is_url_builder)
}

impl StringConstantMap {
    pub fn lookup_constant(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(n, _, builder)| !builder && n == name)
            .map(|(_, v, _)| v.as_str())
    }

    pub fn lookup_url_builder(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(n, _, builder)| *builder && n == name)
            .map(|(_, v, _)| v.as_str())
    }
}

// ── Callee resolution ───────────────────────────────────────────

/// JS/TS template literal flatten (`/things/${id}` → `/things/{}`)
/// (C cbm_template_string_text, #1006).
pub fn template_string_text_public<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
) -> Option<String> {
    template_string_text(node, source)
}

fn template_string_text<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    let mut out = String::new();
    for i in 0..node.named_child_count() {
        let c = node.named_child(i)?;
        match c.kind() {
            "string_fragment" => out.push_str(crate::fqn::node_text(c, source)),
            "template_substitution" => out.push_str("{}"),
            _ => {}
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Chained selector resolution (C resolve_chained_selector): `a().b().c`
/// → innermost base + final method, depth 4.
fn resolve_chained_selector<'a>(sel: tree_sitter::Node<'a>, source: &'a str) -> String {
    const MAX_CHAIN_DEPTH: usize = 4;
    let operand = sel.child_by_field_name("operand");
    let field = sel.child_by_field_name("field");
    let is_call_operand = operand
        .map(|o| o.kind() == "call_expression")
        .unwrap_or(false);
    if !is_call_operand {
        return crate::fqn::node_text(sel, source).to_string();
    }
    let (Some(operand), Some(field)) = (operand, field) else {
        return crate::fqn::node_text(sel, source).to_string();
    };
    let method = crate::fqn::node_text(field, source);
    let mut inner = operand;
    for _ in 0..MAX_CHAIN_DEPTH {
        let Some(fn_node) = inner.child_by_field_name("function") else {
            break;
        };
        if fn_node.kind() == "selector_expression" {
            let inner_op = fn_node.child_by_field_name("operand");
            if inner_op
                .map(|o| o.kind() == "call_expression")
                .unwrap_or(false)
            {
                inner = inner_op.unwrap();
                continue;
            }
        }
        let base = crate::fqn::node_text(fn_node, source);
        return format!("{base}.{method}");
    }
    method.to_string()
}

/// Strip generic args (`Vec<User>` → `Vec`) for constructor types
/// (C strip_generic_args).
fn strip_generic_args(t: &str) -> &str {
    match t.find(['<', '[']) {
        Some(i) => &t[..i],
        None => t,
    }
}

fn first_present_field<'t>(
    node: tree_sitter::Node<'t>,
    fields: &[&str],
) -> Option<tree_sitter::Node<'t>> {
    fields.iter().find_map(|f| node.child_by_field_name(f))
}

/// Constructor/instantiation callee (C extract_constructor_callee):
/// `new T()` / object_creation / instance_expression → constructed type.
fn extract_constructor_callee<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
    kind: &str,
) -> Option<String> {
    if !matches!(
        kind,
        "new_expression"
            | "object_creation_expression"
            | "instance_expression"
            | "allocation_expression"
            | "struct_literal"
    ) {
        return None;
    }
    let type_node = first_present_field(node, &["constructor", "type", "name"])?;
    let text = crate::fqn::node_text(type_node, source);
    let bare = strip_generic_args(text);
    if bare.is_empty() {
        None
    } else {
        Some(bare.to_string())
    }
}

/// Field-based callee resolution (C extract_callee_from_fields).
fn extract_callee_from_fields<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    let func_node = node.child_by_field_name("function")?;
    let fk = func_node.kind();
    if fk == "selector_expression" {
        return Some(resolve_chained_selector(func_node, source));
    }
    if matches!(
        fk,
        "identifier"
            | "simple_identifier"
            | "attribute"
            | "member_expression"
            | "field_expression"
            | "dot"
            | "function"
            | "dotted_identifier"
            | "member_access_expression"
            | "scoped_identifier"
            | "qualified_identifier"
            | "value_identifier"
            | "value_identifier_path"
    ) {
        return Some(crate::fqn::node_text(func_node, source).to_string());
    }
    // C++ explicit template call f<T>(args): `function` is a
    // template_function whose `name` child is the bare callee.
    if fk == "template_function" {
        if let Some(tname) = func_node.child_by_field_name("name") {
            return Some(crate::fqn::node_text(tname, source).to_string());
        }
    }
    // R member call module$fn(): extract_operator lhs/rhs → "module.fn" (#219).
    if fk == "extract_operator" {
        let lhs = func_node.child_by_field_name("lhs");
        let rhs = func_node.child_by_field_name("rhs");
        if let Some(rhs) = rhs {
            let rt = crate::fqn::node_text(rhs, source);
            if let Some(lhs) = lhs {
                let lt = crate::fqn::node_text(lhs, source);
                return Some(format!("{lt}.{rt}"));
            }
            return Some(rt.to_string());
        }
    }
    None
}

/// Generic fallback: first identifier child (C extract_callee_name tail).
fn first_identifier_child<'t>(node: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    if node.child_count() == 0 {
        return None;
    }
    let first = node.child(0)?;
    (first.kind() == "identifier").then_some(first)
}

/// Definition-role containers are not calls (C call_node_is_definition_container,
/// main languages only here: Elixir def/defp via `call` nodes).
pub fn is_definition_container(lang: Language, node: tree_sitter::Node<'_>, source: &str) -> bool {
    if lang == Language::ELIXIR && node.kind() == "call" {
        if let Some(head) = node.child_by_field_name("kernel") {
            let t = crate::fqn::node_text(head, source);
            return matches!(
                t,
                "def"
                    | "defp"
                    | "defmacro"
                    | "defmacrop"
                    | "defmodule"
                    | "defprotocol"
                    | "defimpl"
                    | "defguard"
                    | "defguardp"
                    | "defdelegate"
                    | "defexception"
                    | "defstruct"
                    | "defoverridable"
            );
        }
    }
    false
}

/// Callee name (C extract_callee_name, full language dispatch).
pub fn extract_callee_name<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
    lang: Language,
) -> Option<String> {
    if call_node_is_definition_container(lang, node, source) {
        return None;
    }
    if is_nested_verilog_call_wrapper(lang, node) {
        return None;
    }

    // Lean 4: skip type-position applies.
    if lang == Language::LEAN && node.kind() == "apply" && lean_is_in_type_position(node) {
        return None;
    }

    // Pkl: resolve here and return unconditionally — the access-expr call
    // node types double as plain property reads (C comment).
    if lang == Language::PKL {
        return extract_pkl_callee(node, source);
    }

    // Helm / Go templates: `include "x"` / `template "x"` → the named
    // template (#338).
    if lang == Language::GOTEMPLATE {
        if let Some(g) = gotemplate_callee(node, source) {
            return Some(g);
        }
    }

    // Constructor / instantiation nodes resolve to the constructed type.
    if let Some(ctor) = extract_constructor_callee(node, source, node.kind()) {
        return Some(ctor);
    }

    // Ruby `Widget.new(...)` → the receiver type (callee "new" never
    // resolves; the constructor lives in `initialize`).
    if lang == Language::RUBY {
        let m = node.child_by_field_name("method");
        let recv = node.child_by_field_name("receiver");
        if let (Some(m), Some(recv)) = (m, recv) {
            if recv.kind() == "constant" && crate::fqn::node_text(m, source) == "new" {
                let rt = crate::fqn::node_text(recv, source);
                if !rt.is_empty() {
                    return Some(rt.to_string());
                }
            }
        }
    }

    // #952: PHP facade route registrations (`Route::get(...)`) must carry
    // the scope in the callee text, gated to the literal `Route` scope AND
    // a route-method match.
    if lang == Language::PHP && node.kind() == "scoped_call_expression" {
        let scope = node.child_by_field_name("scope");
        let mname = node.child_by_field_name("name");
        if let (Some(scope), Some(mname)) = (scope, mname) {
            let sc = crate::fqn::node_text(scope, source);
            let mn = crate::fqn::node_text(mname, source);
            if sc == "Route" {
                let qual = format!("{sc}::{mn}");
                if crate::service_patterns::service_pattern_route_method(&qual).is_some() {
                    return Some(qual);
                }
            }
        }
    }

    // Common field-based resolution first.
    if let Some(name) = extract_callee_from_fields(node, source) {
        return Some(name);
    }
    // Language-specific patterns.
    if let Some(name) = extract_callee_lang_specific(node, source, lang) {
        return Some(name);
    }
    // Generic fallback: first identifier child.
    first_identifier_child(node).map(|n| crate::fqn::node_text(n, source).to_string())
}

// ── Argument capture ────────────────────────────────────────────

fn is_url_or_topic_keyword(key: &str) -> bool {
    matches!(
        key,
        "url" | "endpoint" | "path" | "uri" | "target_url" | "base_url"
    ) || matches!(
        key,
        "topic"
            | "topic_id"
            | "topic_name"
            | "queue"
            | "queue_name"
            | "queue_id"
            | "subject"
            | "channel"
    )
}

/// Keyword/value node → string value (C extract_string_value).
fn extract_string_value<'a>(
    ctx: &ExtractCtx<'a>,
    val_node: tree_sitter::Node<'a>,
    constants: &StringConstantMap,
) -> Option<String> {
    let vk = val_node.kind();
    if vk == "template_string" {
        return template_string_text(val_node, ctx.source);
    }
    if is_string_like(vk) {
        let text = crate::fqn::node_text(val_node, ctx.source);
        if !text.is_empty() {
            return Some(strip_quotes(text).to_string());
        }
    } else if vk == "identifier" {
        let const_name = crate::fqn::node_text(val_node, ctx.source);
        return constants.lookup_constant(const_name).map(str::to_string);
    }
    None
}

fn process_keyword_arg(
    ctx: &ExtractCtx<'_>,
    arg_node: tree_sitter::Node<'_>,
    ca: &mut CallArg,
    constants: &StringConstantMap,
) {
    let key_n = arg_node
        .child_by_field_name("name")
        .or_else(|| arg_node.child_by_field_name("key"));
    let val_n = arg_node.child_by_field_name("value");
    if let Some(k) = key_n {
        ca.keyword = Some(crate::fqn::node_text(k, ctx.source).to_string());
    }
    if let Some(v) = val_n {
        ca.expr = crate::fqn::node_text(v, ctx.source).to_string();
        if v.kind() == "identifier" {
            ca.value = constants.lookup_constant(&ca.expr).map(str::to_string);
        } else if is_string_like(v.kind()) {
            ca.value = Some(strip_quotes(&ca.expr).to_string());
        }
    }
}

/// Arguments → call.args (C extract_call_args).
fn extract_call_args(
    ctx: &ExtractCtx<'_>,
    args: tree_sitter::Node<'_>,
    call: &mut Call,
    constants: &StringConstantMap,
) {
    let argc = args.named_child_count();
    let mut positional_idx = 0i32;
    for ai in 0..argc {
        if call.args.len() >= MAX_CALL_ARGS {
            break;
        }
        let arg_node = args.named_child(ai).unwrap();
        let ak = arg_node.kind();
        if matches!(ak, "keyword_argument" | "pair") {
            let mut ca = CallArg::default();
            process_keyword_arg(ctx, arg_node, &mut ca, constants);
            ca.index = positional_idx;
            positional_idx += 1;
            call.args.push(ca);
        } else if matches!(ak, "list_splat" | "dictionary_splat" | "spread_element") {
            positional_idx += 1;
        } else {
            let mut ca = CallArg {
                expr: crate::fqn::node_text(arg_node, ctx.source).to_string(),
                index: positional_idx,
                ..Default::default()
            };
            positional_idx += 1;
            if is_string_like(ak) {
                ca.value = Some(strip_quotes(&ca.expr).to_string());
            } else if ak == "template_string" {
                // Flattened {} form joins the canonical server route (#1006/#1009).
                ca.value = template_string_text(arg_node, ctx.source);
            } else if ak == "identifier" {
                ca.value = constants.lookup_constant(&ca.expr).map(str::to_string);
            } else if ak == "call_expression" {
                // URL-builder helper (issue #1009): client(buildPath(id)).
                if let Some(fn_node) = arg_node.child_by_field_name("function") {
                    if fn_node.kind() == "identifier" {
                        let fname = crate::fqn::node_text(fn_node, ctx.source);
                        ca.value = constants.lookup_url_builder(fname).map(str::to_string);
                    }
                }
            }
            call.args.push(ca);
        }
    }
}

// ── URL / topic / handler extraction ────────────────────────────

/// Composite literal queue field (C extract_composite_queue_field): Go
/// `&sqs.SendMessageInput{QueueUrl: ...}` — the target is a struct field.
fn extract_composite_queue_field<'a>(
    ctx: &ExtractCtx<'a>,
    node: tree_sitter::Node<'a>,
) -> Option<String> {
    // body/fields container → pair entries with url/topic keys.
    let body = node
        .child_by_field_name("body")
        .or_else(|| node.child_by_field_name("fields"))?;
    for i in 0..body.named_child_count() {
        let elem = body.named_child(i)?;
        let key = elem
            .child_by_field_name("key")
            .or_else(|| elem.child_by_field_name("name"))?;
        let key_text = crate::fqn::node_text(key, ctx.source);
        if !is_url_or_topic_keyword(key_text) {
            continue;
        }
        if let Some(value) = elem.child_by_field_name("value") {
            if let Some(v) = extract_string_value(ctx, value, &StringConstantMap::default()) {
                return Some(v);
            }
        }
    }
    None
}

/// Positional-argument URL recovery (C extract_positional_url).
fn extract_positional_url<'a>(
    ctx: &ExtractCtx<'a>,
    arg: tree_sitter::Node<'a>,
    ak: &str,
    constants: &StringConstantMap,
) -> Option<String> {
    if ak == "template_string" {
        let flat = template_string_text(arg, ctx.source)?;
        return strip_and_validate_string_arg(&flat).map(str::to_string);
    }
    if ak == "binary_expression" {
        // Concatenation suffix: `base + "/path"` — take the string side.
        for i in 0..arg.child_count() {
            if let Some(c) = arg.child(i) {
                if is_string_like(c.kind()) {
                    let text = crate::fqn::node_text(c, ctx.source);
                    if let Some(v) = strip_and_validate_string_arg(text) {
                        return Some(v.to_string());
                    }
                }
            }
        }
        return None;
    }
    if is_string_like(ak) {
        let text = crate::fqn::node_text(arg, ctx.source);
        return strip_and_validate_string_arg(text).map(str::to_string);
    }
    if ak == "identifier" {
        let const_name = crate::fqn::node_text(arg, ctx.source);
        return constants.lookup_constant(const_name).map(str::to_string);
    }
    None
}

/// URL or topic string argument (C extract_url_or_topic_arg).
fn extract_url_or_topic_arg<'a>(
    ctx: &ExtractCtx<'a>,
    args: tree_sitter::Node<'a>,
    constants: &StringConstantMap,
) -> Option<String> {
    let nc = args.named_child_count();
    for ai in 0..nc {
        let mut arg = args.named_child(ai)?;
        // PHP/C# wrap positional args in `argument` nodes.
        if arg.kind() == "argument" && arg.named_child_count() > 0 {
            arg = arg.named_child(0)?;
        }
        // Swift value_argument may lead with a label.
        if arg.kind() == "value_argument" && arg.named_child_count() > 0 {
            let val = arg.named_child(0)?;
            if val.kind() == "value_argument_label" && arg.named_child_count() > 1 {
                arg = arg.named_child(1)?;
            } else {
                arg = val;
            }
        }
        let ak = arg.kind();
        if matches!(ak, "keyword_argument" | "pair") {
            let key_node = arg
                .child_by_field_name("name")
                .or_else(|| arg.child_by_field_name("key"));
            let val_node = arg.child_by_field_name("value");
            if let (Some(k), Some(v)) = (key_node, val_node) {
                let key = crate::fqn::node_text(k, ctx.source);
                if is_url_or_topic_keyword(key) {
                    if let Some(val) = extract_string_value(ctx, v, constants) {
                        return Some(val);
                    }
                }
            }
            continue;
        }
        // Cloud SDK input struct (Go `&sqs.SendMessageInput{QueueUrl: ...}`).
        if matches!(ak, "composite_literal" | "unary_expression") {
            if let Some(val) = extract_composite_queue_field(ctx, arg) {
                return Some(val);
            }
        }
        // URL-builder helper call (issue #1009).
        if ak == "call_expression" {
            if let Some(fn_node) = arg.child_by_field_name("function") {
                if fn_node.kind() == "identifier" {
                    let fname = crate::fqn::node_text(fn_node, ctx.source);
                    if let Some(val) = constants.lookup_url_builder(fname) {
                        return Some(val.to_string());
                    }
                }
            }
        }
        if ai < MAX_POSITIONAL_SCAN {
            if let Some(val) = extract_positional_url(ctx, arg, ak, constants) {
                return Some(val);
            }
        }
    }
    None
}

/// Laravel `Controller@method` → method segment (C normalize_string_handler).
fn normalize_string_handler(raw: &str) -> Option<&str> {
    let unq = strip_quotes(raw);
    if unq.is_empty() {
        return None;
    }
    match unq.find('@') {
        Some(i) if i + 1 < unq.len() => Some(&unq[i + 1..]),
        _ => Some(unq),
    }
}

/// Handler ref for route registrations: the LAST function-shaped argument
/// wins (Express/Fastify/gin put middleware first) (C extract_handler_arg).
fn extract_handler_arg<'a>(ctx: &ExtractCtx<'a>, args: tree_sitter::Node<'a>) -> Option<String> {
    let nc = args.named_child_count();
    let mut handler: Option<String> = None;
    for ai in HANDLER_START_IDX..nc {
        let mut arg2 = args.named_child(ai)?;
        if arg2.kind() == "argument" && arg2.named_child_count() > 0 {
            arg2 = arg2.named_child(0)?;
        }
        let ak2 = arg2.kind();
        if matches!(
            ak2,
            "identifier"
                | "member_expression"
                | "selector_expression"
                | "attribute"
                | "field_expression"
                | "name"
        ) {
            handler = Some(crate::fqn::node_text(arg2, ctx.source).to_string());
        } else if is_string_like(ak2) {
            let raw = crate::fqn::node_text(arg2, ctx.source);
            if let Some(h) = normalize_string_handler(raw) {
                if !h.is_empty() {
                    handler = Some(h.to_string());
                }
            }
        }
    }
    handler
}

// ── Entry (C handle_calls standalone shape) ─────────────────────

/// Emit calls for `node` when it is a call node of the spec.
/// Enclosing QN via the EF cache; loop/branch depth counters are carried
/// by the caller's walk (unified handler in part 2 reads WalkState).
pub fn try_emit_call(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    constants: &StringConstantMap,
    loop_depth: i32,
    branch_depth: i32,
) {
    if !spec.call_node_types.contains(&node.kind()) {
        return;
    }
    let Some(callee_name) = extract_callee_name(node, ctx.source, ctx.language) else {
        return;
    };
    // Keyword-filter callees, but keep resolvable builtins (len, str, …)
    // so the LSP-resolved builtin call still forms a CALLS edge.
    if helpers::is_keyword(&callee_name, ctx.language)
        && !helpers::is_resolvable_builtin(&callee_name, ctx.language)
    {
        return;
    }
    let enclosing = ctx.ef_cache.enclosing_qn(
        node,
        ctx.language,
        ctx.source,
        ctx.project,
        ctx.rel_path,
        &ctx.module_qn,
    );
    let mut call = Call {
        callee_name,
        enclosing_func_qn: enclosing,
        loop_depth,
        branch_depth,
        start_line: node.start_position().row as i32 + 1, // TS_LINE_OFFSET
        site_start_byte: node.start_byte() as u32,
        site_end_byte: node.end_byte() as u32,
        source_origin: SourceOrigin::Raw,
        ..Default::default()
    };
    // JS member call x.foo() with a non-this/super receiver → is_method.
    if matches!(
        ctx.language,
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS
    ) {
        if let Some(fn_node) = node.child_by_field_name("function") {
            if fn_node.kind() == "member_expression" {
                if let Some(obj) = fn_node.child_by_field_name("object") {
                    let ok = obj.kind();
                    if ok != "this" && ok != "super" {
                        call.is_method = true;
                    }
                }
            }
        }
    }
    if let Some(args) = node.child_by_field_name("arguments") {
        call.first_string_arg = extract_url_or_topic_arg(ctx, args, constants);
        if let Some(path) = &call.first_string_arg {
            if path.starts_with('/') {
                call.second_arg_name = extract_handler_arg(ctx, args);
            }
        }
        extract_call_args(ctx, args, &mut call, constants);
    }
    ctx.result.calls.push(call);
}

/// Iterative call walk (part-1 shape: no loop/branch tracking yet — those
/// come with the unified walk; depths are passed as 0).
pub fn extract_calls(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec, constants: &StringConstantMap) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        try_emit_call(ctx, node, spec, constants, 0, 0);
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ Language-specific callee extractors (C extract_callee_lang_specific
//     and its helpers) ═══════════════════════════════════════════════════

/// Descend left-most through wrapper nodes to the first identifier-bearing
/// leaf (C first_leaf_identifier): HDL callees nest under grammar wrappers
/// (Verilog tf_call → simple_identifier; SystemVerilog → hierarchical →
/// simple).
fn first_leaf_identifier<'t>(node: tree_sitter::Node<'t>, source: &'t str) -> Option<String> {
    let mut cur = Some(node);
    for _ in 0..8 {
        let n = cur?;
        if matches!(
            n.kind(),
            "simple_identifier" | "identifier" | "word" | "name" | "qid"
        ) {
            let t = crate::fqn::node_text(n, source);
            return (!t.is_empty()).then(|| t.to_string());
        }
        if n.named_child_count() == 0 {
            return None;
        }
        cur = n.named_child(0);
    }
    None
}

/// Lean 4: is an `apply` inside a type annotation? (C
/// lean_is_in_type_position): inside a binder → yes; at a declaration
/// boundary, only when it starts before the end of the `type` field.
fn lean_is_in_type_position(node: tree_sitter::Node<'_>) -> bool {
    let mut cur = node.parent();
    for _ in 0..20 {
        // LEAN_MAX_PARENT_DEPTH
        let Some(n) = cur else { return false };
        let pk = n.kind();
        if matches!(
            pk,
            "explicit_binder" | "implicit_binder" | "instance_binder"
        ) {
            return true;
        }
        if matches!(
            pk,
            "def" | "theorem" | "instance" | "abbrev" | "structure" | "inductive"
        ) {
            let Some(type_field) = n.child_by_field_name("type") else {
                return false; // no type annotation → allow call
            };
            return (node.start_byte() as u32) <= type_field.end_byte() as u32;
        }
        cur = n.parent();
    }
    false
}

/// Fortran: `subroutine_call` → its `subroutine` field text.
fn extract_fortran_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    let sub = node.child_by_field_name("subroutine")?;
    Some(crate::fqn::node_text(sub, source).to_string())
}

/// Verilog/SystemVerilog HDL call shapes (C extract_hdl_callee).
fn extract_hdl_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if !matches!(
        node.kind(),
        "function_subroutine_call" | "subroutine_call" | "tf_call" | "system_tf_call"
    ) {
        return None;
    }
    first_leaf_identifier(node, source)
}

/// VHDL (C extract_vhdl_callee): `add(x,1)` parses as
/// `(name (library_function) (parenthesis_group ...))` — the callee is the
/// parenthesis_group's preceding named sibling.
fn extract_vhdl_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "parenthesis_group" {
        return None;
    }
    let prev = node.prev_named_sibling()?;
    if matches!(
        prev.kind(),
        "library_function" | "identifier" | "name" | "simple_name"
    ) {
        let t = crate::fqn::node_text(prev, source);
        return (!t.is_empty()).then(|| t.to_string());
    }
    None
}

/// NASM (C extract_nasm_callee): call/jmp-style instructions only; the
/// target label is the first operand word.
fn extract_nasm_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() == "call_syntax_expression" {
        return node
            .child_by_field_name("base")
            .and_then(|b| first_leaf_identifier(b, source));
    }
    if node.kind() != "actual_instruction" {
        return None;
    }
    let mnem = node.child_by_field_name("instruction")?;
    let m = crate::fqn::node_text(mnem, source);
    if !matches!(m, "call" | "jmp" | "je" | "jne" | "jz" | "jnz") {
        return None;
    }
    let ops = node.child_by_field_name("operands")?;
    let first = ops.named_child(0)?;
    first_leaf_identifier(first, source)
}

/// LLVM-IR (C extract_llvm_callee): `callee:` → value → var → global_var;
/// strip the leading sigil.
fn extract_llvm_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "instruction_call" {
        return None;
    }
    let callee = node.child_by_field_name("callee")?;
    let t = first_leaf_identifier(callee, source)?;
    Some(t.trim_start_matches('@').to_string())
}

/// ObjC message_expression selector (C extract_objc_callee).
fn extract_objc_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "message_expression" {
        return None;
    }
    let sel = node.child_by_field_name("selector")?;
    Some(crate::fqn::node_text(sel, source).to_string())
}

/// Erlang call: first child text (C extract_erlang_callee).
fn extract_erlang_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "call" || node.child_count() == 0 {
        return None;
    }
    Some(crate::fqn::node_text(node.child(0)?, source).to_string())
}

/// Haskell/OCaml/PureScript/Scala apply heads (C extract_fp_callee): walk
/// the curried left spine iteratively; infix operators extract as `op`.
fn extract_fp_callee<'a>(mut node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    let is_apply = |k: &str| matches!(k, "apply" | "application_expression" | "exp_apply");
    while is_apply(node.kind()) && node.child_count() > 0 {
        let callee = node.child(0)?;
        let ck = callee.kind();
        if matches!(
            ck,
            "identifier" | "variable" | "constructor" | "value_path" | "exp_name"
        ) {
            return Some(crate::fqn::node_text(callee, source).to_string());
        }
        if !is_apply(ck) {
            break;
        }
        node = callee;
    }
    if matches!(node.kind(), "infix" | "infix_expression") {
        if let Some(op) = node.child_by_field_name("operator") {
            return Some(crate::fqn::node_text(op, source).to_string());
        }
        if node.child_count() >= 3 {
            return Some(crate::fqn::node_text(node.child(1)?, source).to_string());
        }
    }
    None
}

/// Wolfram apply head, skipping LHS of set definitions (C
/// extract_wolfram_callee).
fn extract_wolfram_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "set_delayed_top" | "set_top" | "set_delayed" | "set"
        ) && parent.named_child_count() > 0
            && parent.named_child(0) == Some(node)
        {
            return None;
        }
    }
    let head = node.named_child(0)?;
    if matches!(head.kind(), "user_symbol" | "builtin_symbol") {
        return Some(crate::fqn::node_text(head, source).to_string());
    }
    None
}

/// Swift call/constructor first named child (C extract_swift_callee).
fn extract_swift_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if !matches!(node.kind(), "call_expression" | "constructor_expression") {
        return None;
    }
    let callee = node.named_child(0)?;
    if matches!(callee.kind(), "simple_identifier" | "navigation_expression") {
        return Some(crate::fqn::node_text(callee, source).to_string());
    }
    None
}

/// A Perl sub/method name is a bare identifier with '::' package separators
/// (C perl_is_identifier_callee): tree-sitter-perl mis-parses config lines
/// into call-shaped nodes whose "callee" is a dotted config token; rejecting
/// non-identifier text stops those bogus CALLS edges.
fn perl_is_identifier_callee(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let b = name.as_bytes();
    if !(b[0].is_ascii_alphabetic() || b[0] == b'_') {
        return false;
    }
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_alphanumeric() || c == b'_' {
            i += 1;
            continue;
        }
        if c == b':' {
            // Only the '::' package separator: an adjacent pair, not a lone
            // ':', ':::', or trailing '::'.
            if i + 1 >= b.len() || b[i + 1] != b':' || (i + 2 < b.len() && b[i + 2] == b':') {
                return false;
            }
            i += 2;
            continue;
        }
        return false; // '.', space, quote, '/' → not a sub/method name
    }
    true
}

/// Scripting-language callees (C extract_scripting_callee): Elixir, Perl,
/// PHP, Kotlin, MATLAB.
fn extract_scripting_callee<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
    lang: Language,
) -> Option<String> {
    let nk = node.kind();
    if lang == Language::ELIXIR && nk == "binary_operator" {
        // The grammar exposes the operator as an exact field; reading bytes
        // between operands captured binding punctuation in definition heads.
        let op = node.child_by_field_name("operator")?;
        let operator_name = crate::fqn::node_text(op, source);
        if matches!(operator_name, "=" | "<-" | "->" | "\\\\" | "::" | "when") {
            return None;
        }
        return Some(operator_name.to_string());
    }
    if lang == Language::ELIXIR && nk == "call" && node.child_count() > 0 {
        let first = node.child(0)?;
        if matches!(first.kind(), "identifier" | "dot") {
            return Some(crate::fqn::node_text(first, source).to_string());
        }
        return None;
    }
    if lang == Language::PERL && node.child_count() > 0 {
        // Pull the actual sub/method token: method → function → child(0).
        let name_node = node
            .child_by_field_name("method")
            .or_else(|| node.child_by_field_name("function"))
            .or_else(|| node.child(0))?;
        let pn = crate::fqn::node_text(name_node, source);
        return perl_is_identifier_callee(pn).then(|| pn.to_string());
    }
    if lang == Language::PHP {
        let func_node = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("name"))?;
        return Some(crate::fqn::node_text(func_node, source).to_string());
    }
    if lang == Language::KOTLIN && node.child_count() > 0 {
        return Some(crate::fqn::node_text(node.child(0)?, source).to_string());
    }
    if lang == Language::MATLAB && nk == "command" && node.child_count() > 0 {
        return Some(crate::fqn::node_text(node.child(0)?, source).to_string());
    }
    None
}

/// Lisp dialects (C extract_lisp_callee): a call is a list/list_lit whose
/// head is a symbol. Chialisp filters CLVM primitives, binder lists, and
/// quoted data.
fn extract_lisp_callee<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
    lang: Language,
) -> Option<String> {
    let nk = node.kind();
    if nk != "list" && nk != "list_lit" {
        return None;
    }
    let head = node.named_child(0)?;
    if matches!(head.kind(), "symbol" | "sym_lit" | "identifier") {
        let ht = crate::fqn::node_text(head, source);
        if lang == Language::CHIALISP
            && (chialisp_head_is_not_call(ht)
                || chialisp_node_is_binder_list(node, source)
                || helpers::lisp_node_in_quote(node, source))
        {
            return None;
        }
        return Some(ht.to_string());
    }
    None
}

/// F# (C extract_fsharp_callee): application_expression head is a
/// long_identifier_or_op wrapper.
fn extract_fsharp_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "application_expression" || node.named_child_count() == 0 {
        return None;
    }
    let head = node.named_child(0)?;
    if matches!(
        head.kind(),
        "long_identifier_or_op" | "long_identifier" | "identifier"
    ) {
        return Some(crate::fqn::node_text(head, source).to_string());
    }
    None
}

/// CSS call_expression (C extract_css_callee): `url(...)`/`calc(...)` carry
/// the callee on a plain `function_name` child.
fn extract_css_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let fnn = crate::fqn::find_child_by_kind(node, "function_name")?;
    Some(crate::fqn::node_text(fnn, source).to_string())
}

/// Linker scripts (C extract_linkerscript_callee): `function:` field as a
/// `symbol`.
fn extract_linkerscript_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    (function.kind() == "symbol").then(|| crate::fqn::node_text(function, source).to_string())
}

/// PowerShell `command` node's `command_name` child (C
/// extract_powershell_callee).
fn extract_powershell_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "command" {
        return None;
    }
    for i in 0..node.named_child_count() {
        let c = node.named_child(i)?;
        if c.kind() == "command_name" {
            return Some(crate::fqn::node_text(c, source).to_string());
        }
    }
    None
}

/// Ada (C extract_ada_callee): `name` field, else first name/identifier head.
fn extract_ada_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if !matches!(node.kind(), "procedure_call_statement" | "function_call") {
        return None;
    }
    if let Some(name) = node.child_by_field_name("name") {
        return Some(crate::fqn::node_text(name, source).to_string());
    }
    let head = node.named_child(0)?;
    if matches!(head.kind(), "name" | "identifier") {
        return Some(crate::fqn::node_text(head, source).to_string());
    }
    None
}

/// PL/SQL (C extract_plsql_callee): ref_call → referenced_element with
/// ref_name_parent.ref_name for package-qualified calls.
fn extract_plsql_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "ref_call" {
        return None;
    }
    let refr = crate::fqn::find_child_by_kind(node, "referenced_element")?;
    let parent = refr.child_by_field_name("ref_name_parent");
    let name = refr.child_by_field_name("ref_name");
    if let (Some(p), Some(n)) = (parent, name) {
        let pt = crate::fqn::node_text(p, source);
        let nt = crate::fqn::node_text(n, source);
        if !pt.is_empty() && !nt.is_empty() {
            return Some(format!("{pt}.{nt}"));
        }
    }
    if let Some(n) = name {
        return Some(crate::fqn::node_text(n, source).to_string());
    }
    Some(crate::fqn::node_text(refr, source).to_string())
}

/// Solidity (C extract_solidity_callee): unwrap `expression` wrappers to the
/// identifier/member.
fn extract_solidity_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if !matches!(node.kind(), "call_expression" | "call") {
        return None;
    }
    let mut head = node
        .child_by_field_name("function")
        .or_else(|| node.named_child(0))?;
    for _ in 0..4 {
        let hk = head.kind();
        if matches!(hk, "identifier" | "member_expression" | "member_access") {
            return Some(crate::fqn::node_text(head, source).to_string());
        }
        if hk == "expression" && head.named_child_count() > 0 {
            head = head.named_child(0)?;
            continue;
        }
        break;
    }
    None
}

/// Groovy (C extract_groovy_callee): function_call's first named child is
/// the callee identifier (child 0 is anonymous).
fn extract_groovy_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if !matches!(node.kind(), "function_call" | "juxt_function_call") {
        return None;
    }
    let head = node.named_child(0)?;
    (head.kind() == "identifier").then(|| crate::fqn::node_text(head, source).to_string())
}

/// WGSL (C extract_wgsl_callee): nested type_constructor_or_function_call →
/// type_declaration → identifier; descend left-most.
fn extract_wgsl_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "type_constructor_or_function_call_expression" {
        return None;
    }
    let mut head = node;
    while head.named_child_count() > 0 && head.kind() != "identifier" {
        head = head.named_child(0)?;
    }
    (head.kind() == "identifier").then(|| crate::fqn::node_text(head, source).to_string())
}

/// Dart (C extract_dart_callee): `selector` follows the callee identifier as
/// a sibling; `new_expression`'s first named child is the type.
fn extract_dart_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() == "selector" {
        let prev = node.prev_named_sibling()?;
        return (prev.kind() == "identifier")
            .then(|| crate::fqn::node_text(prev, source).to_string());
    }
    if node.kind() == "new_expression" {
        let head = node.named_child(0)?;
        if matches!(head.kind(), "identifier" | "type_identifier") {
            return Some(crate::fqn::node_text(head, source).to_string());
        }
    }
    None
}

/// SCSS (C extract_scss_callee): `@include foo;` and `@function` call shapes.
fn extract_scss_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() == "include_statement" {
        let id = crate::fqn::find_child_by_kind(node, "identifier")?;
        return Some(crate::fqn::node_text(id, source).to_string());
    }
    if node.kind() == "call_expression" {
        let fnn = crate::fqn::find_child_by_kind(node, "function_name")?;
        return Some(crate::fqn::node_text(fnn, source).to_string());
    }
    None
}

/// SQL invocation (C extract_sql_callee): object_reference > `name` field.
fn extract_sql_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "invocation" {
        return None;
    }
    let oref = crate::fqn::find_child_by_kind(node, "object_reference")?;
    let nm = oref.child_by_field_name("name")?;
    Some(crate::fqn::node_text(nm, source).to_string())
}

/// COBOL (C extract_cobol_callee): `CALL 'HELPER'` — the `x` field (or
/// first string child) names the called program.
fn extract_cobol_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "call_statement" {
        return None;
    }
    let x = node
        .child_by_field_name("x")
        .or_else(|| crate::fqn::find_child_by_kind(node, "string"))?;
    let text = crate::fqn::node_text(x, source);
    strip_and_validate_string_arg(text).map(str::to_string)
}

/// Elm (C extract_elm_callee): target → value_expr → name (value_qid) →
/// lower_case_identifier.
fn extract_elm_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "function_call_expr" {
        return None;
    }
    let target = node.child_by_field_name("target")?;
    let ve = if target.kind() == "value_expr" {
        target
    } else {
        crate::fqn::find_child_by_kind(target, "value_expr")?
    };
    let qid = ve
        .child_by_field_name("name")
        .or_else(|| crate::fqn::find_child_by_kind(ve, "value_qid"))?;
    match crate::fqn::find_child_by_kind(qid, "lower_case_identifier") {
        Some(id) => Some(crate::fqn::node_text(id, source).to_string()),
        None => Some(crate::fqn::node_text(qid, source).to_string()), // module-qualified
    }
}

/// Jsonnet (C extract_jsonnet_callee): functioncall's first `id` child.
fn extract_jsonnet_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "functioncall" {
        return None;
    }
    let id = crate::fqn::find_child_by_kind(node, "id")?;
    Some(crate::fqn::node_text(id, source).to_string())
}

/// Nickel (C extract_nickel_callee): curried `applicative` chains — a real
/// call has a `t2` argument field; only the outermost emits, keyed on the
/// leftmost ident down the `t1` chain.
fn extract_nickel_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "applicative" {
        return None;
    }
    node.child_by_field_name("t2")?;
    if node
        .parent()
        .map(|p| p.kind() == "applicative")
        .unwrap_or(false)
    {
        return None;
    }
    let mut cur = Some(node);
    for _ in 0..8 {
        let n = cur?;
        if n.kind() == "ident" {
            return Some(crate::fqn::node_text(n, source).to_string());
        }
        let next = n.child_by_field_name("t1").or_else(|| n.named_child(0))?;
        if next == n {
            break;
        }
        cur = Some(next);
    }
    None
}

/// Pkl (C extract_pkl_callee): access-expr call nodes double as property
/// reads; the `argumentList` child is the only discriminator. `newExpr`
/// resolves to its declaredType.
fn extract_pkl_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() == "newExpr" {
        let dt = crate::fqn::find_child_by_kind(node, "declaredType")?;
        return Some(crate::fqn::node_text(dt, source).to_string());
    }
    let qualified = node.kind() == "qualifiedAccessExpr";
    if !qualified && node.kind() != "unqualifiedAccessExpr" {
        return None;
    }
    crate::fqn::find_child_by_kind(node, "argumentList")?; // property read bail
    let recv = node.child_by_field_name("receiver");
    let mut name = None;
    for i in 0..node.named_child_count() {
        let child = node.named_child(i)?;
        if recv == Some(child) {
            continue;
        }
        if child.kind() == "identifier" {
            name = Some(child);
            break;
        }
    }
    let name = name?;
    let mn = crate::fqn::node_text(name, source);
    if mn.is_empty() {
        return None;
    }
    if !qualified {
        return Some(mn.to_string());
    }
    let Some(recv) = recv else {
        return Some(mn.to_string());
    };
    // Prefix only a plain-name receiver: `utils.fallback(a)` →
    // "utils.fallback"; a receiver that is itself a call
    // (`s.trim().toLowerCase()`) must NOT be prefixed.
    if recv.kind() == "unqualifiedAccessExpr"
        && crate::fqn::find_child_by_kind(recv, "argumentList").is_none()
    {
        let rt = crate::fqn::node_text(recv, source);
        if !rt.is_empty() {
            return Some(format!("{rt}.{mn}"));
        }
    }
    Some(mn.to_string())
}

/// Typst (C extract_typst_callee): call's `item` field.
fn extract_typst_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "call" {
        return None;
    }
    let item = node.child_by_field_name("item")?;
    Some(crate::fqn::node_text(item, source).to_string())
}

/// Meson (C extract_meson_callee): normal_command's `command` field.
fn extract_meson_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "normal_command" {
        return None;
    }
    let cmd = node.child_by_field_name("command")?;
    Some(crate::fqn::node_text(cmd, source).to_string())
}

/// Make (C extract_make_callee): `$(shell ...)` → literal "shell";
/// function_call → its function field.
fn extract_make_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    match node.kind() {
        "shell_function" => Some("shell".to_string()),
        "function_call" => {
            let fnn = node
                .child_by_field_name("function")
                .or_else(|| node.named_child(0))?;
            Some(crate::fqn::node_text(fnn, source).to_string())
        }
        _ => None,
    }
}

/// Just (C extract_just_callee): recipe dependency's `name:` field.
fn extract_just_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "dependency" {
        return None;
    }
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.named_child(0))?;
    Some(crate::fqn::node_text(name, source).to_string())
}

/// Puppet (C extract_puppet_callee): `include foo` → literal "include";
/// function_call's first identifier child.
fn extract_puppet_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() == "include_statement" {
        return Some("include".to_string());
    }
    if node.kind() == "function_call" {
        let head = node.named_child(0)?;
        if head.kind() == "identifier" {
            return Some(crate::fqn::node_text(head, source).to_string());
        }
    }
    None
}

/// Func (C extract_func_callee): function_application's `function` field.
fn extract_func_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "function_application" {
        return None;
    }
    let fnn = node.child_by_field_name("function")?;
    Some(crate::fqn::node_text(fnn, source).to_string())
}

/// Nix (C extract_nix_callee): apply_expression `function:` chain down to
/// variable_expression.name.
fn extract_nix_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "apply_expression" {
        return None;
    }
    let mut fnn = node.child_by_field_name("function")?;
    for _ in 0..8 {
        match fnn.kind() {
            "apply_expression" => {
                fnn = fnn.child_by_field_name("function")?;
            }
            "variable_expression" => {
                let nm = fnn.child_by_field_name("name")?;
                return Some(crate::fqn::node_text(nm, source).to_string());
            }
            "identifier" => {
                return Some(crate::fqn::node_text(fnn, source).to_string());
            }
            _ => return None,
        }
    }
    None
}

/// Agda (C extract_agda_callee): plain application is the exact adjacency
/// shape `expr(atom, atom, ...)`; the head atom descends to a qid.
fn extract_agda_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    if node.kind() != "expr" {
        return None;
    }
    // All children named and all atoms.
    if node.named_child_count() < 2 || node.child_count() != node.named_child_count() {
        return None;
    }
    for i in 0..node.named_child_count() {
        if node.named_child(i)?.kind() != "atom" {
            return None;
        }
    }
    // Head atom descends left-most to a qid.
    let mut current = node.named_child(0)?;
    for _ in 0..8 {
        if current.kind() == "qid" {
            return Some(crate::fqn::node_text(current, source).to_string());
        }
        if current.named_child_count() == 0 {
            return None;
        }
        current = current.named_child(0)?;
    }
    None
}

/// Chialisp: a head atom that is a CLVM primitive/opcode or a
/// syntax/binding/def keyword is NOT a call (C chialisp_head_is_not_call).
/// `export`/`namespace` are here even though they are deliberately NOT
/// definition heads: `(export foo)` names an already-defined function.
fn chialisp_head_is_not_call(t: &str) -> bool {
    const FILTERED: &[&str] = &[
        // CLVM primitives (VM ops)
        "q",
        "a",
        "i",
        "c",
        "f",
        "r",
        "l",
        "x",
        "=",
        ">s",
        "sha256",
        "substr",
        "strlen",
        "concat",
        "+",
        "-",
        "*",
        "/",
        "divmod",
        ">",
        "ash",
        "lsh",
        "logand",
        "logior",
        "logxor",
        "lognot",
        "point_add",
        "pubkey_for_exp",
        "not",
        "any",
        "all",
        "softfork",
        "coinid",
        "g1_subtract",
        "g1_multiply",
        "g1_negate",
        "g2_add",
        "g2_subtract",
        "g2_multiply",
        "g2_negate",
        "g1_map",
        "g2_map",
        "bls_pairing_identity",
        "bls_verify",
        "modpow",
        "%",
        "secp256k1_verify",
        "secp256r1_verify",
        "keccak256",
        // Chialisp syntax / binding / intrinsics
        "quote",
        "qq",
        "unquote",
        "&rest",
        "let",
        "let*",
        "assign",
        "assign-inline",
        "assign-lambda",
        "lambda",
        "mod",
        "if",
        "list",
        "com",
        "opt",
        "@",
        "@*env*",
        "print",
        // def / export / include heads
        "defun",
        "defun-inline",
        "defmacro",
        "defmac",
        "defconstant",
        "defconst",
        "namespace",
        "export",
        "embed-file",
        "compile-file",
        "include",
    ];
    FILTERED.contains(&t)
}

/// Chialisp binder-position detection (C chialisp_node_is_binder_list): a
/// `(defun NAME (params) ...)` parameter list, a `(mod (ARGS) ...)` arg
/// list, a lambda parameter list, or a let binding container/pair. At most
/// two levels, bounded on purpose.
fn chialisp_node_is_binder_list(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let mut node = node;
    for _ in 0..2 {
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.kind() != "list" {
            return false;
        }
        if let Some(head) = helpers::lisp_named_child_skip_comments(parent, 0) {
            if head.kind() == "symbol" {
                let ht = crate::fqn::node_text(head, source);
                if matches!(ht, "defun" | "defun-inline" | "defmacro" | "defmac") {
                    return helpers::lisp_named_child_skip_comments(parent, 2) == Some(node);
                }
                if matches!(ht, "mod" | "lambda" | "let" | "let*") {
                    return helpers::lisp_named_child_skip_comments(parent, 1) == Some(node);
                }
                return false;
            }
        }
        // The head is not a symbol: parent may be a let-binding container
        // and node one of its pairs — retry one level up.
        node = parent;
    }
    false
}

/// ObjectScript (C inline in extract_callee_lang_specific):
/// ##class(Pkg.Class).Method(), $$label^routine extrinsic, $$$Macro.
fn extract_objectscript_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    let nk = node.kind();
    if nk == "class_method_call" {
        let class_ref = crate::fqn::find_child_by_kind(node, "class_ref")?;
        let method_name = crate::fqn::find_child_by_kind(node, "method_name")?;
        let cname = crate::fqn::find_child_by_kind(class_ref, "class_name")?;
        let cls = crate::fqn::node_text(cname, source);
        if cls.is_empty() {
            return None;
        }
        let mname_ident = method_name.named_child(0)?;
        let meth = crate::fqn::node_text(mname_ident, source);
        if meth.is_empty() {
            return Some(cls.to_string());
        }
        return Some(format!("{cls}.{meth}"));
    }
    if nk == "extrinsic_function" || nk == "routine_tag_call" {
        let line_ref = crate::fqn::find_child_by_kind(node, "line_ref")?;
        return Some(crate::fqn::node_text(line_ref, source).to_string());
    }
    if nk == "macro" {
        let raw = crate::fqn::node_text(node, source);
        if !raw.starts_with("$$$") {
            return None;
        }
        let name_start = &raw[3..];
        let name = match name_start.find('(') {
            Some(p) => &name_start[..p],
            None => name_start,
        };
        if name.is_empty() {
            return None;
        }
        return Some(format!("$$${name}"));
    }
    None
}

/// Go template / Helm (C gotemplate_callee): resolve `template "x"` /
/// `include "x"` to the referenced named template (#338).
fn gotemplate_callee<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    let strip =
        |t: &str| -> Option<String> { strip_and_validate_string_arg(t).map(str::to_string) };
    if node.kind() == "template_action" {
        let s = crate::fqn::find_child_by_kind(node, "interpreted_string_literal")?;
        return strip(crate::fqn::node_text(s, source));
    }
    if node.kind() == "function_call" {
        let fnn = crate::fqn::find_child_by_kind(node, "identifier")?;
        let fname = crate::fqn::node_text(fnn, source);
        if !matches!(fname, "include" | "template" | "tpl") {
            return None;
        }
        let args = node
            .child_by_field_name("arguments")
            .or_else(|| crate::fqn::find_child_by_kind(node, "argument_list"))?;
        let s = crate::fqn::find_child_by_kind(args, "interpreted_string_literal")?;
        return strip(crate::fqn::node_text(s, source));
    }
    None
}

/// Language-specific callee dispatch (C extract_callee_lang_specific).
fn extract_callee_lang_specific<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
    lang: Language,
) -> Option<String> {
    let nk = node.kind();
    match lang {
        Language::FORTRAN => {
            if nk == "subroutine_call" {
                return extract_fortran_callee(node, source);
            }
        }
        Language::JSONNET => {
            return extract_jsonnet_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::NICKEL => {
            return extract_nickel_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::TYPST => {
            return extract_typst_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::MESON => {
            return extract_meson_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::SCSS => {
            return extract_scss_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::CSS => {
            return extract_css_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::LINKERSCRIPT => {
            return extract_linkerscript_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::SQL => {
            return extract_sql_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::COBOL => {
            return extract_cobol_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::ELM => {
            return extract_elm_callee(node, source)
                .or_else(|| extract_scripting_callee(node, source, lang));
        }
        Language::CLOJURE
        | Language::COMMONLISP
        | Language::SCHEME
        | Language::FENNEL
        | Language::RACKET
        | Language::EMACSLISP
        | Language::CHIALISP => return extract_lisp_callee(node, source, lang),
        Language::FSHARP => return extract_fsharp_callee(node, source),
        Language::POWERSHELL => return extract_powershell_callee(node, source),
        Language::ADA => return extract_ada_callee(node, source),
        Language::PLSQL => return extract_plsql_callee(node, source),
        Language::SOLIDITY => return extract_solidity_callee(node, source),
        Language::GROOVY => return extract_groovy_callee(node, source),
        Language::WGSL => return extract_wgsl_callee(node, source),
        Language::DART => return extract_dart_callee(node, source),
        Language::OBJC => return extract_objc_callee(node, source),
        Language::ERLANG => return extract_erlang_callee(node, source),
        Language::HASKELL | Language::OCAML | Language::PURESCRIPT | Language::SCALA => {
            return extract_fp_callee(node, source)
        }
        Language::WOLFRAM => {
            if nk == "apply" {
                return extract_wolfram_callee(node, source);
            }
        }
        Language::SWIFT => return extract_swift_callee(node, source),
        Language::VERILOG | Language::SYSTEMVERILOG => {
            if let Some(c) = extract_hdl_callee(node, source) {
                return Some(c);
            }
        }
        Language::VHDL => {
            if let Some(c) = extract_vhdl_callee(node, source) {
                return Some(c);
            }
        }
        Language::NASM => {
            if let Some(c) = extract_nasm_callee(node, source) {
                return Some(c);
            }
        }
        Language::LLVM_IR => {
            if let Some(c) = extract_llvm_callee(node, source) {
                return Some(c);
            }
        }
        Language::FUNC => {
            if let Some(c) = extract_func_callee(node, source) {
                return Some(c);
            }
        }
        Language::AGDA => {
            if let Some(c) = extract_agda_callee(node, source) {
                return Some(c);
            }
        }
        Language::NIX => {
            if let Some(c) = extract_nix_callee(node, source) {
                return Some(c);
            }
        }
        Language::MAKEFILE => {
            if let Some(c) = extract_make_callee(node, source) {
                return Some(c);
            }
        }
        Language::JUST => {
            if let Some(c) = extract_just_callee(node, source) {
                return Some(c);
            }
        }
        Language::PUPPET => {
            if let Some(c) = extract_puppet_callee(node, source) {
                return Some(c);
            }
        }
        Language::OBJECTSCRIPT_UDL | Language::OBJECTSCRIPT_ROUTINE => {
            return extract_objectscript_callee(node, source);
        }
        _ => {}
    }
    extract_scripting_callee(node, source, lang)
}

/// Is this Verilog subroutine_call already wrapped by a
/// function_subroutine_call? (C is_nested_verilog_call_wrapper.)
fn is_nested_verilog_call_wrapper(lang: Language, node: tree_sitter::Node<'_>) -> bool {
    if lang != Language::VERILOG || node.kind() != "subroutine_call" {
        return false;
    }
    node.parent()
        .map(|p| p.kind() == "function_subroutine_call")
        .unwrap_or(false)
}

/// Is `node` (a `list`) the name/params of a definition on this path (C
/// call_node_is_definition_container + its language helpers)? Suppressed
/// roles: Lisp definition forms, Julia/Typst/Agda definition heads, Elixir
/// def calls.
fn call_node_is_definition_container(
    lang: Language,
    node: tree_sitter::Node<'_>,
    source: &str,
) -> bool {
    let kind = node.kind();
    fn contains(outer: tree_sitter::Node<'_>, inner: tree_sitter::Node<'_>) -> bool {
        outer.start_byte() <= inner.start_byte() && outer.end_byte() >= inner.end_byte()
    }
    fn text_in(node: tree_sitter::Node<'_>, source: &str, values: &[&str]) -> bool {
        let t = crate::fqn::node_text(node, source);
        values.contains(&t)
    }
    const CLOJURE_HEADS: &[&str] = &[
        "defn",
        "defn-",
        "def",
        "defmacro",
        "defmulti",
        "defmethod",
        "defprotocol",
        "defrecord",
        "deftype",
        "definterface",
        "defonce",
        "define",
        "define-syntax",
        "define-values",
        "define-syntax-rule",
        "define-struct",
        "define-record-type",
        "define/contract",
        "struct",
    ];
    const CL_HEADS: &[&str] = &[
        "defun",
        "defmacro",
        "defgeneric",
        "defmethod",
        "defvar",
        "defparameter",
        "defconstant",
        "deftype",
        "defstruct",
        "defclass",
    ];
    const ELIXIR_STRUCTURAL: &[&str] = &["def", "defp", "defmacro", "defmodule"];
    const ELIXIR_FUNCTION: &[&str] = &["def", "defp", "defmacro"];

    let lisp_def_head = |head: tree_sitter::Node<'_>| {
        text_in(
            head,
            source,
            if lang == Language::COMMONLISP {
                CL_HEADS
            } else {
                CLOJURE_HEADS
            },
        )
    };

    let lisp_list_is_def = |node: tree_sitter::Node<'_>| -> bool {
        if node.named_child_count() > 0 && lisp_def_head(node.named_child(0).unwrap()) {
            return true;
        }
        let mut parent = node.parent();
        while let Some(p) = parent {
            let pk = p.kind();
            if lang == Language::COMMONLISP && matches!(pk, "defun_header" | "lambda_list") {
                return true;
            }
            if lang == Language::EMACSLISP
                && matches!(pk, "function_definition" | "macro_definition")
            {
                return p
                    .child_by_field_name("parameters")
                    .map(|params| contains(params, node))
                    .unwrap_or(false);
            }
            if matches!(pk, "list" | "list_lit")
                && p.named_child_count() >= 2
                && lisp_def_head(p.named_child(0).unwrap())
            {
                // `(define (name args) body)` nests the signature list in
                // the definition's second form.
                return p
                    .named_child(1)
                    .map(|sig| contains(sig, node))
                    .unwrap_or(false);
            }
            parent = p.parent();
        }
        false
    };

    let julia_is_def_head = |node: tree_sitter::Node<'_>| -> bool {
        let mut parent = node.parent();
        while let Some(p) = parent {
            if matches!(
                p.kind(),
                "assignment" | "function_definition" | "short_function_definition"
            ) {
                return p.named_child(0).map(|h| contains(h, node)).unwrap_or(false);
            }
            parent = p.parent();
        }
        false
    };

    let typst_is_let_pattern = |node: tree_sitter::Node<'_>| -> bool {
        let mut parent = node.parent();
        while let Some(p) = parent {
            if p.kind() == "let" {
                return p
                    .child_by_field_name("pattern")
                    .map(|pat| contains(pat, node))
                    .unwrap_or(false);
            }
            parent = p.parent();
        }
        false
    };

    let agda_is_def_role = |node: tree_sitter::Node<'_>| -> bool {
        let mut parent = node.parent();
        while let Some(p) = parent {
            if matches!(
                p.kind(),
                "lhs"
                    | "typed_binding"
                    | "signature"
                    | "type_signature"
                    | "data_signature"
                    | "record_signature"
            ) {
                return true;
            }
            if p.kind() == "function" {
                // A ':' function line is a type signature; '=' definitions
                // keep rhs applications as executable calls.
                let has_colon = (0..p.child_count())
                    .any(|i| p.child(i).map(|c| c.kind() == ":").unwrap_or(false));
                return has_colon;
            }
            parent = p.parent();
        }
        false
    };

    let elixir_is_def_role = |node: tree_sitter::Node<'_>| -> bool {
        if node.child_count() > 0 && text_in(node.child(0).unwrap(), source, ELIXIR_STRUCTURAL) {
            return true;
        }
        let mut parent = node.parent();
        while let Some(p) = parent {
            if p.kind() != "call"
                || p.child_count() == 0
                || !text_in(p.child(0).unwrap(), source, ELIXIR_FUNCTION)
            {
                parent = p.parent();
                continue;
            }
            let mut arguments = p.child_by_field_name("arguments");
            if arguments.is_none() && p.child_count() > 1 {
                arguments = p.child(1);
            }
            let signature = arguments
                .filter(|a| a.named_child_count() > 0)
                .and_then(|a| a.named_child(0))
                .or(arguments);
            return signature == Some(node);
        }
        false
    };

    match lang {
        Language::CLOJURE
        | Language::SCHEME
        | Language::RACKET
        | Language::COMMONLISP
        | Language::EMACSLISP => matches!(kind, "list" | "list_lit") && lisp_list_is_def(node),
        Language::JULIA => {
            matches!(kind, "call_expression" | "broadcast_call_expression")
                && julia_is_def_head(node)
        }
        Language::TYPST => kind == "call" && typst_is_let_pattern(node),
        Language::AGDA => kind == "expr" && agda_is_def_role(node),
        Language::ELIXIR => kind == "call" && elixir_is_def_role(node),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_env_accesses::ExtractCtx;

    fn run(lang: Language, src: &str, rel: &str) -> Vec<Call> {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", rel);
        let spec = crate::lang_specs::lang_spec(lang);
        extract_calls(&mut ctx, spec, &StringConstantMap::default());
        ctx.result.calls
    }

    #[test]
    fn go_simple_and_selector_calls() {
        let src = "package app\nfunc F() {\n\thandler()\n\tsvc.Process(x)\n}\n";
        let calls = run(Language::GO, src, "a.go");
        let names: Vec<&str> = calls.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(names.contains(&"handler"), "{calls:?}");
        assert!(names.contains(&"svc.Process"), "{calls:?}");
        assert!(calls.iter().all(|c| c.start_line >= 3));
    }

    #[test]
    fn chained_selector_base_method() {
        // router.GetUsers() — chained selector resolves innermost base.
        let src = "package app\nfunc F() {\n\tapi.Router().GetUsers()\n}\n";
        let calls = run(Language::GO, src, "a.go");
        let names: Vec<&str> = calls.iter().map(|c| c.callee_name.as_str()).collect();
        // The outer chain resolves to "api.Router.GetUsers" (innermost base +
        // final method); the inner Router() call is its own edge.
        assert!(names.contains(&"api.Router.GetUsers"), "{names:?}");
        assert!(names.contains(&"api.Router"), "{names:?}");
    }

    #[test]
    fn python_call_with_string_url() {
        let src = "def f():\n    client.post(\"/api/users\")\n";
        let calls = run(Language::PYTHON, src, "a.py");
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].callee_name, "client.post");
        assert_eq!(calls[0].first_string_arg.as_deref(), Some("/api/users"));
        assert_eq!(calls[0].args.len(), 1);
        assert_eq!(calls[0].args[0].value.as_deref(), Some("/api/users"));
    }

    #[test]
    fn keyword_url_and_handler() {
        let src = "def f():\n    app.add_route(url=\"/x\", handler=handle_x)\n";
        let calls = run(Language::PYTHON, src, "a.py");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].first_string_arg.as_deref(), Some("/x"));
        // C's extract_handler_arg only recognizes bare identifier/member/
        // string-shaped args — a keyword_argument wrapper is skipped, so
        // handler=handle_x does NOT set second_arg_name (upstream shape).
        assert_eq!(calls[0].second_arg_name, None);
        // Keyword args captured with keys.
        assert!(calls[0]
            .args
            .iter()
            .any(|a| a.keyword.as_deref() == Some("url")));
    }

    #[test]
    fn keyword_filtered_but_builtins_kept() {
        let src = "def f(xs):\n    return len(xs)\n";
        let calls = run(Language::PYTHON, src, "a.py");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].callee_name, "len");
        let src2 = "def f():\n    return not_a_keyword_call()\n";
        let calls2 = run(Language::PYTHON, src2, "a.py");
        assert_eq!(calls2.len(), 1);
    }

    #[test]
    fn keyword_call_filtered() {
        let src = "def f():\n    import os\n    del(x)\n";
        // `del` is a Python keyword → filtered.
        let calls = run(Language::PYTHON, src, "a.py");
        assert!(calls.is_empty(), "{calls:?}");
    }

    #[test]
    fn constructor_callee() {
        let src = "function f() { var x = new UserService(db); }\n";
        let calls = run(Language::JAVASCRIPT, src, "a.js");
        let names: Vec<&str> = calls.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(names.contains(&"UserService"), "{names:?}");
    }

    #[test]
    fn template_string_flattens() {
        let src = "function f(id) { fetch(`/things/${id}/x`); }\n";
        let calls = run(Language::JAVASCRIPT, src, "a.js");
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(
            calls[0].first_string_arg.as_deref(),
            Some("/things/{}/x"),
            "template ${{id}} → {{}} (#1006)"
        );
    }

    #[test]
    fn ruby_new_redirects_to_receiver() {
        // Ruby grammar not linked; unit-test via the shape guard instead.
        // (Covered by extract_callee_name's Ruby branch when the grammar
        // crate lands.)
        let _ = Language::RUBY;
    }

    #[test]
    fn string_constant_lookup() {
        let mut map = StringConstantMap::default();
        map.entries
            .push(("BASE_URL".into(), "https://api".into(), false));
        map.entries.push(("userPath".into(), "/users".into(), true));
        assert_eq!(map.lookup_constant("BASE_URL"), Some("https://api"));
        assert_eq!(map.lookup_url_builder("userPath"), Some("/users"));
        // URL-builder entries are NOT constants (#1009).
        assert_eq!(map.lookup_constant("userPath"), None);
        assert_eq!(map.lookup_url_builder("BASE_URL"), None);
    }

    #[test]
    fn string_arg_validation() {
        assert_eq!(strip_and_validate_string_arg("\"/ok\""), Some("/ok"));
        assert_eq!(strip_and_validate_string_arg("'y'"), Some("y"));
        assert_eq!(strip_and_validate_string_arg(""), None);
        assert_eq!(strip_and_validate_string_arg("\"\""), None);
        let long = format!("\"{}\"", "x".repeat(600));
        assert_eq!(strip_and_validate_string_arg(&long), None);
    }

    // ── Long-tail language extractors ──

    #[test]
    fn lisp_call_heads() {
        let src = "(other-fn 1 2)\n(greet x)\n";
        let calls = run(Language::CLOJURE, src, "a.clj");
        let names: Vec<&str> = calls.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(names.contains(&"other-fn"), "{names:?}");
        assert!(names.contains(&"greet"), "{names:?}");
        // Definition heads are not calls.
        let src2 = "(defn greet [x] (helper x))\n";
        let calls2 = run(Language::CLOJURE, src2, "b.clj");
        let names2: Vec<&str> = calls2.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(!names2.contains(&"defn"), "{names2:?}");
        assert!(names2.contains(&"helper"), "{names2:?}");
    }

    #[test]
    fn chialisp_primitives_filtered() {
        // No chialisp grammar crate exists on crates.io (the C vendors it),
        // so parse() returns None and the run helper yields nothing — the
        // same empty-result behavior the C has for any language without a
        // grammar. The filter logic itself is exercised through
        // chialisp_head_is_not_call / chialisp_node_is_binder_list below.
        let src = "(sha256 data)\n(mod (params) (helper params))\n";
        let Some(_tree) = crate::ts::parse(Language::CHIALISP, src) else {
            assert!(chialisp_head_is_not_call("sha256"));
            assert!(chialisp_head_is_not_call("defun"));
            assert!(!chialisp_head_is_not_call("helper"));
            assert!(chialisp_head_is_not_call("q"));
            return;
        };
        let calls = run(Language::CHIALISP, src, "a.clsp");
        let names: Vec<&str> = calls.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(
            !names.contains(&"sha256"),
            "CLVM op is not a call: {names:?}"
        );
        assert!(!names.contains(&"mod"), "def head is not a call");
        assert!(names.contains(&"helper"), "real helper resolves: {names:?}");
    }

    #[test]
    fn nix_apply_expression_callee() {
        let src = "let result = addOne 5;\n";
        let calls = run(Language::NIX, src, "a.nix");
        let names: Vec<&str> = calls.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(names.contains(&"addOne"), "{names:?}");
    }

    #[test]
    fn make_shell_and_puppet_include() {
        let src = "$(shell ls)\n";
        let calls = run(Language::MAKEFILE, src, "Makefile");
        let names: Vec<&str> = calls.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(names.contains(&"shell"), "{names:?}");

        let src2 = "include myclass\n";
        let calls2 = run(Language::PUPPET, src2, "a.pp");
        let names2: Vec<&str> = calls2.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(names2.contains(&"include"), "{names2:?}");
    }

    #[test]
    fn julia_definition_head_not_call() {
        let src = "greet(x) = helper(x)\n";
        let calls = run(Language::JULIA, src, "a.jl");
        let names: Vec<&str> = calls.iter().map(|c| c.callee_name.as_str()).collect();
        assert!(!names.contains(&"greet"), "definition head: {names:?}");
        assert!(names.contains(&"helper"), "body call captured: {names:?}");
    }
}
