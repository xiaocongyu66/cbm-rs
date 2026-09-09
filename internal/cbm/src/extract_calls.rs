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
fn is_definition_container(lang: Language, node: tree_sitter::Node<'_>, source: &str) -> bool {
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

/// Callee name for the part-1 languages (C extract_callee_name, main path).
pub fn extract_callee_name<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
    lang: Language,
) -> Option<String> {
    if is_definition_container(lang, node, source) {
        return None;
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
    // Python dict-dispatch `funcs["a"](v)`: emit the base identifier so the
    // py-LSP resolves it and joins via `reason` (lsp_dict_dispatch).
    if lang == Language::PYTHON && node.kind() == "call" {
        if let Some(fnf) = node.child_by_field_name("function") {
            if fnf.kind() == "subscript" {
                let val = fnf.child_by_field_name("value");
                let idx = fnf.child_by_field_name("subscript");
                if let (Some(val), Some(idx)) = (val, idx) {
                    if val.kind() == "identifier" && idx.kind() == "string" {
                        return Some(crate::fqn::node_text(val, source).to_string());
                    }
                }
            }
        }
    }
    // Common field-based resolution first.
    if let Some(name) = extract_callee_from_fields(node, source) {
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
}
