//! extract_usages.rs — 1:1 rewrite of `internal/cbm/extract_usages.c`
//! (2683 lines), part 1: the legacy standalone walker (C walk_usages /
//! try_emit_usage), `is_reference_node` with its per-language reference
//! kinds, STANDARD occurrence policy binding/write classification, and
//! the callable-value candidate stamping for go/python/js-family/rust.
//!
//! The unified-walk half (handle_usages + WalkState lexical scopes) lands
//! with extract_unified.rs; part 1 already covers the full standalone
//! extraction contract (C cbm_extract_usages calls walk_usages directly).

use crate::extract_env_accesses::ExtractCtx;
use crate::helpers;
use crate::lang_specs::LanguageSpec;
use crate::types::{SourceOrigin, Usage, UsageKind};
use crate::Language;

// ── Binding tables (verbatim from C) ────────────────────────────

/// Declaration containers that bind their name/pattern wholesale.
pub const COMMON_WHOLE_BINDING_NODES: &[&str] = &[
    "formal_parameter",
    "formal_parameters",
    "parameter",
    "parameters",
    "parameter_list",
    "parameter_declaration",
    "parameter_specification",
    "required_parameter",
    "optional_parameter",
    "default_parameter",
    "typed_parameter",
    "function_value_parameter",
    "function_value_parameters",
    "lambda_parameter",
    "lambda_parameters",
    "function_parameter_declaration",
    "closure_parameters",
    "block_parameters",
    "receiver",
];

/// Declaration containers whose binding_field children bind.
const FIELD_BINDING_NODES: &[&str] = &[
    "variable_declarator",
    "init_declarator",
    "variable_declaration",
    "const_declaration",
    "lexical_declaration",
    "short_var_declaration",
    "local_variable_declaration",
    "property_declaration",
    "field_declaration",
    "value_declaration",
    "val_definition",
    "var_definition",
    "let_declaration",
    "local_bind",
    "let_binding",
    "data_declaration",
    "net_declaration",
    "object_declaration",
    "number_declaration",
    "typed_binding",
    "variable_assignment",
];

/// Fields under which a declaration container binds its child.
const BINDING_FIELDS: &[&str] = &[
    "name",
    "pattern",
    "declarator",
    "parameter",
    "parameters",
    "left",
    "variable",
    "variables",
    "key",
];

/// Default/value/body fields are barriers: an initializer nested below one
/// of these stays a read (C is_value_field).
fn is_value_field(field: Option<&str>) -> bool {
    matches!(
        field,
        Some(
            "value"
                | "right"
                | "initializer"
                | "default"
                | "default_value"
                | "body"
                | "arguments"
                | "condition"
                | "consequence"
                | "alternative"
                | "expression"
                | "result"
        )
    )
}

pub fn common_whole_binding_nodes() -> &'static [&'static str] {
    COMMON_WHOLE_BINDING_NODES
}

pub fn read_write_nodes() -> &'static [&'static str] {
    READ_WRITE_NODES
}

// ── Reference node classification (C is_reference_node) ────────

/// Is this an identifier-like node that represents a reference?
pub fn is_reference_node(node: tree_sitter::Node<'_>, lang: Language) -> bool {
    let kind = node.kind();

    // Python's attribute node and its terminal identifier describe the same
    // source occurrence; direct callable-value arguments keep the leaf as
    // the raw carrier.
    if lang == Language::PYTHON
        && kind == "attribute"
        && python_direct_callable_attribute_site(node).is_some()
    {
        return false;
    }

    // A Rust scoped_identifier owns the complete path occurrence; its
    // nested path/identifier children are grammar structure.
    if lang == Language::RUST && matches!(kind, "identifier" | "scoped_identifier") {
        if let Some(parent) = node.parent() {
            if parent.kind() == "scoped_identifier" {
                return false;
            }
        }
    }

    // Sigil/scope wrappers keep exactly one occurrence: the wrapper.
    // The language gate MUST precede the parent fetch (C performance note:
    // ts_node_parent re-descends from the root; fetching it per identifier
    // made deep-nesting extraction quadratic).
    if matches!(lang, Language::PUPPET | Language::VIMSCRIPT) && kind == "identifier" {
        if let Some(parent) = node.parent() {
            let wrapper = match lang {
                Language::PUPPET => parent.kind() == "variable",
                Language::VIMSCRIPT => parent.kind() == "argument",
                _ => false,
            };
            if wrapper {
                return false;
            }
        }
    }

    // Common identifier types across languages.
    if matches!(kind, "identifier" | "simple_identifier" | "type_identifier") {
        return true;
    }

    // Language-specific reference kinds.
    match lang {
        Language::JAVASCRIPT
        | Language::TYPESCRIPT
        | Language::TSX
        | Language::ARKTS
        | Language::QML
        | Language::CFSCRIPT => {
            matches!(kind, "property_identifier" | "private_property_identifier")
        }
        Language::GO => matches!(kind, "field_identifier" | "package_identifier"),
        Language::PYTHON => kind == "attribute",
        Language::RUST => matches!(kind, "field_identifier" | "scoped_identifier"),
        Language::C | Language::CPP | Language::CUDA => kind == "field_identifier",
        Language::PHP => matches!(kind, "name" | "variable_name"),
        Language::HASKELL => matches!(kind, "variable" | "constructor"),
        Language::OCAML => matches!(kind, "value_path" | "constructor_path"),
        Language::ERLANG => matches!(kind, "atom" | "var"),
        Language::CSS => kind == "plain_value",
        Language::SCSS => kind == "variable_value",
        Language::CMAKE => kind == "variable",
        Language::WOLFRAM => kind == "user_symbol",
        Language::TYPST => kind == "ident",
        Language::TCL => kind == "variable_substitution",
        Language::TLAPLUS => kind == "identifier_ref",
        Language::AGDA => kind == "qid",
        Language::RESCRIPT => kind == "value_identifier",
        Language::PURESCRIPT => kind == "variable",
        Language::NICKEL => kind == "ident",
        Language::JSONNET => kind == "id",
        Language::CFML => kind == "property_identifier",
        Language::OBJECTSCRIPT_UDL | Language::OBJECTSCRIPT_ROUTINE => {
            matches!(
                kind,
                "objectscript_identifier" | "objectscript_identifier_special"
            )
        }
        Language::PLSQL => kind == "identifier",
        _ => false,
    }
}

// ── Occurrence policy (STANDARD path; the specialized policies land
//    with extract_unified) ───────────────────────────────────────

fn node_contains(outer: tree_sitter::Node<'_>, inner: tree_sitter::Node<'_>) -> bool {
    outer.start_byte() <= inner.start_byte() && outer.end_byte() >= inner.end_byte()
}

fn field_contains_node(
    parent: tree_sitter::Node<'_>,
    field: &str,
    node: tree_sitter::Node<'_>,
) -> bool {
    parent
        .child_by_field_name(field)
        .map(|v| node_contains(v, node))
        .unwrap_or(false)
}

fn field_name_for_node(
    parent: tree_sitter::Node<'_>,
    child: tree_sitter::Node<'_>,
) -> Option<&'static str> {
    // tree-sitter child fields are grammar-static; walk children once.
    let mut cursor = parent.walk();
    if cursor.goto_first_child() {
        loop {
            if cursor.node() == child {
                // SAFETY: field names come from the 'static grammar tables.
                let name = cursor.field_name();
                return name.map(|n| unsafe { std::mem::transmute::<&str, &'static str>(n) });
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

/// Is `parent` a binding container whose `binding_field` holds `node`?
pub fn declared_container_binds_public(
    parent: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    node: tree_sitter::Node<'_>,
) -> bool {
    declared_container_binds(parent, spec, node)
}

pub fn is_call_interior_public(node: tree_sitter::Node<'_>) -> bool {
    // Part 1 approximation: the standalone walker's inside-call check walks
    // ancestors for a call container. The unified walker tracks call depth;
    // the C's invocation-triple suppression (exact callee consumption) lands
    // with lexical bindings.
    let mut cur = node.parent();
    while let Some(p) = cur {
        if matches!(p.kind(), "call" | "call_expression") {
            return true;
        }
        cur = p.parent();
    }
    false
}

fn declared_container_binds(
    parent: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    node: tree_sitter::Node<'_>,
) -> bool {
    let kind = parent.kind();
    let variable_container =
        !spec.variable_node_types.is_empty() && spec.variable_node_types.contains(&kind);
    let declared = FIELD_BINDING_NODES.contains(&kind)
        || (!spec.function_node_types.is_empty() && spec.function_node_types.contains(&kind))
        || (!spec.class_node_types.is_empty() && spec.class_node_types.contains(&kind))
        || (!spec.field_node_types.is_empty() && spec.field_node_types.contains(&kind))
        || variable_container;
    if !declared {
        return false;
    }
    BINDING_FIELDS
        .iter()
        .any(|f| field_contains_node(parent, f, node))
}

/// Binding classification, STANDARD policy (C is_binding_occurrence minus
/// the exact-language/policy hooks that land with the unified walk).
/// Climbs the parent chain; value fields and `type` annotations are
/// barriers; whole-binding containers and declared containers with binding
/// fields bind.
pub fn is_binding_occurrence(
    _ctx: &ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
) -> bool {
    let mut current = node;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        let field = field_name_for_node(parent, current);
        if is_value_field(field) {
            return false;
        }
        // A declaration container binds its name/pattern, not the symbols
        // used by its type annotation (`cfg: Config` / `cfg Config` expose
        // the annotation through the exact `type` field).
        if field == Some("type") {
            return false;
        }
        let kind = parent.kind();
        if COMMON_WHOLE_BINDING_NODES.contains(&kind) {
            return true;
        }
        if declared_container_binds(parent, spec, node) {
            return true;
        }
        current = parent;
    }
}

// ── Write classification (C assignment_reads_target +
//    is_write_occurrence STANDARD path) ─────────────────────────

pub const READ_WRITE_NODES: &[&str] = &[
    "augmented_assignment",
    "augmented_assignment_expression",
    "compound_assignment_expr",
    "compound_assignment_expression",
    "operator_assignment",
    "operator_assign",
    "update_exp",
    "postfix_unary_expression",
    "prefix_unary_expression",
];

const READ_WRITE_OPERATORS: &[&str] = &[
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "??=", "++", "--",
];

/// `+=`/`++`-shaped assignments READ their target as well as write it
/// (C assignment_reads_target).
pub fn assignment_reads_target(assignment: tree_sitter::Node<'_>) -> bool {
    if READ_WRITE_NODES.contains(&assignment.kind()) {
        return true;
    }
    for i in 0..assignment.child_count() {
        let c = assignment.child(i).unwrap();
        if READ_WRITE_OPERATORS.contains(&c.kind()) {
            return true;
        }
    }
    false
}

/// Write occurrence, STANDARD policy (C is_write_occurrence).
pub fn is_write_occurrence(
    _ctx: &ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
) -> bool {
    let mut current = node;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        let field = field_name_for_node(parent, current);
        if is_value_field(field) {
            return false;
        }
        let kind = parent.kind();
        let assignment = (!spec.assignment_node_types.is_empty()
            && spec.assignment_node_types.contains(&kind))
            || READ_WRITE_NODES.contains(&kind);
        if assignment {
            if assignment_reads_target(parent) {
                return false;
            }
            let left = parent.child_by_field_name("left");
            if left.map(|l| node_contains(l, node)).unwrap_or(false)
                || field_contains_node(parent, "target", node)
                || field_contains_node(parent, "destination", node)
            {
                return true;
            }
            return false;
        }
        current = parent;
    }
}

// ── Call-argument labels and direct argument values ────────────

fn is_labeled_argument_kind(kind: &str) -> bool {
    matches!(
        kind,
        "keyword_argument" | "named_argument" | "labeled_argument"
    )
}

fn is_argument_container_kind(kind: &str) -> bool {
    matches!(kind, "arguments" | "argument_list" | "value_arguments")
}

/// A labeled argument's KEY describes the callee parameter — neither a
/// usage nor a caller-local binding (C is_call_argument_label).
pub fn is_call_argument_label(node: tree_sitter::Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        let parent_kind = parent.kind();
        if is_labeled_argument_kind(parent_kind) {
            return field_contains_node(parent, "name", node)
                || field_contains_node(parent, "label", node)
                || field_contains_node(parent, "key", node);
        }
        if is_argument_container_kind(parent_kind) {
            return false;
        }
        current = parent;
    }
    false
}

/// Is `node` a direct argument value of a call (C is_direct_argument_value)?
fn is_direct_argument_value(node: tree_sitter::Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let pk = parent.kind();
    if is_labeled_argument_kind(pk) {
        let value = parent.child_by_field_name("value");
        return value == Some(node) && is_direct_argument_value(parent);
    }
    if let Some(direct) = parent.child_by_field_name("arguments") {
        if direct == node {
            return true;
        }
    }
    if is_argument_container_kind(pk) {
        return true;
    }
    if pk == "list_expression" {
        if let Some(call) = parent.parent() {
            return call
                .child_by_field_name("arguments")
                .map(|a| a == parent)
                .unwrap_or(false);
        }
        return false;
    }
    if pk != "argument" && pk != "value_argument" {
        return false;
    }
    parent
        .parent()
        .map(|gp| is_argument_container_kind(gp.kind()))
        .unwrap_or(false)
}

/// Python attribute site whose value is a direct callable argument
/// (C python_direct_callable_attribute_site).
fn python_direct_callable_attribute_site<'t>(
    node: tree_sitter::Node<'t>,
) -> Option<tree_sitter::Node<'t>> {
    let parent = node.parent()?;
    if parent.kind() != "argument_list" {
        return None;
    }
    let grand = parent.parent()?;
    let candidate = if grand.kind() == "attribute" {
        grand
    } else {
        let call = if grand.kind() == "call" {
            grand
        } else {
            return None;
        };
        call.child_by_field_name("function")?
    };
    if candidate.kind() == "attribute" {
        Some(candidate)
    } else {
        None
    }
}

/// Languages allowed to stamp callable-value candidates
/// (C language_may_stamp_exact_callable_value_candidate).
fn language_may_stamp(lang: Language) -> bool {
    matches!(
        lang,
        Language::JAVASCRIPT
            | Language::TYPESCRIPT
            | Language::TSX
            | Language::ARKTS
            | Language::GO
            | Language::PYTHON
            | Language::C
            | Language::CPP
            | Language::CUDA
            | Language::RUST
            | Language::CSHARP
            | Language::KOTLIN
    )
}

/// Callable-value candidate site (C call_reference_candidate_site): a
/// narrow syntactic shape whose exact occurrence may upgrade USAGE to a
/// typed CALL_REFERENCE after LSP proof.
fn call_reference_candidate_site<'t>(
    ctx: &ExtractCtx<'t>,
    node: tree_sitter::Node<'t>,
    _name: &str,
) -> Option<tree_sitter::Node<'t>> {
    if !language_may_stamp(ctx.language) {
        return None;
    }
    let kind = node.kind();
    let parent = node.parent();
    let ts_family = matches!(
        ctx.language,
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS
    );
    if ts_family
        && kind == "property_identifier"
        && parent
            .map(|p| p.kind() == "member_expression")
            .unwrap_or(false)
    {
        let p = parent.unwrap();
        let property = p.child_by_field_name("property");
        let arguments = p.parent();
        return if property == Some(node)
            && arguments.map(|a| a.kind() == "arguments").unwrap_or(false)
        {
            Some(node)
        } else {
            None
        };
    }
    if ctx.language == Language::PYTHON
        && kind == "identifier"
        && parent.map(|p| p.kind() == "attribute").unwrap_or(false)
    {
        let p = parent.unwrap();
        let attribute = p.child_by_field_name("attribute");
        return if attribute == Some(node) {
            python_direct_callable_attribute_site(p)
        } else {
            None
        };
    }
    if ctx.language == Language::GO
        && kind == "field_identifier"
        && parent
            .map(|p| p.kind() == "selector_expression")
            .unwrap_or(false)
    {
        let p = parent.unwrap();
        let field = p.child_by_field_name("field");
        return if field == Some(node) && is_direct_argument_value(p) {
            Some(p)
        } else {
            None
        };
    }
    if ctx.language == Language::RUST && kind == "scoped_identifier" {
        return is_direct_argument_value(node).then_some(node);
    }
    if kind != "identifier" && kind != "simple_identifier" {
        return None;
    }
    None
}

/// Stamp the exact source occurrence (C stamp_usage_site).
fn stamp_usage_site<'t>(
    ctx: &ExtractCtx<'t>,
    usage: &mut Usage,
    node: tree_sitter::Node<'t>,
    name: &str,
) {
    let candidate = call_reference_candidate_site(ctx, node, name);
    let site = candidate.unwrap_or(node);
    usage.site_start_byte = site.start_byte() as u32;
    usage.site_end_byte = site.end_byte() as u32;
    usage.may_be_call_reference = candidate.is_some();
}

/// Reference name (C reference_name): Makefile `$(watched)` unwraps.
fn reference_name<'a>(ctx: &ExtractCtx<'a>, node: tree_sitter::Node<'a>) -> &'a str {
    let name = crate::fqn::node_text(node, ctx.source);
    if ctx.language != Language::MAKEFILE || node.kind() != "variable_reference" {
        return name;
    }
    let b = name.as_bytes();
    let parenthesized = b.len() > 3 && b[0] == b'$' && b[1] == b'(' && b[b.len() - 1] == b')';
    if parenthesized {
        &name[2..b.len() - 1]
    } else {
        name
    }
}

// ── Walker (C try_emit_usage + walk_usages) ─────────────────────

/// Emit for one node (C try_emit_usage): the standalone walk skips call /
/// import interiors — their call sites are handled by extract_calls and
/// the import parsers.
fn try_emit_usage(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    inside_call: bool,
    inside_import: bool,
) {
    if !is_reference_node(node, ctx.language) {
        return;
    }
    if is_call_argument_label(node) {
        return;
    }
    if inside_call || inside_import {
        return;
    }
    if is_binding_occurrence(ctx, node, spec) || is_write_occurrence(ctx, node, spec) {
        return;
    }
    let name = reference_name(ctx, node);
    if !name.is_empty() && !helpers::is_keyword(name, ctx.language) {
        let mut usage = Usage {
            ref_name: name.to_string(),
            enclosing_func_qn: String::new(),
            kind: UsageKind::Value,
            may_be_call_reference: false,
            semantic_reference_blocked: false,
            semantic_reference_local_shadow: false,
            lexical_scope_id: 0,
            site_start_byte: 0,
            site_end_byte: 0,
            source_origin: SourceOrigin::Raw,
            is_member_access: false,
        };
        stamp_usage_site(ctx, &mut usage, node, name);
        usage.enclosing_func_qn = ctx.ef_cache.enclosing_qn(
            node,
            ctx.language,
            ctx.source,
            ctx.project,
            ctx.rel_path,
            &ctx.module_qn,
        );
        ctx.result.usages.push(usage);
    }
}

/// Iterative usage walker (C walk_usages): call/import ancestry is
/// maintained as ENTER/EXIT counters, and a node is emitted BEFORE its own
/// kind increments them (strict ancestors only).
pub fn extract_usages(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    struct Frame<'t> {
        node: tree_sitter::Node<'t>,
        next_child: usize,
        counts_call: bool,
        counts_import: bool,
    }
    let has_imports = !spec.import_node_types.is_empty();
    let has_from_imports = !spec.import_from_types.is_empty();
    let mut call_depth = 0usize;
    let mut import_depth = 0usize;
    let mut stack: Vec<Frame<'_>> = vec![Frame {
        node: ctx.root,
        next_child: 0,
        counts_call: false,
        counts_import: false,
    }];
    while let Some(frame) = stack.last_mut() {
        if frame.next_child == 0 {
            // Entering: emit before counting this node's own kind.
            let node = frame.node;
            try_emit_usage(ctx, node, spec, call_depth > 0, import_depth > 0);
            frame.counts_call = spec.call_node_types.contains(&node.kind());
            frame.counts_import = (has_imports && spec.import_node_types.contains(&node.kind()))
                || (has_from_imports && spec.import_from_types.contains(&node.kind()));
            if frame.counts_call {
                call_depth += 1;
            }
            if frame.counts_import {
                import_depth += 1;
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
                    counts_call: false,
                    counts_import: false,
                });
            }
        } else {
            // Exiting.
            let frame = stack.pop().unwrap();
            if frame.counts_call {
                call_depth -= 1;
            }
            if frame.counts_import {
                import_depth -= 1;
            }
        }
    }
}

// ── Occurrence policies (C CBMOccurrencePolicy / occurrence_specs) ──

/// Occurrence semantics that evolve per language without touching the
/// positional CBMLangSpec (C CBMOccurrencePolicy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum OccurrencePolicy {
    #[default]
    Standard = 0,
    LispDef,
    CommonlispDefun,
    FennelFn,
    ElixirDef,
    JuliaFunction,
    WolframSet,
    TypstLet,
    AgdaFunction,
    TlaplusOperator,
    CobolMove,
    HclAttribute,
    ElmValue,
    RescriptLet,
    PurescriptLhs,
    NickelLet,
    ErlangClause,
    NixFunction,
    MatlabArguments,
    LeanBinder,
    PascalProc,
    TealFunction,
    VhdlInterface,
    PineFunction,
    LlvmFunction,
    PklDeclaration,
}

/// Per-language occurrence spec (C CBMOccurrenceSpec): the whole-binding
/// container kinds beyond the common set, write-node kinds, the policy, and
/// whether a container's first named child is its write target.
#[derive(Debug, Clone, Copy)]
pub struct OccurrenceSpec {
    pub whole_binding_nodes: &'static [&'static str],
    pub write_nodes: &'static [&'static str],
    pub policy: OccurrencePolicy,
    pub first_named_child_is_write: bool,
}

const SQL_BINDING_NODES: &[&str] = &["function_argument"];
const HASKELL_BINDING_NODES: &[&str] = &["patterns"];
const FSHARP_BINDING_NODES: &[&str] = &[
    "function_declaration_left",
    "value_declaration_left",
    "argument_patterns",
];
const CRYSTAL_BINDING_NODES: &[&str] = &["param_list"];
const AWK_BINDING_NODES: &[&str] = &["param_list"];
const TEAL_BINDING_NODES: &[&str] = &["function_signature"];
const SYSTEMVERILOG_BINDING_NODES: &[&str] = &["tf_port_item", "tf_port_item1"];
const RESCRIPT_BINDING_NODES: &[&str] = &["formal_parameters", "labeled_parameter", "parameter"];
const PURESCRIPT_BINDING_NODES: &[&str] = &["bind_pattern", "pattern", "patterns"];
const NICKEL_BINDING_NODES: &[&str] = &["pattern_fun"];
const JSONNET_BINDING_NODES: &[&str] = &["param"];
const LLVM_BINDING_NODES: &[&str] = &["function_header"];
const LINKERSCRIPT_WRITE_NODES: &[&str] = &["assignment"];
const MESON_WRITE_NODES: &[&str] = &["operatorunit"];
const GN_WRITE_NODES: &[&str] = &["assignment_statement"];
const OBJECTSCRIPT_BINDING_NODES: &[&str] = &["argument", "tag_parameter"];
const OBJECTSCRIPT_WRITE_NODES: &[&str] = &["set_argument"];

const STD: OccurrenceSpec = OccurrenceSpec {
    whole_binding_nodes: &[],
    write_nodes: &[],
    policy: OccurrencePolicy::Standard,
    first_named_child_is_write: false,
};

/// Parallel to lang_specs (C occurrence_specs[CBM_LANG_COUNT]); languages
/// not listed use STANDARD with no extra tables.
pub fn occurrence_spec(lang: Language) -> OccurrenceSpec {
    let (whole, write, policy, first_write): (
        &'static [&'static str],
        &'static [&'static str],
        OccurrencePolicy,
        bool,
    ) = match lang {
        Language::SQL => (SQL_BINDING_NODES, &[], OccurrencePolicy::Standard, false),
        Language::CLOJURE | Language::SCHEME | Language::RACKET | Language::CHIALISP => {
            (&[], &[], OccurrencePolicy::LispDef, false)
        }
        Language::COMMONLISP => (&[], &[], OccurrencePolicy::CommonlispDefun, false),
        Language::FENNEL => (&[], &[], OccurrencePolicy::FennelFn, false),
        Language::ELIXIR => (&[], &[], OccurrencePolicy::ElixirDef, false),
        Language::JULIA => (&[], &[], OccurrencePolicy::JuliaFunction, false),
        Language::WOLFRAM => (&[], &[], OccurrencePolicy::WolframSet, false),
        Language::TYPST => (&[], &[], OccurrencePolicy::TypstLet, false),
        Language::AGDA => (&[], &[], OccurrencePolicy::AgdaFunction, false),
        Language::TLAPLUS => (&[], &[], OccurrencePolicy::TlaplusOperator, false),
        Language::COBOL => (&[], &[], OccurrencePolicy::CobolMove, false),
        Language::HCL => (&[], &[], OccurrencePolicy::HclAttribute, false),
        Language::ELM => (&[], &[], OccurrencePolicy::ElmValue, false),
        Language::RESCRIPT => (
            RESCRIPT_BINDING_NODES,
            &[],
            OccurrencePolicy::RescriptLet,
            false,
        ),
        Language::PURESCRIPT => (
            PURESCRIPT_BINDING_NODES,
            &[],
            OccurrencePolicy::PurescriptLhs,
            false,
        ),
        Language::NICKEL => (
            NICKEL_BINDING_NODES,
            &[],
            OccurrencePolicy::NickelLet,
            false,
        ),
        Language::JSONNET => (
            JSONNET_BINDING_NODES,
            &[],
            OccurrencePolicy::Standard,
            false,
        ),
        Language::HASKELL => (
            HASKELL_BINDING_NODES,
            &[],
            OccurrencePolicy::Standard,
            false,
        ),
        Language::ERLANG => (&[], &[], OccurrencePolicy::ErlangClause, false),
        Language::FSHARP => (FSHARP_BINDING_NODES, &[], OccurrencePolicy::Standard, false),
        Language::NIX => (&[], &[], OccurrencePolicy::NixFunction, false),
        Language::MATLAB => (&[], &[], OccurrencePolicy::MatlabArguments, false),
        Language::LEAN => (&[], &[], OccurrencePolicy::LeanBinder, false),
        Language::PASCAL => (&[], &[], OccurrencePolicy::PascalProc, false),
        Language::VERILOG => (
            SYSTEMVERILOG_BINDING_NODES,
            &[],
            OccurrencePolicy::Standard,
            false,
        ),
        Language::AWK => (AWK_BINDING_NODES, &[], OccurrencePolicy::Standard, false),
        Language::CRYSTAL => (
            CRYSTAL_BINDING_NODES,
            &[],
            OccurrencePolicy::Standard,
            false,
        ),
        Language::TEAL => (
            TEAL_BINDING_NODES,
            &[],
            OccurrencePolicy::TealFunction,
            false,
        ),
        Language::VHDL => (&[], &[], OccurrencePolicy::VhdlInterface, false),
        Language::SYSTEMVERILOG => (
            SYSTEMVERILOG_BINDING_NODES,
            &[],
            OccurrencePolicy::Standard,
            false,
        ),
        Language::PINE => (&[], &[], OccurrencePolicy::PineFunction, false),
        Language::PUPPET => (&[], &[], OccurrencePolicy::Standard, true),
        Language::LLVM_IR => (
            LLVM_BINDING_NODES,
            &[],
            OccurrencePolicy::LlvmFunction,
            false,
        ),
        Language::PKL => (&[], &[], OccurrencePolicy::PklDeclaration, false),
        Language::MESON => (&[], MESON_WRITE_NODES, OccurrencePolicy::Standard, true),
        Language::GN => (&[], GN_WRITE_NODES, OccurrencePolicy::Standard, true),
        Language::LINKERSCRIPT => (
            &[],
            LINKERSCRIPT_WRITE_NODES,
            OccurrencePolicy::Standard,
            true,
        ),
        Language::OBJECTSCRIPT_UDL | Language::OBJECTSCRIPT_ROUTINE => (
            OBJECTSCRIPT_BINDING_NODES,
            OBJECTSCRIPT_WRITE_NODES,
            OccurrencePolicy::Standard,
            true,
        ),
        _ => (&[], &[], OccurrencePolicy::Standard, false),
    };
    if policy == OccurrencePolicy::Standard && whole.is_empty() && write.is_empty() && !first_write
    {
        STD
    } else {
        OccurrenceSpec {
            whole_binding_nodes: whole,
            write_nodes: write,
            policy,
            first_named_child_is_write: first_write,
        }
    }
}

fn named_child_contains(
    parent: tree_sitter::Node<'_>,
    index: usize,
    node: tree_sitter::Node<'_>,
) -> bool {
    parent
        .named_child(index)
        .map(|c| node_contains(c, node))
        .unwrap_or(false)
}

/// Every direct child whose field role is `field` contains `node` (C
/// any_field_contains_node): repeated/inherited fields need all instances.
fn any_field_contains_node(
    parent: tree_sitter::Node<'_>,
    field: &str,
    node: tree_sitter::Node<'_>,
) -> bool {
    let mut cursor = parent.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let matched = cursor.field_name().map(|f| f == field).unwrap_or(false)
            && node_contains(cursor.node(), node);
        if matched {
            return true;
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}

fn text_equals(node: tree_sitter::Node<'_>, expected: &str, source: &str) -> bool {
    crate::fqn::node_text(node, source) == expected
}

/// Lisp def heads (Clojure/Scheme/Racket) (C lisp_def_head).
fn lisp_def_head(t: &str) -> bool {
    matches!(
        t,
        "defn"
            | "defn-"
            | "def"
            | "defmacro"
            | "defmulti"
            | "defmethod"
            | "defprotocol"
            | "defrecord"
            | "deftype"
            | "definterface"
            | "defonce"
            | "define"
            | "define-syntax"
            | "define-values"
            | "define-struct"
            | "define-record-type"
            | "define/contract"
            | "struct"
    )
}

/// Chialisp heads whose THIRD form is a parameter list (C
/// chialisp_head_binds_params_at_2): `(defun NAME (params) body)`.
/// Deliberately not `defconstant` — its third form is the VALUE expression.
fn chialisp_head_binds_params_at_2(head: &str) -> bool {
    matches!(head, "defun" | "defun-inline" | "defmacro" | "defmac")
}

fn is_lisp_def_binding(node: tree_sitter::Node<'_>, lang: Language, source: &str) -> bool {
    let chialisp = lang == Language::CHIALISP;
    let mut form = node.parent();
    while let Some(form_node) = form {
        let kind = form_node.kind();
        if (kind != "list" && kind != "list_lit") || form_node.named_child_count() < 2 {
            form = form_node.parent();
            continue;
        }
        // Chialisp reads its head through the comment-skipping accessor (C).
        let head_node = if chialisp {
            helpers::lisp_named_child_skip_comments(form_node, 0)
        } else {
            form_node.named_child(0)
        };
        let Some(head_node) = head_node else {
            form = form_node.parent();
            continue;
        };
        let head = crate::fqn::node_text(head_node, source);
        let is_def = if chialisp {
            helpers::chialisp_is_def_head(head)
        } else {
            lisp_def_head(head)
        };
        if !is_def {
            form = form_node.parent();
            continue;
        }
        // A def head inside `(q ...)`/`(qq ...)` is quoted DATA (shared rule
        // with extract_defs — the helpers' quote check covers this upstream;
        // here the binding scan inside quotes never fires because quote
        // contents were skipped as data by the walkers).
        if node_contains(head_node, node) || named_child_contains(form_node, 1, node) {
            return true;
        }
        if (lang == Language::CLOJURE || (chialisp && chialisp_head_binds_params_at_2(head)))
            && form_node.named_child_count() > 2
            && named_child_contains(form_node, 2, node)
        {
            return true;
        }
        return false;
    }
    false
}

fn is_fennel_fn_binding(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let mut form = node.parent();
    while let Some(form_node) = form {
        if form_node.kind() == "list"
            && form_node.named_child_count() >= 2
            && form_node
                .named_child(0)
                .map(|h| text_equals(h, "fn", source))
                .unwrap_or(false)
        {
            let first = form_node.named_child(1).unwrap();
            let anonymous = matches!(first.kind(), "sequence" | "table" | "vector");
            if anonymous {
                return named_child_contains(form_node, 0, node) || node_contains(first, node);
            }
            return named_child_contains(form_node, 0, node)
                || node_contains(first, node)
                || (form_node.named_child_count() > 2 && named_child_contains(form_node, 2, node));
        }
        form = form_node.parent();
    }
    false
}

fn is_elixir_def_binding(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let mut form = node.parent();
    while let Some(form_node) = form {
        if form_node.kind() == "call" && form_node.named_child_count() >= 2 {
            let head = form_node.named_child(0).unwrap();
            let head_text = crate::fqn::node_text(head, source);
            if head_text == "def" || head_text == "defp" || head_text == "defmacro" {
                let mut arguments = form_node.child_by_field_name("arguments");
                if arguments
                    .map(|a| a.named_child_count() == 0)
                    .unwrap_or(true)
                {
                    arguments = form_node.named_child(1);
                }
                let signature = arguments
                    .filter(|a| a.named_child_count() > 0)
                    .and_then(|a| a.named_child(0))
                    .or(arguments);
                return node_contains(head, node)
                    || signature.map(|s| node_contains(s, node)).unwrap_or(false);
            }
        }
        form = form_node.parent();
    }
    false
}

fn is_first_named_part_of(node: tree_sitter::Node<'_>, container_kind: &str) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        if p.kind() == container_kind {
            return named_child_contains(p, 0, node);
        }
        parent = p.parent();
    }
    false
}

fn is_wolfram_lhs(node: tree_sitter::Node<'_>) -> bool {
    const SET_NODES: &[&str] = &[
        "set",
        "set_top",
        "set_delayed",
        "set_delayed_top",
        "tag_set",
        "tag_set_top",
        "tag_set_delayed",
        "tag_set_delayed_top",
        "up_set",
        "up_set_top",
        "up_set_delayed",
        "up_set_delayed_top",
    ];
    let mut parent = node.parent();
    while let Some(p) = parent {
        if SET_NODES.contains(&p.kind()) {
            return named_child_contains(p, 0, node);
        }
        parent = p.parent();
    }
    false
}

fn is_tlaplus_binding(node: tree_sitter::Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        match p.kind() {
            "operator_definition" => {
                // `name:` is the callable declaration; every repeated
                // `parameter:` field is a function-wide lexical binder.
                return any_field_contains_node(p, "parameter", node);
            }
            "function_definition" | "bounded_quantification" => {
                // `F[x \in S] == ...`: only quantifier_bound.intro binds.
                let mut bound = node.parent();
                while let Some(b) = bound {
                    if b == p {
                        break;
                    }
                    if b.kind() == "quantifier_bound" {
                        return any_field_contains_node(b, "intro", node);
                    }
                    bound = b.parent();
                }
                return false;
            }
            "unbounded_quantification" => {
                return any_field_contains_node(p, "intro", node);
            }
            _ => {}
        }
        parent = p.parent();
    }
    false
}

fn is_cobol_move_destination(node: tree_sitter::Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        if p.kind() == "move_statement" {
            if field_contains_node(p, "destination", node) || field_contains_node(p, "target", node)
            {
                return true;
            }
            let count = p.named_child_count();
            return count > 1 && named_child_contains(p, count - 1, node);
        }
        parent = p.parent();
    }
    false
}

#[allow(dead_code)] // consumed by the unified-walk handler when it lands
fn is_perl_lexical_declaration_binding(node: tree_sitter::Node<'_>) -> bool {
    // Perl permits repeated `variables:` fields for `my ($a, $b)`.
    let mut parent = node.parent();
    while let Some(p) = parent {
        match p.kind() {
            "variable_declaration" => return any_field_contains_node(p, "variables", node),
            "assignment_expression" => return false,
            _ => {}
        }
        parent = p.parent();
    }
    false
}

#[allow(dead_code)] // consumed by the unified-walk handler when it lands
fn is_cmake_function_parameter(node: tree_sitter::Node<'_>) -> bool {
    if node.kind() != "unquoted_argument" {
        return false;
    }
    let Some(argument) = node.parent() else {
        return false;
    };
    let Some(arguments) = argument.parent() else {
        return false;
    };
    let Some(command) = arguments.parent() else {
        return false;
    };
    if argument.kind() != "argument"
        || arguments.kind() != "argument_list"
        || !matches!(command.kind(), "function_command" | "macro_command")
    {
        return false;
    }
    let count = arguments.named_child_count();
    for i in 1..count {
        if let Some(c) = arguments.named_child(i) {
            if node_contains(c, node) {
                return true;
            }
        }
    }
    false
}

#[allow(dead_code)] // consumed by the unified-walk handler when it lands
fn is_tcl_procedure_parameter(node: tree_sitter::Node<'_>) -> bool {
    let Some(argument) = node.parent() else {
        return false;
    };
    if argument.kind() != "argument" || !any_field_contains_node(argument, "name", node) {
        return false;
    }
    let Some(arguments) = argument.parent() else {
        return false;
    };
    let Some(procedure) = arguments.parent() else {
        return false;
    };
    arguments.kind() == "arguments"
        && procedure.kind() == "procedure"
        && any_field_contains_node(procedure, "arguments", node)
}

#[allow(dead_code)] // consumed by the unified-walk handler when it lands
fn cfml_argument_tag_name_binding(node: tree_sitter::Node<'_>, source: &str) -> bool {
    if node.kind() != "attribute_value" {
        return false;
    }
    let Some(quoted) = node.parent() else {
        return false;
    };
    let Some(attribute) = quoted.parent() else {
        return false;
    };
    if attribute.kind() != "cf_attribute" {
        return false;
    }
    let Some(attribute_name) = crate::fqn::find_child_by_kind(attribute, "cf_attribute_name")
    else {
        return false;
    };
    if !crate::fqn::node_text(attribute_name, source).eq_ignore_ascii_case("name") {
        return false;
    }
    let Some(tag) = attribute.parent() else {
        return false;
    };
    if tag.kind() != "cf_selfclose_tag" {
        return false;
    }
    let tag_text = crate::fqn::node_text(tag, source);
    const ARGUMENT_TAG: &str = "<cfargument";
    if !tag_text
        .get(..ARGUMENT_TAG.len())
        .map(|p| p.eq_ignore_ascii_case(ARGUMENT_TAG))
        .unwrap_or(false)
    {
        return false;
    }
    let mut parent = tag.parent();
    while let Some(p) = parent {
        if p.kind() == "cf_function_tag" {
            return true;
        }
        parent = p.parent();
    }
    false
}

#[allow(dead_code)] // consumed by the unified-walk handler when it lands
fn is_exact_language_binding(node: tree_sitter::Node<'_>, lang: Language, source: &str) -> bool {
    let kind = node.kind();
    match lang {
        Language::OCAML => {
            if kind != "value_pattern" {
                return false;
            }
            node.parent()
                .map(|p| p.kind() == "parameter" && field_contains_node(p, "pattern", node))
                .unwrap_or(false)
        }
        Language::SCSS => {
            // crates.io grammar wraps parameters in `variable`; the vendored
            // one used `variable_name`. Accept both.
            if kind != "variable_name" && kind != "variable" {
                return false;
            }
            node.parent()
                .map(|p| p.kind() == "parameter")
                .unwrap_or(false)
        }
        Language::FORM => {
            if kind != "parameter" {
                return false;
            }
            node.parent()
                .map(|p| p.kind() == "parameter_list")
                .unwrap_or(false)
        }
        Language::FUNC => {
            if kind != "parameter" {
                return false;
            }
            node.parent()
                .map(|p| {
                    p.kind() == "parameter_declaration" && field_contains_node(p, "name", node)
                })
                .unwrap_or(false)
        }
        Language::PERL => is_perl_lexical_declaration_binding(node),
        Language::CMAKE => is_cmake_function_parameter(node),
        Language::TCL => is_tcl_procedure_parameter(node),
        Language::CFML => cfml_argument_tag_name_binding(node, source),
        Language::FISH => false, // needs WalkState occurrence cursor (lands with the unified walk)
        _ => false,
    }
}

fn ancestor_field_binds(
    node: tree_sitter::Node<'_>,
    container_kind: &str,
    fields: &[&str],
) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        if p.kind() == container_kind {
            return fields.iter().any(|f| any_field_contains_node(p, f, node));
        }
        parent = p.parent();
    }
    false
}

fn is_erlang_clause_binding(node: tree_sitter::Node<'_>) -> bool {
    ancestor_field_binds(node, "function_clause", &["args"])
}

fn is_nix_function_binding(node: tree_sitter::Node<'_>) -> bool {
    // tree-sitter-nix names a simple `x: body` binder `universal`;
    // destructuring uses the distinct `formals` field.
    ancestor_field_binds(node, "function_expression", &["universal", "formals"])
}

fn is_lean_binder_name(node: tree_sitter::Node<'_>) -> bool {
    const BINDER_KINDS: &[&str] = &["explicit_binder", "implicit_binder", "instance_binder"];
    let mut parent = node.parent();
    while let Some(p) = parent {
        if BINDER_KINDS.contains(&p.kind()) {
            return any_field_contains_node(p, "name", node);
        }
        parent = p.parent();
    }
    false
}

fn is_pascal_proc_binding(node: tree_sitter::Node<'_>) -> bool {
    ancestor_field_binds(node, "declProc", &["args"])
        || ancestor_field_binds(node, "defProc", &["args"])
}

fn is_teal_function_binding(node: tree_sitter::Node<'_>) -> bool {
    let mut arguments: Option<tree_sitter::Node<'_>> = None;
    let mut current = node.parent();
    while let Some(p) = current {
        if arguments.is_none() && p.kind() == "arguments" {
            arguments = Some(p);
            current = p.parent();
            continue;
        }
        match p.kind() {
            "function_signature" => {
                return any_field_contains_node(p, "arguments", node);
            }
            "function_statement" => {
                let Some(args) = arguments else { return false };
                return p
                    .child_by_field_name("signature")
                    .map(|sig| node_contains(sig, args))
                    .unwrap_or(false);
            }
            _ => {}
        }
        current = p.parent();
    }
    false
}

fn is_commonlisp_defun_binding(node: tree_sitter::Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        if p.kind() == "defun_header" {
            return field_contains_node(p, "function_name", node)
                || field_contains_node(p, "lambda_list", node);
        }
        parent = p.parent();
    }
    false
}

fn is_hcl_attribute_binding(node: tree_sitter::Node<'_>) -> bool {
    // HCL's attribute production exposes no fields: first named child is the
    // key, second is the expression.
    let mut parent = node.parent();
    while let Some(p) = parent {
        if p.kind() == "attribute" {
            return named_child_contains(p, 0, node);
        }
        parent = p.parent();
    }
    false
}

fn is_matlab_argument_binding(node: tree_sitter::Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        if matches!(p.kind(), "function_arguments" | "lambda_arguments") {
            return true;
        }
        parent = p.parent();
    }
    false
}

fn is_vhdl_interface_binding(node: tree_sitter::Node<'_>) -> bool {
    const INTERFACE_KINDS: &[&str] = &[
        "interface_constant_declaration",
        "interface_signal_declaration",
        "interface_variable_declaration",
        "interface_declaration",
    ];
    let mut parent = node.parent();
    while let Some(p) = parent {
        if INTERFACE_KINDS.contains(&p.kind()) {
            // Every interface production starts with its identifier_list.
            return named_child_contains(p, 0, node);
        }
        parent = p.parent();
    }
    false
}

fn is_pine_function_binding(node: tree_sitter::Node<'_>) -> bool {
    ancestor_field_binds(node, "function_declaration_statement", &["argument"])
}

/// Pkl declares names positionally: each container holds its declared name
/// as named child 0; annotations, defaults, and bodies follow and stay
/// reads. Resolved against the NEAREST container (C
/// is_pkl_declaration_binding).
fn is_pkl_declaration_binding(node: tree_sitter::Node<'_>) -> bool {
    const DECLARATION_KINDS: &[&str] = &[
        "methodHeader",
        "typedIdentifier",
        "classProperty",
        "objectProperty",
        "clazz",
        "typeAlias",
    ];
    let mut parent = node.parent();
    while let Some(p) = parent {
        if DECLARATION_KINDS.contains(&p.kind()) {
            return named_child_contains(p, 0, node);
        }
        parent = p.parent();
    }
    false
}

/// Dispatch the per-language policy binding rules (C is_policy_binding).
pub fn is_policy_binding(node: tree_sitter::Node<'_>, lang: Language, source: &str) -> bool {
    match occurrence_spec(lang).policy {
        OccurrencePolicy::LispDef => is_lisp_def_binding(node, lang, source),
        OccurrencePolicy::CommonlispDefun => is_commonlisp_defun_binding(node),
        OccurrencePolicy::FennelFn => is_fennel_fn_binding(node, source),
        OccurrencePolicy::ElixirDef => is_elixir_def_binding(node, source),
        OccurrencePolicy::JuliaFunction => is_first_named_part_of(node, "function_definition"),
        OccurrencePolicy::WolframSet => is_wolfram_lhs(node),
        OccurrencePolicy::TypstLet => is_first_named_part_of(node, "let"),
        OccurrencePolicy::AgdaFunction => {
            let mut parent = node.parent();
            while let Some(p) = parent {
                if p.kind() == "lhs" {
                    return true;
                }
                parent = p.parent();
            }
            false
        }
        OccurrencePolicy::TlaplusOperator => is_tlaplus_binding(node),
        OccurrencePolicy::CobolMove => is_cobol_move_destination(node),
        OccurrencePolicy::HclAttribute => is_hcl_attribute_binding(node),
        OccurrencePolicy::ElmValue => is_first_named_part_of(node, "value_declaration"),
        OccurrencePolicy::RescriptLet => is_first_named_part_of(node, "let_binding"),
        OccurrencePolicy::PurescriptLhs => is_first_named_part_of(node, "function"),
        OccurrencePolicy::NickelLet => {
            is_first_named_part_of(node, "let_binding")
                || is_first_named_part_of(node, "pattern_fun")
        }
        OccurrencePolicy::ErlangClause => is_erlang_clause_binding(node),
        OccurrencePolicy::NixFunction => is_nix_function_binding(node),
        OccurrencePolicy::MatlabArguments => is_matlab_argument_binding(node),
        OccurrencePolicy::LeanBinder => is_lean_binder_name(node),
        OccurrencePolicy::PascalProc => is_pascal_proc_binding(node),
        OccurrencePolicy::TealFunction => is_teal_function_binding(node),
        OccurrencePolicy::VhdlInterface => is_vhdl_interface_binding(node),
        OccurrencePolicy::PineFunction => is_pine_function_binding(node),
        OccurrencePolicy::PklDeclaration => is_pkl_declaration_binding(node),
        OccurrencePolicy::LlvmFunction => {
            let mut parent = node.parent();
            while let Some(p) = parent {
                if p.kind() == "function_header" {
                    return field_contains_node(p, "arguments", node);
                }
                parent = p.parent();
            }
            false
        }
        OccurrencePolicy::Standard => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_env_accesses::ExtractCtx;

    fn run(lang: Language, src: &str, rel: &str) -> Vec<Usage> {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", rel);
        let spec = crate::lang_specs::lang_spec(lang);
        extract_usages(&mut ctx, spec);
        ctx.result.usages
    }

    #[test]
    fn python_identifier_usages() {
        let src = "def f(alpha):\n    return beta + alpha\n";
        let usages = run(Language::PYTHON, src, "a.py");
        let names: Vec<&str> = usages.iter().map(|u| u.ref_name.as_str()).collect();
        // `alpha` is a parameter binding; `beta` is a free read. The return
        // site also reads `alpha` — C emits it (binding only suppresses the
        // binding occurrence itself, not later reads).
        assert!(names.contains(&"beta"), "{usages:?}");
        assert_eq!(
            names.iter().filter(|n| **n == "alpha").count(),
            1,
            "binding suppressed, return-read emitted — {usages:?}"
        );
        assert!(usages.iter().all(|u| u.enclosing_func_qn == "proj.a.f"));
    }

    #[test]
    fn keywords_filtered() {
        let src = "def f(x):\n    return True and x\n";
        let usages = run(Language::PYTHON, src, "a.py");
        let names: Vec<&str> = usages.iter().map(|u| u.ref_name.as_str()).collect();
        assert!(!names.contains(&"True"), "{usages:?}");
        assert!(!names.contains(&"and"));
        assert!(names.contains(&"x"));
    }

    #[test]
    fn assignments_are_writes_not_usages() {
        let src = "def f():\n    value = compute()\n    return value\n";
        let usages = run(Language::PYTHON, src, "a.py");
        let names: Vec<&str> = usages.iter().map(|u| u.ref_name.as_str()).collect();
        // `value = ...` binds (no usage); `return value` is a free READ →
        // one usage; `compute()` is inside a call → skipped by the
        // standalone walker (calls handled by extract_calls).
        let value_uses = names.iter().filter(|n| **n == "value").count();
        assert_eq!(value_uses, 1, "only the return-site read — {usages:?}");
        assert!(!names.contains(&"compute"), "inside call");
    }

    #[test]
    fn probe_go_chain() {
        let src = "package app\nvar cfg = config.Load()\n";
        let tree = crate::ts::parse(Language::GO, src).unwrap();
        let mut stack = vec![tree.root_node()];
        while let Some(n) = stack.pop() {
            if n.kind() == "identifier" && crate::fqn::node_text(n, src) == "cfg" {
                let mut cur = n;
                while let Some(p) = cur.parent() {
                    let field = field_name_for_node(p, cur);
                    eprintln!("DBG climb parent={} field={:?}", p.kind(), field);
                    cur = p;
                }
            }
            for i in 0..n.child_count() {
                stack.push(n.child(i).unwrap());
            }
        }
    }

    #[test]
    fn go_field_and_package_refs() {
        let src = "package app\nvar cfg = config.Load()\n";
        let usages = run(Language::GO, src, "a.go");
        let names: Vec<&str> = usages.iter().map(|u| u.ref_name.as_str()).collect();
        // `app` is the package_identifier of the package clause; `cfg` is
        // an ordinary USAGE (the C climb finds no binding container: GO's
        // var_declaration exposes no name field). config.Load is inside a
        // call → skipped by the standalone walker.
        assert!(names.contains(&"app"), "{usages:?}");
        assert!(
            names.contains(&"cfg"),
            "C parity: var cfg is a USAGE — {usages:?}"
        );
        assert!(!names.contains(&"config"));
        assert!(!names.contains(&"Load"));
    }

    #[test]
    fn call_interior_skipped() {
        let src = "def f():\n    handler(inner_fn)\n";
        let usages = run(Language::PYTHON, src, "a.py");
        let names: Vec<&str> = usages.iter().map(|u| u.ref_name.as_str()).collect();
        // Both handler and inner_fn are inside the call subtree.
        assert!(!names.contains(&"handler"), "{usages:?}");
        assert!(!names.contains(&"inner_fn"));
    }

    #[test]
    fn augmented_assign_is_read_not_usage() {
        // `total += 1` — the write classifier's read_write barrier keeps
        // `total` out of standalone usages (it's a binding read+write).
        let src = "def f():\n    total = 0\n    total += 1\n";
        let usages = run(Language::PYTHON, src, "a.py");
        let names: Vec<&str> = usages.iter().map(|u| u.ref_name.as_str()).collect();
        assert!(!names.contains(&"total"), "{usages:?}");
    }

    #[test]
    fn callable_value_stamp_js() {
        // `register(callback)` — callback is a direct argument value; JS
        // identifiers get a candidate stamp only for member shapes, so a
        // bare identifier stays unstamped (may_be_call_reference=false).
        let src = "function f() { register(callback); }\n";
        let usages = run(Language::JAVASCRIPT, src, "a.js");
        assert!(
            usages.is_empty() || usages.iter().all(|u| !u.may_be_call_reference),
            "{usages:?}"
        );
    }

    // ── Occurrence policy binding rules ──

    #[test]
    fn occurrence_spec_table_covers_languages() {
        let s = occurrence_spec(Language::SQL);
        assert_eq!(s.whole_binding_nodes, SQL_BINDING_NODES);
        assert_eq!(s.policy, OccurrencePolicy::Standard);
        assert!(occurrence_spec(Language::CLOJURE).policy == OccurrencePolicy::LispDef);
        assert!(occurrence_spec(Language::PUPPET).first_named_child_is_write);
        assert!(occurrence_spec(Language::MESON).write_nodes == MESON_WRITE_NODES);
        // Unlisted languages fall back to the shared STANDARD spec.
        assert!(occurrence_spec(Language::GO).policy == OccurrencePolicy::Standard);
        assert!(occurrence_spec(Language::GO).whole_binding_nodes.is_empty());
    }

    #[test]
    fn policy_binding_lisp_forms() {
        // Clojure defn: head + name bind, body doesn't.
        let src = "(defn greet [x] (+ x 1))\n";
        let tree = crate::ts::parse(Language::CLOJURE, src).unwrap();
        // BFS (FIFO): the first occurrence in document order — a LIFO stack
        // would find the BODY's `x` (a genuine read) before the parameter.
        let find = |text: &str| {
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(tree.root_node());
            while let Some(n) = queue.pop_front() {
                if crate::fqn::node_text(n, src) == text {
                    return n;
                }
                for i in 0..n.child_count() {
                    if let Some(c) = n.child(i) {
                        queue.push_back(c);
                    }
                }
            }
            panic!("node not found: {text}");
        };
        let greet = find("greet");
        let x_param = find("x");
        assert!(
            is_policy_binding(greet, Language::CLOJURE, src),
            "name binds"
        );
        assert!(
            is_policy_binding(x_param, Language::CLOJURE, src),
            "param vector member binds (clojure binds child 2)"
        );
        // The `+` head of the body list is NOT a def binding.
        let plus = find("+");
        assert!(!is_policy_binding(plus, Language::CLOJURE, src));
    }

    #[test]
    fn policy_binding_hcl_attribute_key() {
        let src = "resource \"a\" \"b\" {\n  name = \"x\"\n}\n";
        let tree = crate::ts::parse(Language::HCL, src).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut key_node = None;
        while let Some(n) = stack.pop() {
            if n.kind() == "attribute" {
                key_node = n.named_child(0);
                break;
            }
            for i in 0..n.child_count() {
                if let Some(c) = n.child(i) {
                    stack.push(c);
                }
            }
        }
        let key = key_node.expect("hcl attribute key");
        assert!(is_policy_binding(key, Language::HCL, src));
    }

    #[test]
    fn policy_binding_matlab_arguments() {
        let src = "function out = f(a, b)\nend\n";
        let tree = crate::ts::parse(Language::MATLAB, src).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut arg_node = None;
        while let Some(n) = stack.pop() {
            if n.kind() == "identifier" && crate::fqn::node_text(n, src) == "a" {
                arg_node = Some(n);
                break;
            }
            for i in 0..n.child_count() {
                if let Some(c) = n.child(i) {
                    stack.push(c);
                }
            }
        }
        let a = arg_node.expect("matlab param");
        assert!(is_policy_binding(a, Language::MATLAB, src));
    }

    #[test]
    fn exact_language_binding_scss_parameter() {
        let src = "@mixin m($x) {\n  color: $x;\n}\n";
        let tree = crate::ts::parse(Language::SCSS, src).unwrap();
        // crates.io grammar: `variable` nodes carry "$x" (vendored used
        // `variable_name`).
        let find_under = |inside: &str| {
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(tree.root_node());
            while let Some(n) = queue.pop_front() {
                if n.kind() == "variable"
                    && crate::fqn::node_text(n, src) == "$x"
                    && n.parent().map(|p| p.kind() == inside).unwrap_or(false)
                {
                    return n;
                }
                for i in 0..n.child_count() {
                    if let Some(c) = n.child(i) {
                        queue.push_back(c);
                    }
                }
            }
            panic!("variable not found under {inside}");
        };
        let param = find_under("parameter");
        assert!(is_exact_language_binding(param, Language::SCSS, src));
        // The body read is NOT a binding.
        let body = find_under("declaration");
        assert!(!is_exact_language_binding(body, Language::SCSS, src));
    }
}
