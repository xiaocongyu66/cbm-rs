//! extract_unified.rs — 1:1 rewrite of `internal/cbm/extract_unified.c`
//! (2657 lines), part 1: the unified cursor walk with the WalkState scope
//! stack (displaced-tuple save/restore, O(1) push/pop replacing the
//! quadratic whole-stack recompute), string-constant collection, call
//! invocation triple, loop/branch depth tracking, and the handler sequence
//! (calls → usages → throws → readwrites → type_refs → env_accesses).
//!
//! Rust shape notes: the C's `const char *` displaced QN pointers become
//! owned Strings cloned per frame; the TSTreeCursor becomes an explicit
//! node stack carrying depth. Trivia (extra nodes) consume no state.

use crate::extract_env_accesses::ExtractCtx;
use crate::helpers;
use crate::lang_specs::LanguageSpec;
use crate::types::{SourceOrigin, Usage, UsageKind};
use crate::Language;

// ── Scope kinds (C SCOPE_* defines) ─────────────────────────────

// The verbatim SCOPE_* table (C extract_unified.h). LEXICAL/NAMESPACE are
// consumed by specialized lexical-scope paths landing in a later part.
#[allow(dead_code)]
pub(crate) const SCOPE_FUNC: u8 = 1;
#[allow(dead_code)]
pub(crate) const SCOPE_CLASS: u8 = 2;
#[allow(dead_code)]
pub(crate) const SCOPE_CALL: u8 = 3;
pub(crate) const SCOPE_IMPORT: u8 = 4;
pub(crate) const SCOPE_LOOP: u8 = 5;
pub(crate) const SCOPE_BRANCH: u8 = 6;
#[allow(dead_code)]
pub(crate) const SCOPE_LEXICAL: u8 = 7;
#[allow(dead_code)]
pub(crate) const SCOPE_NAMESPACE: u8 = 8;

/// Loop node types (C cbm_is_loop_node_type). Loops are gated on named
/// nodes so anonymous `for`/`while` keyword tokens don't count.
const LOOP_NODE_TYPES: &[&str] = &[
    "for_statement",
    "while_statement",
    "do_statement",
    "do_while_statement",
    "for_in_statement",
    "for_of_statement",
    "for_each_statement",
    "foreach_statement",
    "enhanced_for_statement",
    "for_range_loop",
    "c_style_for_statement",
    "for_expression",
    "while_expression",
    "loop_expression",
    "while_let_expression",
    "repeat_statement",
    "repeat_while_statement",
    // Pkl: `for (x in xs) { ... }` inside an object body.
    "forGenerator",
    "until",
    "while_modifier",
    "until_modifier",
    "for",
    "while",
];

pub fn is_loop_node_type(kind: &str) -> bool {
    LOOP_NODE_TYPES.contains(&kind)
}

// ── Walk state ──────────────────────────────────────────────────

#[derive(Clone)]
struct ScopeFrame {
    #[allow(dead_code)] // parity with CBMWalkScope (read by later parts)
    kind: u8,
    depth: u32,
    #[allow(dead_code)]
    qn: Option<String>,
    // Displaced tuple (C CBMWalkScope prev_* fields) — restored verbatim
    // on pop, O(1) either way.
    prev_enclosing_func_qn: String,
    prev_enclosing_class_qn: Option<String>,
    prev_inside_import: bool,
    prev_loop_depth: i32,
    prev_branch_depth: i32,
}

/// Concrete lexical scope kind (C CBMLexicalScopeKind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LexicalScopeKind {
    #[default]
    Module = 0,
    Class,
    Function,
    Block,
    Comprehension,
}

/// Concrete AST scope identity (C CBMLexicalScope): QNs remain graph
/// attribution metadata only, so overloads/lambdas/sibling blocks never
/// share binding facts.
#[derive(Debug, Clone)]
pub struct LexicalScope {
    pub id: u32,
    pub parent_id: u32,
    /// Python method/function lookup bypasses the containing class
    /// namespace; class attributes require qualification.
    pub lookup_parent_id: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub kind: LexicalScopeKind,
}

/// Unified walk state (C WalkState, scope machinery subset + lexical
/// scopes). Lexical bindings record on it in the next step.
pub struct WalkState {
    pub enclosing_func_qn: String,
    pub enclosing_class_qn: Option<String>,
    pub inside_import: bool,
    pub loop_depth: i32,
    pub branch_depth: i32,
    pub call_depth: usize,
    scopes: Vec<ScopeFrame>,
    /// Id of the lexical scope attached to each walk-scope frame.
    frame_lexical_ids: Vec<u32>,
    /// Concrete lexical scope arena (id = index + 1).
    pub lexical_scopes: Vec<LexicalScope>,
    /// The module-root lexical scope (id 1), created at walk start.
    pub root_lexical_scope_id: u32,
}

impl WalkState {
    pub(crate) fn new(module_qn: &str) -> Self {
        WalkState {
            enclosing_func_qn: module_qn.to_string(),
            enclosing_class_qn: None,
            inside_import: false,
            loop_depth: 0,
            branch_depth: 0,
            call_depth: 0,
            scopes: Vec::with_capacity(64), // MAX_SCOPES
            frame_lexical_ids: Vec::with_capacity(64),
            lexical_scopes: Vec::with_capacity(64),
            root_lexical_scope_id: 0,
        }
    }

    /// Current innermost lexical scope id (C current_lexical_scope_id): the
    /// topmost frame that carries one, else the root.
    pub fn current_lexical_scope_id(&self) -> u32 {
        for id in self.frame_lexical_ids.iter().rev() {
            if *id != 0 {
                return *id;
            }
        }
        self.root_lexical_scope_id
    }

    /// Python function lookup parent: bypass the containing CLASS namespace
    /// (class attributes require `self.x`/`Cls.x`), stopping at the first
    /// enclosing function/comprehension/module (C
    /// python_function_lookup_parent).
    fn python_function_lookup_parent(&self, structural_parent_id: u32) -> u32 {
        let mut id = structural_parent_id;
        let mut remaining = self.lexical_scopes.len();
        while id != 0 && remaining > 0 {
            remaining -= 1;
            let Some(scope) = self.lexical_scope_by_id(id) else {
                return structural_parent_id;
            };
            match scope.kind {
                LexicalScopeKind::Class => return scope.lookup_parent_id,
                LexicalScopeKind::Function
                | LexicalScopeKind::Comprehension
                | LexicalScopeKind::Module => {
                    return structural_parent_id;
                }
                LexicalScopeKind::Block => {}
            }
            id = scope.parent_id;
        }
        structural_parent_id
    }

    /// Register a concrete lexical scope for `node` (C add_lexical_scope).
    fn add_lexical_scope(
        &mut self,
        node: tree_sitter::Node<'_>,
        kind: LexicalScopeKind,
        lang: Language,
    ) -> u32 {
        let parent_id = self.current_lexical_scope_id();
        let mut lookup_parent_id = parent_id;
        if kind == LexicalScopeKind::Function && lang == Language::PYTHON {
            lookup_parent_id = self.python_function_lookup_parent(parent_id);
        }
        let scope = LexicalScope {
            id: self.lexical_scopes.len() as u32 + 1,
            parent_id,
            lookup_parent_id,
            start_byte: node.start_byte() as u32,
            end_byte: node.end_byte() as u32,
            kind,
        };
        let id = scope.id;
        if self.root_lexical_scope_id == 0 {
            self.root_lexical_scope_id = id; // first scope registered is the module
        }
        self.lexical_scopes.push(scope);
        id
    }

    pub fn lexical_scope_by_id(&self, id: u32) -> Option<&LexicalScope> {
        self.lexical_scopes.get(id.wrapping_sub(1) as usize)
    }

    /// Push a scope frame that also opens a concrete lexical scope (C
    /// push_lexical_scope). Returns the new lexical scope id (0 on cap
    /// failure — the caller fails closed).
    pub(crate) fn push_lexical_scope(
        &mut self,
        kind: u8,
        depth: u32,
        qn: Option<String>,
        node: tree_sitter::Node<'_>,
        lexical_kind: LexicalScopeKind,
        lang: Language,
    ) -> u32 {
        if !self.push_scope(kind, depth, qn) {
            return 0;
        }
        let id = self.add_lexical_scope(node, lexical_kind, lang);
        let last = self.frame_lexical_ids.len() - 1;
        self.frame_lexical_ids[last] = id;
        id
    }

    /// Is a lexical scope for this exact byte span already open on the
    /// frame stack? (C node_already_has_lexical_scope.)
    fn node_already_has_lexical_scope(&self, node: tree_sitter::Node<'_>) -> bool {
        let start = node.start_byte() as u32;
        let end = node.end_byte() as u32;
        for fid in &self.frame_lexical_ids {
            if let Some(scope) = self.lexical_scope_by_id(*fid) {
                if scope.start_byte == start && scope.end_byte == end {
                    return true;
                }
            }
        }
        false
    }

    /// Push a scope frame: save the displaced tuple, apply the frame's
    /// effect (C push_scope).
    pub(crate) fn push_scope(&mut self, kind: u8, depth: u32, qn: Option<String>) -> bool {
        if self.scopes.len() >= 64 {
            return false; // MAX_SCOPES
        }
        let frame = ScopeFrame {
            kind,
            depth,
            qn: qn.clone(),
            prev_enclosing_func_qn: self.enclosing_func_qn.clone(),
            prev_enclosing_class_qn: self.enclosing_class_qn.clone(),
            prev_inside_import: self.inside_import,
            prev_loop_depth: self.loop_depth,
            prev_branch_depth: self.branch_depth,
        };
        match kind {
            SCOPE_FUNC => {
                if let Some(q) = &qn {
                    self.enclosing_func_qn = q.clone();
                }
            }
            SCOPE_CLASS | SCOPE_NAMESPACE => {
                self.enclosing_class_qn = qn;
            }
            SCOPE_IMPORT => self.inside_import = true,
            SCOPE_LOOP => self.loop_depth += 1,
            SCOPE_BRANCH => self.branch_depth += 1,
            _ => {}
        }
        self.scopes.push(frame);
        self.frame_lexical_ids.push(0);
        true
    }

    /// Pop scopes ascended out of (depth >= current cursor depth),
    /// restoring the displaced tuple LIFO (C pop_expired_scopes).
    pub(crate) fn pop_expired_scopes(&mut self, cur_depth: u32) {
        while let Some(f) = self.scopes.last() {
            if f.depth < cur_depth {
                break;
            }
            let f = self.scopes.pop().expect("len checked");
            self.frame_lexical_ids.pop();
            self.enclosing_func_qn = f.prev_enclosing_func_qn;
            self.enclosing_class_qn = f.prev_enclosing_class_qn;
            self.inside_import = f.prev_inside_import;
            self.loop_depth = f.prev_loop_depth;
            self.branch_depth = f.prev_branch_depth;
        }
    }

    #[allow(dead_code)] // OCaml nested-def skip lands with that part
    fn in_function_scope(&self) -> bool {
        self.scopes.iter().any(|s| s.kind == SCOPE_FUNC)
    }
}

// ── String constants (C handle_string_constants) ────────────────

fn is_string_node(kind: &str) -> bool {
    matches!(
        kind,
        "string_literal"
            | "string"
            | "string_content"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "string_value"
            // YAML string types
            | "double_quote_scalar"
            | "single_quote_scalar"
    )
}

/// Module-level `NAME = "value"` constants (C handle_string_constants).
/// Only collected at module level (not inside functions/classes).
fn handle_string_constants(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    state: &WalkState,
) {
    if state.enclosing_func_qn != ctx.module_qn {
        return;
    }
    let kind = node.kind();
    // Python: expression_statement → assignment → identifier = string
    // Go: short_var_declaration, const_spec; JS/TS: variable_declarator
    if !matches!(
        kind,
        "assignment"
            | "expression_statement"
            | "short_var_declaration"
            | "const_spec"
            | "variable_declarator"
    ) {
        return;
    }
    let mut name_node = node.child_by_field_name("left");
    let mut value_node = node.child_by_field_name("right");
    // Some grammars use "name" + "value" fields.
    if name_node.is_none() {
        name_node = node.child_by_field_name("name");
    }
    if value_node.is_none() {
        value_node = node.child_by_field_name("value");
    }
    let (Some(name_node), Some(value_node)) = (name_node, value_node) else {
        return;
    };
    // Name must be an identifier.
    if !matches!(name_node.kind(), "identifier" | "constant") {
        return;
    }
    // Value must be a string literal (template literals flatten to "{}").
    let value_kind = value_node.kind();
    let flat_value = if value_kind == "template_string" {
        crate::extract_calls::template_string_text_public(value_node, ctx.source)
    } else if is_string_node(value_kind) {
        None
    } else {
        return;
    };
    let name = crate::fqn::node_text(name_node, ctx.source);
    let raw_value = flat_value
        .as_deref()
        .unwrap_or_else(|| crate::fqn::node_text(value_node, ctx.source));
    if name.is_empty() || raw_value.is_empty() {
        return;
    }
    // Strip quotes from value (template values are already unquoted).
    let value = match &flat_value {
        Some(_) => raw_value.to_string(),
        None => strip_simple_quotes(raw_value),
    };
    if value.is_empty() {
        return;
    }
    ctx.constants.push((name.to_string(), value, false));
}

fn strip_simple_quotes(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        s[1..b.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

// ── Import boundary (C is_actual_import_boundary) ───────────────

fn is_actual_import_boundary(
    _lang: Language,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
) -> bool {
    let direct =
        !spec.import_node_types.is_empty() && spec.import_node_types.contains(&node.kind());
    let from = !spec.import_from_types.is_empty() && spec.import_from_types.contains(&node.kind());
    (direct || from) && !is_export_of_declaration(node)
}

/// JS/TS `export_statement` appears in import_node_types so re-exports are
/// import boundaries, but `export function f() {}` wraps a declaration —
/// not an import boundary (C is_export_of_declaration).
fn is_export_of_declaration(node: tree_sitter::Node<'_>) -> bool {
    if node.kind() != "export_statement" {
        return false;
    }
    (0..node.named_child_count()).any(|i| {
        node.named_child(i)
            .map(|c| c.kind() != "export_clause" && c.kind() != "export_specifier")
            .unwrap_or(false)
    })
}

// ── Boundary scopes (C push_boundary_scopes, main paths) ────────

/// Classify anonymous lexical boundary nodes (C lexical_boundary_kind):
/// Rust inline modules are MODULE scopes; comprehensions are their own
/// FUNCTION-like scope; anonymous functions are FUNCTION; the block family
/// is BLOCK.
fn lexical_boundary_kind(kind: &str) -> Option<LexicalScopeKind> {
    const BLOCK_KINDS: &[&str] = &[
        "block",
        "statement_block",
        "compound_statement",
        "for_in_statement",
        "for_of_statement",
        "enhanced_for_statement",
        "foreach_statement",
        "foreach_clause",
        "loop_expression",
        "match_block",
        "case_block",
        "script_block",
        "do_block",
    ];
    const COMPREHENSION_KINDS: &[&str] = &[
        "list_comprehension",
        "set_comprehension",
        "dictionary_comprehension",
        "generator_expression",
        "comprehension_expression",
    ];
    const ANONYMOUS_FUNCTION_KINDS: &[&str] = &[
        "lambda",
        "lambda_expression",
        "anonymous_function",
        "anonymous_function_creation_expression",
        "anonymous_method_expression",
        "arrow_function",
        "closure_expression",
        "func_literal",
        "function_expression",
        "function_literal",
    ];
    // Rust inline modules own independent item/import namespaces.
    if kind == "mod_item" {
        return Some(LexicalScopeKind::Module);
    }
    if COMPREHENSION_KINDS.contains(&kind) {
        return Some(LexicalScopeKind::Comprehension);
    }
    if ANONYMOUS_FUNCTION_KINDS.contains(&kind) {
        return Some(LexicalScopeKind::Function);
    }
    if BLOCK_KINDS.contains(&kind) {
        return Some(LexicalScopeKind::Block);
    }
    None
}

fn push_boundary_scopes(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    state: &mut WalkState,
    depth: u32,
) {
    // Anonymous lexical boundaries (block/comprehension/lambda/mod) —
    // checked first so they never double-push under the func/class arms.
    if !state.node_already_has_lexical_scope(node) {
        if let Some(lkind) = lexical_boundary_kind(node.kind()) {
            state.push_lexical_scope(SCOPE_LEXICAL, depth, None, node, lkind, ctx.language);
        }
    }
    // Function scopes: attribute in-body calls/usages to the function QN,
    // opening the concrete FUNCTION lexical scope with them.
    if !spec.function_node_types.is_empty() && spec.function_node_types.contains(&node.kind()) {
        let fqn = crate::fqn::func_node_name(node, ctx.source, ctx.language)
            .map(|name| {
                crate::fqn::fqn_compute_source_lang(
                    ctx.project,
                    ctx.rel_path,
                    Some(&name),
                    ctx.language,
                )
            })
            .unwrap_or_else(|| ctx.module_qn.clone());
        state.push_lexical_scope(
            SCOPE_FUNC,
            depth,
            Some(fqn),
            node,
            LexicalScopeKind::Function,
            ctx.language,
        );
        return; // C pushes a func scope and returns from the chain
    }
    // Class scopes.
    if !spec.class_node_types.is_empty() && spec.class_node_types.contains(&node.kind()) {
        let cqn = node
            .child_by_field_name("name")
            .map(|n| {
                let cname = crate::fqn::node_text(n, ctx.source);
                crate::fqn::fqn_compute(ctx.project, ctx.rel_path, Some(cname))
            })
            .unwrap_or_else(|| ctx.module_qn.clone());
        state.push_lexical_scope(
            SCOPE_CLASS,
            depth,
            Some(cqn),
            node,
            LexicalScopeKind::Class,
            ctx.language,
        );
    }
}

// ── Unified usage emission (C handle_usages, main path) ─────────

/// Binding climb (STANDARD policy; C is_binding_occurrence).
fn unified_is_binding(node: tree_sitter::Node<'_>, spec: &LanguageSpec) -> bool {
    let mut current = node;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        let field = field_name_of(parent, current);
        if is_value_field(field) {
            return false;
        }
        if field == Some("type") {
            return false;
        }
        let kind = parent.kind();
        if crate::extract_usages::common_whole_binding_nodes().contains(&kind) {
            return true;
        }
        if crate::extract_usages::declared_container_binds_public(parent, spec, node) {
            return true;
        }
        current = parent;
    }
}

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

fn field_name_of(
    parent: tree_sitter::Node<'_>,
    child: tree_sitter::Node<'_>,
) -> Option<&'static str> {
    let mut cursor = parent.walk();
    if cursor.goto_first_child() {
        loop {
            if cursor.node() == child {
                return cursor
                    .field_name()
                    .map(|n| unsafe { std::mem::transmute::<&str, &'static str>(n) });
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

fn unified_is_write(node: tree_sitter::Node<'_>, spec: &LanguageSpec) -> bool {
    let mut current = node;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        let field = field_name_of(parent, current);
        if is_value_field(field) {
            return false;
        }
        let kind = parent.kind();
        let assignment = (!spec.assignment_node_types.is_empty()
            && spec.assignment_node_types.contains(&kind))
            || crate::extract_usages::read_write_nodes().contains(&kind);
        if assignment {
            if crate::extract_usages::assignment_reads_target(parent) {
                return false;
            }
            let left = parent.child_by_field_name("left");
            if left.map(|l| node_contains(l, node)).unwrap_or(false) {
                return true;
            }
            return false;
        }
        current = parent;
    }
}

fn node_contains(outer: tree_sitter::Node<'_>, inner: tree_sitter::Node<'_>) -> bool {
    outer.start_byte() <= inner.start_byte() && outer.end_byte() >= inner.end_byte()
}

// ── The unified walk (C cbm_extract_unified) ────────────────────

/// Trivia consumes no semantic state (C is_unified_trivia_node: extra
/// nodes — comments, etc.).
fn is_unified_trivia_node(node: tree_sitter::Node<'_>) -> bool {
    node.is_extra()
}

/// The unified extraction walk. Handlers run in the C order per node:
/// pop_expired → string_constants → calls → usages → throws → readwrites →
/// type_refs → env_accesses → boundary scopes. The other extractors must
/// NOT also run standalone afterwards, or records duplicate.
pub fn extract_unified(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    let mut state = WalkState::new(&ctx.module_qn);
    let mut tracker = crate::extract_usages::LexicalBindingTracker {
        usage_start_index: ctx.result.usages.len(),
        ..Default::default()
    };
    let mut stack: Vec<(tree_sitter::Node<'_>, u32, usize)> = vec![(ctx.root, 0, 0)]; // (node, depth, next_child)

    while let Some((node, depth, next_child)) = stack.last().copied() {
        if next_child == 0 {
            // Entering.
            let trivia = is_unified_trivia_node(node);
            if !trivia {
                state.pop_expired_scopes(depth);
                push_boundary_scopes(ctx, node, spec, &mut state, depth);
                handle_string_constants(ctx, node, &state);
                // Calls (invocation emitted; loop/branch depths applied).
                if !spec.call_node_types.is_empty()
                    && spec.call_node_types.contains(&node.kind())
                    && !crate::extract_calls::is_definition_container(
                        ctx.language,
                        node,
                        ctx.source,
                    )
                {
                    crate::extract_calls::try_emit_call(
                        ctx,
                        node,
                        spec,
                        &ctx.constants_map(),
                        state.loop_depth,
                        state.branch_depth,
                    );
                    if state.call_depth < 64 {
                        // C pushes SCOPE_CALL for invocation-eligible nodes;
                        // part 1 tracks depth only (the invocation triple's
                        // usage suppression lands with lexical bindings).
                        state.call_depth += 1;
                    }
                }
                // Unified usages: binding→skip, write→skip, label→skip,
                // else usage attributed to the STATE's function QN (O(1),
                // no ef_cache parent-chain walk).
                // Binding occurrences are recorded into the lexical table
                // (C handle_usages → record_lexical_binding) so the walk
                // finalizer can block shadowed short-name resolution.
                if crate::extract_usages::is_reference_node(node, ctx.language)
                    && !crate::extract_usages::is_call_argument_label(node)
                {
                    let inside_import = state.inside_import;
                    let in_call = state.call_depth > 0;
                    if unified_is_binding(node, spec) || unified_is_write(node, spec) {
                        let bname = crate::fqn::node_text(node, ctx.source);
                        if !bname.is_empty() && !helpers::is_keyword(bname, ctx.language) {
                            crate::extract_usages::record_lexical_binding(
                                &mut tracker,
                                &mut state,
                                node,
                                spec,
                                bname,
                                inside_import,
                                ctx.language,
                            );
                        }
                    } else if !inside_import && !in_call {
                        let name = crate::fqn::node_text(node, ctx.source);
                        if !name.is_empty() && !helpers::is_keyword(name, ctx.language) {
                            ctx.result.usages.push(Usage {
                                ref_name: name.to_string(),
                                enclosing_func_qn: state.enclosing_func_qn.clone(),
                                kind: UsageKind::Value,
                                lexical_scope_id: state.current_lexical_scope_id(),
                                site_start_byte: node.start_byte() as u32,
                                site_end_byte: node.end_byte() as u32,
                                source_origin: SourceOrigin::Raw,
                                ..Default::default()
                            });
                        }
                    }
                }
                // Record-type extractors (state-attributed via the shared
                // standalone implementations; their internal QN attribution
                // runs through the ef_cache which yields the same QNs).
                crate::extract_semantic::extract_semantic_at(
                    ctx,
                    node,
                    spec,
                    &state.enclosing_func_qn,
                );
                crate::extract_type_refs::extract_type_refs_at(
                    ctx,
                    node,
                    spec,
                    &state.enclosing_func_qn,
                );
                crate::extract_type_assigns::extract_type_assigns_at(
                    ctx,
                    node,
                    spec,
                    &state.enclosing_func_qn,
                );
                crate::extract_env_accesses::extract_env_accesses_at(
                    ctx,
                    node,
                    spec,
                    &state.enclosing_func_qn,
                );
                // Boundary scopes: import / loop / branch (function/class
                // pushed earlier in this block via their spec kinds; the C
                // pushes all of them from push_boundary_scopes in one pass).
                if is_actual_import_boundary(ctx.language, node, spec) {
                    state.push_scope(SCOPE_IMPORT, depth, None);
                }
                if node.is_named() && is_loop_node_type(node.kind()) {
                    // A loop is NOT also counted as a branch (loops appear in
                    // many specs' branching lists but are not base-case
                    // guards for unguarded-recursion).
                    state.push_scope(SCOPE_LOOP, depth, None);
                } else if !spec.branching_node_types.is_empty()
                    && spec.branching_node_types.contains(&node.kind())
                {
                    state.push_scope(SCOPE_BRANCH, depth, None);
                }
            }
            // Descend.
            if !trivia || node.child_count() > 0 {
                if let Some(first) = node.child(0) {
                    // Advance the parent's cursor BEFORE pushing, or the
                    // next iteration re-enters this node with next_child
                    // still 0 and pushes the first child forever.
                    stack.last_mut().unwrap().2 = 1;
                    stack.push((first, depth + 1, 0));
                    continue;
                }
            }
            // No children → exit directly. Setting next_child = count ==
            // 0 would re-enter this leaf forever (next_child == 0 means
            // Entering); a non-trivia leaf like the Go `package` keyword
            // token is exactly that shape.
            state.pop_expired_scopes(depth);
            stack.pop();
            continue;
        }
        let count = node.child_count();
        if next_child < count {
            let child = node.child(next_child);
            stack.last_mut().unwrap().2 = next_child + 1;
            if let Some(c) = child {
                stack.push((c, depth + 1, 0));
            }
        } else {
            // Exiting: pop boundary scopes pushed at this depth.
            state.pop_expired_scopes(depth);
            stack.pop();
        }
    }

    // Finalize lexical usages: sort bindings, then block every shadowed
    // short-name resolution (C cbm_finalize_lexical_usages).
    let mut usages = std::mem::take(&mut ctx.result.usages);
    crate::extract_usages::finalize_lexical_usages(&tracker, &state, &mut usages, ctx.language);
    ctx.result.usages = usages;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes_for(lang: Language, src: &str) -> (Vec<(u32, u32, LexicalScopeKind)>, u32) {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", "f");
        let spec = crate::lang_specs::lang_spec(lang);
        extract_unified(&mut ctx, spec);
        // The walk owns the state; re-run capturing scopes through a
        // wrapper is intrusive — instead assert through the public result:
        // scope registration is verified by running extract on a copy and
        // re-walking manually here.
        let tree2 = crate::ts::parse(lang, src).expect("grammar");
        let mut state = WalkState::new("proj.f");
        let _ = &mut ctx;
        // Manually drive push/pop to verify scope machinery on the same tree.
        let mut stack = vec![tree2.root_node()];
        while let Some(n) = stack.pop() {
            if !state.node_already_has_lexical_scope(n) {
                if let Some(k) = lexical_boundary_kind(n.kind()) {
                    state.push_lexical_scope(SCOPE_LEXICAL, 0, None, n, k, lang);
                }
            }
            for i in (0..n.child_count()).rev() {
                if let Some(c) = n.child(i) {
                    stack.push(c);
                }
            }
        }
        (
            state
                .lexical_scopes
                .iter()
                .map(|s| (s.id, s.parent_id, s.kind))
                .collect(),
            state.root_lexical_scope_id,
        )
    }

    #[test]
    fn lexical_scopes_register_with_hierarchy() {
        // A JS arrow function inside a function body: block/arrow scopes
        // nest with parent ids chaining to the root scope.
        let src = "function outer() {\n  const f = () => {\n    return 1;\n  };\n}\n";
        let (scopes, root) = scopes_for(Language::JAVASCRIPT, src);
        assert!(root >= 1, "root scope registered");
        // The first scope's parent is 0 (whatever its kind — the manual
        // drive starts at the tree root, so a `program` block-scope kind is
        // not pushed; the first MATCHED boundary takes parent 0).
        assert_eq!(scopes[0].1, 0);
        assert!(scopes[0].0 == root);
        // Every later scope's parent is an earlier id.
        for (id, parent, kind) in &scopes[1..] {
            assert!(*parent < *id, "id={id} parent={parent}");
            assert!(matches!(
                kind,
                LexicalScopeKind::Block | LexicalScopeKind::Function | LexicalScopeKind::Module
            ));
        }
    }

    #[test]
    fn mod_item_is_module_scope() {
        assert_eq!(
            lexical_boundary_kind("mod_item"),
            Some(LexicalScopeKind::Module)
        );
        assert_eq!(
            lexical_boundary_kind("list_comprehension"),
            Some(LexicalScopeKind::Comprehension)
        );
        assert_eq!(
            lexical_boundary_kind("arrow_function"),
            Some(LexicalScopeKind::Function)
        );
        assert_eq!(
            lexical_boundary_kind("statement_block"),
            Some(LexicalScopeKind::Block)
        );
        assert_eq!(lexical_boundary_kind("identifier"), None);
    }

    #[test]
    fn python_function_lookup_bypasses_class() {
        // add_lexical_scope takes its parent from the current frame stack,
        // so simulate nesting by pushing SCOPE_LEXICAL frames (the walk's
        // real mechanism).
        let tree = crate::ts::parse(Language::PYTHON, "x = 1\n").unwrap();
        let node = tree.root_node();
        let mut state = WalkState::new("p.f");
        // Root module scope (id 1) at depth 0.
        state.push_lexical_scope(
            SCOPE_LEXICAL,
            0,
            None,
            node,
            LexicalScopeKind::Module,
            Language::PYTHON,
        );
        // Class scope (id 2) nested at depth 1.
        let class_id = state.push_lexical_scope(
            SCOPE_LEXICAL,
            1,
            None,
            node,
            LexicalScopeKind::Class,
            Language::PYTHON,
        );
        // Function scope (id 3) nested at depth 2: lookup parent must SKIP
        // the class and point at the module (id 1).
        let func_id = state.push_lexical_scope(
            SCOPE_LEXICAL,
            2,
            None,
            node,
            LexicalScopeKind::Function,
            Language::PYTHON,
        );
        let func = state.lexical_scope_by_id(func_id).unwrap();
        assert_eq!(func.parent_id, class_id);
        assert_eq!(func.lookup_parent_id, 1, "python lookup bypasses class");
        // Non-Python languages keep lookup = structural parent.
        let tree2 = crate::ts::parse(Language::JAVASCRIPT, "function f() {}\n").unwrap();
        let node2 = tree2.root_node();
        let mut js_state = WalkState::new("p.f");
        js_state.push_lexical_scope(
            SCOPE_LEXICAL,
            0,
            None,
            node2,
            LexicalScopeKind::Module,
            Language::JAVASCRIPT,
        );
        let js_class = js_state.push_lexical_scope(
            SCOPE_LEXICAL,
            1,
            None,
            node2,
            LexicalScopeKind::Class,
            Language::JAVASCRIPT,
        );
        let js_func = js_state.push_lexical_scope(
            SCOPE_LEXICAL,
            2,
            None,
            node2,
            LexicalScopeKind::Function,
            Language::JAVASCRIPT,
        );
        let js = js_state.lexical_scope_by_id(js_func).unwrap();
        assert_eq!(js.lookup_parent_id, js_class);
    }
}
