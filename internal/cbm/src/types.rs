//! types.rs — 1:1 rewrite of the result data model in `internal/cbm/cbm.h`.
//!
//! C strings were arena-allocated (`const char *` borrowed from the result's
//! arena, freed wholesale by cbm_free_result); Rust owns them (`String` /
//! `Option<String>`), which removes the arena and its lifetime coupling.
//! Growable `*_Array { items, count, cap }` triples become `Vec<T>`.
//! Field order follows the C structs; comments are carried over verbatim
//! where they encode semantics.

/// A symbol extracted from source (C CBMDefinition).
#[derive(Debug, Clone, Default)]
pub struct Definition {
    /// Short name.
    pub name: String,
    /// project.path.name
    pub qualified_name: String,
    /// "Function", "Method", "Class", "Variable", "Module"
    pub label: String,
    /// Relative path.
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    /// Parameter text.
    pub signature: Option<String>,
    pub return_type: Option<String>,
    /// Go method receiver.
    pub receiver: Option<String>,
    /// Leading doc comment.
    pub docstring: Option<String>,
    /// Enclosing class QN for methods.
    pub parent_class: Option<String>,
    pub decorators: Vec<String>,
    pub base_classes: Vec<String>,
    pub param_names: Vec<String>,
    pub param_types: Vec<String>,
    /// Ordered internal signature types; "?" means unknown.
    pub signature_param_types: Vec<String>,
    pub return_types: Vec<String>,
    /// HTTP route path from decorator ("/api/users").
    pub route_path: Option<String>,
    /// HTTP method from decorator ("POST").
    pub route_method: Option<String>,
    /// Cyclomatic complexity.
    pub complexity: i32,
    /// Cognitive complexity (nesting-weighted).
    pub cognitive: i32,
    /// Loop constructs in the body.
    pub loop_count: i32,
    /// Max nested-loop depth (bottleneck proxy).
    pub loop_depth: i32,
    /// Body contains a direct self-call.
    pub is_recursive: bool,
    /// Parameter count (large = complexity smell).
    pub param_count: i32,
    /// Deepest chained member/subscript access (a.b.c.d).
    pub max_access_depth: i32,
    /// Linear-scan calls (find/contains/indexOf) inside loops.
    pub linear_scan_in_loop: i32,
    /// Allocation/append calls inside loops.
    pub alloc_in_loop: i32,
    /// A self-call occurs inside a loop body.
    pub recursion_in_loop: bool,
    /// Recursive with no self-call guarded by a conditional.
    pub unguarded_recursion: bool,
    /// Body line count.
    pub lines: i32,
    /// MinHash fingerprint (K values).
    pub fingerprint: Vec<u32>,
    pub is_exported: bool,
    pub is_abstract: bool,
    pub is_test: bool,
    pub is_entry_point: bool,
    /// AST structural profile.
    pub structural_profile: Option<String>,
    /// Space-separated raw identifier tokens from body.
    pub body_tokens: Option<String>,
    /// Raw trait path from the exact `impl Trait for Type` block (Rust).
    pub impl_trait: Option<String>,
}

/// Argument captured from a call expression (C CBMCallArg).
#[derive(Debug, Clone, Default)]
pub struct CallArg {
    /// Raw expression text ("payload.info", "MY_URL", "'hello'").
    pub expr: String,
    /// Resolved string value (constant propagation).
    pub value: Option<String>,
    /// Keyword name if keyword arg ("url"), None if positional.
    pub keyword: Option<String>,
    /// Positional index (0-based).
    pub index: i32,
}

pub const MAX_CALL_ARGS: usize = 8;

/// Byte offsets are meaningful only within the source buffer that produced
/// them: C/C++/CUDA run both raw and preprocessed extraction passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceOrigin {
    #[default]
    Raw,
    Preprocessed,
}

/// A call site (C CBMCall).
#[derive(Debug, Clone, Default)]
pub struct Call {
    /// Raw callee text ("pkg.Func", "foo").
    pub callee_name: String,
    /// QN of enclosing function (or module QN).
    pub enclosing_func_qn: String,
    /// First string literal argument (URL, topic, key).
    pub first_string_arg: Option<String>,
    /// Second argument identifier (handler ref).
    pub second_arg_name: Option<String>,
    /// First N arguments with expressions (C cap: MAX_CALL_ARGS).
    pub args: Vec<CallArg>,
    /// Enclosing loop nesting at the call site.
    pub loop_depth: i32,
    /// Enclosing branch nesting at the call site.
    pub branch_depth: i32,
    /// 1-based source line of the call (for def range-match).
    pub start_line: i32,
    /// Exact AST occurrence span (exclusive end; end > start when present).
    pub site_start_byte: u32,
    pub site_end_byte: u32,
    pub source_origin: SourceOrigin,
    /// Method/member call with an UNRESOLVED receiver. Perl: arrow call.
    /// TS/JS/TSX: member call x.foo() whose receiver is not this/super.
    /// Python: x.foo() where x is not self/cls/super() or an imported name.
    /// Read by the weak-member guard and the pxc dedup key. Default false.
    pub is_method: bool,
    /// Synthetic semantic candidate (e.g. an implicit C++ operator). Never
    /// fall back to textual resolution.
    pub requires_lsp_resolution: bool,
    /// Bare call foo() whose callee is bound as an enclosing function's
    /// parameter — cannot be the module-level foo (Python). Read by the
    /// weak-local-binding guard.
    pub callee_is_locally_bound: bool,
}

/// An import (C CBMImport).
#[derive(Debug, Clone, Default)]
pub struct Import {
    /// Local alias or name.
    pub local_name: String,
    /// Resolved module path / QN.
    pub module_path: String,
}

/// Usage kind (C CBMUsageKind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsageKind {
    #[default]
    Value,
    CallReference,
}

/// An identifier usage (C CBMUsage).
#[derive(Debug, Clone, Default)]
pub struct Usage {
    /// Referenced identifier.
    pub ref_name: String,
    /// QN of enclosing function (or module QN).
    pub enclosing_func_qn: String,
    pub kind: UsageKind,
    /// Syntactic candidate; exact LSP proof may upgrade its edge.
    pub may_be_call_reference: bool,
    /// Lexical evidence blocks only unproven textual fallback.
    pub semantic_reference_blocked: bool,
    /// The blocker belongs to a non-module lexical scope.
    pub semantic_reference_local_shadow: bool,
    /// Extraction-local scope instance; never graph identity.
    pub lexical_scope_id: u32,
    /// Exact reference-token span (exclusive end; end > start when present).
    pub site_start_byte: u32,
    pub site_end_byte: u32,
    pub source_origin: SourceOrigin,
    /// Token is the member half of a selector/attribute (Go x.f —
    /// field_identifier). The extractor strips the receiver, so this is the
    /// only surviving record of selector shape (#1962).
    pub is_member_access: bool,
}

/// A thrown exception (C CBMThrow).
#[derive(Debug, Clone, Default)]
pub struct Throw {
    /// Exception class/type name.
    pub exception_name: String,
    pub enclosing_func_qn: String,
}

/// A read/write record (C CBMReadWrite).
#[derive(Debug, Clone, Default)]
pub struct ReadWrite {
    pub var_name: String,
    pub enclosing_func_qn: String,
    /// true = write, false = read.
    pub is_write: bool,
    /// var_name is the field half of a selector/member LHS (`t.err = x` →
    /// "err"); the receiver is stripped here, so this is the only record of
    /// selector shape (#1962).
    pub is_member_access: bool,
}

/// A referenced type (C CBMTypeRef).
#[derive(Debug, Clone, Default)]
pub struct TypeRef {
    pub type_name: String,
    pub enclosing_func_qn: String,
}

/// An environment-variable access (C CBMEnvAccess).
#[derive(Debug, Clone, Default)]
pub struct EnvAccess {
    pub env_key: String,
    pub enclosing_func_qn: String,
}

/// A constructor type assignment (C CBMTypeAssign).
#[derive(Debug, Clone, Default)]
pub struct TypeAssign {
    /// Variable being assigned.
    pub var_name: String,
    /// Class/type name of the RHS constructor.
    pub type_name: String,
    pub enclosing_func_qn: String,
}

/// String-reference kind (C CBMStringRefKind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StringRefKind {
    /// REST path or full URL.
    #[default]
    Url,
    /// Config file path or env var key.
    Config,
}

/// A URL/config string reference (C CBMStringRef).
#[derive(Debug, Clone, Default)]
pub struct StringRef {
    pub value: String,
    pub enclosing_func_qn: String,
    /// Dotted key path from YAML/JSON nesting (None if flat).
    pub key_path: Option<String>,
    pub kind: StringRefKind,
}

/// Infrastructure binding: topic/queue → endpoint URL, from YAML/HCL/JSON
/// subscription/scheduler configs. Connects async Route nodes to handler
/// services (pass_route_nodes).
#[derive(Debug, Clone, Default)]
pub struct InfraBinding {
    /// Topic, queue, or schedule name.
    pub source_name: String,
    /// push_endpoint, uri, or http_target URL.
    pub target_url: String,
    /// "pubsub", "cloud_tasks", "cloud_scheduler", "sqs", "kafka".
    pub broker: String,
}

/// Channel direction (C CBMChannelDirection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChannelDirection {
    #[default]
    Emit,
    Listen,
}

/// Pub/sub participation — one record per emit()/on()/addListener() call.
/// The receiver is intentionally NOT identified; matching is by channel
/// name across files. Transport disambiguates Socket.IO vs EventEmitter vs
/// future detectors.
#[derive(Debug, Clone, Default)]
pub struct Channel {
    /// Literal channel name ("user.created").
    pub channel_name: String,
    /// "socketio", "event_emitter", …
    pub transport: String,
    /// QN of the function containing the emit/on call.
    pub enclosing_func_qn: String,
    pub direction: ChannelDirection,
}

/// Rust: impl Trait for Struct (C CBMImplTrait).
#[derive(Debug, Clone, Default)]
pub struct ImplTrait {
    /// Trait name (raw text).
    pub trait_name: String,
    /// Struct/type name (raw text).
    pub struct_name: String,
    /// Exact extracted QN of the implementing type — no leaf-name guess,
    /// and the relation exists even for an empty `impl Trait for Type {}`.
    pub struct_qn: String,
}

/// Resolved-call kind (C CBMResolvedKind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResolvedKind {
    #[default]
    Invocation,
    CallReference,
}

/// LSP-resolved invocation/reference: high-confidence type-aware
/// resolution (C CBMResolvedCall).
#[derive(Debug, Clone, Default)]
pub struct ResolvedCall {
    /// Enclosing function QN.
    pub caller_qn: String,
    /// Resolved target QN (fully qualified).
    pub callee_qn: String,
    /// "lsp_type_dispatch", "lsp_direct", …
    pub strategy: String,
    /// 0.90–0.95.
    pub confidence: f32,
    /// Diagnostic label for unresolved calls (None if resolved).
    pub reason: Option<String>,
    pub kind: ResolvedKind,
    /// Exact source occurrence (exclusive end; end > start when present).
    pub site_start_byte: u32,
    pub site_end_byte: u32,
    pub source_origin: SourceOrigin,
}

/// Per-file extraction result (C CBMFileResult) — the arrays collapse to
/// Vec and strings are owned.
#[derive(Debug, Clone, Default)]
pub struct FileResult {
    pub definitions: Vec<Definition>,
    pub calls: Vec<Call>,
    pub imports: Vec<Import>,
    pub usages: Vec<Usage>,
    pub throws: Vec<Throw>,
    /// Read/write records (C CBMRWArray rw).
    pub rw: Vec<ReadWrite>,
    pub env_accesses: Vec<EnvAccess>,
    pub type_assigns: Vec<TypeAssign>,
    pub type_refs: Vec<TypeRef>,
    pub impl_traits: Vec<ImplTrait>,
    pub resolved_calls: Vec<ResolvedCall>,
    /// URL/config string literals from AST.
    pub string_refs: Vec<StringRef>,
    /// topic→URL pairs from IaC configs.
    pub infra_bindings: Vec<InfraBinding>,
    /// Socket.IO / EventEmitter pub/sub participation.
    pub channels: Vec<Channel>,

    pub module_qn: Option<String>,
    /// Declared namespace/package (Java/Kotlin/C#/PHP).
    pub namespace_name: Option<String>,
    pub exports: Vec<String>,
    pub constants: Vec<String>,
    pub global_vars: Vec<String>,
    pub macros: Vec<String>,

    pub has_error: bool,
    pub error_msg: Option<String>,
    /// Best-effort parse-coverage signal: true when the parse tree contains
    /// tree-sitter ERROR/MISSING nodes. The absence of a flag is NOT a
    /// completeness guarantee — callers should treat a flagged file as
    /// "prefer grep here", never an unflagged file as provably complete.
    pub parse_incomplete: bool,
    /// True when the ranges cover so much of the file they are no longer
    /// useful advice — one range over 80% of the line count. The file WAS
    /// indexed, but pointing a reader at almost every line tells nothing,
    /// so the report says "read the source". Its customers are non-C
    /// languages: the C/C++/CUDA narrowing refinement does not run there.
    /// Naming mismatch with parse_incomplete's `parse_partial` phase is
    /// historical — do not copy it.
    pub parse_unusable: bool,
    /// Compact "start-end,start-end" list of 1-based line ranges.
    pub error_ranges: Option<String>,
    pub error_region_count: i32,
    pub is_test_file: bool,
    pub imports_count: i32,

    /// Composite extraction results (ObjectScript Studio Export) retain
    /// their per-unit results.
    pub owned_results: Vec<Box<FileResult>>,
}

/// Enclosing-function cache entry (C EFCEntry).
#[derive(Debug, Clone, Default)]
pub struct EfEntry {
    pub start_byte: u32,
    pub end_byte: u32,
    pub qn: String,
}

pub const EFC_SIZE: usize = 64; // power of 2 for fast modulo

/// Enclosing-function cache (C EFCache) — avoids repeated parent-chain
/// walks for nodes within the same function body. Each entry records a
/// function's byte range and its precomputed QN.
#[derive(Debug, Clone, Default)]
pub struct EfCache {
    pub entries: Vec<EfEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_roundtrip() {
        let mut d = Definition {
            name: "Handler".into(),
            qualified_name: "proj.svc.Handler".into(),
            label: "Method".into(),
            file_path: "svc/handler.go".into(),
            start_line: 10,
            end_line: 40,
            complexity: 4,
            ..Default::default()
        };
        d.decorators.push("@Get".into());
        assert_eq!(d.decorators.len(), 1);
        assert_eq!(d.name, "Handler");
    }

    #[test]
    fn call_args_cap_matches_c() {
        let mut call = Call::default();
        for i in 0..MAX_CALL_ARGS {
            call.args.push(CallArg {
                expr: format!("a{i}"),
                index: i as i32,
                ..Default::default()
            });
        }
        assert_eq!(call.args.len(), MAX_CALL_ARGS);
    }

    #[test]
    fn file_result_defaults_empty() {
        let r = FileResult::default();
        assert!(r.definitions.is_empty());
        assert!(!r.has_error);
        assert!(!r.parse_incomplete);
        assert_eq!(r.imports_count, 0);
    }

    #[test]
    fn ef_cache_is_pow2() {
        assert!(EFC_SIZE.is_power_of_two());
    }

    #[test]
    fn composite_results_nest() {
        let mut r = FileResult::default();
        r.owned_results.push(Box::new(FileResult {
            module_qn: Some("child".into()),
            ..Default::default()
        }));
        assert_eq!(r.owned_results[0].module_qn.as_deref(), Some("child"));
    }
}
