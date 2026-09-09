//! extract_env_accesses.rs — 1:1 rewrite of
//! `internal/cbm/extract_env_accesses.c` (211 lines).
//!
//! Environment-variable access extraction: `os.Getenv("KEY")` call sites
//! and `process.env.KEY` / `os.environ["KEY"]` member accesses, gated by
//! the per-language env-access tables in the language spec. Keys must look
//! like environment variables (uppercase + underscore/digit shape).
//! Iterative walk with an explicit stack; a matched node's children are
//! NOT pushed (avoids double-counting nested accesses).

use crate::lang_specs::LanguageSpec;
use crate::types::{EnvAccess, FileResult};
use crate::{fqn, Language};

/// Minimum length for an env var name ("DB").
const MIN_ENV_NAME_LEN: usize = 2;

/// Unquote a string literal: "foo" → foo (C unquote).
fn unquote(s: &str) -> &str {
    let t = s.trim_start_matches([' ', '\t']);
    let b = t.as_bytes();
    if b.len() >= 2 {
        let (first, last) = (b[0], b[b.len() - 1]);
        if (first == b'"' && last == b'"')
            || (first == b'\'' && last == b'\'')
            || (first == b'`' && last == b'`')
        {
            return &t[1..b.len() - 1];
        }
    }
    t
}

/// Extraction context — the Rust shape of C CBMExtractCtx, narrowed to
/// what env-access extraction reads (the full ctx grows with each
/// extractor port).
pub struct ExtractCtx<'t> {
    pub source: &'t str,
    pub root: tree_sitter::Node<'t>,
    pub language: Language,
    pub project: &'t str,
    pub rel_path: &'t str,
    /// Derived from project+rel_path at construction (owned — it embeds
    /// path segments, not a slice of the source).
    pub module_qn: String,
    /// Enclosing-function QN cache (C ef_cache).
    pub ef_cache: fqn::EnclosingQnCache<'t>,
    /// Accumulated result (C ctx->result).
    pub result: FileResult,
    /// Module-level string constants (C string_constants map):
    /// (name, value, is_url_builder). Filled by the unified walk's
    /// handle_string_constants / handle_url_builders.
    pub constants: Vec<(String, String, bool)>,
}

impl<'t> ExtractCtx<'t> {
    /// Snapshot as the lookup map extract_calls reads.
    pub fn constants_map(&self) -> crate::extract_calls::StringConstantMap {
        crate::extract_calls::StringConstantMap {
            entries: self.constants.clone(),
        }
    }

    pub fn new(
        source: &'t str,
        root: tree_sitter::Node<'t>,
        language: Language,
        project: &'t str,
        rel_path: &'t str,
    ) -> Self {
        let module_qn = fqn::fqn_module_source_lang(project, rel_path, language);
        ExtractCtx {
            source,
            root,
            language,
            project,
            rel_path,
            module_qn,
            ef_cache: fqn::EnclosingQnCache::new(),
            result: FileResult::default(),
            constants: Vec::new(),
        }
    }
}

/// Extract the env key from `os.Getenv("KEY")`-style call
/// (C extract_env_key_from_call).
fn env_key_from_call<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
    spec: &LanguageSpec,
) -> Option<&'a str> {
    let funcs = spec.env_access_functions;
    if funcs.is_empty() {
        return None;
    }
    let func_node = node.child_by_field_name("function")?;
    let callee = fqn::node_text(func_node, source);
    if !funcs.contains(&callee) {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    // First named child, skipping punctuation ("(", ")", ",").
    for i in 0..args.child_count() {
        let child = args.child(i)?;
        let ck = child.kind();
        if ck == "(" || ck == ")" || ck == "," {
            continue;
        }
        return Some(unquote(fqn::node_text(child, source)));
    }
    None
}

/// Extract the env key from `process.env.KEY` / `os.environ["KEY"]` member
/// access (C extract_env_key_from_member).
fn env_key_from_member<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a str,
    spec: &LanguageSpec,
) -> Option<&'a str> {
    let patterns = spec.env_access_member_patterns;
    if patterns.is_empty() {
        return None;
    }
    let text = fqn::node_text(node, source);
    if text.is_empty() {
        return None;
    }
    for pat in patterns {
        let plen = pat.len();
        if !text.starts_with(pat) {
            continue;
        }
        let rest = &text[plen..];
        // Dot access: pattern.KEY — no further dots/brackets in the key.
        if let Some(key) = rest.strip_prefix('.') {
            if !key.is_empty() && !key.contains('.') && !key.contains('[') {
                return Some(key);
            }
        }
        // Subscript: pattern["KEY"]
        if let Some(inner) = rest.strip_prefix('[') {
            if let Some(inner) = inner.strip_suffix(']') {
                if !inner.is_empty() {
                    return Some(unquote(inner));
                }
            }
        }
    }
    None
}

/// Does `s` look like an environment variable name (uppercase +
/// underscores/digits)? (C is_env_var_name.)
fn is_env_var_name(s: &str) -> bool {
    if s.len() < MIN_ENV_NAME_LEN {
        return false;
    }
    let mut has_upper = false;
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c == '_' || c.is_ascii_digit() {
            // ok
        } else {
            return false;
        }
    }
    has_upper
}

/// Unified-walk single-node handler (C unified env handler): process one
/// node at the walk's QN; the unified walk supplies traversal.
pub fn extract_env_accesses_at(
    ctx: &mut ExtractCtx<'_>,
    node: tree_sitter::Node<'_>,
    spec: &LanguageSpec,
    func_qn: &str,
) {
    let kind = node.kind();
    let mut env_key: Option<&str> = None;
    if spec.call_node_types.contains(&kind) {
        env_key = env_key_from_call(node, ctx.source, spec);
    }
    if env_key.is_none() && matches!(kind, "member_expression" | "subscript" | "attribute") {
        env_key = env_key_from_member(node, ctx.source, spec);
    }
    if let Some(key) = env_key {
        if !key.is_empty() && is_env_var_name(key) {
            ctx.result.env_accesses.push(EnvAccess {
                env_key: key.to_string(),
                enclosing_func_qn: func_qn.to_string(),
            });
        }
    }
}

/// Walk the AST collecting env accesses (C walk_env_accesses).
pub fn extract_env_accesses(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    let has_funcs = !spec.env_access_functions.is_empty();
    let has_members = !spec.env_access_member_patterns.is_empty();
    if !has_funcs && !has_members {
        return;
    }
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let mut env_key: Option<&str> = None;
        let is_call = spec.call_node_types.contains(&kind);
        if is_call {
            env_key = env_key_from_call(node, ctx.source, spec);
        }
        if env_key.is_none() && matches!(kind, "member_expression" | "subscript" | "attribute") {
            env_key = env_key_from_member(node, ctx.source, spec);
        }
        if let Some(key) = env_key {
            if !key.is_empty() && is_env_var_name(key) {
                let enclosing = ctx.ef_cache.enclosing_qn(
                    node,
                    ctx.language,
                    ctx.source,
                    ctx.project,
                    ctx.rel_path,
                    &ctx.module_qn,
                );
                ctx.result.env_accesses.push(EnvAccess {
                    env_key: key.to_string(),
                    enclosing_func_qn: enclosing,
                });
                continue; // don't push children (avoid double-counting)
            }
        }
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

    fn run_extractor(lang: Language, src: &str) -> Vec<EnvAccess> {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", "app.py");
        let spec = crate::lang_specs::lang_spec(lang);
        extract_env_accesses(&mut ctx, spec);
        ctx.result.env_accesses
    }

    #[test]
    fn python_getenv_call() {
        let src = "import os\nkey = os.getenv(\"DATABASE_URL\")\n";
        let accesses = run_extractor(Language::PYTHON, src);
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].env_key, "DATABASE_URL");
    }

    #[test]
    fn python_environ_subscript() {
        let src = "import os\nkey = os.environ[\"API_KEY\"]\n";
        let accesses = run_extractor(Language::PYTHON, src);
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].env_key, "API_KEY");
    }

    #[test]
    fn member_access_dot_form() {
        // Python pattern is os.environ[...]; the dot form belongs to JS
        // (process.env.KEY) — Python's spec has no dot-member pattern, so a
        // bare attribute access extracts nothing here.
        let src = "import os\nv = os.environ.get(\"X\")\n";
        let accesses = run_extractor(Language::PYTHON, src);
        // `os.environ` attribute matches member pattern; key "get" fails the
        // env-var name check (lowercase) → nothing recorded.
        assert!(accesses.is_empty());
    }

    #[test]
    fn lowercase_keys_rejected() {
        let src = "import os\nk = os.getenv(\"lower_key\")\n";
        let accesses = run_extractor(Language::PYTHON, src);
        assert!(accesses.is_empty(), "env names must be SCREAMING_CASE");
    }

    #[test]
    fn enclosing_qn_recorded() {
        let src = "import os\ndef read_cfg():\n    return os.getenv(\"SERVICE_KEY\")\n";
        let accesses = run_extractor(Language::PYTHON, src);
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].enclosing_func_qn, "proj.app.read_cfg");
    }

    #[test]
    fn no_env_table_no_accesses() {
        // BASH's spec has no env-access tables at all, so nothing extracts
        // even for a Getenv-shaped call (needs the bash grammar crate; use
        // a language with a linked grammar and empty tables instead —
        // verify via a language whose tables are EMPTY: none of the two
        // currently linked (go/python) is, so assert the gate directly).
        // Gate unit check via spec introspection:
        assert!(crate::lang_specs::lang_spec(Language::BASH)
            .env_access_functions
            .is_empty());
        assert!(crate::lang_specs::lang_spec(Language::BASH)
            .env_access_member_patterns
            .is_empty());
        // And a GO call whose callee does not match its table extracts nothing.
        let accesses = run_extractor(Language::GO, "x := notenv.Lookup(\"KEY\")\n");
        assert!(accesses.is_empty());
    }
}
