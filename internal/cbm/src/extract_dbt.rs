//! extract_dbt.rs — 1:1 rewrite of `internal/cbm/extract_dbt.c`: the dbt
//! lineage extractor for Jinja-templated SQL models.
//!
//! A dbt model is an ordinary .sql file whose SELECT is templated with
//! Jinja: dependencies are written `{{ ref('other_model') }}` or
//! `{{ source('group', 'table') }}`, never as literal table names. This
//! pass re-parses the file with the jinja2 grammar, collects those calls,
//! and emits one Model definition (named by the file stem — dbt's own
//! model identity) plus one usage per ref()/source() target, which the
//! usage resolver later turns into lineage edges.
//!
//! Gate: the file must parse as SQL, contain a `{{` opener, and contain
//! at least one real ref()/source() call — generic templated SQL (an
//! Airflow `{{ ds }}`, say) produces nothing at all.
//!
//! Grammar note: the C vendors a jinja2 grammar whose call nodes are
//! `fn_call` (field `fn_name`) over `lit_string` leaves. The crates.io
//! tree-sitter-jinja2 grammar instead models a call as an `expression`
//! whose `identifier` field carries the callee and whose `string` children
//! carry the arguments. The node names differ; the extracted facts do not.

use crate::extract_env_accesses::ExtractCtx;
use crate::fqn;
use crate::fqn::find_child_by_kind;
use crate::ts;
use crate::types::{Definition, Usage};
use crate::Language;
use tree_sitter::Node;

/// C DBT_FIRST_LINE.
const DBT_FIRST_LINE: u32 = 1;

/// Cheap pre-filter (C source_has_jinja_expr): a `{{` opener anywhere.
fn source_has_jinja_expr(s: &str) -> bool {
    s.as_bytes().windows(2).any(|w| w == b"{{")
}

/// Strip one pair of surrounding quotes (C dbt_unquote): the grammar hands
/// back the token with its quotes attached.
fn dbt_unquote(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'\'' || b[0] == b'"') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Rightmost `string` node under `node` in DFS order (C dbt_last_lit_string
/// over the vendored grammar's lit_string). Both dbt builtins put the
/// referenced relation last: ref('model'), ref('package', 'model') and
/// source('group', 'table') all name the relation in their final string
/// argument. The callee itself is an identifier, never a string, so it
/// cannot be mistaken for one.
fn dbt_last_string(node: Node<'_>) -> Option<Node<'_>> {
    let mut best = if node.kind() == "string" {
        Some(node)
    } else {
        None
    };
    for i in 0..node.child_count() {
        if let Some(c) = node.child(i) {
            if let Some(b) = dbt_last_string(c) {
                best = Some(b);
            }
        }
    }
    best
}

/// Collect ref()/source() targets from a jinja2 parse tree into `out`
/// (C collect_dbt_refs). Usages are scoped to `enclosing_qn` (the Model).
fn collect_dbt_refs<'t>(source: &'t str, node: Node<'t>, enclosing_qn: &str, out: &mut Vec<Usage>) {
    if node.kind() == "expression" {
        // C: fn_name field, falling back to an identifier child. The
        // crates.io grammar carries the callee in the `identifier` field
        // (identifier or dotted_identifier).
        let callee = node
            .child_by_field_name("identifier")
            .or_else(|| find_child_by_kind(node, "identifier"));
        if let Some(callee) = callee {
            let fname = fqn::node_text(callee, source);
            if fname == "ref" || fname == "source" {
                if let Some(strn) = dbt_last_string(node) {
                    let name = dbt_unquote(fqn::node_text(strn, source));
                    if !name.is_empty() {
                        out.push(Usage {
                            ref_name: name.to_string(),
                            enclosing_func_qn: enclosing_qn.to_string(),
                            site_start_byte: strn.start_byte() as u32,
                            site_end_byte: strn.end_byte() as u32,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(c) = node.child(i) {
            collect_dbt_refs(source, c, enclosing_qn, out);
        }
    }
}

/// dbt model identity is the file stem (C dbt_name_from_path):
/// models/staging/stg_users.sql is the model `stg_users`. dbt requires
/// model names to be unique across a project, so the directory is
/// deliberately not part of the identity.
pub fn dbt_name_from_path(rel_path: &str) -> Option<&str> {
    let base = rel_path.rsplit(['/', '\\']).next()?;
    let stem = match base.rfind('.') {
        Some(dot) => &base[..dot],
        None => base,
    };
    if stem.is_empty() {
        None
    } else {
        Some(stem)
    }
}

/// The dbt lineage pass (C cbm_extract_dbt).
pub fn extract_dbt(ctx: &mut ExtractCtx<'_>) {
    if ctx.language != Language::SQL || ctx.source.is_empty() {
        return;
    }
    if !source_has_jinja_expr(ctx.source) {
        return;
    }
    let Some(jl) = ts::ts_language(Language::JINJA2) else {
        return;
    };
    let Some(model_name) = dbt_name_from_path(ctx.rel_path) else {
        return;
    };
    let model_qn = fqn::fqn_compute(ctx.project, ctx.rel_path, Some(model_name));

    // A fresh parser: the primary SQL pass owns the thread-local one, and
    // this runs inside its walk.
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&jl).is_err() {
        return;
    }
    let Some(tree) = parser.parse(ctx.source, None) else {
        return;
    };

    // Refs are staged locally so a file with Jinja but no dbt builtins
    // commits nothing at all — neither usages nor a Model node.
    let mut staged: Vec<Usage> = Vec::new();
    collect_dbt_refs(ctx.source, tree.root_node(), &model_qn, &mut staged);
    if staged.is_empty() {
        return; // templated SQL, but not dbt — emit nothing
    }

    let end_line = ctx.root.end_position().row as u32 + 1; // TS_LINE_OFFSET
    ctx.result.definitions.push(Definition {
        name: model_name.to_string(),
        qualified_name: model_qn,
        label: "Model".to_string(),
        file_path: ctx.rel_path.to_string(),
        start_line: DBT_FIRST_LINE,
        end_line,
        is_exported: true,
        ..Default::default()
    });
    ctx.result.usages.extend(staged);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jinja_prefilter() {
        assert!(source_has_jinja_expr("select {{ ref('x') }}"));
        assert!(!source_has_jinja_expr("select 1"));
        assert!(!source_has_jinja_expr("{% if x %}single brace { {"));
    }

    #[test]
    fn unquote_strips_one_pair() {
        assert_eq!(dbt_unquote("'model'"), "model");
        assert_eq!(dbt_unquote("\"model\""), "model");
        assert_eq!(dbt_unquote("plain"), "plain");
        assert_eq!(dbt_unquote("'mismatched\""), "'mismatched\"");
        assert_eq!(dbt_unquote("''"), "");
    }

    #[test]
    fn model_identity_is_file_stem() {
        assert_eq!(
            dbt_name_from_path("models/staging/stg_users.sql"),
            Some("stg_users")
        );
        assert_eq!(dbt_name_from_path("stg_users.sql"), Some("stg_users"));
        assert_eq!(dbt_name_from_path("a\\b\\win_model.sql"), Some("win_model"));
        // Stem runs up to the LAST dot — a leading dot stays in the stem.
        assert_eq!(dbt_name_from_path(".hidden.sql"), Some(".hidden"));
        // No dot at all.
        assert_eq!(dbt_name_from_path("model"), Some("model"));
    }

    fn make_ctx<'t>(source: &'t str, rel_path: &'t str, root: Node<'t>) -> ExtractCtx<'t> {
        ExtractCtx {
            source,
            root,
            language: Language::SQL,
            project: "proj",
            rel_path,
            module_qn: String::new(),
            ef_cache: Default::default(),
            result: Default::default(),
            constants: Vec::new(),
        }
    }

    fn run<'t>(source: &'t str, rel_path: &'t str) -> (usize, usize, Vec<String>, Vec<String>) {
        // The ctx root only supplies the end line; the jinja parse of the
        // same text spans the same rows as the SQL parse would.
        let tree = ts::parse(Language::JINJA2, source).expect("jinja2 grammar");
        let mut ctx = make_ctx(source, rel_path, tree.root_node());
        extract_dbt(&mut ctx);
        // Assert on owned data; the tree dies with this function.
        (
            ctx.result.definitions.len(),
            ctx.result.usages.len(),
            ctx.result
                .definitions
                .iter()
                .map(|d| format!("{}|{}|{}|{}", d.name, d.label, d.start_line, d.is_exported))
                .collect(),
            ctx.result
                .usages
                .iter()
                .map(|u| u.ref_name.clone())
                .collect(),
        )
    }

    #[test]
    fn dbt_model_refs_collected() {
        let src = "select id from {{ ref('stg_users') }} join {{ source('raw', 'events') }}";
        let (ndef, nusage, defs, usages) = run(src, "models/staging/model_x.sql");
        assert_eq!(ndef, 1);
        assert_eq!(nusage, 2);
        // name|label|start_line|is_exported
        assert_eq!(defs[0], format!("model_x|Model|{DBT_FIRST_LINE}|true"));
        // ref() + source() in document order.
        assert_eq!(usages, vec!["stg_users", "events"]);
    }

    #[test]
    fn ref_with_package_takes_last_string() {
        let src = "select 1 from {{ ref('package', 'inner_model') }}";
        let (_, nusage, _, usages) = run(src, "models/m.sql");
        assert_eq!(nusage, 1);
        assert_eq!(usages[0], "inner_model");
    }

    #[test]
    fn generic_templated_sql_emits_nothing() {
        // Airflow-style {{ ds }} — Jinja, but no dbt builtins.
        let src = "select * from events where dt = '{{ ds }}'";
        let (ndef, nusage, _, _) = run(src, "models/airflow.sql");
        assert_eq!((ndef, nusage), (0, 0));
    }

    #[test]
    fn plain_sql_skipped_entirely() {
        let src = "select 1";
        let (ndef, nusage, _, _) = run(src, "models/plain.sql");
        assert_eq!((ndef, nusage), (0, 0));
    }
}
