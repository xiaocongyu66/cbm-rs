//! extract_k8s.rs — 1:1 rewrite of `internal/cbm/extract_k8s.c`: the K8s
//! manifest and Kustomize file extractor.
//!
//! For KUSTOMIZE: walks top-level block_mapping_pair nodes whose key
//! matches one of the resource-list field names, then emits one Import
//! per block_sequence item. A "Resource" def named after the document's
//! `kind` scalar is also emitted so Kustomize resources stay discoverable.
//!
//! For K8S: finds apiVersion-adjacent `kind` and `metadata.name` scalars
//! in the first document's block_mapping and emits one Definition with
//! label "Resource" and name "Kind/metadata-name".

use crate::extract_env_accesses::ExtractCtx;
use crate::fqn::node_text;
use crate::types::{Definition, Import};
use crate::Language;
use tree_sitter::Node;

/// C K8S_BUF_SIZE — scalar text longer than this is not a sane manifest
/// kind/name; the C's fixed stack buffers cap it.
const K8S_BUF_LIMIT: usize = 256;

// ── Shared scalar helpers ───────────────────────────────────────

/// Raw source text for a scalar node (C get_scalar_text): plain,
/// single-quoted, or double-quoted; quotes are stripped for the quoted
/// forms. Descends through flow_node wrappers (the YAML grammar often
/// wraps scalars). Returns None for non-scalar node types.
fn get_scalar_text<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    let mut node = node;
    for _ in 0..4 {
        // C MAX_UNWRAP
        match node.kind() {
            "flow_node" => {
                node = node.named_child(0)?;
            }
            "plain_scalar" => return Some(node_text(node, source)),
            "double_quote_scalar" | "single_quote_scalar" => {
                let raw = node_text(node, source);
                let b = raw.as_bytes();
                if b.len() >= 2 {
                    return Some(&raw[1..raw.len() - 1]);
                }
                return Some(raw);
            }
            _ => return None,
        }
    }
    None
}

/// The named child at `idx`, as in C ts_node_named_child (null-safe).
fn named_child(node: Node<'_>, idx: usize) -> Option<Node<'_>> {
    let mut seen = 0usize;
    for i in 0..node.child_count() {
        let c = node.child(i)?;
        if c.is_named() {
            if seen == idx {
                return Some(c);
            }
            seen += 1;
        }
    }
    None
}

/// All children of a node (C ts_node_child loop helper).
fn children(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    (0..node.child_count()).filter_map(move |i| node.child(i))
}

/// Is the key text one of the Kustomize resource-list field names
/// (C is_kustomize_list_key)?
fn is_kustomize_list_key(key: &str) -> bool {
    matches!(
        key,
        "resources" | "bases" | "patches" | "components" | "patchesStrategicMerge" | "crds"
    )
}

/// Unwrap a block_mapping_pair value through optional block_node
/// (C unwrap_pair_value).
fn unwrap_pair_value(pair: Node<'_>) -> Option<Node<'_>> {
    let mut val = named_child(pair, 1)?;
    if val.kind() == "block_node" {
        val = val.named_child(0)?;
    }
    Some(val)
}

/// Unwrap a YAML document child through optional block_node to get its
/// block_mapping (C unwrap_block_mapping). None when not a block_mapping.
fn unwrap_block_mapping(doc_child: Node<'_>) -> Option<Node<'_>> {
    let mut mapping = named_child(doc_child, 0)?;
    if mapping.kind() == "block_node" {
        mapping = mapping.named_child(0)?;
    }
    if mapping.kind() != "block_mapping" {
        return None;
    }
    Some(mapping)
}

// ── Kustomize extraction ────────────────────────────────────────

/// Walk a block_sequence node and emit one Import per
/// block_sequence_item scalar child, using `key_name` as the local_name
/// (C emit_kustomize_sequence).
fn emit_kustomize_sequence(ctx: &mut ExtractCtx<'_>, seq_node: Node<'_>, key_name: &str) {
    for item in children(seq_node) {
        if item.kind() != "block_sequence_item" {
            continue;
        }
        for val in children(item) {
            let Some(scalar) = get_scalar_text(val, ctx.source) else {
                continue;
            };
            if scalar.len() > K8S_BUF_LIMIT {
                continue; // C's fixed buffers cap the stored text
            }
            ctx.result.imports.push(Import {
                local_name: key_name.to_string(),
                module_path: scalar.to_string(),
            });
        }
    }
}

/// Process a single block_mapping_pair for kustomize list keys
/// (C process_kustomize_pair).
fn process_kustomize_pair(ctx: &mut ExtractCtx<'_>, pair: Node<'_>) {
    if pair.kind() != "block_mapping_pair" {
        return;
    }
    let Some(key_node) = named_child(pair, 0) else {
        return;
    };
    let Some(key_text) = get_scalar_text(key_node, ctx.source) else {
        return;
    };
    if !is_kustomize_list_key(key_text) {
        return;
    }
    let Some(val_node) = named_child(pair, 1) else {
        return;
    };
    let val_node = if val_node.kind() == "block_node" {
        match val_node.named_child(0) {
            Some(v) => v,
            None => return,
        }
    } else {
        val_node
    };
    if val_node.kind() != "block_sequence" {
        return;
    }
    emit_kustomize_sequence(ctx, val_node, key_text);
}

/// Emit a "Resource" def named after the document's `kind` scalar
/// (C emit_kustomize_kind_def). A kustomization file has no metadata.name,
/// so the def name is the bare kind ("Kustomization"). Mirrors the K8s
/// manifest kind-def so Kustomize resources are also discoverable.
fn emit_kustomize_kind_def(ctx: &mut ExtractCtx<'_>, mapping: Node<'_>) {
    for pair in children(mapping) {
        if pair.kind() != "block_mapping_pair" {
            continue;
        }
        let Some(key_node) = named_child(pair, 0) else {
            continue;
        };
        let Some(key) = get_scalar_text(key_node, ctx.source) else {
            continue;
        };
        if key != "kind" {
            continue;
        }
        let Some(val_node) = unwrap_pair_value(pair) else {
            continue;
        };
        let Some(kind) = get_scalar_text(val_node, ctx.source) else {
            continue;
        };
        if kind.is_empty() || kind.len() > K8S_BUF_LIMIT {
            continue;
        }
        ctx.result.definitions.push(Definition {
            name: kind.to_string(),
            qualified_name: format!("{}.{}", ctx.module_qn, kind),
            label: "Resource".to_string(),
            file_path: ctx.rel_path.to_string(),
            start_line: mapping.start_position().row as u32 + 1,
            end_line: mapping.end_position().row as u32 + 1,
            ..Default::default()
        });
        return;
    }
}

/// The Kustomize pass (C extract_kustomize).
fn extract_kustomize(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    for stream_child in children(root) {
        if stream_child.kind() != "document" {
            continue;
        }
        let Some(mapping) = unwrap_block_mapping(stream_child) else {
            continue;
        };
        emit_kustomize_kind_def(ctx, mapping);
        for pair in children(mapping) {
            process_kustomize_pair(ctx, pair);
        }
    }
}

// ── K8s manifest extraction ─────────────────────────────────────

/// Extract the "name" scalar from a metadata block_mapping
/// (C extract_metadata_name).
fn extract_metadata_name<'s>(meta_mapping: Node<'_>, source: &'s str) -> Option<&'s str> {
    if meta_mapping.kind() != "block_mapping" {
        return None;
    }
    let mut found = None;
    for mpair in children(meta_mapping) {
        if mpair.kind() != "block_mapping_pair" {
            continue;
        }
        let Some(mkey) = named_child(mpair, 0) else {
            continue;
        };
        let Some(mkey_text) = get_scalar_text(mkey, source) else {
            continue;
        };
        if mkey_text != "name" {
            continue;
        }
        let Some(mval) = named_child(mpair, 1) else {
            continue;
        };
        if let Some(meta_name) = get_scalar_text(mval, source) {
            found = Some(meta_name); // C keeps the last "name" seen
        }
    }
    found
}

/// Descend into a block_mapping and extract kind and metadata.name
/// (C extract_k8s_scalars).
fn extract_k8s_scalars<'s>(
    mapping: Node<'_>,
    source: &'s str,
) -> (Option<&'s str>, Option<&'s str>) {
    let mut kind = None;
    let mut meta_name = None;
    for pair in children(mapping) {
        if pair.kind() != "block_mapping_pair" {
            continue;
        }
        let Some(key_node) = named_child(pair, 0) else {
            continue;
        };
        let Some(key) = get_scalar_text(key_node, source) else {
            continue;
        };
        let Some(val_node) = unwrap_pair_value(pair) else {
            continue;
        };
        if key == "kind" {
            kind = get_scalar_text(val_node, source);
        } else if key == "metadata" {
            meta_name = extract_metadata_name(val_node, source);
        }
    }
    (kind, meta_name)
}

/// The K8s manifest pass (C extract_k8s_manifest).
fn extract_k8s_manifest(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    for stream_child in children(root) {
        if stream_child.kind() != "document" {
            continue;
        }
        let Some(mapping) = unwrap_block_mapping(stream_child) else {
            continue;
        };

        let (kind, meta_name) = extract_k8s_scalars(mapping, ctx.source);

        // Skip malformed manifests (no kind or no metadata.name).
        let (Some(kind), Some(meta_name)) = (kind, meta_name) else {
            continue;
        };
        if kind.is_empty() || meta_name.is_empty() {
            continue;
        }
        if kind.len() + meta_name.len() + 1 > 2 * K8S_BUF_LIMIT {
            continue; // C's fixed-buffer cap
        }

        let def_name = format!("{kind}/{meta_name}");
        ctx.result.definitions.push(Definition {
            name: def_name.clone(),
            qualified_name: format!("{}.{}", ctx.module_qn, def_name),
            // "Resource" is the canonical def label for a K8s resource kind;
            // the K8s pipeline pass (pass_k8s.c) filters on it to upsert
            // Resource nodes and emit INFRA_MAPS edges.
            label: "Resource".to_string(),
            file_path: ctx.rel_path.to_string(),
            start_line: mapping.start_position().row as u32 + 1,
            end_line: mapping.end_position().row as u32 + 1,
            ..Default::default()
        });

        break; // Only the first document per file
    }
}

/// Public entry point (C cbm_extract_k8s).
pub fn extract_k8s(ctx: &mut ExtractCtx<'_>) {
    match ctx.language {
        Language::KUSTOMIZE => extract_kustomize(ctx),
        Language::K8S => extract_k8s_manifest(ctx),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Imports = Vec<(String, String)>;
    type DefSummaries = Vec<(String, String, String)>;

    /// Returns (imports, def summaries) as owned data — the tree and ctx
    /// are dropped here.
    fn run(lang: Language, source: &str, rel_path: &str) -> (Imports, DefSummaries) {
        let tree = crate::ts::parse(lang, source).expect("yaml grammar");
        let mut ctx = ExtractCtx {
            source,
            root: tree.root_node(),
            language: lang,
            project: "proj",
            rel_path,
            module_qn: format!("proj.{rel_path}"),
            ef_cache: Default::default(),
            result: Default::default(),
            constants: Vec::new(),
        };
        extract_k8s(&mut ctx);
        let imports = ctx
            .result
            .imports
            .iter()
            .map(|i| (i.local_name.clone(), i.module_path.clone()))
            .collect();
        let defs = ctx
            .result
            .definitions
            .iter()
            .map(|d| (d.name.clone(), d.label.clone(), d.qualified_name.clone()))
            .collect();
        (imports, defs)
    }

    const KUSTOMIZE: &str = "\
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
  - service.yaml
patchesStrategicMerge:
  - patch-a.yaml
crds:
  - crd-foo.yaml
notresources:
  - skip-me.yaml
";

    #[test]
    fn kustomize_lists_and_kind_def() {
        let (imports, defs) = run(Language::KUSTOMIZE, KUSTOMIZE, "kustomization.yaml");
        assert_eq!(
            imports,
            vec![
                ("resources".to_string(), "deployment.yaml".to_string()),
                ("resources".to_string(), "service.yaml".to_string()),
                (
                    "patchesStrategicMerge".to_string(),
                    "patch-a.yaml".to_string()
                ),
                ("crds".to_string(), "crd-foo.yaml".to_string()),
            ],
            "unknown keys must be skipped"
        );
        // Kind def: bare kind name, Resource label.
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].0, "Kustomization");
        assert_eq!(defs[0].1, "Resource");
        assert!(defs[0].2.starts_with("proj.kustomization.yaml."));
    }

    const MANIFEST: &str = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
";

    #[test]
    fn k8s_manifest_def() {
        let (_, defs) = run(Language::K8S, MANIFEST, "deploy.yaml");
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].0, "Deployment/my-app");
        assert_eq!(defs[0].1, "Resource");
        assert!(defs[0].2.ends_with(".Deployment/my-app"));
    }

    #[test]
    fn quoted_scalars_unwrapped() {
        let src = "apiVersion: v1\nkind: \"Service\"\nmetadata:\n  name: 'web'\n";
        let (_, defs) = run(Language::K8S, src, "svc.yaml");
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].0, "Service/web");
    }

    #[test]
    fn malformed_manifests_skipped() {
        // No metadata.name.
        let src = "kind: Deployment\nspec: {}\n";
        let (_, defs) = run(Language::K8S, src, "bad.yaml");
        assert!(defs.is_empty());
        // No kind.
        let src2 = "metadata:\n  name: x\n";
        let (_, defs2) = run(Language::K8S, src2, "bad2.yaml");
        assert!(defs2.is_empty());
    }

    #[test]
    fn other_languages_noop() {
        let (_, defs) = run(Language::YAML, "kind: X", "f.yaml");
        assert!(defs.is_empty());
    }
}
