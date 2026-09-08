//! minhash.rs — 1:1 rewrite of `src/simhash/minhash.{c,h}`.
//!
//! Structural function fingerprinting: collect normalised leaf-token
//! trigrams from an AST body, hash them with XXH3 (seeded, weighted),
//! and emit a K=64 MinHash signature. Two bodies whose signatures agree
//! on ≥ JACCARD_THRESHOLD of the slots are near-duplicates.

use std::collections::HashSet;

pub const MINHASH_K: usize = 64;
pub const MINHASH_MIN_NODES: usize = 30;
pub const MINHASH_JACCARD_THRESHOLD: f64 = 0.95;
pub const MINHASH_MAX_EDGES_PER_NODE: usize = 10;
pub const LSH_BANDS: usize = 32;
pub const LSH_ROWS: usize = 2;
pub const HEX_BUF: usize = MINHASH_K * 8 + 1;

/// MinHash signature (C cbm_minhash_t).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinHash {
    pub values: [u32; MINHASH_K],
}

impl Default for MinHash {
    fn default() -> Self {
        MinHash {
            values: [u32::MAX; MINHASH_K],
        }
    }
}

const AST_WALK_CAP: usize = 2048;
const TRIGRAM_WINDOW: usize = 2;
const MIN_UNIQUE_TRIGRAMS: usize = 32;
const MAX_STRUCTURAL_WEIGHT: u64 = 3;
const UNIQ_SET_SIZE: usize = 4096;
const TRIGRAM_BUF_LEN: usize = 160;
const MAX_TOKENS: usize = 4096;

fn is_identifier_type(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "field_identifier"
            | "property_identifier"
            | "type_identifier"
            | "shorthand_property_identifier"
            | "shorthand_field_identifier"
            | "variable_name"
            | "name"
    )
}

fn is_string_type(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "template_string"
            | "string_content"
            | "escape_sequence"
    )
}

fn is_number_type(kind: &str) -> bool {
    matches!(
        kind,
        "number"
            | "integer"
            | "float"
            | "integer_literal"
            | "float_literal"
            | "int_literal"
            | "number_literal"
    )
}

fn is_type_annotation(kind: &str) -> bool {
    matches!(
        kind,
        "type_identifier"
            | "predefined_type"
            | "primitive_type"
            | "builtin_type"
            | "type_annotation"
            | "simple_type"
    )
}

/// Normalise a node type to a short canonical token (C normalise_node_type).
fn normalise_node_type(kind: &str) -> &str {
    if is_identifier_type(kind) {
        return "I";
    }
    if is_string_type(kind) {
        return "S";
    }
    if is_number_type(kind) {
        return "N";
    }
    if is_type_annotation(kind) {
        return "T";
    }
    kind
}

/// Phase 1: walk the AST iteratively, collecting normalised LEAF token
/// types. Leaf-only counting is language-agnostic.
fn collect_ast_tokens(root: tree_sitter::Node<'_>) -> Vec<&'static str> {
    let mut tokens = Vec::with_capacity(256);
    let mut stack = Vec::with_capacity(AST_WALK_CAP.min(64));
    stack.push(root);
    while let Some(node) = stack.pop() {
        if tokens.len() >= MAX_TOKENS {
            break;
        }
        let child_count = node.child_count();
        if child_count == 0 {
            let kind = node.kind();
            if !kind.is_empty() {
                // SAFETY of lifetime: node kinds are 'static grammar strings.
                tokens.push(normalise_node_type(kind));
            }
        } else {
            for i in (0..child_count).rev() {
                if stack.len() >= AST_WALK_CAP {
                    break;
                }
                stack.push(node.child(i).unwrap());
            }
        }
    }
    tokens
}

/// Weight of a trigram: count of non-normalised tokens (0–3). 0 = pure
/// data manipulation (noise), 3 = rich control flow (signal).
fn trigram_structural_weight(a: &str, b: &str, c: &str) -> u64 {
    let mut w = 0;
    for t in [a, b, c] {
        if !(t.len() == 1 && matches!(t, "I" | "S" | "N" | "T")) {
            w += 1;
        }
    }
    w
}

/// Phase 2: hash trigrams into the signature with structural weighting;
/// returns the unique-trigram count.
fn hash_trigrams(tokens: &[&'static str], out: &mut MinHash) -> usize {
    let mut uniq: HashSet<u64> = HashSet::with_capacity(UNIQ_SET_SIZE);
    for i in 0..tokens.len().saturating_sub(TRIGRAM_WINDOW) {
        let (a, b, c) = (tokens[i], tokens[i + 1], tokens[i + 2]);
        let w = trigram_structural_weight(a, b, c);
        if w == 0 {
            continue;
        }
        let trigram = format!("{a}|{b}|{c}");
        if trigram.len() >= TRIGRAM_BUF_LEN {
            continue;
        }
        uniq.insert(xxhash_rust::xxh3::xxh3_64(trigram.as_bytes()));
        // Weighted MinHash: hash w times per seed.
        for k in 0..MINHASH_K {
            for rep in 0..w {
                let seed = (k as u64 * MAX_STRUCTURAL_WEIGHT) + rep;
                let h = xxhash_rust::xxh3::xxh3_64_with_seed(trigram.as_bytes(), seed);
                let h32 = (h & 0xFFFF_FFFF) as u32;
                if h32 < out.values[k] {
                    out.values[k] = h32;
                }
            }
        }
    }
    uniq.len()
}

/// Compute from a parse-tree body node (C cbm_minhash_compute). Returns
/// None when the body is too short or has too few unique trigrams.
pub fn compute(func_body: tree_sitter::Node<'_>) -> Option<MinHash> {
    let tokens = collect_ast_tokens(func_body);
    if tokens.len() < MINHASH_MIN_NODES {
        return None;
    }
    let mut out = MinHash::default();
    let unique = hash_trigrams(&tokens, &mut out);
    if unique < MIN_UNIQUE_TRIGRAMS {
        return None;
    }
    Some(out)
}

/// Jaccard similarity estimate: fraction of matching slots.
pub fn jaccard(a: &MinHash, b: &MinHash) -> f64 {
    let matching = a
        .values
        .iter()
        .zip(b.values.iter())
        .filter(|(x, y)| x == y)
        .count();
    matching as f64 / MINHASH_K as f64
}

/// Hex encoding (8 chars per u32).
pub fn to_hex(fp: &MinHash) -> String {
    fp.values.iter().map(|v| format!("{v:08x}")).collect()
}

pub fn from_hex(hex: &str) -> Option<MinHash> {
    if hex.len() < HEX_BUF - 1 {
        return None;
    }
    let mut out = MinHash::default();
    for (i, v) in out.values.iter_mut().enumerate() {
        let chunk = &hex[i * 8..(i + 1) * 8];
        *v = u32::from_str_radix(chunk, 16).ok()?;
    }
    Some(out)
}

/// LSH band key: hash one band of R consecutive slots (C LSH scheme).
pub fn band_key(fp: &MinHash, band: usize) -> u64 {
    let start = band * LSH_ROWS;
    let mut h: u64 = 0xcbf29ce484222325;
    for v in &fp.values[start..start + LSH_ROWS] {
        h ^= *v as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fn(src: &str) -> tree_sitter::Tree {
        crate::ts::parse(crate::Language::PYTHON, src).expect("py grammar")
    }

    fn body_of<'t>(tree: &'t tree_sitter::Tree) -> tree_sitter::Node<'t> {
        // Walk the whole tree pre-order, first `block` wins.
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "block" {
                return node;
            }
            for i in (0..node.child_count()).rev() {
                stack.push(node.child(i).unwrap());
            }
        }
        tree.root_node()
    }

    #[test]
    fn short_body_gets_no_fingerprint() {
        let tree = parse_fn("def f():\n    pass\n");
        let body = body_of(&tree);
        assert!(compute(body).is_none(), "pass-only body is too short");
    }

    #[test]
    fn substantial_body_gets_fingerprint() {
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
        let tree = parse_fn(src);
        let body = body_of(&tree);
        let fp = compute(body).expect("fingerprint");
        assert_eq!(
            fp.values.iter().filter(|v| **v != u32::MAX).count(),
            MINHASH_K
        );
    }

    #[test]
    fn identical_bodies_match() {
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
        let t1 = parse_fn(src);
        let t2 = parse_fn(src);
        let fp1 = compute(body_of(&t1)).unwrap();
        let fp2 = compute(body_of(&t2)).unwrap();
        assert!(jaccard(&fp1, &fp2) >= MINHASH_JACCARD_THRESHOLD);
        assert_eq!(to_hex(&fp1), to_hex(&fp2));
    }

    #[test]
    fn hex_roundtrip() {
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
        let tree = parse_fn(src);
        let fp = compute(body_of(&tree)).unwrap();
        let hex = to_hex(&fp);
        assert_eq!(hex.len(), HEX_BUF - 1);
        let back = from_hex(&hex).unwrap();
        assert_eq!(back, fp);
    }

    #[test]
    fn band_keys_differ_across_bands() {
        let mut fp = MinHash::default();
        for (i, v) in fp.values.iter_mut().enumerate() {
            *v = ((i as u64) * 2654435761 % 1000) as u32;
        }
        let k0 = band_key(&fp, 0);
        let k1 = band_key(&fp, 1);
        assert_ne!(k0, k1);
    }
}
