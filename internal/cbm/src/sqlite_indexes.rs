//! sqlite_indexes.rs — part 4 of the sqlite_writer rewrite: index record
//! builders, the sort permutations (C make_sorted_perm + the
//! cmp_node_by_* / cmp_edge_by_* comparators), index overflow spilling
//! (C overflowize_index_cell), and the index B-tree writer
//! (C write_index_btree / write_empty_index_leaf).
//!
//! Ordering contract: every comparator is a total order (it ends in the
//! row id), so the serial sorts here produce byte-identical page layout to
//! the C's parallel qsort permutations.

use std::cmp::Ordering;
use std::fs::File;

use crate::page_builder::{write_empty_leaf_page, write_overflow_chain, PageBuilder};
use crate::sqlite_writer::{
    put_u32, put_varint, skip_pending_byte, DumpEdge, DumpNode, RecordBuilder, BTREE_PTR_SIZE,
    CBM_PAGE_SIZE, VARINT_BUF_SIZE,
};

// ── Index overflow thresholds (C defines) ───────────────────────

/// Index interior/leaf pages use smaller max_local than tables
/// (PAGE_SIZE=65536, reserved=0).
pub const INDEX_OVERFLOW_MAX_LOCAL: usize = 16422;
pub const INDEX_OVERFLOW_MIN_LOCAL: usize = 8199;

// ── Varint decoding (C get_varint) ──────────────────────────────

/// Read a SQLite varint (1-9 bytes, big-endian 7-bit groups, 9th byte uses
/// all 8 bits). Returns (value, bytes consumed).
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for (i, &b) in buf.iter().take(8).enumerate() {
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    if buf.len() < 9 {
        return None;
    }
    v = (v << 8) | buf[8] as u64;
    Some((v, 9))
}

// ── Index cell builders ─────────────────────────────────────────

/// Index cell wrapper: varint(payload_len) + payload(record) — index cells
/// carry no rowid prefix (the rowid is the record's last column).
pub fn build_index_cell(record: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(record.len() + VARINT_BUF_SIZE);
    let mut tmp = [0u8; VARINT_BUF_SIZE];
    let n = put_varint(&mut tmp, record.len() as i64);
    out.extend_from_slice(&tmp[..n]);
    out.extend_from_slice(&record);
    out
}

/// (int, text) + rowid — idx_edges_source / idx_edges_target.
fn index_cell_int_text_rowid(val: i64, text: &str, rowid: i64) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_int(val);
    r.add_text(text);
    r.add_int(rowid);
    build_index_cell(r.finalize())
}

/// (text, text) + rowid — idx_nodes_* and idx_edges_type.
fn index_cell_2text_rowid(t1: &str, t2: &str, rowid: i64) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_text(t1);
    r.add_text(t2);
    r.add_int(rowid);
    build_index_cell(r.finalize())
}

/// (text, int, text) + rowid — idx_edges_target_type / idx_edges_source_type.
fn index_cell_text_int_text_rowid(t1: &str, val: i64, t2: &str, rowid: i64) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_text(t1);
    r.add_int(val);
    r.add_text(t2);
    r.add_int(rowid);
    build_index_cell(r.finalize())
}

/// UNIQUE (int, int, text, text) + rowid — sqlite_autoindex_edges_1 over
/// (source_id, target_id, type, local_name_gen) (#768).
fn index_cell_unique_2int_2text_rowid(
    v1: i64,
    v2: i64,
    text: &str,
    text2: &str,
    rowid: i64,
) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_int(v1);
    r.add_int(v2);
    r.add_text(text);
    r.add_text(text2);
    r.add_int(rowid);
    build_index_cell(r.finalize())
}

/// (project, url_path|null) + rowid — idx_edges_url_path. An empty url_path
/// column becomes SQL NULL (json_extract of a missing key), and NULL sorts
/// before every text value.
fn index_cell_url_path(e: &DumpEdge) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_text(&e.project);
    if e.url_path.is_empty() {
        r.add_null();
    } else {
        r.add_text(&e.url_path);
    }
    r.add_int(e.id);
    build_index_cell(r.finalize())
}

// ── Sort permutations (C make_sorted_perm + comparators) ────────

/// Sorted permutation [0..n) under `cmp` (C make_sorted_perm).
fn sorted_perm<T>(items: &[T], cmp: impl Fn(&T, &T) -> Ordering) -> Vec<u32> {
    let mut perm: Vec<u32> = (0..items.len() as u32).collect();
    perm.sort_by(|&a, &b| cmp(&items[a as usize], &items[b as usize]));
    perm
}

// Node comparators (C cmp_node_by_*): text column, then row id.
fn cmp_node_label(a: &DumpNode, b: &DumpNode) -> Ordering {
    a.label.cmp(&b.label).then(a.id.cmp(&b.id))
}
fn cmp_node_name(a: &DumpNode, b: &DumpNode) -> Ordering {
    a.name.cmp(&b.name).then(a.id.cmp(&b.id))
}
fn cmp_node_file(a: &DumpNode, b: &DumpNode) -> Ordering {
    a.file_path.cmp(&b.file_path).then(a.id.cmp(&b.id))
}
fn cmp_node_qn(a: &DumpNode, b: &DumpNode) -> Ordering {
    a.qualified_name
        .cmp(&b.qualified_name)
        .then(a.id.cmp(&b.id))
}

// Edge comparators (C cmp_edge_by_*).
fn cmp_edge_source_type(a: &DumpEdge, b: &DumpEdge) -> Ordering {
    a.source_id
        .cmp(&b.source_id)
        .then(a.type_.cmp(&b.type_))
        .then(a.id.cmp(&b.id))
}
fn cmp_edge_target_type(a: &DumpEdge, b: &DumpEdge) -> Ordering {
    a.target_id
        .cmp(&b.target_id)
        .then(a.type_.cmp(&b.type_))
        .then(a.id.cmp(&b.id))
}
fn cmp_edge_type(a: &DumpEdge, b: &DumpEdge) -> Ordering {
    // C sorts by type alone (the project column rides along in the cell).
    a.type_.cmp(&b.type_).then(a.id.cmp(&b.id))
}
fn cmp_edge_proj_target_type(a: &DumpEdge, b: &DumpEdge) -> Ordering {
    a.target_id
        .cmp(&b.target_id)
        .then(a.type_.cmp(&b.type_))
        .then(a.id.cmp(&b.id))
}
fn cmp_edge_proj_source_type(a: &DumpEdge, b: &DumpEdge) -> Ordering {
    a.source_id
        .cmp(&b.source_id)
        .then(a.type_.cmp(&b.type_))
        .then(a.id.cmp(&b.id))
}
fn cmp_edge_url_path(a: &DumpEdge, b: &DumpEdge) -> Ordering {
    // Empty url_path == NULL column → sorts FIRST (C returns CBM_NOT_FOUND
    // for a-empty, SERIAL_SIZE_INT8 (1) for b-empty).
    let na = a.url_path.is_empty();
    let nb = b.url_path.is_empty();
    if na && nb {
        return a.id.cmp(&b.id);
    }
    if na {
        return Ordering::Less;
    }
    if nb {
        return Ordering::Greater;
    }
    a.url_path.cmp(&b.url_path).then(a.id.cmp(&b.id))
}
fn cmp_edge_src_tgt_type(a: &DumpEdge, b: &DumpEdge) -> Ordering {
    a.source_id
        .cmp(&b.source_id)
        .then(a.target_id.cmp(&b.target_id))
        .then(a.type_.cmp(&b.type_))
        .then(a.local_name.cmp(&b.local_name))
        .then(a.id.cmp(&b.id))
}

// ── Index overflow spilling (C overflowize_index_cell) ──────────

/// Spill an oversized index cell's payload tail to overflow pages BEFORE
/// page building so every cell added to a leaf is within the local-payload
/// limit: varint(payload_len) + payload[..local) + u32(first_ovfl).
fn overflowize_index_cell(
    file: &mut File,
    next_page: &mut u32,
    cell: &[u8],
) -> std::io::Result<Vec<u8>> {
    let Some((plen, vlen)) = get_varint(cell) else {
        return Ok(cell.to_vec());
    };
    if plen <= INDEX_OVERFLOW_MAX_LOCAL as u64 {
        return Ok(cell.to_vec());
    }
    let per_ovfl = (CBM_PAGE_SIZE - BTREE_PTR_SIZE as u32) as i64;
    let k = INDEX_OVERFLOW_MIN_LOCAL as i64
        + ((plen as i64 - INDEX_OVERFLOW_MIN_LOCAL as i64) % per_ovfl);
    let local = if k <= INDEX_OVERFLOW_MAX_LOCAL as i64 {
        k as usize
    } else {
        INDEX_OVERFLOW_MIN_LOCAL
    };
    let end = vlen + plen as usize;
    let first_ovfl = write_overflow_chain(file, next_page, &cell[vlen + local..end])?;
    let mut out = Vec::with_capacity(vlen + local + BTREE_PTR_SIZE);
    out.extend_from_slice(&cell[..vlen + local]);
    let mut ptr = [0u8; BTREE_PTR_SIZE];
    put_u32(&mut ptr, first_ovfl);
    out.extend_from_slice(&ptr);
    Ok(out)
}

// ── Index B-tree writer (C write_index_btree) ───────────────────

/// Write an empty index leaf page (C write_empty_index_leaf): the page
/// starts with 0x0A (the C's NEWLINE_BYTE constant — ASCII '\n' doubles as
/// the index-leaf b-tree flag).
pub fn write_empty_index_leaf(file: &mut File, next_page: &mut u32) -> std::io::Result<u32> {
    *next_page = skip_pending_byte(*next_page);
    let pnum = *next_page;
    *next_page += 1;
    write_empty_leaf_page(file, pnum, true)?;
    Ok(pnum)
}

/// Write an index B-tree from presorted cells; returns the root page
/// (C write_index_btree). Empty input allocates a single empty index leaf.
pub fn write_index_btree(
    file: &mut File,
    next_page: &mut u32,
    cells: &[Vec<u8>],
) -> std::io::Result<u32> {
    if cells.is_empty() {
        return write_empty_index_leaf(file, next_page);
    }

    // Spill oversized index payloads BEFORE page building so every cell
    // added below is within the local-payload limit. Overflow pages are
    // allocated ahead of the leaf pages — page order is arbitrary.
    let mut spilled: Vec<Vec<u8>> = Vec::with_capacity(cells.len());
    for cell in cells {
        spilled.push(overflowize_index_cell(file, next_page, cell)?);
    }

    let mut pb = PageBuilder::open_index(file, *next_page)?;
    for (i, cell) in spilled.iter().enumerate() {
        if !pb.cell_fits(cell.len()) {
            if pb.cell_count() > 0 {
                // Promote the previous cell to the interior separator.
                pb.promote_and_flush(&spilled[i - 1])?;
            }
            // After flush, an oversized cell still doesn't fit an empty
            // page: index cells larger than a full page can never be
            // stored; skip them (C prints and continues).
            if !pb.cell_fits(cell.len()) {
                eprintln!(
                    "cbm_write_db: index cell oversized, skipped len={} idx={}",
                    cell.len(),
                    i
                );
                continue;
            }
        }
        pb.add_index_cell(cell);
    }

    if pb.cell_count() > 0 {
        // Trailing leaf keeps its last cell inline (rightmost child's
        // separator is never referenced as an interior key).
        let last = spilled.len() - 1;
        pb.flush_leaf_with_sep(&spilled[last])?;
    }

    // C: *next_page = pb.next_page — the builder's cursor wins.
    let (root, np) = pb.finalize_index()?;
    *next_page = np;
    Ok(root)
}

// ── Per-index builders (C build_node_index_sorted / build_edge_index_sorted)
// ──

/// One node index B-tree: (project, col) + rowid cells in sorted order.
fn build_node_index_sorted(
    file: &mut File,
    next_page: &mut u32,
    nodes: &[DumpNode],
    perm: &[u32],
    col: impl Fn(&DumpNode) -> &str,
) -> std::io::Result<u32> {
    if nodes.is_empty() {
        return write_index_btree(file, next_page, &[]);
    }
    let cells: Vec<Vec<u8>> = perm
        .iter()
        .map(|&si| {
            let n = &nodes[si as usize];
            index_cell_2text_rowid(&n.project, col(n), n.id)
        })
        .collect();
    write_index_btree(file, next_page, &cells)
}

/// One edge index B-tree from a cell-builder closure.
fn build_edge_index_sorted(
    file: &mut File,
    next_page: &mut u32,
    edges: &[DumpEdge],
    perm: &[u32],
    cell_fn: impl Fn(&DumpEdge) -> Vec<u8>,
) -> std::io::Result<u32> {
    if edges.is_empty() {
        return write_index_btree(file, next_page, &[]);
    }
    let cells: Vec<Vec<u8>> = perm
        .iter()
        .map(|&si| cell_fn(&edges[si as usize]))
        .collect();
    write_index_btree(file, next_page, &cells)
}

// ── Full index suites (C build_node_indexes / build_edge_indexes) ──

/// Root pages of the 4 node indexes (C build_node_indexes outputs).
#[derive(Debug, Clone, Copy)]
pub struct NodeIndexRoots {
    pub idx_nodes_label: u32,
    pub idx_nodes_name: u32,
    pub idx_nodes_file: u32,
    /// sqlite_autoindex_nodes_1 over UNIQUE(project, qualified_name).
    pub autoindex_nodes: u32,
}

/// Sort + write all 4 node index B-trees. The C sorts the 4 permutations on
/// parallel threads (parallel_sort_indexes); the comparators are total
/// orders, so serial sorting yields identical page layout.
pub fn build_node_indexes(
    file: &mut File,
    next_page: &mut u32,
    nodes: &[DumpNode],
) -> std::io::Result<NodeIndexRoots> {
    let p_label = sorted_perm(nodes, cmp_node_label);
    let p_name = sorted_perm(nodes, cmp_node_name);
    let p_file = sorted_perm(nodes, cmp_node_file);
    let p_qn = sorted_perm(nodes, cmp_node_qn);
    Ok(NodeIndexRoots {
        idx_nodes_label: build_node_index_sorted(file, next_page, nodes, &p_label, |n| &n.label)?,
        idx_nodes_name: build_node_index_sorted(file, next_page, nodes, &p_name, |n| &n.name)?,
        idx_nodes_file: build_node_index_sorted(file, next_page, nodes, &p_file, |n| &n.file_path)?,
        autoindex_nodes: build_node_index_sorted(file, next_page, nodes, &p_qn, |n| {
            &n.qualified_name
        })?,
    })
}

/// Root pages of the 7 edge indexes (C build_edge_indexes outputs).
#[derive(Debug, Clone, Copy)]
pub struct EdgeIndexRoots {
    pub idx_edges_source: u32,
    pub idx_edges_target: u32,
    pub idx_edges_type: u32,
    pub idx_edges_target_type: u32,
    pub idx_edges_source_type: u32,
    pub idx_edges_url_path: u32,
    /// sqlite_autoindex_edges_1 over UNIQUE(source_id, target_id, type,
    /// local_name_gen) (#768).
    pub autoindex_edges: u32,
}

/// Sort + write all 7 edge index B-trees.
pub fn build_edge_indexes(
    file: &mut File,
    next_page: &mut u32,
    edges: &[DumpEdge],
) -> std::io::Result<EdgeIndexRoots> {
    let p_source = sorted_perm(edges, cmp_edge_source_type);
    let p_target = sorted_perm(edges, cmp_edge_target_type);
    let p_type = sorted_perm(edges, cmp_edge_type);
    let p_tgt_type = sorted_perm(edges, cmp_edge_proj_target_type);
    let p_src_type = sorted_perm(edges, cmp_edge_proj_source_type);
    let p_url = sorted_perm(edges, cmp_edge_url_path);
    let p_auto = sorted_perm(edges, cmp_edge_src_tgt_type);
    Ok(EdgeIndexRoots {
        idx_edges_source: build_edge_index_sorted(file, next_page, edges, &p_source, |e| {
            index_cell_int_text_rowid(e.source_id, &e.type_, e.id)
        })?,
        idx_edges_target: build_edge_index_sorted(file, next_page, edges, &p_target, |e| {
            index_cell_int_text_rowid(e.target_id, &e.type_, e.id)
        })?,
        idx_edges_type: build_edge_index_sorted(file, next_page, edges, &p_type, |e| {
            index_cell_2text_rowid(&e.project, &e.type_, e.id)
        })?,
        idx_edges_target_type: build_edge_index_sorted(file, next_page, edges, &p_tgt_type, |e| {
            index_cell_text_int_text_rowid(&e.project, e.target_id, &e.type_, e.id)
        })?,
        idx_edges_source_type: build_edge_index_sorted(file, next_page, edges, &p_src_type, |e| {
            index_cell_text_int_text_rowid(&e.project, e.source_id, &e.type_, e.id)
        })?,
        idx_edges_url_path: build_edge_index_sorted(file, next_page, edges, &p_url, |e| {
            index_cell_url_path(e)
        })?,
        autoindex_edges: build_edge_index_sorted(file, next_page, edges, &p_auto, |e| {
            index_cell_unique_2int_2text_rowid(
                e.source_id,
                e.target_id,
                &e.type_,
                &e.local_name,
                e.id,
            )
        })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file() -> (File, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!(
            "cbm-idx-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
            .unwrap();
        (f, p)
    }

    fn node(id: i64, label: &str, qn: &str) -> DumpNode {
        DumpNode {
            id,
            project: "proj".into(),
            label: label.into(),
            name: qn.into(),
            qualified_name: format!("proj.{qn}"),
            file_path: "a.go".into(),
            start_line: 1,
            end_line: 2,
            properties: "{}".into(),
        }
    }

    fn edge(id: i64, src: i64, tgt: i64, ty: &str) -> DumpEdge {
        DumpEdge {
            id,
            project: "proj".into(),
            source_id: src,
            target_id: tgt,
            type_: ty.into(),
            properties: "{}".into(),
            url_path: String::new(),
            local_name: String::new(),
        }
    }

    #[test]
    fn get_varint_roundtrip() {
        let mut buf = [0u8; VARINT_BUF_SIZE];
        // Round-trip values up to 2^56-1 (the 8-byte varint path; the 9th
        // byte in SQLite's format carries the high 8 bits and only matters
        // for non-canonical encodings above 2^56).
        for v in [0u64, 1, 127, 128, 16383, 16384, (1u64 << 56) - 1] {
            let n = put_varint(&mut buf, v as i64);
            let (dec, used) = get_varint(&buf[..n]).unwrap();
            assert_eq!(dec, v, "v={v}");
            assert_eq!(used, n);
        }
        assert!(get_varint(&[]).is_none());
    }

    #[test]
    fn index_cell_layout() {
        let cell = index_cell_2text_rowid("proj", "Function", 7);
        // varint(payload_len) then payload; decode via get_varint.
        let (plen, vlen) = get_varint(&cell).unwrap();
        assert_eq!(cell.len(), vlen + plen as usize);
        // Payload ends with the rowid byte 7.
        assert_eq!(cell[cell.len() - 1], 7);
    }

    #[test]
    fn empty_index_btree_allocates_leaf() {
        let (mut f, path) = temp_file();
        let mut next = crate::sqlite_writer::FIRST_DATA_PAGE;
        let root = write_index_btree(&mut f, &mut next, &[]).unwrap();
        assert_eq!(root, crate::sqlite_writer::FIRST_DATA_PAGE);
        assert_eq!(next, root + 1);
        let bytes = std::fs::read(&path).unwrap();
        let off = (root - 1) as usize * CBM_PAGE_SIZE as usize;
        assert_eq!(bytes[off], 0x0A);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn small_index_single_leaf() {
        let (mut f, path) = temp_file();
        let mut next = crate::sqlite_writer::FIRST_DATA_PAGE;
        let cells: Vec<Vec<u8>> = (1..=10)
            .map(|i| index_cell_2text_rowid("proj", &format!("sym{i}"), i))
            .collect();
        let root = write_index_btree(&mut f, &mut next, &cells).unwrap();
        // 10 tiny cells fit one 64K leaf.
        assert_eq!(root, crate::sqlite_writer::FIRST_DATA_PAGE);
        let bytes = std::fs::read(&path).unwrap();
        let off = (root - 1) as usize * CBM_PAGE_SIZE as usize;
        assert_eq!(bytes[off], 0x0A); // index leaf
        assert_eq!(bytes[off + 4], 10); // cell count low byte
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn multi_leaf_index_promotes_separators() {
        let (mut f, path) = temp_file();
        let mut next = crate::sqlite_writer::FIRST_DATA_PAGE;
        // ~30KB payload per cell → 2 cells per 64K page → several leaves.
        let big = "x".repeat(30_000);
        let cells: Vec<Vec<u8>> = (1..=8)
            .map(|i| index_cell_2text_rowid("proj", &format!("{big}{i}"), i))
            .collect();
        let root = write_index_btree(&mut f, &mut next, &cells).unwrap();
        // 8 cells / 2 per page → 4+ leaves → interior root above the leaves.
        assert!(root > 4, "root={root}");
        let bytes = std::fs::read(&path).unwrap();
        // Root page must be an index interior (0x02).
        let off = (root - 1) as usize * CBM_PAGE_SIZE as usize;
        assert_eq!(bytes[off], 0x02);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn url_path_empty_sorts_first() {
        let a = edge(1, 1, 2, "IMPORTS");
        let mut b = edge(2, 1, 3, "IMPORTS");
        b.url_path = "/x".into();
        // Empty (NULL) url sorts BEFORE any text.
        assert_eq!(cmp_edge_url_path(&a, &b), Ordering::Less);
        assert_eq!(cmp_edge_url_path(&b, &a), Ordering::Greater);
    }

    #[test]
    fn node_indexes_full_suite() {
        let (mut f, path) = temp_file();
        let mut next = crate::sqlite_writer::FIRST_DATA_PAGE;
        let nodes: Vec<DumpNode> = (1..=50)
            .map(|i| node(i, &format!("Label{}", i % 7), &format!("qn{i}")))
            .collect();
        let roots = build_node_indexes(&mut f, &mut next, &nodes).unwrap();
        // All four roots are real pages (small indexes → single leaf each);
        // they must be distinct, strictly increasing allocations.
        assert!(roots.idx_nodes_label >= 2);
        assert!(roots.idx_nodes_name > roots.idx_nodes_label);
        assert!(roots.idx_nodes_file > roots.idx_nodes_name);
        assert!(roots.autoindex_nodes > roots.idx_nodes_file);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn edge_indexes_full_suite() {
        let (mut f, path) = temp_file();
        let mut next = crate::sqlite_writer::FIRST_DATA_PAGE;
        let edges: Vec<DumpEdge> = (1..=50)
            .map(|i| {
                let mut e = edge(
                    i,
                    i % 10,
                    i % 13 + 1,
                    if i % 2 == 0 { "CALLS" } else { "IMPORTS" },
                );
                if i % 5 == 0 {
                    e.url_path = format!("/api/func{i}");
                }
                e
            })
            .collect();
        let roots = build_edge_indexes(&mut f, &mut next, &edges).unwrap();
        assert!(roots.idx_edges_source >= 2);
        assert!(roots.autoindex_edges > roots.idx_edges_source);
        assert!(roots.idx_edges_url_path > roots.idx_edges_source_type);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn oversized_index_cell_spills_to_overflow() {
        let (mut f, path) = temp_file();
        let mut next = crate::sqlite_writer::FIRST_DATA_PAGE;
        // A cell whose record exceeds INDEX_OVERFLOW_MAX_LOCAL (16422).
        let big = "y".repeat(INDEX_OVERFLOW_MAX_LOCAL + 5000);
        let cells = vec![index_cell_2text_rowid("proj", &big, 1)];
        let root = write_index_btree(&mut f, &mut next, &cells).unwrap();
        // Cell spilled → at least one overflow page was allocated before
        // the leaf; root is the leaf page.
        assert!(root >= 3, "root={root}");
        let bytes = std::fs::read(&path).unwrap();
        // Overflow page 2 exists and starts with a backpatchable pointer.
        let off = CBM_PAGE_SIZE as usize;
        assert_eq!(bytes[off], 0);
        std::fs::remove_file(&path).ok();
    }
}
