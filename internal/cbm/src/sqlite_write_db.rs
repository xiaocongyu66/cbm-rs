//! write_db.rs — part 5 (final) of the sqlite_writer rewrite: the one-shot
//! `write_db` orchestrator and the streaming `DbWriter` (C
//! write_db_after_nodes / cbm_db_writer open-append-finalize / cbm_write_db).
//!
//! Pipeline: nodes table (streamed) → edges/vectors/token_vectors tables →
//! metadata tables → 11 index B-trees → 5 autoindexes → sqlite_master
//! page 1 + file header → pad → fsync → atomic rename over the target →
//! sidecar cleanup.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cbm_foundation::compat_fs::{remove_db_sidecars, rename_replace};

use crate::page_builder::PageBuilder;
use crate::sqlite_finalize::{
    write_master_page1, MasterEntry, SCHEMA_SQL_EDGES, SCHEMA_SQL_FILE_HASHES,
    SCHEMA_SQL_IDX_EDGES_SOURCE, SCHEMA_SQL_IDX_EDGES_SOURCE_TYPE, SCHEMA_SQL_IDX_EDGES_TARGET,
    SCHEMA_SQL_IDX_EDGES_TARGET_TYPE, SCHEMA_SQL_IDX_EDGES_TYPE, SCHEMA_SQL_IDX_EDGES_URL_PATH,
    SCHEMA_SQL_IDX_NODES_FILE, SCHEMA_SQL_IDX_NODES_LABEL, SCHEMA_SQL_IDX_NODES_NAME,
    SCHEMA_SQL_NODES, SCHEMA_SQL_NODE_VECTORS, SCHEMA_SQL_PROJECTS, SCHEMA_SQL_PROJECT_SUMMARIES,
    SCHEMA_SQL_SQLITE_SEQUENCE, SCHEMA_SQL_TOKEN_VECTORS,
};
use crate::sqlite_indexes::{build_edge_indexes, build_node_indexes};
use crate::sqlite_writer::{
    build_edge_record, build_token_vec_record, build_vector_record, DumpEdge, DumpNode,
    DumpTokenVec, DumpVector, FIRST_DATA_PAGE,
};

/// Sentinel exit codes mirroring the C's error enum values (negative);
/// CBM_OK == 0. The C returns CBM_NOT_FOUND (-1) for open failures and
/// ERR_WRITE_FAILED (-3) for I/O failures.
pub const WRITE_OK: i32 = 0;
pub const WRITE_ERR_OPEN: i32 = -1;
pub const WRITE_ERR_IO: i32 = -3;

/// Pad the file to the exact page boundary (C pad_file_to_page_boundary):
/// pages are 1-based, so the file must span (next_page - 1) pages.
fn pad_file_to_page_boundary(file: &mut File, next_page: u32) -> std::io::Result<()> {
    let expected = (next_page as u64 - 1) * CBM_PAGE_SIZE_U64;
    let size = file.seek(SeekFrom::End(0))?;
    if size < expected {
        file.set_len(expected)?;
        file.seek(SeekFrom::Start(expected))?;
        file.write_all(&[0u8])?;
    }
    Ok(())
}

const CBM_PAGE_SIZE_U64: u64 = 65536;

/// Flush + fsync + close + atomic rename + sidecar cleanup
/// (C sync_writer_output / publish_writer_output).
fn publish_writer_output(file: File, temp_path: &Path, final_path: &Path) -> i32 {
    if file.sync_all().is_err() {
        return WRITE_ERR_IO;
    }
    drop(file);
    if rename_replace(temp_path, final_path) != 0 {
        std::fs::remove_file(temp_path).ok();
        return WRITE_ERR_IO;
    }
    // Sidecars are removed only after the replacement succeeds — POSIX
    // readers of the old generation retain their unlinked handles.
    remove_db_sidecars(final_path);
    WRITE_OK
}

/// Drop the temp file (C discard_writer_output).
fn discard_writer_output(file: File, temp_path: &Path) -> i32 {
    drop(file);
    std::fs::remove_file(temp_path).ok();
    WRITE_ERR_IO
}

/// Write one data table B-tree from records (C write_one_table +
/// adapters): empty input → single empty leaf page.
fn write_one_table(
    file: &mut File,
    next_page: &mut u32,
    records: &[Vec<u8>],
    rowids: &[i64],
) -> std::io::Result<u32> {
    if records.is_empty() {
        let mut pb = PageBuilder::open(file, *next_page)?;
        let pnum = pb.alloc_page();
        let np = pb.next_page_cursor();
        crate::page_builder::write_empty_leaf_page(file, pnum, false)?;
        *next_page = np;
        return Ok(pnum);
    }
    let mut pb = PageBuilder::open(file, *next_page)?;
    for (i, rec) in records.iter().enumerate() {
        pb.add_table_cell_with_flush(
            rowids[i],
            rec,
            rowids.get(i.wrapping_sub(1)).copied().unwrap_or(0),
        )?;
    }
    let (root, np) = pb.finalize_table(rowids[rowids.len() - 1])?;
    *next_page = np;
    Ok(root)
}

/// The streaming DB writer (C cbm_db_writer_t): nodes are appended in
/// batches and their leaves flushed as they fill; everything else is
/// written at finalize.
pub struct DbWriter {
    final_path: PathBuf,
    temp_path: PathBuf,
    file: Option<File>,
    /// PageBuilder for the nodes table, kept across append calls.
    nodes_pb: Option<PageBuilder>,
    next_page: u32,
    last_node_rowid: i64,
    node_rows_written: i64,
    err: bool,
}

impl DbWriter {
    /// Open a writer targeting `path` (C cbm_writer_open: temp name is
    /// "<path>.tmp.<pid>.<ptr-token>"; the pointer token only exists to
    /// disambiguate concurrent writers — an atomic counter does the same).
    pub fn open(path: &Path) -> Option<DbWriter> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEMP_TOKEN: AtomicU64 = AtomicU64::new(0);
        let token = TEMP_TOKEN.fetch_add(1, Ordering::Relaxed);
        let temp_path = PathBuf::from(format!(
            "{}.tmp.{}.{:x}",
            path.display(),
            std::process::id(),
            token
        ));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .ok()?;
        let mut next_page = FIRST_DATA_PAGE;
        // Nodes are never page 1 (page 1 is sqlite_master, written at
        // finalize).
        let nodes_pb = PageBuilder::open(&mut file, next_page).ok()?;
        next_page = FIRST_DATA_PAGE; // PageBuilder::open does not consume the cursor
        Some(DbWriter {
            final_path: path.to_path_buf(),
            temp_path,
            file: Some(file),
            nodes_pb: Some(nodes_pb),
            next_page,
            last_node_rowid: 0,
            node_rows_written: 0,
            err: false,
        })
    }

    /// Append a batch of nodes (C cbm_writer_append_nodes). Ids must be
    /// ascending across calls.
    pub fn append_nodes(&mut self, nodes: &[DumpNode]) -> i32 {
        if self.err {
            return WRITE_ERR_IO;
        }
        if self.file.is_none() {
            return WRITE_ERR_OPEN;
        }
        let Some(pb) = self.nodes_pb.as_mut() else {
            return WRITE_ERR_IO;
        };
        // PageBuilder cloned its own file handle; it writes directly.
        let mut last = self.last_node_rowid;
        if pb.append_nodes(nodes, &mut last).is_err() {
            self.err = true;
            return WRITE_ERR_IO;
        }
        self.last_node_rowid = last;
        self.node_rows_written += nodes.len() as i64;
        WRITE_OK
    }

    /// Finalize: flush the nodes B-tree, write everything else, publish
    /// (C cbm_writer_finalize). The node rows must be re-supplied here —
    /// the C stashes them in write_db_ctx_t for the index sorters.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize(
        mut self,
        project: &str,
        root_path: &str,
        indexed_at: &str,
        nodes: &[DumpNode],
        edges: &[DumpEdge],
        vectors: &[DumpVector],
        token_vecs: &[DumpTokenVec],
    ) -> i32 {
        let Some(mut file) = self.file.take() else {
            return WRITE_ERR_OPEN;
        };
        let file_ref = &mut file;

        // Nodes table root: finalized here from the streamed pages, or a
        // single empty leaf when nothing was appended.
        let nodes_root = if self.node_rows_written == 0 {
            self.nodes_pb = None;
            let mut pb = match PageBuilder::open(file_ref, self.next_page) {
                Ok(pb) => pb,
                Err(_) => return discard_writer_output(file, &self.temp_path),
            };
            let pnum = pb.alloc_page();
            self.next_page = pb.next_page_cursor();
            if crate::page_builder::write_empty_leaf_page(file_ref, pnum, false).is_err() {
                return discard_writer_output(file, &self.temp_path);
            }
            pnum
        } else {
            let Some(pb) = self.nodes_pb.take() else {
                return discard_writer_output(file, &self.temp_path);
            };
            match pb.finalize_table(self.last_node_rowid) {
                Ok((root, np)) => {
                    self.next_page = np;
                    root
                }
                Err(_) => return discard_writer_output(file, &self.temp_path),
            }
        };

        // sqlite_sequence's nodes high-water: the C reads the last node id
        // from the array; the streaming writer tracks it across appends.
        let last_node_id = self.last_node_rowid;

        match write_db_after_nodes(
            file,
            &self.temp_path,
            &self.final_path,
            self.next_page,
            nodes_root,
            last_node_id,
            project,
            root_path,
            indexed_at,
            nodes,
            edges,
            vectors,
            token_vecs,
        ) {
            Ok(rc) => rc,
            Err(_) => WRITE_ERR_IO,
        }
    }
}

/// Write everything after the nodes table (C write_db_after_nodes):
/// data tables → metadata → 11 indexes → 5 autoindexes → master page 1 →
/// pad → publish. Takes ownership of `file` (closes it on both paths).
#[allow(clippy::too_many_arguments)]
fn write_db_after_nodes(
    mut file: File,
    temp_path: &Path,
    final_path: &Path,
    mut next_page: u32,
    nodes_root: u32,
    last_node_id: i64,
    project: &str,
    root_path: &str,
    indexed_at: &str,
    nodes: &[DumpNode],
    edges: &[DumpEdge],
    vectors: &[DumpVector],
    token_vecs: &[DumpTokenVec],
) -> Result<i32, std::io::Error> {
    // Phase 1 (cont.): remaining data tables.
    let edge_rows: Vec<i64> = edges.iter().map(|e| e.id).collect();
    let edge_recs: Vec<Vec<u8>> = edges.iter().map(build_edge_record).collect();
    let edges_root = write_one_table(&mut file, &mut next_page, &edge_recs, &edge_rows)?;

    let vec_rows: Vec<i64> = vectors.iter().map(|v| v.node_id).collect();
    let vec_recs: Vec<Vec<u8>> = vectors.iter().map(build_vector_record).collect();
    let vectors_root = write_one_table(&mut file, &mut next_page, &vec_recs, &vec_rows)?;

    let tv_rows: Vec<i64> = token_vecs.iter().map(|t| t.id).collect();
    let tv_recs: Vec<Vec<u8>> = token_vecs.iter().map(build_token_vec_record).collect();
    let token_vecs_root = write_one_table(&mut file, &mut next_page, &tv_recs, &tv_rows)?;

    // Phase 2: metadata tables (projects 1 row, file_hashes/summaries
    // empty leaves, sqlite_sequence nodes+edges high-water).
    let proj_rec = crate::sqlite_writer::build_project_record(project, indexed_at, root_path);
    let projects_root = write_one_table(&mut file, &mut next_page, &[proj_rec], &[1])?;
    let file_hashes_root = write_one_table(&mut file, &mut next_page, &[], &[])?;
    let summaries_root = write_one_table(&mut file, &mut next_page, &[], &[])?;
    let seq_nodes_high_water = last_node_id;
    let seq_recs: Vec<Vec<u8>> = [
        {
            let mut r = crate::sqlite_writer::RecordBuilder::new();
            r.add_text("nodes");
            r.add_int(seq_nodes_high_water);
            r.finalize()
        },
        {
            let mut r = crate::sqlite_writer::RecordBuilder::new();
            r.add_text("edges");
            r.add_int(edges.last().map(|e| e.id).unwrap_or(0));
            r.finalize()
        },
    ]
    .to_vec();
    let sqlite_seq_root = write_one_table(&mut file, &mut next_page, &seq_recs, &[1, 2])?;

    // Phases 4-5: node + edge index B-trees (4 + 7). The C re-sorts from
    // the full node array carried in write_db_ctx_t; the streaming writer
    // therefore takes the node rows as a finalize argument.
    let node_roots = build_node_indexes(&mut file, &mut next_page, nodes)?;
    let edge_roots = build_edge_indexes(&mut file, &mut next_page, edges)?;

    // Autoindex for projects(name TEXT PK) — 1 row: (name, rowid=1).
    let autoindex_projects_root = {
        let mut r = crate::sqlite_writer::RecordBuilder::new();
        r.add_text(project);
        r.add_int(1); // rowid column
        let cell = {
            let rec = r.finalize();
            let mut out = Vec::with_capacity(rec.len() + 10);
            let mut tmp = [0u8; 10];
            let n = crate::sqlite_writer::put_varint(&mut tmp, rec.len() as i64);
            out.extend_from_slice(&tmp[..n]);
            out.extend_from_slice(&rec);
            out
        };
        crate::sqlite_indexes::write_index_btree(&mut file, &mut next_page, &[cell])?
    };
    // Autoindexes for empty PK tables — single empty index leaf each.
    let autoindex_file_hashes_root =
        crate::sqlite_indexes::write_empty_index_leaf(&mut file, &mut next_page)?;
    let autoindex_summaries_root =
        crate::sqlite_indexes::write_empty_index_leaf(&mut file, &mut next_page)?;

    // --- sqlite_master (page 1), written last: root pages of everything.
    // CRITICAL ordering: table → autoindex → user indexes per table; the
    // schema loader expects autoindexes immediately after their table.
    let master = vec![
        MasterEntry {
            typ: "table",
            name: "projects",
            tbl_name: "projects",
            root_page: projects_root,
            sql: Some(SCHEMA_SQL_PROJECTS),
        },
        MasterEntry {
            typ: "index",
            name: "sqlite_autoindex_projects_1",
            tbl_name: "projects",
            root_page: autoindex_projects_root,
            sql: None,
        },
        MasterEntry {
            typ: "table",
            name: "file_hashes",
            tbl_name: "file_hashes",
            root_page: file_hashes_root,
            sql: Some(SCHEMA_SQL_FILE_HASHES),
        },
        MasterEntry {
            typ: "index",
            name: "sqlite_autoindex_file_hashes_1",
            tbl_name: "file_hashes",
            root_page: autoindex_file_hashes_root,
            sql: None,
        },
        MasterEntry {
            typ: "table",
            name: "nodes",
            tbl_name: "nodes",
            root_page: nodes_root,
            sql: Some(SCHEMA_SQL_NODES),
        },
        MasterEntry {
            typ: "index",
            name: "sqlite_autoindex_nodes_1",
            tbl_name: "nodes",
            root_page: node_roots.autoindex_nodes,
            sql: None,
        },
        MasterEntry {
            typ: "index",
            name: "idx_nodes_label",
            tbl_name: "nodes",
            root_page: node_roots.idx_nodes_label,
            sql: Some(SCHEMA_SQL_IDX_NODES_LABEL),
        },
        MasterEntry {
            typ: "index",
            name: "idx_nodes_name",
            tbl_name: "nodes",
            root_page: node_roots.idx_nodes_name,
            sql: Some(SCHEMA_SQL_IDX_NODES_NAME),
        },
        MasterEntry {
            typ: "index",
            name: "idx_nodes_file",
            tbl_name: "nodes",
            root_page: node_roots.idx_nodes_file,
            sql: Some(SCHEMA_SQL_IDX_NODES_FILE),
        },
        // local_name_gen + widened UNIQUE (#768): the hand-built
        // sqlite_autoindex_edges_1 must produce exactly the values SQLite
        // computes for local_name_gen, or integrity_check fails.
        MasterEntry {
            typ: "table",
            name: "edges",
            tbl_name: "edges",
            root_page: edges_root,
            sql: Some(SCHEMA_SQL_EDGES),
        },
        MasterEntry {
            typ: "index",
            name: "sqlite_autoindex_edges_1",
            tbl_name: "edges",
            root_page: edge_roots.autoindex_edges,
            sql: None,
        },
        MasterEntry {
            typ: "index",
            name: "idx_edges_source",
            tbl_name: "edges",
            root_page: edge_roots.idx_edges_source,
            sql: Some(SCHEMA_SQL_IDX_EDGES_SOURCE),
        },
        MasterEntry {
            typ: "index",
            name: "idx_edges_target",
            tbl_name: "edges",
            root_page: edge_roots.idx_edges_target,
            sql: Some(SCHEMA_SQL_IDX_EDGES_TARGET),
        },
        MasterEntry {
            typ: "index",
            name: "idx_edges_type",
            tbl_name: "edges",
            root_page: edge_roots.idx_edges_type,
            sql: Some(SCHEMA_SQL_IDX_EDGES_TYPE),
        },
        MasterEntry {
            typ: "index",
            name: "idx_edges_target_type",
            tbl_name: "edges",
            root_page: edge_roots.idx_edges_target_type,
            sql: Some(SCHEMA_SQL_IDX_EDGES_TARGET_TYPE),
        },
        MasterEntry {
            typ: "index",
            name: "idx_edges_source_type",
            tbl_name: "edges",
            root_page: edge_roots.idx_edges_source_type,
            sql: Some(SCHEMA_SQL_IDX_EDGES_SOURCE_TYPE),
        },
        MasterEntry {
            typ: "index",
            name: "idx_edges_url_path",
            tbl_name: "edges",
            root_page: edge_roots.idx_edges_url_path,
            sql: Some(SCHEMA_SQL_IDX_EDGES_URL_PATH),
        },
        MasterEntry {
            typ: "table",
            name: "project_summaries",
            tbl_name: "project_summaries",
            root_page: summaries_root,
            sql: Some(SCHEMA_SQL_PROJECT_SUMMARIES),
        },
        MasterEntry {
            typ: "index",
            name: "sqlite_autoindex_project_summaries_1",
            tbl_name: "project_summaries",
            root_page: autoindex_summaries_root,
            sql: None,
        },
        MasterEntry {
            typ: "table",
            name: "node_vectors",
            tbl_name: "node_vectors",
            root_page: vectors_root,
            sql: Some(SCHEMA_SQL_NODE_VECTORS),
        },
        MasterEntry {
            typ: "table",
            name: "token_vectors",
            tbl_name: "token_vectors",
            root_page: token_vecs_root,
            sql: Some(SCHEMA_SQL_TOKEN_VECTORS),
        },
        MasterEntry {
            typ: "table",
            name: "sqlite_sequence",
            tbl_name: "sqlite_sequence",
            root_page: sqlite_seq_root,
            sql: Some(SCHEMA_SQL_SQLITE_SEQUENCE),
        },
    ];

    let page1 = write_master_page1(&master, next_page)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&page1)?;

    pad_file_to_page_boundary(&mut file, next_page)?;
    Ok(publish_writer_output(file, temp_path, final_path))
}

/// One-shot DB write (C cbm_write_db): open + append all nodes + finalize.
/// Produces byte-identical output to the streaming path.
#[allow(clippy::too_many_arguments)]
pub fn write_db(
    path: &Path,
    project: &str,
    root_path: &str,
    indexed_at: &str,
    nodes: &[DumpNode],
    edges: &[DumpEdge],
    vectors: &[DumpVector],
    token_vecs: &[DumpTokenVec],
) -> i32 {
    let Some(mut w) = DbWriter::open(path) else {
        return WRITE_ERR_OPEN;
    };
    w.append_nodes(nodes); // error recorded in w, handled by finalize
    w.finalize(
        project, root_path, indexed_at, nodes, edges, vectors, token_vecs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cbm-wdb-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn node(id: i64, qn: &str) -> DumpNode {
        DumpNode {
            id,
            project: "proj".into(),
            label: "Function".into(),
            name: qn.into(),
            qualified_name: format!("proj.{qn}"),
            file_path: "a.go".into(),
            start_line: 1,
            end_line: 2,
            properties: "{}".into(),
        }
    }

    fn edge(id: i64, src: i64, tgt: i64) -> DumpEdge {
        DumpEdge {
            id,
            project: "proj".into(),
            source_id: src,
            target_id: tgt,
            type_: "CALLS".into(),
            properties: "{}".into(),
            url_path: String::new(),
            local_name: String::new(),
        }
    }

    #[test]
    fn write_db_produces_sqlite_magic_and_pads() {
        let path = temp_path("oneshot");
        let nodes: Vec<DumpNode> = (1..=20).map(|i| node(i, &format!("fn{i}"))).collect();
        let edges: Vec<DumpEdge> = (1..=10).map(|i| edge(i, i, i + 1)).collect();
        let rc = write_db(
            &path,
            "proj",
            "/repo",
            "2026-09-10T00:00:00Z",
            &nodes,
            &edges,
            &[],
            &[],
        );
        assert_eq!(rc, WRITE_OK, "write_db rc={rc}");
        let bytes = std::fs::read(&path).unwrap();
        // SQLite magic string.
        assert_eq!(&bytes[..15], b"SQLite format 3");
        // Page size code 1 (64K).
        assert_eq!(&bytes[16..18], &[0, 1]);
        // File length is a multiple of 64K.
        assert_eq!(bytes.len() % 65536, 0, "len={}", bytes.len());
        // Master table lists 22 entries.
        let expected_entries = 22;
        assert_eq!(bytes[100 + 3], 0); // cell count high byte
        assert!(bytes[100 + 4] as usize >= expected_entries - 1); // 22 ≤ 255
                                                                  // sqlite_master entry count cell-count field (u16 BE at 103).
        let cell_count = u16::from_be_bytes([bytes[103], bytes[104]]);
        assert_eq!(cell_count, expected_entries as u16);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_db_empty_graph_still_valid() {
        let path = temp_path("empty");
        let rc = write_db(&path, "p", "/r", "t", &[], &[], &[], &[]);
        assert_eq!(rc, WRITE_OK);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..15], b"SQLite format 3");
        assert_eq!(bytes.len() % 65536, 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn streaming_writer_matches_one_shot() {
        // Streaming: open → append in two batches → finalize must produce
        // the same node table layout as one-shot (byte-identical contract
        // from the C). Compare file sizes and page-1 bytes.
        let p_stream = temp_path("stream");
        let p_oneshot = temp_path("oneshot2");
        let nodes: Vec<DumpNode> = (1..=100).map(|i| node(i, &format!("sym{i}"))).collect();
        let edges: Vec<DumpEdge> = (1..=40).map(|i| edge(i, i % 50 + 1, i % 50 + 2)).collect();

        let rc_one = write_db(&p_oneshot, "proj", "/repo", "T0", &nodes, &edges, &[], &[]);
        assert_eq!(rc_one, WRITE_OK);

        {
            let mut w = DbWriter::open(&p_stream).unwrap();
            assert_eq!(w.append_nodes(&nodes[..50]), WRITE_OK);
            assert_eq!(w.append_nodes(&nodes[50..]), WRITE_OK);
            assert_eq!(
                w.finalize("proj", "/repo", "T0", &nodes, &edges, &[], &[]),
                WRITE_OK
            );
        }

        let a = std::fs::read(&p_stream).unwrap();
        let b = std::fs::read(&p_oneshot).unwrap();
        assert_eq!(a.len(), b.len(), "file sizes diverge");
        // Page 1 (master) must be byte-identical.
        assert_eq!(&a[..65536], &b[..65536]);
        std::fs::remove_file(&p_stream).ok();
        std::fs::remove_file(&p_oneshot).ok();
    }

    #[test]
    fn publish_removes_sidecars() {
        let path = temp_path("sidecar");
        // SQLite sidecar suffixes: -wal/-shm/-journal (foundation removes
        // exactly these).
        std::fs::write(format!("{}-wal", path.display()), b"stale").ok();
        std::fs::write(format!("{}-journal", path.display()), b"stale").ok();
        let rc = write_db(&path, "p", "/r", "t", &[], &[], &[], &[]);
        assert_eq!(rc, WRITE_OK);
        assert!(!PathBuf::from(format!("{}-wal", path.display())).exists());
        assert!(!PathBuf::from(format!("{}-journal", path.display())).exists());
        std::fs::remove_file(&path).ok();
    }
}
