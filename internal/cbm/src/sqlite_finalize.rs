//! finalize.rs — part 3 of the sqlite_writer rewrite: metadata tables,
//! index B-trees, the sqlite_master page-1 B-tree, and the SQLite file
//! header (C write_metadata_tables / write_master_page1 /
//! write_sqlite_file_header / cbm_writer_finalize tail).
//!
//! Ordering contract: sqlite_master entries must follow standard SQLite
//! ordering (table → autoindex → user indexes → next table); the schema
//! loader expects autoindexes immediately after their table.

use std::fs::File;

use crate::page_builder::{write_empty_leaf_page, PageBuilder};
use crate::sqlite_writer::{
    build_project_record, build_table_cell, put_u16, put_u32, skip_pending_byte, BTREE_HEADER_SIZE,
    CBM_PAGE_SIZE, CELL_PTR_SIZE, FIRST_DATA_PAGE, FIRST_ROWID, SQLITE_HEADER_SIZE,
};

const HDR_FREEBLOCK_OFF: usize = 1;
const HDR_CELLCOUNT_OFF: usize = 3;
const HDR_CONTENT_OFF: usize = 5;
const HDR_FRAGBYTES_OFF: usize = 7;
const LEAF_TABLE_FLAG: u8 = 0x0D;

// ── File header constants (C HDR_OFF_* / defines) ───────────────

const HDR_OFF_PAGE_SIZE: usize = 16;
const HDR_OFF_WRITE_VERSION: usize = 18;
const HDR_OFF_READ_VERSION: usize = 19;
const HDR_OFF_RESERVED: usize = 20;
const HDR_OFF_MAX_EMBED_FRAC: usize = 21;
const HDR_OFF_MIN_EMBED_FRAC: usize = 22;
const HDR_OFF_LEAF_FRAC: usize = 23;
const HDR_OFF_FILE_CHANGE: usize = 24;
const HDR_OFF_DB_SIZE: usize = 28;
const HDR_OFF_FREELIST_TRUNK: usize = 32;
const HDR_OFF_FREELIST_COUNT: usize = 36;
const HDR_OFF_SCHEMA_COOKIE: usize = 40;
const HDR_OFF_SCHEMA_FORMAT: usize = 44;
const HDR_OFF_DEFAULT_CACHE: usize = 48;
const HDR_OFF_AUTOVAC_TOP: usize = 52;
const HDR_OFF_TEXT_ENCODING: usize = 56;
const HDR_OFF_USER_VERSION: usize = 60;
const HDR_OFF_INCR_VACUUM: usize = 64;
const HDR_OFF_APP_ID: usize = 68;
const HDR_OFF_VERSION_VALID: usize = 92;
const HDR_OFF_SQLITE_VERSION: usize = 96;

const FILE_FORMAT: u8 = 1;
const SCHEMA_FORMAT: u32 = 4;
/// 3.46.0
const SQLITE_VERSION: u32 = 3_046_000;

// ── sqlite_master schema (verbatim SQL strings) ─────────────────

pub const SCHEMA_SQL_PROJECTS: &str = "CREATE TABLE projects (\n\t\tname TEXT PRIMARY KEY,\n\t\tindexed_at TEXT NOT NULL,\n\t\troot_path TEXT NOT NULL\n\t)";
pub const SCHEMA_SQL_FILE_HASHES: &str = "CREATE TABLE file_hashes (\n\t\tproject TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,\n\t\trel_path TEXT NOT NULL,\n\t\tsha256 TEXT NOT NULL,\n\t\tmtime_ns INTEGER NOT NULL DEFAULT 0,\n\t\tsize INTEGER NOT NULL DEFAULT 0,\n\t\tPRIMARY KEY (project, rel_path)\n\t)";
pub const SCHEMA_SQL_NODES: &str = "CREATE TABLE nodes (\n\t\tid INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tproject TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,\n\t\tlabel TEXT NOT NULL,\n\t\tname TEXT NOT NULL,\n\t\tqualified_name TEXT NOT NULL,\n\t\tfile_path TEXT DEFAULT '',\n\t\tstart_line INTEGER DEFAULT 0,\n\t\tend_line INTEGER DEFAULT 0,\n\t\tproperties TEXT DEFAULT '{}',\n\t\tUNIQUE(project, qualified_name)\n\t)";
pub const SCHEMA_SQL_IDX_NODES_LABEL: &str =
    "CREATE INDEX idx_nodes_label ON nodes(project, label)";
pub const SCHEMA_SQL_IDX_NODES_NAME: &str = "CREATE INDEX idx_nodes_name ON nodes(project, name)";
pub const SCHEMA_SQL_IDX_NODES_FILE: &str =
    "CREATE INDEX idx_nodes_file ON nodes(project, file_path)";
pub const SCHEMA_SQL_EDGES: &str = "CREATE TABLE edges (\n\t\tid INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tproject TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,\n\t\tsource_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,\n\t\ttarget_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,\n\t\ttype TEXT NOT NULL,\n\t\tproperties TEXT DEFAULT '{}',\n\t\turl_path_gen TEXT GENERATED ALWAYS AS (json_extract(properties,'$.url_path')),\n\t\tlocal_name_gen TEXT GENERATED ALWAYS AS (CASE WHEN type='IMPORTS' THEN coalesce(json_extract(properties,'$.local_name'),'') ELSE '' END),\n\t\tUNIQUE(source_id, target_id, type, local_name_gen)\n\t)";
pub const SCHEMA_SQL_IDX_EDGES_SOURCE: &str =
    "CREATE INDEX idx_edges_source ON edges(source_id, type)";
pub const SCHEMA_SQL_IDX_EDGES_TARGET: &str =
    "CREATE INDEX idx_edges_target ON edges(target_id, type)";
pub const SCHEMA_SQL_IDX_EDGES_TYPE: &str = "CREATE INDEX idx_edges_type ON edges(project, type)";
pub const SCHEMA_SQL_IDX_EDGES_TARGET_TYPE: &str =
    "CREATE INDEX idx_edges_target_type ON edges(project, target_id, type)";
pub const SCHEMA_SQL_IDX_EDGES_SOURCE_TYPE: &str =
    "CREATE INDEX idx_edges_source_type ON edges(project, source_id, type)";
pub const SCHEMA_SQL_IDX_EDGES_URL_PATH: &str =
    "CREATE INDEX idx_edges_url_path ON edges(project, url_path_gen)";
pub const SCHEMA_SQL_PROJECT_SUMMARIES: &str = "CREATE TABLE project_summaries (\n\t\t\tproject TEXT PRIMARY KEY,\n\t\t\tsummary TEXT NOT NULL,\n\t\t\tsource_hash TEXT NOT NULL,\n\t\t\tcreated_at TEXT NOT NULL,\n\t\t\tupdated_at TEXT NOT NULL\n\t\t)";
pub const SCHEMA_SQL_NODE_VECTORS: &str = "CREATE TABLE node_vectors (\n\t\tnode_id INTEGER PRIMARY KEY,\n\t\tproject TEXT NOT NULL,\n\t\tvector BLOB NOT NULL\n\t)";
pub const SCHEMA_SQL_TOKEN_VECTORS: &str = "CREATE TABLE token_vectors (\n\t\tid INTEGER PRIMARY KEY,\n\t\tproject TEXT NOT NULL,\n\t\ttoken TEXT NOT NULL,\n\t\tvector BLOB NOT NULL,\n\t\tidf INTEGER NOT NULL\n\t)";
pub const SCHEMA_SQL_SQLITE_SEQUENCE: &str = "CREATE TABLE sqlite_sequence(name,seq)";

/// sqlite_master entry (C MasterEntry).
#[derive(Debug, Clone)]
pub struct MasterEntry {
    pub typ: &'static str, // "table" | "index"
    pub name: &'static str,
    pub tbl_name: &'static str,
    pub root_page: u32,
    pub sql: Option<&'static str>,
}

/// Master record: (type, name, tbl_name, rootpage, sql|null)
/// (C build_master_record).
pub fn build_master_record(e: &MasterEntry) -> Vec<u8> {
    use crate::sqlite_writer::RecordBuilder;
    let mut r = RecordBuilder::new();
    r.add_text(e.typ);
    r.add_text(e.name);
    r.add_text(e.tbl_name);
    r.add_int(e.root_page as i64);
    match e.sql {
        Some(sql) => r.add_text(sql),
        None => r.add_null(),
    }
    r.finalize()
}

/// Write the SQLite file header on page 1 (C write_sqlite_file_header).
/// `page_size_code`: 1 when page size == 65536 (64K encodes as 1), else
/// the size in bytes.
pub fn write_sqlite_file_header(page1: &mut [u8], total_pages: u32) {
    page1[..16].copy_from_slice(b"SQLite format 3\0");
    // CBM_PAGE_SIZE == SQLITE_MAX_PAGE_SIZE → the 16-bit field encodes 1.
    put_u16(&mut page1[HDR_OFF_PAGE_SIZE..], 1);
    page1[HDR_OFF_WRITE_VERSION] = FILE_FORMAT;
    page1[HDR_OFF_READ_VERSION] = FILE_FORMAT;
    page1[HDR_OFF_RESERVED] = 0;
    page1[HDR_OFF_MAX_EMBED_FRAC] = 64;
    page1[HDR_OFF_MIN_EMBED_FRAC] = 32;
    page1[HDR_OFF_LEAF_FRAC] = 32;
    put_u32(&mut page1[HDR_OFF_FILE_CHANGE..], 1);
    put_u32(&mut page1[HDR_OFF_DB_SIZE..], total_pages);
    put_u32(&mut page1[HDR_OFF_FREELIST_TRUNK..], 0);
    put_u32(&mut page1[HDR_OFF_FREELIST_COUNT..], 0);
    put_u32(&mut page1[HDR_OFF_SCHEMA_COOKIE..], 1);
    put_u32(&mut page1[HDR_OFF_SCHEMA_FORMAT..], SCHEMA_FORMAT);
    put_u32(&mut page1[HDR_OFF_DEFAULT_CACHE..], 0);
    put_u32(&mut page1[HDR_OFF_AUTOVAC_TOP..], 0);
    put_u32(&mut page1[HDR_OFF_TEXT_ENCODING..], 1); // UTF-8
    put_u32(&mut page1[HDR_OFF_USER_VERSION..], 0);
    put_u32(&mut page1[HDR_OFF_INCR_VACUUM..], 0);
    put_u32(&mut page1[HDR_OFF_APP_ID..], 0);
    put_u32(&mut page1[HDR_OFF_VERSION_VALID..], 1);
    put_u32(&mut page1[HDR_OFF_SQLITE_VERSION..], SQLITE_VERSION);
}

/// Context for a full one-shot DB write (C write_db_ctx_t fields used here).
pub struct FinalizeCtx<'a> {
    pub file: &'a mut File,
    pub next_page: &'a mut u32,
    pub project: &'a str,
    pub root_path: &'a str,
    pub indexed_at: &'a str,
    /// Last node id (0 when no nodes).
    pub last_node_id: i64,
    /// Last edge id (0 when no edges).
    pub last_edge_id: i64,
}

/// Write metadata tables: projects (1 row), file_hashes (empty),
/// project_summaries (empty), sqlite_sequence (nodes/edges high-water).
/// Returns (projects_root, file_hashes_root, summaries_root,
/// sqlite_seq_root) (C write_metadata_tables).
pub fn write_metadata_tables(ctx: &mut FinalizeCtx<'_>) -> std::io::Result<(u32, u32, u32, u32)> {
    // projects: single row.
    let proj_rec = build_project_record(ctx.project, ctx.indexed_at, ctx.root_path);
    let projects_root = write_table_btree_multi(ctx.file, ctx.next_page, &[&proj_rec], &[1])?;

    // file_hashes / project_summaries: empty tables still allocate one
    // empty leaf page each (C write_table_btree count==0 branch).
    let file_hashes_root = write_table_btree_multi(ctx.file, ctx.next_page, &[], &[])?;
    let summaries_root = write_table_btree_multi(ctx.file, ctx.next_page, &[], &[])?;

    // sqlite_sequence: (name, seq) rows for nodes and edges — the C uses
    // rowids {1, 2} (FIRST_ROWID, FIRST_DATA_PAGE).
    let mut r1 = crate::sqlite_writer::RecordBuilder::new();
    r1.add_text("nodes");
    r1.add_int(ctx.last_node_id);
    let rec1 = r1.finalize();
    let mut r2 = crate::sqlite_writer::RecordBuilder::new();
    r2.add_text("edges");
    r2.add_int(ctx.last_edge_id);
    let rec2 = r2.finalize();
    let rowids = [FIRST_ROWID, FIRST_DATA_PAGE as i64];
    let sqlite_seq_root =
        write_table_btree_multi(ctx.file, ctx.next_page, &[&rec1, &rec2], &rowids)?;

    Ok((
        projects_root,
        file_hashes_root,
        summaries_root,
        sqlite_seq_root,
    ))
}

/// Write a table B-tree from records; empty input allocates a single
/// empty leaf page (C write_table_btree count==0 branch — NOT root 0).
pub fn write_table_btree_multi(
    file: &mut File,
    next_page: &mut u32,
    records: &[&[u8]],
    rowids: &[i64],
) -> std::io::Result<u32> {
    if records.is_empty() {
        *next_page = skip_pending_byte(*next_page);
        let pnum = *next_page;
        *next_page += 1;
        write_empty_leaf_page(file, pnum, false)?;
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

/// Assemble the page-1 sqlite_master B-tree in the C's ordering (table →
/// autoindex → user indexes per table) plus the file header, built
/// directly in memory exactly like the C (which writes the page with an
/// in-place cell layout rather than going through PageBuilder — the master
/// must fit one page or the C fails with ERR_MASTER_OVERFLOW). Returns the
/// complete page-1 bytes for the caller to write at file offset 0
/// (C write_master_page1 + write_sqlite_file_header).
///
/// `master` entries must already carry correct root pages; rowids are
/// 1..N; the header DB-size field is `next_page - 1` (pages are 1-based).
pub fn write_master_page1(master: &[MasterEntry], next_page: u32) -> std::io::Result<Vec<u8>> {
    let mut page1 = vec![0u8; CBM_PAGE_SIZE as usize];
    let hdr = SQLITE_HEADER_SIZE;
    page1[hdr] = LEAF_TABLE_FLAG;
    let mut content_off = CBM_PAGE_SIZE as usize;
    let mut ptr_off = hdr + BTREE_HEADER_SIZE;

    for (i, e) in master.iter().enumerate() {
        let rec = build_master_record(e);
        let cell = build_table_cell(i as i64 + 1, &rec);
        let available = content_off - ptr_off - CELL_PTR_SIZE;
        if cell.len() > available {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "master overflow",
            ));
        }
        content_off -= cell.len();
        page1[content_off..content_off + cell.len()].copy_from_slice(&cell);
        put_u16(&mut page1[ptr_off..], content_off as u16);
        ptr_off += CELL_PTR_SIZE;
    }

    put_u16(&mut page1[hdr + HDR_FREEBLOCK_OFF..], 0);
    put_u16(&mut page1[hdr + HDR_CELLCOUNT_OFF..], master.len() as u16);
    put_u16(&mut page1[hdr + HDR_CONTENT_OFF..], content_off as u16);
    page1[hdr + HDR_FRAGBYTES_OFF] = 0;

    write_sqlite_file_header(&mut page1, next_page - 1);
    Ok(page1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAF_TABLE_FLAG: u8 = 0x0D;

    #[test]
    fn header_layout_matches_sqlite() {
        let mut page1 = vec![0u8; CBM_PAGE_SIZE as usize];
        write_sqlite_file_header(&mut page1, 42);
        assert_eq!(&page1[..15], b"SQLite format 3");
        assert_eq!(page1[18], 1); // write version
        assert_eq!(page1[19], 1); // read version
        assert_eq!(page1[20], 0); // reserved
        assert_eq!(page1[21], 64); // max embed frac
        assert_eq!(page1[22], 32); // min embed frac
        assert_eq!(page1[23], 32); // leaf frac
                                   // DB size (pages) at offset 28.
        assert_eq!(&page1[28..32], &[0, 0, 0, 42]);
        // Schema format 4 at offset 44.
        assert_eq!(&page1[44..48], &[0, 0, 0, 4]);
        // Text encoding UTF-8 (1) at offset 56.
        assert_eq!(&page1[56..60], &[0, 0, 0, 1]);
        // Page size code = 1 (64K).
        assert_eq!(&page1[16..18], &[0, 1]);
    }

    #[test]
    fn master_record_shape() {
        let e = MasterEntry {
            typ: "table",
            name: "nodes",
            tbl_name: "nodes",
            root_page: 7,
            sql: Some("CREATE TABLE nodes (...)"),
        };
        let rec = build_master_record(&e);
        assert!(!rec.is_empty());
        let e2 = MasterEntry {
            typ: "index",
            name: "sqlite_autoindex_nodes_1",
            tbl_name: "nodes",
            root_page: 9,
            sql: None,
        };
        let rec2 = build_master_record(&e2);
        assert!(!rec2.is_empty());
    }

    #[test]
    fn metadata_tables_roots() {
        let (mut f, path) = temp_file_pair();
        let mut next = FIRST_DATA_PAGE;
        let mut ctx = FinalizeCtx {
            file: &mut f,
            next_page: &mut next,
            project: "proj",
            root_path: "/repo",
            indexed_at: "2026-09-09T00:00:00Z",
            last_node_id: 5,
            last_edge_id: 3,
        };
        let (projects, file_hashes, summaries, seq) = write_metadata_tables(&mut ctx).unwrap();
        assert!(projects >= 2);
        // Empty tables still allocate one empty leaf page each (C parity).
        assert!(file_hashes > projects);
        assert!(summaries > file_hashes);
        assert!(seq > summaries);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn master_page1_assembles() {
        let master = vec![
            MasterEntry {
                typ: "table",
                name: "projects",
                tbl_name: "projects",
                root_page: 2,
                sql: Some(SCHEMA_SQL_PROJECTS),
            },
            MasterEntry {
                typ: "index",
                name: "sqlite_autoindex_projects_1",
                tbl_name: "projects",
                root_page: 3,
                sql: None,
            },
        ];
        let page1 = write_master_page1(&master, 4).unwrap();
        assert_eq!(&page1[..15], b"SQLite format 3");
        // The 100-byte file header occupies the page start; the master
        // table's b-tree leaf header begins at offset 100.
        assert_eq!(page1[100], LEAF_TABLE_FLAG);
    }

    fn temp_file_pair() -> (File, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!(
            "cbm-fin-{}-{}",
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
}
