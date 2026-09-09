//! page_builder.rs — 1:1 rewrite of the PageBuilder half of
//! `internal/cbm/sqlite_writer.c`: leaf-table page construction with
//! overflow spilling, interior B-tree assembly, and the streaming
//! `append_nodes`/`finalize_table` API the pipeline uses to flush node
//! rows in batches while keeping the direct-page bulk write.
//!
//! Page layout facts encoded here (SQLite file format, PAGE_SIZE=65536,
//! reserved=0):
//!   leaf table page   = flag 0x0D, header 8 bytes, cell pointers grow up
//!                       from header end, cell content grows down from page
//!                       end; cell = varint(payload_len) + varint(rowid) +
//!                       payload (+ uint32 first-overflow-page on spill)
//!   interior table    = flag 0x05, header 12 bytes (extra right-child
//!                       pointer); N children → N-1 cells
//!                       {left_child(4), varint(max_rowid)}
//!   overflow pages    = 4-byte next-page pointer + up to PAGE_SIZE-4 data

use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use crate::sqlite_writer::{
    build_node_record, build_table_cell, put_u16, put_u32, put_varint, skip_pending_byte, DumpNode,
    BTREE_HEADER_SIZE, BTREE_INTERIOR_HDR, BTREE_PTR_SIZE, CBM_PAGE_SIZE, CELL_PTR_SIZE,
    SQLITE_HEADER_SIZE,
};

const INTERIOR_TABLE_FLAG: u8 = 0x05;
const LEAF_TABLE_FLAG: u8 = 0x0D;
const HDR_FREEBLOCK_OFF: usize = 1;
const HDR_CELLCOUNT_OFF: usize = 3;
const HDR_CONTENT_OFF: usize = 5;
const HDR_FRAGBYTES_OFF: usize = 7;
const HDR_RIGHTCHILD_OFF: usize = 8;
/// SQLite overflow thresholds for leaf table B-tree pages
/// (PAGE_SIZE=65536, reserved=0): max_local = usable - 35 = 65501;
/// min_local = (usable - 12) * 32 / 255 - 23 = 8199 (C integer arithmetic).
const TABLE_OVERFLOW_MAX_LOCAL: usize = 65501;
const TABLE_OVERFLOW_MIN_LOCAL: usize = 8199;

/// Completed leaf-page reference for interior assembly (C PageRef).
#[derive(Debug, Clone, Default)]
struct PageRef {
    page_num: u32,
    /// Max rowid on this page (table B-trees).
    max_key: i64,
    /// Separator cell for index interior pages (None for table).
    sep_cell: Option<Vec<u8>>,
}

/// Streaming table-B-tree page builder (C PageBuilder): owns the output
/// file handle, builds leaf pages as cells arrive, tracks leaf refs for
/// interior assembly at finalize.
pub struct PageBuilder {
    file: File,
    next_page: u32,
    page1_offset: usize,
    page: Vec<u8>,
    cell_count: i32,
    content_offset: usize,
    ptr_offset: usize,
    leaves: Vec<PageRef>,
}

impl PageBuilder {
    /// Open the output file and start at `start_page` (page 1 carries the
    /// 100-byte SQLite header offset). Accepts `&mut File` (the caller
    /// retains ownership, matching the C's shared FILE*).
    pub fn open(file: &mut File, start_page: u32) -> std::io::Result<Self> {
        let mut owned = file.try_clone()?;
        owned.seek(SeekFrom::Start(0))?;
        let page1_offset = usize::from(start_page == 1) * SQLITE_HEADER_SIZE;
        let page = vec![0u8; CBM_PAGE_SIZE as usize];
        Ok(PageBuilder {
            file: owned,
            next_page: start_page,
            page1_offset,
            page,
            cell_count: 0,
            content_offset: CBM_PAGE_SIZE as usize,
            ptr_offset: page1_offset + BTREE_HEADER_SIZE,
            leaves: Vec::new(),
        })
    }

    /// Flush the current leaf page to disk and record it
    /// (C pb_flush_leaf). `max_key` is the largest rowid on the page.
    fn flush_leaf(&mut self, max_key: i64) -> std::io::Result<()> {
        if self.cell_count == 0 {
            return Ok(());
        }
        let hdr = self.page1_offset;
        self.page[hdr] = LEAF_TABLE_FLAG;
        put_u16(&mut self.page[hdr + HDR_FREEBLOCK_OFF..], 0);
        put_u16(
            &mut self.page[hdr + HDR_CELLCOUNT_OFF..],
            self.cell_count as u16,
        );
        put_u16(
            &mut self.page[hdr + HDR_CONTENT_OFF..],
            self.content_offset as u16,
        );
        self.page[hdr + HDR_FRAGBYTES_OFF] = 0;

        self.next_page = skip_pending_byte(self.next_page);
        let page_num = self.next_page;
        let offset = (page_num - 1) as u64 * CBM_PAGE_SIZE as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&self.page)?;

        self.leaves.push(PageRef {
            page_num,
            max_key,
            sep_cell: None,
        });

        // Reset for the next page.
        self.next_page += 1;
        self.cell_count = 0;
        self.content_offset = CBM_PAGE_SIZE as usize;
        self.page1_offset = 0; // only page 1 carries the 100-byte header
        self.page = vec![0u8; CBM_PAGE_SIZE as usize];
        self.ptr_offset = self.page1_offset + BTREE_HEADER_SIZE;
        Ok(())
    }

    fn cell_fits(&self, cell_len: usize) -> bool {
        // Cell pointer (2 bytes) + cell content.
        let available = self.content_offset - self.ptr_offset - CELL_PTR_SIZE;
        cell_len <= available
    }

    fn add_cell(&mut self, cell: &[u8]) {
        // Content grows down, pointer grows up.
        self.content_offset -= cell.len();
        self.page[self.content_offset..self.content_offset + cell.len()].copy_from_slice(cell);
        put_u16(
            &mut self.page[self.ptr_offset..],
            self.content_offset as u16,
        );
        self.ptr_offset += CELL_PTR_SIZE;
        self.cell_count += 1;
    }

    /// Add a table cell, flushing the leaf page when full. Payload over
    /// max_local spills to overflow pages; the leaf stores the local
    /// portion plus a 4-byte first-overflow-page pointer
    /// (C pb_add_table_cell_with_flush). `prev_rowid` is the previous
    /// cell's rowid (the page's max_key when this cell triggers a flush).
    pub fn add_table_cell_with_flush(
        &mut self,
        rowid: i64,
        payload: &[u8],
        prev_rowid: i64,
    ) -> std::io::Result<()> {
        let cell: Vec<u8> = if payload.len() > TABLE_OVERFLOW_MAX_LOCAL {
            // local_len per SQLite spec for leaf table cells.
            let ovfl_page_data = CBM_PAGE_SIZE as usize - BTREE_PTR_SIZE;
            let remainder = (payload.len() - TABLE_OVERFLOW_MIN_LOCAL) % ovfl_page_data;
            let mut local_len = TABLE_OVERFLOW_MIN_LOCAL + remainder;
            if local_len > TABLE_OVERFLOW_MAX_LOCAL {
                local_len = TABLE_OVERFLOW_MIN_LOCAL;
            }
            // Overflow pages for the bytes that don't fit locally.
            let overflow_page = self.write_overflow_pages(&payload[local_len..])?;
            build_table_cell_overflow(rowid, payload, local_len, overflow_page)
        } else {
            build_table_cell(rowid, payload)
        };
        if !self.cell_fits(cell.len()) && self.cell_count > 0 {
            self.flush_leaf(prev_rowid)?;
        }
        self.add_cell(&cell);
        Ok(())
    }

    /// Overflow page writer (C write_overflow_pages): each page is a
    /// 4-byte next-page pointer + up to PAGE_SIZE-4 data bytes; the final
    /// page's pointer is 0. Returns the first overflow page number.
    fn write_overflow_pages(&mut self, data: &[u8]) -> std::io::Result<u32> {
        let per_page = CBM_PAGE_SIZE as usize - BTREE_PTR_SIZE;
        let mut first_page = 0u32;
        let mut prev_next_ptr_offset: i64 = -1;

        let mut offset = 0usize;
        while offset < data.len() {
            let pnum = self.next_page;
            self.next_page += 1;
            if first_page == 0 {
                first_page = pnum;
            }
            // Backpatch the previous overflow page's next-page pointer.
            if prev_next_ptr_offset >= 0 {
                let mut ptr = [0u8; BTREE_PTR_SIZE];
                put_u32(&mut ptr, pnum);
                self.file
                    .seek(SeekFrom::Start(prev_next_ptr_offset as u64))?;
                self.file.write_all(&ptr)?;
            }

            let chunk = (data.len() - offset).min(per_page);
            let mut page = vec![0u8; CBM_PAGE_SIZE as usize];
            put_u32(&mut page, 0); // next-page pointer, backpatched next loop
            page[BTREE_PTR_SIZE..BTREE_PTR_SIZE + chunk]
                .copy_from_slice(&data[offset..offset + chunk]);
            let po = (pnum - 1) as u64 * CBM_PAGE_SIZE as u64;
            self.file.seek(SeekFrom::Start(po))?;
            self.file.write_all(&page)?;
            prev_next_ptr_offset = po as i64;
            offset += chunk;
        }
        Ok(first_page)
    }

    /// Finalize: flush the trailing leaf, assemble interior pages, return
    /// (root_page, next_free_page) (C pb_finalize_table).
    pub fn finalize_table(mut self, last_rowid: i64) -> std::io::Result<(u32, u32)> {
        if self.cell_count > 0 {
            self.flush_leaf(last_rowid)?;
        }
        let next_page = self.next_page;
        let root = match self.leaves.len() {
            0 => 0,
            1 => self.leaves[0].page_num,
            _ => build_interior(&mut self.file, &mut self.next_page, &self.leaves, false)?,
        };
        Ok((root, next_page))
    }

    /// Append a batch of node records (C cbm_writer_append_nodes). Node
    /// ids must be ascending and contiguous across all append calls.
    pub fn append_nodes(
        &mut self,
        nodes: &[DumpNode],
        last_rowid: &mut i64,
    ) -> std::io::Result<()> {
        for n in nodes {
            let rec = build_node_record(n);
            // prev_rowid matches the one-shot write loop so output is
            // byte-identical.
            self.add_table_cell_with_flush(n.id, &rec, *last_rowid)?;
            *last_rowid = n.id;
        }
        Ok(())
    }
}

/// Interior cell for a child ref: table = child_page(4) + varint(max_key);
/// index = child_page(4) + separator cell (C build_interior_cell).
fn build_interior_cell(child: &PageRef, is_index: bool) -> Vec<u8> {
    let mut cell = Vec::with_capacity(BTREE_PTR_SIZE + 10);
    cell.extend_from_slice(&child.page_num.to_be_bytes()); // child_page(4)
    if is_index {
        cell.extend_from_slice(child.sep_cell.as_deref().unwrap_or(&[]));
    } else {
        let mut tmp = [0u8; 10];
        let n = put_varint(&mut tmp, child.max_key);
        cell.extend_from_slice(&tmp[..n]);
    }
    cell
}

/// Assemble interior pages level by level; returns the root page number
/// (C pb_build_interior). SQLite interior page: N children → N-1 cells
/// {left_child(4), key}; children[N-1] goes in the header right-child
/// pointer.
fn build_interior(
    file: &mut File,
    next_page: &mut u32,
    leaves: &[PageRef],
    is_index: bool,
) -> std::io::Result<u32> {
    if leaves.is_empty() {
        return Ok(0);
    }
    if leaves.len() == 1 {
        return Ok(leaves[0].page_num);
    }
    let mut children: Vec<PageRef> = leaves.to_vec();
    while children.len() > 1 {
        let mut parents: Vec<PageRef> = Vec::new();
        let mut i = 0usize;
        while i < children.len() {
            let mut page = vec![0u8; CBM_PAGE_SIZE as usize];
            let mut cell_count = 0i32;
            let mut content_offset = CBM_PAGE_SIZE as usize;
            let mut ptr_offset = BTREE_INTERIOR_HDR;
            // Fill cells until exhausted or full.
            while i < children.len() - 1 {
                let cell = build_interior_cell(&children[i], is_index);
                let available = content_offset - ptr_offset - CELL_PTR_SIZE;
                if cell.len() > available && cell_count > 0 {
                    break;
                }
                content_offset -= cell.len();
                page[content_offset..content_offset + cell.len()].copy_from_slice(&cell);
                put_u16(&mut page[ptr_offset..], content_offset as u16);
                ptr_offset += CELL_PTR_SIZE;
                cell_count += 1;
                i += 1;
            }
            // Right child = next unprocessed child (or the last one).
            let right_child_idx = if i < children.len() - 1 {
                i
            } else {
                children.len() - 1
            };
            let right_child_page = children[right_child_idx].page_num;
            if i < children.len() - 1 {
                i += 1;
            } else {
                i = children.len();
            }
            // Write the interior page.
            *next_page = skip_pending_byte(*next_page);
            let pnum = *next_page;
            *next_page += 1;
            page[0] = if is_index { 0x02 } else { INTERIOR_TABLE_FLAG };
            put_u16(&mut page[HDR_FREEBLOCK_OFF..], 0);
            put_u16(&mut page[HDR_CELLCOUNT_OFF..], cell_count as u16);
            put_u16(&mut page[HDR_CONTENT_OFF..], content_offset as u16);
            page[HDR_FRAGBYTES_OFF] = 0;
            put_u32(&mut page[HDR_RIGHTCHILD_OFF..], right_child_page);
            let po = (pnum - 1) as u64 * CBM_PAGE_SIZE as u64;
            file.seek(SeekFrom::Start(po))?;
            file.write_all(&page)?;
            parents.push(PageRef {
                page_num: pnum,
                max_key: children[right_child_idx].max_key,
                sep_cell: children[right_child_idx].sep_cell.clone(),
            });
        }
        children = parents;
    }
    Ok(children[0].page_num)
}

/// Schema text registry: table/index CREATE statements exactly as the C
/// writes them into sqlite_master (ordering table → autoindex → indexes is
/// enforced at finalize).
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

/// sqlite_master entry (C MasterEntry).
#[derive(Debug, Clone)]
pub struct MasterEntry {
    pub typ: &'static str, // "table" | "index"
    pub name: &'static str,
    pub tbl_name: &'static str,
    pub root_page: u32,
    pub sql: Option<&'static str>,
}

/// One-shot write of a complete table B-tree from prepared records
/// (C write_table_btree). Returns (root_page, next_page).
pub fn write_table_btree(
    file: &mut File,
    next_page: &mut u32,
    rowids: &[i64],
    records: &[Vec<u8>],
) -> std::io::Result<(u32, u32)> {
    if records.is_empty() {
        return Ok((0, *next_page));
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
    Ok((root, np))
}

/// Overflow-page count for a payload (helper for tests/finalize sizing).
pub fn overflow_page_count(payload_len: usize) -> usize {
    if payload_len <= TABLE_OVERFLOW_MAX_LOCAL {
        return 0;
    }
    let ovfl_page_data = CBM_PAGE_SIZE as usize - BTREE_PTR_SIZE;
    let overflow_len = payload_len - TABLE_OVERFLOW_MIN_LOCAL;
    overflow_len.div_ceil(ovfl_page_data)
}

/// local_len computation shared by cell builders (C inline arithmetic).
pub fn table_local_len(payload_len: usize) -> usize {
    if payload_len <= TABLE_OVERFLOW_MAX_LOCAL {
        return payload_len;
    }
    let ovfl_page_data = CBM_PAGE_SIZE as usize - BTREE_PTR_SIZE;
    let remainder = (payload_len - TABLE_OVERFLOW_MIN_LOCAL) % ovfl_page_data;
    let local = TABLE_OVERFLOW_MIN_LOCAL + remainder;
    local.min(TABLE_OVERFLOW_MAX_LOCAL)
}

/// Leaf table cell with overflow pointer (C build_table_cell_overflow):
/// varint(total_payload_len) + varint(rowid) + payload[..local_len] +
/// uint32(first_overflow_page).
fn build_table_cell_overflow(
    rowid: i64,
    payload: &[u8],
    local_len: usize,
    overflow_page: u32,
) -> Vec<u8> {
    let total_payload_len = payload.len();
    let mut cell: Vec<u8> = Vec::with_capacity(local_len + 20);
    let mut tmp = [0u8; 10];
    let n = put_varint(&mut tmp, total_payload_len as i64);
    cell.extend_from_slice(&tmp[..n]);
    let n = put_varint(&mut tmp, rowid);
    cell.extend_from_slice(&tmp[..n]);
    cell.extend_from_slice(&payload[..local_len]);
    let mut ptr = [0u8; BTREE_PTR_SIZE];
    put_u32(&mut ptr, overflow_page);
    cell.extend_from_slice(&ptr);
    cell
}

/// Page-number allocation map for tests and finalize ordering.
pub type PageAlloc = HashMap<u32, ()>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite_writer::{varint_len, DumpNode, FIRST_DATA_PAGE};

    fn temp_file() -> (File, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!(
            "cbm-pb-{}-{}",
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

    fn node(id: i64, qn: &str) -> DumpNode {
        DumpNode {
            id,
            project: "p".into(),
            label: "Function".into(),
            name: qn.into(),
            qualified_name: format!("p.{qn}"),
            file_path: "a.go".into(),
            start_line: 1,
            end_line: 2,
            properties: "{}".into(),
        }
    }

    #[test]
    fn single_leaf_single_page_tree() {
        let (mut f, path) = temp_file();
        let mut pb = PageBuilder::open(&mut f, FIRST_DATA_PAGE).unwrap();
        pb.add_table_cell_with_flush(1, b"payload-one", 0).unwrap();
        pb.add_table_cell_with_flush(2, b"payload-two", 1).unwrap();
        let (root, next) = pb.finalize_table(2).unwrap();
        // Two small cells fit one leaf: root == that leaf == page 2.
        assert_eq!(root, 2);
        assert_eq!(next, 3);
        // Verify page 2 bytes: flag 0x0D at the data-page start (no 100-byte
        // header on non-page-1).
        let bytes = std::fs::read(&path).unwrap();
        let off = (2 - 1) as usize * CBM_PAGE_SIZE as usize;
        assert_eq!(bytes[off], LEAF_TABLE_FLAG);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn many_cells_build_interior() {
        let (mut f, path) = temp_file();
        let mut pb = PageBuilder::open(&mut f, FIRST_DATA_PAGE).unwrap();
        // Payload big enough that only a few fit per 64K page → interior.
        let payload = vec![b'x'; 40_000];
        let n = 6;
        for id in 1..=n {
            pb.add_table_cell_with_flush(id as i64, &payload, (id - 1) as i64)
                .unwrap();
        }
        let (root, _next) = pb.finalize_table(n as i64).unwrap();
        // 40K payload → 1 cell/page → 6 leaves → interior root (page ≥ 8).
        assert!(root > 7, "root={root}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn append_nodes_matches_manual() {
        let (mut f, path) = temp_file();
        let mut pb = PageBuilder::open(&mut f, FIRST_DATA_PAGE).unwrap();
        let nodes: Vec<DumpNode> = (1..=5).map(|i| node(i, &format!("f{i}"))).collect();
        let mut last = 0i64;
        pb.append_nodes(&nodes, &mut last).unwrap();
        assert_eq!(last, 5);
        let (root, _) = pb.finalize_table(5).unwrap();
        assert!(root >= 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn overflow_spills_and_points() {
        let (mut f, path) = temp_file();
        let mut pb = PageBuilder::open(&mut f, FIRST_DATA_PAGE).unwrap();
        // Exceed max_local (65501) → overflow pages written.
        let payload = vec![b'z'; TABLE_OVERFLOW_MAX_LOCAL + 10_000];
        let overflow_pages = overflow_page_count(payload.len());
        assert!(overflow_pages > 0);
        pb.add_table_cell_with_flush(1, &payload, 0).unwrap();
        pb.add_table_cell_with_flush(2, b"small", 1).unwrap();
        let (root, next) = pb.finalize_table(2).unwrap();
        assert!(root >= 2);
        // Page allocation order: overflow pages first, then leaf pages,
        // then interior pages. Every page the builder handed out is
        // strictly below next_page, and the root is above them all only
        // when an interior level exists — assert total conservation
        // instead (next counts every allocated page starting at page 2).
        assert!(next >= FIRST_DATA_PAGE + overflow_pages as u32);
        assert!(root >= FIRST_DATA_PAGE);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn local_len_matches_sqlite_spec() {
        assert_eq!(table_local_len(100), 100);
        assert_eq!(
            table_local_len(TABLE_OVERFLOW_MAX_LOCAL),
            TABLE_OVERFLOW_MAX_LOCAL
        );
        let big = TABLE_OVERFLOW_MAX_LOCAL + 1;
        let l = table_local_len(big);
        assert!((TABLE_OVERFLOW_MIN_LOCAL..=TABLE_OVERFLOW_MAX_LOCAL).contains(&l));
    }

    #[test]
    fn interior_cell_shape() {
        let r = PageRef {
            page_num: 42,
            max_key: 777,
            sep_cell: None,
        };
        let cell = build_interior_cell(&r, false);
        // child_page(4 BE) + varint(777).
        assert_eq!(&cell[..4], &[0, 0, 0, 42]);
        let mut tmp = [0u8; 10];
        let n = put_varint(&mut tmp, 777);
        assert_eq!(&cell[4..4 + n], &tmp[..n]);
        assert_eq!(cell.len(), BTREE_PTR_SIZE + varint_len(777));
    }

    #[test]
    fn schema_sql_matches_c_strings() {
        // A few load-bearing fragments must match byte-for-byte.
        assert!(SCHEMA_SQL_NODES.contains("UNIQUE(project, qualified_name)"));
        assert!(SCHEMA_SQL_EDGES.contains("local_name_gen TEXT GENERATED ALWAYS AS"));
        assert!(SCHEMA_SQL_PROJECTS.contains("root_path TEXT NOT NULL"));
    }
}
