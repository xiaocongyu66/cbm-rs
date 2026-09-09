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

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use crate::sqlite_writer::{
    build_node_record, build_table_cell, put_u16, put_u32, put_varint, skip_pending_byte, DumpNode,
    BTREE_HEADER_SIZE, BTREE_INTERIOR_HDR, BTREE_PTR_SIZE, CBM_PAGE_SIZE, CELL_PTR_SIZE,
    SQLITE_HEADER_SIZE,
};

const INTERIOR_TABLE_FLAG: u8 = 0x05;
const LEAF_TABLE_FLAG: u8 = 0x0D;
const LEAF_INDEX_FLAG: u8 = 0x0A;
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

/// Streaming table/index B-tree page builder (C PageBuilder): owns the
/// output file handle, builds leaf pages as cells arrive, tracks leaf refs
/// for interior assembly at finalize. Table mode (is_index=false) emits
/// 0x0D leaves with rowid keys; index mode emits 0x0A leaves with
/// separator cells promoted to the interior pages.
pub struct PageBuilder {
    file: File,
    next_page: u32,
    page1_offset: usize,
    page: Vec<u8>,
    cell_count: i32,
    content_offset: usize,
    ptr_offset: usize,
    is_index: bool,
    /// Separator queued for the leaf flushed next (index mode: the cell
    /// promoted by promote_and_flush / the trailing cell at finalize).
    pending_sep: Option<Vec<u8>>,
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
            is_index: false,
            pending_sep: None,
            leaves: Vec::new(),
        })
    }

    /// Index B-tree mode (C pb_init with is_index=true): 0x0A leaf pages,
    /// separator-cell interior keys.
    pub fn open_index(file: &mut File, start_page: u32) -> std::io::Result<Self> {
        let mut pb = Self::open(file, start_page)?;
        pb.is_index = true;
        Ok(pb)
    }

    /// Flush the current leaf page to disk and record it
    /// (C pb_flush_leaf). `max_key` is the largest rowid on the page.
    fn flush_leaf(&mut self, max_key: i64) -> std::io::Result<()> {
        if self.cell_count == 0 {
            return Ok(());
        }
        let hdr = self.page1_offset;
        self.page[hdr] = if self.is_index {
            LEAF_INDEX_FLAG
        } else {
            LEAF_TABLE_FLAG
        };
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
            sep_cell: self.pending_sep.take(),
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

    pub(crate) fn cell_fits(&self, cell_len: usize) -> bool {
        // Cell pointer (2 bytes) + cell content.
        let available = self.content_offset - self.ptr_offset - CELL_PTR_SIZE;
        cell_len <= available
    }

    pub(crate) fn add_cell(&mut self, cell: &[u8]) {
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
        write_overflow_chain(&mut self.file, &mut self.next_page, data)
    }

    /// Allocate the next page number, skipping the pending-byte page.
    pub(crate) fn alloc_page(&mut self) -> u32 {
        self.next_page = skip_pending_byte(self.next_page);
        let p = self.next_page;
        self.next_page += 1;
        p
    }

    /// Current next-page cursor (callers that pre-allocate their own pages,
    /// e.g. the empty-table leaf writer).
    pub(crate) fn next_page_cursor(&self) -> u32 {
        self.next_page
    }

    /// Add an index cell to the current leaf page (C pb_add_cell inside
    /// the write_index_btree loop); the caller drives page-full promotion.
    pub(crate) fn add_index_cell(&mut self, cell: &[u8]) {
        self.add_cell(cell);
    }

    /// Number of cells on the current (unflushed) leaf page.
    pub(crate) fn cell_count(&self) -> i32 {
        self.cell_count
    }

    /// Remove the last-added cell from the page (C's cell_count-- /
    /// content_offset += / ptr_offset -= in pb_promote_and_flush).
    pub(crate) fn unadd_cell(&mut self, cell: &[u8]) {
        self.cell_count -= 1;
        self.content_offset += cell.len();
        self.ptr_offset -= CELL_PTR_SIZE;
    }

    /// Page-full path (C pb_promote_and_flush): the promoted cell is
    /// REMOVED from the leaf (SQLite index B-trees count interior keys in
    /// integrity_check, so the separator must not also live in the leaf)
    /// and flushes the page with that cell as the interior separator.
    pub(crate) fn promote_and_flush(&mut self, sep_cell: &[u8]) -> std::io::Result<()> {
        self.unadd_cell(sep_cell);
        self.pending_sep = Some(sep_cell.to_vec());
        self.flush_leaf(0)
    }

    /// Trailing-leaf path (C write_index_btree post-loop): the last cell
    /// STAYS in the leaf; only the interior separator reference is set
    /// (the last leaf is always the rightmost child, so its separator is
    /// never used as an interior key).
    pub(crate) fn flush_leaf_with_sep(&mut self, sep_cell: &[u8]) -> std::io::Result<()> {
        self.pending_sep = Some(sep_cell.to_vec());
        self.flush_leaf(0)
    }

    /// Finalize an index B-tree: assemble interior pages over the flushed
    /// leaves, return (root_page, next_free_page) (C pb_build_interior,
    /// index mode). Caller must have flushed all cells.
    pub(crate) fn finalize_index(mut self) -> std::io::Result<(u32, u32)> {
        let next_page = self.next_page;
        let root = match self.leaves.len() {
            0 => 0,
            1 => self.leaves[0].page_num,
            _ => build_interior(&mut self.file, &mut self.next_page, &self.leaves, true)?,
        };
        Ok((root, next_page))
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

/// Overflow page chain writer (C write_overflow_pages, free-function form):
/// used both by the table PageBuilder and by index overflow spilling, which
/// runs BEFORE page building and therefore cannot hold a PageBuilder.
pub fn write_overflow_chain(
    file: &mut File,
    next_page: &mut u32,
    data: &[u8],
) -> std::io::Result<u32> {
    let per_page = CBM_PAGE_SIZE as usize - BTREE_PTR_SIZE;
    let mut first_page = 0u32;
    let mut prev_next_ptr_offset: i64 = -1;

    let mut offset = 0usize;
    while offset < data.len() {
        let pnum = *next_page;
        *next_page += 1;
        if first_page == 0 {
            first_page = pnum;
        }
        // Backpatch the previous overflow page's next-page pointer.
        if prev_next_ptr_offset >= 0 {
            let mut ptr = [0u8; BTREE_PTR_SIZE];
            put_u32(&mut ptr, pnum);
            file.seek(SeekFrom::Start(prev_next_ptr_offset as u64))?;
            file.write_all(&ptr)?;
        }

        let chunk = (data.len() - offset).min(per_page);
        let mut page = vec![0u8; CBM_PAGE_SIZE as usize];
        put_u32(&mut page, 0); // next-page pointer, backpatched next loop
        page[BTREE_PTR_SIZE..BTREE_PTR_SIZE + chunk].copy_from_slice(&data[offset..offset + chunk]);
        let po = (pnum - 1) as u64 * CBM_PAGE_SIZE as u64;
        file.seek(SeekFrom::Start(po))?;
        file.write_all(&page)?;
        prev_next_ptr_offset = po as i64;
        offset += chunk;
    }
    Ok(first_page)
}

/// One-shot write of a complete table B-tree from prepared records
/// (C write_table_btree). Empty input writes a single empty leaf page and
/// returns its page number (the C allocates a page, NOT root 0).
pub fn write_table_btree(
    file: &mut File,
    next_page: &mut u32,
    rowids: &[i64],
    records: &[Vec<u8>],
) -> std::io::Result<(u32, u32)> {
    if records.is_empty() {
        let mut pb = PageBuilder::open(file, *next_page)?;
        let pnum = pb.alloc_page();
        let np = pb.next_page_cursor();
        write_empty_leaf_page(file, pnum, false)?;
        *next_page = np;
        return Ok((pnum, np));
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

/// Write an empty B-tree leaf page (C write_table_btree count==0 branch /
/// write_empty_index_leaf): flag + zeroed header fields, content offset at
/// page end. `is_index` selects 0x0A (the C's empty index leaf writes
/// NEWLINE_BYTE 0x0A at page start; 0x0A == empty index leaf flag).
pub(crate) fn write_empty_leaf_page(
    file: &mut File,
    page_num: u32,
    is_index: bool,
) -> std::io::Result<()> {
    let mut page = vec![0u8; CBM_PAGE_SIZE as usize];
    page[0] = if is_index {
        LEAF_INDEX_FLAG
    } else {
        LEAF_TABLE_FLAG
    };
    put_u16(&mut page[HDR_FREEBLOCK_OFF..], 0);
    put_u16(&mut page[HDR_CELLCOUNT_OFF..], 0);
    put_u16(&mut page[HDR_CONTENT_OFF..], CBM_PAGE_SIZE as u16);
    page[HDR_FRAGBYTES_OFF] = 0;
    let offset = (page_num - 1) as u64 * CBM_PAGE_SIZE as u64;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&page)
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
    fn empty_table_allocates_one_leaf_page() {
        let (mut f, path) = temp_file();
        let mut next = FIRST_DATA_PAGE;
        let (root, next2) = write_table_btree(&mut f, &mut next, &[], &[]).unwrap();
        // The C writes a single empty leaf page for count==0, NOT root 0.
        assert_eq!(root, FIRST_DATA_PAGE);
        assert_eq!(next2, FIRST_DATA_PAGE + 1);
        let bytes = std::fs::read(&path).unwrap();
        let off = (root - 1) as usize * CBM_PAGE_SIZE as usize;
        assert_eq!(bytes[off], LEAF_TABLE_FLAG);
        // 0 cells, content offset at page end (65536 truncated to u16 = 0,
        // SQLite stores the 64K content start as zero per spec).
        assert_eq!(bytes[off + HDR_CELLCOUNT_OFF], 0);
        let content = u16::from_be_bytes([bytes[off + HDR_CONTENT_OFF], bytes[off + 6]]);
        assert_eq!(content, 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn index_btree_builds_and_promotes_separators() {
        let (mut f, path) = temp_file();
        let mut next = FIRST_DATA_PAGE;
        // Payloads just under the index spill threshold (16422): no overflow
        // pages, but only 3-4 cells fit per 64K leaf → several leaves →
        // interior root with promoted separator cells.
        let mid = "k".repeat(12_000);
        let cells: Vec<Vec<u8>> = (0..8u32)
            .map(|i| {
                let payload = format!("{mid}{:04}", i);
                let mut cell = Vec::new();
                let mut tmp = [0u8; 10];
                let n = put_varint(&mut tmp, payload.len() as i64);
                cell.extend_from_slice(&tmp[..n]);
                cell.extend_from_slice(payload.as_bytes());
                cell
            })
            .collect();
        let root = crate::sqlite_indexes::write_index_btree(&mut f, &mut next, &cells).unwrap();
        // 8 × ~12KB cells → 2 leaves + 1 interior root = page 4.
        assert!(root >= 4, "root={root}");
        let bytes = std::fs::read(&path).unwrap();
        // Root is an index interior page (0x02); first leaf is 0x0A.
        let off = (root - 1) as usize * CBM_PAGE_SIZE as usize;
        assert_eq!(bytes[off], 0x02);
        let off2 = (FIRST_DATA_PAGE - 1) as usize * CBM_PAGE_SIZE as usize;
        assert_eq!(bytes[off2], 0x0A);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_index_allocates_one_leaf_page() {
        let (mut f, path) = temp_file();
        let mut pb = PageBuilder::open_index(&mut f, FIRST_DATA_PAGE).unwrap();
        let pnum = pb.alloc_page();
        let next = pb.next_page_cursor();
        write_empty_leaf_page(&mut f, pnum, true).unwrap();
        assert_eq!(pnum, FIRST_DATA_PAGE);
        assert_eq!(next, FIRST_DATA_PAGE + 1);
        let bytes = std::fs::read(&path).unwrap();
        let off = (pnum - 1) as usize * CBM_PAGE_SIZE as usize;
        // C write_empty_index_leaf writes NEWLINE_BYTE (0x0A == leaf index).
        assert_eq!(bytes[off], 0x0A);
        std::fs::remove_file(&path).ok();
    }
}
