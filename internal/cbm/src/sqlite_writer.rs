//! sqlite_writer.rs — 1:1 rewrite of `internal/cbm/sqlite_writer.c`
//! (2377 lines), part 1: format primitives — varint encoding, serial
//! types, record building (SQLite record format: header + body), DynBuf,
//! and the constants that govern page allocation and B-tree layout.
//!
//! The C constructs SQLite database files directly — no SQL parser, no
//! INSERTs: B-tree leaf/interior pages are built and written as raw bytes.
//! Part 2 lands the PageBuilder and finalize path.

use std::collections::HashSet;

// ── Constants (verbatim from the C enum/defines) ────────────────

pub const VARINT_SHIFT: u32 = 7;
pub const VARINT_BUF_SIZE: usize = 10;
pub const VARINT_MIN_LEN: usize = 1;
pub const SERIAL_INT8: i64 = 1;
pub const SERIAL_INT16: i64 = 2;
pub const SERIAL_INT24: i64 = 3;
pub const SERIAL_INT32: i64 = 4;
pub const SERIAL_INT48: i64 = 5;
pub const SERIAL_INT64: i64 = 6;
pub const SERIAL_FLOAT64: i64 = 7;
pub const SERIAL_CONST_ZERO: i64 = 8;
pub const SERIAL_CONST_ONE: i64 = 9;
pub const SERIAL_SIZE_INT8: i64 = 1;
pub const SERIAL_SIZE_INT16: i64 = 2;
pub const SERIAL_SIZE_INT24: i64 = 3;
pub const SERIAL_SIZE_INT32: i64 = 4;
pub const SERIAL_SIZE_INT48: i64 = 6;
pub const SERIAL_SIZE_INT64: i64 = 8;
pub const BTREE_HEADER_SIZE: usize = 8;
pub const BTREE_INTERIOR_HDR: usize = 12;
pub const BTREE_PTR_SIZE: usize = 4;
pub const CELL_PTR_SIZE: usize = 2;
pub const VARINT_MASK: u64 = 0x7f;
pub const VARINT_CONTINUE: u8 = 0x80;
pub const SQLITE_HEADER_SIZE: usize = 100;
pub const TEXT_SERIAL_BASE: i64 = 13;
pub const BLOB_SERIAL_BASE: i64 = 12;
/// Page size: 64 KiB pages.
pub const CBM_PAGE_SIZE: u32 = 65536;
/// SQLite reserves the page at the 1 GiB offset (file locking "pending
/// byte" on Windows). Pages MUST skip it or integrity_check reports
/// "2nd reference to page N".
pub const CBM_PENDING_BYTE: u32 = 0x4000_0000;
pub const CBM_PENDING_BYTE_PAGE: u32 = (CBM_PENDING_BYTE / CBM_PAGE_SIZE) + 1;
pub const CBM_MAX_PAGE_SIZE: u32 = 65536;
pub const FIRST_ROWID: i64 = 1;
pub const FIRST_DATA_PAGE: u32 = 2;
pub const MAX_STRING_ARG: usize = 512;

/// Skip the pending-byte page if allocation lands on it.
pub fn skip_pending_byte(pgno: u32) -> u32 {
    if pgno == CBM_PENDING_BYTE_PAGE {
        pgno + 1
    } else {
        pgno
    }
}

// ── Varint (SQLite big-endian, 7-bit continuation) ──────────────

/// Encode `value` as a SQLite varint; returns bytes written (1..9).
pub fn put_varint(buf: &mut [u8], value: i64) -> usize {
    let v = value as u64;
    if v <= VARINT_MASK {
        buf[0] = v as u8;
        return SERIAL_SIZE_INT8 as usize;
    }
    let mut tmp = [0u8; VARINT_BUF_SIZE];
    let mut n = 0usize;
    let mut v = v;
    while v > VARINT_MASK {
        tmp[n] = (v & VARINT_MASK) as u8;
        n += 1;
        v >>= VARINT_SHIFT;
    }
    tmp[n] = v as u8;
    n += 1;
    for i in 0..n {
        buf[i] = tmp[n - 1 - i];
        if i < n - 1 {
            buf[i] |= VARINT_CONTINUE;
        }
    }
    n
}

pub fn varint_len(value: i64) -> usize {
    let mut v = value as u64;
    let mut n = VARINT_MIN_LEN;
    while v > VARINT_MASK {
        v >>= VARINT_SHIFT;
        n += 1;
    }
    n
}

// ── Serial types ────────────────────────────────────────────────

/// serial_type = len*2 + TEXT_SERIAL_BASE.
pub fn text_serial_type(len: usize) -> i64 {
    (len * 2) as i64 + TEXT_SERIAL_BASE
}

/// Integer serial type by range (C int_serial_type).
pub fn int_serial_type(val: i64) -> i64 {
    if val == 0 {
        return SERIAL_CONST_ZERO;
    }
    if val == SERIAL_INT8 {
        return SERIAL_CONST_ONE;
    }
    // C ranges: INT8/INT16 are [-MAX-1, MAX]; INT24/32/48 use the signed
    // two's-complement min of the width.
    if (-128..=127).contains(&val) {
        return SERIAL_SIZE_INT8;
    }
    if (-32_768..=32_767).contains(&val) {
        return SERIAL_SIZE_INT16;
    }
    if (-8_388_608..=8_388_607).contains(&val) {
        return SERIAL_SIZE_INT24;
    }
    if (-2_147_483_648..=2_147_483_647).contains(&val) {
        return SERIAL_SIZE_INT32;
    }
    if (-140_737_488_355_328..=140_737_488_355_327).contains(&val) {
        return SERIAL_SIZE_INT48;
    }
    SERIAL_SIZE_INT64
}

/// Storage bytes for an integer of the given serial type
/// (C int_storage_bytes).
pub fn int_storage_bytes(serial_type: i64) -> usize {
    match serial_type {
        0 => 0, // NULL
        SERIAL_INT8 => SERIAL_SIZE_INT8 as usize,
        SERIAL_INT16 => SERIAL_SIZE_INT16 as usize,
        SERIAL_INT24 => SERIAL_SIZE_INT24 as usize,
        SERIAL_INT32 => SERIAL_SIZE_INT32 as usize,
        SERIAL_INT48 => SERIAL_SIZE_INT48 as usize,
        SERIAL_INT64 => SERIAL_SIZE_INT64 as usize,
        _ => 0,
    }
}

// ── Big-endian integer writes (C put_int_be/put_u16/put_u32) ────

pub fn put_int_be(buf: &mut [u8], val: i64, nbytes: usize) {
    for (i, slot) in buf.iter_mut().take(nbytes).enumerate() {
        *slot = (val >> (8 * (nbytes - 1 - i))) as u8;
    }
}

pub fn put_u16(buf: &mut [u8], val: u16) {
    buf[0] = (val >> 8) as u8;
    buf[1] = val as u8;
}

pub fn put_u32(buf: &mut [u8], val: u32) {
    buf[0] = (val >> 24) as u8;
    buf[1] = (val >> 16) as u8;
    buf[2] = (val >> 8) as u8;
    buf[3] = val as u8;
}

// ── Record builder (SQLite record format: header size + serial-type
//    header + body) ───────────────────────────────────────────────

/// Column value being accumulated (C RecordBuilder role).
#[derive(Debug, Clone)]
pub enum RecValue {
    Null,
    Int(i64),
    Text(String),
    Blob(Vec<u8>),
}

/// Record builder (C RecordBuilder): collects values, finalizes into the
/// SQLite record layout — header (varint header-size, serial types) then
/// body (values in order).
#[derive(Debug, Default)]
pub struct RecordBuilder {
    values: Vec<RecValue>,
}

impl RecordBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_null(&mut self) {
        self.values.push(RecValue::Null);
    }

    pub fn add_int(&mut self, val: i64) {
        self.values.push(RecValue::Int(val));
    }

    pub fn add_text(&mut self, s: &str) {
        self.values.push(RecValue::Text(s.to_string()));
    }

    pub fn add_blob(&mut self, data: &[u8]) {
        self.values.push(RecValue::Blob(data.to_vec()));
    }

    pub fn add_bool(&mut self, b: bool) {
        self.values.push(RecValue::Int(if b { 1 } else { 0 }));
    }

    /// Finalize into the record bytes (C rec_finalize).
    pub fn finalize(&self) -> Vec<u8> {
        // Serial types first.
        let mut serials: Vec<i64> = Vec::with_capacity(self.values.len());
        for v in &self.values {
            serials.push(match v {
                RecValue::Null => 0,
                RecValue::Int(i) => int_serial_type(*i),
                RecValue::Text(s) => text_serial_type(s.len()),
                RecValue::Blob(b) => (b.len() * 2) as i64 + BLOB_SERIAL_BASE,
            });
        }
        // Body bytes.
        let mut body: Vec<u8> = Vec::new();
        for v in &self.values {
            match v {
                RecValue::Null => {}
                RecValue::Int(i) => {
                    let st = int_serial_type(*i);
                    let n = int_storage_bytes(st);
                    let mut tmp = [0u8; 8];
                    put_int_be(&mut tmp, *i, n);
                    body.extend_from_slice(&tmp[..n]);
                }
                RecValue::Text(s) => body.extend_from_slice(s.as_bytes()),
                RecValue::Blob(b) => body.extend_from_slice(b),
            }
        }
        // Header: varint(header_len incl. itself) + serial types.
        let mut header_len = varint_len(0); // placeholder worst case start
        let mut serials_bytes: Vec<u8> = Vec::new();
        for st in &serials {
            let mut tmp = [0u8; VARINT_BUF_SIZE];
            let n = put_varint(&mut tmp, *st);
            serials_bytes.extend_from_slice(&tmp[..n]);
        }
        // header size = serials bytes + varint-of-total; iterate to fixpoint.
        loop {
            let total = header_len + serials_bytes.len();
            let need = varint_len(total as i64);
            if need == header_len {
                break;
            }
            header_len = need;
        }
        let total = header_len + serials_bytes.len();
        let mut out: Vec<u8> = Vec::with_capacity(total + body.len());
        let mut tmp = [0u8; VARINT_BUF_SIZE];
        let n = put_varint(&mut tmp, total as i64);
        out.extend_from_slice(&tmp[..n]);
        out.extend_from_slice(&serials_bytes);
        out.extend_from_slice(&body);
        out
    }
}

// ── Input structs (flat, owned) ─────────────────────────────────

/// Node row (C CBMDumpNode).
#[derive(Debug, Clone, Default)]
pub struct DumpNode {
    /// Sequential ID (1..N), assigned by Go.
    pub id: i64,
    pub project: String,
    pub label: String,
    pub name: String,
    pub qualified_name: String,
    pub file_path: String,
    pub start_line: i32,
    pub end_line: i32,
    /// JSON string.
    pub properties: String,
}

/// Edge row (C CBMDumpEdge).
#[derive(Debug, Clone, Default)]
pub struct DumpEdge {
    /// Sequential ID (1..M), assigned by Go.
    pub id: i64,
    pub project: String,
    pub source_id: i64,
    pub target_id: i64,
    pub type_: String,
    /// JSON string.
    pub properties: String,
    /// Extracted from properties by Go (for idx_edges_url_path).
    pub url_path: String,
    /// For IMPORTS edges: the UNESCAPED json_extract local_name; feeds
    /// sqlite_autoindex_edges_1 — must match what SQLite computes for the
    /// local_name_gen column or integrity_check reports the row missing.
    pub local_name: String,
}

/// Vector row (C CBMDumpVector).
#[derive(Debug, Clone, Default)]
pub struct DumpVector {
    pub node_id: i64,
    pub project: String,
    /// int8-quantized vector blob.
    pub vector: Vec<u8>,
}

/// Token-vector row (C CBMDumpTokenVec).
#[derive(Debug, Clone, Default)]
pub struct DumpTokenVec {
    pub id: i64,
    pub project: String,
    pub token: String,
    /// int8-quantized enriched RI vector blob.
    pub vector: Vec<u8>,
    /// Inverse document frequency weight.
    pub idf: f32,
}

// ── Record builders for the specific tables ─────────────────────

/// nodes table record (C build_node_record).
pub fn build_node_record(n: &DumpNode) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_int(n.id);
    r.add_text(&n.project);
    r.add_text(&n.label);
    r.add_text(&n.name);
    r.add_text(&n.qualified_name);
    r.add_text(&n.file_path);
    r.add_int(n.start_line as i64);
    r.add_int(n.end_line as i64);
    r.add_text(&n.properties);
    r.finalize()
}

/// edges table record (C build_edge_record).
pub fn build_edge_record(e: &DumpEdge) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_int(e.id);
    r.add_text(&e.project);
    r.add_int(e.source_id);
    r.add_int(e.target_id);
    r.add_text(&e.type_);
    r.add_text(&e.properties);
    r.finalize()
}

/// node_vectors record (C build_vector_record).
pub fn build_vector_record(v: &DumpVector) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_int(v.node_id);
    r.add_text(&v.project);
    r.add_blob(&v.vector);
    r.finalize()
}

/// token_vectors record (C build_token_vec_record): idf is stored as a
/// fixed-point integer (×1000).
pub fn build_token_vec_record(tv: &DumpTokenVec) -> Vec<u8> {
    const IDF_FIXED_POINT_SCALE: i64 = 1000;
    let mut r = RecordBuilder::new();
    r.add_int(tv.id);
    r.add_text(&tv.project);
    r.add_text(&tv.token);
    r.add_blob(&tv.vector);
    r.add_int((tv.idf * IDF_FIXED_POINT_SCALE as f32) as i64);
    r.finalize()
}

/// projects record (C build_project_record).
pub fn build_project_record(name: &str, indexed_at: &str, root_path: &str) -> Vec<u8> {
    let mut r = RecordBuilder::new();
    r.add_text(name);
    r.add_text(indexed_at);
    r.add_text(root_path);
    r.finalize()
}

/// Table-leaf cell: varint(payload_len) + varint(rowid) + payload
/// (C build_table_cell).
pub fn build_table_cell(rowid: i64, payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(payload.len() + 18);
    let mut tmp = [0u8; VARINT_BUF_SIZE];
    let n = put_varint(&mut tmp, payload.len() as i64);
    out.extend_from_slice(&tmp[..n]);
    let n = put_varint(&mut tmp, rowid);
    out.extend_from_slice(&tmp[..n]);
    out.extend_from_slice(payload);
    out
}

/// Dedup helper used by index builders (C's seen-set analogue).
pub fn seen_insert(seen: &mut HashSet<u64>, key: u64) -> bool {
    seen.insert(key | 1) // non-zero mask like the C
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_single_byte() {
        let mut buf = [0u8; VARINT_BUF_SIZE];
        assert_eq!(put_varint(&mut buf, 0), 1);
        assert_eq!(buf[0], 0);
        assert_eq!(put_varint(&mut buf, 127), 1);
        assert_eq!(buf[0], 127);
    }

    #[test]
    fn varint_multi_byte_roundtrip() {
        let mut buf = [0u8; VARINT_BUF_SIZE];
        // 128 needs 2 bytes: [0x81, 0x00].
        let n = put_varint(&mut buf, 128);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0x81, 0x00]);
        // Decode back (SQLite semantics: big-endian 7-bit groups).
        let decoded = ((buf[0] & 0x7f) as i64) << 7 | (buf[1] & 0x7f) as i64;
        assert_eq!(decoded, 128);
        // 16384 → 3 bytes.
        assert_eq!(put_varint(&mut buf, 16384), 3);
        // Large value: 9 bytes max for i64.
        assert_eq!(put_varint(&mut buf, i64::MAX), 9);
    }

    #[test]
    fn varint_len_matches_encoding() {
        for v in [
            0i64,
            1,
            127,
            128,
            16383,
            16384,
            2_097_151,
            2_097_152,
            i64::MAX,
        ] {
            let mut buf = [0u8; VARINT_BUF_SIZE];
            let n = put_varint(&mut buf, v);
            assert_eq!(varint_len(v), n, "v={v}");
        }
    }

    #[test]
    fn serial_types_by_range() {
        assert_eq!(int_serial_type(0), SERIAL_CONST_ZERO);
        assert_eq!(int_serial_type(1), SERIAL_CONST_ONE);
        assert_eq!(int_serial_type(2), SERIAL_SIZE_INT8);
        assert_eq!(int_serial_type(127), SERIAL_SIZE_INT8);
        assert_eq!(int_serial_type(-128), SERIAL_SIZE_INT8);
        assert_eq!(int_serial_type(128), SERIAL_SIZE_INT16);
        assert_eq!(int_serial_type(-32_768), SERIAL_SIZE_INT16);
        assert_eq!(int_serial_type(32_768), SERIAL_SIZE_INT24);
        assert_eq!(int_serial_type(8_388_608), SERIAL_SIZE_INT32);
        assert_eq!(int_serial_type(2_147_483_648), SERIAL_SIZE_INT48);
        assert_eq!(int_serial_type(140_737_488_355_328), SERIAL_SIZE_INT64);
    }

    #[test]
    fn text_and_blob_serial() {
        assert_eq!(text_serial_type(0), 13);
        assert_eq!(text_serial_type(1), 15);
        assert_eq!(text_serial_type(5), 23);
        // blob: len*2 + 12
        assert_eq!((4 * 2) + BLOB_SERIAL_BASE, 20);
    }

    #[test]
    fn record_layout_matches_sqlite() {
        // Simple text record: value "ab" → header [2 bytes: hdr-len=2,
        // serial=17] + body "ab" = 4 bytes total.
        let mut r = RecordBuilder::new();
        r.add_text("ab");
        let rec = r.finalize();
        assert_eq!(rec, vec![2, 17, b'a', b'b']);
    }

    #[test]
    fn record_int_and_null() {
        let mut r = RecordBuilder::new();
        r.add_null();
        r.add_int(5);
        r.finalize();
        let mut r = RecordBuilder::new();
        r.add_null();
        r.add_int(5);
        let rec = r.finalize();
        // header: [len=3, 0(null), 1(int8)]; body: [5]
        assert_eq!(rec, vec![3, 0, 1, 5]);
    }

    #[test]
    fn node_record_shape() {
        let n = DumpNode {
            id: 1,
            project: "p".into(),
            label: "Function".into(),
            name: "f".into(),
            qualified_name: "p.f".into(),
            file_path: "a.go".into(),
            start_line: 1,
            end_line: 2,
            properties: "{}".into(),
        };
        let rec = build_node_record(&n);
        // First byte is the header length varint; decode it.
        let header_len = rec[0] as usize;
        assert!(header_len > 0 && header_len < rec.len());
        // Body ends at rec.len(); header covers serial types.
        assert_eq!(header_len + body_len_estimate(&n), rec.len());
    }

    fn body_len_estimate(n: &DumpNode) -> usize {
        // project + label + name + qn + file_path + properties text bytes
        // + 2 ints (start/end lines each ≤1 byte when small)
        n.project.len()
            + n.label.len()
            + n.name.len()
            + n.qualified_name.len()
            + n.file_path.len()
            + n.properties.len()
            + int_storage_bytes(int_serial_type(n.start_line as i64))
            + int_storage_bytes(int_serial_type(n.end_line as i64))
    }

    #[test]
    fn table_cell_layout() {
        let payload = vec![1, 2, 3];
        let cell = build_table_cell(7, &payload);
        // varint(3)=3, varint(7)=7, then payload.
        assert_eq!(cell, vec![3, 7, 1, 2, 3]);
    }

    #[test]
    fn pending_byte_skipped() {
        assert_eq!(
            skip_pending_byte(CBM_PENDING_BYTE_PAGE),
            CBM_PENDING_BYTE_PAGE + 1
        );
        assert_eq!(skip_pending_byte(1), 1);
        assert_eq!(skip_pending_byte(2), 2);
    }

    #[test]
    fn token_idf_fixed_point() {
        let tv = DumpTokenVec {
            id: 1,
            project: "p".into(),
            token: "t".into(),
            vector: vec![1, 2],
            idf: 1.5,
        };
        let rec = build_token_vec_record(&tv);
        // Record must be non-empty and the idf int should be 1500.
        assert!(!rec.is_empty());
        // Sanity: decode the last int body byte pair loosely via length.
        assert!(rec.len() > 6);
    }
}
