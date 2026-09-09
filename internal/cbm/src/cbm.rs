//! cbm.rs — 1:1 rewrite of `internal/cbm/cbm.c` part 1: profile counters,
//! bottleneck-metric helpers, error-region collection and the parse-coverage
//! recovery/refinement rules.
//!
//! Part 2 (the `extract_file` orchestrator) lives in cbm_extract.rs.
//!
//! Porting notes:
//! - The C's atomic profile counters become AtomicU64 statics with the same
//!   accessors.
//! - cbm_error_regions_t's fixed 256-slot arrays become a Vec with the same
//!   cap/dropped accounting, so `dropped` still means "ranges the cap threw
//!   away" and the "+N" suffix contract is unchanged.

// Part-2 (the extract_file orchestrator in cbm_extract.rs) consumes the
// pub(crate) API below; until it lands, dead-code analysis sees only the
// tests. The allow keeps clippy -D warnings green across the split.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use tree_sitter::Node;

// ── Profile counters (C total_* atomics) ────────────────────────

static TOTAL_PARSE_NS: AtomicU64 = AtomicU64::new(0);
static TOTAL_EXTRACT_NS: AtomicU64 = AtomicU64::new(0);
static TOTAL_LSP_NS: AtomicU64 = AtomicU64::new(0);
static TOTAL_PREPROCESS_NS: AtomicU64 = AtomicU64::new(0);
static TOTAL_FILES_PREPROCESSED: AtomicU64 = AtomicU64::new(0);
static TOTAL_FILES: AtomicU64 = AtomicU64::new(0);

/// Accumulated profile snapshot (C cbm_profile_out_t fields).
#[derive(Debug, Clone, Copy, Default)]
pub struct Profile {
    pub parse_ns: u64,
    pub extract_ns: u64,
    pub lsp_ns: u64,
    pub preprocess_ns: u64,
    pub files_preprocessed: u64,
    pub files: u64,
}

/// Accumulated parse/extract times and file count (C cbm_get_profile).
pub fn get_profile() -> Profile {
    Profile {
        parse_ns: TOTAL_PARSE_NS.load(Ordering::Relaxed),
        extract_ns: TOTAL_EXTRACT_NS.load(Ordering::Relaxed),
        lsp_ns: TOTAL_LSP_NS.load(Ordering::Relaxed),
        preprocess_ns: TOTAL_PREPROCESS_NS.load(Ordering::Relaxed),
        files_preprocessed: TOTAL_FILES_PREPROCESSED.load(Ordering::Relaxed),
        files: TOTAL_FILES.load(Ordering::Relaxed),
    }
}

pub fn get_lsp_ns() -> u64 {
    TOTAL_LSP_NS.load(Ordering::Relaxed)
}

pub fn get_preprocess_ns() -> u64 {
    TOTAL_PREPROCESS_NS.load(Ordering::Relaxed)
}

pub fn get_files_preprocessed() -> u64 {
    TOTAL_FILES_PREPROCESSED.load(Ordering::Relaxed)
}

/// Zero the profiling counters (C cbm_reset_profile).
pub fn reset_profile() {
    TOTAL_PARSE_NS.store(0, Ordering::Relaxed);
    TOTAL_EXTRACT_NS.store(0, Ordering::Relaxed);
    TOTAL_LSP_NS.store(0, Ordering::Relaxed);
    TOTAL_PREPROCESS_NS.store(0, Ordering::Relaxed);
    TOTAL_FILES_PREPROCESSED.store(0, Ordering::Relaxed);
    TOTAL_FILES.store(0, Ordering::Relaxed);
}

#[allow(dead_code)] // consumed by the part-2 extract_file orchestrator
pub(crate) fn profile_add_parse(ns: u64) {
    TOTAL_PARSE_NS.fetch_add(ns, Ordering::Relaxed);
}
#[allow(dead_code)] // consumed by the part-2 extract_file orchestrator
pub(crate) fn profile_add_extract(ns: u64) {
    TOTAL_EXTRACT_NS.fetch_add(ns, Ordering::Relaxed);
}
#[allow(dead_code)] // consumed by the part-2 extract_file orchestrator
pub(crate) fn profile_add_lsp(ns: u64) {
    TOTAL_LSP_NS.fetch_add(ns, Ordering::Relaxed);
}
#[allow(dead_code)] // consumed by the part-2 extract_file orchestrator
pub(crate) fn profile_add_preprocess(ns: u64) {
    TOTAL_PREPROCESS_NS.fetch_add(ns, Ordering::Relaxed);
}
#[allow(dead_code)] // consumed by the part-2 extract_file orchestrator
pub(crate) fn profile_add_file() {
    TOTAL_FILES.fetch_add(1, Ordering::Relaxed);
}
#[allow(dead_code)] // consumed by the part-2 extract_file orchestrator
pub(crate) fn profile_add_file_preprocessed() {
    TOTAL_FILES_PREPROCESSED.fetch_add(1, Ordering::Relaxed);
}

// ── Bottleneck metric helpers (C name_ieq … count_params) ───────

/// Case-insensitive ASCII name equality (C name_ieq).
fn name_ieq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn name_in_set(name: &str, set: &[&str]) -> bool {
    set.iter().any(|s| name_ieq(name, s))
}

/// Linear-scan / membership calls: a hit inside a loop is the textbook
/// hidden O(n^2) (cf. Olivo et al., PLDI'15) that syntactic loop-depth
/// alone misses (C is_linear_scan_name).
pub(crate) fn is_linear_scan_name(n: &str) -> bool {
    const SET: &[&str] = &[
        "find",
        "indexof",
        "contains",
        "includes",
        "search",
        "lookup",
        "strstr",
        "strchr",
        "strrchr",
        "memchr",
        "find_if",
        "findindex",
        "count",
        "index",
    ];
    name_in_set(n, SET)
}

/// Allocation / growable-append calls: repeated inside a loop is the classic
/// accidental reallocation / string-concat O(n^2) (C is_alloc_name).
pub(crate) fn is_alloc_name(n: &str) -> bool {
    const SET: &[&str] = &[
        "malloc",
        "calloc",
        "realloc",
        "strdup",
        "strndup",
        "append",
        "push_back",
        "emplace_back",
        "concat",
        "strcat",
        "strncat",
        "push",
        "pushback",
    ];
    name_in_set(n, SET)
}

/// Extract the receiver identifier from a def's receiver text — Go's
/// `(s *Store)` / `(s Store)` → "s" (C receiver_ident). None for unnamed
/// receivers ("(*Store)", "(Store)"): a lone token is the TYPE, not a name.
pub(crate) fn receiver_ident(recv_text: &str) -> Option<&str> {
    let mut rest = recv_text.strip_prefix('(').unwrap_or(recv_text);
    rest = rest.trim_start_matches([' ', '\t']);
    let ident_len = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    if ident_len == 0 {
        return None; // "(*Store)": leading '*', no identifier
    }
    let ident = &rest[..ident_len];
    let after = rest[ident_len..].trim_start_matches([' ', '\t']);
    if after.is_empty() || after.starts_with(')') {
        return None; // "(Store)": single token is the type, receiver unnamed
    }
    Some(ident)
}

/// Whether a callee expression targets the same instance/class as the
/// enclosing def — genuine self-recursion, not a same-named call on a
/// different receiver (C is_self_receiver). Bare names have no receiver →
/// assume self-call. Qualified names: the WHOLE receiver chain before the
/// last '.' must be self/this/cls/@self or the def's own receiver
/// identifier (Go `s` in `func (s *Store) save()`); `self.obj.recur`
/// targets a FIELD and stays false. See #599.
pub(crate) fn is_self_receiver(callee_name: &str, def_receiver: Option<&str>) -> bool {
    if callee_name.is_empty() {
        return false;
    }
    let Some(dot) = callee_name.rfind('.') else {
        return true; // bare name → self-recursion candidate
    };
    let chain = &callee_name[..dot];
    if matches!(chain, "self" | "this" | "cls" | "@self") {
        return true;
    }
    if let Some(recv) = def_receiver {
        if let Some(rid) = receiver_ident(recv) {
            if rid == chain {
                return true; // call through the enclosing method's own receiver
            }
        }
    }
    false // super() / axios / console / self.obj / any other receiver
}

/// Count parameters from a signature like "(int a, Foo* b, cb (*)(int,int))"
/// (C count_params_from_signature): top-level commas + 1; "()" and "(void)"
/// count as 0. Approximate by design (a structural smell, not exact arity).
pub(crate) fn count_params_from_signature(sig: &str) -> i32 {
    let Some(open) = sig.find('(') else {
        return 0;
    };
    let mut depth = 0i32;
    let mut commas = 0i32;
    let mut any = false;
    for ch in sig[open + 1..].chars() {
        match ch {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' if depth == 0 => break,
            ')' => depth -= 1,
            ']' | '}' | '>' if depth > 0 => depth -= 1,
            ']' | '}' | '>' => {}
            ',' if depth == 0 => commas += 1,
            c if !c.is_whitespace() => any = true,
            _ => {}
        }
    }
    if !any {
        return 0; // "()"
    }
    if commas == 0 {
        let list = sig[open + 1..].trim_start_matches([' ', '\t']);
        if list.starts_with("void")
            && matches!(list.as_bytes().get(4), Some(b')') | Some(b' ') | None)
        {
            return 0; // C "(void)"
        }
    }
    commas + 1
}

// ── Error regions (C cbm_error_regions_t) ───────────────────────

/// C CBM_MAX_ERROR_REGIONS.
pub(crate) const MAX_ERROR_REGIONS: usize = 256;
/// C CBM_PERL_MAX_PARSE_NESTING.
pub(crate) const PERL_MAX_PARSE_NESTING: i32 = 128;
/// C CBM_UNUSABLE_PCT — one range must cover 80% of a file to be noise.
pub(crate) const UNUSABLE_PCT: u32 = 80;

/// Top-most ERROR/MISSING line ranges (C cbm_error_regions_t). `dropped`
/// counts ranges the cap threw away so a clipped list cannot read complete.
#[derive(Debug, Clone, Default)]
pub(crate) struct ErrorRegions {
    pub starts: Vec<u32>,
    pub ends: Vec<u32>,
    pub dropped: i32,
}

impl ErrorRegions {
    fn push(&mut self, start_line: u32, end_line: u32) {
        // Only an EXACT repeat of the already-open range is dropped
        // (overlapping ranges are judged separately by recovery — see C).
        if let (Some(&ls), Some(&le)) = (self.starts.last(), self.ends.last()) {
            if ls == start_line && le == end_line {
                return;
            }
        }
        if self.starts.len() >= MAX_ERROR_REGIONS {
            self.dropped += 1;
            return;
        }
        self.starts.push(start_line);
        self.ends.push(end_line);
    }
}

/// Skip pathologically nested Perl before tree-sitter's recursive GLR
/// stack merge overflows a small stack (C cbm_source_nesting_exceeds).
pub(crate) fn source_nesting_exceeds(source: &str, cap: i32) -> bool {
    let mut depth = 0i32;
    for c in source.bytes() {
        match c {
            b'(' | b'[' | b'{' => {
                depth += 1;
                if depth > cap {
                    return true;
                }
            }
            b')' | b']' | b'}' if depth > 0 => depth -= 1,
            _ => {}
        }
    }
    false
}

/// Line flags for the Phase-2 coverage map (C CBM_LINE_* enum).
pub(crate) const LINE_PP_PARSED: u8 = 1;
pub(crate) const LINE_NO_CODE: u8 = 2;

/// Zero-width MISSING terminator at EOF is not a miss (C
/// cbm_is_eof_terminator_miss): the parser consumed no source for it, and
/// grammars disagree on whether the terminator token is visible — flagging
/// it made the verdict arbitrary. #1746 extends the exact-EOF rule past
/// trailing blanks only for a missing NEWLINE token.
fn is_blank_not_newline(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | 0x0B | 0x0C | b'\r')
}

fn is_eof_terminator_miss(node: Node<'_>, source: &[u8]) -> bool {
    if !node.is_missing() {
        return false;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    if start != end || end > source.len() {
        return false;
    }
    if end == source.len() {
        return true;
    }
    if node.kind() != "\n" {
        return false;
    }
    source[end..].iter().all(|&b| is_blank_not_newline(b))
}

/// Walk only the has_error paths and record the 1-based line ranges of the
/// TOP-MOST ERROR/MISSING nodes, without descending into an error subtree
/// (C cbm_collect_error_regions). Walks to the end even after the cap is
/// full so `dropped` is the real count.
pub(crate) fn collect_error_regions(root: Node<'_>, source: &str) -> ErrorRegions {
    let mut acc = ErrorRegions::default();
    let src = source.as_bytes();
    // Explicit recursion stack — the C recurses, bounded by tree depth.
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        for i in 0..n.child_count() {
            let Some(c) = n.child(i) else { continue };
            if c.is_missing() || c.kind() == "ERROR" {
                if is_eof_terminator_miss(c, src) {
                    continue; // absent final newline only — nothing was dropped
                }
                // Column 0 end = stopped right after the previous newline;
                // counting that row named a line past EOF (C comment).
                let (start_point, end_point) = (c.start_position(), c.end_position());
                let start_line = (start_point.row + 1) as u32;
                let mut end_line = (end_point.row + 1) as u32;
                if end_point.column == 0 && end_point.row > start_point.row {
                    end_line = end_point.row as u32;
                }
                acc.push(start_line, end_line);
                // top-most region; do not descend
            } else if c.has_error() {
                stack.push(c);
            }
        }
    }
    acc
}

// ── Recovery subtraction (C cbm_region_is_recovered …) ──────────

const MAX_COVER_DEFS: usize = 256;

/// True when definitions starting inside [rs, re] fully cover it — the
/// region was re-extracted, so it is not a parse miss (C
/// cbm_region_is_recovered). Insertion-sorts by start, then sweeps for
/// gaps; Module/Package defs carry no recovery evidence.
fn region_is_recovered(rs: u32, re: u32, defs: &[crate::types::Definition]) -> bool {
    let mut starts: Vec<u32> = Vec::with_capacity(MAX_COVER_DEFS);
    let mut ends: Vec<u32> = Vec::with_capacity(MAX_COVER_DEFS);
    for d in defs {
        if d.label == "Module" || d.label == "Package" {
            continue;
        }
        if d.start_line < rs || d.start_line > re {
            continue; // recovery evidence must originate inside the region
        }
        if starts.len() >= MAX_COVER_DEFS {
            break;
        }
        starts.push(d.start_line);
        ends.push(d.end_line.max(d.start_line));
    }
    if starts.is_empty() {
        return false;
    }
    // Sort by start (C uses insertion sort).
    let mut order: Vec<usize> = (0..starts.len()).collect();
    order.sort_by_key(|&i| starts[i]);
    let mut covered_to = rs - 1;
    for &i in &order {
        if starts[i] > covered_to + 1 {
            return false; // uncovered gap
        }
        if ends[i] > covered_to {
            covered_to = ends[i];
        }
    }
    covered_to >= re
}

/// True when 1-based `line` of `src` contains `name` (C cbm_line_contains):
/// verifies a def recovered from EXPANDED source really lives on that
/// ORIGINAL line.
pub(crate) fn line_contains(src: &str, line: u32, name: &str) -> bool {
    if name.is_empty() || line == 0 {
        return false;
    }
    let bytes = src.as_bytes();
    let mut offset = 0usize;
    for _ in 1..line {
        match bytes[offset..].iter().position(|&b| b == b'\n') {
            Some(p) => offset += p + 1,
            None => return false,
        }
    }
    if offset > bytes.len() {
        return false;
    }
    let end = bytes[offset..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |p| offset + p);
    // Substring test within the line.
    src[offset..end].contains(name)
}

fn is_identifier_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Verify the mapped original span contains callable-definition SYNTAX —
/// `name(` with a `{` body after the matching `)` — not merely the name at
/// a call site (C cbm_span_contains_callable_def).
pub(crate) fn span_contains_callable_def(
    src: &str,
    start_line: u32,
    end_line: u32,
    name: &str,
) -> bool {
    if name.is_empty() || start_line == 0 || end_line < start_line {
        return false;
    }
    let bytes = src.as_bytes();
    let mut span_start = 0usize;
    let mut line = 1u32;
    while span_start < bytes.len() && line < start_line {
        if bytes[span_start] == b'\n' {
            line += 1;
        }
        span_start += 1;
    }
    if line != start_line {
        return false;
    }
    let mut span_end = span_start;
    while span_end < bytes.len() && line <= end_line {
        if bytes[span_end] == b'\n' {
            if line == end_line {
                break;
            }
            line += 1;
        }
        span_end += 1;
    }
    if line < end_line {
        return false;
    }
    let name_len = name.len();
    let mut pos = span_start;
    while pos + name_len <= span_end {
        if &bytes[pos..pos + name_len] != name.as_bytes()
            || (pos > 0 && is_identifier_char(bytes[pos - 1]))
            || (pos + name_len < bytes.len() && is_identifier_char(bytes[pos + name_len]))
        {
            pos += 1;
            continue;
        }
        let mut before = pos;
        while before > span_start && bytes[before - 1].is_ascii_whitespace() {
            before -= 1;
        }
        if before > span_start
            && matches!(
                bytes[before - 1],
                b'(' | b',' | b'=' | b'!' | b'?' | b'[' | b'.'
            )
        {
            pos += 1;
            continue;
        }
        let mut open = pos + name_len;
        while open < span_end && bytes[open].is_ascii_whitespace() {
            open += 1;
        }
        if open >= span_end || bytes[open] != b'(' {
            pos += 1;
            continue;
        }
        let mut depth = 0i32;
        let close = bytes[open..span_end].iter().position(|&b| {
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
            false
        });
        let close = close.map(|p| open + p);
        let Some(close) = close else {
            pos += 1;
            continue;
        };
        for &b in &bytes[close + 1..span_end] {
            if b == b'{' {
                return true;
            }
            if b == b';' {
                break;
            }
        }
        pos += 1;
    }
    false
}

/// Drop every region that definitions re-extracted (C
/// cbm_subtract_recovered_regions).
pub(crate) fn subtract_recovered_regions(
    regs: &mut ErrorRegions,
    defs: &[crate::types::Definition],
) {
    let mut kept = 0;
    for i in 0..regs.starts.len() {
        let (rs, re) = (regs.starts[i], regs.ends[i]);
        if !region_is_recovered(rs, re, defs) {
            regs.starts[kept] = rs;
            regs.ends[kept] = re;
            kept += 1;
        }
    }
    regs.starts.truncate(kept);
    regs.ends.truncate(kept);
}

/// True when [start_line, end_line] contains a call `NAME(` to a
/// file-defined function-like macro (Macro label + signature) — a benign
/// call the grammar can't parse without the preprocessor (#1071; C
/// cbm_byte_span_is_macro_invocation).
fn byte_span_is_macro_invocation(
    src: &str,
    span_start: usize,
    span_end: usize,
    defs: &[crate::types::Definition],
) -> bool {
    if span_start >= span_end || span_end > src.len() {
        return false;
    }
    let bytes = src.as_bytes();
    for d in defs {
        // Function-like macros only: an object-like macro has no parameter
        // signature and can't be mistaken for a call.
        if d.label != "Macro" || d.signature.is_none() || d.name.is_empty() {
            continue;
        }
        let name = d.name.as_bytes();
        let nlen = name.len();
        let mut pos = span_start;
        while pos + nlen <= span_end {
            if &bytes[pos..pos + nlen] != name
                || (pos > 0 && is_identifier_char(bytes[pos - 1]))
                || (pos + nlen < bytes.len() && is_identifier_char(bytes[pos + nlen]))
            {
                pos += 1;
                continue;
            }
            let mut open = pos + nlen;
            while open < span_end && bytes[open].is_ascii_whitespace() {
                open += 1;
            }
            if open < span_end && bytes[open] == b'(' {
                return true; // NAME( ... ) — an invocation of this file's macro
            }
            pos += 1;
        }
    }
    false
}

/// Line-span form of byte_span_is_macro_invocation (C
/// cbm_span_is_macro_invocation).
fn span_is_macro_invocation(
    src: &str,
    start_line: u32,
    end_line: u32,
    defs: &[crate::types::Definition],
) -> bool {
    if start_line == 0 || end_line < start_line {
        return false;
    }
    let bytes = src.as_bytes();
    let mut span_start = 0usize;
    let mut line = 1u32;
    while span_start < bytes.len() && line < start_line {
        if bytes[span_start] == b'\n' {
            line += 1;
        }
        span_start += 1;
    }
    if line != start_line {
        return false;
    }
    let mut span_end = span_start;
    while span_end < bytes.len() && line <= end_line {
        if bytes[span_end] == b'\n' {
            if line == end_line {
                break;
            }
            line += 1;
        }
        span_end += 1;
    }
    if line < end_line {
        return false;
    }
    byte_span_is_macro_invocation(src, span_start, span_end, defs)
}

/// True if [rs, re] is fully enclosed by an extracted Function/Method/
/// Constructor/Destructor body (C cbm_region_inside_callable): a macro
/// invocation INSIDE a body is an expression-level use (#1071); a TOP-LEVEL
/// invocation may expand to a whole definition (#949) and stays flagged.
fn region_inside_callable(rs: u32, re: u32, defs: &[crate::types::Definition]) -> bool {
    defs.iter().any(|d| {
        matches!(
            d.label.as_str(),
            "Function" | "Method" | "Constructor" | "Destructor"
        ) && d.start_line <= rs
            && d.end_line >= re
            && d.end_line > d.start_line
    })
}

/// Drop benign in-body macro-invocation regions (C
/// cbm_subtract_macro_invocation_regions).
pub(crate) fn subtract_macro_invocation_regions(
    regs: &mut ErrorRegions,
    defs: &[crate::types::Definition],
    src: &str,
) {
    let mut kept = 0;
    for i in 0..regs.starts.len() {
        let (rs, re) = (regs.starts[i], regs.ends[i]);
        let benign =
            span_is_macro_invocation(src, rs, re, defs) && region_inside_callable(rs, re, defs);
        if !benign {
            regs.starts[kept] = rs;
            regs.ends[kept] = re;
            kept += 1;
        }
    }
    regs.starts.truncate(kept);
    regs.ends.truncate(kept);
}

/// Push [start, end] after trimming no-code lines off both ends (C
/// cbm_push_trimmed_run). A run made only of directives, comments or blank
/// lines disappears entirely.
fn push_trimmed_run(
    out: &mut ErrorRegions,
    mut start: u32,
    mut end: u32,
    map: &[u8],
    line_count: u32,
) {
    while start <= end && start <= line_count && (map[start as usize] & LINE_NO_CODE) != 0 {
        start += 1;
    }
    while end >= start && end <= line_count && (map[end as usize] & LINE_NO_CODE) != 0 {
        end -= 1;
    }
    if start > end {
        return;
    }
    if out.starts.len() >= MAX_ERROR_REGIONS {
        out.dropped += 1;
        return;
    }
    out.starts.push(start);
    out.ends.push(end);
}

/// Byte offset where every 1-based line starts (C cbm_build_line_offsets):
/// line_count + 2 entries; unreached lines start at the source end so their
/// span is empty.
fn build_line_offsets(src: &str, line_count: u32) -> Vec<usize> {
    let n = line_count as usize + 2;
    let mut offsets = vec![src.len(); n];
    offsets[0] = 0;
    if n > 1 {
        offsets[1] = 0;
    }
    let mut line = 1u32;
    for (i, &b) in src.as_bytes().iter().enumerate() {
        if b != b'\n' {
            continue;
        }
        line += 1;
        if line as usize > line_count as usize + 1 {
            break;
        }
        offsets[line as usize] = i + 1;
    }
    offsets
}

/// Top-level macro invocation: the one place where a clean second parse
/// proves nothing (#949; C cbm_line_is_toplevel_macro_call).
fn line_is_toplevel_macro_call(
    src: &str,
    line: u32,
    line_offsets: &[usize],
    defs: &[crate::types::Definition],
) -> bool {
    let is_call = byte_span_is_macro_invocation(
        src,
        line_offsets[line as usize],
        line_offsets[line as usize + 1],
        defs,
    );
    is_call && !region_inside_callable(line, line, defs)
}

/// Cut every raw region down to the lines the preprocessed parse could not
/// vouch for (C cbm_refine_regions_with_pp_lines). One region becomes zero
/// or more smaller ranges — one per run of uncovered consecutive lines.
/// The branch the preprocessor discarded is genuinely absent from the
/// graph and must stay flagged, so a covered line only splits the run when
/// it is not itself a top-level macro call.
pub(crate) fn refine_regions_with_pp_lines(
    regs: &mut ErrorRegions,
    map: &[u8],
    line_count: u32,
    src: &str,
    defs: &[crate::types::Definition],
) {
    let mut out = ErrorRegions {
        dropped: regs.dropped,
        ..Default::default()
    };
    let line_offsets = build_line_offsets(src, line_count);
    for i in 0..regs.starts.len() {
        let mut run_start = 0u32;
        let mut run_end = 0u32;
        let end = regs.ends[i].min(line_count);
        let mut line = regs.starts[i];
        while line <= end {
            let covered = (map[line as usize] & LINE_PP_PARSED) != 0
                && !line_is_toplevel_macro_call(src, line, &line_offsets, defs);
            if covered {
                if run_start != 0 {
                    push_trimmed_run(&mut out, run_start, run_end, map, line_count);
                    run_start = 0;
                }
            } else {
                if run_start == 0 {
                    run_start = line;
                }
                run_end = line;
            }
            line += 1;
        }
        if run_start != 0 {
            push_trimmed_run(&mut out, run_start, run_end, map, line_count);
        }
    }
    *regs = out;
}

/// Number of 1-based lines (C cbm_count_lines): separators plus one, so a
/// file without a trailing newline still has its last line.
pub(crate) fn count_lines(src: &str) -> u32 {
    let bytes = src.as_bytes();
    let mut n = 1u32;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' && i + 1 < bytes.len() {
            n += 1;
        }
    }
    n
}

/// Serialize regions as "start-end,start-end,..." with a trailing ",+<N>"
/// when the cap threw N ranges away (C cbm_error_ranges_str). The marker
/// must stay a SUFFIX — every reader stops at the first non-range token.
pub(crate) fn error_ranges_str(regs: &ErrorRegions) -> Option<String> {
    if regs.starts.is_empty() && regs.dropped <= 0 {
        return None;
    }
    let mut out = String::new();
    for i in 0..regs.starts.len() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{}-{}", regs.starts[i], regs.ends[i]));
    }
    if regs.dropped > 0 {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&format!("+{}", regs.dropped));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_scan_and_alloc_names() {
        assert!(is_linear_scan_name("find"));
        assert!(is_linear_scan_name("IndexOf")); // case-insensitive
        assert!(is_linear_scan_name("memchr"));
        assert!(!is_linear_scan_name("insert"));
        assert!(is_alloc_name("malloc"));
        assert!(is_alloc_name("Append"));
        assert!(is_alloc_name("push_back"));
        assert!(!is_alloc_name("free"));
    }

    #[test]
    fn receiver_ident_go_forms() {
        assert_eq!(receiver_ident("(s *Store)"), Some("s"));
        assert_eq!(receiver_ident("(s Store)"), Some("s"));
        assert_eq!(receiver_ident("(*Store)"), None);
        assert_eq!(receiver_ident("(Store)"), None);
        assert_eq!(receiver_ident("()"), None);
    }

    #[test]
    fn self_receiver_chain_rules() {
        assert!(is_self_receiver("recur", None), "bare name");
        assert!(is_self_receiver("self.recur", None));
        assert!(is_self_receiver("this.save", None));
        assert!(is_self_receiver("cls.create", None));
        assert!(!is_self_receiver("super().save", None));
        assert!(!is_self_receiver("axios.get", None));
        assert!(!is_self_receiver("self.obj.recur", None), "field target");
        // Go receiver match: `s.Recur` inside `func (s *Store) Recur`.
        assert!(is_self_receiver("s.Recur", Some("(s *Store)")));
        assert!(!is_self_receiver("t.Recur", Some("(s *Store)")));
    }

    #[test]
    fn param_count_from_signature() {
        assert_eq!(count_params_from_signature("()"), 0);
        assert_eq!(count_params_from_signature("(void)"), 0);
        assert_eq!(count_params_from_signature("(int a, Foo* b)"), 2);
        assert_eq!(
            count_params_from_signature("cb (*)(int,int)"),
            1,
            "first paren is the fn-pointer group — C counts the same"
        );
        assert_eq!(count_params_from_signature("(void (*)(int), int n)"), 2);
    }

    #[test]
    fn nesting_guard() {
        assert!(!source_nesting_exceeds("a(b(c))", 128));
        assert!(source_nesting_exceeds("((((((((((((1))))))))))))", 5));
    }

    #[test]
    fn error_region_collection_and_dedup() {
        let src = "function a() {\n  @@bad syntax here\n}\n\nfunction b() {\n";
        let tree = crate::ts::parse(crate::Language::JAVASCRIPT, src).unwrap();
        let regs = collect_error_regions(tree.root_node(), src);
        // Actual number depends on the grammar's recovery; just verify
        // plumbing: no exact repeats, ranges sorted as collected, EOF
        // zero-width MISSING excluded when present.
        for i in 1..regs.starts.len() {
            assert!(
                !(regs.starts[i] == regs.starts[i - 1] && regs.ends[i] == regs.ends[i - 1]),
                "exact repeat {i}"
            );
        }
    }

    #[test]
    fn region_recovery_by_defs() {
        let mkdef = |name: &str, s: u32, e: u32, label: &str| crate::types::Definition {
            name: name.into(),
            label: label.into(),
            start_line: s,
            end_line: e,
            ..Default::default()
        };
        let defs = vec![mkdef("a", 1, 5, "Function"), mkdef("b", 7, 9, "Function")];
        // Line 6 has no covering def → gap → not recovered.
        assert!(!region_is_recovered(1, 9, &defs));
        assert!(!region_is_recovered(1, 10, &defs));
        // Adjacent coverage 1-5 + 6-9 → recovered.
        let defs2 = vec![mkdef("a", 1, 5, "Function"), mkdef("b", 6, 9, "Function")];
        assert!(region_is_recovered(1, 9, &defs2));
        // Module labels carry no evidence.
        let mods = vec![mkdef("m", 1, 9, "Module")];
        assert!(!region_is_recovered(1, 9, &mods));
    }

    #[test]
    fn line_contains_and_callable_def() {
        let src = "int main(void)\n{\n  return 0;\n}\n";
        assert!(line_contains(src, 1, "main"));
        assert!(!line_contains(src, 2, "main"));
        assert!(span_contains_callable_def(src, 1, 4, "main"));
        // A call site is not a definition: `main();` has ';' before '{'.
        let call_src = "  main();\n  int x;\n";
        assert!(!span_contains_callable_def(call_src, 1, 2, "main"));
    }

    #[test]
    fn count_lines_and_ranges_str() {
        assert_eq!(count_lines("a\nb\nc"), 3);
        assert_eq!(count_lines("a\nb\n"), 2);
        assert_eq!(count_lines(""), 1);

        let mut regs = ErrorRegions::default();
        regs.push(3, 5);
        regs.push(7, 7);
        regs.dropped = 2;
        assert_eq!(error_ranges_str(&regs).as_deref(), Some("3-5,7-7,+2"));
        assert_eq!(error_ranges_str(&ErrorRegions::default()), None);
    }

    #[test]
    fn macro_invocation_regions() {
        let mut d = crate::types::Definition {
            name: "ALLOC".into(),
            label: "Macro".into(),
            signature: Some("(type, n)".into()),
            start_line: 1,
            end_line: 2,
            ..Default::default()
        };
        d.signature = Some("(t, n)".into());
        let defs = vec![d];
        let src = "ALLOC(int, n)\n";
        assert!(span_is_macro_invocation(src, 1, 1, &defs));
        // Not inside a callable → NOT benign (top-level stays flagged).
        let mut regs = ErrorRegions::default();
        regs.push(1, 1);
        subtract_macro_invocation_regions(&mut regs, &defs, src);
        assert_eq!(regs.starts.len(), 1, "top-level invocation stays flagged");

        // Inside a function body → benign, dropped.
        let defs2: Vec<crate::types::Definition> = defs
            .iter()
            .cloned()
            .chain(std::iter::once(crate::types::Definition {
                name: "f".into(),
                label: "Function".into(),
                start_line: 2,
                end_line: 5,
                ..Default::default()
            }))
            .collect();
        let src2 = "int f() {\n  ALLOC(int, n);\n}\n";
        let mut regs2 = ErrorRegions::default();
        regs2.push(2, 2);
        subtract_macro_invocation_regions(&mut regs2, &defs2, src2);
        assert!(regs2.starts.is_empty(), "in-body invocation is benign");
    }

    #[test]
    fn refine_with_pp_lines_splits_runs() {
        let src = "a\nb\nc\nd\ne\n";
        // Lines 1-5; mark 2 and 4 as parsed by the preprocessed pass, and
        // 5 as no-code (directive/comment/blank).
        let mut map = [0u8; 8];
        map[2] = LINE_PP_PARSED;
        map[4] = LINE_PP_PARSED;
        map[5] = LINE_NO_CODE;
        let mut regs = ErrorRegions::default();
        regs.push(1, 5);
        let defs: Vec<crate::types::Definition> = Vec::new();
        refine_regions_with_pp_lines(&mut regs, &map, 5, src, &defs);
        // Covered lines 2 and 4 split the run into 1, 3, and 5-trimmed-away.
        assert_eq!(regs.starts, vec![1, 3], "{regs:?}");
        assert_eq!(regs.ends, vec![1, 3]);
    }
}
