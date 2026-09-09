//! ac.rs — 1:1 rewrite of `internal/cbm/ac.c`: an Aho-Corasick
//! multi-pattern matcher with fused LZ4 decompression. The C is custom
//! (~300 lines) because permissive-licensed C AC libraries don't exist;
//! the Rust keeps the same design: a pre-computed goto table (ACISM matrix
//! approach — for each (state, byte) pair the next state is a direct array
//! lookup, zero branches during scanning) and bitmask output for ≤64
//! patterns with an output_next chain for denser sets.

use std::cell::RefCell;

use crate::lz4_store::cbm_lz4_decompress;

/// Maximum pattern count for bitmask mode (C CBM_AC_MAX_BITMASK).
pub const AC_MAX_BITMASK: usize = 64;
const AC_BYTE_RANGE: usize = 256;
const AC_NO_STATE: i32 = -1;
#[inline]
const fn ac_pattern_bit(p: usize) -> u64 {
    1u64 << p
}

#[inline]
const fn ac_clear_low_bit(b: u64) -> u64 {
    b & (b - 1)
}

/// Decompression buffer alignment mask (round up to 64KB chunks).
const DECOMP_BUF_ALIGN_MASK: usize = 0xFFFF;

/// Input for batch LZ4 scanning (C CBMLz4Entry).
pub struct Lz4Entry<'a> {
    pub data: &'a [u8],
    pub original_len: usize,
}

/// One file's batch-scan hit (C CBMLz4Match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lz4Match {
    pub file_index: usize,
    pub bitmask: u64,
}

/// One name's batch-scan hit (C CBMMatchResult).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchResult {
    pub name_index: usize,
    pub pattern_id: usize,
}

/// The automaton (C CBMAutomaton). The C's malloc/realloc tables become
/// owned Vecs; shrink-to-fit at build end mirrors ac_shrink_tables.
pub struct Automaton {
    pub(crate) num_states: usize,
    pub(crate) num_patterns: usize,
    alpha_size: usize,
    /// byte → mapped index (identity when alpha_size == 256).
    alpha_map: [u8; AC_BYTE_RANGE],
    /// [num_states * alpha_size] pre-computed transitions.
    go_table: Vec<i32>,
    /// [num_states] bitmask of matching pattern IDs (≤64).
    output: Vec<u64>,
    /// [num_states] pattern ID at this state, or -1.
    output_list: Vec<i32>,
    /// [num_states] next pointer for the output chain.
    output_next: Vec<i32>,
}

/// Phase 1: build trie (goto function) from patterns. Returns state count
/// (C ac_build_trie).
fn ac_build_trie(
    go_table: &mut [i32],
    output: &mut [u64],
    output_list: &mut [i32],
    alpha_size: usize,
    alpha_map: &[u8; AC_BYTE_RANGE],
    patterns: &[&[u8]],
) -> usize {
    let mut num_states = 1usize; // state 0 = root

    for (p, pattern) in patterns.iter().enumerate() {
        let mut state = 0usize;
        for &byte in pattern.iter() {
            let c = alpha_map[byte as usize] as usize;
            let idx = state * alpha_size + c;
            if go_table[idx] == AC_NO_STATE {
                go_table[idx] = num_states as i32;
                num_states += 1;
            }
            state = go_table[idx] as usize;
        }
        if p < AC_MAX_BITMASK {
            output[state] |= ac_pattern_bit(p);
        }
        output_list[state] = p as i32;
    }

    // Root self-loops for unmatched bytes.
    for slot in &mut go_table[..alpha_size] {
        if *slot == AC_NO_STATE {
            *slot = 0;
        }
    }
    num_states
}

/// Phase 2: build failure function via BFS + compute full goto table
/// (C ac_build_failure).
fn ac_build_failure(ac: &mut Automaton, num_states: usize) {
    let alpha_size = ac.alpha_size;
    let mut fail = vec![0i32; num_states];
    let mut queue: Vec<usize> = Vec::with_capacity(num_states);
    let mut head = 0usize;

    for c in 0..alpha_size {
        let s = ac.go_table[c];
        if s != 0 {
            fail[s as usize] = 0;
            queue.push(s as usize);
        }
    }

    while head < queue.len() {
        let r = queue[head];
        head += 1;
        for c in 0..alpha_size {
            let idx = r * alpha_size + c;
            let s = ac.go_table[idx];
            if s != AC_NO_STATE {
                let s_us = s as usize;
                fail[s_us] = ac.go_table[(fail[r] as usize) * alpha_size + c];
                ac.output[s_us] |= ac.output[fail[s_us] as usize];
                if ac.output_next[s_us] == AC_NO_STATE
                    && ac.output_list[fail[s_us] as usize] != AC_NO_STATE
                {
                    ac.output_next[s_us] = fail[s_us];
                }
                queue.push(s_us);
            } else {
                ac.go_table[idx] = ac.go_table[(fail[r] as usize) * alpha_size + c];
            }
        }
    }
}

impl Automaton {
    /// Construct an automaton from a set of patterns (C cbm_ac_build).
    ///
    /// `alpha_map` — byte→index mapping (None = identity/256). For compact
    /// alphabets, map relevant chars to 1..N and everything else to 0.
    /// Returns None for an empty pattern set (the C returns NULL).
    pub fn build(
        patterns: &[&[u8]],
        alpha_map: Option<&[u8; AC_BYTE_RANGE]>,
        mut alpha_size: usize,
    ) -> Option<Automaton> {
        if patterns.is_empty() {
            return None;
        }
        if alpha_size == 0 {
            alpha_size = AC_BYTE_RANGE;
        }

        let max_states = 1 + patterns.iter().map(|p| p.len()).sum::<usize>();

        let mut map = [0u8; AC_BYTE_RANGE];
        match alpha_map {
            Some(m) => map.copy_from_slice(m),
            None => {
                for (i, slot) in map.iter_mut().enumerate() {
                    *slot = i as u8;
                }
            }
        }

        let mut ac = Automaton {
            num_states: 0,
            num_patterns: patterns.len(),
            alpha_size,
            alpha_map: map,
            go_table: vec![AC_NO_STATE; max_states * alpha_size],
            output: vec![0u64; max_states],
            output_list: vec![AC_NO_STATE; max_states],
            output_next: vec![AC_NO_STATE; max_states],
        };

        let num_states = ac_build_trie(
            &mut ac.go_table,
            &mut ac.output,
            &mut ac.output_list,
            alpha_size,
            &ac.alpha_map,
            patterns,
        );
        ac_build_failure(&mut ac, num_states);
        ac.num_states = num_states;
        // Shrink allocations to the exact state count (C ac_shrink_tables).
        ac.go_table.truncate(num_states * alpha_size);
        ac.go_table.shrink_to_fit();
        ac.output.truncate(num_states);
        ac.output_list.truncate(num_states);
        ac.output_next.truncate(num_states);
        Some(ac)
    }

    /// Scan text and return a bitmask of all matched pattern IDs
    /// (C cbm_ac_scan_bitmask, patterns 0..63).
    pub fn scan_bitmask(&self, text: &[u8]) -> u64 {
        let alpha_size = self.alpha_size;
        let mut result = 0u64;
        let mut state = 0usize;
        for &byte in text {
            let c = self.alpha_map[byte as usize] as usize;
            state = self.go_table[state * alpha_size + c] as usize;
            result |= self.output[state];
        }
        result
    }

    /// Scan multiple NUL-separated names through the automaton; for each
    /// name reports all unique matched pattern IDs (C cbm_ac_scan_batch).
    /// Returns the number of matches written to `out_matches`.
    pub fn scan_batch(
        &self,
        names_buf: &[u8],
        name_offsets: &[usize],
        name_lengths: &[usize],
        out_matches: &mut [MatchResult],
    ) -> usize {
        let mut total = 0usize;
        let alpha_size = self.alpha_size;

        for (n, (&off, &len)) in name_offsets.iter().zip(name_lengths).enumerate() {
            if total >= out_matches.len() {
                break;
            }
            let text = &names_buf[off..off + len];
            let mut state = 0usize;
            let mut seen = 0u64; // per-name dedup

            for &byte in text {
                let c = self.alpha_map[byte as usize] as usize;
                state = self.go_table[state * alpha_size + c] as usize;

                // Walk output chain for >64 patterns (C while s > 0).
                let mut s = state;
                while s > 0 && total < out_matches.len() {
                    // Bitmask fast path for the first 64 patterns.
                    let mut bits = self.output[s] & !seen;
                    while bits != 0 && total < out_matches.len() {
                        let pid = bits.trailing_zeros() as usize;
                        out_matches[total] = MatchResult {
                            name_index: n,
                            pattern_id: pid,
                        };
                        total += 1;
                        seen |= ac_pattern_bit(pid);
                        bits = ac_clear_low_bit(bits);
                    }
                    // Follow output_next for patterns beyond bitmask range.
                    let next_state = self.output_next[s] as usize;
                    if self.output_next[s] == AC_NO_STATE || next_state == s {
                        break;
                    }
                    s = next_state;
                }
            }
        }
        total
    }

    pub fn num_states(&self) -> usize {
        self.num_states
    }

    pub fn num_patterns(&self) -> usize {
        self.num_patterns
    }

    /// Approximate memory used by the goto table (C cbm_ac_table_bytes).
    pub fn table_bytes(&self) -> usize {
        self.num_states * self.alpha_size * std::mem::size_of::<i32>()
    }
}

// ─── Fused LZ4 + AC scan ────────────────────────────────────────

// Thread-local reusable decompression buffer (C tls_decomp_buf): grown in
// 64KB chunks, never shrunk.
thread_local! {
    static DECOMP_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Borrow the thread-local buffer with at least `needed` bytes (C
/// get_decomp_buf).
fn with_decomp_buf<R>(needed: usize, f: impl FnOnce(&[u8]) -> R) -> R {
    DECOMP_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        if buf.len() < needed {
            // Round up to 64KB chunks for reuse.
            let cap = (needed + DECOMP_BUF_ALIGN_MASK) & !DECOMP_BUF_ALIGN_MASK;
            buf.resize(cap, 0);
        }
        f(&buf[..needed])
    })
}

/// Decompress LZ4 data into the thread-local buffer and scan it through
/// the automaton (C cbm_ac_scan_lz4_bitmask). Returns the matched bitmask,
/// or 0 on failure.
pub fn ac_scan_lz4_bitmask(ac: &Automaton, compressed: &[u8], original_len: usize) -> u64 {
    if compressed.is_empty() || original_len == 0 {
        return 0;
    }
    with_decomp_buf(original_len, |buf| {
        let mut slice = buf.to_vec();
        let decompressed = cbm_lz4_decompress(compressed, &mut slice, original_len);
        if decompressed < 0 {
            return 0;
        }
        ac.scan_bitmask(&slice[..decompressed as usize])
    })
}

/// Decompress and scan multiple files in one call (C
/// cbm_ac_scan_lz4_batch). Uses a single reusable decompression buffer
/// across all files; returns the number of matches written to
/// `out_matches`.
pub fn ac_scan_lz4_batch(
    ac: &Automaton,
    entries: &[Lz4Entry<'_>],
    out_matches: &mut [Lz4Match],
) -> usize {
    if entries.is_empty() {
        return 0;
    }
    // Allocate the decompression buffer sized to the largest file.
    let max_orig = entries.iter().map(|e| e.original_len).max().unwrap_or(0);
    with_decomp_buf(max_orig, |shared| {
        let alpha_size = ac.alpha_size;
        let mut total = 0usize;

        for (i, entry) in entries.iter().enumerate() {
            if total >= out_matches.len() {
                break;
            }
            if entry.data.is_empty() || entry.original_len == 0 {
                continue;
            }
            let mut buf = shared.to_vec();
            let decompressed = cbm_lz4_decompress(entry.data, &mut buf, entry.original_len);
            if decompressed <= 0 {
                continue;
            }
            // Inline AC scan for speed (avoid call overhead per file).
            let mut result = 0u64;
            let mut state = 0usize;
            for &byte in &buf[..decompressed as usize] {
                let c = ac.alpha_map[byte as usize] as usize;
                state = ac.go_table[state * alpha_size + c] as usize;
                result |= ac.output[state];
            }
            if result != 0 {
                out_matches[total] = Lz4Match {
                    file_index: i,
                    bitmask: result,
                };
                total += 1;
            }
        }
        total
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lz4_store::{cbm_lz4_bound, cbm_lz4_compress_hc};

    /// Classic example: patterns he/she/his/hers over "ushers".
    #[test]
    fn classic_ushers_bitmask() {
        let patterns: &[&[u8]] = &[b"he", b"she", b"his", b"hers"];
        let ac = Automaton::build(patterns, None, 0).unwrap();
        assert_eq!(ac.num_patterns(), 4);
        // "ushers" contains: "he" (idx 0) at 1, "she" (idx 1) at 1,
        // "hers" (idx 3) at 2. NOT "his" (idx 2).
        let mask = ac.scan_bitmask(b"ushers");
        assert_eq!(mask, 0b1011);
        // Separate hits: "he" only.
        assert_eq!(ac.scan_bitmask(b"he"), 0b0001);
        assert_eq!(ac.scan_bitmask(b"his"), 0b0100);
        assert_eq!(ac.scan_bitmask(b"xyz"), 0);
    }

    #[test]
    fn empty_patterns_returns_none() {
        assert!(Automaton::build(&[], None, 0).is_none());
    }

    #[test]
    fn mapped_alphabet_compacts_table() {
        // Map only a..c to 1..3, everything else to 0.
        let mut map = [0u8; 256];
        map[b'a' as usize] = 1;
        map[b'b' as usize] = 2;
        map[b'c' as usize] = 3;
        let ac = Automaton::build(&[b"abc", b"cab"], Some(&map), 4).unwrap();
        assert_eq!(ac.scan_bitmask(b"xxabcxx"), 0b01);
        assert_eq!(ac.scan_bitmask(b"cab"), 0b10, "cab only matches pattern 1");
        assert_eq!(ac.scan_bitmask(b"xxacbx"), 0);
        // Table bytes use the compact alphabet size.
        assert_eq!(ac.table_bytes(), ac.num_states() * 4 * 4);
    }

    #[test]
    fn batch_scan_dedups_per_name() {
        let patterns: &[&[u8]] = &[b"ab", b"bc", b"ab"];
        let ac = Automaton::build(patterns, None, 0).unwrap();
        // One NUL-separated buffer: "xabc\0abab".
        let names = b"xabc\0abab";
        let offsets = [0usize, 5];
        let lengths = [4usize, 4];
        let mut out = vec![
            MatchResult {
                name_index: 0,
                pattern_id: 0
            };
            8
        ];
        let n = ac.scan_batch(names, &offsets, &lengths, &mut out);
        // Patterns 0 and 2 are both "ab" — the bitmask path reports each
        // distinct pattern ID once per name, in ctz order.
        // Name 0 "xabc": ab(0), ab(2) at the b, then bc(1) at the c.
        // Name 1 "abab": ab(0), ab(2) once (deduped per name).
        assert_eq!(n, 5, "out={out:?}");
        assert_eq!(
            &out[..n],
            &[
                MatchResult {
                    name_index: 0,
                    pattern_id: 0
                },
                MatchResult {
                    name_index: 0,
                    pattern_id: 2
                },
                MatchResult {
                    name_index: 0,
                    pattern_id: 1
                },
                MatchResult {
                    name_index: 1,
                    pattern_id: 0
                },
                MatchResult {
                    name_index: 1,
                    pattern_id: 2
                },
            ]
        );
    }

    #[test]
    fn lz4_fused_scan_roundtrip() {
        let src = b"the quick brown fox, she sells sea shells by the shore. ".repeat(50);
        let mut dst = vec![0u8; cbm_lz4_bound(src.len()) as usize];
        let clen = cbm_lz4_compress_hc(&src, &mut dst);
        assert!(clen > 0);

        let patterns: &[&[u8]] = &[b"she", b"fox", b"zzz"];
        let ac = Automaton::build(patterns, None, 0).unwrap();
        let mask = ac_scan_lz4_bitmask(&ac, &dst[..clen as usize], src.len());
        assert_eq!(mask, 0b011, "she+fox match, zzz not");

        // Corrupt compressed data → 0.
        assert_eq!(ac_scan_lz4_bitmask(&ac, &[0xFF; 32], src.len()), 0);
        assert_eq!(ac_scan_lz4_bitmask(&ac, &dst[..clen as usize], 0), 0);
    }

    #[test]
    fn lz4_batch_reports_file_indexes() {
        let mk = |txt: &[u8]| -> (Vec<u8>, usize) {
            let mut dst = vec![0u8; cbm_lz4_bound(txt.len()) as usize];
            let n = cbm_lz4_compress_hc(txt, &mut dst);
            (dst[..n as usize].to_vec(), txt.len())
        };
        let (d0, o0) = mk(b"alpha beta gamma");
        let (d1, o1) = mk(b"nothing relevant here");
        let (d2, o2) = mk(b"beta found twice: beta");
        let entries = vec![
            Lz4Entry {
                data: &d0,
                original_len: o0,
            },
            Lz4Entry {
                data: &d1,
                original_len: o1,
            },
            Lz4Entry {
                data: &d2,
                original_len: o2,
            },
        ];
        let ac = Automaton::build(&[b"beta"], None, 0).unwrap();
        let mut out = vec![
            Lz4Match {
                file_index: 0,
                bitmask: 0
            };
            4
        ];
        let n = ac_scan_lz4_batch(&ac, &entries, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0].file_index, 0);
        assert_eq!(out[0].bitmask, 1);
        assert_eq!(out[1].file_index, 2);
    }
}
