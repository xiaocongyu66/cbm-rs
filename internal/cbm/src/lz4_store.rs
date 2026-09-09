//! lz4_store.rs — 1:1 rewrite of `internal/cbm/lz4_store.c`: thin wrappers
//! around LZ4 (HC level 9 in the C) used by the auto-complete cache. The C
//! vendors the LZ4 source; the Rust uses the `lz4_flex` crate, which writes
//! the same LZ4 block format but offers no separate HC implementation and
//! no `compress_bound` — the bound follows the official LZ4 formula.
//!
//! C's int-returning convention: positive = bytes written, negative =
//! error.

/// Worst-case compressed size (LZ4_compressBound): input + input/255 + 16.
fn lz4_compress_bound(input_size: usize) -> usize {
    if input_size > LZ4_MAX_INPUT_SIZE {
        return 0;
    }
    input_size + input_size / 255 + 16
}

/// LZ4_MAX_INPUT_SIZE (0x7E000000): inputs beyond this have no bound.
const LZ4_MAX_INPUT_SIZE: usize = 0x7E00_0000;

/// Compress into the caller's buffer (C cbm_lz4_compress_hc). Returns the
/// compressed length, or -1 when the destination is too small or the input
/// is invalid. lz4_flex's slice API demands ~10% headroom beyond the
/// official LZ4_compressBound, so compress to a scratch Vec and copy —
/// callers allocating with cbm_lz4_bound (the C convention) still work.
pub fn cbm_lz4_compress_hc(src: &[u8], dst: &mut [u8]) -> i32 {
    let compressed = lz4_flex::block::compress(src);
    if compressed.len() > dst.len() {
        return -1;
    }
    dst[..compressed.len()].copy_from_slice(&compressed);
    compressed.len() as i32
}

/// Decompress into the caller's buffer (C cbm_lz4_decompress). Returns the
/// decompressed length, or -1 on corruption / size mismatch.
pub fn cbm_lz4_decompress(src: &[u8], dst: &mut [u8], original_len: usize) -> i32 {
    match lz4_flex::block::decompress_into(src, dst) {
        Ok(n) if n == original_len => n as i32,
        _ => -1,
    }
}

/// Worst-case bound (C cbm_lz4_bound → LZ4_compressBound): 0 for inputs
/// over LZ4_MAX_INPUT_SIZE.
pub fn cbm_lz4_bound(input_size: usize) -> i32 {
    lz4_compress_bound(input_size) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_matches_lz4_spec() {
        // LZ4_compressBound(n) = n + n/255 + 16.
        assert_eq!(cbm_lz4_bound(0), 16);
        assert_eq!(cbm_lz4_bound(65536), 65809);
        assert!(cbm_lz4_bound(1_000_000) > 1_000_000);
        assert_eq!(cbm_lz4_bound(LZ4_MAX_INPUT_SIZE + 1), 0);
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let src = b"hello compressible world ".repeat(200);
        let mut dst = vec![0u8; cbm_lz4_bound(src.len()) as usize];
        let n = cbm_lz4_compress_hc(&src, &mut dst);
        assert!(n > 0, "compress rc={n}");
        assert!((n as usize) < src.len(), "repetitive input must shrink");

        let mut out = vec![0u8; src.len()];
        let m = cbm_lz4_decompress(&dst[..n as usize], &mut out, src.len());
        assert_eq!(m as usize, src.len());
        assert_eq!(out, src);
    }

    #[test]
    fn decompress_rejects_corruption() {
        let src = b"payload payload payload";
        let mut dst = vec![0u8; cbm_lz4_bound(src.len()) as usize];
        let n = cbm_lz4_compress_hc(src, &mut dst);
        assert!(n > 0);
        // Wrong original length → rejected.
        let mut out = vec![0u8; src.len()];
        assert_eq!(
            cbm_lz4_decompress(&dst[..n as usize], &mut out, src.len() + 1),
            -1
        );
        // Garbage input → rejected.
        assert_eq!(cbm_lz4_decompress(&[0xFF; 64], &mut out, src.len()), -1);
    }
}
