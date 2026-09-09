//! zstd_store.rs — 1:1 rewrite of `internal/cbm/zstd_store.c`: thin
//! wrappers around Zstandard, used by artifact packaging (src/pipeline/
//! artifact.c compresses dumped DBs). The C vendors zstd; the Rust uses
//! the `zstd` crate.
//!
//! C convention: negative/int64 returns are 0 on error (callers treat 0
//! as failure).

/// Compress into the caller's buffer (C cbm_zstd_compress). Returns the
/// compressed length, or 0 on error.
pub fn cbm_zstd_compress(src: &[u8], dst: &mut [u8], level: i32) -> i64 {
    match zstd::bulk::compress_to_buffer(src, dst, level) {
        Ok(n) => n as i64,
        Err(_) => 0,
    }
}

/// Decompress into the caller's buffer (C cbm_zstd_decompress). Returns
/// the decompressed length, or 0 on error.
pub fn cbm_zstd_decompress(src: &[u8], dst: &mut [u8]) -> i64 {
    match zstd::bulk::decompress_to_buffer(src, dst) {
        Ok(n) => n as i64,
        Err(_) => 0,
    }
}

/// Frame content size (C cbm_zstd_frame_content_size): 0 when unknown or
/// on a malformed frame. zstd_safe returns Option<Option<u64>>: outer None
/// = ZSTD_CONTENTSIZE_ERROR, inner None = ZSTD_CONTENTSIZE_UNKNOWN.
pub fn cbm_zstd_frame_content_size(src: &[u8]) -> usize {
    zstd_safe::get_frame_content_size(src)
        .unwrap_or(None)
        .unwrap_or(0) as usize
}

/// Worst-case compressed bound (C cbm_zstd_compress_bound).
pub fn cbm_zstd_compress_bound(input_size: usize) -> usize {
    zstd_safe::compress_bound(input_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_frame_size() {
        let src = vec![7u8; 100_000];
        let bound = cbm_zstd_compress_bound(src.len());
        let mut dst = vec![0u8; bound];
        let n = cbm_zstd_compress(&src, &mut dst, 3);
        assert!(n > 0, "compress rc={n}");
        assert!((n as usize) < src.len(), "repetitive input must shrink");

        let frame = cbm_zstd_frame_content_size(&dst[..n as usize]);
        assert_eq!(frame, src.len());

        let mut out = vec![0u8; frame];
        let m = cbm_zstd_decompress(&dst[..n as usize], &mut out);
        assert_eq!(m as usize, src.len());
        assert_eq!(out, src);
    }

    #[test]
    fn error_paths_return_zero() {
        // Garbage input: frame size 0, decompress 0.
        assert_eq!(cbm_zstd_frame_content_size(&[0xFF; 32]), 0);
        let mut out = vec![0u8; 1024];
        assert_eq!(cbm_zstd_decompress(&[0xFF; 32], &mut out), 0);
    }

    #[test]
    fn dst_too_small_fails() {
        let src = vec![9u8; 10_000];
        let mut tiny = vec![0u8; 16];
        assert_eq!(cbm_zstd_compress(&src, &mut tiny, 3), 0);
    }
}
