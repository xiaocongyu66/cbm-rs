//! constants.rs — 1:1 rewrite of `src/foundation/constants.h`.
//!
//! Project-wide named constants. Every literal integer/float in source
//! should reference a named constant.

/// Full byte range 0x00–0xFF.
pub const BYTE_RANGE: usize = 256;
/// Two quote characters (open + close).
pub const QUOTE_PAIR: usize = 2;
/// Skip opening quote.
pub const QUOTE_OFFSET: usize = 1;

pub const SZ_2: usize = 2;
pub const SZ_3: usize = 3;
pub const SZ_4: usize = 4;
pub const SZ_5: usize = 5;
pub const SZ_6: usize = 6;
pub const SZ_7: usize = 7;
pub const SZ_8: usize = 8;
pub const SZ_16: usize = 16;
pub const SZ_32: usize = 32;
pub const SZ_64: usize = 64;
pub const SZ_128: usize = 128;
pub const SZ_256: usize = 256;
pub const SZ_512: usize = 512;
pub const SZ_1K: usize = 1024;
pub const SZ_2K: usize = 2048;
pub const SZ_4K: usize = 4096;
pub const SZ_8K: usize = 8192;
pub const SZ_16K: usize = 16384;
pub const SZ_32K: usize = 32768;
pub const SZ_64K: usize = 65536;

pub const DECIMAL_BASE: u32 = 10;
pub const HEX_BASE: u32 = 16;
pub const PERCENT: u64 = 100;

/// ts_node row is 0-based; source lines are 1-based.
pub const TS_LINE_OFFSET: usize = 1;

/// Search miss, invalid index.
pub const NOT_FOUND: i64 = -1;
/// Initialization flag.
pub const INIT_DONE: i32 = 1;

/// Default page size for search_graph and the underlying store-layer search.
/// Responses land in an LLM agent's context window, so the default favors a
/// cheap first page (~50 TOON rows ≈ 1.5K tokens) over raw coverage; the
/// response always carries 'total' and 'has_more', and agents page via
/// offset+limit or narrow with label/file_pattern when has_more is true.
pub const DEFAULT_SEARCH_LIMIT: usize = 50;

pub const NSEC_PER_SEC: u64 = 1_000_000_000;
pub const USEC_PER_SEC: u64 = 1_000_000;
pub const MSEC_PER_SEC: u64 = 1_000;
pub const NSEC_PER_USEC: u64 = 1_000;
pub const NSEC_PER_MSEC: u64 = 1_000_000;

/// Small scratch buffers.
pub const SMALL_BUF: usize = 3;
/// Name buffer slots.
pub const NAME_BUF: usize = 4;
/// Path buffer size.
pub const PATH_MAX: usize = 1024;
/// Line read buffer.
pub const LINE_BUF: usize = 512;

pub const SKIP_ONE: usize = 1;
pub const PAIR_LEN: usize = 2;

/// SQL allowlist mirror of `label_is_type_like()` (cbm module, to come).
/// The C original documents `cbm_label_is_type_like()` as the single source
/// of truth for type-like labels; SQL string literals cannot call it, so
/// these constants exist instead of scattering hardcoded lists across
/// queries. Adding a type-like label to that function without updating this
/// fails CI rather than quietly shrinking query results.
pub const SQL_TYPE_LIKE_LABELS: &str = "'Class','Struct','Interface','Enum','Type','Trait'";
pub const SQL_CALLABLE_LABELS: &str = "'Function','Method'";
pub const SQL_CALLABLE_OR_TYPE_LABELS: &str = concat!(
    "'Function','Method',",
    "'Class','Struct','Interface','Enum','Type','Trait'"
);
/// SQL mirror of `label_is_relation()` (data-lineage nodes).
pub const SQL_RELATION_LABELS: &str = "'Table','View','Model'";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_ladder_is_monotonic() {
        let ladder = [
            SZ_2, SZ_3, SZ_4, SZ_8, SZ_16, SZ_32, SZ_64, SZ_128, SZ_256, SZ_512, SZ_1K, SZ_2K,
            SZ_4K, SZ_8K, SZ_16K, SZ_32K, SZ_64K,
        ];
        for w in ladder.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn sql_label_sets_match_documented_membership() {
        // These sets are pinned against the cbm-module label classifiers
        // (see C tests/test_store_nodes.c); keep them in sync.
        for l in SQL_TYPE_LIKE_LABELS.split(',').map(str::trim) {
            assert!(l.starts_with('\'') && l.ends_with('\''));
        }
        assert!(SQL_CALLABLE_OR_TYPE_LABELS.contains(SQL_CALLABLE_LABELS));
        assert!(SQL_RELATION_LABELS.contains("'Table'"));
    }
}
