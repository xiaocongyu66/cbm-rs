//! cbm-foundation — 1:1 Rust rewrite of `src/foundation/*`.
//!
//! Each module replaces the C file of the same name; the C original is
//! deleted once the Rust version and its tests land.

pub mod arena;
pub mod compat;
pub mod compat_fs;
pub mod compat_regex;
pub mod compat_thread;
pub mod constants;
pub mod dyn_array;
pub mod hash_table;
pub mod limits;
pub mod log;
pub mod platform;
pub mod secure_random;
pub mod sha256;
pub mod str_util;
pub mod system_info;
