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
pub mod dump_verify;
pub mod dyn_array;
pub mod hash_table;
pub mod limits;
pub mod lock_registry;
pub mod log;
pub mod macos_acl;
pub mod mem;
pub mod mem_override_win;
pub mod mem_profile;
pub mod platform;
pub mod private_file_lock;
pub mod profile;
pub mod secure_random;
pub mod sha256;
pub mod slab_alloc;
pub mod str_intern;
pub mod str_util;
pub mod system_info;
pub mod vmem;
pub mod yaml;
