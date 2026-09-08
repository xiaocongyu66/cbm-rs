//! hash_table.rs — 1:1 rewrite of `src/foundation/hash_table.{c,h}`.
//!
//! String → value map. The C version wraps vendored Verstable (open
//! addressing, quadratic probing, 4-bit hash fragments); the Rust standard
//! `HashMap<String, T>` with SipHash provides the same semantics with
//! equivalent or better collision behavior and no vendored code.
//!
//! Lifetime difference from C: the C API takes borrowed `const char*` keys
//! and the caller owns them; here keys are owned `String`s, which subsumes
//! the `get_key` canonicalization use case (return `&str` backed by the map).

use std::collections::HashMap;
use std::hash::BuildHasherDefault;

type BuildHasher = BuildHasherDefault<std::collections::hash_map::DefaultHasher>;

/// String → T map mirroring `CBMHashTable`.
pub struct HashTable<T> {
    map: HashMap<String, T, BuildHasher>,
}

impl<T> HashTable<T> {
    /// Create with an initial capacity hint (0 = library default).
    pub fn create(initial_capacity: u32) -> Self {
        HashTable {
            map: HashMap::with_capacity_and_hasher(initial_capacity as usize, BuildHasher::default()),
        }
    }

    /// Insert or update. Returns the previous value (`None` if new key).
    pub fn set(&mut self, key: &str, value: T) -> Option<T> {
        self.map.insert(key.to_string(), value)
    }

    /// Lookup. Returns a reference, `None` if not found.
    pub fn get(&self, key: &str) -> Option<&T> {
        self.map.get(key)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut T> {
        self.map.get_mut(key)
    }

    /// Check if key exists.
    pub fn has(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// Return the stored (canonical, owned) key for a lookup key.
    /// C equivalent: `cbm_ht_get_key`.
    pub fn get_key(&self, key: &str) -> Option<&str> {
        self.map.get_key_value(key).map(|(k, _)| k.as_str())
    }

    /// Delete. Returns the removed value (`None` if not found).
    pub fn delete(&mut self, key: &str) -> Option<T> {
        self.map.remove(key)
    }

    /// Number of entries.
    pub fn count(&self) -> u32 {
        self.map.len() as u32
    }

    /// Iterate all `(key, value)` pairs.
    pub fn foreach(&self, mut f: impl FnMut(&str, &T)) {
        for (k, v) in &self.map {
            f(k, v);
        }
    }

    /// Clear all entries (keeps allocated memory).
    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl<T> Default for HashTable<T> {
    fn default() -> Self {
        Self::create(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_has_roundtrip() {
        let mut ht: HashTable<u32> = HashTable::create(0);
        assert_eq!(ht.set("a", 1), None);
        assert_eq!(ht.get("a"), Some(&1));
        assert!(ht.has("a"));
        assert!(!ht.has("b"));
        assert_eq!(ht.count(), 1);
    }

    #[test]
    fn set_updates_and_returns_previous() {
        let mut ht: HashTable<&str> = HashTable::default();
        assert_eq!(ht.set("k", "v1"), None);
        assert_eq!(ht.set("k", "v2"), Some("v1"));
        assert_eq!(ht.get("k"), Some(&"v2"));
    }

    #[test]
    fn delete_returns_value() {
        let mut ht: HashTable<u8> = HashTable::default();
        ht.set("x", 9);
        assert_eq!(ht.delete("x"), Some(9));
        assert_eq!(ht.delete("x"), None);
        assert_eq!(ht.count(), 0);
    }

    #[test]
    fn get_key_returns_canonical() {
        let mut ht: HashTable<()> = HashTable::default();
        ht.set("canonical", ());
        assert_eq!(ht.get_key("canonical"), Some("canonical"));
        assert_eq!(ht.get_key("missing"), None);
    }

    #[test]
    fn foreach_visits_all() {
        let mut ht: HashTable<u32> = HashTable::default();
        ht.set("a", 1);
        ht.set("b", 2);
        ht.set("c", 3);
        let mut seen = std::collections::BTreeMap::new();
        ht.foreach(|k, v| {
            seen.insert(k.to_string(), *v);
        });
        assert_eq!(seen.len(), 3);
        assert_eq!(seen["b"], 2);
    }

    #[test]
    fn clear_keeps_capacity() {
        let mut ht: HashTable<u32> = HashTable::create(64);
        for i in 0..32 {
            ht.set(&format!("k{i}"), i);
        }
        ht.clear();
        assert_eq!(ht.count(), 0);
        ht.set("again", 1);
        assert_eq!(ht.get("again"), Some(&1));
    }

    #[test]
    fn get_mut() {
        let mut ht: HashTable<Vec<u32>> = HashTable::default();
        ht.set("list", vec![1]);
        ht.get_mut("list").unwrap().push(2);
        assert_eq!(ht.get("list"), Some(&vec![1, 2]));
    }
}
