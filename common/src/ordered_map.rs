//! The ordered map type provides a map-like interface that maintains the order
//! in which elements were added to the structure
//!
//! This is useful when indexing wallet information, the order of which changes
//! the commitment. We need to maintain the order of e.g. balances to ensure
//! that the locally stored wallet commits to the one on-chain

use serde::{Deserialize, Serialize};

/// The ordered map type, a map-like interface that maintains insertion order
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct OrderedMap<K: Eq, V: Clone> {
    /// The underlying store of keys and values
    ///
    /// Currently we only use the `OrderedMap` for very small maps; for which a
    /// vector is simpler and faster than a hash based structure
    elems: Vec<(K, V)>,
}

impl<K: Eq, V: Clone> OrderedMap<K, V> {
    /// Constructor
    pub fn new() -> Self {
        Self { elems: Vec::new() }
    }

    // -----------
    // | Getters |
    // -----------

    /// Returns whether the number of elements is zero
    pub fn is_empty(&self) -> bool {
        self.elems.len() == 0
    }

    /// Returns the length of the map
    pub fn len(&self) -> usize {
        self.elems.len()
    }

    /// Checks if the map contains the given key
    pub fn contains_key(&self, key: &K) -> bool {
        self.elems.iter().any(|(k, _)| k == key)
    }

    /// Returns a reference to the value corresponding to the key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.elems.iter().find_map(|(k, v)| if k == key { Some(v) } else { None })
    }

    /// Returns a mutable reference to the corresponding key and value
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.elems.iter_mut().find_map(|(k, v)| if k == key { Some(v) } else { None })
    }

    /// Returns the index of the value if it exists
    pub fn index_of(&self, key: &K) -> Option<usize> {
        self.elems.iter().position(|(k, _)| k == key)
    }

    /// Returns an iterator over the map. The iterator yields elements in the
    /// order they were inserted into the map.
    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.elems.iter()
    }

    /// Returns an iterator over the map that allows modifying each value.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (K, V)> {
        self.elems.iter_mut()
    }

    // -----------
    // | Setters |
    // -----------

    /// Inserts a key-value pair into the map
    ///
    /// If the map did not have this key present, `None` is returned.
    ///
    /// If the map did have this key present, the value is updated, and the old
    /// value is returned.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.index_of(&key) {
            Some(idx) => {
                let old_value = self.elems[idx].1.clone();
                self.elems[idx].1 = value;

                Some(old_value)
            },
            None => {
                self.elems.push((key, value));
                None
            },
        }
    }

    /// Removes a key from the map, returning the value at the key if the key
    /// was previously in the map.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let index = self.elems.iter().position(|(k, _)| k == key)?;
        Some(self.elems.remove(index).1)
    }

    /// Clears the map, removing all key-value pairs.
    pub fn clear(&mut self) {
        self.elems.clear()
    }
}

#[cfg(test)]
mod test {
    use super::OrderedMap;

    /// Tests basic setting and getting patterns
    #[test]
    fn test_basic_set_get_remove() {
        let mut map = OrderedMap::default();
        assert!(map.is_empty());

        let (key, value) = ("key".to_string(), "value".to_string());
        assert!(!map.contains_key(&key));
        assert!(map.get(&key).is_none());

        // Insert the key
        map.insert(key.clone(), value.clone());
        assert!(map.contains_key(&key));
        assert_eq!(map.get(&key), Some(&value));

        // Remove the key
        assert_eq!(map.remove(&key), Some(value));
        assert!(map.get(&key).is_none());
    }

    /// Tests getting a mutable reference to a key
    #[test]
    fn test_get_mut() {
        let mut map = OrderedMap::default();
        let (key, value) = ("key".to_string(), "value".to_string());
        let new_value = "new_value".to_string();

        // Insert the key
        map.insert(key.clone(), value.clone());
        assert_eq!(map.get(&key), Some(&value));

        // Change the value
        if let Some(v) = map.get_mut(&key) {
            *v = new_value.clone();
        }

        assert_eq!(map.get(&key), Some(&new_value));
    }

    /// Tests the `index_of` method
    #[test]
    fn test_index_of() {
        let mut map = OrderedMap::default();
        let (key, value) = (0, 0);

        // Insert the key
        map.insert(key, value);
        assert_eq!(map.index_of(&key), Some(0));

        // Insert a few keys in order
        const N: usize = 10;
        for i in 1..=N {
            map.insert(i, i);
        }

        // Check the index of each key
        for i in 0..=N {
            assert_eq!(map.index_of(&i), Some(i));
        }
        assert_eq!(map.len(), N + 1);
    }

    /// Tests the `remove` method
    #[test]
    fn test_remove_key() {
        let mut map = OrderedMap::default();
        let (key, value) = ("key".to_string(), "value".to_string());

        // Insert the key
        map.insert(key.clone(), value.clone());
        assert_eq!(map.get(&key), Some(&value));
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&key));

        // Remove the key
        map.remove(&key);
        assert_eq!(map.get(&key), None);
        assert_eq!(map.len(), 0);
        assert!(!map.contains_key(&key));

        // Try to remove a non-existent key
        let non_existent_key = "non_existent".to_string();
        map.remove(&non_existent_key);
        assert_eq!(map.get(&non_existent_key), None);
        assert_eq!(map.len(), 0);
        assert!(!map.contains_key(&non_existent_key));
    }

    /// Test that serialization and deserialization preserves the order of the
    /// keys
    #[test]
    fn test_serde_order() {
        const N: usize = 10;
        let mut map = OrderedMap::default();

        // Insert the keys
        for i in 0..N {
            map.insert(i, i);
        }

        // Serialize and deserialize the map
        let serialized = serde_json::to_string(&map).unwrap();
        let deserialized: OrderedMap<usize, usize> = serde_json::from_str(&serialized).unwrap();
        for (i, (k, v)) in deserialized.iter().enumerate() {
            assert_eq!(i, *k);
            assert_eq!(i, *v);
            assert_eq!(i, deserialized.index_of(k).unwrap());
        }
    }
}
