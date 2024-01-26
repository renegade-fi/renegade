//! The keyed list type provides a map-like interface that maintains the order
//! in which elements were added to the structure
//!
//! This is useful when indexing wallet information, the order of which changes
//! the commitment. We need to maintain the order of e.g. balances to ensure
//! that the locally stored wallet commits to the one on-chain

use serde::{Deserialize, Serialize};

/// The ordered map type, a map-like interface that maintains insertion order
///
/// Duplicate keys are explicitly _allowed_, though some setter methods allow
/// the caller to enforce a unique key. Some `get` methods short circuit, i.e.
/// they will return the first of such duplicate keys
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct KeyedList<K: Eq, V: Clone> {
    /// The underlying store of keys and values
    ///
    /// Currently we only use the `KeyedList` for very small maps; for which a
    /// vector is simpler and faster than a hash based structure
    elems: Vec<(K, V)>,
}

impl<K: Eq, V: Clone> KeyedList<K, V> {
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

    /// Get the first key-value pair
    pub fn first(&self) -> Option<&(K, V)> {
        self.elems.first()
    }

    /// Returns a reference to the value corresponding to the key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.elems.iter().find_map(|(k, v)| (k == key).then_some(v))
    }

    /// Returns a mutable reference to the corresponding key and value
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.elems.iter_mut().find_map(|(k, v)| (k == key).then_some(v))
    }

    /// Returns the index of the value if it exists
    pub fn index_of(&self, key: &K) -> Option<usize> {
        self.elems.iter().position(|(k, _)| k == key)
    }

    /// Get a borrowed reference to the value at the given index
    pub fn get_index(&self, index: usize) -> Option<&V> {
        self.elems.get(index).map(|(_, v)| v)
    }

    /// Get a borrowed reference to the kv pair at the given index
    pub fn get_index_full(&self, index: usize) -> Option<&(K, V)> {
        self.elems.get(index)
    }

    /// Get a mutable reference to the value at the given index
    pub fn get_index_mut(&mut self, index: usize) -> Option<&mut V> {
        self.elems.get_mut(index).map(|(_, v)| v)
    }

    /// Get a mutable reference to the key and value at the given index
    pub fn get_index_full_mut(&mut self, index: usize) -> Option<&mut (K, V)> {
        self.elems.get_mut(index)
    }

    /// Returns an iterator over the keys and values. The iterator yields
    /// elements in the order they were inserted into the map.
    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.elems.iter()
    }

    /// Returns an iterator over the map that allows modifying each value.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (K, V)> {
        self.elems.iter_mut()
    }

    /// Returns an iterator over borrowed keys
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.elems.iter().map(|(k, _)| k)
    }

    /// Returns an iterator over the keys of a map that takes ownership of the
    /// keys
    pub fn into_keys(self) -> impl Iterator<Item = K> {
        self.elems.into_iter().map(|(k, _)| k)
    }

    /// Returns an iterator over borrowed values
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.elems.iter().map(|(_, v)| v)
    }

    /// Returns an iterator over the values of the map that takes ownership of
    /// the values
    pub fn into_values(self) -> impl Iterator<Item = V> {
        self.elems.into_iter().map(|(_, v)| v)
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

    /// Append a value to the elements, do not check if the key is already
    /// present
    pub fn append(&mut self, key: K, value: V) {
        self.elems.push((key, value));
    }

    /// Insert a key-value pair at a specific index
    pub fn insert_at_index(&mut self, index: usize, key: K, value: V) {
        self.elems.insert(index, (key, value));
    }

    /// Replace the key-value pair at the given index
    pub fn replace_at_index(&mut self, index: usize, key: K, value: V) {
        self.elems[index] = (key, value);
    }

    /// Removes a key from the map, returning the value at the key if the key
    /// was previously in the map.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let index = self.elems.iter().position(|(k, _)| k == key)?;
        Some(self.elems.remove(index).1)
    }

    /// Retain only those elements that satisfy the predicate
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &V) -> bool,
    {
        self.elems.retain(|(k, v)| f(k, v));
    }

    /// Clears the map, removing all key-value pairs.
    pub fn clear(&mut self) {
        self.elems.clear()
    }
}

/// This `FromIterator` method allows duplicates
impl<K: Eq, V: Clone> FromIterator<(K, V)> for KeyedList<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let elems = iter.into_iter().collect();
        KeyedList { elems }
    }
}

impl<K: Eq, V: Clone> IntoIterator for KeyedList<K, V> {
    type Item = (K, V);
    type IntoIter = std::vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.elems.into_iter()
    }
}

#[cfg(test)]
mod test {
    use super::KeyedList;

    /// Tests basic setting and getting patterns
    #[test]
    fn test_basic_set_get_remove() {
        let mut map = KeyedList::default();
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

    /// Tests inserting a duplicate key, overwriting the original
    #[test]
    fn test_insert_overwrite() {
        let mut map = KeyedList::default();
        let (key, value) = ("key".to_string(), "value".to_string());
        let value2 = "value2".to_string();

        // Insert the key
        map.insert(key.clone(), value.clone());
        assert_eq!(map.get(&key), Some(&value));

        // Insert the key again
        map.insert(key.clone(), value2.clone());
        assert_eq!(map.get(&key), Some(&value2));
    }

    /// Tests inserting a duplicate key without overwriting the original
    #[test]
    fn test_insert_no_overwrite() {
        let mut map = KeyedList::default();
        let (key, value) = ("key".to_string(), "value".to_string());
        let value2 = "value2".to_string();

        // Insert the key, and append the second key
        map.insert(key.clone(), value.clone());
        map.append(key.clone(), value2.clone());

        assert_eq!(map.get(&key), Some(&value));
        assert_eq!(map.get_index(1), Some(&value2));
    }

    /// Tests getting a mutable reference to a key
    #[test]
    fn test_get_mut() {
        let mut map = KeyedList::default();
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
        let mut map = KeyedList::default();
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
        let mut map = KeyedList::default();
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
        let mut map = KeyedList::default();

        // Insert the keys
        for i in 0..N {
            map.insert(i, i);
        }

        // Serialize and deserialize the map
        let serialized = serde_json::to_string(&map).unwrap();
        let deserialized: KeyedList<usize, usize> = serde_json::from_str(&serialized).unwrap();
        for (i, (k, v)) in deserialized.iter().enumerate() {
            assert_eq!(i, *k);
            assert_eq!(i, *v);
            assert_eq!(i, deserialized.index_of(k).unwrap());
        }
    }
}
