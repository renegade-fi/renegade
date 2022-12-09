//! Implements a cache of pairs of order identifiers that have already been matched against
//! one another. We use this cache to avoid duplicating work; i.e. once a pair of orders have
//! gone through the matching engine, they should not be matched again.
//!
//! The cache abstracts mostly over ordering semantics. We cache in pairs of orders and the
//! caller should not have to implement messy logic to order the pairs correctly.

// TODO: Remove this lint allowance
#![allow(dead_code)]

use std::{
    cmp::{max, min},
    hash::Hash,
    num::NonZeroUsize,
};

use lru::LruCache;

use crate::state::Shared;

/// A type alias for a HandshakeCache shared between threads
pub(super) type SharedHandshakeCache<O> = Shared<HandshakeCache<O>>;

/// Caches pairs of orders that have already been matched so that we may avoid attempting to
/// match orders multiple times
///
/// `O` is an abstract order identifier that can be hashed into a cache key
pub struct HandshakeCache<O> {
    /// The current number of elements in the cache
    size: usize,
    /// The maximum number of elements in the cache
    max_size: usize,
    /// The underlying LRU cache controlling evication from the HandshakeCache
    ///
    /// Entries are cached with the lower (abstract ordering) identifier stored first
    lru_cache: LruCache<(O, O), ()>,
}

impl<O: Clone + Eq + Hash + Ord> HandshakeCache<O> {
    /// Create a new handshake cache with given capacity
    pub fn new(max_size: usize) -> Self {
        Self {
            size: 0,
            max_size,
            lru_cache: LruCache::new(NonZeroUsize::new(max_size).unwrap()),
        }
    }

    /// Returns the number of elements currently cached
    pub fn len(&self) -> usize {
        self.lru_cache.len()
    }

    /// Computes the cache tuple from a given pair of identifiers
    ///
    /// The ordering of identifiers in the cache tuple is defined abstractly by
    /// the implementation of `Ord` on the identifier type. We place the "lesser"
    /// identifier first in the tuple
    fn cache_tuple(o1: O, o2: O) -> (O, O) {
        let first_entry = min(o1.clone(), o2.clone());
        let second_entry = max(o1, o2);
        (first_entry, second_entry)
    }

    /// Caches an entry
    pub fn push(&mut self, o1: O, o2: O) {
        self.lru_cache.push(Self::cache_tuple(o1, o2), ());
    }

    /// Checks whether a given pair is cached
    pub fn contains(&self, o1: O, o2: O) -> bool {
        self.lru_cache.contains(&Self::cache_tuple(o1, o2))
    }
}

#[cfg(test)]
mod handshake_cache_tests {
    use super::HandshakeCache;

    /// Tests that LRU is enforced on the cache
    #[test]
    fn test_lru_policy() {
        let mut cache = HandshakeCache::new(2 /* max_size */);
        cache.push(1, 1);
        cache.push(2, 2);
        cache.push(3, 3);

        assert!(!cache.contains(1, 1));
        assert!(cache.contains(2, 2));
        assert!(cache.contains(3, 3));
    }

    /// Tests that cache pushes and queries can occur in either key order
    #[test]
    fn test_cache_ordering() {
        let mut cache = HandshakeCache::new(1 /* max_size */);
        // Try the smaller value first
        cache.push(4, 5);
        assert!(cache.contains(4, 5));
        assert!(cache.contains(5, 4));

        // Try the larger value first
        cache.push(7, 6);
        assert!(!cache.contains(4, 5));
        assert!(cache.contains(6, 7));
        assert!(cache.contains(7, 6));
    }
}
