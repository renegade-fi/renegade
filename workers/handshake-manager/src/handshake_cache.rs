//! Implements a cache of pairs of order identifiers that have already been
//! matched against one another. We use this cache to avoid duplicating work;
//! i.e. once a pair of orders have gone through the matching engine, they
//! should not be matched again.
//!
//! The cache abstracts mostly over ordering semantics. We cache in pairs of
//! orders and the caller should not have to implement messy logic to order the
//! pairs correctly.

// TODO: Remove this lint allowance
#![allow(dead_code)]

use std::{
    cmp::{max, min},
    hash::Hash,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use common::AsyncShared;
use lru::LruCache;

/// A type alias for a HandshakeCache shared between threads
pub(super) type SharedHandshakeCache<O> = AsyncShared<HandshakeCache<O>>;

/// Caches pairs of orders that have already been matched so that we may avoid
/// attempting to match orders multiple times
///
/// `O` is an abstract order identifier that can be hashed into a cache key
pub struct HandshakeCache<O> {
    /// The current number of elements in the cache
    size: usize,
    /// The maximum number of elements in the cache
    max_size: usize,
    /// The underlying LRU cache controlling eviction from the HandshakeCache
    ///
    /// Entries are cached with the lower (abstract ordering) identifier stored
    /// first
    lru_cache: LruCache<(O, O), HandshakeCacheState>,
}

/// Represents the state of an entry in the handshake cache for various types of
/// caching
#[derive(Clone, Copy, Debug)]
pub enum HandshakeCacheState {
    /// A completed match, either by the local peer or a cluster replica;
    /// this order pair should not be scheduled again
    Completed,
    /// A match that a remote peer has initiated; the local peer places this
    /// order pair in an invisibility window to avoid duplicating the remote
    /// peer's work.
    ///
    /// There are two transitions out of this state:
    ///     1. The remote peer completes a match on the pair; in which case it
    ///        will broadcast a message to complete the pair, moving it to the
    ///        completed state
    ///     2. The remote peer fails to complete a match; the invisibility
    ///        window elapses, and this entry is removed from the cache
    Invisible {
        /// The `Instant` at which the invisibility window expires
        until: Instant,
    },
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
    /// the implementation of `Ord` on the identifier type. We place the
    /// "lesser" identifier first in the tuple
    fn cache_tuple(o1: O, o2: O) -> (O, O) {
        let first_entry = min(o1.clone(), o2.clone());
        let second_entry = max(o1, o2);
        (first_entry, second_entry)
    }

    /// Caches an entry
    pub fn mark_completed(&mut self, o1: O, o2: O) {
        self.lru_cache
            .push(Self::cache_tuple(o1, o2), HandshakeCacheState::Completed);
    }

    /// Mark the given pair as invisible for a duration
    ///
    /// Window represents the amount of time this order pair is invisible for
    pub fn mark_invisible(&mut self, o1: O, o2: O, window: Duration) {
        self.lru_cache.push(
            Self::cache_tuple(o1, o2),
            HandshakeCacheState::Invisible {
                until: Instant::now() + window,
            },
        );
    }

    /// Checks whether a given pair is cached
    pub fn contains(&self, o1: O, o2: O) -> bool {
        // If the cache contains the entry in the `Invisible` state and the invisibility
        // window has expired, return false
        if let Some(entry) = self.lru_cache.peek(&Self::cache_tuple(o1, o2)) {
            match entry {
                HandshakeCacheState::Completed => true,
                HandshakeCacheState::Invisible { until } => {
                    // checked_duration_since will return none if the arg is later than
                    // `Instant::now()`. If `is_none() == true` then the invisibility
                    // window has not elapsed and the entry is considered cached
                    Instant::now().checked_duration_since(*until).is_none()
                },
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
mod handshake_cache_tests {
    use super::HandshakeCache;

    /// Tests that LRU is enforced on the cache
    #[test]
    fn test_lru_policy() {
        let mut cache = HandshakeCache::new(2 /* max_size */);
        cache.mark_completed(1, 1);
        cache.mark_completed(2, 2);
        cache.mark_completed(3, 3);

        assert!(!cache.contains(1, 1));
        assert!(cache.contains(2, 2));
        assert!(cache.contains(3, 3));
    }

    /// Tests that cache pushes and queries can occur in either key order
    #[test]
    fn test_cache_ordering() {
        let mut cache = HandshakeCache::new(1 /* max_size */);
        // Try the smaller value first
        cache.mark_completed(4, 5);
        assert!(cache.contains(4, 5));
        assert!(cache.contains(5, 4));

        // Try the larger value first
        cache.mark_completed(7, 6);
        assert!(!cache.contains(4, 5));
        assert!(cache.contains(6, 7));
        assert!(cache.contains(7, 6));
    }
}
