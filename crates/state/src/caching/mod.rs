//! Caching mechanisms for the relayer state

use std::collections::{HashMap, HashSet};

use tokio::sync::RwLock;

pub mod matchable_amount;
pub mod order_cache;
pub mod order_metadata_index;

/// A type alias for a rwlock-ed hashset
pub(crate) type RwLockHashSet<T> = RwLock<HashSet<T>>;
/// A type alias for a rwlock-ed hashmap
pub(crate) type RwLockHashMap<K, V> = RwLock<HashMap<K, V>>;
