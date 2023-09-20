//! Defines traits for storage access

use serde::{Deserialize, Serialize};

/// An abstraction over keys in the database, which are concretely stored as
/// byte slices. Keys must be serializable and deserializable from bytes
pub trait Key: Serialize + for<'de> Deserialize<'de> + Clone {}

impl<T: Serialize + for<'de> Deserialize<'de> + Clone> Key for T {}

/// An abstraction over values in the database, which are concretely stored as
/// byte slices. Values must be serializable and deserializable from bytes
pub trait Value: Serialize + for<'de> Deserialize<'de> + Clone {}

impl<T: Serialize + for<'de> Deserialize<'de> + Clone> Value for T {}
