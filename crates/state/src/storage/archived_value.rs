//! A wrapper type for zero-copy access to archived values from the database

use std::borrow::Cow;
use std::marker::PhantomData;
use std::ops::Deref;

use crate::storage::traits::{RkyvValue, RkyvWith};

use super::error::StorageError;
use super::traits::Value;

/// A type alias for a Cow buffer of bytes
pub type CowBuffer<'a> = Cow<'a, [u8]>;

/// A wrapper holding archived data from the database
///
/// Provides zero-copy access to archived values via Deref
///
/// We wrap bytes returned from the database to ensure that the bytes are valid
/// for the advertised lifetime. In the case of a write transaction, mdbx will
/// return owned bytes for those references allocated on dirty pages. If we
/// don't return the backing copy-on-write buffer, the bytes will be dropped at
/// the transaction layer and be invalid.
pub struct ArchivedValue<'a, V: Value> {
    /// The backing bytes of the archived value
    backing: CowBuffer<'a>,
    /// Phantom
    _phantom: PhantomData<V>,
}

impl<'a, V: Value> ArchivedValue<'a, V> {
    /// Create a new ArchivedValue from backing bytes
    pub fn new(backing: CowBuffer<'a>) -> Self {
        Self { backing, _phantom: PhantomData }
    }

    /// Deserialize to an owned value
    pub fn deserialize(&self) -> Result<V, StorageError> {
        V::rkyv_deserialize_from_bytes(&self.backing)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.backing
    }
}

impl<T, W> ArchivedValue<'_, RkyvWith<T, W>>
where
    RkyvWith<T, W>: Value,
{
    /// Get the inner value
    pub fn deserialize_with(&self) -> Result<T, StorageError> {
        <RkyvWith<T, W> as RkyvValue>::rkyv_deserialize_from_bytes(&self.backing)
            .map(|v| v.into_inner())
    }
}

impl<V: Value> Deref for ArchivedValue<'_, V> {
    type Target = V::ArchivedType;

    #[allow(unsafe_code)]
    fn deref(&self) -> &Self::Target {
        unsafe { V::rkyv_access(&self.backing) }
    }
}
