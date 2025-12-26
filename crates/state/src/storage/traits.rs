//! Defines traits for storage access

use std::fmt::Debug;

use rkyv::{
    Archive, Deserialize, Portable, Serialize as RkyvSerialize,
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    de::Pool,
    rancor::{self, Strategy},
    ser::allocator::ArenaHandle,
    util::AlignedVec,
};

use crate::storage::error::StorageError;

/// A trait encapsulating the bounds on a key type
pub trait Key: RkyvValue + Debug + Clone {}
impl<T: RkyvValue + Debug + Clone> Key for T {}

/// A trait encapsulating the bounds on a value type
pub trait Value: RkyvValue {}
impl<T: RkyvValue> Value for T {}

// -----------------
// | Rkyv Wrappers |
// -----------------

/// A wrapper trait around rkyv compatible types
///
/// Pushing functionality into this trait allows us to operate generically at
/// the storage layer without excessive trait bounds.
pub trait RkyvValue: Archive<Archived = Self::ArchivedType> + RkyvSerializable + Sized {
    /// The archived type of the value
    type ArchivedType: Portable
        + for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + Deserialize<Self, Strategy<Pool, rancor::Error>>;

    /// Deserialize the value from an archived type
    fn rkyv_deserialize(bytes: &Self::ArchivedType) -> Self {
        rkyv::deserialize::<_, rancor::Error>(bytes).map_err(StorageError::serialization).unwrap()
    }

    /// Serialize the value to a byte vector
    fn rkyv_serialize(&self) -> Result<Vec<u8>, StorageError>
    where
        Self: Sized,
    {
        rkyv::to_bytes::<rancor::Error>(self)
            .map_err(StorageError::serialization)
            .map(|v| v.into_vec())
    }

    /// Access the value without deserializing it
    ///
    /// This method is zero-copy
    fn rkyv_access(value_bytes: &[u8]) -> Result<&Self::Archived, StorageError> {
        rkyv::access::<Self::Archived, rancor::Error>(value_bytes)
            .map_err(StorageError::serialization)
    }
}
impl<T: Archive + RkyvSerializable> RkyvValue for T
where
    T::Archived: Portable
        + for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + Deserialize<T, Strategy<Pool, rancor::Error>>,
{
    type ArchivedType = T::Archived;
}

/// A trait encapsulating the serialization behavior of a type
pub trait RkyvSerializable:
    for<'a> RkyvSerialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>
{
}
impl<T: for<'a> RkyvSerialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>>
    RkyvSerializable for T
{
}
