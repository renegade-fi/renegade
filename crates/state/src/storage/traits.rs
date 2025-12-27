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
        + Debug
        + for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + Deserialize<Self, Strategy<Pool, rancor::Error>>;

    /// Deserialize the value from an archived type
    fn rkyv_deserialize(archived: &Self::ArchivedType) -> Result<Self, StorageError> {
        rkyv::deserialize::<_, rancor::Error>(archived).map_err(StorageError::serialization)
    }

    /// Deserialize the value from bytes
    fn rkyv_deserialize_from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        rkyv::from_bytes::<_, rancor::Error>(bytes).map_err(StorageError::serialization)
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
    ///
    /// # Safety
    ///
    /// The caller must ensure that the bytes are a valid serialized value of
    /// the type. The bytes must have been produced by rkyv serialization
    /// and must be valid for the lifetime of the returned reference.
    #[allow(unsafe_code)]
    unsafe fn rkyv_access(value_bytes: &[u8]) -> &Self::Archived {
        unsafe { rkyv::access_unchecked::<Self::Archived>(value_bytes) }
    }

    /// Access the value and validate the bytes
    fn rkyv_access_validated(value_bytes: &[u8]) -> Result<&Self::Archived, StorageError> {
        rkyv::access::<Self::Archived, rancor::Error>(value_bytes)
            .map_err(StorageError::serialization)
    }
}
impl<T: Archive + RkyvSerializable> RkyvValue for T
where
    T::Archived: Portable
        + Debug
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
