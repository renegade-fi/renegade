//! Defines traits for storage access

use std::{fmt::Debug, marker::PhantomData};

use rkyv::{
    Archive, Deserialize, Portable, Serialize,
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    de::Pool,
    rancor::{self, Strategy},
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    with::{ArchiveWith, DeserializeWith, SerializeWith, With},
};

use crate::storage::error::StorageError;

// ---------------------
// | Key Value Markers |
// ---------------------

/// A trait encapsulating the bounds on a key type
pub trait Key: RkyvValue + Debug + Clone {}
impl<T: RkyvValue + Debug + Clone> Key for T {}

/// A trait encapsulating the bounds on a value type
pub trait Value: RkyvValue {}
impl<T: RkyvValue> Value for T {}

// -----------------
// | Rkyv Wrappers |
// -----------------

/// A trait encapsulating the behavior of a (de)serializable value
///
/// We structure the trait in generic terms without requiring bounds on the
/// types or the trait itself. This is done to allow both native rkyv-capable
/// types and non-rkyv types wrapped in `With` (below) to be used
/// interchangeably.
pub trait RkyvValue: Sized {
    /// The archived type of the value
    ///
    /// This is the type that we may view in a zero-copy manner, without fully
    /// deserializing.
    type ArchivedType;

    /// Deserialize the value from its archived type
    fn from_archived(archived: &Self::ArchivedType) -> Result<Self, StorageError>;
    /// Deserialize the value from bytes
    fn rkyv_deserialize_from_bytes(bytes: &[u8]) -> Result<Self, StorageError>;
    /// Serialize the value to bytes
    fn rkyv_serialize(&self) -> Result<Vec<u8>, StorageError>;
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
    unsafe fn rkyv_access(value_bytes: &[u8]) -> &Self::ArchivedType;
    /// Access the value and validate the bytes
    fn rkyv_access_validated(value_bytes: &[u8]) -> Result<&Self::ArchivedType, StorageError>;
}

/// An implementation of the `RkyvValue` trait for rkyv-compatible types
impl<A, T> RkyvValue for T
where
    T: Archive<Archived = A>,
    T: RkyvSerializable2,
    A: ArchivedValue,
    A: RkyvDeserializable2<T>,
{
    type ArchivedType = A;

    #[inline]
    fn from_archived(archived: &Self::ArchivedType) -> Result<Self, StorageError> {
        rkyv::deserialize::<_, rancor::Error>(archived).map_err(StorageError::serialization)
    }

    #[inline]
    fn rkyv_deserialize_from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        rkyv::from_bytes::<_, rancor::Error>(bytes).map_err(StorageError::serialization)
    }

    #[inline]
    fn rkyv_serialize(&self) -> Result<Vec<u8>, StorageError> {
        rkyv::to_bytes::<rancor::Error>(self)
            .map_err(StorageError::serialization)
            .map(|v| v.into_vec())
    }

    #[inline]
    #[allow(unsafe_code)]
    unsafe fn rkyv_access(value_bytes: &[u8]) -> &Self::ArchivedType {
        unsafe { rkyv::access_unchecked::<Self::ArchivedType>(value_bytes) }
    }

    #[inline]
    fn rkyv_access_validated(value_bytes: &[u8]) -> Result<&Self::ArchivedType, StorageError> {
        rkyv::access::<Self::ArchivedType, rancor::Error>(value_bytes)
            .map_err(StorageError::serialization)
    }
}

/// A type that wraps a remote (non-rkyv) type and implements the `RkyvValue`
/// trait
///
/// This is a clone of the `rkyv::With` wrapper; but we localize the type to
/// this crate to prevent foreign implementation conflicts from the rkyv crate.
///
/// `T` is the wrapped type and `W` is the remote type shim that implements the
/// `rkyv::with` traits for `T`
pub struct RkyvWith<T: Sized, W> {
    /// The wrapped value
    inner: T,
    /// Phantom
    _phantom: PhantomData<W>,
}

impl<T: Sized, W> RkyvWith<T, W> {
    /// Create a new RkyvWith
    pub fn new(inner: T) -> Self {
        Self { inner, _phantom: PhantomData }
    }

    /// Get the wrapped value
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T, W, A> RkyvValue for RkyvWith<T, W>
where
    T: Sized,
    A: ArchivedValue,
    W: ArchiveWith<T, Archived = A>,
    W: RkyvSerializableWith<T>,
    W: RkyvDeserializableWith<A, T>,
{
    type ArchivedType = A;

    #[inline]
    fn from_archived(archived: &Self::ArchivedType) -> Result<Self, StorageError> {
        // Use the rkyv `With` type to broker this implementation
        let with: &With<A, W> = With::cast(archived);
        let inner: T =
            rkyv::deserialize::<_, rancor::Error>(with).map_err(StorageError::serialization)?;

        Ok(Self { inner, _phantom: PhantomData })
    }

    #[inline]
    #[allow(unsafe_code)]
    fn rkyv_deserialize_from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        let archived = unsafe { Self::rkyv_access(bytes) };
        Self::from_archived(archived)
    }

    #[inline]
    fn rkyv_serialize(&self) -> Result<Vec<u8>, StorageError> {
        let with = With::<T, W>::cast(&self.inner);
        rkyv::to_bytes::<rancor::Error>(with)
            .map_err(StorageError::serialization)
            .map(|v| v.into_vec())
    }

    #[inline]
    #[allow(unsafe_code)]
    unsafe fn rkyv_access(value_bytes: &[u8]) -> &Self::ArchivedType {
        unsafe { rkyv::access_unchecked::<A>(value_bytes) }
    }

    #[inline]
    fn rkyv_access_validated(value_bytes: &[u8]) -> Result<&Self::ArchivedType, StorageError> {
        rkyv::access::<A, rancor::Error>(value_bytes).map_err(StorageError::serialization)
    }
}

// --- Bound Traits --- //

/// Bound trait for the bounds on an archived value
trait ArchivedValue: Portable + for<'a> CheckBytes<HighValidator<'a, rancor::Error>> {}
impl<A> ArchivedValue for A where A: Portable + for<'a> CheckBytes<HighValidator<'a, rancor::Error>> {}

/// Bound trait for the bounds on a serializable type
trait RkyvSerializable2:
    for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>
{
}
impl<T: for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>>
    RkyvSerializable2 for T
{
}

/// Bound trait for a serializable with type
trait RkyvSerializableWith<T>:
    for<'a> SerializeWith<T, HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>
{
}
impl<T, S: for<'a> SerializeWith<T, HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>>
    RkyvSerializableWith<T> for S
{
}

/// Bound trait for the bounds on a deserializable type
trait RkyvDeserializable2<T>: for<'a> Deserialize<T, Strategy<Pool, rancor::Error>> {}
impl<T, D: for<'a> Deserialize<T, Strategy<Pool, rancor::Error>>> RkyvDeserializable2<T> for D {}

/// Bound trait for a deserializable with type
trait RkyvDeserializableWith<A, T>:
    for<'a> DeserializeWith<A, T, Strategy<Pool, rancor::Error>>
{
}
impl<A, T, D: for<'a> DeserializeWith<A, T, Strategy<Pool, rancor::Error>>>
    RkyvDeserializableWith<A, T> for D
{
}
