//! Groups type definitions and abstractions useful in the circuitry

use serde::{de::Error as SerdeErr, Deserialize, Deserializer, Serialize, Serializer};
pub mod balance;
pub mod fee;
pub mod handshake_tuple;
pub mod keychain;
pub mod r#match;
pub mod note;
pub mod order;
pub mod wallet;

// -----------------------------------------
// | Serialization Deserialization Helpers |
// -----------------------------------------

/// A helper for serializing array types
pub(crate) fn serialize_array<const ARR_SIZE: usize, T, S>(
    arr: &[T; ARR_SIZE],
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize + Clone,
    [(); ARR_SIZE]: Sized,
{
    // Convert the array to a vec
    let arr_vec: Vec<T> = arr.clone().into();
    arr_vec.serialize(s)
}

/// A helper for deserializing array types
pub(crate) fn deserialize_array<'de, const ARR_SIZE: usize, T, D>(
    d: D,
) -> Result<[T; ARR_SIZE], D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
    [(); ARR_SIZE]: Sized,
{
    // Deserialize a vec and then convert to an array
    let deserialized_vec: Vec<T> = Vec::deserialize(d)?;
    deserialized_vec
        .try_into()
        .map_err(|_| SerdeErr::custom("incorrect size of serialized array"))
}
