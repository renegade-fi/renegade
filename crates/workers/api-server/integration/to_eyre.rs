//! Helpers for converting errors to eyre errors
//!
//! In specific this trait allows us to convert string to eyre using `Try`

use eyre::Result;

/// A trait with auto-implementations that makes it easier to convert errors to
/// `eyre::Result`
///
/// In particular, this lets us easily convert `String` to `eyre::Result` by
/// calling `to_eyre` on it.
pub trait WrapEyre {
    /// The type of the value being wrapped
    type Value;
    /// Convert the error to an eyre::Result
    fn to_eyre(self) -> Result<Self::Value>;
}

impl<R, E: ToString> WrapEyre for core::result::Result<R, E> {
    type Value = R;

    fn to_eyre(self) -> Result<R> {
        match self {
            Ok(r) => Ok(r),
            Err(e) => Err(eyre::eyre!(e.to_string())),
        }
    }
}
