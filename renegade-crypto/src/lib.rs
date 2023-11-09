//! Cryptography helpers and primitives useful throughout the relayer
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(inherent_associated_types)]

#[cfg(feature = "non-wasm")]
pub mod elgamal;
#[cfg(feature = "non-wasm")]
pub mod fields;
pub mod hash;
