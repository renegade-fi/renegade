//! Defines common types, traits, and functionality useful throughout the
//! workspace

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![deny(clippy::missing_docs_in_private_items)]
#![feature(generic_const_exprs)]

use num_bigint::BigUint;
use std::sync::{Arc, RwLock};
use tokio::sync::RwLock as TokioRwLock;

pub mod default_wrapper;
pub mod types;
pub mod worker;

/// A type alias for a shared, concurrency safe, mutable pointer
pub type Shared<T> = Arc<RwLock<T>>;
/// A type alias for a shared, concurrency safe, mutable pointer in an
/// async context
pub type AsyncShared<T> = Arc<TokioRwLock<T>>;

/// Wrap an abstract value in an async shared lock
pub fn new_async_shared<T>(wrapped: T) -> AsyncShared<T> {
    Arc::new(TokioRwLock::new(wrapped))
}

/// From a biguint, get a hex string with a 0x prefix
pub fn biguint_to_str_addr(x: &BigUint) -> String {
    let addr = x.to_str_radix(16 /* radix */);
    format!("0x{addr}")
}
