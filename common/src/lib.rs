//! Defines common types, traits, and functionality useful throughout the
//! workspace

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![deny(clippy::missing_docs_in_private_items)]
#![feature(generic_const_exprs)]

use ethers::types::Address;
use num_bigint::BigUint;
use std::sync::{Arc, RwLock};
use tokio::sync::RwLock as TokioRwLock;

pub mod default_wrapper;
pub mod keyed_list;
pub mod types;
pub mod worker;

/// A type alias for a shared, concurrency safe, mutable pointer
pub type Shared<T> = Arc<RwLock<T>>;
/// A type alias for a shared, concurrency safe, mutable pointer in an
/// async context
pub type AsyncShared<T> = Arc<TokioRwLock<T>>;

/// Wrap an abstract value in a shared lock
pub fn new_shared<T>(wrapped: T) -> Shared<T> {
    Arc::new(RwLock::new(wrapped))
}

/// Wrap an abstract value in an async shared lock
pub fn new_async_shared<T>(wrapped: T) -> AsyncShared<T> {
    Arc::new(TokioRwLock::new(wrapped))
}

/// From a biguint, get a lowercase hex string with a 0x prefix, padded to the
/// Ethereum address length
pub fn biguint_to_str_addr(x: &BigUint) -> String {
    let mut bytes = [0_u8; Address::len_bytes()];
    let x_bytes = x.to_bytes_be();
    bytes[..x_bytes.len()].copy_from_slice(&x_bytes);
    let addr = Address::from_slice(&bytes);
    format!("{addr:#x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint_to_str_addr() {
        let x = BigUint::from(1u8);
        let addr = biguint_to_str_addr(&x);
        println!("addr: {}", addr);
    }
}
