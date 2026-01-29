//! Configuration utils for contract interaction

use std::{
    collections::HashMap,
    sync::{OnceLock, RwLock},
};

use alloy::primitives::Address;
use circuit_types::{elgamal::EncryptionKey, fixed_point::FixedPoint};

use crate::concurrency::RwStatic;

/// A type alias for a pair of addresses used in the fee override mapping
type PairFeeKey = (Address, Address);

/// The protocol fee that the contract charges on a match
static PROTOCOL_FEE: RwStatic<FixedPoint> = RwStatic::new(|| RwLock::new(FixedPoint::zero()));
/// The protocol fee overrides for an external match
///
/// Maps a mint to the fee override if one exists
pub static PROTOCOL_FEE_OVERRIDES: RwStatic<HashMap<PairFeeKey, FixedPoint>> =
    RwStatic::new(|| RwLock::new(HashMap::new()));
/// The protocol's public encryption key used for paying fees
pub static PROTOCOL_PUBKEY: OnceLock<EncryptionKey> = OnceLock::new();
/// The address at which the protocol collects fees
pub static PROTOCOL_FEE_ADDR: OnceLock<Address> = OnceLock::new();
/// The chain ID for the blockchain network
static CHAIN_ID: OnceLock<u64> = OnceLock::new();

/// Get the protocol fee from the static variable
///
/// Panics if the protocol fee has not been set
pub fn get_default_protocol_fee() -> FixedPoint {
    #[cfg(feature = "mocks")]
    {
        FixedPoint::from_f64_round_down(0.0006) // 6 bps
    }

    #[cfg(not(feature = "mocks"))]
    {
        *PROTOCOL_FEE.read().expect("fee lock poisoned")
    }
}

/// Set the protocol fee
pub fn set_default_protocol_fee(fee: FixedPoint) {
    *PROTOCOL_FEE.write().expect("fee lock poisoned") = fee;
}

/// Get the protocol fee override for the given pair
pub fn get_protocol_fee(asset0: &Address, asset1: &Address) -> FixedPoint {
    let key = fee_pair_key(asset0, asset1);
    PROTOCOL_FEE_OVERRIDES
        .read()
        .expect("fee override lock poisoned")
        .get(&key)
        .cloned()
        .unwrap_or(get_default_protocol_fee())
}

/// Set the protocol fee override for the given pair
pub fn set_protocol_fee(asset0: &Address, asset1: &Address, fee: FixedPoint) {
    let key = fee_pair_key(asset0, asset1);
    PROTOCOL_FEE_OVERRIDES.write().expect("fee override lock poisoned").insert(key, fee);
}

/// Get the fee key for the given pair
fn fee_pair_key(asset0: &Address, asset1: &Address) -> PairFeeKey {
    if asset0 < asset1 { (*asset0, *asset1) } else { (*asset1, *asset0) }
}

/// Get the protocol encryption key from the static variable
///
/// Panics if the protocol encryption key has not been set
pub fn get_protocol_pubkey() -> EncryptionKey {
    // If the mocks feature is enabled we unwrap to a default
    #[cfg(feature = "mocks")]
    {
        use circuit_types::elgamal::DecryptionKey;
        use rand::thread_rng;

        let mut rng = thread_rng();
        *PROTOCOL_PUBKEY.get_or_init(|| DecryptionKey::random(&mut rng).public_key())
    }

    #[cfg(not(feature = "mocks"))]
    {
        *PROTOCOL_PUBKEY.get().expect("Protocol pubkey has not been set")
    }
}

/// Set the protocol encryption key
pub fn set_protocol_pubkey(key: EncryptionKey) {
    PROTOCOL_PUBKEY.set(key).expect("protocol pubkey has already been set");
}

/// Get the protocol fee address from the static variable
pub fn get_protocol_fee_addr() -> Address {
    *PROTOCOL_FEE_ADDR.get().expect("protocol fee address has not been set")
}

/// Set the protocol fee address
pub fn set_protocol_fee_addr(addr: Address) {
    PROTOCOL_FEE_ADDR.set(addr).expect("protocol fee address has already been set");
}

/// Get the chain ID from the static variable
///
/// Panics if the chain ID has not been set
pub fn get_chain_id() -> u64 {
    *CHAIN_ID.get().expect("chain ID has not been set")
}

/// Set the chain ID
pub fn set_chain_id(chain_id: u64) {
    CHAIN_ID.set(chain_id).expect("chain ID has already been set");
}
