//! Keychain helpers for the wallet

use derivative::Derivative;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use types_core::HmacKey;

/// Represents the private keys a relayer has access to for a given wallet
#[derive(Clone, Debug, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct PrivateKeyChain {
    /// The symmetric HMAC key that the user has registered with the relayer for
    /// API authentication
    pub symmetric_key: HmacKey,
}

impl PrivateKeyChain {
    /// Create a new private key chain from a symmetric key
    pub fn new(symmetric_key: HmacKey) -> Self {
        Self { symmetric_key }
    }
}

/// Represents the public and private keys given to the relayer managing a
/// wallet
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct KeyChain {
    /// The private keys in the wallet
    pub secret_keys: PrivateKeyChain,
}

impl KeyChain {
    /// Create a new keychain from a private keychain
    pub fn new(secret_keys: PrivateKeyChain) -> Self {
        Self { secret_keys }
    }

    /// Get the symmetric key
    pub fn symmetric_key(&self) -> HmacKey {
        self.secret_keys.symmetric_key
    }
}
