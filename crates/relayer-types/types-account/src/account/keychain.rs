//! Keychain helpers for the wallet

use constants::Scalar;
use darkpool_types::csprng::PoseidonCSPRNG;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::ScalarDef;
use derivative::Derivative;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use types_core::HmacKey;

use crate::derivation::{derive_master_share_stream_seed, derive_recovery_stream_seed};

/// Represents the private keys a relayer has access to for a given wallet
#[derive(Clone, Debug, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct PrivateKeyChain {
    /// The symmetric HMAC key that the user has registered with the relayer for
    /// API authentication
    pub symmetric_key: HmacKey,
    /// The master view seed of the account
    #[cfg_attr(feature = "rkyv", rkyv(with = ScalarDef))]
    pub master_view_seed: Scalar,
    /// The master share seed CSPRNG state
    pub master_share_seed_csprng: PoseidonCSPRNG,
    /// The master recovery seed CSPRNG state
    pub master_recovery_seed_csprng: PoseidonCSPRNG,
}

impl PrivateKeyChain {
    /// Create a new private key chain from a symmetric key
    pub fn new(symmetric_key: HmacKey, master_view_seed: Scalar) -> Self {
        let master_share_seed_csprng = derive_master_share_stream_seed(&master_view_seed);
        let master_recovery_seed_csprng = derive_recovery_stream_seed(&master_view_seed);
        Self {
            symmetric_key,
            master_view_seed,
            master_share_seed_csprng,
            master_recovery_seed_csprng,
        }
    }

    /// Sample a new recovery id stream seed from the master keychain
    ///
    /// Mutates the underlying CSPRNG state.
    pub fn sample_recovery_id_stream_seed(&mut self) -> PoseidonCSPRNG {
        let seed = self.master_recovery_seed_csprng.next().unwrap(); // CSPRNG is infallible
        PoseidonCSPRNG::new(seed)
    }

    /// Sample a new share stream seed from the master keychain
    ///
    /// Mutates the underlying CSPRNG state.
    pub fn sample_share_stream_seed(&mut self) -> PoseidonCSPRNG {
        let seed = self.master_share_seed_csprng.next().unwrap(); // CSPRNG is infallible
        PoseidonCSPRNG::new(seed)
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

    /// Sample a new recovery id stream seed from the master keychain
    ///
    /// Mutates the underlying CSPRNG state.
    pub fn sample_recovery_id_stream_seed(&mut self) -> PoseidonCSPRNG {
        let master_seed = &mut self.secret_keys.master_recovery_seed_csprng;
        let seed = master_seed.next().unwrap(); // CSPRNG is infallible
        PoseidonCSPRNG::new(seed)
    }

    /// Sample a new share stream seed from the master keychain
    ///
    /// Mutates the underlying CSPRNG state.
    pub fn sample_share_stream_seed(&mut self) -> PoseidonCSPRNG {
        let master_seed = &mut self.secret_keys.master_share_seed_csprng;
        let seed = master_seed.next().unwrap(); // CSPRNG is infallible
        PoseidonCSPRNG::new(seed)
    }
}
