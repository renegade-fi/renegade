//! Authorization types for orders

#![allow(missing_docs)] // rkyv generates archived types

use circuit_types::schnorr::SchnorrSignature;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::SchnorrSignatureDef;
use renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
/// Authorization payload for an order
pub enum OrderAuth {
    /// Authentication for a public order (ring 0)
    PublicOrder {
        /// The signature over the intent's hash
        #[cfg_attr(feature = "rkyv", rkyv(with = SignatureWithNonceDef))]
        intent_signature: SignatureWithNonce,
    },
    /// Authentication for a natively settled private order (ring 1)
    NativelySettledPrivateOrder {
        /// The Schnorr signature for the intent
        #[cfg_attr(feature = "rkyv", rkyv(with = SchnorrSignatureDef))]
        intent_signature: SchnorrSignature,
    },
    /// Authentication for a Renegade-settled order
    RenegadeSettledOrder {
        /// The Schnorr signature for intent
        #[cfg_attr(feature = "rkyv", rkyv(with = SchnorrSignatureDef))]
        intent_signature: SchnorrSignature,
        /// The Schnorr signature for the new output balance, if one is needed
        #[cfg_attr(feature = "rkyv", rkyv(with = SchnorrSignatureDef))]
        new_output_balance_signature: SchnorrSignature,
    },
}

#[cfg(feature = "rkyv")]
mod rkyv_impls {
    //! Rkyv implementations for order auth
    #![allow(missing_docs, clippy::missing_docs_in_private_items)]

    use alloy::primitives::{Bytes, U256};
    use darkpool_types::rkyv_remotes::U256Def;
    use renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce;
    use rkyv::{Archive, Deserialize, Serialize};

    /// An rkyv remote type shim for the SignatureWithNonce type
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(derive(Debug), compare(PartialEq))]
    #[rkyv(remote = SignatureWithNonce)]
    pub struct SignatureWithNonceDef {
        /// The nonce
        #[rkyv(with = U256Def)]
        pub nonce: U256,
        /// The signature bytes
        #[rkyv(getter = extract_bytes)]
        pub signature: Vec<u8>,
    }

    /// Extract bytes from a signature as a vec
    fn extract_bytes(sig: &SignatureWithNonce) -> Vec<u8> {
        sig.signature.to_vec()
    }

    impl From<SignatureWithNonceDef> for SignatureWithNonce {
        fn from(value: SignatureWithNonceDef) -> Self {
            let signature = Bytes::from(value.signature);
            SignatureWithNonce { nonce: value.nonce, signature }
        }
    }

    impl From<SignatureWithNonce> for SignatureWithNonceDef {
        fn from(value: SignatureWithNonce) -> Self {
            SignatureWithNonceDef { nonce: value.nonce, signature: value.signature.to_vec() }
        }
    }
}

// Re-export the rkyv remote type shims
#[cfg(feature = "rkyv")]
pub use rkyv_impls::*;
