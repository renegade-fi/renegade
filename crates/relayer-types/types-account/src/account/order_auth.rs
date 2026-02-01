//! Authorization types for orders

#![allow(missing_docs)] // rkyv generates archived types

use circuit_types::schnorr::SchnorrSignature;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::SchnorrSignatureDef;
use renegade_solidity_abi::v2::IDarkpoolV2::{PublicIntentPermit, SignatureWithNonce};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
/// Authorization payload for an order
pub enum OrderAuth {
    /// Authentication for a public order (ring 0)
    PublicOrder {
        /// The permit for the intent
        #[cfg_attr(feature = "rkyv", rkyv(with = PublicIntentPermitDef))]
        permit: PublicIntentPermit,
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

impl OrderAuth {
    /// Monomorphize the order auth into a public intent permit and intent
    /// signature
    pub fn into_public(&self) -> (PublicIntentPermit, SignatureWithNonce) {
        match self {
            OrderAuth::PublicOrder { permit, intent_signature } => {
                (permit.clone(), intent_signature.clone())
            },
            _ => panic!("Order auth is not a public order"),
        }
    }
}

#[cfg(feature = "rkyv")]
mod rkyv_impls {
    //! Rkyv implementations for order auth
    #![allow(missing_docs)]
    #![allow(clippy::missing_docs_in_private_items)]
    #![allow(non_snake_case)]

    use alloy::primitives::{Address, Bytes, U256};
    use circuit_types::{Amount, fixed_point::FixedPoint};
    use darkpool_types::rkyv_remotes::{AddressDef, FixedPointDef, U256Def};
    use renegade_solidity_abi::v2::{
        IDarkpoolV2::{self, PublicIntentPermit, SignatureWithNonce},
        relayer_types::u256_to_u128,
    };
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

    /// An rkyv remote type shim for the public intent permit type
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(derive(Debug))]
    #[rkyv(remote = PublicIntentPermit)]
    #[rkyv(archived = ArchivedPublicIntentPermit)]
    pub struct PublicIntentPermitDef {
        /// The intent
        #[rkyv(with = IntentDef)]
        intent: IDarkpoolV2::Intent,
        /// The executor
        #[rkyv(with = AddressDef)]
        executor: Address,
    }

    impl From<PublicIntentPermitDef> for PublicIntentPermit {
        fn from(value: PublicIntentPermitDef) -> Self {
            PublicIntentPermit { intent: value.intent, executor: value.executor }
        }
    }

    /// An rkyv remote type shim for the darkpool intent type
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(derive(Debug), compare(PartialEq))]
    #[rkyv(remote = IDarkpoolV2::Intent)]
    #[rkyv(archived = ArchivedIntent)]
    pub struct IntentDef {
        /// The input token
        #[rkyv(with = AddressDef)]
        pub inToken: Address,
        /// The output token
        #[rkyv(with = AddressDef)]
        pub outToken: Address,
        /// The owner
        #[rkyv(with = AddressDef)]
        pub owner: Address,
        /// The minimum price
        #[rkyv(with = FixedPointDef)]
        #[rkyv(getter = parse_min_price)]
        pub minPrice: FixedPoint,
        /// The amount in
        #[rkyv(getter = get_amount_as_u128)]
        pub amountIn: Amount,
    }

    /// An rkyv helper to fetch teh amount as a u128
    fn get_amount_as_u128(intent: &IDarkpoolV2::Intent) -> Amount {
        u256_to_u128(intent.amountIn)
    }

    /// Parse an IDarkpoolV2::FixedPoint as a relayer FixedPoint for the min
    /// price
    fn parse_min_price(intent: &IDarkpoolV2::Intent) -> FixedPoint {
        FixedPoint::from(intent.minPrice.clone())
    }

    impl From<IntentDef> for IDarkpoolV2::Intent {
        fn from(value: IntentDef) -> Self {
            IDarkpoolV2::Intent {
                inToken: value.inToken,
                outToken: value.outToken,
                owner: value.owner,
                minPrice: value.minPrice.into(),
                amountIn: U256::from(value.amountIn),
            }
        }
    }
}

// Re-export the rkyv remote type shims
#[cfg(feature = "rkyv")]
pub use rkyv_impls::*;

#[cfg(feature = "mocks")]
pub mod mocks {
    //! Mocks for order auth
    #![allow(missing_docs, clippy::missing_docs_in_private_items)]

    use alloy::primitives::{Bytes, U256};
    use darkpool_types::fuzzing::random_address;
    use renegade_solidity_abi::v2::IDarkpoolV2::{PublicIntentPermit, SignatureWithNonce};

    use crate::mocks::mock_intent;

    use super::OrderAuth;

    /// Create a mock signature with nonce
    pub fn mock_signature_with_nonce() -> SignatureWithNonce {
        SignatureWithNonce { nonce: U256::from(0), signature: Bytes::from(vec![0u8; 65]) }
    }

    /// Create a mock public intent permit
    pub fn mock_public_intent_permit() -> PublicIntentPermit {
        let intent = mock_intent();
        let executor = random_address();
        PublicIntentPermit { intent: intent.into(), executor }
    }

    /// Create a mock order auth
    pub fn mock_order_auth() -> OrderAuth {
        let permit = mock_public_intent_permit();
        let intent_signature = mock_signature_with_nonce();
        OrderAuth::PublicOrder { permit, intent_signature }
    }
}
