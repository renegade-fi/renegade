//! Types for depositing into an account

#[cfg(feature = "rkyv")]
mod rkyv_impls {
    //! Rkyv remote type shims for darkpool abi types
    #![allow(missing_docs, clippy::missing_docs_in_private_items, non_snake_case)]

    use alloy::primitives::{Bytes, U256};
    use darkpool_types::rkyv_remotes::U256Def;
    use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
    use rkyv::{Archive, Deserialize, Serialize};

    /// An rkyv remote type shim for the `DepositAuth` type
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(derive(Debug), compare(PartialEq))]
    #[rkyv(remote = DepositAuth)]
    pub struct DepositAuthDef {
        #[rkyv(with = U256Def)]
        pub permit2Nonce: U256,
        #[rkyv(with = U256Def)]
        pub permit2Deadline: U256,
        #[rkyv(getter = extract_bytes)]
        pub permit2Signature: Vec<u8>,
    }

    /// Extract bytes from a permit2 signature as a vec
    fn extract_bytes(auth: &DepositAuth) -> Vec<u8> {
        auth.permit2Signature.to_vec()
    }

    #[allow(non_snake_case)]
    impl From<DepositAuthDef> for DepositAuth {
        fn from(value: DepositAuthDef) -> Self {
            let permit2Signature = Bytes::from(value.permit2Signature);
            DepositAuth {
                permit2Nonce: value.permit2Nonce,
                permit2Deadline: value.permit2Deadline,
                permit2Signature,
            }
        }
    }

    impl From<DepositAuth> for DepositAuthDef {
        fn from(value: DepositAuth) -> Self {
            DepositAuthDef {
                permit2Nonce: value.permit2Nonce,
                permit2Deadline: value.permit2Deadline,
                permit2Signature: value.permit2Signature.to_vec(),
            }
        }
    }
}

// Re-export the rkyv remote type shims
#[cfg(feature = "rkyv")]
pub use rkyv_impls::*;
