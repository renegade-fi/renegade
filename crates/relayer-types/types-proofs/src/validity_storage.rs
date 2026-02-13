//! Shared storage types for validity proof bundles.
#![cfg_attr(feature = "rkyv", allow(missing_docs))]

use alloy_primitives::Address;
use circuits_core::zk_circuits::validity_proofs::{
    intent_and_balance::SizedIntentAndBalanceValidityWitness,
    intent_and_balance_first_fill::SizedIntentAndBalanceFirstFillValidityWitness,
    intent_only::SizedIntentOnlyValidityWitness,
    intent_only_first_fill::IntentOnlyFirstFillValidityWitness,
    new_output_balance::SizedNewOutputBalanceValidityWitness,
    output_balance::SizedOutputBalanceValidityWitness,
};
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
use serde::{Deserialize, Serialize};
use types_account::OrderId;
use types_core::AccountId;

use crate::{
    IntentAndBalanceFirstFillValidityBundle, IntentAndBalanceValidityBundle,
    IntentOnlyFirstFillValidityBundle, IntentOnlyValidityBundle, NewOutputBalanceValidityBundle,
    OutputBalanceValidityBundle,
};

/// Locates a validity proof in storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub enum ValidityProofLocator {
    /// A proof indexed by intent/order id.
    Intent {
        /// The order id associated with the intent.
        order_id: OrderId,
    },
    /// A proof indexed by account and mint.
    Balance {
        /// The account id owning the balance.
        account_id: AccountId,
        /// The mint address for the balance.
        #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
        mint: Address,
    },
}

impl ValidityProofLocator {
    /// Build a key for a proof type prefix.
    pub fn storage_key(&self, proof_type_key: &str) -> String {
        match self {
            Self::Intent { order_id } => format!("{proof_type_key}:{order_id}"),
            Self::Balance { account_id, mint } => format!("{proof_type_key}:{account_id}:{mint:?}"),
        }
    }
}

/// A concrete payload for all currently supported validity proof bundles.
///
/// Each variant carries both the proof bundle and its corresponding witness,
/// ensuring that the proof and witness types always match at the type system
/// level. The storage layer writes them to separate keys so clients can
/// deserialize each independently.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub enum ValidityProofBundle {
    /// `INTENT ONLY FIRST FILL VALIDITY`
    IntentOnlyFirstFill {
        /// The proof bundle
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentOnlyFirstFillValidityBundleDef)
        )]
        bundle: IntentOnlyFirstFillValidityBundle,
        /// The witness used to generate the proof
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentOnlyFirstFillValidityWitnessDef)
        )]
        witness: IntentOnlyFirstFillValidityWitness,
    },
    /// `INTENT ONLY VALIDITY`
    IntentOnly {
        /// The proof bundle
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentOnlyValidityBundleDef)
        )]
        bundle: IntentOnlyValidityBundle,
        /// The witness used to generate the proof
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentOnlyValidityWitnessDef)
        )]
        witness: SizedIntentOnlyValidityWitness,
    },
    /// `INTENT AND BALANCE FIRST FILL VALIDITY`
    IntentAndBalanceFirstFill {
        /// The proof bundle
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentAndBalanceFirstFillValidityBundleDef)
        )]
        bundle: IntentAndBalanceFirstFillValidityBundle,
        /// The witness used to generate the proof
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentAndBalanceFirstFillValidityWitnessDef)
        )]
        witness: SizedIntentAndBalanceFirstFillValidityWitness,
    },
    /// `INTENT AND BALANCE VALIDITY`
    IntentAndBalance {
        /// The proof bundle
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentAndBalanceValidityBundleDef)
        )]
        bundle: IntentAndBalanceValidityBundle,
        /// The witness used to generate the proof
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentAndBalanceValidityWitnessDef)
        )]
        witness: SizedIntentAndBalanceValidityWitness,
    },
    /// `NEW OUTPUT BALANCE VALIDITY`
    NewOutputBalance {
        /// The proof bundle
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::NewOutputBalanceValidityBundleDef)
        )]
        bundle: NewOutputBalanceValidityBundle,
        /// The witness used to generate the proof
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::NewOutputBalanceValidityWitnessDef)
        )]
        witness: SizedNewOutputBalanceValidityWitness,
    },
    /// `OUTPUT BALANCE VALIDITY`
    OutputBalance {
        /// The proof bundle
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::OutputBalanceValidityBundleDef)
        )]
        bundle: OutputBalanceValidityBundle,
        /// The witness used to generate the proof
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::OutputBalanceValidityWitnessDef)
        )]
        witness: SizedOutputBalanceValidityWitness,
    },
}

impl ValidityProofBundle {
    /// Consume and cast to `IntentOnlyFirstFillValidityBundle`, panicking on
    /// mismatch.
    pub fn into_intent_only_first_fill(self) -> IntentOnlyFirstFillValidityBundle {
        match self {
            Self::IntentOnlyFirstFill { bundle, .. } => bundle,
            _ => panic!("expected ValidityProofBundle::IntentOnlyFirstFill"),
        }
    }

    /// Consume and cast to `IntentOnlyValidityBundle`, panicking on mismatch.
    pub fn into_intent_only(self) -> IntentOnlyValidityBundle {
        match self {
            Self::IntentOnly { bundle, .. } => bundle,
            _ => panic!("expected ValidityProofBundle::IntentOnly"),
        }
    }

    /// Consume and cast to `IntentAndBalanceFirstFillValidityBundle`, panicking
    /// on mismatch.
    pub fn into_intent_and_balance_first_fill(self) -> IntentAndBalanceFirstFillValidityBundle {
        match self {
            Self::IntentAndBalanceFirstFill { bundle, .. } => bundle,
            _ => panic!("expected ValidityProofBundle::IntentAndBalanceFirstFill"),
        }
    }

    /// Consume and cast to `IntentAndBalanceValidityBundle`, panicking on
    /// mismatch.
    pub fn into_intent_and_balance(self) -> IntentAndBalanceValidityBundle {
        match self {
            Self::IntentAndBalance { bundle, .. } => bundle,
            _ => panic!("expected ValidityProofBundle::IntentAndBalance"),
        }
    }

    /// Consume and cast to `NewOutputBalanceValidityBundle`, panicking on
    /// mismatch.
    pub fn into_new_output_balance(self) -> NewOutputBalanceValidityBundle {
        match self {
            Self::NewOutputBalance { bundle, .. } => bundle,
            _ => panic!("expected ValidityProofBundle::NewOutputBalance"),
        }
    }

    /// Consume and cast to `OutputBalanceValidityBundle`, panicking on
    /// mismatch.
    pub fn into_output_balance(self) -> OutputBalanceValidityBundle {
        match self {
            Self::OutputBalance { bundle, .. } => bundle,
            _ => panic!("expected ValidityProofBundle::OutputBalance"),
        }
    }
}
