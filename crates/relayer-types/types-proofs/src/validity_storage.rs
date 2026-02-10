//! Shared storage types for validity proof bundles.
#![cfg_attr(feature = "rkyv", allow(missing_docs))]

use alloy_primitives::Address;
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub enum ValidityProofBundle {
    /// `INTENT ONLY FIRST FILL VALIDITY`
    IntentOnlyFirstFill(
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentOnlyFirstFillValidityBundleDef)
        )]
        IntentOnlyFirstFillValidityBundle,
    ),
    /// `INTENT ONLY VALIDITY`
    IntentOnly(
        #[cfg_attr(feature = "rkyv", rkyv(with = crate::rkyv_impls::IntentOnlyValidityBundleDef))]
        IntentOnlyValidityBundle,
    ),
    /// `INTENT AND BALANCE FIRST FILL VALIDITY`
    IntentAndBalanceFirstFill(
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::IntentAndBalanceFirstFillValidityBundleDef)
        )]
        IntentAndBalanceFirstFillValidityBundle,
    ),
    /// `INTENT AND BALANCE VALIDITY`
    IntentAndBalance(
        #[cfg_attr(feature = "rkyv", rkyv(with = crate::rkyv_impls::IntentAndBalanceValidityBundleDef))]
         IntentAndBalanceValidityBundle,
    ),
    /// `NEW OUTPUT BALANCE VALIDITY`
    NewOutputBalance(
        #[cfg_attr(
            feature = "rkyv",
            rkyv(with = crate::rkyv_impls::NewOutputBalanceValidityBundleDef)
        )]
        NewOutputBalanceValidityBundle,
    ),
    /// `OUTPUT BALANCE VALIDITY`
    OutputBalance(
        #[cfg_attr(feature = "rkyv", rkyv(with = crate::rkyv_impls::OutputBalanceValidityBundleDef))]
         OutputBalanceValidityBundle,
    ),
}

impl ValidityProofBundle {
    /// Consume and cast to `IntentOnlyFirstFillValidityBundle`, panicking on
    /// mismatch.
    pub fn into_intent_only_first_fill(self) -> IntentOnlyFirstFillValidityBundle {
        match self {
            Self::IntentOnlyFirstFill(bundle) => bundle,
            _ => panic!("expected ValidityProofBundle::IntentOnlyFirstFill"),
        }
    }

    /// Consume and cast to `IntentOnlyValidityBundle`, panicking on mismatch.
    pub fn into_intent_only(self) -> IntentOnlyValidityBundle {
        match self {
            Self::IntentOnly(bundle) => bundle,
            _ => panic!("expected ValidityProofBundle::IntentOnly"),
        }
    }

    /// Consume and cast to `IntentAndBalanceFirstFillValidityBundle`, panicking
    /// on mismatch.
    pub fn into_intent_and_balance_first_fill(self) -> IntentAndBalanceFirstFillValidityBundle {
        match self {
            Self::IntentAndBalanceFirstFill(bundle) => bundle,
            _ => panic!("expected ValidityProofBundle::IntentAndBalanceFirstFill"),
        }
    }

    /// Consume and cast to `IntentAndBalanceValidityBundle`, panicking on
    /// mismatch.
    pub fn into_intent_and_balance(self) -> IntentAndBalanceValidityBundle {
        match self {
            Self::IntentAndBalance(bundle) => bundle,
            _ => panic!("expected ValidityProofBundle::IntentAndBalance"),
        }
    }

    /// Consume and cast to `NewOutputBalanceValidityBundle`, panicking on
    /// mismatch.
    pub fn into_new_output_balance(self) -> NewOutputBalanceValidityBundle {
        match self {
            Self::NewOutputBalance(bundle) => bundle,
            _ => panic!("expected ValidityProofBundle::NewOutputBalance"),
        }
    }

    /// Consume and cast to `OutputBalanceValidityBundle`, panicking on
    /// mismatch.
    pub fn into_output_balance(self) -> OutputBalanceValidityBundle {
        match self {
            Self::OutputBalance(bundle) => bundle,
            _ => panic!("expected ValidityProofBundle::OutputBalance"),
        }
    }
}
