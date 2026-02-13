//! Helpers for private fill validity bundles
//!
//! Private settlement can consume either:
//! - `INTENT AND BALANCE FIRST FILL VALIDITY` for first fills
//! - `INTENT AND BALANCE VALIDITY` for subsequent fills
//!
//! This module provides a single enum that papers over both cases.

use alloy::primitives::U256;
use circuit_types::{PlonkLinkProof, ProofLinkingHint};
use constants::MERKLE_HEIGHT;
use darkpool_types::{balance::PostMatchBalanceShare, intent::Intent};
use renegade_solidity_abi::v2::IDarkpoolV2::{
    OutputBalanceBundle, RenegadeSettledIntentAuthBundle, RenegadeSettledIntentAuthBundleFirstFill,
    SettlementBundle,
};
use types_account::{OrderId, order::Order};
use types_proofs::{
    IntentAndBalanceFirstFillValidityBundle, IntentAndBalanceValidityBundle,
    SizedIntentAndBalanceFirstFillValidityWitness, SizedIntentAndBalanceValidityWitness,
};

use crate::tasks::settlement::helpers::{SettlementProcessor, error::SettlementError};

/// A validity bundle for private settlement.
///
/// Wraps either first-fill or subsequent-fill intent-and-balance validity
/// proof data behind one interface for downstream settlement code.
#[allow(clippy::large_enum_variant)]
pub(crate) enum PrivateFillValidityBundle {
    /// First-fill intent and balance validity data.
    FirstFill {
        /// The first-fill validity proof bundle.
        bundle: IntentAndBalanceFirstFillValidityBundle,
        /// The first-fill validity witness.
        witness: SizedIntentAndBalanceFirstFillValidityWitness,
    },
    /// Subsequent-fill intent and balance validity data.
    SubsequentFill {
        /// The subsequent-fill validity proof bundle.
        bundle: IntentAndBalanceValidityBundle,
        /// The subsequent-fill validity witness.
        witness: SizedIntentAndBalanceValidityWitness,
    },
}

impl PrivateFillValidityBundle {
    /// Get the linking hint for proof linking.
    pub fn linking_hint(&self) -> ProofLinkingHint {
        match self {
            Self::FirstFill { bundle, .. } => bundle.linking_hint.clone(),
            Self::SubsequentFill { bundle, .. } => bundle.linking_hint.clone(),
        }
    }

    /// Get the witness intent.
    pub fn intent(&self) -> Intent {
        match self {
            Self::FirstFill { witness, .. } => witness.intent.clone(),
            Self::SubsequentFill { witness, .. } => witness.intent.clone(),
        }
    }

    /// Get the witness balance.
    pub fn balance(&self) -> darkpool_types::balance::DarkpoolBalance {
        match self {
            Self::FirstFill { witness, .. } => witness.balance.clone(),
            Self::SubsequentFill { witness, .. } => witness.balance.clone(),
        }
    }

    /// Get the pre-settlement amount public share.
    pub fn new_amount_public_share(&self) -> constants::Scalar {
        match self {
            Self::FirstFill { witness, .. } => witness.new_amount_public_share,
            Self::SubsequentFill { witness, .. } => witness.new_amount_public_share,
        }
    }

    /// Get the pre-settlement input balance public shares.
    pub fn post_match_balance_shares(&self) -> PostMatchBalanceShare {
        match self {
            Self::FirstFill { witness, .. } => witness.post_match_balance_shares.clone(),
            Self::SubsequentFill { witness, .. } => witness.post_match_balance_shares.clone(),
        }
    }

    /// Get a settlement bundle for the validity bundle
    pub fn build_settlement_bundle(
        &self,
        output_bundle: OutputBalanceBundle,
        linking_proof: PlonkLinkProof,
    ) -> SettlementBundle {
        match self {
            Self::FirstFill { bundle, .. } => {
                let auth = RenegadeSettledIntentAuthBundleFirstFill {
                    merkleDepth: U256::from(MERKLE_HEIGHT),
                    statement: bundle.statement.clone().into(),
                    validityProof: bundle.proof.clone().into(),
                };

                Self::build_first_fill_settlement_bundle(auth, output_bundle, linking_proof)
            },
            Self::SubsequentFill { bundle, .. } => {
                let auth = RenegadeSettledIntentAuthBundle {
                    merkleDepth: U256::from(MERKLE_HEIGHT),
                    statement: bundle.statement.clone().into(),
                    validityProof: bundle.proof.clone().into(),
                };

                Self::build_subsequent_fill_settlement_bundle(auth, output_bundle, linking_proof)
            },
        }
    }

    /// Build a settlement bundle for the first fill validity bundle
    pub fn build_first_fill_settlement_bundle(
        auth: RenegadeSettledIntentAuthBundleFirstFill,
        output_bundle: OutputBalanceBundle,
        linking_proof: PlonkLinkProof,
    ) -> SettlementBundle {
        SettlementBundle::renegade_settled_private_first_fill(
            auth,
            output_bundle,
            linking_proof.into(),
        )
    }

    /// Build a settlement bundle for the subsequent fill validity bundle
    pub fn build_subsequent_fill_settlement_bundle(
        auth: RenegadeSettledIntentAuthBundle,
        output_bundle: OutputBalanceBundle,
        linking_proof: PlonkLinkProof,
    ) -> SettlementBundle {
        SettlementBundle::renegade_settled_private_fill(auth, output_bundle, linking_proof.into())
    }
}

impl SettlementProcessor {
    /// Get private fill validity data for an order, selecting first-fill or
    /// subsequent-fill based on order metadata.
    pub(crate) async fn get_private_fill_validity_bundle(
        &self,
        order: &Order,
    ) -> Result<PrivateFillValidityBundle, SettlementError> {
        self.get_private_fill_validity_bundle_by_state(order.id, order.metadata.has_been_filled)
            .await
    }

    /// Get private fill validity data by order id and fill status.
    pub(crate) async fn get_private_fill_validity_bundle_by_state(
        &self,
        order_id: OrderId,
        has_been_filled: bool,
    ) -> Result<PrivateFillValidityBundle, SettlementError> {
        if has_been_filled {
            let (bundle, witness) =
                self.get_private_subsequent_fill_validity_bundle(order_id).await?;
            Ok(PrivateFillValidityBundle::SubsequentFill { bundle, witness })
        } else {
            let (bundle, witness) = self.get_private_first_fill_validity_bundle(order_id).await?;
            Ok(PrivateFillValidityBundle::FirstFill { bundle, witness })
        }
    }
}
