//! Helpers for output balance bundles

use alloy::primitives::{Address, U256};
use circuit_types::{PlonkLinkProof, ProofLinkingHint};
use constants::MERKLE_HEIGHT;
use darkpool_types::balance::{DarkpoolBalance, PostMatchBalanceShare};
use renegade_solidity_abi::v2::IDarkpoolV2;
use types_account::order::Order;
use types_core::AccountId;
use types_proofs::{
    NewOutputBalanceValidityBundle, OutputBalanceValidityBundle,
    SizedNewOutputBalanceValidityWitness, SizedOutputBalanceValidityWitness,
};

use crate::tasks::settlement::helpers::{SettlementProcessor, error::SettlementError};

/// The output balance bundle type
///
/// This type allows us to operate generically over output balance bundles in
/// higher level processing
#[allow(clippy::large_enum_variant)]
pub(crate) enum OutputBalanceBundle {
    /// A new output balance bundle
    New {
        /// The new output balance validity bundle
        bundle: NewOutputBalanceValidityBundle,
        /// The new output balance validity witness
        witness: SizedNewOutputBalanceValidityWitness,
    },
    /// An existing output balance bundle
    Existing {
        /// The existing output balance validity bundle
        bundle: OutputBalanceValidityBundle,
        /// The existing output balance validity witness
        witness: SizedOutputBalanceValidityWitness,
    },
}

impl OutputBalanceBundle {
    /// Get the balance itself from the bundle
    pub fn balance(&self) -> DarkpoolBalance {
        match self {
            Self::New { witness, .. } => witness.balance.clone(),
            Self::Existing { witness, .. } => witness.balance.clone(),
        }
    }

    /// Get the post-match balance shares from the bundle
    pub fn post_match_balance_shares(&self) -> PostMatchBalanceShare {
        match self {
            Self::New { witness, .. } => witness.post_match_balance_shares.clone(),
            Self::Existing { witness, .. } => witness.post_match_balance_shares.clone(),
        }
    }

    /// Get the linking hint for proof linking from the bundle
    pub fn linking_hint(&self) -> ProofLinkingHint {
        match self {
            Self::New { bundle, .. } => bundle.linking_hint.clone(),
            Self::Existing { bundle, .. } => bundle.linking_hint.clone(),
        }
    }

    /// Build an output balance ABI bundle
    pub fn build_abi_bundle(
        &self,
        linking_proof: PlonkLinkProof,
    ) -> IDarkpoolV2::OutputBalanceBundle {
        match self {
            Self::New { bundle, .. } => IDarkpoolV2::OutputBalanceBundle::new_output_balance(
                U256::from(MERKLE_HEIGHT),
                bundle.statement.clone().into(),
                bundle.proof.clone().into(),
                linking_proof.into(),
            ),
            Self::Existing { bundle, .. } => {
                IDarkpoolV2::OutputBalanceBundle::existing_output_balance(
                    U256::from(MERKLE_HEIGHT),
                    bundle.statement.clone().into(),
                    bundle.proof.clone().into(),
                    linking_proof.into(),
                )
            },
        }
    }
}

// ---------------------
// | Processor Methods |
// ---------------------

impl SettlementProcessor {
    // --- Output Balances --- //

    /// Get the output balance bundle for a given order
    ///
    /// This method also returns the `DarkpoolBalance` directly for
    /// convenience.
    pub(crate) async fn get_output_balance_bundle(
        &self,
        account_id: AccountId,
        order: &Order,
    ) -> Result<OutputBalanceBundle, SettlementError> {
        let output_mint = order.intent.inner.out_token;
        let has_balance = self.ctx.state.has_darkpool_balance(&account_id, &output_mint).await?;
        if !has_balance {
            self.get_new_output_balance_bundle(account_id, output_mint).await
        } else {
            self.get_existing_output_balance_bundle(account_id, output_mint).await
        }
    }

    /// Get a new output balance bundle for the given mint
    async fn get_new_output_balance_bundle(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<OutputBalanceBundle, SettlementError> {
        let (bundle, witness) = self
            .ctx
            .state
            .get_new_output_balance_validity_proof_and_witness(account_id, mint)
            .await?
            .ok_or_else(|| {
                SettlementError::state(format!(
                    "new output balance proof not found for account {account_id} and mint {mint}"
                ))
            })?;

        let bundle = OutputBalanceBundle::New { bundle, witness: witness.clone() };
        Ok(bundle)
    }

    /// Get an existing output balance bundle for the given mint
    async fn get_existing_output_balance_bundle(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<OutputBalanceBundle, SettlementError> {
        let (bundle, witness) = self
            .ctx
            .state
            .get_output_balance_validity_proof_and_witness(account_id, mint)
            .await?
            .ok_or_else(|| {
                SettlementError::state(format!(
                    "output balance proof not found for account {account_id} and mint {mint}"
                ))
            })?;

        let bundle = OutputBalanceBundle::Existing { bundle, witness: witness.clone() };
        Ok(bundle)
    }
}
