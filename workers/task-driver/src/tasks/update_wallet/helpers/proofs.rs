//! Helpers for generating witness statements for `VALID WALLET UPDATE`

use crate::tasks::update_wallet::{UpdateWalletTask, UpdateWalletTaskError};
use circuit_types::transfers::{ExternalTransfer, ExternalTransferDirection};
use circuits::zk_circuits::valid_wallet_update::{
    SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
};
use common::types::{
    proof_bundles::ValidWalletUpdateBundle, tasks::WalletUpdateType, wallet::Wallet,
};

/// The wallet does not have a known Merkle proof attached
const ERR_NO_MERKLE_PROOF: &str = "merkle proof for wallet not found";

impl UpdateWalletTask {
    // --- Proof Generation --- //

    /// Build the witness and statement for the update described by the task
    ///
    /// This is as opposed to witness and statement types for e.g. a precomputed
    /// cancellation proof
    pub(crate) fn build_task_witness_statement(
        &self,
    ) -> Result<
        (SizedValidWalletUpdateWitness, SizedValidWalletUpdateStatement),
        UpdateWalletTaskError,
    > {
        // Build the witness and statement
        let old_wallet = &self.old_wallet;
        let new_wallet = &self.new_wallet;
        let transfer_index = self.get_transfer_idx()?;
        let transfer = self.transfer.clone().map(|t| t.external_transfer).unwrap_or_default();
        Self::construct_witness_statement_with_transfer(
            old_wallet,
            new_wallet,
            transfer_index,
            transfer,
        )
    }

    /// Construct a witness and statement for `VALID WALLET UPDATE` without an
    /// external transfer
    pub(crate) fn construct_witness_statement(
        old_wallet: &Wallet,
        new_wallet: &Wallet,
    ) -> Result<
        (SizedValidWalletUpdateWitness, SizedValidWalletUpdateStatement),
        UpdateWalletTaskError,
    > {
        Self::construct_witness_statement_with_transfer(
            old_wallet,
            new_wallet,
            0, // transfer_index
            ExternalTransfer::default(),
        )
    }

    /// Construct a witness and statement for `VALID WALLET UPDATE` with an
    /// external transfer
    pub(crate) fn construct_witness_statement_with_transfer(
        old_wallet: &Wallet,
        new_wallet: &Wallet,
        transfer_index: usize,
        external_transfer: ExternalTransfer,
    ) -> Result<
        (SizedValidWalletUpdateWitness, SizedValidWalletUpdateStatement),
        UpdateWalletTaskError,
    > {
        // Get the Merkle opening previously stored to the wallet
        let merkle_opening = old_wallet
            .merkle_proof
            .clone()
            .ok_or_else(|| UpdateWalletTaskError::Missing(ERR_NO_MERKLE_PROOF.to_string()))?;
        let merkle_root = merkle_opening.compute_root();

        // Build the witness and statement
        let new_wallet_commitment = new_wallet.get_wallet_share_commitment();
        let statement = SizedValidWalletUpdateStatement {
            old_shares_nullifier: old_wallet.get_wallet_nullifier(),
            new_wallet_commitment,
            new_public_shares: new_wallet.blinded_public_shares.clone(),
            merkle_root,
            external_transfer,
            old_pk_root: old_wallet.key_chain.public_keys.pk_root.clone(),
        };

        let witness = SizedValidWalletUpdateWitness {
            old_wallet_private_shares: old_wallet.private_shares.clone(),
            old_wallet_public_shares: old_wallet.blinded_public_shares.clone(),
            old_shares_opening: merkle_opening.into(),
            new_wallet_private_shares: new_wallet.private_shares.clone(),
            transfer_index,
        };

        Ok((witness, statement))
    }

    /// Get the index that the transfer is applied to
    pub(crate) fn get_transfer_idx(&self) -> Result<usize, UpdateWalletTaskError> {
        if let Some(transfer) = self.transfer.as_ref().map(|t| &t.external_transfer) {
            let mint = &transfer.mint;
            match transfer.direction {
                ExternalTransferDirection::Deposit => self.new_wallet.get_balance_index(mint),
                ExternalTransferDirection::Withdrawal => self.old_wallet.get_balance_index(mint),
            }
            .ok_or(UpdateWalletTaskError::Missing(format!("transfer mint {mint:#x} not found")))
        } else {
            Ok(0)
        }
    }

    // --- Proof Storage --- //

    /// Check if the current task has a precomputed update proof
    pub(crate) async fn has_precomputed_update_proof(
        &self,
    ) -> Result<Option<ValidWalletUpdateBundle>, UpdateWalletTaskError> {
        // Check for a cancellation type
        let oid = match self.update_type {
            WalletUpdateType::CancelOrder { id, .. } => id,
            _ => return Ok(None),
        };

        self.ctx.state.get_cancellation_proof(&oid).await.map_err(UpdateWalletTaskError::state)
    }
}
