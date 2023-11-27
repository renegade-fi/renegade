//! Defines `StarknetClient` helpers that allow for interacting with the
//! `darkpool` contract

use circuit_types::merkle::MerkleRoot;
use circuit_types::native_helpers::compute_wallet_commitment_from_private;
use circuit_types::traits::BaseType;
use circuit_types::traits::CircuitCommitmentType;
use circuit_types::wallet::Nullifier;
use circuit_types::wallet::WalletShareStateCommitment;
use circuit_types::SizedWalletShare;
use common::types::proof_bundles::OrderValidityProofBundle;
use common::types::proof_bundles::ValidMatchMpcBundle;
use common::types::proof_bundles::ValidSettleBundle;
use common::types::proof_bundles::ValidWalletCreateBundle;
use common::types::proof_bundles::ValidWalletUpdateBundle;
use mpc_stark::algebra::scalar::Scalar;
use renegade_crypto::fields::scalar_to_starknet_felt;
use renegade_crypto::fields::starknet_felt_to_scalar;
use starknet::accounts::Call;
use starknet::core::types::FieldElement as StarknetFieldElement;
use starknet::core::types::FunctionCall;

use crate::types::CalldataSerializable;
use crate::types::ExternalTransfer;
use crate::types::MatchPayload;
use crate::GET_PUBLIC_BLINDER_TRANSACTION;
use crate::MATCH_SELECTOR;
use crate::MERKLE_ROOT_SELECTOR;
use crate::NEW_WALLET_SELECTOR;
use crate::NULLIFIER_USED_SELECTOR;
use crate::UPDATE_WALLET_SELECTOR;
use crate::{error::StarknetClientError, MERKLE_ROOT_IN_HISTORY_SELECTOR};

use super::StarknetClient;
use super::TransactionHash;

impl StarknetClient {
    // --- Getters ---

    /// Get the current Merkle root in the contract
    pub async fn get_merkle_root(&self) -> Result<Scalar, StarknetClientError> {
        let call = FunctionCall {
            contract_address: self.contract_address,
            entry_point_selector: *MERKLE_ROOT_SELECTOR,
            calldata: vec![],
        };

        let res = self.call_contract(call).await?;
        Ok(starknet_felt_to_scalar(&res[0]))
    }

    /// Check whether the given Merkle root is valid
    pub async fn check_merkle_root_valid(
        &self,
        root: MerkleRoot,
    ) -> Result<bool, StarknetClientError> {
        let root = scalar_to_starknet_felt(&root);
        let call = FunctionCall {
            contract_address: self.contract_address,
            entry_point_selector: *MERKLE_ROOT_IN_HISTORY_SELECTOR,
            calldata: vec![root],
        };

        let res = self.call_contract(call).await?;
        Ok(res[0].eq(&StarknetFieldElement::from(1u8)))
    }

    /// Check whether the given nullifier is used
    pub async fn check_nullifier_unused(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, StarknetClientError> {
        let reduced_nullifier = scalar_to_starknet_felt(&nullifier);
        let call = FunctionCall {
            contract_address: self.contract_address,
            entry_point_selector: *NULLIFIER_USED_SELECTOR,
            calldata: vec![reduced_nullifier],
        };

        let res = self.call_contract(call).await?;
        Ok(res[0].eq(&StarknetFieldElement::from(0u8)))
    }

    /// Return the hash of the transaction that last indexed secret shares for
    /// the given public blinder share
    ///
    /// Returns `None` if the public blinder share has not been used
    pub async fn get_public_blinder_tx(
        &self,
        public_blinder_share: Scalar,
    ) -> Result<Option<TransactionHash>, StarknetClientError> {
        let reduced_blinder_share = scalar_to_starknet_felt(&public_blinder_share);
        let call = FunctionCall {
            contract_address: self.contract_address,
            entry_point_selector: *GET_PUBLIC_BLINDER_TRANSACTION,
            calldata: vec![reduced_blinder_share],
        };

        self.call_contract(call).await.map(|call_res| call_res[0]).map(|ret_val| {
            if ret_val.eq(&StarknetFieldElement::from(0u8)) {
                None
            } else {
                Some(ret_val)
            }
        })
    }

    // --- Setters --- //

    /// Call the `new_wallet` contract method with the given source data
    ///
    /// Returns the transaction hash corresponding to the `new_wallet`
    /// invocation
    pub async fn new_wallet(
        &self,
        private_share_commitment: WalletShareStateCommitment,
        public_shares: SizedWalletShare,
        valid_wallet_create: ValidWalletCreateBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        assert!(self.config.account_enabled(), "no private key given to sign transactions with");

        // Compute a commitment to the public shares
        let wallet_share_commitment =
            compute_wallet_commitment_from_private(public_shares.clone(), private_share_commitment);

        // Build the calldata
        let mut calldata = public_shares.blinder.to_calldata();
        calldata.extend(wallet_share_commitment.to_calldata());
        calldata.extend(public_shares.to_scalars().to_calldata());
        calldata.extend(valid_wallet_create.proof.to_calldata());
        calldata.extend(valid_wallet_create.commitment.to_commitments().to_calldata());

        // Call the `new_wallet` contract function
        self.execute_transaction(Call {
            to: self.contract_address,
            selector: *NEW_WALLET_SELECTOR,
            calldata,
        })
        .await
    }

    /// Call the `update_wallet` function in the contract, passing it all the
    /// information needed to nullify the old wallet, transition the wallet
    /// to a newly committed one, and handle internal/external transfers
    ///
    /// Returns the transaction hash of the `update_wallet` call
    #[allow(clippy::too_many_arguments)]
    pub async fn update_wallet(
        &self,
        new_private_shares_commitment: WalletShareStateCommitment,
        old_shares_nullifier: Nullifier,
        external_transfer: Option<ExternalTransfer>,
        new_public_shares: SizedWalletShare,
        valid_wallet_update: ValidWalletUpdateBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        let new_wallet_share_commitment = compute_wallet_commitment_from_private(
            new_public_shares.clone(),
            new_private_shares_commitment,
        );

        // Build the calldata
        let mut calldata = new_public_shares.blinder.to_calldata();
        calldata.extend(new_wallet_share_commitment.to_calldata());
        calldata.extend(old_shares_nullifier.to_calldata());
        calldata.extend(new_public_shares.to_scalars().to_calldata());

        // Add the external transfer tuple to the calldata
        if let Some(transfer) = external_transfer {
            calldata.push(1u8.into() /* external_transfers_len */);
            calldata.extend(transfer.to_calldata());
        } else {
            calldata.push(0u8.into() /* external_transfers_len */);
        }

        calldata.extend(valid_wallet_update.proof.to_calldata());
        calldata.extend(valid_wallet_update.commitment.to_commitments().to_calldata());

        // Call the `update_wallet` function in the contract
        self.execute_transaction(Call {
            to: self.contract_address,
            selector: *UPDATE_WALLET_SELECTOR,
            calldata,
        })
        .await
    }

    /// Submit a `match` transaction to the contract
    ///
    /// Returns the transaction hash of the call
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_match(
        &self,
        party0_old_shares_nullifier: Nullifier,
        party1_old_shares_nullifier: Nullifier,
        party0_private_share_commitment: WalletShareStateCommitment,
        party1_private_share_commitment: WalletShareStateCommitment,
        party0_public_shares: SizedWalletShare,
        party1_public_shares: SizedWalletShare,
        party0_validity_proofs: OrderValidityProofBundle,
        party1_validity_proofs: OrderValidityProofBundle,
        valid_match_proof: ValidMatchMpcBundle,
        valid_settle_proof: ValidSettleBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        // Compute commitments to both party's public shares
        let party0_wallet_share_commitment = compute_wallet_commitment_from_private(
            party0_public_shares.clone(),
            party0_private_share_commitment,
        );
        let party1_wallet_share_commitment = compute_wallet_commitment_from_private(
            party1_public_shares.clone(),
            party1_private_share_commitment,
        );

        // Construct the match payloads for each party
        let party0_match_payload = MatchPayload {
            wallet_blinder_share: party0_public_shares.blinder,
            old_shares_nullifier: party0_old_shares_nullifier,
            wallet_share_commitment: party0_wallet_share_commitment,
            public_wallet_shares: party0_public_shares.to_scalars(),
            valid_commitments_proof: party0_validity_proofs.commitment_proof.proof.clone(),
            valid_commitments_witness_commitments: party0_validity_proofs
                .commitment_proof
                .commitment
                .to_commitments(),
            valid_reblind_proof: party0_validity_proofs.reblind_proof.proof.clone(),
            valid_reblind_witness_commitments: party0_validity_proofs
                .reblind_proof
                .commitment
                .to_commitments(),
        };

        let party1_match_payload = MatchPayload {
            wallet_blinder_share: party1_public_shares.blinder,
            old_shares_nullifier: party1_old_shares_nullifier,
            wallet_share_commitment: party1_wallet_share_commitment,
            public_wallet_shares: party1_public_shares.to_scalars(),
            valid_commitments_proof: party1_validity_proofs.commitment_proof.proof.clone(),
            valid_commitments_witness_commitments: party1_validity_proofs
                .commitment_proof
                .commitment
                .to_commitments(),
            valid_reblind_proof: party1_validity_proofs.reblind_proof.proof.clone(),
            valid_reblind_witness_commitments: party1_validity_proofs
                .reblind_proof
                .commitment
                .to_commitments(),
        };

        // Build the calldata
        let mut calldata = party0_match_payload.to_calldata();
        calldata.extend(party1_match_payload.to_calldata());
        calldata.extend(valid_match_proof.proof.to_calldata());
        calldata.extend(valid_match_proof.commitment.to_commitments().to_calldata());
        calldata.extend(valid_settle_proof.proof.to_calldata());
        calldata.extend(valid_settle_proof.commitment.to_commitments().to_calldata());

        // Call the contract
        self.execute_transaction(Call {
            to: self.contract_address,
            selector: *MATCH_SELECTOR,
            calldata,
        })
        .await
    }
}
