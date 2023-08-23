//! Groups the handshake manager definitions necessary to run the MPC match computation
//! and collaboratively generate a proof of `VALID MATCH MPC`

use std::cmp;

use circuit_types::{
    balance::{Balance, LinkableBalance},
    fixed_point::FixedPoint,
    order::{LinkableOrder, Order, OrderSide},
    r#match::AuthenticatedLinkableMatchResult,
    traits::{BaseType, LinkableType, MpcBaseType, MpcType, MultiproverCircuitCommitmentType},
};
use circuits::{
    mpc_circuits::r#match::compute_match,
    multiprover_prove, verify_collaborative_proof,
    zk_circuits::{
        commitment_links::{verify_augmented_shares_commitments, verify_commitment_match_link},
        valid_match_mpc::{
            AuthenticatedValidMatchMpcWitness, ValidMatchMpcCircuit, ValidMatchMpcWitnessCommitment,
        },
    },
};
use common::types::{
    handshake::{HandshakeResult, HandshakeState},
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle, ValidMatchMpcBundle},
};
use crossbeam::channel::{bounded, Receiver};
use mpc_bulletproof::r1cs::R1CSProof;
use mpc_stark::{network::QuicTwoPartyNet, MpcFabric, PARTY0, PARTY1};
use test_helpers::mpc_network::mocks::PartyIDBeaverSource;
use tracing::log;
use uuid::Uuid;

use crate::error::HandshakeManagerError;

use super::HandshakeExecutor;

/// Error message emitted when the opened VALID MATCH proof does not properly link to
/// both parties' proofs of VALID COMMITMENTS
const ERR_INVALID_PROOF_LINK: &str =
    "invalid commitment link between VALID COMMITMENTS and VALID MATCH MPC";

// -----------
// | Helpers |
// -----------

/// Compute the maximum matchable amount for an order and balance
fn compute_max_amount(price: &FixedPoint, order: &Order, balance: &Balance) -> u64 {
    match order.side {
        // Buy the base, the max amount is possibly limited by the quote
        // balance
        OrderSide::Buy => {
            let price_f64 = price.to_f64();
            let balance_limit = (balance.amount as f64 / price_f64).floor() as u64;
            cmp::min(order.amount, balance_limit)
        }
        // Buy the quote, sell the base, the maximum amount is directly limited
        // by the balance
        OrderSide::Sell => cmp::min(order.amount, balance.amount),
    }
}

// ----------------------
// | Handshake Executor |
// ----------------------

/// Match-centric implementations for the handshake manager
impl HandshakeExecutor {
    /// Execute the MPC and collaborative proof for a match computation
    ///
    /// Spawns the match computation in a separate thread wrapped by a custom
    /// Tokio runtime. The QUIC implementation in quinn is async and expects
    /// to be run inside of a Tokio runtime
    pub(super) async fn execute_match(
        &self,
        request_id: Uuid,
        party_id: u64,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
        mpc_net: QuicTwoPartyNet,
    ) -> Result<Box<HandshakeResult>, HandshakeManagerError> {
        // Fetch the handshake state from the state index
        let handshake_state = self
            .handshake_state_index
            .get_state(&request_id)
            .await
            .ok_or_else(|| {
                HandshakeManagerError::StateNotFound(
                    "missing handshake state for request".to_string(),
                )
            })?;

        // Build a cancel channel; the coordinator may use this to cancel (shootdown) an in flight MPC
        let (cancel_sender, cancel_receiver) = bounded(1 /* capacity */);
        // Record the match as in progress and tag it with a cancel channel that may be used to
        // abort the MPC
        self.handshake_state_index
            .in_progress(&request_id, cancel_sender)
            .await;

        // Wrap the current thread's execution in a Tokio blocking thread
        let self_clone = self.clone();
        let res = self_clone
            .execute_match_impl(
                party_id,
                handshake_state.to_owned(),
                party0_validity_proof,
                party1_validity_proof,
                mpc_net,
                cancel_receiver,
            )
            .await?;

        // Await MPC completion
        log::info!("Finished match!");

        Ok(res)
    }

    /// Implementation of the execute_match method that is wrapped in a Tokio runtime
    async fn execute_match_impl(
        &self,
        party_id: u64,
        handshake_state: HandshakeState,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
        mpc_net: QuicTwoPartyNet,
        cancel_channel: Receiver<()>,
    ) -> Result<Box<HandshakeResult>, HandshakeManagerError> {
        log::info!("Matching order...");

        // Build a fabric
        // TODO: Replace the dummy beaver source
        let beaver_source = PartyIDBeaverSource::new(party_id);
        let fabric = MpcFabric::new(mpc_net, beaver_source);

        // Lookup the witness bundle used in validity proofs for this order, balance, fee pair
        // Use the linkable commitments from this witness to commit to values in `VALID MATCH MPC`
        let proof_witnesses = self
            .global_state
            .read_order_book()
            .await
            .get_validity_proof_witnesses(&handshake_state.local_order_id)
            .await
            .ok_or_else(|| {
                HandshakeManagerError::StateNotFound(
                    "missing validity proof witness, cannot link proofs".to_string(),
                )
            })?;

        // Run the mpc to get a match result
        let commitment_witness = proof_witnesses.copy_commitment_witness();
        let witness = Self::execute_match_mpc(
            &commitment_witness.order,
            &commitment_witness.balance_send,
            &handshake_state.execution_price,
            &fabric,
        );

        // Check if a cancel has come in after the MPC
        if !cancel_channel.is_empty() {
            return Err(HandshakeManagerError::MpcShootdown);
        }

        // Prove `VALID MATCH MPC` with the counterparty
        let (commitment, proof) = Self::prove_valid_match(&witness, &fabric).await?;

        // Verify the commitment links between the match proof and the two parties'
        // proofs of VALID COMMITMENTS
        if !verify_commitment_match_link(
            &party0_validity_proof.commitment_proof.commitment,
            &party1_validity_proof.commitment_proof.commitment,
            &commitment,
        ) {
            return Err(HandshakeManagerError::VerificationError(
                ERR_INVALID_PROOF_LINK.to_string(),
            ));
        };

        // Check if a cancel has come in after the collaborative proof
        if !cancel_channel.is_empty() {
            return Err(HandshakeManagerError::MpcShootdown);
        }

        self.build_handshake_result(
            witness.match_res,
            commitment,
            proof,
            proof_witnesses,
            party0_validity_proof,
            party1_validity_proof,
            handshake_state,
            &fabric,
            cancel_channel,
        )
        .await
    }

    /// Execute the match MPC over the provisioned QUIC stream
    fn execute_match_mpc(
        my_order: &LinkableOrder,
        my_balance: &LinkableBalance,
        my_price: &FixedPoint,
        fabric: &MpcFabric,
    ) -> AuthenticatedValidMatchMpcWitness {
        // Allocate the orders in the MPC fabric
        let o1 = my_order.allocate(PARTY0, fabric);
        let b1 = my_balance.allocate(PARTY0, fabric);
        let price1 = my_price.allocate(PARTY0, fabric);

        let o2 = my_order.allocate(PARTY1, fabric);
        let b2 = my_balance.allocate(PARTY1, fabric);
        let price2 = my_price.allocate(PARTY1, fabric);

        // Use the first party's price, the second party's price will be constrained to equal the
        // first party's in the subsequent proof of `VALID MATCH MPC`
        let price = my_price.allocate(PARTY0, fabric);

        let my_amount = compute_max_amount(
            my_price,
            &my_order.to_base_type(),
            &my_balance.to_base_type(),
        );
        let amount1 = my_amount.allocate(PARTY0, fabric);
        let amount2 = my_amount.allocate(PARTY1, fabric);

        // Run the circuit
        let match_res = compute_match(&o1, &o2, &amount1, &amount2, &price, fabric);

        // Build a witness for the collaborative proof
        AuthenticatedValidMatchMpcWitness {
            order1: o1,
            balance1: b1,
            amount1,
            price1,
            order2: o2,
            balance2: b2,
            amount2,
            price2,
            match_res: match_res.link_commitments(fabric),
        }
    }

    /// Generates a collaborative proof of the validity of a given match result
    ///
    /// The implementation *does not* open the match result. This leaks information and should
    /// be done last, after all other openings, validity checks, etc are performed
    async fn prove_valid_match(
        witness: &AuthenticatedValidMatchMpcWitness,
        fabric: &MpcFabric,
    ) -> Result<(ValidMatchMpcWitnessCommitment, R1CSProof), HandshakeManagerError> {
        // Prove the statement
        let (witness_commitment, proof) = multiprover_prove::<ValidMatchMpcCircuit>(
            witness.clone(),
            (), /* statement */
            fabric.clone(),
        )
        .map_err(|err| HandshakeManagerError::Multiprover(err.to_string()))?;

        // Open the proof and verify it
        let opened_commit = witness_commitment
            .open_and_authenticate()
            .await
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let opened_proof = proof
            .open()
            .await
            .map_err(|_| HandshakeManagerError::MpcNetwork("error opening proof".to_string()))?;

        verify_collaborative_proof::<ValidMatchMpcCircuit>(
            (), /* statement */
            opened_commit.clone(),
            opened_proof.clone(),
        )
        .map_err(|err| HandshakeManagerError::VerificationError(err.to_string()))?;

        Ok((opened_commit, opened_proof))
    }

    /// Build the handshake result from a match and proof
    #[allow(clippy::too_many_arguments)]
    async fn build_handshake_result(
        &self,
        shared_match_res: AuthenticatedLinkableMatchResult,
        commitment: ValidMatchMpcWitnessCommitment,
        proof: R1CSProof,
        validity_proof_witness: OrderValidityWitnessBundle,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
        handshake_state: HandshakeState,
        fabric: &MpcFabric,
        cancel_channel: Receiver<()>,
    ) -> Result<Box<HandshakeResult>, HandshakeManagerError> {
        // Exchange fees and public secret shares before opening the match result
        let party0_fee = validity_proof_witness
            .commitment_witness
            .fee
            .share_public(PARTY0, fabric.clone());
        let party1_fee = validity_proof_witness
            .commitment_witness
            .fee
            .share_public(PARTY1, fabric.clone());

        let party0_public_shares = validity_proof_witness
            .commitment_witness
            .augmented_public_shares
            .share_public(PARTY0, fabric.clone());
        let party1_public_shares = validity_proof_witness
            .commitment_witness
            .augmented_public_shares
            .share_public(PARTY1, fabric.clone());

        // Verify that the opened augmented shares are the same used in the validity proofs
        let party0_public_shares = party0_public_shares.await;
        let party1_public_shares = party1_public_shares.await;
        if !verify_augmented_shares_commitments(
            &party0_public_shares,
            &party1_public_shares,
            &party0_validity_proof.commitment_proof.commitment,
            &party1_validity_proof.commitment_proof.commitment,
        ) {
            return Err(HandshakeManagerError::VerificationError(
                ERR_INVALID_PROOF_LINK.to_string(),
            ));
        }

        // Finally, before revealing the match, we make a check that the MPC has
        // not been terminated by the coordinator
        if !cancel_channel.is_empty() {
            return Err(HandshakeManagerError::MpcShootdown);
        }

        // Open the match result and build the handshake result
        let match_res_open = shared_match_res
            .open_and_authenticate()
            .await
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        Ok(Box::new(HandshakeResult {
            match_: match_res_open,
            match_proof: ValidMatchMpcBundle {
                commitment,
                statement: (),
                proof,
            },
            party0_share_nullifier: handshake_state.local_share_nullifier,
            party1_share_nullifier: handshake_state.peer_share_nullifier,
            party0_reblinded_shares: party0_public_shares,
            party1_reblinded_shares: party1_public_shares,
            party0_fee: party0_fee.await,
            party1_fee: party1_fee.await,
        }))
    }
}
