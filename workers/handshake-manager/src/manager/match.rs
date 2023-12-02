//! Groups the handshake manager definitions necessary to run the MPC match
//! computation and collaboratively generate a proof of `VALID MATCH MPC`

use std::cmp;

use ark_mpc::{network::QuicTwoPartyNet, MpcFabric, PARTY0, PARTY1};
use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    r#match::OrderSettlementIndices,
    traits::{MpcBaseType, MpcType},
    Fabric, SizedWalletShare,
};
use circuits::{
    mpc_circuits::{r#match::compute_match, settle::settle_match},
    multiprover_prove, verify_singleprover_proof,
    zk_circuits::valid_match_settle::{
        SizedAuthenticatedMatchSettleStatement, SizedAuthenticatedMatchSettleWitness,
        SizedValidMatchSettle,
    },
};
use common::types::{
    handshake::HandshakeState,
    proof_bundles::{GenericMatchSettleBundle, OrderValidityProofBundle, ValidMatchSettleBundle},
};
use constants::SystemCurveGroup;
use crossbeam::channel::{bounded, Receiver};
use test_helpers::mpc_network::mocks::PartyIDBeaverSource;
use tracing::log;
use uuid::Uuid;

use crate::error::HandshakeManagerError;

use super::HandshakeExecutor;

/// Error message emitted when opening a statement fails
const ERR_OPENING_STATEMENT: &str = "error opening statement";
/// Error message emitted when opening a proof fails
const ERR_OPENING_PROOF: &str = "error opening proof";

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
        },
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
        mpc_net: QuicTwoPartyNet<SystemCurveGroup>,
    ) -> Result<ValidMatchSettleBundle, HandshakeManagerError> {
        // Fetch the handshake state from the state index
        let handshake_state =
            self.handshake_state_index.get_state(&request_id).await.ok_or_else(|| {
                HandshakeManagerError::StateNotFound(
                    "missing handshake state for request".to_string(),
                )
            })?;

        // Build a cancel channel; the coordinator may use this to cancel (shootdown) an
        // in flight MPC
        let (cancel_sender, cancel_receiver) = bounded(1 /* capacity */);
        // Record the match as in progress and tag it with a cancel channel that may be
        // used to abort the MPC
        self.handshake_state_index.in_progress(&request_id, cancel_sender).await;

        // Wrap the current thread's execution in a Tokio blocking thread
        let self_clone = self.clone();
        let res = self_clone
            .execute_match_impl(
                party_id,
                handshake_state,
                party0_validity_proof,
                party1_validity_proof,
                mpc_net,
                cancel_receiver,
            )
            .await;

        // Await MPC completion
        log::info!("Match completed!");
        res
    }

    /// Implementation of the execute_match method that is wrapped in a Tokio
    /// runtime
    async fn execute_match_impl(
        &self,
        party_id: u64,
        handshake_state: HandshakeState,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
        mpc_net: QuicTwoPartyNet<SystemCurveGroup>,
        cancel_channel: Receiver<()>,
    ) -> Result<ValidMatchSettleBundle, HandshakeManagerError> {
        log::info!("Matching order...");

        // Build a fabric
        // TODO: Replace the dummy beaver source
        let beaver_source = PartyIDBeaverSource::new(party_id);
        let fabric = MpcFabric::new(mpc_net, beaver_source);

        // Lookup the witness bundle used in validity proofs for this order, balance,
        // fee pair Use the linkable commitments from this witness to commit to
        // values in `VALID MATCH MPC`
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
        let reblind_witness = proof_witnesses.copy_reblind_witness();
        let party0_commitments_statement = &party0_validity_proof.commitment_proof.statement;
        let party1_commitments_statement = &party1_validity_proof.commitment_proof.statement;
        let (witness, statement) = Self::execute_match_settle_mpc(
            &commitment_witness.order,
            &commitment_witness.balance_send,
            &handshake_state.execution_price,
            &reblind_witness.reblinded_wallet_public_shares,
            party0_commitments_statement.indices,
            party1_commitments_statement.indices,
            &fabric,
        );

        // Check if a cancel has come in after the MPC
        if !cancel_channel.is_empty() {
            return Err(HandshakeManagerError::MpcShootdown);
        }

        // Prove `VALID MATCH SETTLE` with the counterparty
        Self::prove_valid_match(witness, statement, &fabric).await
    }

    /// Execute the match settle MPC over the provisioned fabric
    fn execute_match_settle_mpc(
        my_order: &Order,
        my_balance: &Balance,
        my_price: &FixedPoint,
        my_public_shares: &SizedWalletShare,
        party0_indices: OrderSettlementIndices,
        party1_indices: OrderSettlementIndices,
        fabric: &Fabric,
    ) -> (SizedAuthenticatedMatchSettleWitness, SizedAuthenticatedMatchSettleStatement) {
        let my_amount = compute_max_amount(my_price, my_order, my_balance);

        // Allocate the matching engine inputs in the MPC fabric
        let o1 = my_order.allocate(PARTY0, fabric);
        let b1 = my_balance.allocate(PARTY0, fabric);
        let price1 = my_price.allocate(PARTY0, fabric);
        let amount1 = my_amount.allocate(PARTY0, fabric);
        let party0_public_shares = my_public_shares.allocate(PARTY0, fabric);

        let o2 = my_order.allocate(PARTY1, fabric);
        let b2 = my_balance.allocate(PARTY1, fabric);
        let price2 = my_price.allocate(PARTY1, fabric);
        let amount2 = my_amount.allocate(PARTY1, fabric);
        let party1_public_shares = my_public_shares.allocate(PARTY1, fabric);

        // Match the orders
        //
        // We use the first party's price, the second party's price will be constrained
        // to equal the first party's in the subsequent proof of `VALID MATCH
        // MPC`
        let match_res = compute_match(&o1, &amount1, &amount2, &price1, fabric);

        // Settle the orders into the party's wallets
        let (party0_modified_shares, party1_modified_shares) = settle_match(
            party0_indices,
            party1_indices,
            &party0_public_shares,
            &party1_public_shares,
            &match_res,
        );

        // Build a witness and statement for the collaborative proof
        (
            SizedAuthenticatedMatchSettleWitness {
                order1: o1,
                balance1: b1,
                amount1,
                price1,
                order2: o2,
                balance2: b2,
                amount2,
                price2,
                match_res,
                party0_public_shares,
                party1_public_shares,
            },
            SizedAuthenticatedMatchSettleStatement {
                party0_indices: party0_indices.allocate(PARTY0, fabric),
                party1_indices: party1_indices.allocate(PARTY1, fabric),
                party0_modified_shares,
                party1_modified_shares,
            },
        )
    }

    /// Generates a collaborative proof of the validity of a given match result
    async fn prove_valid_match(
        shared_witness: SizedAuthenticatedMatchSettleWitness,
        shared_statement: SizedAuthenticatedMatchSettleStatement,
        fabric: &Fabric,
    ) -> Result<ValidMatchSettleBundle, HandshakeManagerError> {
        // Prove the statement
        let shared_proof = multiprover_prove::<SizedValidMatchSettle>(
            shared_witness,
            shared_statement.clone(),
            fabric.clone(),
        )
        .map_err(|err| HandshakeManagerError::Multiprover(err.to_string()))?;

        // Open the proof and verify it
        let proof = shared_proof
            .open_authenticated()
            .await
            .map_err(|_| HandshakeManagerError::MpcNetwork(ERR_OPENING_PROOF.to_string()))?;
        let statement = shared_statement
            .open_and_authenticate()
            .await
            .map_err(|_| HandshakeManagerError::MpcNetwork(ERR_OPENING_STATEMENT.to_string()))?;

        verify_singleprover_proof::<SizedValidMatchSettle>(statement.clone(), &proof)
            .map_err(|err| HandshakeManagerError::VerificationError(err.to_string()))?;

        Ok(Box::new(GenericMatchSettleBundle { statement, proof }))
    }
}
