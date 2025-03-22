//! Groups the handshake manager definitions necessary to run the MPC match
//! computation and collaboratively generate a proof of `VALID MATCH MPC`

use std::sync::Arc;

use ark_mpc::{network::QuicTwoPartyNet, MpcFabric, PARTY0, PARTY1};
use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::Order,
    r#match::{MatchResult, OrderSettlementIndices},
    traits::{MpcBaseType, MpcType},
    CollaborativePlonkProof, Fabric, MpcPlonkLinkProof, MpcProofLinkingHint, PlonkProof,
    ProofLinkingHint, SizedWalletShare,
};
use circuits::{
    mpc_circuits::{r#match::compute_match, settle::settle_match},
    multiprover_prove_with_hint, verify_singleprover_proof,
    zk_circuits::{
        proof_linking::{
            link_sized_commitments_match_settle_multiprover,
            validate_sized_commitments_match_settle_link,
        },
        valid_match_settle::{
            SizedAuthenticatedMatchSettleStatement, SizedAuthenticatedMatchSettleWitness,
            SizedValidMatchSettle,
        },
    },
};
use common::types::{
    handshake::HandshakeState,
    proof_bundles::{MatchBundle, OrderValidityProofBundle, SizedValidMatchSettleBundle},
};
use constants::SystemCurveGroup;
use crossbeam::channel::{bounded, Receiver};
use test_helpers::mpc_network::mocks::PartyIDBeaverSource;
use tracing::info;
use util::{matching_engine::compute_max_amount, on_chain::get_protocol_fee};
use uuid::Uuid;

use crate::{error::HandshakeManagerError, manager::HandshakeExecutor};

/// Error message emitted when opening a statement fails
const ERR_OPENING_STATEMENT: &str = "error opening statement";
/// Error message emitted when opening a proof fails
const ERR_OPENING_PROOF: &str = "error opening proof";
/// Error message emitted when opening a match result fails
const ERR_OPENING_MATCH_RES: &str = "error opening match result";

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
    pub(crate) async fn execute_match(
        &self,
        request_id: Uuid,
        party_id: u64,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
        mpc_net: QuicTwoPartyNet<SystemCurveGroup>,
    ) -> Result<(MatchBundle, MatchResult), HandshakeManagerError> {
        // Fetch the handshake state from the state index
        let handshake_state =
            self.handshake_state_index.get_state(&request_id).await.ok_or_else(|| {
                HandshakeManagerError::State("missing handshake state for request".to_string())
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
        info!("Match completed!");
        res
    }

    /// Implementation of the execute_match method that is wrapped in a Tokio
    /// runtime
    async fn execute_match_impl(
        &self,
        party_id: u64,
        handshake_state: HandshakeState,
        party0_validity_bundle: OrderValidityProofBundle,
        party1_validity_bundle: OrderValidityProofBundle,
        mpc_net: QuicTwoPartyNet<SystemCurveGroup>,
        cancel_channel: Receiver<()>,
    ) -> Result<(MatchBundle, MatchResult), HandshakeManagerError> {
        info!("Matching order...");

        // Build a fabric
        // TODO: Replace the dummy beaver source
        let beaver_source = PartyIDBeaverSource::new(party_id);
        let fabric = MpcFabric::new(mpc_net, beaver_source);

        // Lookup the witness bundle used in validity proofs for this order, balance,
        // fee pair Use the linkable commitments from this witness to commit to
        // values in `VALID MATCH MPC`
        let proof_witnesses = self
            .state
            .get_validity_proof_witness(&handshake_state.local_order_id)
            .await?
            .ok_or_else(|| {
                HandshakeManagerError::State(
                    "missing validity proof witness, cannot link proofs".to_string(),
                )
            })?;

        // Run the mpc to get a match result
        let commitment_witness = proof_witnesses.copy_commitment_witness();
        let reblind_witness = proof_witnesses.copy_reblind_witness();
        let party0_commitments_statement = &party0_validity_bundle.commitment_proof.statement;
        let party1_commitments_statement = &party1_validity_bundle.commitment_proof.statement;
        let price_fp = FixedPoint::from_f64_round_down(handshake_state.execution_price.price);
        let (witness, statement) = Self::execute_match_settle_mpc(
            &commitment_witness.order,
            &commitment_witness.balance_send,
            &commitment_witness.balance_receive,
            &commitment_witness.relayer_fee,
            &price_fp,
            &reblind_witness.reblinded_wallet_public_shares,
            party0_commitments_statement.indices,
            party1_commitments_statement.indices,
            &fabric,
        );

        let shared_match_res = witness.match_res.clone();

        // Check if a cancel has come in after the MPC
        if !cancel_channel.is_empty() {
            return Err(HandshakeManagerError::MpcShootdown);
        }

        // Prove `VALID MATCH SETTLE` with the counterparty
        let (match_proof, link_proof0, link_proof1) = Self::prove_valid_match_and_link(
            witness,
            &statement,
            &proof_witnesses.commitment_linking_hint,
            &fabric,
        )?;

        // Open and verify the result
        let match_bundle = Self::open_and_verify_match_settle_proofs(
            &statement,
            match_proof,
            &link_proof0,
            &link_proof1,
            &party0_validity_bundle.commitment_proof.proof,
            &party1_validity_bundle.commitment_proof.proof,
        )
        .await?;

        // Open the match result so that it can be recorded for the relayer's
        // metrics
        let match_res = shared_match_res
            .open_and_authenticate()
            .await
            .map_err(|_| HandshakeManagerError::MpcNetwork(ERR_OPENING_MATCH_RES.to_string()))?;

        Ok((match_bundle, match_res))
    }

    /// Execute the match settle MPC over the provisioned fabric
    #[allow(clippy::too_many_arguments)]
    fn execute_match_settle_mpc(
        my_order: &Order,
        my_balance: &Balance,
        my_balance_receive: &Balance,
        my_relayer_fee: &FixedPoint,
        my_price: &FixedPoint,
        my_public_shares: &SizedWalletShare,
        party0_indices: OrderSettlementIndices,
        party1_indices: OrderSettlementIndices,
        fabric: &Fabric,
    ) -> (SizedAuthenticatedMatchSettleWitness, SizedAuthenticatedMatchSettleStatement) {
        let my_amount = compute_max_amount(my_price, my_order, my_balance);

        // Allocate the matching engine inputs in the MPC fabric
        let order0 = my_order.allocate(PARTY0, fabric);
        let balance0 = my_balance.allocate(PARTY0, fabric);
        let balance_receive0 = my_balance_receive.allocate(PARTY0, fabric);
        let relayer_fee0 = my_relayer_fee.allocate(PARTY0, fabric);
        let price0 = my_price.allocate(PARTY0, fabric);
        let amount0 = my_amount.allocate(PARTY0, fabric);
        let party0_public_shares = my_public_shares.allocate(PARTY0, fabric);

        let order1 = my_order.allocate(PARTY1, fabric);
        let balance1 = my_balance.allocate(PARTY1, fabric);
        let balance_receive1 = my_balance_receive.allocate(PARTY1, fabric);
        let relayer_fee1 = my_relayer_fee.allocate(PARTY1, fabric);
        let price1 = my_price.allocate(PARTY1, fabric);
        let amount1 = my_amount.allocate(PARTY1, fabric);
        let party1_public_shares = my_public_shares.allocate(PARTY1, fabric);

        let protocol_fee = get_protocol_fee().allocate(PARTY0, fabric);

        // Match the orders
        //
        // We use the first party's price, the second party's price will be constrained
        // to equal the first party's in the subsequent proof of `VALID MATCH
        // MPC`
        let match_res = compute_match(&order0, &amount0, &amount1, &price0, fabric);

        // Settle the orders into the party's wallets
        let (party0_fees, party1_fees, party0_modified_shares, party1_modified_shares) =
            settle_match(
                &relayer_fee0,
                &relayer_fee1,
                party0_indices,
                party1_indices,
                &party0_public_shares,
                &party1_public_shares,
                &match_res,
                fabric,
            );

        // Build a witness and statement for the collaborative proof
        (
            SizedAuthenticatedMatchSettleWitness {
                order0,
                balance0,
                balance_receive0,
                relayer_fee0,
                party0_fees,
                price0,
                amount0,
                order1,
                balance1,
                balance_receive1,
                relayer_fee1,
                party1_fees,
                price1,
                amount1,
                match_res,
                party0_public_shares,
                party1_public_shares,
            },
            SizedAuthenticatedMatchSettleStatement {
                party0_indices: party0_indices.allocate(PARTY0, fabric),
                party1_indices: party1_indices.allocate(PARTY1, fabric),
                party0_modified_shares,
                party1_modified_shares,
                protocol_fee,
            },
        )
    }

    /// Generates a collaborative proof of the validity of a given match result
    fn prove_valid_match_and_link(
        shared_witness: SizedAuthenticatedMatchSettleWitness,
        shared_statement: &SizedAuthenticatedMatchSettleStatement,
        my_commitments_link_hint: &ProofLinkingHint,
        fabric: &Fabric,
    ) -> Result<
        (CollaborativePlonkProof, MpcPlonkLinkProof, MpcPlonkLinkProof),
        HandshakeManagerError,
    > {
        // Prove the match-settle statement
        let (proof, hint) = multiprover_prove_with_hint::<SizedValidMatchSettle>(
            shared_witness,
            shared_statement.clone(),
            fabric.clone(),
        )
        .map_err(|err| HandshakeManagerError::Multiprover(err.to_string()))?;

        // Link the match-settle proof to the commitments proofs
        let (link_proof0, link_proof1) =
            Self::compute_match_links(my_commitments_link_hint, &hint, fabric)?;

        Ok((proof, link_proof0, link_proof1))
    }

    /// Link a proof of `VALID MATCH SETTLE` with a two proofs of `VALID
    /// COMMITMENTS`
    fn compute_match_links(
        my_commitments_link_hint: &ProofLinkingHint,
        match_settle_link_hint: &MpcProofLinkingHint,
        fabric: &Fabric,
    ) -> Result<(MpcPlonkLinkProof, MpcPlonkLinkProof), HandshakeManagerError> {
        // Share the commitments proof links
        let party0_commitments_hint =
            MpcProofLinkingHint::from_singleprover_hint(my_commitments_link_hint, PARTY0, fabric);
        let party1_commitments_hint =
            MpcProofLinkingHint::from_singleprover_hint(my_commitments_link_hint, PARTY1, fabric);

        // Link each proof
        let link_proof0 = link_sized_commitments_match_settle_multiprover(
            PARTY0,
            &party0_commitments_hint,
            match_settle_link_hint,
            fabric,
        )
        .map_err(|e| HandshakeManagerError::Multiprover(e.to_string()))?;

        let link_proof1 = link_sized_commitments_match_settle_multiprover(
            PARTY1,
            &party1_commitments_hint,
            match_settle_link_hint,
            fabric,
        )
        .map_err(|e| HandshakeManagerError::Multiprover(e.to_string()))?;

        Ok((link_proof0, link_proof1))
    }

    /// Open and verify the match-settle proof and its links to the commitments
    /// proofs
    ///
    /// TODO: Safe opening -- zero the match result if the orders don't cross
    async fn open_and_verify_match_settle_proofs(
        shared_statement: &SizedAuthenticatedMatchSettleStatement,
        shared_proof: CollaborativePlonkProof,
        link_proof0: &MpcPlonkLinkProof,
        link_proof1: &MpcPlonkLinkProof,
        commitments_proof0: &PlonkProof,
        commitments_proof1: &PlonkProof,
    ) -> Result<MatchBundle, HandshakeManagerError> {
        // Open the proofs before awaiting them, letting the fabric schedule all
        // openings in parallel
        let proof = shared_proof.open_authenticated();
        let statement = shared_statement.open_and_authenticate();
        let link_proof0 = link_proof0.open_authenticated();
        let link_proof1 = link_proof1.open_authenticated();

        // Verify the R1CS proof
        let proof = proof
            .await
            .map_err(|_| HandshakeManagerError::MpcNetwork(ERR_OPENING_PROOF.to_string()))?;
        let statement = statement
            .await
            .map_err(|_| HandshakeManagerError::MpcNetwork(ERR_OPENING_STATEMENT.to_string()))?;

        verify_singleprover_proof::<SizedValidMatchSettle>(statement.clone(), &proof)
            .map_err(|err| HandshakeManagerError::VerificationError(err.to_string()))?;

        // Verify the links
        let link_proof0 = link_proof0
            .await
            .map_err(|_| HandshakeManagerError::MpcNetwork(ERR_OPENING_PROOF.to_string()))?;
        validate_sized_commitments_match_settle_link(
            PARTY0,
            &link_proof0,
            commitments_proof0,
            &proof,
        )
        .map_err(|e| HandshakeManagerError::Multiprover(e.to_string()))?;

        let link_proof1 = link_proof1
            .await
            .map_err(|_| HandshakeManagerError::MpcNetwork(ERR_OPENING_PROOF.to_string()))?;
        validate_sized_commitments_match_settle_link(
            PARTY1,
            &link_proof1,
            commitments_proof1,
            &proof,
        )
        .map_err(|e| HandshakeManagerError::Multiprover(e.to_string()))?;

        // Structure the openings into a match bundle
        Ok(MatchBundle {
            match_proof: Arc::new(SizedValidMatchSettleBundle { proof, statement }),
            commitments_link0: link_proof0,
            commitments_link1: link_proof1,
        })
    }
}
