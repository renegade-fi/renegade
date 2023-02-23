//! Groups the handshake manager definitions necessary to run the MPC match computation
//! and collaboratively generate a proof of `VALID MATCH MPC`

use std::{cell::RefCell, rc::Rc, thread};

use circuits::{
    mpc::SharedFabric,
    mpc_circuits::r#match::compute_match,
    multiprover_prove,
    native_helpers::compute_poseidon_hash,
    types::{
        balance::LinkableBalanceCommitment,
        fee::LinkableFeeCommitment,
        order::{LinkableOrderCommitment, Order},
        r#match::{
            AuthenticatedLinkableMatchResultCommitment, AuthenticatedMatchResult,
            LinkableMatchResultCommitment,
        },
    },
    verify_collaborative_proof,
    zk_circuits::valid_match_mpc::{
        ValidMatchMpcCircuit, ValidMatchMpcStatement, ValidMatchMpcWitness,
    },
    Allocate, Open, SharePublic,
};
use crypto::fields::biguint_to_scalar;
use curve25519_dalek::scalar::Scalar;
use futures::executor::block_on;
use integration_helpers::mpc_network::mocks::PartyIDBeaverSource;
use mpc_bulletproof::r1cs::R1CSProof;
use mpc_ristretto::{
    beaver::SharedValueSource,
    fabric::AuthenticatedMpcFabric,
    network::{MpcNetwork, QuicTwoPartyNet},
};
use tokio::runtime::Builder as TokioBuilder;
use tracing::log;

use crate::types::SizedValidCommitmentsWitness;

use super::{error::HandshakeManagerError, manager::HandshakeExecutor, state::HandshakeState};

/// The type returned by the match process, including the result, the validity proof, and
/// all witness/statement variables that must be revealed to complete the match
#[derive(Clone, Debug)]
pub struct HandshakeResult {
    /// The plaintext, opened result of the match
    pub match_: LinkableMatchResultCommitment,
    /// The collaboratively proved proof of `VALID MATCH MPC`
    pub proof: R1CSProof,
    /// The first party's fee, opened to create fee notes
    pub party0_fee: LinkableFeeCommitment,
    /// The second party's fee, opened to create fee notes
    pub party1_fee: LinkableFeeCommitment,
    /// The Poseidon hash of the first party's wallet randomness
    pub party0_randomness_hash: Scalar,
    /// The Poseidon hash of the second party's wallet randomness
    pub party1_randomness_hash: Scalar,
    /// The public settle key of the first party
    pub pk_settle0: Scalar,
    /// The public settle key of the second party
    pub pk_settle1: Scalar,
    /// The public settle key of the cluster managing the first party's order
    pub pk_settle_cluster0: Scalar,
    /// The public settle key fo the cluster managing the second party's order
    pub pk_settle_cluster1: Scalar,
}

/// Match-centric implementations for the handshake manager
impl HandshakeExecutor {
    /// Execute the MPC and collaborative proof for a match computation
    ///
    /// Spawns the match computation in a separate thread wrapped by a custom
    /// Tokio runtime. The QUIC implementation in quinn is async and expects
    /// to be run inside of a Tokio runtime
    pub(super) fn execute_match(
        &self,
        party_id: u64,
        handshake_state: HandshakeState,
        mpc_net: QuicTwoPartyNet,
    ) -> Result<HandshakeResult, HandshakeManagerError> {
        // Build a tokio runtime in the current thread for the MPC to run inside of
        let tid = thread::current().id();
        let tokio_runtime = TokioBuilder::new_multi_thread()
            .thread_name(format!("handshake-mpc-{:?}", tid))
            .enable_io()
            .enable_time()
            .build()
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        // Wrap the current thread's execution in a Tokio blocking thread
        let self_clone = self.clone();
        let join_handle = tokio_runtime.spawn_blocking(move || {
            self_clone.execute_match_impl(party_id, handshake_state.to_owned(), mpc_net)
        });

        let res = block_on(join_handle).unwrap()?;
        log::info!("Finished match!");

        Ok(res)
    }

    /// Implementation of the execute_match method that is wrapped in a Tokio runtime
    fn execute_match_impl(
        &self,
        party_id: u64,
        handshake_state: HandshakeState,
        mut mpc_net: QuicTwoPartyNet,
    ) -> Result<HandshakeResult, HandshakeManagerError> {
        log::info!("Matching order...");
        // Connect the network
        block_on(mpc_net.connect())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        // Build a fabric
        // TODO: Replace the dummy beaver source
        let beaver_source = PartyIDBeaverSource::new(party_id);
        let fabric = AuthenticatedMpcFabric::new_with_network(
            party_id,
            Rc::new(RefCell::new(mpc_net)),
            Rc::new(RefCell::new(beaver_source)),
        );

        let shared_fabric = SharedFabric::new(fabric);

        // Lookup the witness used to prove valid commitments for this order, balance, fee pair
        // Use the linkable commitments from this witness to commit to values in `VALID MATCH MPC`
        let commitments_witness = self
            .global_state
            .read_order_book()
            .get_validity_proof_witness(&handshake_state.local_order_id)
            .ok_or_else(|| {
                HandshakeManagerError::StateNotFound(
                    "missing validity proof witness, cannot link proofs".to_string(),
                )
            })?;

        // Run the mpc to get a match result
        let match_res = Self::execute_match_mpc(
            &commitments_witness.order.clone().into(),
            shared_fabric.clone(),
        )?;

        // The statement parameterization of the VALID MATCH MPC circuit is empty
        let statement = ValidMatchMpcStatement {};
        let (witness, proof) = Self::prove_valid_match(
            commitments_witness.order.clone(),
            commitments_witness.balance.clone(),
            statement,
            match_res,
            shared_fabric.clone(),
        )?;

        self.build_handshake_result(
            witness.match_res,
            proof,
            commitments_witness,
            handshake_state,
            shared_fabric,
        )
    }

    /// Execute the match MPC over the provisioned QUIC stream
    fn execute_match_mpc<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
        local_order: &Order,
        fabric: SharedFabric<N, S>,
    ) -> Result<AuthenticatedMatchResult<N, S>, HandshakeManagerError> {
        // Allocate the orders in the MPC fabric
        let shared_order1 = local_order
            .allocate(0 /* owning_party */, fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let shared_order2 = local_order
            .allocate(1 /* owning_party */, fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        // Run the circuit
        compute_match(&shared_order1, &shared_order2, fabric)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))
    }

    /// Generates a collaborative proof of the validity of a given match result
    #[allow(unused)]
    #[allow(unused_variables)]
    fn prove_valid_match<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
        my_order: LinkableOrderCommitment,
        my_balance: LinkableBalanceCommitment,
        statement: ValidMatchMpcStatement,
        match_res: AuthenticatedMatchResult<N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<(ValidMatchMpcWitness<N, S>, R1CSProof), HandshakeManagerError> {
        // Build a witness to the VALID MATCH MPC statement
        // TODO: Use proof-linked witness vars
        let witness = ValidMatchMpcWitness {
            my_order,
            my_balance,
            match_res: match_res.into(),
        };

        // Prove the statement
        let (witness_commitment, proof) =
            multiprover_prove::<'_, N, S, ValidMatchMpcCircuit<'_, N, S>>(
                witness.clone(),
                statement.clone(),
                fabric.clone(),
            )
            .map_err(|err| HandshakeManagerError::Multiprover(err.to_string()))?;

        // Open the proof and verify it
        let opened_commit = witness_commitment
            .open_and_authenticate(fabric)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let opened_proof = proof
            .open()
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        verify_collaborative_proof::<'_, N, S, ValidMatchMpcCircuit<'_, N, S>>(
            statement,
            opened_commit,
            opened_proof.clone(),
        )
        .map_err(|err| HandshakeManagerError::VerificationError(err.to_string()))?;

        Ok((witness, opened_proof))
    }

    /// Build the handshake result from a match and proof
    fn build_handshake_result<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
        &self,
        shared_match_res: AuthenticatedLinkableMatchResultCommitment<N, S>,
        proof: R1CSProof,
        validity_proof_witness: SizedValidCommitmentsWitness,
        handshake_state: HandshakeState,
        fabric: SharedFabric<N, S>,
    ) -> Result<HandshakeResult, HandshakeManagerError> {
        // Exchange fees, randomness, and keys before opening the match result
        let party0_fee = validity_proof_witness
            .fee
            .share_public(0 /* owning_party */, fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let party1_fee = validity_proof_witness
            .fee
            .share_public(1 /* owning_party */, fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        // Lookup the wallet that the matched order belongs to in the global state
        let wallet = {
            let locked_wallet_index = self.global_state.read_wallet_index();
            let wallet_id = locked_wallet_index
                .get_wallet_for_order(&handshake_state.local_order_id)
                .ok_or_else(|| {
                    HandshakeManagerError::StateNotFound(
                        "couldn't find wallet for order".to_string(),
                    )
                })?;
            locked_wallet_index
                .read_wallet(&wallet_id)
                .map(|wallet| wallet.clone())
                .ok_or_else(|| {
                    HandshakeManagerError::StateNotFound("no wallet found for ID".to_string())
                })?
        }; // locked_wallet_index released

        // Share the wallet randomness and keys with the counterparty
        let my_randomness = biguint_to_scalar(&wallet.randomness);
        let party0_randomness = fabric
            .borrow_fabric()
            .share_plaintext_scalar(0 /* owning_party */, my_randomness)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let party1_randomness = fabric
            .borrow_fabric()
            .share_plaintext_scalar(1 /* owning_party */, my_randomness)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        let party0_randomness_hash = compute_poseidon_hash(&[party0_randomness]);
        let party1_randomness_hash = compute_poseidon_hash(&[party1_randomness]);

        // Share the wallet public settle keys with the counterparty
        let my_key = wallet.public_keys.pk_settle;
        let party0_key = fabric
            .borrow_fabric()
            .share_plaintext_scalar(0 /* owning_party */, my_key)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let party1_key = fabric
            .borrow_fabric()
            .share_plaintext_scalar(1 /* owning_party */, my_key)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        // Open the match result and build the handshake result
        let match_res_open = shared_match_res
            .open_and_authenticate(fabric)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        Ok(HandshakeResult {
            match_: match_res_open,
            proof,
            party0_fee,
            party1_fee,
            party0_randomness_hash,
            party1_randomness_hash,
            pk_settle0: party0_key,
            pk_settle1: party1_key,
            // Dummy values for now
            pk_settle_cluster0: Scalar::zero(),
            pk_settle_cluster1: Scalar::zero(),
        })
    }
}
