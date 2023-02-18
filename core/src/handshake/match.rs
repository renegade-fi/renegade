//! Groups the handshake manager definitions necessary to run the MPC match computation
//! and collaboratively generate a proof of `VALID MATCH MPC`

use std::{cell::RefCell, rc::Rc, thread};

use circuits::{
    mpc::SharedFabric,
    mpc_circuits::r#match::compute_match,
    multiprover_prove,
    types::{
        balance::Balance,
        fee::Fee,
        order::Order,
        r#match::{AuthenticatedMatchResult, MatchResult},
    },
    verify_collaborative_proof,
    zk_circuits::valid_match_mpc::{
        ValidMatchMpcCircuit, ValidMatchMpcStatement, ValidMatchMpcWitness,
    },
    Allocate, Open, SharePublic,
};
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

use super::{error::HandshakeManagerError, manager::HandshakeExecutor, state::HandshakeState};

/// The type returned by the match process, including the result, the validity proof, and
/// all witness/statement variables that must be revealed to complete the match
#[derive(Clone, Debug)]
pub struct HandshakeResult {
    /// The plaintext, opened result of the match
    pub match_: MatchResult,
    /// The collaboratively proved proof of `VALID MATCH MPC`
    pub proof: R1CSProof,
    /// The first party's fee, opened to create fee notes
    pub party0_fee: Fee,
    /// The second party's fee, opened to create fee notes
    pub party1_fee: Fee,
}

/// Match-centric implementations for the handshake manager
impl HandshakeExecutor {
    /// Execute the MPC and collaborative proof for a match computation
    ///
    /// Spawns the match computation in a separate thread wrapped by a custom
    /// Tokio runtime. The QUIC implementation in quinn is async and expects
    /// to be run inside of a Tokio runtime
    pub(super) fn execute_match(
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
        let join_handle = tokio_runtime.spawn_blocking(move || {
            Self::execute_match_impl(party_id, handshake_state.to_owned(), mpc_net)
        });

        let res = block_on(join_handle).unwrap()?;
        log::info!("Finished match!");

        Ok(res)
    }

    /// Implementation of the execute_match method that is wrapped in a Tokio runtime
    fn execute_match_impl(
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

        // Run the mpc to get a match result
        let match_res = Self::execute_match_mpc(&handshake_state.order, shared_fabric.clone())?;

        // The statement parameterization of the VALID MATCH MPC circuit is empty
        let statement = ValidMatchMpcStatement {};
        let proof = Self::prove_valid_match(
            handshake_state.order,
            handshake_state.balance,
            statement,
            match_res.clone(),
            shared_fabric.clone(),
        )?;

        // Open the fees for each party so that they may be used to create fee notes
        let party0_fee = handshake_state
            .fee
            .share_public(0 /* owning_party */, shared_fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let party1_fee = handshake_state
            .fee
            .share_public(1 /* owning_party */, shared_fabric)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        // Open the match result
        let match_open = match_res
            .open_and_authenticate()
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        Ok(HandshakeResult {
            match_: match_open,
            proof,
            party0_fee,
            party1_fee,
        })
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
        order: Order,
        balance: Balance,
        statement: ValidMatchMpcStatement,
        match_res: AuthenticatedMatchResult<N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<R1CSProof, HandshakeManagerError> {
        // Build a witness to the VALID MATCH MPC statement
        let witness = ValidMatchMpcWitness {
            my_order: order,
            my_balance: balance,
            match_res,
        };

        // Prove the statement
        let (witness_commitment, proof) = multiprover_prove::<
            '_,
            N,
            S,
            ValidMatchMpcCircuit<'_, N, S>,
        >(witness, statement.clone(), fabric)
        .map_err(|err| HandshakeManagerError::Multiprover(err.to_string()))?;

        // Open the proof and verify it
        let opened_commit = witness_commitment
            .open_and_authenticate()
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

        Ok(opened_proof)
    }
}
