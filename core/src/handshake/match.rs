//! Groups the handshake manager definitions necessary to run the MPC match computation
//! and collaboratively generate a proof of `VALID MATCH MPC`

use std::{cell::RefCell, rc::Rc, thread};

use circuits::{
    mpc::SharedFabric,
    mpc_circuits::r#match::compute_match,
    multiprover_prove,
    types::{balance::Balance, fee::Fee, order::Order, r#match::AuthenticatedMatchResult},
    verify_collaborative_proof,
    zk_circuits::valid_match_mpc::{
        ValidMatchMpcCircuit, ValidMatchMpcStatement, ValidMatchMpcWitness,
    },
    Allocate, Open,
};
use curve25519_dalek::scalar::Scalar;
use futures::executor::block_on;
use integration_helpers::mpc_network::mocks::PartyIDBeaverSource;
use mpc_ristretto::{
    beaver::SharedValueSource,
    fabric::AuthenticatedMpcFabric,
    network::{MpcNetwork, QuicTwoPartyNet},
};
use tokio::runtime::Builder as TokioBuilder;

use super::{error::HandshakeManagerError, manager::HandshakeManager, state::HandshakeState};

/// The party_id of the leader (aka dialer/king) in the MPC computation
pub(crate) const KING: u64 = 0;

/// Match-centric implementations for the handshake manager
impl HandshakeManager {
    /// Execute the MPC and collaborative proof for a match computation
    ///
    /// Spawns the match computation in a separate thread wrapped by a custom
    /// Tokio runtime. The QUIC implementation in quinn is async and expects
    /// to be run inside of a Tokio runtime
    pub(super) fn execute_match(
        party_id: u64,
        handshake_state: HandshakeState,
        mpc_net: QuicTwoPartyNet,
    ) -> Result<(), HandshakeManagerError> {
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

        block_on(join_handle).unwrap()?;
        println!("Finished match!");

        Ok(())
    }

    /// Implementation of the execute_match method that is wrapped in a Tokio runtime
    fn execute_match_impl(
        party_id: u64,
        handshake_state: HandshakeState,
        mut mpc_net: QuicTwoPartyNet,
    ) -> Result<(), HandshakeManagerError> {
        println!("Matching order...\n");
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
        let match_res_open = match_res
            .clone()
            .open_and_authenticate()
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        println!("Got MPC res: {:?}", match_res_open);

        let statement = handshake_state.build_valid_match_statement(party_id);
        Self::prove_valid_match(
            handshake_state.order,
            handshake_state.balance,
            handshake_state.fee,
            statement,
            match_res,
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
        order: Order,
        balance: Balance,
        fee: Fee,
        statement: ValidMatchMpcStatement,
        match_res: AuthenticatedMatchResult<N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<(), HandshakeManagerError> {
        println!("proving...");

        // Build a witness to the VALID MATCH MPC statement
        let witness = ValidMatchMpcWitness {
            my_order: order,
            my_balance: balance,
            my_fee: fee,
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
            opened_proof,
        )
        .map_err(|err| HandshakeManagerError::VerificationError(err.to_string()))
    }
}
