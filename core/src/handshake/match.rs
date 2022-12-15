//! Groups the handshake manager definitions necessary to run the MPC match computation
//! and collaboratively generate a proof of `VALID MATCH MPC`

use std::{cell::RefCell, rc::Rc};

use circuits::{
    mpc::SharedFabric,
    mpc_circuits::r#match::compute_match,
    types::{balance::Balance, fee::Fee, order::Order, r#match::MatchResult},
    Allocate, Open,
};
use futures::executor::block_on;
use integration_helpers::mpc_network::mocks::PartyIDBeaverSource;
use mpc_ristretto::{fabric::AuthenticatedMpcFabric, network::QuicTwoPartyNet};

use super::{error::HandshakeManagerError, manager::HandshakeManager};

/// Match-centric implementations for the handshake manager
impl HandshakeManager {
    /// Execute the match MPC over the provisioned QUIC stream
    pub(super) fn execute_match_mpc(
        party_id: u64,
        local_order: Order,
        local_balance: Balance,
        local_fee: Fee,
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

        let shared_order1 = local_order
            .allocate(0 /* owning_party */, shared_fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;
        let shared_order2 = local_order
            .allocate(1 /* owning_party */, shared_fabric.clone())
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        let match_res = compute_match(&shared_order1, &shared_order2, shared_fabric)
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?
            .open_and_authenticate()
            .map_err(|err| HandshakeManagerError::MpcNetwork(err.to_string()))?;

        println!("Got MPC res: {:?}", match_res);
        Self::prove_valid_match(local_order, local_balance, local_fee, match_res)
    }

    /// Generates a collaborative proof of the validity of a given match result
    #[allow(unused_variables)]
    fn prove_valid_match(
        order: Order,
        balance: Balance,
        fee: Fee,
        match_res: MatchResult,
    ) -> Result<(), HandshakeManagerError> {
        unimplemented!("")
    }
}
