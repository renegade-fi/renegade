//! The state applicator applies updates that have been committed to by the raft
//! group to the global state, persisting them to local storage

use std::sync::Arc;

use common::types::gossip::ClusterId;
use external_api::bus_message::SystemBusMessage;
use state_proto::StateTransition;
use system_bus::SystemBus;

use crate::storage::db::DB;

use self::error::StateApplicatorError;

pub mod error;
pub mod order_book;
pub mod peer_index;
pub mod wallet_index;

// -------------
// | Constants |
// -------------

/// A type alias for the result type given by the applicator
pub(crate) type Result<T> = std::result::Result<T, StateApplicatorError>;

/// The name of the db table that stores peer information
pub(crate) const PEER_INFO_TABLE: &str = "peer-info";
/// The name of the db table that stores cluster membership information
pub(crate) const CLUSTER_MEMBERSHIP_TABLE: &str = "cluster-membership";

/// The name of the db table that stores order and cluster priorities
pub(crate) const PRIORITIES_TABLE: &str = "priorities";
/// The name of the table that stores orders by their ID
pub(crate) const ORDERS_TABLE: &str = "orders";

/// The name of the db table that maps order to their encapsulating wallet
pub(crate) const ORDER_TO_WALLET_TABLE: &str = "order-to-wallet";
/// The name of the db table that stores wallet information
pub(crate) const WALLETS_TABLE: &str = "wallet-info";

/// The config for the state applicator
#[derive(Clone)]
pub struct StateApplicatorConfig {
    /// Whether or not to allow peers on the localhost
    pub allow_local: bool,
    /// The local peer's cluster ID
    pub cluster_id: ClusterId,
    /// A handle to the database underlying the storage layer
    pub db: Arc<DB>,
    /// A handle to the system bus used for internal pubsub
    pub system_bus: SystemBus<SystemBusMessage>,
}

/// The applicator applies state updates to the global state and persists them
/// to local storage after consensus has been formed on the updates
///
/// If we view our state implementation as a distributed log forming consensus
/// over the ordering of RPC executions, then the `StateApplicator` can be
/// thought of as the RPC server that executes the RPCs after their consensus
/// has been formed
#[derive(Clone)]
pub struct StateApplicator {
    /// The config for the applicator
    config: StateApplicatorConfig,
}

impl StateApplicator {
    /// Create a new state applicator
    pub fn new(config: StateApplicatorConfig) -> Result<Self> {
        Self::create_db_tables(&config.db)?;

        Ok(Self { config })
    }

    /// Handle a state transition
    pub fn handle_state_transition(&self, transition: StateTransition) -> Result<()> {
        match transition {
            StateTransition::AddWallet(msg) => self.add_wallet(msg),
            StateTransition::UpdateWallet(msg) => self.update_wallet(msg),
            StateTransition::AddOrder(msg) => self.new_order(msg),
            StateTransition::AddOrderValidityProof(msg) => self.add_order_validity_proof(msg),
            StateTransition::NullifyOrders(msg) => self.nullify_orders(msg),
            StateTransition::AddPeers(msg) => self.add_peers(msg),
            StateTransition::RemovePeer(msg) => self.remove_peer(msg),
            _ => unimplemented!("Unsupported state transition forwarded to applicator"),
        }
    }

    /// Create tables in the DB if not already created
    fn create_db_tables(db: &DB) -> Result<()> {
        for table in [
            PEER_INFO_TABLE,
            CLUSTER_MEMBERSHIP_TABLE,
            PRIORITIES_TABLE,
            ORDERS_TABLE,
            ORDER_TO_WALLET_TABLE,
            WALLETS_TABLE,
        ]
        .iter()
        {
            db.create_table(table)
                .map_err(Into::<StateApplicatorError>::into)?;
        }

        Ok(())
    }

    /// Get a reference to the db
    fn db(&self) -> &DB {
        &self.config.db
    }

    /// Get a reference to the system bus
    fn system_bus(&self) -> &SystemBus<SystemBusMessage> {
        &self.config.system_bus
    }
}

#[cfg(test)]
mod test_helpers {
    use std::{str::FromStr, sync::Arc};

    use common::types::gossip::ClusterId;
    use system_bus::SystemBus;

    use crate::test_helpers::mock_db;

    use super::{StateApplicator, StateApplicatorConfig};

    /// Create a mock `StateApplicator`
    pub(crate) fn mock_applicator() -> StateApplicator {
        let config = StateApplicatorConfig {
            allow_local: true,
            db: Arc::new(mock_db()),
            system_bus: SystemBus::new(),
            cluster_id: ClusterId::from_str("test-cluster").unwrap(),
        };

        StateApplicator::new(config).unwrap()
    }
}
