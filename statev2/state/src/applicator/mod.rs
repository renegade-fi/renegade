//! The state applicator applies updates that have been committed to by the raft group
//! to the global state, persisting them to local storage

use std::sync::Arc;

use external_api::bus_message::SystemBusMessage;
use system_bus::SystemBus;

use crate::storage::db::DB;

use self::error::StateApplicatorError;

pub mod error;
pub mod peer_index;

// -------------
// | Constants |
// -------------

/// A type alias for the result type given by the applicator
pub(crate) type Result<T> = std::result::Result<T, StateApplicatorError>;

/// The name of the db table that stores peer information
pub(crate) const PEER_INFO_TABLE: &str = "peer-info";
/// The name of the db table that stores cluster membership information
pub(crate) const CLUSTER_MEMBERSHIP_TABLE: &str = "cluster-membership";

/// The config for the state applicator
#[derive(Clone)]
pub struct StateApplicatorConfig {
    /// Whether or not to allow peers on the localhost
    pub allow_local: bool,
    /// A handle to the database underlying the storage layer
    db: Arc<DB>,
    /// A handle to the system bus used for internal pubsub
    system_bus: SystemBus<SystemBusMessage>,
}

/// The applicator applies state updates to the global state and persists them to local storage
/// after consensus has been formed on the updates
///
/// If we view our state implementation as a distributed log forming consensus over the ordering of RPC
/// executions, then the `StateApplicator` can be thought of as the RPC server that executes the RPCs
/// after their consensus has been formed
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

    /// Create tables in the DB if not already created
    fn create_db_tables(db: &DB) -> Result<()> {
        for table in [PEER_INFO_TABLE, CLUSTER_MEMBERSHIP_TABLE].iter() {
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
