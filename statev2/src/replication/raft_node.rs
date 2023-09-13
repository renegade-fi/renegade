//! A raft node that processes events from the consensus layer and the network, and handles
//! interactions with storage

use std::sync::Arc;

use raft::{Config as RaftConfig, RawNode};
use slog::Logger;
use tracing_slog::TracingSlogDrain;

use crate::storage::db::DB;

use super::{error::ReplicationError, log_store::LogStore};

// -------------
// | Raft Node |
// -------------

/// A raft node that replicates the relayer's state machine
pub struct ReplicationNode {
    /// The inner raft node
    _inner: RawNode<LogStore>,
}

impl ReplicationNode {
    /// Creates a new replication node
    pub fn new(db: Arc<DB>, config: &RaftConfig) -> Result<Self, ReplicationError> {
        // Build the log store on top of the DB
        let store = LogStore::new(db)?;

        // Build an slog logger and connect it to the tracing logger
        let tracing_drain = TracingSlogDrain;
        let logger = Logger::root(tracing_drain, slog::o!());

        // Build raft node
        let node = RawNode::new(config, store, &logger).map_err(ReplicationError::Raft)?;

        Ok(Self { _inner: node })
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use raft::Config as RaftConfig;
    use std::sync::Arc;

    use crate::test_helpers::mock_db;

    use super::ReplicationNode;

    /// A local node ID for testing
    const NODE_ID: u64 = 1;

    /// Tests that the constructor works properly, largely this means testing that the `LogStore`
    /// initialization is compatible with the `raft` setup
    #[test]
    fn test_constructor() {
        let db = Arc::new(mock_db());
        let config = RaftConfig::new(NODE_ID);

        let _node = ReplicationNode::new(db, &config).unwrap();
    }
}
