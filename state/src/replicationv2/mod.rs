//! Defines replication primitives for the relayer state on top of a
//! base raft implementation. Raft provides a consistent, distributed log
//! with serializable access. We describe state transitions and persist these
//! to the raft log

pub mod error;
mod log_store;
mod network;
mod snapshot;
mod state_machine;

use openraft::{EmptyNode, RaftTypeConfig};

use crate::StateTransition;

// Declare the types config for the raft
openraft::declare_raft_types! (
    /// The type config for the raft
    pub TypeConfig:
        D = StateTransition,
        R = (), // Response
        Node = EmptyNode,
        SnapshotData = tokio::fs::File,
);

/// A type alias for entries in the raft log
pub type Entry = <TypeConfig as RaftTypeConfig>::Entry;
/// A type alias for the node id type
pub type NodeId = <TypeConfig as RaftTypeConfig>::NodeId;
/// A type alias for the node type
pub type Node = <TypeConfig as RaftTypeConfig>::Node;
/// A type alias for the snapshot data type
pub type SnapshotData = <TypeConfig as RaftTypeConfig>::SnapshotData;

#[cfg(test)]
pub mod test_helpers {
    use crate::applicator::test_helpers::mock_applicator;

    use super::state_machine::{StateMachine, StateMachineConfig};

    /// Create a mock state machine
    pub fn mock_state_machine() -> StateMachine {
        let app = mock_applicator();
        let db = app.config.db.clone();
        let state_config = StateMachineConfig::new(db.path().to_string());

        StateMachine::new(state_config, app)
    }
}

#[cfg(test)]
mod test {

    use openraft::{testing::StoreBuilder, StorageError as RaftStorageError};

    use crate::applicator::test_helpers::mock_applicator;

    use super::{
        log_store::LogStore,
        state_machine::{StateMachine, StateMachineConfig},
        NodeId, TypeConfig,
    };

    /// A builder for the storage layer, used to fit into the `openraft` test
    /// interface
    struct StorageBuilder;
    impl StoreBuilder<TypeConfig, LogStore, StateMachine> for StorageBuilder {
        async fn build(&self) -> Result<((), LogStore, StateMachine), RaftStorageError<NodeId>> {
            let app = mock_applicator();
            let db = app.config.db.clone();
            let state_config = StateMachineConfig::new(db.path().to_string());
            let store = LogStore::new(db);

            Ok(((), store, StateMachine::new(state_config, app)))
        }
    }

    /// Run the `openraft` test suite on our `RaftStateMachine` and
    /// `RaftLogStore` impls
    #[test]
    fn test_openraft_suite() {
        openraft::testing::Suite::test_all(StorageBuilder).unwrap();
    }
}
