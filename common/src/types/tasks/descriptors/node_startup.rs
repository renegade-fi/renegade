//! Task descriptor for the node startup task

use serde::{Deserialize, Serialize};

use super::TaskIdentifier;

/// The task descriptor for the node startup task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStartupTaskDescriptor {
    /// The task id
    pub id: TaskIdentifier,
    /// The amount of time to wait for the gossip layer to warmup before setting
    /// up the rest of the node
    pub gossip_warmup_ms: u64,
}
