//! Task descriptor for the node startup task

use serde::{Deserialize, Serialize};

use super::{TaskDescriptor, TaskIdentifier};

/// The task descriptor for the node startup task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStartupTaskDescriptor {
    /// The task id
    pub id: TaskIdentifier,
    /// The amount of time to wait for the gossip layer to warmup before setting
    /// up the rest of the node
    pub gossip_warmup_ms: u64,
}

impl NodeStartupTaskDescriptor {
    /// Construct a new node startup task descriptor
    pub fn new(gossip_warmup_ms: u64) -> Self {
        let id = TaskIdentifier::new_v4();
        Self { id, gossip_warmup_ms }
    }
}

impl From<NodeStartupTaskDescriptor> for TaskDescriptor {
    fn from(desc: NodeStartupTaskDescriptor) -> Self {
        TaskDescriptor::NodeStartup(desc)
    }
}
