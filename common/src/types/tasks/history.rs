//! Types for task history storage

use circuit_types::r#match::MatchResult;
use serde::{Deserialize, Serialize};

use super::{QueuedTaskState, TaskDescriptor, TaskIdentifier, WalletUpdateType};

/// A historical task executed by the task driver
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoricalTask {
    /// The ID of the task
    pub id: TaskIdentifier,
    /// The state of the task
    pub state: QueuedTaskState,
    /// The time the task was created
    pub created_at: u64,
    /// The auxiliary information from the task descriptor that we keep in the
    /// history
    pub task_info: HistoricalTaskDescription,
}

/// A historical description of a task
///
/// Separated out from the task descriptors as the descriptors may contain
/// runtime information irrelevant for storage
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HistoricalTaskDescription {
    /// A new wallet was created
    NewWallet,
    /// An update to a wallet
    UpdateWallet(WalletUpdateType),
    /// A match was settled
    SettleMatch(MatchResult),
    /// A fee was paid
    PayOfflineFee,
}

impl HistoricalTaskDescription {
    /// Create a historical task description from a task descriptor
    pub fn from_task_descriptor(desc: &TaskDescriptor) -> Option<Self> {
        match desc {
            TaskDescriptor::NewWallet(_) => Some(Self::NewWallet),
            TaskDescriptor::UpdateWallet(desc) => {
                Some(Self::UpdateWallet(desc.description.clone()))
            },
            TaskDescriptor::SettleMatch(desc) => Some(Self::SettleMatch(desc.match_res.clone())),
            TaskDescriptor::SettleMatchInternal(desc) => {
                Some(Self::SettleMatch(desc.match_result.clone()))
            },
            TaskDescriptor::OfflineFee(_) => Some(Self::PayOfflineFee),
            _ => None,
        }
    }
}