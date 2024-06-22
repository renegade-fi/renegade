//! Types for task history storage

use ark_mpc::PARTY1;
use circuit_types::{r#match::MatchResult, Amount};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use super::{
    QueuedTask, QueuedTaskState, TaskDescriptor, TaskIdentifier, TaskQueueKey, WalletUpdateType,
};

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

impl HistoricalTask {
    /// Create a new historical task from a `QueuedTask`
    ///
    /// Returns `None` for tasks that should not be stored in history
    pub fn from_queued_task(key: TaskQueueKey, task: QueuedTask) -> Option<Self> {
        let desc = task.descriptor.clone();
        let task_info = HistoricalTaskDescription::from_task_descriptor(key, &desc)?;
        Some(Self { id: task.id, state: task.state, created_at: task.created_at, task_info })
    }
}

/// A historical description of a task
///
/// Separated out from the task descriptors as the descriptors may contain
/// runtime information irrelevant for storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HistoricalTaskDescription {
    /// A new wallet was created
    NewWallet,
    /// An update to a wallet
    UpdateWallet(WalletUpdateType),
    /// A match was settled
    SettleMatch(MatchResult),
    /// A fee was paid
    PayOfflineFee {
        /// The mind the fee was paid from
        mint: BigUint,
        /// The amount of the fee
        amount: Amount,
        /// Whether the fee was paid for a protocol fee
        is_protocol: bool,
    },
}

impl HistoricalTaskDescription {
    /// Create a historical task description from a task descriptor
    pub fn from_task_descriptor(key: TaskQueueKey, desc: &TaskDescriptor) -> Option<Self> {
        match desc {
            TaskDescriptor::NewWallet(_) => Some(Self::NewWallet),
            TaskDescriptor::UpdateWallet(desc) => {
                Some(Self::UpdateWallet(desc.description.clone()))
            },
            TaskDescriptor::SettleMatch(desc) => {
                let mut match_res = desc.match_res.clone();
                let was_party1 = desc.handshake_state.role.get_party_id() == PARTY1;

                // Flip the direction if the local party was party1, so that the
                // direction is consistent with the local party's perspective
                let my_direction = was_party1 ^ desc.match_res.direction;
                match_res.direction = my_direction;
                Some(Self::SettleMatch(match_res))
            },
            TaskDescriptor::SettleMatchInternal(desc) => {
                let mut match_res = desc.match_result.clone();
                let was_party1 = key == desc.wallet_id2;

                let my_direction = was_party1 ^ desc.match_result.direction;
                match_res.direction = my_direction;
                Some(Self::SettleMatch(match_res))
            },
            TaskDescriptor::OfflineFee(desc) => Some(Self::PayOfflineFee {
                mint: desc.mint.clone(),
                amount: desc.amount,
                is_protocol: desc.is_protocol_fee,
            }),
            _ => None,
        }
    }
}

/// Mock helpers for testing task history
#[cfg(feature = "mocks")]
pub mod historical_mocks {

    use rand::{thread_rng, RngCore};

    use crate::types::{
        tasks::{QueuedTaskState, TaskIdentifier, WalletUpdateType},
        wallet::OrderIdentifier,
        wallet_mocks::mock_order,
    };

    use super::{HistoricalTask, HistoricalTaskDescription};

    /// Return a mock historical task
    pub fn mock_historical_task() -> HistoricalTask {
        let mut rng = thread_rng();
        let id = OrderIdentifier::new_v4();
        let ty = WalletUpdateType::PlaceOrder { order: mock_order(), id, matching_pool: None };
        HistoricalTask {
            id: TaskIdentifier::new_v4(),
            state: QueuedTaskState::Completed,
            created_at: rng.next_u64(),
            task_info: HistoricalTaskDescription::UpdateWallet(ty),
        }
    }
}
