//! Descriptors of tasks used to parameterize their execution
mod lookup_wallet;
mod new_wallet;
mod node_startup;
mod pay_fees;
mod redeem_fee;
mod refresh_wallet;
mod settle_match;
mod update_merkle_proof;
mod update_wallet;

pub use lookup_wallet::*;
pub use new_wallet::*;
pub use node_startup::*;
pub use pay_fees::*;
pub use redeem_fee::*;
pub use refresh_wallet::*;
pub use settle_match::*;
pub use update_merkle_proof::*;
pub use update_wallet::*;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::wallet::WalletIdentifier;

/// The error message returned when a wallet's shares are invalid
const INVALID_WALLET_SHARES: &str = "invalid wallet shares";

/// A type alias for the identifier underlying a task
pub type TaskIdentifier = Uuid;
/// A type alias for the task queue key type, used to index tasks by shared
/// resource
pub type TaskQueueKey = Uuid;

/// A task in the task queue
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedTask {
    /// The ID of the task
    pub id: TaskIdentifier,
    /// The state of the task
    pub state: QueuedTaskState,
    /// The task descriptor
    pub descriptor: TaskDescriptor,
    /// The time at which the task was created
    pub created_at: u64,
}

/// The state of a queued task
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueuedTaskState {
    /// The task is waiting in the queue
    Queued,
    /// The task is running and has preempted the queue
    Preemptive,
    /// The task is being run
    ///
    /// The state is serialized to a string before being stored to give a better
    /// API serialization
    Running {
        /// The state description of the task
        state: String,
        /// Whether the task has committed or not
        committed: bool,
    },
    /// The task is completed
    Completed,
    /// The task failed
    Failed,
}

impl QueuedTaskState {
    /// Whether the task is running
    pub fn is_running(&self) -> bool {
        matches!(self, QueuedTaskState::Running { .. })
            || matches!(self, QueuedTaskState::Preemptive)
    }

    /// Whether the task is committed
    pub fn is_committed(&self) -> bool {
        matches!(self, QueuedTaskState::Running { committed: true, .. })
    }

    /// Get a human-readable description of the task state
    pub fn display_description(&self) -> String {
        match self {
            QueuedTaskState::Queued => "Queued".to_string(),
            QueuedTaskState::Preemptive => "Running".to_string(),
            QueuedTaskState::Running { state, .. } => state.clone(),
            QueuedTaskState::Completed => "Completed".to_string(),
            QueuedTaskState::Failed => "Failed".to_string(),
        }
    }
}

/// A wrapper around the task descriptors
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum TaskDescriptor {
    /// The task descriptor for the `NewWallet` task
    NewWallet(NewWalletTaskDescriptor),
    /// The task descriptor for the `LookupWallet` task
    LookupWallet(LookupWalletTaskDescriptor),
    /// The task descriptor for the `RefreshWallet` task
    RefreshWallet(RefreshWalletTaskDescriptor),
    /// The task descriptor for the `PayProtocolFee` task
    OfflineFee(PayOfflineFeeTaskDescriptor),
    /// The task descriptor for the `PayRelayerFee` task
    RelayerFee(PayRelayerFeeTaskDescriptor),
    /// The task descriptor for the `RedeemFee` task
    RedeemFee(RedeemFeeTaskDescriptor),
    /// The task descriptor for the `SettleMatchInternal` task
    SettleMatchInternal(SettleMatchInternalTaskDescriptor),
    /// The task descriptor for the `SettleMatch` task
    SettleMatch(SettleMatchTaskDescriptor),
    /// The task descriptor for the `SettleExternalMatch` task
    SettleExternalMatch(SettleExternalMatchTaskDescriptor),
    /// The task descriptor for the `UpdateMerkleProof` task
    UpdateMerkleProof(UpdateMerkleProofTaskDescriptor),
    /// The task descriptor for the `UpdateWallet` task
    UpdateWallet(UpdateWalletTaskDescriptor),
    /// The task descriptor for the `NodeStartup` task
    NodeStartup(NodeStartupTaskDescriptor),
}

impl TaskDescriptor {
    /// Compute the task queue key for the task
    pub fn queue_key(&self) -> TaskQueueKey {
        match self {
            TaskDescriptor::NewWallet(task) => task.wallet.wallet_id,
            TaskDescriptor::LookupWallet(task) => task.wallet_id,
            TaskDescriptor::RefreshWallet(task) => task.wallet_id,
            TaskDescriptor::OfflineFee(task) => task.wallet_id,
            TaskDescriptor::RelayerFee(task) => task.wallet_id,
            TaskDescriptor::RedeemFee(task) => task.wallet_id,
            TaskDescriptor::SettleMatch(_) => {
                unimplemented!("SettleMatch should preempt queue, no key needed")
            },
            TaskDescriptor::SettleMatchInternal(_) => {
                unimplemented!("SettleMatchInternal should preempt queue, no key needed")
            },
            TaskDescriptor::SettleExternalMatch(task) => task.internal_wallet_id,
            TaskDescriptor::UpdateMerkleProof(task) => task.wallet.wallet_id,
            TaskDescriptor::UpdateWallet(task) => task.wallet_id,
            TaskDescriptor::NodeStartup(task) => task.id,
        }
    }

    /// Returns the IDs of the wallets affected by the task
    pub fn affected_wallets(&self) -> Vec<WalletIdentifier> {
        match self {
            TaskDescriptor::NewWallet(task) => vec![task.wallet.wallet_id],
            TaskDescriptor::LookupWallet(task) => vec![task.wallet_id],
            TaskDescriptor::RefreshWallet(task) => vec![task.wallet_id],
            TaskDescriptor::OfflineFee(task) => vec![task.wallet_id],
            TaskDescriptor::RelayerFee(task) => vec![task.wallet_id],
            TaskDescriptor::RedeemFee(task) => vec![task.wallet_id],
            TaskDescriptor::SettleMatch(task) => vec![task.wallet_id],
            TaskDescriptor::SettleMatchInternal(task) => vec![task.wallet_id1, task.wallet_id2],
            TaskDescriptor::SettleExternalMatch(task) => vec![task.internal_wallet_id],
            TaskDescriptor::UpdateMerkleProof(task) => vec![task.wallet.wallet_id],
            TaskDescriptor::UpdateWallet(task) => vec![task.wallet_id],
            TaskDescriptor::NodeStartup(_) => vec![],
        }
    }

    /// Returns whether the task is a wallet task
    pub fn is_wallet_task(&self) -> bool {
        match self {
            TaskDescriptor::NewWallet(_)
            | TaskDescriptor::LookupWallet(_)
            | TaskDescriptor::RefreshWallet(_)
            | TaskDescriptor::OfflineFee(_)
            | TaskDescriptor::RelayerFee(_)
            | TaskDescriptor::RedeemFee(_)
            | TaskDescriptor::UpdateWallet(_)
            | TaskDescriptor::SettleMatch(_)
            | TaskDescriptor::SettleMatchInternal(_)
            | TaskDescriptor::SettleExternalMatch(_)
            | TaskDescriptor::UpdateMerkleProof(_) => true,
            TaskDescriptor::NodeStartup(_) => false,
        }
    }

    /// Get a human readable description of the task
    pub fn display_description(&self) -> String {
        match self {
            TaskDescriptor::NewWallet(_) => "New Wallet".to_string(),
            TaskDescriptor::UpdateWallet(args) => args.description.display_description(),
            TaskDescriptor::LookupWallet(_) => "Lookup Wallet".to_string(),
            TaskDescriptor::RefreshWallet(_) => "Refresh Wallet".to_string(),
            TaskDescriptor::SettleMatch(_) => "Settle Match".to_string(),
            TaskDescriptor::SettleMatchInternal(_) => "Settle Match".to_string(),
            TaskDescriptor::SettleExternalMatch(_) => "Settle Match".to_string(),
            TaskDescriptor::OfflineFee(_) => "Pay Fee Offline".to_string(),
            TaskDescriptor::RelayerFee(_) => "Pay Relayer Fee".to_string(),
            TaskDescriptor::RedeemFee(_) => "Redeem Fee".to_string(),
            TaskDescriptor::UpdateMerkleProof(_) => "Update Merkle Proof".to_string(),
            TaskDescriptor::NodeStartup(_) => "Node Startup".to_string(),
        }
    }
}

// ---------
// | Mocks |
// ---------

/// Mocks for the task descriptors
#[cfg(any(test, feature = "mocks"))]
pub mod mocks {
    use circuit_types::keychain::SecretSigningKey;
    use constants::Scalar;
    use contracts_common::custom_serde::BytesSerializable;
    use ethers::core::utils::keccak256;
    use ethers::signers::Wallet as EthersWallet;
    use k256::ecdsa::SigningKey as K256SigningKey;
    use rand::thread_rng;
    use util::get_current_time_millis;

    use crate::types::{tasks::TaskIdentifier, wallet::Wallet, wallet_mocks::mock_empty_wallet};

    use super::{
        NewWalletTaskDescriptor, QueuedTask, QueuedTaskState, TaskDescriptor, TaskQueueKey,
    };

    /// Generate the wallet update signature for a new wallet
    pub fn gen_wallet_update_sig(wallet: &Wallet, key: &SecretSigningKey) -> Vec<u8> {
        let new_wallet_comm = wallet.get_wallet_share_commitment();

        // Serialize the commitment, uses the contract's serialization here:
        //  https://github.com/renegade-fi/renegade-contracts/blob/main/contracts-common/src/custom_serde.rs#L82-L87
        let comm_bytes = new_wallet_comm.inner().serialize_to_bytes();
        let digest = keccak256(comm_bytes);

        // Sign the message
        let signing_key: K256SigningKey = key.try_into().unwrap();
        let wallet = EthersWallet::from(signing_key);
        let sig = wallet.sign_hash(digest.into()).unwrap();

        sig.to_vec()
    }

    /// Get a dummy queued task
    pub fn mock_queued_task(queue_key: TaskQueueKey) -> super::QueuedTask {
        QueuedTask {
            id: TaskIdentifier::new_v4(),
            state: QueuedTaskState::Queued,
            descriptor: mock_task_descriptor(queue_key),
            created_at: get_current_time_millis(),
        }
    }

    /// Get a dummy preemptive queued task
    pub fn mock_preemptive_task(queue_key: TaskQueueKey) -> super::QueuedTask {
        let mut task = mock_queued_task(queue_key);
        task.state = QueuedTaskState::Preemptive;
        task
    }

    /// Get a dummy task descriptor
    pub fn mock_task_descriptor(queue_key: TaskQueueKey) -> TaskDescriptor {
        let mut rng = thread_rng();

        // Set the wallet ID to the task queue key so we can generate predictable mock
        // queues
        let mut wallet = mock_empty_wallet();
        wallet.wallet_id = queue_key;
        TaskDescriptor::NewWallet(NewWalletTaskDescriptor {
            wallet,
            blinder_seed: Scalar::random(&mut rng),
        })
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use constants::Scalar;

    use crate::types::{
        wallet::OrderIdentifier,
        wallet_mocks::{mock_empty_wallet, mock_order},
    };

    use super::{
        mocks::gen_wallet_update_sig, NewWalletTaskDescriptor, UpdateWalletTaskDescriptor,
    };

    /// Tests creating a new wallet task with an invalid secret sharing
    #[test]
    #[should_panic(expected = "invalid wallet shares")]
    fn test_invalid_new_wallet_shares() {
        let mut wallet = mock_empty_wallet();
        wallet.blinded_public_shares.orders[0].amount += Scalar::one();

        NewWalletTaskDescriptor::new(wallet, Scalar::zero()).unwrap();
    }

    /// Tests creating an update wallet task with an invalid shares
    #[test]
    #[should_panic(expected = "invalid wallet shares")]
    fn test_invalid_update_wallet_shares() {
        let mut wallet = mock_empty_wallet();
        wallet.blinded_public_shares.orders[0].amount += Scalar::one();

        UpdateWalletTaskDescriptor::new_order_placement(
            OrderIdentifier::new_v4(),
            mock_order(),
            wallet.clone(),
            wallet,
            vec![],
        )
        .unwrap();
    }

    /// Tests creating an update wallet task with an invalid signatures
    #[test]
    #[should_panic(expected = "invalid wallet update sig")]
    fn test_invalid_wallet_update_signature() {
        let wallet = mock_empty_wallet();
        let sig = vec![0; 64];

        UpdateWalletTaskDescriptor::new_order_placement(
            OrderIdentifier::new_v4(),
            mock_order(),
            wallet.clone(),
            wallet,
            sig,
        )
        .unwrap();
    }

    /// Tests creating a valid update wallet task
    #[test]
    fn test_valid_update_wallet() {
        let wallet = mock_empty_wallet();

        let key = wallet.key_chain.secret_keys.sk_root.as_ref().unwrap();
        let sig = gen_wallet_update_sig(&wallet, key);

        UpdateWalletTaskDescriptor::new_order_placement(
            OrderIdentifier::new_v4(),
            mock_order(),
            wallet.clone(),
            wallet,
            sig,
        )
        .unwrap();
    }
}
