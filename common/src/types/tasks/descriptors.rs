//! Defines task related types

use circuit_types::{
    fixed_point::FixedPoint, keychain::PublicSigningKey, note::Note, order::Order,
    r#match::MatchResult, Amount,
};
use constants::Scalar;
use ethers::core::types::Signature;
use ethers::core::utils::keccak256;
use ethers::utils::public_key_to_address;
use k256::ecdsa::VerifyingKey as K256VerifyingKey;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{
    gossip::WrappedPeerId,
    handshake::HandshakeState,
    proof_bundles::{MatchBundle, OrderValidityProofBundle, OrderValidityWitnessBundle},
    transfer_auth::ExternalTransferWithAuth,
    wallet::{KeyChain, OrderIdentifier, Wallet, WalletIdentifier},
};

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
    /// The peer assigned to the task
    pub executor: WrappedPeerId,
    /// The state of the task
    pub state: QueuedTaskState,
    /// The task descriptor
    pub descriptor: TaskDescriptor,
    /// The time at which the task was created
    pub created_at: u64,
}

/// The state of a queued task
///
/// TODO: We can add completed and failed states if/when we implement a task
/// history
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
    /// The task descriptor for the `PayProtocolFee` task
    OfflineFee(PayOfflineFeeTaskDescriptor),
    /// The task descriptor for the `PayRelayerFee` task
    RelayerFee(PayRelayerFeeTaskDescriptor),
    /// The task descriptor for the `RedeemRelayerFee` task
    RedeemRelayerFee(RedeemRelayerFeeTaskDescriptor),
    /// The task descriptor for the `SettleMatchInternal` task
    SettleMatchInternal(SettleMatchInternalTaskDescriptor),
    /// The task descriptor for the `SettleMatch` task
    SettleMatch(SettleMatchTaskDescriptor),
    /// The task descriptor for the `UpdateMerkleProof` task
    UpdateMerkleProof(UpdateMerkleProofTaskDescriptor),
    /// The task descriptor for the `UpdateWallet` task
    UpdateWallet(UpdateWalletTaskDescriptor),
}

impl TaskDescriptor {
    /// Compute the task queue key for the task
    pub fn queue_key(&self) -> TaskQueueKey {
        match self {
            TaskDescriptor::NewWallet(task) => task.wallet.wallet_id,
            TaskDescriptor::LookupWallet(task) => task.wallet_id,
            TaskDescriptor::OfflineFee(task) => task.wallet_id,
            TaskDescriptor::RelayerFee(task) => task.wallet_id,
            TaskDescriptor::RedeemRelayerFee(task) => task.wallet_id,
            TaskDescriptor::SettleMatch(_) => {
                unimplemented!("SettleMatch should preempt queue, no key needed")
            },
            TaskDescriptor::SettleMatchInternal(_) => {
                unimplemented!("SettleMatchInternal should preempt queue, no key needed")
            },
            TaskDescriptor::UpdateMerkleProof(task) => task.wallet.wallet_id,
            TaskDescriptor::UpdateWallet(task) => task.wallet_id,
        }
    }

    /// Returns whether the task is a wallet task
    ///
    /// Currently all tasks are wallet tasks
    pub fn is_wallet_task(&self) -> bool {
        match self {
            TaskDescriptor::NewWallet(_)
            | TaskDescriptor::LookupWallet(_)
            | TaskDescriptor::OfflineFee(_)
            | TaskDescriptor::RelayerFee(_)
            | TaskDescriptor::RedeemRelayerFee(_)
            | TaskDescriptor::UpdateWallet(_)
            | TaskDescriptor::SettleMatch(_)
            | TaskDescriptor::SettleMatchInternal(_)
            | TaskDescriptor::UpdateMerkleProof(_) => true,
        }
    }

    /// Get a human readable description of the task
    pub fn display_description(&self) -> String {
        match self {
            TaskDescriptor::NewWallet(_) => "New Wallet".to_string(),
            TaskDescriptor::UpdateWallet(args) => args.description.display_description(),
            TaskDescriptor::LookupWallet(_) => "Lookup Wallet".to_string(),
            TaskDescriptor::SettleMatch(_) => "Settle Match".to_string(),
            TaskDescriptor::SettleMatchInternal(_) => "Settle Match".to_string(),
            TaskDescriptor::OfflineFee(_) => "Pay Fee Offline".to_string(),
            TaskDescriptor::RelayerFee(_) => "Pay Relayer Fee".to_string(),
            TaskDescriptor::RedeemRelayerFee(_) => "Redeem Relayer Fee".to_string(),
            TaskDescriptor::UpdateMerkleProof(_) => "Update Merkle Proof".to_string(),
        }
    }
}

// ---------------
// | Descriptors |
// ---------------

/// The task descriptor containing only the parameterization of the `NewWallet`
/// task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewWalletTaskDescriptor {
    /// The wallet to create
    pub wallet: Wallet,
}

impl NewWalletTaskDescriptor {
    /// Constructor
    pub fn new(wallet: Wallet) -> Result<Self, String> {
        // Validate that the wallet shares are well formed
        if !wallet.check_wallet_shares() {
            return Err(INVALID_WALLET_SHARES.to_string());
        }

        Ok(NewWalletTaskDescriptor { wallet })
    }
}

impl From<NewWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: NewWalletTaskDescriptor) -> Self {
        TaskDescriptor::NewWallet(descriptor)
    }
}

/// The task descriptor containing only the parameterization of the
/// `LookupWallet` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LookupWalletTaskDescriptor {
    /// The ID to provision for the wallet
    pub wallet_id: WalletIdentifier,
    /// The CSPRNG seed for the blinder stream
    pub blinder_seed: Scalar,
    /// The CSPRNG seed for the secret share stream
    pub secret_share_seed: Scalar,
    /// The keychain to manage the wallet with
    pub key_chain: KeyChain,
}

impl LookupWalletTaskDescriptor {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        blinder_seed: Scalar,
        secret_share_seed: Scalar,
        key_chain: KeyChain,
    ) -> Result<Self, String> {
        Ok(LookupWalletTaskDescriptor { wallet_id, blinder_seed, secret_share_seed, key_chain })
    }
}

impl From<LookupWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: LookupWalletTaskDescriptor) -> Self {
        TaskDescriptor::LookupWallet(descriptor)
    }
}

/// The task descriptor containing only the parameterization of the
/// `SettleMatchInternal` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleMatchInternalTaskDescriptor {
    /// The price at which the match was executed
    pub execution_price: FixedPoint,
    /// The identifier of the first order
    pub order_id1: OrderIdentifier,
    /// The identifier of the second order
    pub order_id2: OrderIdentifier,
    /// The identifier of the first order's wallet
    pub wallet_id1: WalletIdentifier,
    /// The identifier of the second order's wallet
    pub wallet_id2: WalletIdentifier,
    /// The validity proofs for the first order
    pub order1_proof: OrderValidityProofBundle,
    /// The validity proof witness for the first order
    pub order1_validity_witness: OrderValidityWitnessBundle,
    /// The validity proofs for the second order
    pub order2_proof: OrderValidityProofBundle,
    /// The validity proof witness for the second order
    pub order2_validity_witness: OrderValidityWitnessBundle,
    /// The match result
    pub match_result: MatchResult,
}

impl SettleMatchInternalTaskDescriptor {
    /// Constructor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_price: FixedPoint,
        order_id1: OrderIdentifier,
        order_id2: OrderIdentifier,
        wallet_id1: WalletIdentifier,
        wallet_id2: WalletIdentifier,
        order1_proof: OrderValidityProofBundle,
        order1_validity_witness: OrderValidityWitnessBundle,
        order2_proof: OrderValidityProofBundle,
        order2_validity_witness: OrderValidityWitnessBundle,
        match_result: MatchResult,
    ) -> Result<Self, String> {
        Ok(SettleMatchInternalTaskDescriptor {
            execution_price,
            order_id1,
            order_id2,
            wallet_id1,
            wallet_id2,
            order1_proof,
            order1_validity_witness,
            order2_proof,
            order2_validity_witness,
            match_result,
        })
    }
}

impl From<SettleMatchInternalTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettleMatchInternalTaskDescriptor) -> Self {
        TaskDescriptor::SettleMatchInternal(descriptor)
    }
}

/// The task descriptor containing only the parameterization of the
/// `SettleMatch` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleMatchTaskDescriptor {
    /// The ID of the wallet that the local node matched an order from
    pub wallet_id: WalletIdentifier,
    /// The state entry from the handshake manager that parameterizes the
    /// match process
    pub handshake_state: HandshakeState,
    /// The match result from the matching engine
    pub match_res: MatchResult,
    /// The proof that comes from the collaborative match-settle process
    pub match_bundle: MatchBundle,
    /// The validity proofs submitted by the first party
    pub party0_validity_proof: OrderValidityProofBundle,
    /// The validity proofs submitted by the second party
    pub party1_validity_proof: OrderValidityProofBundle,
}

impl SettleMatchTaskDescriptor {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        handshake_state: HandshakeState,
        match_res: MatchResult,
        match_bundle: MatchBundle,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
    ) -> Result<Self, String> {
        Ok(SettleMatchTaskDescriptor {
            wallet_id,
            handshake_state,
            match_res,
            match_bundle,
            party0_validity_proof,
            party1_validity_proof,
        })
    }
}

impl From<SettleMatchTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettleMatchTaskDescriptor) -> Self {
        TaskDescriptor::SettleMatch(descriptor)
    }
}

/// The task descriptor containing only the parameterization of the
/// `UpdateMerkleProof` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateMerkleProofTaskDescriptor {
    /// The wallet to update
    pub wallet: Wallet,
}

impl UpdateMerkleProofTaskDescriptor {
    /// Constructor
    pub fn new(wallet: Wallet) -> Result<Self, String> {
        Ok(UpdateMerkleProofTaskDescriptor { wallet })
    }
}

impl From<UpdateMerkleProofTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: UpdateMerkleProofTaskDescriptor) -> Self {
        TaskDescriptor::UpdateMerkleProof(descriptor)
    }
}

/// A type representing a description of an update wallet task
///
/// Differentiates between order vs balance updates, and holds fields for
/// display
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WalletUpdateType {
    /// Deposit a balance
    Deposit {
        /// The deposited mint
        mint: BigUint,
        /// The amount deposited
        amount: Amount,
    },
    /// Withdraw a balance
    Withdraw {
        /// The withdrawn mint
        mint: BigUint,
        /// The amount withdrawn
        amount: Amount,
    },
    /// Place an order
    PlaceOrder {
        /// The order to place
        order: Order,
    },
    /// Cancel an order
    CancelOrder {
        /// The order that was cancelled
        order: Order,
    },
}

impl WalletUpdateType {
    /// Get a human-readable description of the wallet update type
    pub fn display_description(&self) -> String {
        match self {
            WalletUpdateType::Deposit { .. } => "Deposit",
            WalletUpdateType::Withdraw { .. } => "Withdraw",
            WalletUpdateType::PlaceOrder { .. } => "Place order",
            WalletUpdateType::CancelOrder { .. } => "Cancel order",
        }
        .to_string()
    }
}

/// The task descriptor containing only the parameterization of the
/// `UpdateWallet` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateWalletTaskDescriptor {
    /// A description of the update task, maintained for historical state
    pub description: WalletUpdateType,
    /// The external transfer & auth data, if one exists
    pub transfer: Option<ExternalTransferWithAuth>,
    /// The old wallet before update
    pub wallet_id: WalletIdentifier,
    /// The new wallet after update
    pub new_wallet: Wallet,
    /// A signature of the `VALID WALLET UPDATE` statement by the wallet's root
    /// key, the contract uses this to authorize the update
    pub wallet_update_signature: Vec<u8>,
}

impl UpdateWalletTaskDescriptor {
    /// Base constructor
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        description: WalletUpdateType,
        transfer_with_auth: Option<ExternalTransferWithAuth>,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        // Check that the new wallet is properly reblinded
        if !new_wallet.check_wallet_shares() {
            return Err(INVALID_WALLET_SHARES.to_string());
        }

        // Check the signature on the updated shares commitment
        let key = &old_wallet.key_chain.public_keys.pk_root;
        verify_wallet_update_signature(&new_wallet, key, &wallet_update_signature)
            .map_err(|e| format!("invalid wallet update sig: {e}"))?;

        Ok(UpdateWalletTaskDescriptor {
            description,
            transfer: transfer_with_auth,
            wallet_id: old_wallet.wallet_id,
            new_wallet,
            wallet_update_signature,
        })
    }

    /// A new deposit
    pub fn new_deposit(
        transfer_with_auth: ExternalTransferWithAuth,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let transfer = &transfer_with_auth.external_transfer;
        let desc =
            WalletUpdateType::Deposit { mint: transfer.mint.clone(), amount: transfer.amount };

        Self::new(desc, Some(transfer_with_auth), old_wallet, new_wallet, wallet_update_signature)
    }

    /// A new withdrawal
    pub fn new_withdrawal(
        transfer_with_auth: ExternalTransferWithAuth,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let transfer = &transfer_with_auth.external_transfer;
        let desc =
            WalletUpdateType::Withdraw { mint: transfer.mint.clone(), amount: transfer.amount };

        Self::new(desc, Some(transfer_with_auth), old_wallet, new_wallet, wallet_update_signature)
    }

    /// A new create order
    pub fn new_order(
        order: Order,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let desc = WalletUpdateType::PlaceOrder { order };
        Self::new(desc, None, old_wallet, new_wallet, wallet_update_signature)
    }

    /// A new order cancellation
    pub fn new_order_cancellation(
        order: Order,
        old_wallet: Wallet,
        new_wallet: Wallet,
        wallet_update_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let desc = WalletUpdateType::CancelOrder { order };
        Self::new(desc, None, old_wallet, new_wallet, wallet_update_signature)
    }
}

impl From<UpdateWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: UpdateWalletTaskDescriptor) -> Self {
        TaskDescriptor::UpdateWallet(descriptor)
    }
}

/// The task descriptor for the offline fee payment task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayOfflineFeeTaskDescriptor {
    /// Whether the fee is a protocol fee or a relayer fee
    pub is_protocol_fee: bool,
    /// The wallet to pay fees for
    pub wallet_id: WalletIdentifier,
    /// The balance to pay fees for
    pub balance_mint: BigUint,
}

impl PayOfflineFeeTaskDescriptor {
    /// Constructor for the relayer fee payment task
    pub fn new_relayer_fee(
        wallet_id: WalletIdentifier,
        balance_mint: BigUint,
    ) -> Result<Self, String> {
        Ok(PayOfflineFeeTaskDescriptor { is_protocol_fee: false, wallet_id, balance_mint })
    }

    /// Constructor for the protocol fee payment task
    pub fn new_protocol_fee(
        wallet_id: WalletIdentifier,
        balance_mint: BigUint,
    ) -> Result<Self, String> {
        Ok(PayOfflineFeeTaskDescriptor { is_protocol_fee: true, wallet_id, balance_mint })
    }
}

impl From<PayOfflineFeeTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: PayOfflineFeeTaskDescriptor) -> Self {
        TaskDescriptor::OfflineFee(descriptor)
    }
}

/// The task descriptor for the relayer fee payment task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayRelayerFeeTaskDescriptor {
    /// The wallet to pay fees for
    pub wallet_id: WalletIdentifier,
    /// The balance to pay fees for
    pub balance_mint: BigUint,
}

impl PayRelayerFeeTaskDescriptor {
    /// Constructor
    pub fn new(wallet_id: WalletIdentifier, balance_mint: BigUint) -> Result<Self, String> {
        Ok(PayRelayerFeeTaskDescriptor { wallet_id, balance_mint })
    }
}

impl From<PayRelayerFeeTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: PayRelayerFeeTaskDescriptor) -> Self {
        TaskDescriptor::RelayerFee(descriptor)
    }
}

/// The task descriptor for redeeming a relayer note
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemRelayerFeeTaskDescriptor {
    /// The wallet ID of the relayer's wallet
    ///
    /// Technically this should be static and not needed here, but we include it
    /// to allow the descriptor struct to compute its own task queue key
    pub wallet_id: WalletIdentifier,
    /// The note to redeem
    pub note: Note,
}

impl RedeemRelayerFeeTaskDescriptor {
    /// Constructor
    pub fn new(wallet_id: WalletIdentifier, note: Note) -> Result<Self, String> {
        Ok(RedeemRelayerFeeTaskDescriptor { wallet_id, note })
    }
}

impl From<RedeemRelayerFeeTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: RedeemRelayerFeeTaskDescriptor) -> Self {
        TaskDescriptor::RedeemRelayerFee(descriptor)
    }
}

// -----------
// | Helpers |
// -----------

/// Verify a signature of a wallet update
pub fn verify_wallet_update_signature(
    wallet: &Wallet,
    key: &PublicSigningKey,
    wallet_update_signature: &[u8],
) -> Result<(), String> {
    let key: K256VerifyingKey = key.into();
    let new_wallet_comm = wallet.get_wallet_share_commitment();

    // Serialize the commitment, matches the contract's serialization here:
    //  https://github.com/renegade-fi/renegade-contracts/blob/main/contracts-common/src/custom_serde.rs#L82-L87
    let comm_bytes = new_wallet_comm.to_biguint().to_bytes_be();
    let digest = keccak256(comm_bytes);

    // Verify the signature
    let addr = public_key_to_address(&key);
    let sig = Signature::try_from(wallet_update_signature).map_err(|e| e.to_string())?;
    sig.verify(digest, addr).map_err(|e| e.to_string())
}

// ---------
// | Mocks |
// ---------

#[cfg(any(test, feature = "mocks"))]
pub mod mocks {
    //! Mocks for the task descriptors
    use circuit_types::keychain::SecretSigningKey;
    use ethers::core::utils::keccak256;
    use ethers::signers::Wallet as EthersWallet;
    use k256::ecdsa::SigningKey as K256SigningKey;
    use util::get_current_time_millis;

    use crate::types::{
        gossip::mocks::mock_peer, tasks::TaskIdentifier, wallet::Wallet,
        wallet_mocks::mock_empty_wallet,
    };

    use super::{
        NewWalletTaskDescriptor, QueuedTask, QueuedTaskState, TaskDescriptor, TaskQueueKey,
    };

    /// Generate the wallet update signature for a new wallet
    pub fn gen_wallet_update_sig(wallet: &Wallet, key: &SecretSigningKey) -> Vec<u8> {
        // Serialize and hash the wallet commitment
        let new_wallet_comm = wallet.get_wallet_share_commitment();
        let digest = keccak256(new_wallet_comm.to_biguint().to_bytes_be());

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
            executor: mock_peer().peer_id,
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
        // Set the wallet ID to the task queue key so we can generate predictable mock
        // queues
        let mut wallet = mock_empty_wallet();
        wallet.wallet_id = queue_key;

        TaskDescriptor::NewWallet(NewWalletTaskDescriptor { wallet })
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use constants::Scalar;

    use crate::types::wallet_mocks::{mock_empty_wallet, mock_order};

    use super::{
        mocks::gen_wallet_update_sig, NewWalletTaskDescriptor, UpdateWalletTaskDescriptor,
    };

    /// Tests creating a new wallet task with an invalid secret sharing
    #[test]
    #[should_panic(expected = "invalid wallet shares")]
    fn test_invalid_new_wallet_shares() {
        let mut wallet = mock_empty_wallet();
        wallet.blinded_public_shares.orders[0].amount += Scalar::one();

        NewWalletTaskDescriptor::new(wallet).unwrap();
    }

    /// Tests creating an update wallet task with an invalid shares
    #[test]
    #[should_panic(expected = "invalid wallet shares")]
    fn test_invalid_update_wallet_shares() {
        let mut wallet = mock_empty_wallet();
        wallet.blinded_public_shares.orders[0].amount += Scalar::one();

        UpdateWalletTaskDescriptor::new_order(mock_order(), wallet.clone(), wallet, vec![])
            .unwrap();
    }

    /// Tests creating an update wallet task with an invalid signatures
    #[test]
    #[should_panic(expected = "invalid wallet update sig")]
    fn test_invalid_wallet_update_signature() {
        let wallet = mock_empty_wallet();
        let sig = vec![0; 64];

        UpdateWalletTaskDescriptor::new_order(mock_order(), wallet.clone(), wallet, sig).unwrap();
    }

    /// Tests creating a valid update wallet task
    #[test]
    fn test_valid_update_wallet() {
        let wallet = mock_empty_wallet();

        let key = wallet.key_chain.secret_keys.sk_root.as_ref().unwrap();
        let sig = gen_wallet_update_sig(&wallet, key);

        UpdateWalletTaskDescriptor::new_order(mock_order(), wallet.clone(), wallet, sig).unwrap();
    }
}
