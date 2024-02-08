//! Defines task related types

use circuit_types::{
    fixed_point::FixedPoint, keychain::PublicSigningKey, r#match::MatchResult,
    transfers::ExternalTransfer,
};
use constants::Scalar;
use ethers_rs::keccak256;
use k256::ecdsa::{Signature, VerifyingKey as K256VerifyingKey};
use serde::{Deserialize, Serialize};
use signature::hazmat::PrehashVerifier;
use uuid::Uuid;

use super::{
    gossip::WrappedPeerId,
    handshake::HandshakeState,
    proof_bundles::{MatchBundle, OrderValidityProofBundle, OrderValidityWitnessBundle},
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
}

/// The state of a queued task
///
/// TODO: We can add completed and failed states if/when we implement a task
/// history
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status")]
pub enum QueuedTaskState {
    /// The task is waiting in the queue
    Queued,
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
}

/// A wrapper around the task descriptors
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum TaskDescriptor {
    /// The task descriptor for the `NewWallet` task
    NewWallet(NewWalletTaskDescriptor),
    /// The task descriptor for the `LookupWallet` task
    LookupWallet(LookupWalletTaskDescriptor),
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
            TaskDescriptor::SettleMatch(_) => {
                unimplemented!("SettleMatch should preempt queue, no key needed")
            },
            TaskDescriptor::SettleMatchInternal(_) => {
                unimplemented!("SettleMatchInternal should preempt queue, no key needed")
            },
            TaskDescriptor::UpdateMerkleProof(task) => task.wallet.wallet_id,
            TaskDescriptor::UpdateWallet(task) => task.old_wallet.wallet_id,
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
        match_bundle: MatchBundle,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
    ) -> Result<Self, String> {
        Ok(SettleMatchTaskDescriptor {
            wallet_id,
            handshake_state,
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

/// The task descriptor containing only the parameterization of the
/// `UpdateWallet` task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateWalletTaskDescriptor {
    /// The timestamp at which the task was initiated, used to timestamp orders
    pub timestamp_received: u64,
    /// The external transfer, if one exists
    pub external_transfer: Option<ExternalTransfer>,
    /// The old wallet before update
    pub old_wallet: Wallet,
    /// The new wallet after update
    pub new_wallet: Wallet,
    /// A signature of the `VALID WALLET UPDATE` statement by the wallet's root
    /// key, the contract uses this to authorize the update
    pub wallet_update_signature: Vec<u8>,
}

impl UpdateWalletTaskDescriptor {
    /// Constructor
    pub fn new(
        timestamp_received: u64,
        external_transfer: Option<ExternalTransfer>,
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
            timestamp_received,
            external_transfer,
            old_wallet,
            new_wallet,
            wallet_update_signature,
        })
    }
}

impl From<UpdateWalletTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: UpdateWalletTaskDescriptor) -> Self {
        TaskDescriptor::UpdateWallet(descriptor)
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
    let sig = Signature::from_slice(wallet_update_signature).map_err(|e| e.to_string())?;
    key.verify_prehash(&digest, &sig).map_err(|e| e.to_string())
}

// ---------
// | Mocks |
// ---------

#[cfg(any(test, feature = "mocks"))]
pub mod mocks {
    //! Mocks for the task descriptors
    use circuit_types::keychain::SecretSigningKey;
    use ethers_rs::keccak256;
    use k256::ecdsa::{Signature, SigningKey as K256SigningKey};
    use signature::hazmat::PrehashSigner;

    use crate::types::{
        gossip::mocks::mock_peer, tasks::TaskIdentifier, wallet::Wallet,
        wallet_mocks::mock_empty_wallet,
    };

    use super::{QueuedTask, QueuedTaskState, TaskDescriptor, TaskQueueKey};

    /// Generate the wallet update signature for a new wallet
    pub fn gen_wallet_update_sig(wallet: &Wallet, key: &SecretSigningKey) -> Vec<u8> {
        // Serialize and hash the wallet commitment
        let new_wallet_comm = wallet.get_wallet_share_commitment();
        let digest = keccak256(new_wallet_comm.to_biguint().to_bytes_be());

        // Sign the message
        let signing_key: K256SigningKey = key.try_into().unwrap();
        let sig: Signature = signing_key.sign_prehash(&digest).unwrap();

        sig.to_bytes().to_vec()
    }

    /// Get a dummy queued task
    pub fn mock_queued_task(queue_key: TaskQueueKey) -> super::QueuedTask {
        QueuedTask {
            id: TaskIdentifier::new_v4(),
            executor: mock_peer().peer_id,
            state: QueuedTaskState::Queued,
            descriptor: mock_task_descriptor(queue_key),
        }
    }

    /// Get a dummy task descriptor
    pub fn mock_task_descriptor(queue_key: TaskQueueKey) -> super::TaskDescriptor {
        // Set the wallet ID to the task queue key so we can generate predictable mock
        // queues
        let mut wallet = mock_empty_wallet();
        wallet.wallet_id = queue_key;

        TaskDescriptor::NewWallet(super::NewWalletTaskDescriptor { wallet })
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use constants::Scalar;

    use crate::types::wallet_mocks::mock_empty_wallet;

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

        UpdateWalletTaskDescriptor::new(
            0,    // timestamp
            None, // transfer
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

        UpdateWalletTaskDescriptor::new(
            0,    // timestamp
            None, // transfer
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

        UpdateWalletTaskDescriptor::new(
            0,    // timestamp
            None, // transfer
            wallet.clone(),
            wallet,
            sig,
        )
        .unwrap();
    }
}
