//! Descriptor types for various tasks, refactored here to avoid cyclic
//! dependencies

use circuit_types::{fixed_point::FixedPoint, r#match::MatchResult, transfers::ExternalTransfer};
use constants::Scalar;
use serde::{Deserialize, Serialize};

use super::{
    handshake::HandshakeState,
    proof_bundles::{MatchBundle, OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::{KeyChain, OrderIdentifier, Wallet, WalletIdentifier},
};

/// The task descriptor containing only the parameterization of the task
#[derive(Debug, Serialize, Deserialize)]
pub struct NewWalletTaskDescriptor {
    /// The wallet to create
    pub wallet: Wallet,
}

/// The task descriptor containing only the parameterization of the task
#[derive(Debug, Serialize, Deserialize)]
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

/// The descriptor for the task
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

/// The task descriptor containing only the parameterization of the task
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

/// The task descriptor, containing only the parameterization of the task
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMerkleProofTaskDescriptor {
    /// The wallet to update
    pub wallet: Wallet,
}

/// The task descriptor, containing only the parameterization of the task
#[derive(Debug, Serialize, Deserialize)]
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
