//! Trait definitions for the `DarkpoolClient`

use alloy::primitives::Address;
use alloy::rpc::types::TransactionRequest;
use alloy_primitives::Selector;
use alloy_sol_types::SolEvent;
use async_trait::async_trait;
use circuit_types::{
    elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot, wallet::Nullifier,
    SizedWalletShare,
};
use common::types::{
    proof_bundles::{
        AtomicMatchSettleBundle, MalleableAtomicMatchSettleBundle, MatchBundle,
        OrderValidityProofBundle, SizedFeeRedemptionBundle, SizedOfflineFeeSettlementBundle,
        SizedRelayerFeeSettlementBundle, SizedValidWalletCreateBundle,
        SizedValidWalletUpdateBundle,
    },
    transfer_auth::TransferAuth,
};
use constants::Scalar;

use crate::errors::DarkpoolClientError;

/// The `DarkpoolImpl` trait defines the functionality that must be implemented
/// for a given blockchain.
#[async_trait]
pub(crate) trait DarkpoolImpl {
    /// The Merkle insertion event type
    type MerkleInsertion: MerkleInsertionEvent;
    /// The Merkle opening event type
    type MerkleOpening: MerkleOpeningNodeEvent;
    /// The nullifier spent event type
    type NullifierSpent: NullifierSpentEvent;
    /// The wallet updated event type
    type WalletUpdated: WalletUpdatedEvent;

    // -----------
    // | Getters |
    // -----------

    /// Get the current Merkle root in the contract
    async fn get_merkle_root(&self) -> Result<Scalar, DarkpoolClientError>;

    /// Get the base fee charged by the contract
    async fn get_protocol_fee(&self) -> Result<FixedPoint, DarkpoolClientError>;

    /// Get the external match fee charged by the contract for the given mint
    async fn get_external_match_fee(
        &self,
        mint: Address,
    ) -> Result<FixedPoint, DarkpoolClientError>;

    /// Get the protocol pubkey
    async fn get_protocol_pubkey(&self) -> Result<EncryptionKey, DarkpoolClientError>;

    /// Check whether a given root is in the contract's history
    async fn check_merkle_root(&self, root: MerkleRoot) -> Result<bool, DarkpoolClientError>;

    /// Check whether a given nullifier is used
    async fn check_nullifier(&self, nullifier: Nullifier) -> Result<bool, DarkpoolClientError>;

    /// Check whether a given blinder is used
    async fn check_public_blinder(&self, blinder: Scalar) -> Result<bool, DarkpoolClientError>;

    /// Whether a given selector is known to the darkpool implementation
    ///
    /// This method is used in share recovery to decide whether a top level
    /// trace calls the darkpool directly. If not, the relayer should trace the
    /// transaction's calls and parse shares from darkpool subcalls.
    fn is_known_selector(&self, selector: Selector) -> bool;

    // -----------
    // | Setters |
    // -----------

    /// Create a new wallet in the darkpool contract
    async fn new_wallet(
        &self,
        valid_wallet_create: &SizedValidWalletCreateBundle,
    ) -> Result<(), DarkpoolClientError>;

    /// Update a wallet in the darkpool contract
    async fn update_wallet(
        &self,
        valid_wallet_update: &SizedValidWalletUpdateBundle,
        wallet_commitment_signature: Vec<u8>,
        transfer_auth: Option<TransferAuth>,
    ) -> Result<(), DarkpoolClientError>;

    /// Process a match settle in the darkpool contract
    async fn process_match_settle(
        &self,
        party0_validity_proofs: &OrderValidityProofBundle,
        party1_validity_proofs: &OrderValidityProofBundle,
        match_bundle: &MatchBundle,
    ) -> Result<(), DarkpoolClientError>;

    /// Settle an fee online; i.e. wherein the receiving part directly receives
    /// the note in their wallet.
    ///
    /// TODO: This method is unused currently, we may want to remove it
    async fn settle_online_relayer_fee(
        &self,
        valid_relayer_fee_settlement: &SizedRelayerFeeSettlementBundle,
        relayer_wallet_commitment_signature: Vec<u8>,
    ) -> Result<(), DarkpoolClientError>;

    /// Settle an offline fee; committing a note to the Merkle state that can be
    /// later redeemed
    async fn settle_offline_fee(
        &self,
        valid_offline_fee_settlement: &SizedOfflineFeeSettlementBundle,
    ) -> Result<(), DarkpoolClientError>;

    /// Redeem a fee note into a wallet
    async fn redeem_fee(
        &self,
        valid_fee_redemption: &SizedFeeRedemptionBundle,
        recipient_wallet_commitment_signature: Vec<u8>,
    ) -> Result<(), DarkpoolClientError>;

    // ----------------
    // | Calldata Gen |
    // ----------------

    /// Generate calldata for a `processAtomicMatchSEttle` call
    fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: &AtomicMatchSettleBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError>;

    /// Generate calldata for a `processMalleableAtomicMatchSettle` call
    fn gen_malleable_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: &MalleableAtomicMatchSettleBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError>;

    // ------------
    // | Recovery |
    // ------------

    /// Parse wallet shares from a given transaction's calldata and selector
    fn parse_shares(
        selector: Selector,
        calldata: &[u8],
        public_blinder_share: Scalar,
    ) -> Result<SizedWalletShare, DarkpoolClientError>;
}

// ----------------
// | Event Traits |
// ----------------

/// A trait for the Merkle insertion event
pub(crate) trait MerkleInsertionEvent: SolEvent {
    /// The height of the insertion
    fn height(&self) -> Result<u64, DarkpoolClientError>;
    /// The new value of the insertion
    fn new_value(&self) -> Result<Scalar, DarkpoolClientError>;
}

/// A trait for the Merkle opening event
pub(crate) trait MerkleOpeningNodeEvent: SolEvent {
    /// The height of the opening
    fn height(&self) -> Result<u64, DarkpoolClientError>;
    /// The index of the opening
    fn index(&self) -> Result<u64, DarkpoolClientError>;
    /// The new value of the opening
    fn new_value(&self) -> Result<Scalar, DarkpoolClientError>;
}

/// A trait for the nullifier spent event
pub(crate) trait NullifierSpentEvent: SolEvent {
    /// The nullifier that was spent
    fn nullifier(&self) -> Result<Nullifier, DarkpoolClientError>;
}

/// A trait for the wallet updated event
pub(crate) trait WalletUpdatedEvent: SolEvent {
    /// The public blinder share that was used
    fn blinder_share(&self) -> Result<Scalar, DarkpoolClientError>;
}
