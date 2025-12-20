//! Trait definitions for the `DarkpoolClient`

use std::time::Duration;

use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::{primitives::Address, rpc::types::TransactionReceipt};
use alloy_contract::CallDecoder;
use alloy_primitives::Selector;
use alloy_sol_types::SolEvent;
use async_trait::async_trait;
use circuit_types::r#match::ExternalMatchResult;
use circuit_types::{
    SizedWalletShare, elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot,
    wallet::Nullifier,
};
use common::types::proof_bundles::{
    ValidMalleableMatchSettleAtomicBundle, ValidMatchSettleAtomicBundle, ValidMatchSettleBundle,
};
use common::types::{
    proof_bundles::{
        OrderValidityProofBundle, SizedFeeRedemptionBundle, SizedOfflineFeeSettlementBundle,
        SizedRelayerFeeSettlementBundle, SizedValidWalletCreateBundle,
        SizedValidWalletUpdateBundle,
    },
    transfer_auth::TransferAuth,
};
use constants::Scalar;
use tracing::info;

use crate::client::{DarkpoolCallBuilder, RenegadeProvider};
use crate::errors::DarkpoolClientError;

// -------------
// | Constants |
// -------------

/// The timeout for awaiting the receipt of a pending transaction
const TX_RECEIPT_TIMEOUT: Duration = Duration::from_secs(15);

/// The multiple of the gas price estimate we use for submitting a transaction
const GAS_PRICE_MULTIPLIER: u128 = 2;

/// The `DarkpoolImpl` trait defines the functionality that must be implemented
/// for a given blockchain.
#[async_trait]
pub trait DarkpoolImpl: Clone {
    /// The Merkle insertion event type
    type MerkleInsertion: MerkleInsertionEvent;
    /// The Merkle opening event type
    type MerkleOpening: MerkleOpeningNodeEvent;
    /// The nullifier spent event type
    type NullifierSpent: NullifierSpentEvent;
    /// The wallet updated event type
    type WalletUpdated: WalletUpdatedEvent;

    /// Create a new darkpool implementation
    fn new(darkpool_addr: Address, provider: RenegadeProvider) -> Self;

    // -----------
    // | Getters |
    // -----------

    /// Get the address of the darkpool contract
    fn address(&self) -> Address;

    /// Get a reference to the provider
    fn provider(&self) -> &RenegadeProvider;

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
    async fn is_nullifier_spent(&self, nullifier: Nullifier) -> Result<bool, DarkpoolClientError>;

    /// Check whether a given blinder is used
    async fn is_blinder_used(&self, blinder: Scalar) -> Result<bool, DarkpoolClientError>;

    /// Whether a given selector is known to the darkpool implementation
    ///
    /// This method is used in share recovery to decide whether a top level
    /// trace calls the darkpool directly. If not, the relayer should trace the
    /// transaction's calls and parse shares from darkpool subcalls.
    fn is_known_selector(selector: Selector) -> bool;

    // -----------
    // | Setters |
    // -----------

    /// Create a new wallet in the darkpool contract
    async fn new_wallet(
        &self,
        valid_wallet_create: &SizedValidWalletCreateBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError>;

    /// Update a wallet in the darkpool contract
    async fn update_wallet(
        &self,
        valid_wallet_update: &SizedValidWalletUpdateBundle,
        wallet_commitment_signature: Vec<u8>,
        transfer_auth: Option<TransferAuth>,
    ) -> Result<TransactionReceipt, DarkpoolClientError>;

    /// Process a match settle in the darkpool contract
    async fn process_match_settle(
        &self,
        party0_validity_proofs: &OrderValidityProofBundle,
        party1_validity_proofs: &OrderValidityProofBundle,
        match_bundle: ValidMatchSettleBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError>;

    /// Settle an fee online; i.e. wherein the receiving part directly receives
    /// the note in their wallet.
    ///
    /// TODO: This method is unused currently, we may want to remove it
    async fn settle_online_relayer_fee(
        &self,
        valid_relayer_fee_settlement: &SizedRelayerFeeSettlementBundle,
        relayer_wallet_commitment_signature: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError>;

    /// Settle an offline fee; committing a note to the Merkle state that can be
    /// later redeemed
    async fn settle_offline_fee(
        &self,
        valid_offline_fee_settlement: &SizedOfflineFeeSettlementBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError>;

    /// Redeem a fee note into a wallet
    async fn redeem_fee(
        &self,
        valid_fee_redemption: &SizedFeeRedemptionBundle,
        recipient_wallet_commitment_signature: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError>;

    // ----------------
    // | Calldata Gen |
    // ----------------

    /// Generate calldata for a `processAtomicMatchSEttle` call
    fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: ValidMatchSettleAtomicBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError>;

    /// Generate calldata for a `processMalleableAtomicMatchSettle` call
    fn gen_malleable_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: ValidMalleableMatchSettleAtomicBundle,
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

    /// Parse an external match from a given transaction's calldata
    fn parse_external_match(
        calldata: &[u8],
    ) -> Result<Option<ExternalMatchResult>, DarkpoolClientError>;

    // -----------
    // | Testing |
    // -----------

    /// Clear the Merkle tree for testing
    #[cfg(feature = "integration")]
    async fn clear_merkle_tree(&self) -> Result<TransactionReceipt, DarkpoolClientError>;
}

/// A trait defining useful methods automatically implemented for all darkpool
/// implementations
#[async_trait]
pub trait DarkpoolImplExt: DarkpoolImpl {
    // ----------------
    // | Transactions |
    // ----------------

    /// Send a txn and return the receipt
    ///
    /// We implement this at the trait level to give a useful default
    /// implementation
    async fn send_tx<'a, C>(
        &self,
        tx: DarkpoolCallBuilder<'a, C>,
    ) -> Result<TransactionReceipt, DarkpoolClientError>
    where
        C: CallDecoder + Send + Sync,
    {
        let gas_price = self.get_adjusted_gas_price().await?;
        let pending_tx = tx
            .gas_price(gas_price)
            .send()
            .await
            .map_err(DarkpoolClientError::contract_interaction)?;

        // TODO: Remove this debug log
        info!("Pending tx hash: {:#x}", pending_tx.tx_hash());
        let receipt = pending_tx
            .with_timeout(Some(TX_RECEIPT_TIMEOUT))
            .get_receipt()
            .await
            .map_err(DarkpoolClientError::contract_interaction)?;

        // Check for failure
        if !receipt.status() {
            let error_msg = format!("tx ({:#x}) failed with status 0", receipt.transaction_hash);
            return Err(DarkpoolClientError::contract_interaction(error_msg));
        }

        Ok(receipt)
    }

    /// Get the adjusted gas price for submitting a transaction
    ///
    /// We double the latest basefee to prevent reverts
    async fn get_adjusted_gas_price(&self) -> Result<u128, DarkpoolClientError> {
        // Set the gas price to 2x the latest gas price estimate for simplicity
        let gas_price = self.provider().get_gas_price().await.map_err(DarkpoolClientError::rpc)?;
        let adjusted_gas_price = gas_price * GAS_PRICE_MULTIPLIER;
        Ok(adjusted_gas_price)
    }
}
impl<T: DarkpoolImpl> DarkpoolImplExt for T {}

// ----------------
// | Event Traits |
// ----------------

/// A trait for the Merkle insertion event
pub trait MerkleInsertionEvent: SolEvent {
    /// The index of the insertion
    fn index(&self) -> u128;
    /// The value that was inserted
    fn value(&self) -> Scalar;
}

/// A trait for the Merkle opening event
pub trait MerkleOpeningNodeEvent: SolEvent {
    /// The height of the opening
    fn depth(&self) -> u64;
    /// The index of the opening
    fn index(&self) -> u64;
    /// The new value of the opening
    fn new_value(&self) -> Scalar;
}

/// A trait for the nullifier spent event
pub trait NullifierSpentEvent: SolEvent {
    /// The nullifier that was spent
    fn nullifier(&self) -> Nullifier;
}

/// A trait for the wallet updated event
pub trait WalletUpdatedEvent: SolEvent {
    /// The public blinder share that was used
    fn blinder_share(&self) -> Scalar;
}
