//! Trait definitions for the `DarkpoolClient`

use std::time::Duration;

use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::{primitives::Address, rpc::types::TransactionReceipt};
use alloy_contract::CallDecoder;
use alloy_primitives::Selector;
use alloy_sol_types::SolEvent;
use async_trait::async_trait;
use circuit_types::Nullifier;
use circuit_types::{elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot};
use constants::Scalar;
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use tracing::info;
use types_proofs::{
    IntentOnlyBoundedSettlementBundle, OrderValidityProofBundle, ValidBalanceCreateBundle,
    ValidDepositBundle,
};

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
    async fn get_protocol_fee(
        &self,
        in_token: Address,
        out_token: Address,
    ) -> Result<FixedPoint, DarkpoolClientError>;

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

    /// Whether a given selector is known to the darkpool implementation
    ///
    /// This method is used in share recovery to decide whether a top level
    /// trace calls the darkpool directly. If not, the relayer should trace the
    /// transaction's calls and parse shares from darkpool subcalls.
    fn is_known_selector(selector: Selector) -> bool;

    // -----------
    // | Setters |
    // -----------

    /// Create a new balance in the darkpool contract
    async fn create_balance(
        &self,
        auth: DepositAuth,
        proof_bundle: ValidBalanceCreateBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError>;

    /// Deposit funds into an existing balance in the darkpool contract
    async fn deposit(
        &self,
        auth: DepositAuth,
        proof_bundle: ValidDepositBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError>;

    // ----------------
    // | Calldata Gen |
    // ----------------

    /// Generate calldata for a `processAtomicMatchSEttle` call
    fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        // TODO: Update these types
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: IntentOnlyBoundedSettlementBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError>;

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
