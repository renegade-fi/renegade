//! The Solidity implementation of the darkpool client

use alloy::{
    consensus::constants::SELECTOR_LEN,
    rpc::types::{TransactionReceipt, TransactionRequest},
};
use alloy_primitives::{Address, Selector, U256};
use async_trait::async_trait;
use circuit_types::{
    Nullifier, elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot,
};
use constants::{MERKLE_HEIGHT, Scalar};
use crypto::fields::{scalar_to_u256, u256_to_scalar};
use renegade_solidity_abi::v2::IDarkpoolV2::{
    self, DepositAuth, DepositProofBundle, IDarkpoolV2Instance,
    MerkleInsertion as AbiMerkleInsertion, MerkleOpeningNode as AbiMerkleOpeningNode,
    NullifierSpent as AbiNullifierSpent, ObligationBundle, SettlementBundle,
};
use types_core::Token;
use types_proofs::{
    IntentOnlyBoundedSettlementBundle, OrderValidityProofBundle, ValidBalanceCreateBundle,
    ValidDepositBundle,
};

use crate::{
    client::RenegadeProvider,
    errors::DarkpoolClientError,
    traits::{
        DarkpoolImpl, DarkpoolImplExt, MerkleInsertionEvent, MerkleOpeningNodeEvent,
        NullifierSpentEvent,
    },
};

/// The set of known selectors for the Solidity darkpool
/// TODO: Add known selectors
const KNOWN_SELECTORS: [[u8; SELECTOR_LEN]; 0] = [];

/// The Solidity darkpool implementation
#[derive(Clone)]
pub struct SolidityDarkpool {
    /// The darkpool instance
    darkpool: IDarkpoolV2Instance<RenegadeProvider>,
}

impl SolidityDarkpool {
    /// Get a reference to the darkpool instance
    pub fn darkpool(&self) -> &IDarkpoolV2Instance<RenegadeProvider> {
        &self.darkpool
    }

    /// Get the Merkle depth to use for contract calls
    pub(crate) fn merkle_depth(&self) -> U256 {
        U256::from(MERKLE_HEIGHT as u64)
    }
}

#[async_trait]
impl DarkpoolImpl for SolidityDarkpool {
    type MerkleInsertion = AbiMerkleInsertion;
    type MerkleOpening = AbiMerkleOpeningNode;
    type NullifierSpent = AbiNullifierSpent;

    fn new(darkpool_addr: Address, provider: RenegadeProvider) -> Self {
        Self { darkpool: IDarkpoolV2Instance::new(darkpool_addr, provider) }
    }

    fn address(&self) -> Address {
        *self.darkpool.address()
    }

    fn provider(&self) -> &RenegadeProvider {
        self.darkpool.provider()
    }

    // -----------
    // | Getters |
    // -----------

    async fn get_merkle_root(&self) -> Result<Scalar, DarkpoolClientError> {
        let depth = U256::from(MERKLE_HEIGHT as u64);
        self.darkpool
            .getMerkleRoot(depth)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(u256_to_scalar)
    }

    async fn get_protocol_fee(
        &self,
        in_token: Address,
        out_token: Address,
    ) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool
            .getProtocolFee(in_token, out_token)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(|r| r.into())
    }

    async fn get_default_protocol_fee(&self) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool
            .getDefaultProtocolFee()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(|r| r.into())
    }

    async fn get_protocol_pubkey(&self) -> Result<EncryptionKey, DarkpoolClientError> {
        let pubkey = self
            .darkpool()
            .getProtocolFeeKey()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)?;

        let x = u256_to_scalar(pubkey.point.x);
        let y = u256_to_scalar(pubkey.point.y);
        Ok(EncryptionKey { x, y })
    }

    async fn check_merkle_root(&self, root: MerkleRoot) -> Result<bool, DarkpoolClientError> {
        let root_u256 = scalar_to_u256(&root);
        self.darkpool()
            .rootInHistory(root_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    async fn is_nullifier_spent(&self, nullifier: Nullifier) -> Result<bool, DarkpoolClientError> {
        let nullifier_u256 = scalar_to_u256(&nullifier);
        self.darkpool()
            .nullifierSpent(nullifier_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    fn is_known_selector(selector: Selector) -> bool {
        KNOWN_SELECTORS.contains(&selector.0)
    }

    // -----------
    // | Setters |
    // -----------

    async fn create_balance(
        &self,
        auth: DepositAuth,
        proof_bundle: ValidBalanceCreateBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let bundle = proof_bundle.into_inner();
        let contract_statement: IDarkpoolV2::ValidBalanceCreateStatement = bundle.statement.into();
        let proof = bundle.proof.into();

        let calldata_bundle = IDarkpoolV2::NewBalanceDepositProofBundle {
            merkleDepth: self.merkle_depth(),
            statement: contract_statement,
            proof,
        };
        let tx = self.darkpool().depositNewBalance(auth, calldata_bundle);
        self.send_tx(tx).await
    }

    async fn deposit(
        &self,
        auth: DepositAuth,
        proof_bundle: ValidDepositBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let bundle = proof_bundle.into_inner();
        let contract_statement: IDarkpoolV2::ValidDepositStatement = bundle.statement.into();
        let proof = bundle.proof.into();

        let calldata_bundle = DepositProofBundle {
            merkleDepth: self.merkle_depth(),
            statement: contract_statement,
            proof,
        };
        let tx = self.darkpool().deposit(auth, calldata_bundle);

        self.send_tx(tx).await
    }

    async fn settle_match(
        &self,
        obligation_bundle: ObligationBundle,
        settlement_bundle0: SettlementBundle,
        settlement_bundle1: SettlementBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let tx =
            self.darkpool().settleMatch(obligation_bundle, settlement_bundle0, settlement_bundle1);

        self.send_tx(tx).await
    }

    // ----------------
    // | Calldata Gen |
    // ----------------

    fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: IntentOnlyBoundedSettlementBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError> {
        unimplemented!(
            "gen_atomic_match_settle_calldata needs to be adapted for IntentOnlyBoundedSettlementBundle"
        )
    }

    // -----------
    // | Testing |
    // -----------

    #[cfg(feature = "integration")]
    async fn clear_merkle_tree(&self) -> Result<TransactionReceipt, DarkpoolClientError> {
        unimplemented!("clear_merkle_tree not yet implemented for Solidity darkpool")
    }
}

// ----------
// | Events |
// ----------

impl MerkleInsertionEvent for AbiMerkleInsertion {
    fn index(&self) -> u128 {
        self.index
    }

    fn value(&self) -> Scalar {
        u256_to_scalar(self.value)
    }
}

impl MerkleOpeningNodeEvent for AbiMerkleOpeningNode {
    fn depth(&self) -> u64 {
        self.depth as u64
    }

    fn index(&self) -> u64 {
        self.index as u64
    }

    fn new_value(&self) -> Scalar {
        u256_to_scalar(self.new_value)
    }
}

impl NullifierSpentEvent for AbiNullifierSpent {
    fn nullifier(&self) -> Nullifier {
        u256_to_scalar(self.nullifier)
    }
}
