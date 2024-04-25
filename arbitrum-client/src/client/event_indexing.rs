//! Defines `ArbitrumClient` helpers that allow for indexing events
//! emitted by the darkpool contract

use std::cmp::Reverse;

use alloy_sol_types::SolCall;
use circuit_types::SizedWalletShare;
use common::types::merkle::MerkleAuthenticationPath;
use constants::Scalar;
use ethers::contract::EthLogDecode;
use ethers::{
    middleware::Middleware,
    types::{TransactionReceipt, TxHash},
};
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::fields::{scalar_to_u256, u256_to_scalar};
use tracing::{error, instrument};

use crate::abi::MerkleInsertionFilter;
use crate::{
    abi::{
        newWalletCall, processMatchSettleCall, redeemFeeCall, settleOfflineFeeCall,
        settleOnlineRelayerFeeCall, updateWalletCall, DarkpoolContractEvents,
        MerkleOpeningNodeFilter, WalletUpdatedFilter,
    },
    constants::SELECTOR_LEN,
    errors::ArbitrumClientError,
    helpers::{
        parse_shares_from_new_wallet, parse_shares_from_process_match_settle,
        parse_shares_from_redeem_fee, parse_shares_from_settle_offline_fee,
        parse_shares_from_settle_online_relayer_fee, parse_shares_from_update_wallet,
    },
};

use super::ArbitrumClient;

/// The error message emitted when not enough Merkle path siblings are found
const ERR_MERKLE_PATH_SIBLINGS: &str = "not enough Merkle path siblings found";

impl ArbitrumClient {
    /// Return the hash of the transaction that last indexed secret shares for
    /// the given public blinder share
    ///
    /// Returns `None` if the public blinder share has not been used
    #[instrument(skip_all, err, fields(
        tx_hash,
        public_blinder_share = %public_blinder_share
    ))]
    pub async fn get_public_blinder_tx(
        &self,
        public_blinder_share: Scalar,
    ) -> Result<Option<TxHash>, ArbitrumClientError> {
        let events = self
            .darkpool_contract
            .event::<WalletUpdatedFilter>()
            .address(self.darkpool_contract.address().into())
            .topic1(scalar_to_u256(&public_blinder_share))
            .from_block(self.deploy_block)
            .query_with_meta()
            .await
            .map_err(|e| ArbitrumClientError::EventQuerying(e.to_string()))?;

        let tx_hash = events.last().map(|(_, meta)| meta.transaction_hash);

        if let Some(tx_hash) = tx_hash {
            tracing::Span::current().record("tx_hash", format!("{:#x}", tx_hash));
        }

        Ok(tx_hash)
    }

    /// Searches on-chain state for the insertion of the given wallet, then
    /// finds the most recent updates of the path's siblings and creates a
    /// Merkle authentication path
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub async fn find_merkle_authentication_path(
        &self,
        commitment: Scalar,
    ) -> Result<MerkleAuthenticationPath, ArbitrumClientError> {
        let (index, tx) = self.find_commitment_in_state_with_tx(commitment).await?;
        let leaf_index = BigUint::from(index);
        let tx: TransactionReceipt = self
            .darkpool_contract
            .client()
            .get_transaction_receipt(tx)
            .await
            .map_err(|e| ArbitrumClientError::TxQuerying(e.to_string()))?
            .ok_or(ArbitrumClientError::TxNotFound(tx.to_string()))?;

        // Parse the Merkle path from the transaction logs
        let mut merkle_path = vec![];
        for eth_log in tx.logs.into_iter() {
            match DarkpoolContractEvents::decode_log(&eth_log.into()) {
                Ok(DarkpoolContractEvents::MerkleOpeningNodeFilter(MerkleOpeningNodeFilter {
                    height: depth,
                    new_value,
                    ..
                })) => {
                    merkle_path.push((depth, u256_to_scalar(&new_value)));
                },
                // Ignore other events and unknown events
                _ => continue,
            }
        }

        // Sort the Merkle path by depth; "deepest" here being the leaves
        merkle_path.sort_by_key(|(depth, _)| Reverse(*depth));
        let siblings =
            merkle_path.into_iter().map(|(_, sibling)| sibling).collect_vec().try_into().map_err(
                |_| ArbitrumClientError::EventQuerying(ERR_MERKLE_PATH_SIBLINGS.to_string()),
            )?;

        Ok(MerkleAuthenticationPath::new(siblings, leaf_index, commitment))
    }

    /// A helper to find a commitment's index in the Merkle tree
    ///
    /// Returns the tx that submitted the commitment
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub async fn find_commitment_in_state(
        &self,
        commitment: Scalar,
    ) -> Result<u128, ArbitrumClientError> {
        let (index, _) = self.find_commitment_in_state_with_tx(commitment).await?;
        Ok(index)
    }

    /// A helper to find a commitment's index in the Merkle tree, also returns
    /// the tx that submitted the commitment
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub async fn find_commitment_in_state_with_tx(
        &self,
        commitment: Scalar,
    ) -> Result<(u128, TxHash), ArbitrumClientError> {
        let events = self
            .darkpool_contract
            .event::<MerkleInsertionFilter>()
            .address(self.darkpool_contract.address().into())
            .topic2(scalar_to_u256(&commitment))
            .from_block(self.deploy_block)
            .query_with_meta()
            .await
            .map_err(|e| ArbitrumClientError::EventQuerying(e.to_string()))?;

        events
            .last()
            .map(|(event, meta)| (event.index, meta.transaction_hash))
            .ok_or(ArbitrumClientError::CommitmentNotFound)
    }

    /// Fetch and parse the public secret shares from the calldata of the
    /// transaction that updated the wallet with the given blinder
    // TODO: Add support for nested calls
    #[instrument(skip_all, err, fields(public_blinder_share = %public_blinder_share))]
    pub async fn fetch_public_shares_for_blinder(
        &self,
        public_blinder_share: Scalar,
    ) -> Result<SizedWalletShare, ArbitrumClientError> {
        let tx_hash = self
            .get_public_blinder_tx(public_blinder_share)
            .await?
            .ok_or(ArbitrumClientError::BlinderNotFound)?;

        let tx = self
            .darkpool_contract
            .client()
            .get_transaction(tx_hash)
            .await
            .map_err(|e| ArbitrumClientError::TxQuerying(e.to_string()))?
            .ok_or(ArbitrumClientError::TxNotFound(tx_hash.to_string()))?;

        let calldata: Vec<u8> = tx.input.to_vec();
        let selector: [u8; 4] = calldata[..SELECTOR_LEN].try_into().unwrap();
        match selector {
            <newWalletCall as SolCall>::SELECTOR => parse_shares_from_new_wallet(&calldata),
            <updateWalletCall as SolCall>::SELECTOR => parse_shares_from_update_wallet(&calldata),
            <processMatchSettleCall as SolCall>::SELECTOR => {
                parse_shares_from_process_match_settle(&calldata, public_blinder_share)
            },
            <settleOnlineRelayerFeeCall as SolCall>::SELECTOR => {
                parse_shares_from_settle_online_relayer_fee(&calldata, public_blinder_share)
            },
            <settleOfflineFeeCall as SolCall>::SELECTOR => {
                parse_shares_from_settle_offline_fee(&calldata)
            },
            <redeemFeeCall as SolCall>::SELECTOR => parse_shares_from_redeem_fee(&calldata),
            sel => {
                error!("invalid selector when parsing public shares: {sel:?}");
                Err(ArbitrumClientError::InvalidSelector)
            },
        }
    }
}
