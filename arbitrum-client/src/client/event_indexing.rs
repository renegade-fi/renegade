//! Defines `ArbitrumClient` helpers that allow for indexing events
//! emitted by the darkpool contract

use alloy_sol_types::SolCall;
use circuit_types::SizedWalletShare;
use common::types::merkle::MerkleAuthenticationPath;
use constants::{Scalar, MERKLE_HEIGHT};
use ethers::{
    abi::AbiEncode,
    middleware::Middleware,
    types::{TxHash, H256},
};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use renegade_crypto::fields::{scalar_to_u256, u256_to_scalar};
use tracing::{error, instrument};

use crate::{
    abi::{
        newWalletCall, processMatchSettleCall, updateWalletCall, NodeChangedFilter,
        WalletUpdatedFilter,
    },
    constants::{DEFAULT_AUTHENTICATION_PATH, SELECTOR_LEN},
    errors::ArbitrumClientError,
    helpers::{
        parse_shares_from_new_wallet, parse_shares_from_process_match_settle,
        parse_shares_from_update_wallet,
    },
};

use super::ArbitrumClient;

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
        let leaf_index = BigUint::from(self.find_commitment_in_state(commitment).await?);

        // Construct a set that holds pairs of (depth, index) values in the
        // authentication path; i.e. the tree coordinates of the sibling nodes
        // in the authentication path
        let authentication_path_coords =
            MerkleAuthenticationPath::construct_path_coords(leaf_index.clone(), MERKLE_HEIGHT);

        // For each coordinate in the authentication path,
        // find the last value it was updated to
        let mut path = *DEFAULT_AUTHENTICATION_PATH;
        for coords in authentication_path_coords {
            let height = H256::from_slice((coords.height as u8).encode().as_slice());
            let index = H256::from_slice(coords.index.to_u128().unwrap().encode().as_slice());
            let events = self
                .darkpool_contract
                .event::<NodeChangedFilter>()
                .address(self.darkpool_contract.address().into())
                .topic1(height)
                .topic2(index)
                .from_block(self.deploy_block)
                .query()
                .await
                .map_err(|e| ArbitrumClientError::EventQuerying(e.to_string()))?;

            let value = events.last().map(|event| event.new_value);

            if let Some(value) = value {
                path[MERKLE_HEIGHT - coords.height] = u256_to_scalar(&value);
            }
        }

        Ok(MerkleAuthenticationPath::new(path, leaf_index, commitment))
    }

    /// A helper to find a commitment's index in the Merkle tree
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub async fn find_commitment_in_state(
        &self,
        commitment: Scalar,
    ) -> Result<u128, ArbitrumClientError> {
        let events = self
            .darkpool_contract
            .event::<NodeChangedFilter>()
            .address(self.darkpool_contract.address().into())
            .topic3(scalar_to_u256(&commitment))
            .from_block(self.deploy_block)
            .query()
            .await
            .map_err(|e| ArbitrumClientError::EventQuerying(e.to_string()))?;

        events.last().map(|event| event.index).ok_or(ArbitrumClientError::CommitmentNotFound)
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
            sel => {
                error!("invalid selector when parsing public shares: {sel:?}");
                Err(ArbitrumClientError::InvalidSelector)
            },
        }
    }
}
