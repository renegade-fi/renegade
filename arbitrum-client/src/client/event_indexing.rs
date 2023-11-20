//! Defines `ArbitrumClient` helpers that allow for indexing events
//! emitted by the darkpool contract

use alloy_sol_types::SolCall;
use circuit_types::{traits::BaseType, SizedWalletShare};
use common::types::merkle::{MerkleAuthenticationPath, MerkleTreeCoords};
use constants::{Scalar, MERKLE_HEIGHT};
use ethers::types::TxHash;
use num_bigint::BigUint;

use crate::{
    abi::{
        newWalletCall, processMatchSettleCall, updateWalletCall, NodeChangedFilter,
        WalletUpdatedFilter,
    },
    constants::{DEFAULT_AUTHENTICATION_PATH, SELECTOR_LEN},
    errors::ArbitrumClientError,
    helpers::{
        deserialize_calldata, keccak_hash_scalar, parse_shares_from_new_wallet,
        parse_shares_from_process_match_settle, parse_shares_from_update_wallet,
    },
    serde_def_types::SerdeScalarField,
    types::{
        MatchPayload, ValidMatchSettleStatement, ValidWalletCreateStatement,
        ValidWalletUpdateStatement,
    },
};

use super::ArbitrumClient;

impl ArbitrumClient {
    /// Return the hash of the transaction that last indexed secret shares for
    /// the given public blinder share
    ///
    /// Returns `None` if the public blinder share has not been used
    pub async fn get_public_blinder_tx(
        &self,
        public_blinder_share: Scalar,
    ) -> Result<Option<TxHash>, ArbitrumClientError> {
        let public_blinder_share_hash = keccak_hash_scalar(public_blinder_share)?;
        let events = self
            .darkpool_event_source
            .event::<WalletUpdatedFilter>()
            .topic1(public_blinder_share_hash)
            .from_block(self.deploy_block)
            .query_with_meta()
            .await
            .map_err(|e| ArbitrumClientError::EventQuerying(e.to_string()))?;

        Ok(events.last().map(|(_, meta)| meta.transaction_hash))
    }

    /// Searches on-chain state for the insertion of the given wallet, then
    /// finds the most recent updates of the path's siblings and creates a
    /// Merkle authentication path
    pub async fn find_merkle_authentication_path(
        &self,
        commitment: Scalar,
    ) -> Result<MerkleAuthenticationPath, ArbitrumClientError> {
        let leaf_index = BigUint::from(self.find_commitment_in_state(commitment).await?);

        // Construct a set that holds pairs of (depth, index) values in the
        // authentication path; i.e. the tree coordinates of the sibling nodes
        // in the authentication path
        let mut authentication_path_coords =
            MerkleAuthenticationPath::construct_path_coords(leaf_index.clone(), MERKLE_HEIGHT);

        // For each coordinate in the authentication path,
        // find the last value it was updated to
        let mut path = *DEFAULT_AUTHENTICATION_PATH;
        for coords in authentication_path_coords {
            let events = self
                .darkpool_event_source
                .event::<NodeChangedFilter>()
                .topic1(coords.height.into())
                .topic2(coords.index.into())
                .from_block(self.deploy_block)
                .query()
                .await
                .map_err(|e| ArbitrumClientError::EventQuerying(e.to_string()))?;

            let value = events.last().map(|event| {
                postcard::from_bytes::<SerdeScalarField>(&event.new_value)
                    .map_err(|e| ArbitrumClientError::Serde(e.to_string()))?
                    .0 // Scalar
            });

            if let Some(value) = value {
                path[MERKLE_HEIGHT - coords.height] = value;
            }
        }

        Ok(MerkleAuthenticationPath::new(path, leaf_index, commitment))
    }

    /// A helper to find a commitment's index in the Merkle tree
    pub async fn find_commitment_in_state(
        &self,
        commitment: Scalar,
    ) -> Result<u128, ArbitrumClientError> {
        let commitment_hash = keccak_hash_scalar(commitment)?;
        let events = self
            .darkpool_event_source
            .event::<NodeChangedFilter>()
            .topic3(commitment_hash)
            .from_block(self.deploy_block)
            .query()
            .await
            .map_err(|e| ArbitrumClientError::EventQuerying(e.to_string()))?;

        events
            .last()
            .map(|event| event.index)
            .ok_or(ArbitrumClientError::CommitmentNotFound)
    }

    /// Fetch and parse the public secret shares from the calldata of the given
    /// transaction
    ///
    /// In the case that the referenced transaction is a `process_match_settle`,
    /// we disambiguate between the two parties by adding the public blinder of
    /// the party's shares the caller intends to fetch
    // TODO: Add support for nested calls
    pub async fn fetch_public_shares_from_tx(
        &self,
        public_blinder_share: Scalar,
        tx_hash: TxHash,
    ) -> Result<SizedWalletShare, ArbitrumClientError> {
        let tx = self
            .darkpool_contract
            .client()
            .get_transaction(tx_hash)
            .await
            .map_err(|e| ArbitrumClientError::TxNotFound(e.to_string()))?;

        let calldata: Vec<u8> = tx.input.into();
        let selector = &calldata[..SELECTOR_LEN];
        match selector {
            &<newWalletCall as SolCall>::SELECTOR => parse_shares_from_new_wallet(&calldata),
            &<updateWalletCall as SolCall>::SELECTOR => parse_shares_from_update_wallet(&calldata),
            &<processMatchSettleCall as SolCall>::SELECTOR => {
                parse_shares_from_process_match_settle(&calldata)
            },
            _ => return Err(ArbitrumClientError::InvalidSelector),
        }
    }
}
