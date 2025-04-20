//! Defines `DarkpoolClient` helpers that allow for indexing events
//! emitted by the darkpool contract

use std::cmp::Reverse;
use std::collections::VecDeque;

use alloy::consensus::constants::SELECTOR_LEN;
use alloy::consensus::Transaction;
use alloy::providers::{ext::DebugApi, Provider};
use alloy::rpc::types::trace::geth::{
    CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
};
use alloy::rpc::types::TransactionReceipt;
use alloy_primitives::{Log, Selector, TxHash};
use alloy_sol_types::SolEvent;
use circuit_types::r#match::ExternalMatchResult;
use circuit_types::SizedWalletShare;
use common::types::merkle::MerkleAuthenticationPath;
use constants::{Scalar, MERKLE_HEIGHT};
use itertools::Itertools;
use num_bigint::BigUint;
use tracing::{info, instrument};

use crate::conversion::scalar_to_u256;
use crate::errors::DarkpoolClientError;
use crate::traits::{DarkpoolImpl, MerkleInsertionEvent, MerkleOpeningNodeEvent};

use super::DarkpoolClientInner;

/// The error message emitted when not enough Merkle path siblings are found
const ERR_MERKLE_PATH_SIBLINGS: &str = "not enough Merkle path siblings found";
/// The error message emitted when a TX hash is not found in a log
const ERR_NO_TX_HASH: &str = "no tx hash for log";

impl<D: DarkpoolImpl> DarkpoolClientInner<D> {
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
    ) -> Result<Option<TxHash>, DarkpoolClientError> {
        let events = self
            .event_filter::<D::WalletUpdated>()
            .topic1(scalar_to_u256(public_blinder_share))
            .from_block(self.deploy_block)
            .query()
            .await
            .map_err(DarkpoolClientError::event_querying)?;

        // Fetch the tx hash from the latest event
        let tx_hash = events.last().map(|(_, meta)| meta.transaction_hash.expect(ERR_NO_TX_HASH));
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
    ) -> Result<MerkleAuthenticationPath, DarkpoolClientError> {
        unimplemented!("not implemented on alloy-v0.11.0 branch")
    }

    /// A helper to find a commitment's index in the Merkle tree, also returns
    /// the tx that submitted the commitment
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub async fn find_commitment_in_state_with_tx(
        &self,
        commitment: Scalar,
    ) -> Result<(u128, TxHash), DarkpoolClientError> {
        let events = self
            .event_filter::<D::MerkleInsertion>()
            .topic2(scalar_to_u256(commitment))
            .from_block(self.deploy_block)
            .query()
            .await
            .map_err(DarkpoolClientError::event_querying)?;

        events
            .last()
            .map(|(event, meta)| (event.index(), meta.transaction_hash.expect(ERR_NO_TX_HASH)))
            .ok_or(DarkpoolClientError::CommitmentNotFound)
    }

    /// Fetch and parse the public secret shares from the calldata of the
    /// transaction that updated the wallet with the given blinder
    #[instrument(skip_all, err, fields(public_blinder_share = %public_blinder_share))]
    pub async fn fetch_public_shares_for_blinder(
        &self,
        public_blinder_share: Scalar,
    ) -> Result<SizedWalletShare, DarkpoolClientError> {
        let tx_hash = self
            .get_public_blinder_tx(public_blinder_share)
            .await?
            .ok_or(DarkpoolClientError::BlinderNotFound)?;

        let tx = self
            .provider()
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(DarkpoolClientError::tx_querying)?
            .ok_or(DarkpoolClientError::TxNotFound(tx_hash.to_string()))?;

        let calldata: Vec<u8> = tx.input().to_vec();
        let selector = Selector::from_slice(&calldata[..SELECTOR_LEN]);
        if D::is_known_selector(selector) {
            D::parse_shares(selector, &calldata, public_blinder_share)
        } else {
            info!("unknown selector {selector:?}, searching calldata...");
            self.fetch_public_shares_for_unknown_selector(tx_hash, public_blinder_share).await
        }
    }

    /// Fetch all external matches in a given transaction
    pub async fn find_external_matches_in_tx(
        &self,
        tx_hash: TxHash,
    ) -> Result<Vec<ExternalMatchResult>, DarkpoolClientError> {
        // Get all darkpool subcalls in the tx
        let mut matches = Vec::new();
        let darkpool_calls = self.fetch_tx_darkpool_calls(tx_hash).await?;
        for frame in darkpool_calls.into_iter() {
            let calldata: &[u8] = &frame.input;
            if let Some(match_res) = D::parse_external_match(calldata)? {
                matches.push(match_res);
            }
        }

        Ok(matches)
    }

    // -----------
    // | Helpers |
    // -----------

    // --- Fetch Shares --- //

    /// Fetch the public shares from a transaction that has an unknown selector
    async fn fetch_public_shares_for_unknown_selector(
        &self,
        tx_hash: TxHash,
        public_blinder_share: Scalar,
    ) -> Result<SizedWalletShare, DarkpoolClientError> {
        // Parse the call trace for calls to the darkpool contract
        let calls = self.fetch_tx_darkpool_calls(tx_hash).await?;
        if calls.is_empty() {
            let hash_str = format!("{tx_hash:#x}");
            return Err(DarkpoolClientError::DarkpoolSubcallNotFound(hash_str));
        }

        // Attempt to parse public shares from the calldata of each call
        for call in calls {
            let data = call.input;
            let selector = data[..SELECTOR_LEN].try_into().unwrap();
            let public_share = D::parse_shares(selector, &data, public_blinder_share)?;
            if public_share.blinder == public_blinder_share {
                return Ok(public_share);
            }
        }

        Err(DarkpoolClientError::InvalidSelector)
    }

    // --- Call Tracing --- //

    /// Fetch the darkpool calls from a given transaction
    async fn fetch_tx_darkpool_calls(
        &self,
        tx_hash: TxHash,
    ) -> Result<Vec<CallFrame>, DarkpoolClientError> {
        let trace = self.fetch_call_trace(tx_hash).await?;
        Ok(self.find_darkpool_subcalls(&trace))
    }

    /// Fetch the call trace for a given transaction
    async fn fetch_call_trace(&self, tx_hash: TxHash) -> Result<GethTrace, DarkpoolClientError> {
        // Fetch a call trace for the transaction
        let options = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            ..Default::default()
        };

        self.provider()
            .debug_trace_transaction(tx_hash, options)
            .await
            .map_err(DarkpoolClientError::tx_querying)
    }

    /// Find all darkpool sub-calls in a call trace
    fn find_darkpool_subcalls(&self, trace: &GethTrace) -> Vec<CallFrame> {
        let darkpool = self.darkpool_addr();
        let global_call_frame = match trace {
            GethTrace::CallTracer(frame) => frame.clone(),
            _ => return vec![],
        };

        // BFS the call tree to find all calls to the darkpool contract
        let mut darkpool_calls = vec![];
        let mut calls = VecDeque::from([global_call_frame]);
        while let Some(call) = calls.pop_front() {
            if let Some(to) = call.to
                && to == darkpool
            {
                darkpool_calls.push(call.clone());
            }

            // Add the sub-calls to the queue
            calls.extend(call.calls);
        }

        darkpool_calls
    }
}
