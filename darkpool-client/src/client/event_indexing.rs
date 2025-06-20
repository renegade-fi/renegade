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
use alloy::rpc::types::Log as RpcLog;
use alloy::rpc::types::TransactionReceipt;
use alloy_contract::Event;
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

use super::{DarkpoolClientInner, RenegadeProvider};

/// The starting range of blocks to query for events
const STARTING_BLOCK_RANGE: u64 = 10;
/// The rate at which to increase the block range
const BLOCK_RANGE_INCREASE_RATE: u64 = 10;

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
        let filter =
            self.event_filter::<D::WalletUpdated>().topic1(scalar_to_u256(public_blinder_share));

        let maybe_event = self.query_latest_event(filter).await?;
        if maybe_event.is_none() {
            return Ok(None);
        }

        let (_event, log) = maybe_event.unwrap();
        let tx_hash = log.transaction_hash.expect(ERR_NO_TX_HASH);
        tracing::Span::current().record("tx_hash", format!("{tx_hash:#x}"));

        Ok(Some(tx_hash))
    }

    /// Searches on-chain state for the insertion of the given wallet, then
    /// finds the most recent updates of the path's siblings and creates a
    /// Merkle authentication path
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub async fn find_merkle_authentication_path(
        &self,
        commitment: Scalar,
    ) -> Result<MerkleAuthenticationPath, DarkpoolClientError> {
        let (_, tx) = self.find_commitment_in_state_with_tx(commitment).await?;
        let tx: TransactionReceipt = self
            .provider()
            .get_transaction_receipt(tx)
            .await
            .map_err(|e| DarkpoolClientError::TxQuerying(e.to_string()))?
            .ok_or(DarkpoolClientError::TxNotFound(tx.to_string()))?;

        self.find_merkle_authentication_path_with_tx(commitment, &tx)
    }

    /// Parses the Merkle authentication path from a transaction receipt
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub fn find_merkle_authentication_path_with_tx(
        &self,
        commitment: Scalar,
        tx: &TransactionReceipt,
    ) -> Result<MerkleAuthenticationPath, DarkpoolClientError> {
        // The number of Merkle insertions that occurred in a transaction
        let mut n_insertions = 0;
        let mut insertion_idx = 0;

        // Parse the Merkle path from the transaction logs
        let mut leaf_index = None;
        let mut all_insertion_events = vec![];
        for log in tx.logs().iter().cloned().map(Log::from) {
            let topic0 = match log.topics().first() {
                Some(topic) => *topic,
                None => continue,
            };

            // Matches cannot depend on associated constants, so we if-else
            if topic0 == D::MerkleInsertion::SIGNATURE_HASH {
                // Track the number of Merkle insertions in the tx, so that we may properly find
                // our commitment in the log stream
                let event = D::MerkleInsertion::decode_log(&log)
                    .map_err(DarkpoolClientError::event_querying)?;

                if event.value() == commitment {
                    insertion_idx = n_insertions;
                    leaf_index = Some(BigUint::from(event.index()));
                }
                n_insertions += 1;
            } else if topic0 == D::MerkleOpening::SIGNATURE_HASH {
                let event = D::MerkleOpening::decode_log(&log)
                    .map_err(DarkpoolClientError::event_querying)?;
                all_insertion_events.push((event.depth(), event.new_value()));
            } else {
                // Ignore other events and unknown events
                continue;
            }
        }

        // Slice only the events corresponding to the correct insertion in the tx
        let start = MERKLE_HEIGHT * insertion_idx;
        let end = start + MERKLE_HEIGHT;
        let mut merkle_path = all_insertion_events[start..end].to_vec();

        // Sort the Merkle path by depth; "deepest" here being the leaves
        merkle_path.sort_by_key(|(depth, _)| Reverse(*depth));
        let siblings =
            merkle_path.into_iter().map(|(_, sibling)| sibling).collect_vec().try_into().map_err(
                |_| DarkpoolClientError::EventQuerying(ERR_MERKLE_PATH_SIBLINGS.to_string()),
            )?;

        let leaf_index = leaf_index.ok_or(DarkpoolClientError::CommitmentNotFound)?;
        Ok(MerkleAuthenticationPath::new(siblings, leaf_index, commitment))
    }

    /// A helper to find a commitment's index in the Merkle tree, also returns
    /// the tx that submitted the commitment
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub async fn find_commitment_in_state_with_tx(
        &self,
        commitment: Scalar,
    ) -> Result<(u128, TxHash), DarkpoolClientError> {
        let filter = self
            .event_filter::<D::MerkleInsertion>()
            .topic2(scalar_to_u256(commitment))
            .from_block(self.deploy_block);
        let (event, log) = self
            .query_latest_event(filter)
            .await?
            .ok_or(DarkpoolClientError::CommitmentNotFound)?;

        Ok((event.index(), log.transaction_hash.expect(ERR_NO_TX_HASH)))
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
    pub async fn fetch_tx_darkpool_calls(
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

    /// Query events paginating by block number
    async fn query_latest_event<E: SolEvent>(
        &self,
        mut filter: Event<&RenegadeProvider, E>,
    ) -> Result<Option<(E, RpcLog)>, DarkpoolClientError> {
        let mut range_size = STARTING_BLOCK_RANGE;
        let mut end = self.block_number().await?;
        let mut start = end.saturating_sub(range_size);

        while end > self.deploy_block {
            // Query events
            filter = filter.from_block(start);
            filter = filter.to_block(end);
            let mut block_events =
                filter.query().await.map_err(DarkpoolClientError::event_querying)?;
            if let Some((event, log)) = block_events.pop() {
                return Ok(Some((event, log)));
            }

            // Update the range if none are found
            end = start;
            range_size *= BLOCK_RANGE_INCREASE_RATE;
            start = end.saturating_sub(range_size);
        }

        Ok(None)
    }
}
