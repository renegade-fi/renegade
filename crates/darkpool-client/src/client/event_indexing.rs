//! Defines `DarkpoolClient` helpers that allow for indexing events
//! emitted by the darkpool contract

use std::cmp::Reverse;
use std::collections::VecDeque;

use alloy::consensus::constants::SELECTOR_LEN;
use alloy::providers::{Provider, ext::DebugApi};
use alloy::rpc::types::Log as RpcLog;
use alloy::rpc::types::TransactionReceipt;
use alloy::rpc::types::trace::geth::{
    CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
};
use alloy_contract::Event;
use alloy_primitives::{Log, TxHash};
use alloy_sol_types::{SolCall, SolEvent};
use circuit_types::Amount;
use constants::{MERKLE_HEIGHT, Scalar};
use crypto::fields::{scalar_to_u256, u256_to_scalar};
use darkpool_types::bounded_match_result::BoundedMatchResult;
use itertools::Itertools;
use renegade_solidity_abi::v2::IDarkpoolV2::{
    self, MerkleInsertion as AbiMerkleInsertion, MerkleOpeningNode as AbiMerkleOpeningNode,
};
use renegade_solidity_abi::v2::relayer_types::u256_to_u128;
use tracing::instrument;
use types_account::MerkleAuthenticationPath;

use crate::errors::DarkpoolClientError;

use super::{DarkpoolClient, RenegadeProvider};

/// The starting range of blocks to query for events
const STARTING_BLOCK_RANGE: u64 = 10;
/// The rate at which to increase the block range
const BLOCK_RANGE_INCREASE_RATE: u64 = 10;

/// The error message emitted when not enough Merkle path siblings are found
const ERR_MERKLE_PATH_SIBLINGS: &str = "not enough Merkle path siblings found";
/// The error message emitted when a TX hash is not found in a log
const ERR_NO_TX_HASH: &str = "no tx hash for log";

impl DarkpoolClient {
    /// Searches on-chain state for the insertion of the given commitment, then
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

            if topic0 == AbiMerkleInsertion::SIGNATURE_HASH {
                // Track the number of Merkle insertions in the tx, so that we may properly
                // find our commitment in the log stream
                let event = AbiMerkleInsertion::decode_log(&log)
                    .map_err(DarkpoolClientError::event_querying)?;

                let value = u256_to_scalar(event.value);
                if value == commitment {
                    insertion_idx = n_insertions;
                    leaf_index = Some(event.index as u64);
                }
                n_insertions += 1;
            } else if topic0 == AbiMerkleOpeningNode::SIGNATURE_HASH {
                let event = AbiMerkleOpeningNode::decode_log(&log)
                    .map_err(DarkpoolClientError::event_querying)?;
                let depth = event.depth as u64;
                let new_value = u256_to_scalar(event.new_value);
                all_insertion_events.push((depth, new_value));
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
            .event_filter::<AbiMerkleInsertion>()
            .topic2(scalar_to_u256(&commitment))
            .from_block(self.deploy_block);
        let (event, log) = self
            .query_latest_event(filter)
            .await?
            .ok_or(DarkpoolClientError::CommitmentNotFound)?;

        Ok((event.index, log.transaction_hash.expect(ERR_NO_TX_HASH)))
    }

    /// Fetch all external matches in a given transaction
    ///
    /// Returns a vector of bounded match results and the actual amount in that
    /// was traded by the external party.
    pub async fn find_external_matches_in_tx(
        &self,
        tx_hash: TxHash,
    ) -> Result<Vec<(BoundedMatchResult, Amount)>, DarkpoolClientError> {
        // Get all darkpool subcalls in the tx
        let mut matches = Vec::new();
        let darkpool_calls = self.fetch_tx_darkpool_calls(tx_hash).await?;
        for frame in darkpool_calls.into_iter() {
            let calldata: &[u8] = &frame.input;
            if let Some(match_res) = self.parse_external_match(calldata)? {
                matches.push(match_res);
            }
        }

        Ok(matches)
    }

    /// Check whether a transaction contains a darkpool `settleExternalMatch`
    /// call.
    pub async fn is_external_match_tx(&self, tx_hash: TxHash) -> Result<bool, DarkpoolClientError> {
        let darkpool_calls = self.fetch_tx_darkpool_calls(tx_hash).await?;
        for frame in darkpool_calls {
            if Self::is_external_match_call(&frame.input) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    // -----------
    // | Helpers |
    // -----------

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

    // --- Calldata Parsing --- //

    /// Whether calldata corresponds to a `settleExternalMatch` call.
    fn is_external_match_call(calldata: &[u8]) -> bool {
        if calldata.len() < SELECTOR_LEN {
            return false;
        }

        calldata[..SELECTOR_LEN] == IDarkpoolV2::settleExternalMatchCall::SELECTOR
    }

    /// Parse an external match from calldata
    ///
    /// The calldata input to this method is assumed to be darkpool calldata.
    /// The caller should filter a tx trace for darkpool sub-calls and pass only
    /// the darkpool calldata to this method.
    fn parse_external_match(
        &self,
        calldata: &[u8],
    ) -> Result<Option<(BoundedMatchResult, Amount)>, DarkpoolClientError> {
        // Parse calldata
        let selector: [u8; SELECTOR_LEN] = calldata[..SELECTOR_LEN].try_into().unwrap();
        let call = match selector {
            IDarkpoolV2::settleExternalMatchCall::SELECTOR => {
                IDarkpoolV2::settleExternalMatchCall::abi_decode(calldata)?
            },
            _ => return Ok(None),
        };

        // Build an external party's settlement obligation from the match result and the
        // traded volume
        let match_res = BoundedMatchResult::from(call.matchResult);
        let amount_in = u256_to_u128(call.externalPartyAmountIn);
        Ok(Some((match_res, amount_in)))
    }

    // --- Query Helpers --- //

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
