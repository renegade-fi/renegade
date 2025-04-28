//! Defines `ArbitrumClient` helpers that allow for indexing events
//! emitted by the darkpool contract

use std::cmp::Reverse;
use std::collections::VecDeque;

use alloy::consensus::Transaction;
use alloy::providers::{ext::DebugApi, Provider};
use alloy::rpc::types::trace::geth::{
    CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
};
use alloy::rpc::types::TransactionReceipt;
use alloy_primitives::{Log, TxHash, U256};
use alloy_sol_types::{SolCall, SolEventInterface};
use circuit_types::SizedWalletShare;
use common::types::merkle::MerkleAuthenticationPath;
use constants::{Scalar, MERKLE_HEIGHT};
use itertools::Itertools;
use num_bigint::BigUint;
use tracing::{error, info, instrument};

use crate::abi::Darkpool::{DarkpoolEvents, MerkleInsertion, MerkleOpeningNode};
use crate::constants::{
    KNOWN_SELECTORS, PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR,
    PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
    PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR,
    PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
};
use crate::contract_types::{
    ExternalMatchResult,
    ValidMalleableMatchSettleAtomicStatement as ContractValidMalleableMatchSettleAtomicStatement,
    ValidMatchSettleAtomicStatement as ContractValidMatchSettleAtomicStatement,
};
use crate::conversion::{scalar_to_u256, to_circuit_fixed_point, u256_to_scalar};
use crate::helpers::{
    deserialize_calldata, parse_shares_from_process_malleable_atomic_match_settle,
    parse_shares_from_process_malleable_atomic_match_settle_with_receiver,
};
use crate::{
    abi::Darkpool::{
        newWalletCall, processAtomicMatchSettleCall, processAtomicMatchSettleWithReceiverCall,
        processMalleableAtomicMatchSettleCall, processMalleableAtomicMatchSettleWithReceiverCall,
        processMatchSettleCall, redeemFeeCall, settleOfflineFeeCall, settleOnlineRelayerFeeCall,
        updateWalletCall,
    },
    constants::SELECTOR_LEN,
    errors::ArbitrumClientError,
    helpers::{
        parse_shares_from_new_wallet, parse_shares_from_process_atomic_match_settle,
        parse_shares_from_process_atomic_match_settle_with_receiver,
        parse_shares_from_process_match_settle, parse_shares_from_redeem_fee,
        parse_shares_from_settle_offline_fee, parse_shares_from_settle_online_relayer_fee,
        parse_shares_from_update_wallet,
    },
};

use super::ArbitrumClient;

/// The error message emitted when not enough Merkle path siblings are found
const ERR_MERKLE_PATH_SIBLINGS: &str = "not enough Merkle path siblings found";
/// The error message emitted when a TX hash is not found in a log
const ERR_NO_TX_HASH: &str = "no tx hash for log";

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
        let darkpool_client = self.darkpool_client();
        let events = darkpool_client
            .WalletUpdated_filter()
            .topic1(scalar_to_u256(public_blinder_share))
            .from_block(self.deploy_block)
            .query()
            .await
            .map_err(ArbitrumClientError::event_querying)?;

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
    ) -> Result<MerkleAuthenticationPath, ArbitrumClientError> {
        let (index, tx) = self.find_commitment_in_state_with_tx(commitment).await?;
        let leaf_index = BigUint::from(index);
        let tx: TransactionReceipt = self
            .provider()
            .get_transaction_receipt(tx)
            .await
            .map_err(|e| ArbitrumClientError::TxQuerying(e.to_string()))?
            .ok_or(ArbitrumClientError::TxNotFound(tx.to_string()))?;

        // The number of Merkle insertions that occurred in a transaction
        let mut n_insertions = 0;
        let mut insertion_idx = 0;

        // Parse the Merkle path from the transaction logs
        let mut all_insertion_events = vec![];
        for log in tx.logs().iter().cloned().map(Log::from) {
            match DarkpoolEvents::decode_log(&log).map(|l| l.data) {
                Ok(DarkpoolEvents::MerkleOpeningNode(MerkleOpeningNode {
                    height: depth,
                    new_value,
                    ..
                })) => {
                    all_insertion_events.push((depth, u256_to_scalar(new_value)));
                },

                // Track the number of Merkle insertions in the tx, so that we may properly find our
                // commitment in the log stream
                Ok(DarkpoolEvents::MerkleInsertion(MerkleInsertion { value, .. })) => {
                    if u256_to_scalar(value) == commitment {
                        insertion_idx = n_insertions;
                    }

                    n_insertions += 1;
                },

                // Ignore other events and unknown events
                _ => continue,
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
                |_| ArbitrumClientError::EventQuerying(ERR_MERKLE_PATH_SIBLINGS.to_string()),
            )?;

        Ok(MerkleAuthenticationPath::new(siblings, leaf_index, commitment))
    }

    /// A helper to find a commitment's index in the Merkle tree, also returns
    /// the tx that submitted the commitment
    #[instrument(skip_all, err, fields(commitment = %commitment))]
    pub async fn find_commitment_in_state_with_tx(
        &self,
        commitment: Scalar,
    ) -> Result<(u128, TxHash), ArbitrumClientError> {
        let events = self
            .darkpool_client()
            .MerkleInsertion_filter()
            .topic2(scalar_to_u256(commitment))
            .from_block(self.deploy_block)
            .query()
            .await
            .map_err(ArbitrumClientError::event_querying)?;

        events
            .last()
            .map(|(event, meta)| (event.index, meta.transaction_hash.expect(ERR_NO_TX_HASH)))
            .ok_or(ArbitrumClientError::CommitmentNotFound)
    }

    /// Fetch and parse the public secret shares from the calldata of the
    /// transaction that updated the wallet with the given blinder
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
            .provider()
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(ArbitrumClientError::tx_querying)?
            .ok_or(ArbitrumClientError::TxNotFound(tx_hash.to_string()))?;

        let calldata: Vec<u8> = tx.input().to_vec();
        let selector: [u8; 4] = calldata[..SELECTOR_LEN].try_into().unwrap();
        if KNOWN_SELECTORS.contains(&selector) {
            Self::parse_shares_from_selector_and_calldata(selector, &calldata, public_blinder_share)
        } else {
            info!("unknown selector {selector:?}, searching calldata...");
            self.fetch_public_shares_for_unknown_selector(tx_hash, public_blinder_share).await
        }
    }

    /// Fetch all external matches in a given transaction
    pub async fn find_external_matches_in_tx(
        &self,
        tx_hash: TxHash,
    ) -> Result<Vec<ExternalMatchResult>, ArbitrumClientError> {
        // Get all darkpool subcalls in the tx
        let mut matches = Vec::new();
        let darkpool_calls = self.fetch_tx_darkpool_calls(tx_hash).await?;
        for frame in darkpool_calls.into_iter() {
            let calldata: &[u8] = &frame.input;
            let selector = calldata[..SELECTOR_LEN].try_into().unwrap();

            // Parse the `VALID MATCH SETTLE ATOMIC` statement from the calldata
            let match_res = match selector {
                PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR => {
                    let call = processAtomicMatchSettleCall::abi_decode(calldata)?;
                    Self::parse_external_match_from_calldata(
                        &call.valid_match_settle_atomic_statement,
                    )
                },
                PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR => {
                    let call = processAtomicMatchSettleWithReceiverCall::abi_decode(calldata)?;
                    Self::parse_external_match_from_calldata(
                        &call.valid_match_settle_atomic_statement,
                    )
                },
                PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR => {
                    let call =
                        processMalleableAtomicMatchSettleWithReceiverCall::abi_decode(calldata)?;
                    Self::parse_external_match_from_malleable(
                        call.base_amount,
                        &call.valid_match_settle_statement,
                    )
                },
                PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR => {
                    let call = processMalleableAtomicMatchSettleCall::abi_decode(calldata)?;
                    Self::parse_external_match_from_malleable(
                        call.base_amount,
                        &call.valid_match_settle_statement,
                    )
                },
                _ => continue,
            }?;

            // Deserialize the statement, and store the match
            matches.push(match_res);
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
    ) -> Result<SizedWalletShare, ArbitrumClientError> {
        // Parse the call trace for calls to the darkpool contract
        let calls = self.fetch_tx_darkpool_calls(tx_hash).await?;
        if calls.is_empty() {
            let hash_str = format!("{tx_hash:#x}");
            return Err(ArbitrumClientError::DarkpoolSubcallNotFound(hash_str));
        }

        // Attempt to parse public shares from the calldata of each call
        for call in calls {
            let data = call.input;
            let selector = data[..SELECTOR_LEN].try_into().unwrap();
            let public_share = Self::parse_shares_from_selector_and_calldata(
                selector,
                &data,
                public_blinder_share,
            )?;

            if public_share.blinder == public_blinder_share {
                return Ok(public_share);
            }
        }

        Err(ArbitrumClientError::InvalidSelector)
    }

    /// Parse wallet shares given a selector and calldata
    fn parse_shares_from_selector_and_calldata(
        selector: [u8; SELECTOR_LEN],
        calldata: &[u8],
        public_blinder_share: Scalar,
    ) -> Result<SizedWalletShare, ArbitrumClientError> {
        match selector {
            <newWalletCall as SolCall>::SELECTOR => parse_shares_from_new_wallet(calldata),
            <updateWalletCall as SolCall>::SELECTOR => parse_shares_from_update_wallet(calldata),
            <processMatchSettleCall as SolCall>::SELECTOR => {
                parse_shares_from_process_match_settle(calldata, public_blinder_share)
            },
            <processAtomicMatchSettleCall as SolCall>::SELECTOR => {
                parse_shares_from_process_atomic_match_settle(calldata)
            },
            <processAtomicMatchSettleWithReceiverCall as SolCall>::SELECTOR => {
                parse_shares_from_process_atomic_match_settle_with_receiver(calldata)
            },
            <processMalleableAtomicMatchSettleCall as SolCall>::SELECTOR => {
                parse_shares_from_process_malleable_atomic_match_settle(calldata)
            },
            <processMalleableAtomicMatchSettleWithReceiverCall as SolCall>::SELECTOR => {
                parse_shares_from_process_malleable_atomic_match_settle_with_receiver(calldata)
            },
            <settleOnlineRelayerFeeCall as SolCall>::SELECTOR => {
                parse_shares_from_settle_online_relayer_fee(calldata, public_blinder_share)
            },
            <settleOfflineFeeCall as SolCall>::SELECTOR => {
                parse_shares_from_settle_offline_fee(calldata)
            },
            <redeemFeeCall as SolCall>::SELECTOR => parse_shares_from_redeem_fee(calldata),
            _ => {
                error!("invalid selector when parsing public shares: {selector:?}");
                Err(ArbitrumClientError::InvalidSelector)
            },
        }
    }

    // --- Parse External Matches --- //

    /// Parse an external match from a `VALID MATCH SETTLE ATOMIC` statement
    /// serialized as calldata bytes
    fn parse_external_match_from_calldata(
        statement_bytes: &[u8],
    ) -> Result<ExternalMatchResult, ArbitrumClientError> {
        let statement: ContractValidMatchSettleAtomicStatement =
            deserialize_calldata(statement_bytes)?;
        Ok(statement.match_result)
    }

    /// Parse an external match from a `VALID MALLEABLE MATCH SETTLE ATOMIC`
    /// statement and the calldata of the `processMalleableAtomicMatchSettle`
    fn parse_external_match_from_malleable(
        base_amount: U256,
        statement_bytes: &[u8],
    ) -> Result<ExternalMatchResult, ArbitrumClientError> {
        let statement: ContractValidMalleableMatchSettleAtomicStatement =
            deserialize_calldata(statement_bytes)?;
        let match_res = statement.match_result;

        // Compute the quote amount from the price and the base amount
        let price = to_circuit_fixed_point(&match_res.price);
        let base_scalar = u256_to_scalar(base_amount);
        let quote_scalar = (price * base_scalar).floor();
        let base_amount = scalar_to_u256(base_scalar);
        let quote_amount = scalar_to_u256(quote_scalar);

        Ok(ExternalMatchResult {
            base_mint: match_res.base_mint,
            quote_mint: match_res.quote_mint,
            base_amount,
            quote_amount,
            direction: match_res.direction,
        })
    }

    // --- Call Tracing --- //

    /// Fetch the darkpool calls from a given transaction
    async fn fetch_tx_darkpool_calls(
        &self,
        tx_hash: TxHash,
    ) -> Result<Vec<CallFrame>, ArbitrumClientError> {
        let trace = self.fetch_call_trace(tx_hash).await?;
        Ok(self.find_darkpool_subcalls(&trace))
    }

    /// Fetch the call trace for a given transaction
    async fn fetch_call_trace(&self, tx_hash: TxHash) -> Result<GethTrace, ArbitrumClientError> {
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
            .map_err(ArbitrumClientError::tx_querying)
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
