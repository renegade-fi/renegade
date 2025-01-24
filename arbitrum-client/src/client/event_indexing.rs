//! Defines `ArbitrumClient` helpers that allow for indexing events
//! emitted by the darkpool contract

use std::cmp::Reverse;
use std::collections::VecDeque;
use std::time::Duration;

use alloy_sol_types::SolCall;
use circuit_types::wallet::Nullifier;
use circuit_types::SizedWalletShare;
use common::types::merkle::MerkleAuthenticationPath;
use constants::{Scalar, MERKLE_HEIGHT};
use ethers::contract::EthLogDecode;
use ethers::types::{
    CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
    GethTraceFrame, NameOrAddress, Transaction,
};
use ethers::{
    middleware::Middleware,
    prelude::StreamExt,
    types::{TransactionReceipt, TxHash},
};
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::fields::{scalar_to_u256, u256_to_scalar};
use tracing::{error, info, instrument};
use util::err_str;

use crate::abi::{
    processAtomicMatchSettleCall, processAtomicMatchSettleWithReceiverCall, MerkleInsertionFilter,
    NullifierSpentFilter,
};
use crate::constants::{Selector, KNOWN_SELECTORS};
use crate::{
    abi::{
        newWalletCall, processMatchSettleCall, redeemFeeCall, settleOfflineFeeCall,
        settleOnlineRelayerFeeCall, updateWalletCall, DarkpoolContractEvents,
        MerkleOpeningNodeFilter, WalletUpdatedFilter,
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
/// Error message emitted when a timeout occurs while waiting for an event
const ERR_NULLIFIER_SPENT_TIMEOUT: &str = "nullifier spent event not found";
/// Error message emitted when an event stream closes unexpectedly
const ERR_EVENT_STREAM_CLOSED: &str = "event stream closed";

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
        let darkpool_client = self.get_darkpool_client();
        let events = darkpool_client
            .event::<WalletUpdatedFilter>()
            .address(darkpool_client.address().into())
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
            .get_darkpool_client()
            .client()
            .get_transaction_receipt(tx)
            .await
            .map_err(|e| ArbitrumClientError::TxQuerying(e.to_string()))?
            .ok_or(ArbitrumClientError::TxNotFound(tx.to_string()))?;

        // The number of Merkle insertions that occurred in a transaction
        let mut n_insertions = 0;
        let mut insertion_idx = 0;

        // Parse the Merkle path from the transaction logs
        let mut all_insertion_events = vec![];
        for eth_log in tx.logs.into_iter() {
            match DarkpoolContractEvents::decode_log(&eth_log.into()) {
                Ok(DarkpoolContractEvents::MerkleOpeningNodeFilter(MerkleOpeningNodeFilter {
                    height: depth,
                    new_value,
                    ..
                })) => {
                    all_insertion_events.push((depth, u256_to_scalar(&new_value)));
                },

                // Track the number of Merkle insertions in the tx, so that we may properly find our
                // commitment in the log stream
                Ok(DarkpoolContractEvents::MerkleInsertionFilter(MerkleInsertionFilter {
                    value,
                    ..
                })) => {
                    if u256_to_scalar(&value) == commitment {
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
            .get_darkpool_client()
            .event::<MerkleInsertionFilter>()
            .address(self.get_darkpool_client().address().into())
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

    /// Await a nullifier spent event on a given nullifier from a given selector
    pub async fn await_nullifier_spent(
        &self,
        nullifier: Nullifier,
        timeout: Duration,
    ) -> Result<(), ArbitrumClientError> {
        self.await_nullifier_spent_from_selectors(nullifier, &[] /* selectors */, timeout).await
    }

    /// Await a nullifier spent event on a given nullifier
    #[instrument(skip_all, err, fields(nullifier = %nullifier))]
    pub async fn await_nullifier_spent_from_selectors(
        &self,
        nullifier: Nullifier,
        selectors: &[Selector],
        timeout: Duration,
    ) -> Result<(), ArbitrumClientError> {
        // Build an event filter on the nullifier
        let nullifier_u256 = scalar_to_u256(&nullifier);
        let address = self.get_darkpool_client().address().into();
        let filter = self
            .get_darkpool_client()
            .event::<NullifierSpentFilter>()
            .address(address)
            .topic1(nullifier_u256)
            .from_block(self.deploy_block);

        // Create a stream that includes event metadata
        let mut stream = filter
            .stream_with_meta()
            .await
            .map_err(err_str!(ArbitrumClientError::EventQuerying))?;

        // Await the event with a timeout
        let next_event = tokio::time::timeout(timeout, stream.next()).await;
        let (_event, meta) = next_event
            .map_err(|_| ArbitrumClientError::event_querying(ERR_NULLIFIER_SPENT_TIMEOUT))? // timeout
            .ok_or(ArbitrumClientError::event_querying(ERR_EVENT_STREAM_CLOSED))? // no event
            .map_err(err_str!(ArbitrumClientError::event_querying))?; // query error
        let tx_hash = meta.transaction_hash;

        // Check if the transaction selector matches one of the given selectors
        // This is not a perfect check; it merely suffices for the ways in which this
        // method is currently used -- to check for external match events.
        // If, in the future, we want to filter for more complex transaction shapes, we
        // can trace subcall events
        if !selectors.is_empty() && !self.tx_calls_selectors(tx_hash, selectors).await? {
            return Err(ArbitrumClientError::EventQuerying(
                "Nullifier spent with wrong selector".to_string(),
            ));
        }

        Ok(())
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

        let tx: Transaction = self
            .get_darkpool_client()
            .client()
            .get_transaction(tx_hash)
            .await
            .map_err(|e| ArbitrumClientError::TxQuerying(e.to_string()))?
            .ok_or(ArbitrumClientError::TxNotFound(tx_hash.to_string()))?;

        let calldata: Vec<u8> = tx.input.to_vec();
        let selector: [u8; 4] = calldata[..SELECTOR_LEN].try_into().unwrap();
        if KNOWN_SELECTORS.contains(&selector) {
            Self::parse_shares_from_selector_and_calldata(selector, &calldata, public_blinder_share)
        } else {
            info!("unknown selector {selector:?}, searching calldata...");
            self.fetch_public_shares_for_unknown_selector(tx_hash, public_blinder_share).await
        }
    }

    // -----------
    // | Helpers |
    // -----------

    /// Check whether a transaction contains a selector from the given set
    async fn tx_calls_selectors(
        &self,
        tx_hash: TxHash,
        selectors: &[Selector],
    ) -> Result<bool, ArbitrumClientError> {
        // If the top-level selector is known, return whether it is in the set
        let selector = self.fetch_selector_from_tx(tx_hash).await?;
        if KNOWN_SELECTORS.contains(&selector) {
            return Ok(selectors.contains(&selector));
        }

        // Otherwise, trace the call to find known selectors in the subcalls
        let calls = self.fetch_tx_darkpool_calls(tx_hash).await?;
        for call in calls {
            let data = call.input;
            let subcall_selector = data[..SELECTOR_LEN].try_into().unwrap();
            if selectors.contains(&subcall_selector) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Fetch the selector from a transaction
    async fn fetch_selector_from_tx(
        &self,
        tx_hash: TxHash,
    ) -> Result<[u8; SELECTOR_LEN], ArbitrumClientError> {
        let tx: Transaction = self
            .get_darkpool_client()
            .client()
            .get_transaction(tx_hash)
            .await
            .map_err(|e| ArbitrumClientError::TxQuerying(e.to_string()))?
            .ok_or(ArbitrumClientError::TxNotFound(tx_hash.to_string()))?;

        // Ensure the input data is at least as long as a selector
        let input_data = tx.input.as_ref();
        if input_data.len() < SELECTOR_LEN {
            return Err(ArbitrumClientError::InvalidSelector);
        }

        // Parse the selector from the input data
        let selector = input_data[..SELECTOR_LEN]
            .try_into()
            .map_err(|_| ArbitrumClientError::InvalidSelector)?;
        Ok(selector)
    }

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

        self.client()
            .debug_trace_transaction(tx_hash, options)
            .await
            .map_err(err_str!(ArbitrumClientError::TxQuerying))
    }

    /// Find all darkpool sub-calls in a call trace
    fn find_darkpool_subcalls(&self, trace: &GethTrace) -> Vec<CallFrame> {
        let darkpool = self.get_darkpool_client().address();
        let global_call_frame = match trace {
            GethTrace::Known(GethTraceFrame::CallTracer(frame)) => frame,
            _ => return vec![],
        };

        // BFS the call tree to find all calls to the darkpool contract
        let mut darkpool_calls = vec![];
        let mut calls = VecDeque::from([global_call_frame]);
        while let Some(call) = calls.pop_front() {
            match call.to {
                Some(NameOrAddress::Address(addr)) if addr == darkpool => {
                    darkpool_calls.push(call.clone());
                },
                _ => {},
            }

            if let Some(sub_calls) = &call.calls {
                calls.extend(sub_calls);
            }
        }

        darkpool_calls
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
}
