//! Defines `StarknetClient` implementations related to querying and updating the chain state

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use circuit_types::SizedWalletShare;
use common::types::merkle::{MerkleAuthenticationPath, MerkleTreeCoords};
use constants::MERKLE_HEIGHT;
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::BigUint;
use renegade_crypto::fields::{
    scalar_to_starknet_felt, starknet_felt_to_biguint, starknet_felt_to_scalar,
    starknet_felt_to_u64,
};
use starknet::{
    accounts::{Account, Call},
    core::types::{
        BlockId, BlockTag, EmittedEvent, EventFilter, FieldElement as StarknetFieldElement,
        FunctionCall, InvokeTransaction, MaybePendingTransactionReceipt, Transaction,
        TransactionReceipt,
    },
    providers::Provider,
};
use tracing::log;

use crate::{
    client::EVENTS_PAGE_SIZE, error::StarknetClientError, helpers::parse_shares_from_calldata,
    DEFAULT_AUTHENTICATION_PATH, INTERNAL_NODE_CHANGED_EVENT_SELECTOR,
    VALUE_INSERTED_EVENT_SELECTOR,
};

use super::{
    StarknetClient, TransactionHash, BLOCK_PAGINATION_WINDOW, ERR_UNEXPECTED_TX_TYPE,
    MAX_FEE_MULTIPLIER, TX_STATUS_POLL_INTERVAL_MS,
};
impl StarknetClient {
    /// Helper to make a view call to the contract
    pub(crate) async fn call_contract(
        &self,
        call: FunctionCall,
    ) -> Result<Vec<StarknetFieldElement>, StarknetClientError> {
        self.get_jsonrpc_client()
            .call(call, BlockId::Tag(BlockTag::Pending))
            .await
            .map_err(|err| StarknetClientError::Rpc(err.to_string()))
    }

    /// Helper to setup a contract call with the correct max fee and account nonce
    pub(crate) async fn execute_transaction(
        &self,
        call: Call,
    ) -> Result<TransactionHash, StarknetClientError> {
        // Estimate the fee and add a buffer to avoid rejected transaction
        let account_index = self.next_account_index();
        let acct_nonce = self.pending_block_nonce(account_index).await?;
        let execution = self
            .get_account(account_index)
            .execute(vec![call])
            .nonce(acct_nonce);

        let fee_estimate = execution
            .estimate_fee()
            .await
            .map_err(|err| StarknetClientError::ExecuteTransaction(err.to_string()))?;
        let max_fee = (fee_estimate.overall_fee as f32) * MAX_FEE_MULTIPLIER;
        let max_fee = StarknetFieldElement::from(max_fee as u64);

        // Send the transaction and await receipt
        execution
            .max_fee(max_fee)
            .send()
            .await
            .map(|res| res.transaction_hash)
            .map_err(|err| StarknetClientError::ExecuteTransaction(err.to_string()))
    }

    /// Get the current StarkNet block number
    pub async fn get_block_number(&self) -> Result<u64, StarknetClientError> {
        self.get_jsonrpc_client()
            .block_number()
            .await
            .map_err(|err| StarknetClientError::Rpc(err.to_string()))
    }

    /// Get the nonce of the account at the provided index in the pending block
    pub async fn pending_block_nonce(
        &self,
        account_index: usize,
    ) -> Result<StarknetFieldElement, StarknetClientError> {
        self.jsonrpc_client
            .get_nonce(
                BlockId::Tag(BlockTag::Pending),
                self.get_account(account_index).address(),
            )
            .await
            .map_err(|err| StarknetClientError::Rpc(err.to_string()))
    }

    /// Poll a transaction until it is finalized into the accepted on L2 state
    #[allow(deprecated)]
    pub async fn poll_transaction_completed(
        &self,
        tx_hash: StarknetFieldElement,
    ) -> Result<TransactionReceipt, StarknetClientError> {
        let sleep_duration = Duration::from_millis(TX_STATUS_POLL_INTERVAL_MS);
        loop {
            let res = self
                .jsonrpc_client
                .get_transaction_receipt(tx_hash)
                .await
                .map_err(|err| StarknetClientError::Rpc(err.to_string()))?;

            // Break if the transaction has made it out of the received state
            match res {
                MaybePendingTransactionReceipt::PendingReceipt(_) => {
                    log::info!("transaction 0x{tx_hash:x} pending...");
                }
                MaybePendingTransactionReceipt::Receipt(receipt) => {
                    log::info!("transaction 0x{tx_hash:x} finalized",);

                    return Ok(receipt);
                }
            }

            // Sleep and poll again
            tokio::time::sleep(sleep_duration).await;
        }
    }

    /// Searches on-chain state for the insertion of the given wallet, then finds the most
    /// recent updates of the path's siblings and creates a Merkle authentication path
    pub async fn find_merkle_authentication_path(
        &self,
        commitment: Scalar,
    ) -> Result<MerkleAuthenticationPath, StarknetClientError> {
        // Find the index of the wallet in the commitment tree
        let leaf_index = self.find_commitment_in_state(commitment).await?;

        // Construct a set that holds pairs of (depth, index) values in the authentication path; i.e. the
        // tree coordinates of the sibling nodes in the authentication path
        let mut authentication_path_coords: HashSet<MerkleTreeCoords> =
            MerkleAuthenticationPath::construct_path_coords(leaf_index.clone(), MERKLE_HEIGHT)
                .into_iter()
                .collect();

        // Search for these on-chain
        let mut found_coords: HashMap<MerkleTreeCoords, StarknetFieldElement> = HashMap::new();
        let coords_ref = &mut found_coords;
        self.paginate_events(
            move |event| {
                let height: usize = starknet_felt_to_u64(&event.data[0]) as usize;
                let index = starknet_felt_to_biguint(&event.data[1]);
                let new_value = event.data[2];

                let coords = MerkleTreeCoords::new(height, index);
                if authentication_path_coords.remove(&coords) {
                    coords_ref.insert(coords, new_value);
                }

                if authentication_path_coords.is_empty() {
                    Ok(Some(()))
                } else {
                    Ok(None)
                }
            },
            vec![*INTERNAL_NODE_CHANGED_EVENT_SELECTOR],
        )
        .await?;

        // Gather the coordinates found on-chain into a Merkle authentication path
        let mut path = *DEFAULT_AUTHENTICATION_PATH;
        for (coordinate, value) in found_coords.into_iter() {
            let path_index = MERKLE_HEIGHT - coordinate.height;
            path[path_index] = starknet_felt_to_scalar(&value);
        }

        Ok(MerkleAuthenticationPath::new(path, leaf_index, commitment))
    }

    /// A helper to find a commitment in the Merkle tree
    pub async fn find_commitment_in_state(
        &self,
        commitment: Scalar,
    ) -> Result<BigUint, StarknetClientError> {
        let commitment_starknet_felt = scalar_to_starknet_felt(&commitment);

        log::info!(
            "searching for commitment: 0x{:x}",
            starknet_felt_to_biguint(&commitment_starknet_felt)
        );

        // Paginate through events in the contract, searching for the Merkle tree insertion event that
        // corresponds to the given commitment
        //
        // Return the Merkle leaf index at which the commitment was inserted
        self.paginate_events(
            |event| {
                let index = event.data[0];
                let value = event.data[1];

                if value == commitment_starknet_felt {
                    return Ok(Some(starknet_felt_to_biguint(&index)));
                }

                Ok(None)
            },
            vec![*VALUE_INSERTED_EVENT_SELECTOR],
        )
        .await?
        .ok_or_else(|| {
            StarknetClientError::NotFound("commitment not found in Merkle tree".to_string())
        })
    }

    /// A helper for paginating backwards in block history over contract events
    ///
    /// Calls the handler on each event, which indicates whether the pagination should
    /// stop, and gives a response value
    async fn paginate_events<T>(
        &self,
        mut handler: impl FnMut(EmittedEvent) -> Result<Option<T>, StarknetClientError>,
        event_keys: Vec<StarknetFieldElement>,
    ) -> Result<Option<T>, StarknetClientError> {
        // Build the event filter template
        let current_block = self.get_block_number().await?;
        let mut filter = EventFilter {
            from_block: None,
            to_block: None,
            address: Some(self.contract_address),
            keys: if event_keys.is_empty() {
                None
            } else {
                Some(vec![event_keys])
            },
        };

        // Paginate backwards in block history
        let earliest_block = self.config.earliest_block();
        'outer: for end_block in (earliest_block..current_block)
            .rev()
            .step_by(BLOCK_PAGINATION_WINDOW)
        {
            // Exhaust events from the start block to the end block
            let start_block = end_block.saturating_sub(BLOCK_PAGINATION_WINDOW as u64);
            filter.from_block = Some(BlockId::Number(start_block));
            filter.to_block = Some(BlockId::Number(end_block));

            // Keep paging until the response includes no token
            let mut pagination_token = None;
            'inner: loop {
                // Fetch the next page of events
                let res = self
                    .get_jsonrpc_client()
                    .get_events(filter.clone(), pagination_token.clone(), EVENTS_PAGE_SIZE)
                    .await
                    .map_err(|err| StarknetClientError::Rpc(err.to_string()))?;

                // Process each event with the handler
                for event in res.events.into_iter() {
                    if let Some(ret_val) = handler(event)? {
                        return Ok(Some(ret_val));
                    }
                }

                if res.continuation_token.is_none() {
                    break 'inner;
                }
                pagination_token = res.continuation_token;
            }

            // If we are already at the genesis block, stop searching
            if start_block == 0 {
                break 'outer;
            }
        }

        Ok(None)
    }

    /// Fetch and parse the public secret shares from the calldata of the given transactions
    ///
    /// In the case that the referenced transaction is a `match`, we disambiguate between the
    /// two parties by adding the public blinder of the party's shares the caller intends to fetch
    #[allow(deprecated)]
    pub async fn fetch_public_shares_from_tx(
        &self,
        public_blinder_share: Scalar,
        tx_hash: TransactionHash,
    ) -> Result<SizedWalletShare, StarknetClientError> {
        // Parse the selector and calldata from the transaction info
        let tx_info = self
            .get_jsonrpc_client()
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(|err| StarknetClientError::Rpc(err.to_string()))?;

        let (selector, calldata) = if let Transaction::Invoke(info) = tx_info {
            match info {
                InvokeTransaction::V0(tx_info) => (tx_info.entry_point_selector, tx_info.calldata),
                InvokeTransaction::V1(tx_info) => {
                    // In an invoke v1 transaction, the calldata is of the form:
                    //      `[contract_addr, entrypoint_selector, ..calldata]`
                    // We need to strip the first two elements to get the actual calldata
                    let selector = tx_info.calldata[1];
                    let calldata = tx_info.calldata[2..].to_vec();
                    (selector, calldata)
                }
            }
        } else {
            return Err(StarknetClientError::NotFound(
                ERR_UNEXPECTED_TX_TYPE.to_string(),
            ));
        };

        // Parse the secret shares from the calldata
        parse_shares_from_calldata(
            selector,
            &calldata,
            scalar_to_starknet_felt(&public_blinder_share),
        )
    }
}
