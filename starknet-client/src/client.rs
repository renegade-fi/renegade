//! A wrapper around the starknet client made available by:
//! https://docs.rs/starknet-core/latest/starknet_core/

use std::{
    collections::{HashMap, HashSet},
    iter,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use circuit_types::{
    merkle::MerkleRoot,
    native_helpers::compute_wallet_commitment_from_private,
    wallet::{Nullifier, WalletShareStateCommitment},
    SizedWalletShare,
};
use common::types::{
    chain_id::ChainId,
    merkle::{MerkleAuthenticationPath, MerkleTreeCoords},
    proof_bundles::{
        OrderValidityProofBundle, ValidMatchMpcBundle, ValidSettleBundle, ValidWalletCreateBundle,
        ValidWalletUpdateBundle,
    },
};
use constants::{
    DEVNET_CONTRACT_DEPLOYMENT_BLOCK, GOERLI_CONTRACT_DEPLOYMENT_BLOCK,
    MAINNET_CONTRACT_DEPLOYMENT_BLOCK,
};
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::BigUint;
use renegade_crypto::fields::{
    scalar_to_starknet_felt, starknet_felt_to_biguint, starknet_felt_to_scalar,
    starknet_felt_to_u64,
};
use reqwest::Url as ReqwestUrl;
use starknet::{
    accounts::{Account, Call, SingleOwnerAccount},
    core::types::{
        BlockId as CoreBlockId, BlockTag, EmittedEvent, EventFilter,
        FieldElement as StarknetFieldElement, FunctionCall,
    },
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        sequencer::{
            models::{TransactionInfo, TransactionStatus},
            SequencerGatewayProvider,
        },
        Provider,
    },
    signers::{LocalWallet, SigningKey},
};
use tracing::log;

use crate::{
    helpers::parse_shares_from_calldata, INTERNAL_NODE_CHANGED_EVENT_SELECTOR, MATCH_SELECTOR,
    MERKLE_HEIGHT, MERKLE_ROOT_IN_HISTORY_SELECTOR, NEW_WALLET_SELECTOR, UPDATE_WALLET_SELECTOR,
    VALUE_INSERTED_EVENT_SELECTOR,
};

use super::{
    error::StarknetClientError, helpers::pack_bytes_into_felts, types::ExternalTransfer,
    DEFAULT_AUTHENTICATION_PATH, GET_PUBLIC_BLINDER_TRANSACTION, NULLIFIER_USED_SELECTOR,
};

/// A type alias for a felt that represents a transaction hash
pub type TransactionHash = StarknetFieldElement;

/// The block length of the window to poll events in while paginating
///
/// I.e. when paginating events, we paginate backwards by increments of
/// `BLOCK_PAGINATION_WINDOW` blocks. Meaning we first fetch the most recent
/// `BLOCK_PAGINATION_WINDOW` blocks; scan them, then search the next
/// `BLOCK_PAGINATION_WINDOW` blocks
const BLOCK_PAGINATION_WINDOW: u64 = 1000;
/// The page size to request when querying events
const EVENTS_PAGE_SIZE: u64 = 50;
/// The interval at which to poll the gateway for transaction status
const TX_STATUS_POLL_INTERVAL_MS: u64 = 10_000; // 10 seconds
/// The fee estimate multiplier to use as `MAX_FEE` for transactions
const MAX_FEE_MULTIPLIER: f32 = 3.0;

/// Error message emitted when wallet secret shares cannot be parsed from a tx
const ERR_WALLET_SHARES_NOT_FOUND: &str = "could not parse wallet public shares from tx calldata";

/// Macro helper to pack a serializable value into a vector of felts
///
/// Prepends a length felt for run length encoding
macro_rules! pack_serializable {
    ($val:ident) => {{
        let bytes = serde_json::to_vec(&($val))
            .map_err(|err| StarknetClientError::Serde(err.to_string()))?;
        let mut felts = pack_bytes_into_felts(&bytes);
        felts.insert(0, (felts.len() as u64).into());

        felts
    }};
}
/// The config type for the client, consists of secrets needed to connect to
/// the gateway and API server, as well as keys for sending transactions
#[derive(Clone)]
pub struct StarknetClientConfig {
    /// The chain this client should submit requests to
    pub chain: ChainId,
    /// The address of the Darkpool contract on chain
    pub contract_addr: String,
    /// The HTTP addressable JSON-RPC node to connect to for
    /// requests that cannot go through the gateway
    pub starknet_json_rpc_addr: Option<String>,
    /// The sequencer gateway address to connect to if on `Devnet`
    pub sequencer_addr: Option<String>,
    /// The API key for the JSON-RPC node
    ///
    /// For now, we require only the API key's ID on our RPC node,
    /// so this parameter is unused
    pub infura_api_key: Option<String>,
    /// The starknet addresses of the accounts corresponding to the given keys
    pub starknet_account_addresses: Vec<String>,
    /// The starknet signing keys, used to submit transactions on-chain
    pub starknet_pkeys: Vec<String>,
}

impl StarknetClientConfig {
    /// Whether or not the client is enabled given its configuration
    pub fn enabled(&self) -> bool {
        self.starknet_json_rpc_addr.is_some()
    }

    /// Whether or not a signing account has been passed with the config
    ///
    /// Only when this is enabled may the client write transactions to the sequencer
    pub fn account_enabled(&self) -> bool {
        !self.starknet_pkeys.is_empty() && !self.starknet_account_addresses.is_empty()
    }

    /// Build a gateway client from the config values
    pub fn new_gateway_client(&self) -> SequencerGatewayProvider {
        match self.chain {
            ChainId::AlphaGoerli => SequencerGatewayProvider::starknet_alpha_goerli(),
            ChainId::Mainnet => SequencerGatewayProvider::starknet_alpha_mainnet(),
            ChainId::Devnet => {
                let sequencer_url = self
                    .sequencer_addr
                    .clone()
                    .unwrap_or_else(|| "http://localhost:5050".to_string());

                SequencerGatewayProvider::new(
                    ReqwestUrl::parse(&format!("{}/gateway", sequencer_url)).unwrap(),
                    ReqwestUrl::parse(&format!("{}/feeder_gateway", sequencer_url)).unwrap(),
                    StarknetFieldElement::from(0u8),
                )
            }
        }
    }

    /// Create a new JSON-RPC client using the API credentials in the config
    ///
    /// Returns `None` if the config does not specify the correct credentials
    pub fn new_jsonrpc_client(&self) -> Option<JsonRpcClient<HttpTransport>> {
        if !self.enabled() {
            return None;
        }

        let transport = HttpTransport::new(
            ReqwestUrl::parse(self.starknet_json_rpc_addr.as_ref().unwrap()).ok()?,
        );
        Some(JsonRpcClient::new(transport))
    }
}

/// A wrapper around the concrete JSON-RPC client that provides helpers for common
/// Renegade-specific access patterns
#[derive(Clone)]
pub struct StarknetClient {
    /// The config for the client
    pub config: StarknetClientConfig,
    /// The address of the contract on-chain
    pub contract_address: StarknetFieldElement,
    /// The client used to connect with the sequencer gateway
    gateway_client: Arc<SequencerGatewayProvider>,
    /// The client used to send starknet JSON-RPC requests
    jsonrpc_client: Option<Arc<JsonRpcClient<HttpTransport>>>,
    /// The accounts that may be used to sign outbound transactions
    accounts: Arc<Vec<SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>>>,
    /// The account index to use for the next transaction
    account_index: Arc<Mutex<usize>>,
}

impl StarknetClient {
    /// Constructor
    pub fn new(config: StarknetClientConfig) -> Self {
        // Build the gateway and JSON-RPC clients
        let gateway_client = Arc::new(config.new_gateway_client());
        let jsonrpc_client = config.new_jsonrpc_client().map(Arc::new);

        // Build the accounts to sign transactions with
        let account_addrs = config.starknet_account_addresses.clone();
        let keys = config.starknet_pkeys.clone();
        let accounts = account_addrs
            .into_iter()
            .zip(keys)
            .map(|(account_addr, key)| {
                // Parse the account address and key
                let account_addr_felt = StarknetFieldElement::from_str(&account_addr).unwrap();
                let key_felt = StarknetFieldElement::from_str(&key).unwrap();

                // Build the account
                let signer = LocalWallet::from(SigningKey::from_secret_scalar(key_felt));
                SingleOwnerAccount::new(
                    config.new_gateway_client(),
                    signer,
                    account_addr_felt,
                    config.chain.into(),
                )
            })
            .collect::<Vec<_>>();

        // Wrap the accounts an Arc for read access across workers
        let accounts = Arc::new(accounts);

        // Parse the contract address
        let contract_address: StarknetFieldElement =
            StarknetFieldElement::from_str(&config.contract_addr).unwrap_or_else(|_| {
                panic!("could not parse contract address {}", config.contract_addr)
            });

        Self {
            config,
            contract_address,
            gateway_client,
            jsonrpc_client,
            accounts,
            account_index: Arc::new(Mutex::new(0)),
        }
    }

    // -----------
    // | Helpers |
    // -----------

    /// Whether or not JSON-RPC is enabled via the given config values
    pub fn jsonrpc_enabled(&self) -> bool {
        self.config.enabled()
    }

    /// Get the underlying gateway client as an immutable reference
    pub fn get_gateway_client(&self) -> &SequencerGatewayProvider {
        &self.gateway_client
    }

    /// Get the underlying RPC client as an immutable reference
    pub fn get_jsonrpc_client(&self) -> &JsonRpcClient<HttpTransport> {
        self.jsonrpc_client.as_ref().unwrap()
    }

    /// Get the underlying account at the given index as an immutable reference
    pub fn get_account(
        &self,
        account_index: usize,
    ) -> &SingleOwnerAccount<SequencerGatewayProvider, LocalWallet> {
        self.accounts.as_ref().get(account_index).unwrap()
    }

    /// Query the current nonce and advance it by one
    pub fn next_account_index(&self) -> usize {
        // Acquire a lock on self.account_index, copy it to a usize, and increment it
        let mut account_index = self.account_index.lock().unwrap();
        let current_account_index = *account_index;
        *account_index = (*account_index + 1) % self.accounts.as_ref().len();
        current_account_index
    }

    /// Helper to make a view call to the contract
    async fn call_contract(
        &self,
        call: FunctionCall,
    ) -> Result<Vec<StarknetFieldElement>, StarknetClientError> {
        self.get_jsonrpc_client()
            .call(call, CoreBlockId::Tag(BlockTag::Pending))
            .await
            .map_err(|err| StarknetClientError::Gateway(err.to_string()))
    }

    /// Helper to setup a contract call with the correct max fee and account nonce
    async fn execute_transaction(
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

    // ---------------
    // | Chain State |
    // ---------------

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
        self.gateway_client
            .get_nonce(
                CoreBlockId::Tag(BlockTag::Pending),
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
    ) -> Result<TransactionInfo, StarknetClientError> {
        let sleep_duration = Duration::from_millis(TX_STATUS_POLL_INTERVAL_MS);
        loop {
            let res = self
                .gateway_client
                .get_transaction(tx_hash)
                .await
                .map_err(|err| StarknetClientError::Gateway(err.to_string()))?;
            log::info!("polling transaction, status: {:?}", res.status);

            // Break if the transaction has made it out of the received state
            match res.status {
                TransactionStatus::Rejected
                | TransactionStatus::Pending
                | TransactionStatus::AcceptedOnL2
                | TransactionStatus::AcceptedOnL1 => return Ok(res),
                _ => {}
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
            true, /* pending */
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
            true, /* pending */
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
        pending: bool,
    ) -> Result<Option<T>, StarknetClientError> {
        // Paginate backwards in block history
        let current_block = self.get_block_number().await?;
        let mut start_block = current_block.saturating_sub(BLOCK_PAGINATION_WINDOW);
        let mut end_block = if pending {
            CoreBlockId::Tag(BlockTag::Pending)
        } else {
            CoreBlockId::Number(current_block)
        };

        // Build the event filter template
        let mut filter = EventFilter {
            from_block: Some(CoreBlockId::Number(start_block)),
            to_block: Some(end_block),
            address: Some(self.contract_address),
            keys: if event_keys.is_empty() {
                None
            } else {
                Some(vec![event_keys])
            },
        };

        println!("got block range: [{start_block}, {end_block:?}]");

        let earliest_block = match self.config.chain {
            ChainId::AlphaGoerli => GOERLI_CONTRACT_DEPLOYMENT_BLOCK,
            ChainId::Mainnet => MAINNET_CONTRACT_DEPLOYMENT_BLOCK,
            ChainId::Devnet => DEVNET_CONTRACT_DEPLOYMENT_BLOCK,
        };
        while start_block >= earliest_block.saturating_sub(BLOCK_PAGINATION_WINDOW) {
            // Exhaust events from the start block to the end block
            let mut pagination_token = Some(String::from("0"));
            filter.from_block = Some(CoreBlockId::Number(start_block));
            filter.to_block = Some(end_block);

            while pagination_token.is_some() {
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

                pagination_token = res.continuation_token;
            }

            // If we are already at the genesis block, break
            if start_block == 0 {
                break;
            }

            // If no return value is found decrement the start and end block
            end_block = CoreBlockId::Number(start_block.saturating_sub(BLOCK_PAGINATION_WINDOW));
            start_block = start_block.saturating_sub(BLOCK_PAGINATION_WINDOW);
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
        let invocation_details = self
            .get_gateway_client()
            .get_transaction_trace(tx_hash)
            .await
            .map_err(|err| StarknetClientError::Gateway(err.to_string()))?
            .function_invocation
            .unwrap();

        // Check the wrapper call as well as any internal calls for the ciphertext
        // Typically the relevant calldata will be found in an internal call that the account
        // contract delegates to via __execute__
        let reduced_blinder_share = scalar_to_starknet_felt(&public_blinder_share);
        for invocation in
            iter::once(&invocation_details).chain(invocation_details.internal_calls.iter())
        {
            if let Ok(public_shares) = parse_shares_from_calldata(
                invocation.selector.unwrap(),
                &invocation.calldata,
                reduced_blinder_share,
            ) {
                return Ok(public_shares);
            }
        }

        log::error!("could not parse wallet public shares from transaction trace");
        Err(StarknetClientError::NotFound(
            ERR_WALLET_SHARES_NOT_FOUND.to_string(),
        ))
    }

    // ------------------------
    // | Contract Interaction |
    // ------------------------

    // --- Getters ---

    /// Check whether the given Merkle root is valid
    pub async fn check_merkle_root_valid(
        &self,
        root: MerkleRoot,
    ) -> Result<bool, StarknetClientError> {
        // TODO: Implement BigUint on the contract
        let reduced_root = scalar_to_starknet_felt(&root);
        let call = FunctionCall {
            contract_address: self.contract_address,
            entry_point_selector: *MERKLE_ROOT_IN_HISTORY_SELECTOR,
            calldata: vec![reduced_root],
        };

        let res = self.call_contract(call).await?;
        Ok(res[0].eq(&StarknetFieldElement::from(1u8)))
    }

    /// Check whether the given nullifier is used
    pub async fn check_nullifier_unused(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, StarknetClientError> {
        let reduced_nullifier = scalar_to_starknet_felt(&nullifier);
        let call = FunctionCall {
            contract_address: self.contract_address,
            entry_point_selector: *NULLIFIER_USED_SELECTOR,
            calldata: vec![reduced_nullifier],
        };

        let res = self.call_contract(call).await?;
        Ok(res[0].eq(&StarknetFieldElement::from(0u8)))
    }

    /// Return the hash of the transaction that last indexed secret shares for
    /// the given public blinder share
    ///
    /// Returns `None` if the public blinder share has not been used
    pub async fn get_public_blinder_tx(
        &self,
        public_blinder_share: Scalar,
    ) -> Result<Option<TransactionHash>, StarknetClientError> {
        let reduced_blinder_share = scalar_to_starknet_felt(&public_blinder_share);
        let call = FunctionCall {
            contract_address: self.contract_address,
            entry_point_selector: *GET_PUBLIC_BLINDER_TRANSACTION,
            calldata: vec![reduced_blinder_share],
        };

        self.call_contract(call)
            .await
            .map(|call_res| call_res[0])
            .map(|ret_val| {
                if ret_val.eq(&StarknetFieldElement::from(0u8)) {
                    None
                } else {
                    Some(ret_val)
                }
            })
    }

    // --- Setters ---

    /// Call the `new_wallet` contract method with the given source data
    ///
    /// Returns the transaction hash corresponding to the `new_wallet` invocation
    pub async fn new_wallet(
        &self,
        private_share_commitment: WalletShareStateCommitment,
        public_shares: SizedWalletShare,
        valid_wallet_create: ValidWalletCreateBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        assert!(
            self.config.account_enabled(),
            "no private key given to sign transactions with"
        );

        // Compute a commitment to the public shares
        let wallet_share_commitment =
            compute_wallet_commitment_from_private(public_shares.clone(), private_share_commitment);
        let mut calldata = vec![
            scalar_to_starknet_felt(&public_shares.blinder),
            scalar_to_starknet_felt(&wallet_share_commitment),
            scalar_to_starknet_felt(&private_share_commitment),
        ];

        // Pack the wallet's public shares into a list of felts
        calldata.append(&mut pack_serializable!(public_shares));

        // Pack the proof into a list of felts
        calldata.append(&mut pack_serializable!(valid_wallet_create));

        // Call the `new_wallet` contract function
        self.execute_transaction(Call {
            to: self.contract_address,
            selector: *NEW_WALLET_SELECTOR,
            calldata,
        })
        .await
    }

    /// Call the `update_wallet` function in the contract, passing it all the information
    /// needed to nullify the old wallet, transition the wallet to a newly committed one,
    /// and handle internal/external transfers
    ///
    /// Returns the transaction hash of the `update_wallet` call
    #[allow(clippy::too_many_arguments)]
    pub async fn update_wallet(
        &self,
        new_private_shares_commitment: WalletShareStateCommitment,
        old_shares_nullifier: Nullifier,
        external_transfer: Option<ExternalTransfer>,
        new_public_shares: SizedWalletShare,
        valid_wallet_update: ValidWalletUpdateBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        let new_wallet_share_commitment = compute_wallet_commitment_from_private(
            new_public_shares.clone(),
            new_private_shares_commitment,
        );
        let mut calldata = vec![
            scalar_to_starknet_felt(&old_shares_nullifier),
            scalar_to_starknet_felt(&new_public_shares.blinder),
            scalar_to_starknet_felt(&new_wallet_share_commitment),
            scalar_to_starknet_felt(&new_private_shares_commitment),
        ];

        // Add the external transfer tuple to the calldata
        if let Some(transfer) = external_transfer {
            calldata.push(1u8.into() /* external_transfers_len */);
            calldata.append(&mut transfer.into());
        } else {
            calldata.push(0u8.into() /* external_transfers_len */);
        }

        // Append the packed wallet shares and proof of `VALID WALLET UPDATE`
        calldata.append(&mut pack_serializable!(new_public_shares));
        calldata.append(&mut pack_serializable!(valid_wallet_update));

        // Call the `update_wallet` function in the contract
        self.execute_transaction(Call {
            to: self.contract_address,
            selector: *UPDATE_WALLET_SELECTOR,
            calldata,
        })
        .await
    }

    /// Submit a `match` transaction to the contract
    ///
    /// Returns the transaction hash of the call
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_match(
        &self,
        party0_old_shares_nullifier: Nullifier,
        party1_old_shares_nullifier: Nullifier,
        party0_private_share_commitment: WalletShareStateCommitment,
        party1_private_share_commitment: WalletShareStateCommitment,
        party0_public_shares: SizedWalletShare,
        party1_public_shares: SizedWalletShare,
        party0_validity_proofs: OrderValidityProofBundle,
        party1_validity_proofs: OrderValidityProofBundle,
        valid_match_proof: ValidMatchMpcBundle,
        valid_settle_proof: ValidSettleBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        // Compute commitments to both party's public shares
        let party0_wallet_share_commitment = compute_wallet_commitment_from_private(
            party0_public_shares.clone(),
            party0_private_share_commitment,
        );
        let party1_wallet_share_commitment = compute_wallet_commitment_from_private(
            party1_public_shares.clone(),
            party1_private_share_commitment,
        );

        // Build the calldata
        let mut calldata = vec![
            scalar_to_starknet_felt(&party0_old_shares_nullifier),
            scalar_to_starknet_felt(&party1_old_shares_nullifier),
            scalar_to_starknet_felt(&party0_public_shares.blinder),
            scalar_to_starknet_felt(&party1_public_shares.blinder),
            scalar_to_starknet_felt(&party0_wallet_share_commitment),
            scalar_to_starknet_felt(&party0_private_share_commitment),
            scalar_to_starknet_felt(&party1_wallet_share_commitment),
            scalar_to_starknet_felt(&party1_private_share_commitment),
        ];

        calldata.append(&mut pack_serializable!(party0_public_shares));
        calldata.append(&mut pack_serializable!(party1_public_shares));
        calldata.append(&mut pack_serializable!(party0_validity_proofs));
        calldata.append(&mut pack_serializable!(party1_validity_proofs));
        calldata.append(&mut pack_serializable!(valid_match_proof));
        calldata.append(&mut pack_serializable!(valid_settle_proof));

        // Call the contract
        self.execute_transaction(Call {
            to: self.contract_address,
            selector: *MATCH_SELECTOR,
            calldata,
        })
        .await
    }
}
