//! A wrapper around the starknet client made available by:
//! https://docs.rs/starknet-core/latest/starknet_core/

use std::{
    collections::{HashMap, HashSet},
    iter,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use circuits::{
    types::wallet::{NoteCommitment, Nullifier, WalletCommitment},
    zk_gadgets::merkle::MerkleRoot,
};
use crypto::{
    elgamal::ElGamalCiphertext,
    fields::{
        biguint_to_starknet_felt, scalar_to_biguint, starknet_felt_to_biguint,
        starknet_felt_to_scalar, starknet_felt_to_u64,
    },
};
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use reqwest::Url;
use starknet::{
    accounts::{Account, Call, SingleOwnerAccount},
    core::types::{
        BlockId as CoreBlockId, FieldElement as StarknetFieldElement, TransactionInfo,
        TransactionStatus,
    },
    providers::{
        jsonrpc::models::{BlockTag, EventFilter},
        SequencerGatewayProvider,
    },
    signers::{LocalWallet, SigningKey},
};
use starknet::{
    core::types::{CallContractResult, CallFunction},
    providers::{
        jsonrpc::{
            models::{BlockId, EmittedEvent},
            HttpTransport, JsonRpcClient,
        },
        Provider,
    },
};
use tracing::log;

use crate::{
    proof_generation::jobs::{
        ValidCommitmentsBundle, ValidMatchEncryptBundle, ValidMatchMpcBundle, ValidSettleBundle,
        ValidWalletCreateBundle, ValidWalletUpdateBundle,
    },
    starknet_client::{
        GET_WALLET_LAST_UPDATED_SELECTOR, INTERNAL_NODE_CHANGED_EVENT_SELECTOR, MATCH_SELECTOR,
        MERKLE_ROOT_IN_HISTORY_SELECTOR, NEW_WALLET_SELECTOR, UPDATE_WALLET_SELECTOR,
        VALUE_INSERTED_EVENT_SELECTOR,
    },
    state::{wallet::MerkleAuthenticationPath, MerkleTreeCoords},
    MERKLE_HEIGHT,
};

use super::{
    error::StarknetClientError,
    helpers::{pack_bytes_into_felts, parse_ciphertext_from_calldata},
    types::ExternalTransfer,
    ChainId, DEFAULT_AUTHENTICATION_PATH, NULLIFIER_USED_SELECTOR, SETTLE_SELECTOR,
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
/// The earliest block to search events for, i.e. the contract deployment block
const EARLIEST_BLOCK: u64 = 780361;
/// The page size to request when querying events
const EVENTS_PAGE_SIZE: u64 = 50;
/// The interval at which to poll the gateway for transaction status
const TX_STATUS_POLL_INTERVAL_MS: u64 = 10_000; // 10 seconds
/// The fee estimate multiplier to use as `MAX_FEE` for transactions
const MAX_FEE_MULTIPLIER: f32 = 1.5;

/// Error message thrown when the client cannot find a ciphertext blob in
/// a transaction's trace
const ERR_CIPHERTEXT_NOT_FOUND: &str = "ciphertext blob not found in tx trace";

//r Macro helper to pack a serializable value into a vector of felts
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
    /// The API key for the JSON-RPC node
    ///
    /// For now, we require only the API key's ID on our RPC node,
    /// so this parameter is unused
    pub infura_api_key: Option<String>,
    /// The starknet address of the account corresponding to the given key
    pub starknet_account_address: Option<String>,
    /// The starknet signing key, used to submit transactions on-chain
    pub starknet_pkey: Option<String>,
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
        self.starknet_pkey.is_some() && self.starknet_account_address.is_some()
    }

    /// Build a gateway client from the config values
    pub fn new_gateway_client(&self) -> SequencerGatewayProvider {
        match self.chain {
            ChainId::AlphaGoerli => SequencerGatewayProvider::starknet_alpha_goerli(),
            ChainId::Mainnet => SequencerGatewayProvider::starknet_alpha_mainnet(),
        }
    }

    /// Create a new JSON-RPC client using the API credentials in the config
    ///
    /// Returns `None` if the config does not specify the correct credentials
    pub fn new_jsonrpc_client(&self) -> Option<JsonRpcClient<HttpTransport>> {
        if !self.enabled() {
            return None;
        }

        let transport =
            HttpTransport::new(Url::parse(&self.starknet_json_rpc_addr.clone().unwrap()).ok()?);
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
    /// The account that may be used to sign outbound transactions
    account: Option<Arc<SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>>>,
}

impl StarknetClient {
    /// Constructor
    pub fn new(config: StarknetClientConfig) -> Self {
        // Build the gateway and JSON-RPC clients
        let gateway_client = Arc::new(config.new_gateway_client());
        let jsonrpc_client = config.new_jsonrpc_client().map(Arc::new);

        // Build an account to sign transactions with
        let account = if config.account_enabled() {
            let account_addr = config.starknet_account_address.clone().unwrap();
            let key = config.starknet_pkey.clone().unwrap();
            let account_addr_felt = StarknetFieldElement::from_str(&account_addr).unwrap();
            let key_felt = StarknetFieldElement::from_str(&key).unwrap();

            let signer = LocalWallet::from(SigningKey::from_secret_scalar(key_felt));
            let account = SingleOwnerAccount::new(
                config.new_gateway_client(),
                signer,
                account_addr_felt,
                config.chain.into(),
            );

            Some(account)
        } else {
            None
        };

        // Wrap in an Arc for read access across workers
        let account = account.map(Arc::new);

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
            account,
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

    /// Get the underlying account as an immutable reference
    pub fn get_account(&self) -> &SingleOwnerAccount<SequencerGatewayProvider, LocalWallet> {
        self.account.as_ref().unwrap()
    }

    /// A helper to reduce a Dalek scalar modulo the Stark field
    ///
    /// Note that this a bandaid, we will be replacing all the felts with U256
    /// values in the contract to emulate the Dalek field
    fn reduce_scalar_to_felt(val: &Scalar) -> StarknetFieldElement {
        let val_bigint = scalar_to_biguint(val);
        let modulus_bigint = starknet_felt_to_biguint(&StarknetFieldElement::MAX) + 1u8;
        let val_mod_starknet_prime = val_bigint % modulus_bigint;

        biguint_to_starknet_felt(&val_mod_starknet_prime)
    }

    /// Helper to make a view call to the contract
    async fn call_contract(
        &self,
        call: CallFunction,
    ) -> Result<CallContractResult, StarknetClientError> {
        self.get_gateway_client()
            .call_contract(call, CoreBlockId::Pending)
            .await
            .map_err(|err| StarknetClientError::Gateway(err.to_string()))
    }

    /// Helper to setup a contract call with the correct max fee and account nonce
    async fn execute_transaction(
        &self,
        call: Call,
    ) -> Result<TransactionHash, StarknetClientError> {
        // Estimate the fee and add a buffer to avoid rejected transaction
        let acct_nonce = self.pending_block_nonce().await?;
        let execution = self.get_account().execute(vec![call]).nonce(acct_nonce);

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

    /// Get the nonce of the account in the pending block
    pub async fn pending_block_nonce(&self) -> Result<StarknetFieldElement, StarknetClientError> {
        self.gateway_client
            .get_nonce(self.get_account().address(), CoreBlockId::Pending)
            .await
            .map_err(|err| StarknetClientError::Rpc(err.to_string()))
    }

    /// Poll a transaction until it is finalized into the accepted on L2 state
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
            false, /* pending */
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
        let commitment_starknet_felt = Self::reduce_scalar_to_felt(&commitment);

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
            false, /* pending */
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
        let mut start_block = self.get_block_number().await? - BLOCK_PAGINATION_WINDOW;
        let mut end_block = if pending {
            BlockId::Tag(BlockTag::Pending)
        } else {
            BlockId::Number(self.get_block_number().await?)
        };

        let keys = if event_keys.is_empty() {
            None
        } else {
            Some(event_keys)
        };

        while start_block > EARLIEST_BLOCK - BLOCK_PAGINATION_WINDOW {
            // Exhaust events from the start block to the end block
            let mut pagination_token = Some(String::from("0"));
            let filter = EventFilter {
                from_block: Some(BlockId::Number(start_block)),
                to_block: Some(end_block.clone()),
                address: Some(self.contract_address),
                keys: keys.clone(),
            };

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

            // If no return value is found decrement the start and end block
            end_block = BlockId::Number(start_block - 1);
            start_block -= BLOCK_PAGINATION_WINDOW;
        }

        Ok(None)
    }

    /// Pull the ciphertext blob from the calldata of the given transaction, return it
    /// as a vector of ElGamal ciphertexts
    pub async fn fetch_ciphertext_from_tx(
        &self,
        tx_hash: TransactionHash,
    ) -> Result<Vec<ElGamalCiphertext>, StarknetClientError> {
        // Lookup the calldata for the given tx
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
        for invocation in
            iter::once(&invocation_details).chain(invocation_details.internal_calls.iter())
        {
            if let Ok(ciphertext) =
                parse_ciphertext_from_calldata(invocation.selector.unwrap(), &invocation.calldata)
            {
                return Ok(ciphertext);
            }
        }

        log::error!("could not parse ciphertext blob from transaction trace");
        Err(StarknetClientError::NotFound(
            ERR_CIPHERTEXT_NOT_FOUND.to_string(),
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
        let reduced_root = Self::reduce_scalar_to_felt(&root);
        let call = CallFunction {
            contract_address: self.contract_address,
            entry_point_selector: *MERKLE_ROOT_IN_HISTORY_SELECTOR,
            calldata: vec![reduced_root],
        };

        let res = self.call_contract(call).await?;
        Ok(res.result[0].eq(&StarknetFieldElement::from(1u8)))
    }

    /// Check whether the given nullifier is used
    pub async fn check_nullifier_unused(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, StarknetClientError> {
        let reduced_nullifier = Self::reduce_scalar_to_felt(&nullifier);
        let call = CallFunction {
            contract_address: self.contract_address,
            entry_point_selector: *NULLIFIER_USED_SELECTOR,
            calldata: vec![reduced_nullifier],
        };

        let res = self.call_contract(call).await?;
        Ok(res.result[0].eq(&StarknetFieldElement::from(0u8)))
    }

    /// Call the "get_wallet_update" view function in the contract
    pub async fn get_wallet_last_updated(
        &self,
        pk_view: Scalar,
    ) -> Result<TransactionHash, StarknetClientError> {
        let reduced_pk_view = Self::reduce_scalar_to_felt(&pk_view);
        let call = CallFunction {
            contract_address: self.contract_address,
            entry_point_selector: *GET_WALLET_LAST_UPDATED_SELECTOR,
            calldata: vec![reduced_pk_view],
        };

        self.call_contract(call)
            .await
            .map(|call_res| call_res.result[0])
    }

    // --- Setters ---

    /// Call the `new_wallet` contract method with the given source data
    ///
    /// Returns the transaction hash corresponding to the `new_wallet` invocation
    ///
    /// TODO: Add proof and wallet encryption under pk_view to the contract
    pub async fn new_wallet(
        &self,
        pk_view: Scalar,
        wallet_commitment: WalletCommitment,
        wallet_ciphertext: Vec<ElGamalCiphertext>,
        valid_wallet_create: ValidWalletCreateBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        assert!(
            self.config.account_enabled(),
            "no private key given to sign transactions with"
        );

        // Reduce the wallet commitment mod the Starknet field
        let mut calldata = vec![
            Self::reduce_scalar_to_felt(&pk_view),
            Self::reduce_scalar_to_felt(&wallet_commitment),
        ];
        // Pack the ciphertext into a list of felts
        calldata.append(&mut pack_serializable!(wallet_ciphertext));
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
        pk_view: Scalar,
        new_wallet_commitment: WalletCommitment,
        old_match_nullifier: Nullifier,
        old_spend_nullifier: Nullifier,
        external_transfer: Option<ExternalTransfer>,
        internal_transfer_ciphertext: Option<Vec<ElGamalCiphertext>>,
        wallet_ciphertext: Vec<ElGamalCiphertext>,
        valid_wallet_update: ValidWalletUpdateBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        let mut calldata = vec![
            Self::reduce_scalar_to_felt(&pk_view),
            Self::reduce_scalar_to_felt(&new_wallet_commitment),
            Self::reduce_scalar_to_felt(&old_match_nullifier),
            Self::reduce_scalar_to_felt(&old_spend_nullifier),
        ];

        // Append the internal transfer ciphertext if there is one
        if let Some(internal_transfer) = internal_transfer_ciphertext {
            calldata.append(&mut pack_serializable!(internal_transfer));
        } else {
            // Otherwise, push 0 to the calldata to indicate a zero-length ciphertext blob
            calldata.push(0u8.into());
        }

        // Add the external transfer tuple to the calldata
        if let Some(transfer) = external_transfer {
            calldata.push(1u8.into() /* external_transfers_len */);
            calldata.append(&mut transfer.into());
        } else {
            calldata.push(0u8.into() /* external_transfers_len */);
        }

        // Append the packed wallet ciphertext and proof of `VALID WALLET UPDATE`
        calldata.append(&mut pack_serializable!(wallet_ciphertext));
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
        match_nullifier1: Nullifier,
        match_nullifier2: Nullifier,
        party0_note_commitment: NoteCommitment,
        party0_note_ciphertext: Vec<ElGamalCiphertext>,
        party1_note_commitment: NoteCommitment,
        party1_note_ciphertext: Vec<ElGamalCiphertext>,
        relayer0_note_commitment: NoteCommitment,
        relayer0_note_ciphertext: Vec<ElGamalCiphertext>,
        relayer1_note_commitment: NoteCommitment,
        relayer1_note_ciphertext: Vec<ElGamalCiphertext>,
        protocol_note_commitment: NoteCommitment,
        protocol_note_ciphertext: Vec<ElGamalCiphertext>,
        party0_validity_proof: ValidCommitmentsBundle,
        party1_validity_proof: ValidCommitmentsBundle,
        valid_match_proof: ValidMatchMpcBundle,
        valid_encryption_proof: ValidMatchEncryptBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        // Build the calldata
        let mut calldata = vec![
            Self::reduce_scalar_to_felt(&match_nullifier1),
            Self::reduce_scalar_to_felt(&match_nullifier2),
        ];
        calldata.push(Self::reduce_scalar_to_felt(&party0_note_commitment));
        calldata.append(&mut pack_serializable!(party0_note_ciphertext));

        calldata.push(Self::reduce_scalar_to_felt(&party1_note_commitment));
        calldata.append(&mut pack_serializable!(party1_note_ciphertext));

        calldata.push(Self::reduce_scalar_to_felt(&relayer0_note_commitment));
        calldata.append(&mut pack_serializable!(relayer0_note_ciphertext));

        calldata.push(Self::reduce_scalar_to_felt(&relayer1_note_commitment));
        calldata.append(&mut pack_serializable!(relayer1_note_ciphertext));

        calldata.push(Self::reduce_scalar_to_felt(&protocol_note_commitment));
        calldata.append(&mut pack_serializable!(protocol_note_ciphertext));

        // Build the proof blob that consists of all four proofs
        let mut proof_blob = Vec::new();
        proof_blob.append(&mut serde_json::to_vec(&party0_validity_proof).unwrap());
        proof_blob.append(&mut serde_json::to_vec(&party1_validity_proof).unwrap());
        proof_blob.append(&mut serde_json::to_vec(&valid_match_proof).unwrap());
        proof_blob.append(&mut serde_json::to_vec(&valid_encryption_proof).unwrap());

        calldata.append(&mut pack_serializable!(proof_blob));

        // Call the contract
        self.execute_transaction(Call {
            to: self.contract_address,
            selector: *MATCH_SELECTOR,
            calldata,
        })
        .await
    }

    /// Submit a `settle` transaction to the contract
    ///
    /// Returns the transaction hash of the call
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_settle(
        &self,
        pk_view: Scalar,
        new_wallet_commit: WalletCommitment,
        old_match_nullifier: Nullifier,
        old_spend_nullifier: Nullifier,
        note_redeem_nullifier: Nullifier,
        wallet_ciphertext: Vec<ElGamalCiphertext>,
        proof: ValidSettleBundle,
    ) -> Result<TransactionHash, StarknetClientError> {
        let mut calldata = vec![
            Self::reduce_scalar_to_felt(&pk_view),
            StarknetFieldElement::from(0u8), // from_internal_transfer
            Self::reduce_scalar_to_felt(&new_wallet_commit),
            Self::reduce_scalar_to_felt(&old_match_nullifier),
            Self::reduce_scalar_to_felt(&old_spend_nullifier),
            Self::reduce_scalar_to_felt(&note_redeem_nullifier),
        ];

        calldata.append(&mut pack_serializable!(wallet_ciphertext));
        calldata.append(&mut pack_serializable!(proof));

        // Call the `settle` contract function
        self.execute_transaction(Call {
            to: self.contract_address,
            selector: *SETTLE_SELECTOR,
            calldata,
        })
        .await
    }
}
