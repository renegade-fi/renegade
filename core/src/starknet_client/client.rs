//! A wrapper around the starknet client made available by:
//! https://docs.rs/starknet-core/latest/starknet_core/

use std::{str::FromStr, sync::Arc, time::Duration};

use circuits::types::wallet::WalletCommitment;
use crypto::fields::{biguint_to_starknet_felt, scalar_to_biguint, starknet_felt_to_biguint};
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use reqwest::Url;
use starknet::providers::{
    jsonrpc::{HttpTransport, JsonRpcClient},
    Provider, ProviderError,
};
use starknet::{
    accounts::{Account, AccountError, Call, SingleOwnerAccount},
    core::{
        types::{FieldElement as StarknetFieldElement, TransactionInfo, TransactionStatus},
        utils::get_selector_from_name,
    },
    providers::{SequencerGatewayProvider, SequencerGatewayProviderError},
    signers::{LocalWallet, SigningKey},
};
use tracing::log;

use crate::proof_generation::jobs::ValidWalletCreateBundle;

use super::ChainId;

/// A type alias for the Starknet client's common account error pattern
pub type AccountErr = AccountError<
    <SingleOwnerAccount<SequencerGatewayProvider, LocalWallet> as Account>::SignError,
    <SequencerGatewayProvider as Provider>::Error,
>;

/// The interval at which to poll the gateway for transaction status
const TX_STATUS_POLL_INTERVAL_MS: u64 = 10_000; // 10 seconds
/// The fee estimate multiplier to use as `MAX_FEE` for transactions
const MAX_FEE_MULTIPLIER: f32 = 1.5;

lazy_static! {
    /// Contract selector to create a new wallet
    static ref NEW_WALLET_SELECTOR: StarknetFieldElement = get_selector_from_name("new_wallet")
        .unwrap();
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

        log::info!("write enabled: {}", config.account_enabled());

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

    // ---------------
    // | Chain State |
    // ---------------

    /// Poll a transaction until it is finalized into the accepted on L2 state
    pub async fn poll_transaction_completed(
        &self,
        tx_hash: StarknetFieldElement,
    ) -> Result<TransactionInfo, ProviderError<SequencerGatewayProviderError>> {
        let sleep_duration = Duration::from_millis(TX_STATUS_POLL_INTERVAL_MS);
        loop {
            let res = self.gateway_client.get_transaction(tx_hash).await?;
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

    // ------------------------
    // | Contract Interaction |
    // ------------------------

    /// Call the `new_wallet` contract method with the given source data
    ///
    /// Returns the transaction hash corresponding to the `new_wallet` invocation
    ///
    /// TODO: Add proof and wallet encryption under pk_view to the contract
    pub async fn new_wallet(
        &self,
        wallet_commitment: WalletCommitment,
        _valid_wallet_create: ValidWalletCreateBundle,
    ) -> Result<StarknetFieldElement, AccountErr> {
        assert!(
            self.config.account_enabled(),
            "no private key given to sign transactions with"
        );

        // Call the `new_wallet` contract function
        let commitment_felt = Self::reduce_scalar_to_felt(&wallet_commitment);
        let call = Call {
            to: self.contract_address,
            selector: *NEW_WALLET_SELECTOR,
            calldata: vec![commitment_felt],
        };

        // Estimate the fee and add a buffer to avoid rejected transaction
        let execution = self.get_account().execute(vec![call]);

        let fee_estimate = execution.estimate_fee().await?;
        let max_fee = (fee_estimate.overall_fee as f32) * MAX_FEE_MULTIPLIER;
        let max_fee = StarknetFieldElement::from(max_fee as u64);

        // Send the transaction and await receipt
        execution
            .max_fee(max_fee)
            .send()
            .await
            .map(|res| res.transaction_hash)
    }
}
