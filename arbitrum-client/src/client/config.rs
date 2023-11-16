//! The configuration options for the Arbitrum client, along with
//! convenience methods for converting them into richer types that the
//! client works with.

use std::{error::Error, fmt::Display, str::FromStr, sync::Arc};

use ethers::{
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::Address,
};

use crate::abi::DarkpoolContract;

pub struct ArbitrumClientConfig {
    /// The address of the darkpool proxy contract.
    ///
    /// This is the main entrypoint to interaction with the darkpool.
    pub proxy_address: String,
    /// The address of the darkpool implementation contract.
    ///
    /// This is used to filter for events emitted by the darkpool.
    pub implementation_address: String,
    /// The URL of the Arbitrum RPC endpoint
    pub rpc_url: String,
    /// The private key of the account to use for signing transactions
    pub arb_priv_key: String,
}

#[derive(Clone, Debug)]
pub enum ArbitrumClientConfigError {
    RpcClientInitialization(String),
    ContractAddressParsing(String),
}

impl Display for ArbitrumClientConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for ArbitrumClientConfigError {}

impl ArbitrumClientConfig {
    async fn get_rpc_client(&self) -> Result<Arc<impl Middleware>, ArbitrumClientConfigError> {
        let provider = Provider::<Http>::try_from(&self.rpc_url)
            .map_err(|e| ArbitrumClientConfigError::RpcClientInitialization(e.to_string()))?;

        let wallet = LocalWallet::from_str(&self.arb_priv_key)
            .map_err(|e| ArbitrumClientConfigError::RpcClientInitialization(e.to_string()))?;

        let chain_id = provider
            .get_chainid()
            .await
            .map_err(|e| ArbitrumClientConfigError::RpcClientInitialization(e.to_string()))?
            .as_u64();

        let rpc_client = Arc::new(SignerMiddleware::new(
            provider,
            wallet.clone().with_chain_id(chain_id),
        ));

        Ok(rpc_client)
    }

    fn get_proxy_address(&self) -> Result<Address, ArbitrumClientConfigError> {
        Address::from_str(&self.proxy_address)
            .map_err(|e| ArbitrumClientConfigError::ContractAddressParsing(e.to_string()))
    }

    pub async fn get_contract_instance(
        &self,
    ) -> Result<DarkpoolContract<impl Middleware>, ArbitrumClientConfigError> {
        let rpc_client = self.get_rpc_client().await?;
        let contract_address = self.get_proxy_address()?;
        let contract = DarkpoolContract::new(contract_address, rpc_client);
        Ok(contract)
    }
}
