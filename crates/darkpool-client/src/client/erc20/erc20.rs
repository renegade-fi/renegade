//! ERC20 implementation on the Darkpool client

use alloy_primitives::{Address, U256};

use crate::{
    client::{DarkpoolClient, RenegadeProvider, erc20::abis::erc20::IERC20::IERC20Instance},
    errors::DarkpoolClientError,
};

impl DarkpoolClient {
    /// Get the ticker of a given erc20 token
    pub async fn get_erc20_ticker(&self, token: Address) -> Result<String, DarkpoolClientError> {
        let erc20 = self.erc20_client(token);
        let ticker = erc20.symbol().call().await.map_err(DarkpoolClientError::erc20)?;
        Ok(ticker)
    }

    /// Get the erc20 balance of a given address
    pub async fn get_erc20_balance(
        &self,
        token: Address,
        address: Address,
    ) -> Result<U256, DarkpoolClientError> {
        let erc20 = self.erc20_client(token);
        let balance = erc20.balanceOf(address).call().await.map_err(DarkpoolClientError::erc20)?;
        Ok(balance)
    }

    /// Get an instance of an erc20 contract client
    pub(crate) fn erc20_client(&self, token: Address) -> IERC20Instance<&RenegadeProvider> {
        let provider = self.provider();
        IERC20Instance::new(token, provider)
    }
}
