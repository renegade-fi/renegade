//! ERC20 implementation on the Darkpool client

use std::cmp;

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

    /// Get the usable ring-0 balance for a token and owner.
    ///
    /// Usable balance is defined as the minimum of the wallet's ERC20 balance
    /// and the owner's Permit2 allowance to the darkpool.
    pub async fn get_erc20_usable_balance(
        &self,
        token: Address,
        owner: Address,
    ) -> Result<U256, DarkpoolClientError> {
        let erc20 = self.erc20_client(token);
        let erc20_balance =
            erc20.balanceOf(owner).call().await.map_err(DarkpoolClientError::erc20)?;
        let permit_allowance = self.get_darkpool_allowance(owner, token).await?;
        Ok(cmp::min(erc20_balance, permit_allowance))
    }

    /// Get an instance of an erc20 contract client
    pub(crate) fn erc20_client(&self, token: Address) -> IERC20Instance<&RenegadeProvider> {
        let provider = self.provider();
        IERC20Instance::new(token, provider)
    }
}
