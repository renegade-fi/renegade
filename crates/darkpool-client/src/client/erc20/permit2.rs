//! Permit2 implementation on the Darkpool client

use alloy_primitives::{Address, U256};

use crate::{
    client::{
        DarkpoolClientInner, RenegadeProvider, erc20::abis::permit2::IPermit2::IPermit2Instance,
    },
    errors::DarkpoolClientError,
    traits::DarkpoolImpl,
};

impl<D: DarkpoolImpl> DarkpoolClientInner<D> {
    /// Get the allowance of a given token to a given spender
    pub async fn get_permit2_allowance(
        &self,
        owner: Address,
        token: Address,
        spender: Address,
    ) -> Result<U256, DarkpoolClientError> {
        let permit2 = self.permit2_client();
        let allowance = permit2
            .allowance(owner, token, spender)
            .call()
            .await
            .map_err(DarkpoolClientError::permit2)?;

        let amount = U256::from(allowance.amount);
        Ok(amount)
    }
    /// Get an instance of a permit2 contract client
    pub(crate) fn permit2_client(&self) -> IPermit2Instance<&RenegadeProvider> {
        let provider = self.provider();
        IPermit2Instance::new(self.permit2_addr, provider)
    }
}
