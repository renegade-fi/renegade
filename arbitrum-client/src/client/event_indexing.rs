//! Defines `ArbitrumClient` helpers that allow for indexing events
//! emitted by the darkpool contract

use constants::ScalarField;
use ethers::{
    types::{TxHash, H256},
    utils::keccak256,
};

use crate::{
    abi::WalletUpdatedFilter, errors::ArbitrumClientError, helpers::serialize_calldata,
    serde_def_types::SerdeScalarField,
};

use super::ArbitrumClient;

impl ArbitrumClient {
    /// Return the hash of the transaction that last indexed secret shares for
    /// the given public blinder share
    ///
    /// Returns `None` if the public blinder share has not been used
    pub async fn get_public_blinder_tx(
        &self,
        public_blinder_share: ScalarField,
    ) -> Result<Option<TxHash>, ArbitrumClientError> {
        let public_blinder_share_bytes =
            serialize_calldata(&SerdeScalarField(public_blinder_share))?;
        let public_blinder_share_hash = H256::from(keccak256(public_blinder_share_bytes));
        let events = self
            .darkpool_event_source
            .event::<WalletUpdatedFilter>()
            .topic1(public_blinder_share_hash)
            .from_block(self.deploy_block)
            .query_with_meta()
            .await
            .map_err(|e| ArbitrumClientError::EventQuerying(e.to_string()))?;

        // TODO: Assert ordering (want latest)
        Ok(events.last().map(|(_, meta)| meta.transaction_hash))
    }
}
