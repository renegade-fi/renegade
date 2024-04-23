//! Interface to MPC preprocessing methods

use common::types::{
    gossip::ClusterId,
    mpc_preprocessing::{PairwiseOfflineSetup, PreprocessingSlice},
};

use crate::{error::StateError, notifications::ProposalWaiter, State, StateTransition};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the size of available preprocessing values
    pub fn get_mpc_prep_size(&self, cluster: &ClusterId) -> Result<PreprocessingSlice, StateError> {
        let tx = self.db.new_read_tx()?;
        let size = tx.get_mpc_prep_size(cluster)?.unwrap_or_default();
        tx.commit()?;

        Ok(size)
    }

    // -----------
    // | Setters |
    // -----------

    /// Add values to the preprocessing store
    pub fn append_preprocessing_values(
        &self,
        cluster: ClusterId,
        values: PairwiseOfflineSetup,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddMpcPreprocessingValues { cluster, values })
    }

    /// Pop a set of values for consumption by the caller
    pub fn consume_preprocessing_values(
        &self,
        cluster: ClusterId,
        request: PreprocessingSlice,
    ) -> Result<ProposalWaiter, StateError> {
        // Use self as recipient
        let recipient = self.get_peer_id()?;
        self.send_proposal(StateTransition::ConsumePreprocessingValues {
            recipient,
            cluster,
            request,
        })
    }
}
