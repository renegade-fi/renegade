//! Interface to MPC preprocessing methods

use common::types::{
    gossip::ClusterId,
    mpc_preprocessing::{PairwiseOfflineSetup, PreprocessingSlice},
};

use crate::{
    error::StateError, notifications::ProposalWaiter, replicationv2::raft::NetworkEssential, State,
    StateHandle, StateTransition,
};

impl<N: NetworkEssential> StateHandle<N> {
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
    pub async fn append_preprocessing_values(
        &self,
        cluster: ClusterId,
        values: PairwiseOfflineSetup,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddMpcPreprocessingValues { cluster, values }).await
    }

    /// Pop a set of values for consumption by the caller
    pub async fn consume_preprocessing_values(
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
        .await
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use common::types::{
        gossip::ClusterId,
        mpc_preprocessing::{PairwiseOfflineSetup, PreprocessingSlice},
    };

    use crate::{
        applicator::mpc_preprocessing::test_helpers::mock_prep_values, test_helpers::mock_state,
    };

    #[tokio::test]
    async fn test_add_prep_values() {
        let state = mock_state().await;
        let cluster = ClusterId::from_str("test").unwrap();

        // One of each type
        let prep = mock_prep_values(1, 1, 1, 1, 1);
        let waiter = state.append_preprocessing_values(cluster.clone(), prep).await.unwrap();
        waiter.await.unwrap();

        // Check the size of the preprocessing store
        let size = state.get_mpc_prep_size(&cluster).unwrap();
        assert_eq!(size.num_bits, 1);
        assert_eq!(size.num_values, 1);
        assert_eq!(size.num_inverse_pairs, 1);
        assert_eq!(size.num_input_masks, 1);
        assert_eq!(size.num_triples, 1);
    }

    #[tokio::test]
    async fn test_consume_prep_values() {
        let state = mock_state().await;
        let cluster = ClusterId::from_str("test").unwrap();

        // Add prep values to the state, one of each type
        let prep = mock_prep_values(1, 1, 1, 1, 1);
        let _ = state.append_preprocessing_values(cluster.clone(), prep).await.unwrap().await;

        let request = PreprocessingSlice { num_inverse_pairs: 1, ..Default::default() };
        let waiter = state.consume_preprocessing_values(cluster, request).await.unwrap();
        let prep: PairwiseOfflineSetup = waiter.await.unwrap().into();

        let vals = prep.values;
        assert_eq!(vals.random_bits.len(), 0);
        assert_eq!(vals.random_values.len(), 0);
        assert_eq!(vals.my_input_masks.0.len(), 0);
        assert_eq!(vals.counterparty_input_masks.len(), 0);
        assert_eq!(vals.beaver_triples.0.len(), 0);
        assert_eq!(vals.inverse_pairs.0.len(), 1);
    }
}
