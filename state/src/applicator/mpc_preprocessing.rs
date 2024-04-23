//! Applicator implementation for the preprocessing functionality

use common::types::{
    gossip::{ClusterId, WrappedPeerId},
    mpc_preprocessing::{PairwiseOfflineSetup, PreprocessingSlice},
};

use super::{error::StateApplicatorError, return_type::ApplicatorReturnType, StateApplicator};

impl StateApplicator {
    /// Add values to the preprocessing state for a given cluster
    pub fn add_preprocessing_values(
        &self,
        cluster: &ClusterId,
        value: &PairwiseOfflineSetup,
    ) -> Result<(), StateApplicatorError> {
        let tx = self.db().new_write_tx()?;
        tx.append_mpc_prep_values(cluster, value)?;
        tx.commit()?;

        Ok(())
    }

    /// Consume values from the preprocessing state for a given cluster
    pub fn consume_preprocessing_values(
        &self,
        recipient: WrappedPeerId,
        cluster: &ClusterId,
        slice: &PreprocessingSlice,
    ) -> Result<ApplicatorReturnType, StateApplicatorError> {
        let tx = self.db().new_write_tx()?;
        let values = tx.consume_mpc_prep_values(cluster, slice)?;
        let my_id = tx.get_peer_id()?;
        tx.commit()?;

        // Only the recipient should take ownership of the values
        if my_id == recipient {
            return Ok(ApplicatorReturnType::MpcPrep(values));
        }

        Ok(ApplicatorReturnType::None)
    }
}

#[cfg(test)]
pub mod test_helpers {
    use common::types::mpc_preprocessing::PairwiseOfflineSetup;
    use constants::{Scalar, ScalarShare};
    use itertools::Itertools;
    use rand::thread_rng;

    /// Get a random preprocessing values set
    pub fn mock_prep_values(
        bits: usize,
        values: usize,
        inverse_pairs: usize,
        input_masks: usize,
        triplets: usize,
    ) -> PairwiseOfflineSetup {
        let mut rng = thread_rng();
        let key = Scalar::random(&mut rng);
        let mut prep = PairwiseOfflineSetup::new(key);
        let vals = &mut prep.values;

        let share = ScalarShare::new(Scalar::random(&mut rng), Scalar::random(&mut rng));
        vals.random_bits = (0..bits).map(|_| share).collect_vec();
        vals.random_values = (0..values).map(|_| share).collect_vec();
        vals.inverse_pairs.0 = (0..inverse_pairs).map(|_| share).collect_vec();
        vals.inverse_pairs.1 = (0..inverse_pairs).map(|_| share).collect_vec();
        vals.my_input_masks.0 = (0..input_masks).map(|_| Scalar::random(&mut rng)).collect_vec();
        vals.my_input_masks.1 = (0..input_masks).map(|_| share).collect_vec();
        vals.counterparty_input_masks = (0..input_masks).map(|_| share).collect_vec();
        vals.beaver_triples.0 = (0..triplets).map(|_| share).collect_vec();
        vals.beaver_triples.1 = (0..triplets).map(|_| share).collect_vec();
        vals.beaver_triples.2 = (0..triplets).map(|_| share).collect_vec();

        prep
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use common::types::{
        gossip::{ClusterId, WrappedPeerId},
        mpc_preprocessing::PreprocessingSlice,
    };

    use crate::{
        applicator::{
            mpc_preprocessing::test_helpers::mock_prep_values, return_type::ApplicatorReturnType,
            test_helpers::mock_applicator,
        },
        storage::db::DB,
    };

    /// Set the local peer ID
    fn set_local_peer_id(peer_id: &WrappedPeerId, db: &DB) {
        let tx = db.new_write_tx().unwrap();
        tx.set_peer_id(peer_id).unwrap();
        tx.commit().unwrap();
    }

    /// Tests adding preprocessing values to the state
    #[test]
    fn test_add_prep_values() {
        let applicator = mock_applicator();
        let cluster = ClusterId::from_str("test").unwrap();

        // One inverse pair and two bits
        let prep = mock_prep_values(2, 0, 1, 0, 0);
        applicator.add_preprocessing_values(&cluster, &prep).unwrap();

        // Check the size of the preprocessing state
        let tx = applicator.db().new_read_tx().unwrap();
        let values = tx.get_mpc_prep_size(&cluster).unwrap().unwrap();
        tx.commit().unwrap();

        assert_eq!(
            values,
            PreprocessingSlice { num_bits: 2, num_inverse_pairs: 1, ..Default::default() }
        );
    }

    /// Tests consuming preprocessing values from a node that isn't the
    /// recipient
    #[test]
    #[allow(non_snake_case)]
    fn test_consume_prep__not_recipient() {
        let peer_id = WrappedPeerId::random();
        let applicator = mock_applicator();
        set_local_peer_id(&peer_id, applicator.db());
        let cluster = ClusterId::from_str("test").unwrap();

        // Add values to the preprocessing
        let prep = mock_prep_values(0, 0, 0, 1, 2);
        applicator.add_preprocessing_values(&cluster, &prep).unwrap();

        // Consume a single triple
        let slice = PreprocessingSlice { num_triples: 1, ..Default::default() };
        let result = applicator
            .consume_preprocessing_values(WrappedPeerId::random(), &cluster, &slice)
            .unwrap();

        // No value should be received
        match result {
            ApplicatorReturnType::None => (),
            _ => panic!("Expected MpcPrep"),
        };
    }

    /// Tests consuming preprocessing values from a node that is the
    /// recipient
    #[test]
    #[allow(non_snake_case)]
    fn test_consume_prep__as_recipient() {
        let peer_id = WrappedPeerId::random();
        let applicator = mock_applicator();
        set_local_peer_id(&peer_id, applicator.db());
        let cluster = ClusterId::from_str("test").unwrap();

        // Add values to the preprocessing
        let prep = mock_prep_values(0, 0, 0, 1, 2);
        applicator.add_preprocessing_values(&cluster, &prep).unwrap();

        // Consume a single triple
        let slice = PreprocessingSlice { num_triples: 1, ..Default::default() };
        let result = applicator.consume_preprocessing_values(peer_id, &cluster, &slice).unwrap();
        let values = match result {
            ApplicatorReturnType::MpcPrep(prep) => prep.values,
            _ => panic!("Expected MpcPrep"),
        };

        assert_eq!(values.beaver_triples.0[0], prep.values.beaver_triples.0[0]);
        assert_eq!(values.beaver_triples.1[0], prep.values.beaver_triples.1[0]);
        assert_eq!(values.beaver_triples.2[0], prep.values.beaver_triples.2[0]);
        assert_eq!(values.random_bits.len(), 0);
        assert_eq!(values.random_values.len(), 0);
        assert_eq!(values.inverse_pairs.0.len(), 0);
        assert_eq!(values.my_input_masks.0.len(), 0);
        assert_eq!(values.counterparty_input_masks.len(), 0);
    }
}
