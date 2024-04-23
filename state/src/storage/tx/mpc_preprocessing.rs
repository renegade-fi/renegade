//! Storage methods for the MPC preprocessing phase
//!
//! Clusters generate shared correlated randomness with each other cluster.
//! These values allow the parties to accelerate computation in the online phase

use common::types::{
    gossip::ClusterId,
    mpc_preprocessing::{PairwiseOfflineSetup, PreprocessingSlice},
};
use libmdbx::{TransactionKind, RW};
use util::res_some;

use crate::{storage::error::StorageError, MPC_PREPROCESSING_TABLE};

use super::StateTxn;

/// Error message emitted when the preprocessing values for a given cluster
/// cannot support a requested slice
const ERR_INSUFFICIENT_CAPACITY: &str = "Requested preprocessing values exceed capacity";

/// Generate the key under which we store preprocessing values between the local
/// cluster and a given remote cluster
fn preprocessing_key(remote_cluster: &ClusterId) -> String {
    format!("mpc-preprocessing/{}", remote_cluster)
}

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Get the preprocessing values for the given cluster
    pub fn get_mpc_prep(
        &self,
        cluster: &ClusterId,
    ) -> Result<Option<PairwiseOfflineSetup>, StorageError> {
        self.inner().read(MPC_PREPROCESSING_TABLE, &preprocessing_key(cluster))
    }

    /// Get the size of the preprocessing value for a cluster
    pub fn get_mpc_prep_size(
        &self,
        cluster: &ClusterId,
    ) -> Result<Option<PreprocessingSlice>, StorageError> {
        let prep = res_some!(self.get_mpc_prep(cluster)?).values;
        let slice = PreprocessingSlice {
            num_bits: prep.random_bits.len(),
            num_values: prep.random_values.len(),
            num_input_masks: usize::min(
                prep.my_input_masks.0.len(),
                prep.counterparty_input_masks.len(),
            ),
            num_inverse_pairs: prep.inverse_pairs.0.len(),
            num_triples: prep.beaver_triples.0.len(),
        };

        Ok(Some(slice))
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Set the preprocessing values for the given cluster
    pub fn set_mpc_prep(
        &self,
        cluster: &ClusterId,
        setup: &PairwiseOfflineSetup,
    ) -> Result<(), StorageError> {
        self.inner().write(MPC_PREPROCESSING_TABLE, &preprocessing_key(cluster), setup)
    }

    /// Append values to the preprocessing
    pub fn append_mpc_prep_values(
        &self,
        cluster: &ClusterId,
        new: &PairwiseOfflineSetup,
    ) -> Result<(), StorageError> {
        let mut prep =
            self.get_mpc_prep(cluster)?.unwrap_or_else(|| PairwiseOfflineSetup::new(new.mac_key));
        prep.append(&new.values);

        self.set_mpc_prep(cluster, &prep)?;
        Ok(())
    }

    /// Consume values from the preprocessing store
    pub fn consume_mpc_prep_values(
        &self,
        cluster: &ClusterId,
        slice: &PreprocessingSlice,
    ) -> Result<PairwiseOfflineSetup, StorageError> {
        // Read the preprocessing store
        let mut prep = self.get_mpc_prep(cluster)?.unwrap_or_default();
        if !prep.has_capacity_for_slice(slice) {
            return Err(StorageError::Other(ERR_INSUFFICIENT_CAPACITY.to_string()));
        }

        // Consume the values and write back
        let values = prep.pop(slice);
        self.set_mpc_prep(cluster, &prep)?;
        Ok(values)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use common::types::{
        gossip::ClusterId,
        mpc_preprocessing::{PairwiseOfflineSetup, PreprocessingSlice},
    };
    use constants::{Scalar, ScalarShare};
    use rand::thread_rng;

    use crate::test_helpers::mock_db;

    #[test]
    fn test_get_prep_size() {
        let mut rng = thread_rng();
        let db = mock_db();
        let cluster = ClusterId::from_str("test").unwrap();
        let key = Scalar::random(&mut rng);

        let mut prep = PairwiseOfflineSetup::new(key);
        let share = ScalarShare::new(Scalar::random(&mut rng), Scalar::random(&mut rng));
        prep.values.random_bits.push(share);
        prep.values.random_values.push(share);

        // Set the prep
        let tx = db.new_write_tx().unwrap();
        tx.set_mpc_prep(&cluster, &prep).unwrap();
        tx.commit().unwrap();

        // Read back the size
        let tx = db.new_read_tx().unwrap();
        let size = tx.get_mpc_prep_size(&cluster).unwrap().unwrap();
        assert_eq!(size.num_bits, 1);
        assert_eq!(size.num_values, 1);
        assert_eq!(size.num_input_masks, 0);
        assert_eq!(size.num_inverse_pairs, 0);
        assert_eq!(size.num_triples, 0);
    }

    #[test]
    fn test_get_set_prep() {
        let mut rng = thread_rng();
        let db = mock_db();
        let cluster = ClusterId::from_str("test").unwrap();

        let key = Scalar::random(&mut rng);
        let prep = PairwiseOfflineSetup::new(key);
        let tx = db.new_write_tx().unwrap();
        tx.set_mpc_prep(&cluster, &prep).unwrap();
        tx.commit().unwrap();

        // Append to the prep
        let mut new_vals = PairwiseOfflineSetup::new(key);
        let share = ScalarShare::new(Scalar::random(&mut rng), Scalar::random(&mut rng));
        new_vals.values.random_values.push(share);
        let tx = db.new_write_tx().unwrap();
        tx.append_mpc_prep_values(&cluster, &new_vals).unwrap();
        tx.commit().unwrap();

        // Fetch the prep
        let tx = db.new_read_tx().unwrap();
        let fetched = tx.get_mpc_prep(&cluster).unwrap();
        assert_eq!(fetched, Some(new_vals));
    }

    #[test]
    #[allow(non_snake_case)]
    #[should_panic(expected = "exceed capacity")]
    fn test_consume_prep__insufficient_capacity() {
        let mut rng = thread_rng();
        let db = mock_db();
        let cluster = ClusterId::from_str("test").unwrap();

        let key = Scalar::random(&mut rng);
        let prep = PairwiseOfflineSetup::new(key);
        let tx = db.new_write_tx().unwrap();
        tx.set_mpc_prep(&cluster, &prep).unwrap();
        tx.commit().unwrap();

        // Consume the prep
        let slice = PreprocessingSlice {
            num_bits: 1,
            num_values: 1,
            num_input_masks: 1,
            num_inverse_pairs: 1,
            num_triples: 1,
        };
        let tx = db.new_write_tx().unwrap();
        tx.consume_mpc_prep_values(&cluster, &slice).unwrap();
    }

    #[test]
    fn test_consume_prep_values() {
        let mut rng = thread_rng();
        let db = mock_db();
        let cluster = ClusterId::from_str("test").unwrap();

        // Setup a mock prep
        let mut prep = PairwiseOfflineSetup::new(Scalar::random(&mut rng));
        let share = ScalarShare::new(Scalar::random(&mut rng), Scalar::random(&mut rng));
        prep.values.random_bits.push(share);
        prep.values.random_values.push(share);
        prep.values.beaver_triples.0.push(share);
        prep.values.beaver_triples.1.push(share);
        prep.values.beaver_triples.2.push(share);

        let tx = db.new_write_tx().unwrap();
        tx.set_mpc_prep(&cluster, &prep).unwrap();
        tx.commit().unwrap();

        // Consume the prep
        let slice = PreprocessingSlice {
            num_bits: 1,
            num_values: 0, // leave the random value
            num_input_masks: 0,
            num_inverse_pairs: 0,
            num_triples: 1,
        };

        let tx = db.new_write_tx().unwrap();
        let vals = tx.consume_mpc_prep_values(&cluster, &slice).unwrap().values;
        tx.commit().unwrap();

        // Check the values
        assert_eq!(vals.random_bits, vec![share]);
        assert_eq!(vals.random_values.len(), 0);
        assert_eq!(vals.beaver_triples.0, vec![share]);
        assert_eq!(vals.beaver_triples.1, vec![share]);
        assert_eq!(vals.beaver_triples.2, vec![share]);

        // Check the size of the remaining prep
        let tx = db.new_read_tx().unwrap();
        let size = tx.get_mpc_prep_size(&cluster).unwrap().unwrap();
        assert_eq!(size.num_bits, 0);
        assert_eq!(size.num_values, 1); // one left
        assert_eq!(size.num_input_masks, 0);
        assert_eq!(size.num_inverse_pairs, 0);
        assert_eq!(size.num_triples, 0);
    }
}
