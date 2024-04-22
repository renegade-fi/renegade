//! Storage methods for the MPC preprocessing phase
//!
//! Clusters generate shared correlated randomness with each other cluster.
//! These values allow the parties to accelerate computation in the online phase

use common::types::{gossip::ClusterId, offline_phase::PairwiseOfflineSetup};
use libmdbx::{TransactionKind, RW};

use crate::{storage::error::StorageError, MPC_PREPROCESSING_TABLE};

use super::StateTxn;

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
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use common::types::{gossip::ClusterId, offline_phase::PairwiseOfflineSetup};
    use constants::{Scalar, ScalarShare};
    use rand::thread_rng;

    use crate::test_helpers::mock_db;

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
}
