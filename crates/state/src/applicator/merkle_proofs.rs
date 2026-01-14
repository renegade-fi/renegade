//! Applicator methods for Merkle authentication paths (proofs)

use tracing::instrument;
use types_account::MerkleAuthenticationPath;

use crate::{
    applicator::return_type::ApplicatorReturnType, storage::tx::merkle_proofs::MerkleProofType,
};

use super::{Result, StateApplicator};

impl StateApplicator {
    /// Add a Merkle authentication path for a given proof type
    #[instrument(skip_all, err, fields(proof_type = ?proof_type))]
    pub fn add_merkle_proof(
        &self,
        proof_type: MerkleProofType,
        proof: MerkleAuthenticationPath,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        tx.set_merkle_proof(&proof_type, &proof)?;
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }
}
