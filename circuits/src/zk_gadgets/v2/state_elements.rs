//! Gadgets for operating on abstract state elements

use circuit_types::{
    PlonkCircuit,
    state_wrapper::StateWrapperVar,
    traits::{CircuitBaseType, CircuitVarType, SecretShareVarType},
};
use mpc_relation::traits::Circuit;
use mpc_relation::{Variable, errors::CircuitError};

use crate::zk_gadgets::{csprng::CSPRNGGadget, poseidon::PoseidonHashGadget};

/// A gadget for operating on abstract state elements
pub struct StateElementGadget;
impl StateElementGadget {
    // --- Commitments --- //

    /// Compute the commitment to an abstract state element
    ///
    /// A commitment is defined as:
    ///     H(recovery_stream_state || share_stream_state || private_shares ||
    /// public_shares)
    pub fn compute_commitment<V: SecretShareVarType>(
        private_share: &V,
        public_share: &V,
        element: &StateWrapperVar<<V::Base as CircuitVarType>::BaseType>,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        // Serialize the commitment input
        let private_commitment = Self::compute_private_commitment(private_share, element, cs)?;
        Self::compute_commitment_from_private(private_commitment, public_share, cs)
    }

    /// Compute the commitment to the private shares of a state element
    fn compute_private_commitment<V: SecretShareVarType>(
        private_share: &V,
        element: &StateWrapperVar<<V::Base as CircuitVarType>::BaseType>,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&element.recovery_stream.to_vars(), cs)?;
        hasher.batch_absorb(&element.share_stream.to_vars(), cs)?;
        hasher.batch_absorb(&private_share.to_vars(), cs)?;

        hasher.squeeze(cs)
    }

    /// Compute the commitment to a full state element given a commitment to the
    /// private shares
    ///
    /// As opposed to directly absorbing the public shares into the hasher, we
    /// iterative 2-1 hash the commitment and the next public share.
    ///
    /// The reason for doing this is that it creates a "resumable" partial
    /// commitment. We can partially commit to a state elements up through
    /// the public shares that won't change. Then, we can resume the
    /// commitment in the contracts by hashing the rest of the public shares
    /// into the commitment. This allows us to pre-commit to a state element
    /// e.g. before a match and then commit only to the updated shares after
    /// their values are determined.
    fn compute_commitment_from_private<V: SecretShareVarType>(
        private_commitment: Variable,
        public_share: &V,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let public_share_vars = public_share.to_vars();

        let mut hasher = PoseidonHashGadget::new(cs.zero());
        let mut comm = private_commitment;
        for share in public_share_vars.iter() {
            comm = hasher.hash(&[comm, *share], cs)?;
            hasher.reset_state(cs);
        }

        Ok(comm)
    }

    // --- Nullifiers --- //

    /// Compute the nullifier of a state element
    ///
    /// A state element's nullifier is the hash of the recovery identifier for
    /// the current version of the element with the seed of the recovery stream.
    /// This recovery identifier was emitted on the last update of the element.
    /// So if the current index in the recovery stream is `i`, the recovery
    /// identifier in question is the value at index `i - 1`.
    pub fn compute_nullifier<V: CircuitBaseType>(
        element: &StateWrapperVar<V>,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let last_idx = cs.sub(element.recovery_stream.index, cs.one())?;
        let recovery_id = CSPRNGGadget::get_ith(&element.recovery_stream, last_idx, cs)?;

        // Compute the nullifier as H(recovery_id || recovery_stream_seed)
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&[recovery_id, element.recovery_stream.seed], cs)?;
        hasher.squeeze(cs)
    }
}
