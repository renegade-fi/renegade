//! Groups logical gate gadgets used in ZK circuits

use std::marker::PhantomData;

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem},
};
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};

use crate::errors::ProverError;

/// Represents an OR gate in a single-prover constraint system
pub struct OrGate {}

impl OrGate {
    /// Computes the logical OR of the two arguments
    ///
    /// The arguments are assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn or<L, CS>(cs: &mut CS, a: L, b: L) -> LinearCombination
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let (a, b, a_times_b) = cs.multiply(a.into(), b.into());
        a + b - a_times_b
    }
}

/// Represents an OR gate in a multi-prover constraint system
pub struct MultiproverOrGate<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>> MultiproverOrGate<'a, N, S> {
    /// Return the logical OR of the two arguemnts
    ///
    /// The arguments are assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn or<L, CS>(cs: &mut CS, a: L, b: L) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        let (a, b, a_times_b) = cs
            .multiply(&a.into(), &b.into())
            .map_err(ProverError::Collaborative)?;
        Ok(&a + &b - a_times_b)
    }
}
