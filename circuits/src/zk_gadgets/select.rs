//! Groups gadgets for conditional selection

use std::marker::PhantomData;

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem},
};
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};

use crate::{
    errors::ProverError,
    mpc::SharedFabric,
    traits::{LinearCombinationLike, MpcLinearCombinationLike},
};

/// Implements the control flow gate if selector { a } else { b }
pub struct CondSelectGadget {}

impl CondSelectGadget {
    /// Computes the control flow statement if selector { a } else { b }
    pub fn select<L1, L2, CS>(a: L1, b: L1, selector: L2, cs: &mut CS) -> LinearCombination
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Computes selector * a + (1 - selector) * b
        let (_, _, mul1_out) = cs.multiply(a.into(), selector.clone().into());
        let (_, _, mul2_out) = cs.multiply(b.into(), Variable::One() - selector);

        mul1_out + mul2_out
    }
}

/// A multiprover version of the conditional select gadget
pub struct MultiproverCondSelectGadget<
    'a,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverCondSelectGadget<'a, N, S>
{
    /// Computes the control flow statement if selector { a } else { b }
    pub fn select<L, CS>(
        a: L,
        b: L,
        selector: L,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: MpcLinearCombinationLike<N, S>,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Computes selector * a + (1 - selector) * b
        let (_, _, mul1_out) = cs
            .multiply(&a.into(), &selector.clone().into())
            .map_err(ProverError::Collaborative)?;
        let (_, _, mul2_out) = cs
            .multiply(
                &b.into(),
                &(MpcLinearCombination::from_scalar(Scalar::one(), fabric.0) - selector.into()),
            )
            .map_err(ProverError::Collaborative)?;

        Ok(mul1_out + mul2_out)
    }
}

/// Implements the control flow gate if selector { a } else { b }
/// where `a` and `b` are vectors of values
pub struct CondSelectVectorGadget {}
impl CondSelectVectorGadget {
    /// Implements the control flow statement if selector { a } else { b }
    pub fn select<L1, L2, CS>(
        a: &[L1],
        b: &[L1],
        selector: L2,
        cs: &mut CS,
    ) -> Vec<LinearCombination>
    where
        CS: RandomizableConstraintSystem,
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
    {
        assert_eq!(a.len(), b.len(), "a and b must be of equal length");
        let mut selected = Vec::with_capacity(a.len());
        for (a_val, b_val) in a.iter().zip(b.iter()) {
            selected.push(CondSelectGadget::select(
                a_val.clone(),
                b_val.clone(),
                selector.clone(),
                cs,
            ));
        }

        selected
    }
}

/// A multiprover variant of the CondSelectVectorGadget
pub struct MultiproverCondSelectVectorGadget<
    'a,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverCondSelectVectorGadget<'a, N, S>
{
    /// Implements the control flow block if selector { a } else { b }
    /// where `a` and `b` are vectors
    pub fn select<L, CS>(
        cs: &mut CS,
        a: &[L],
        b: &[L],
        selector: L,
        fabric: SharedFabric<N, S>,
    ) -> Result<Vec<MpcLinearCombination<N, S>>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: MpcLinearCombinationLike<N, S>,
    {
        assert_eq!(a.len(), b.len(), "a and b must be of equal length");
        let mut selected = Vec::with_capacity(a.len());
        for (a_val, b_val) in a.iter().zip(b.iter()) {
            selected.push(MultiproverCondSelectGadget::select(
                a_val.clone(),
                b_val.clone(),
                selector.clone(),
                fabric.clone(),
                cs,
            )?)
        }

        Ok(selected)
    }
}

#[cfg(test)]
mod cond_select_test {
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, Prover},
        PedersenGens,
    };
    use rand_core::OsRng;

    use crate::traits::CircuitBaseType;

    use super::{CondSelectGadget, CondSelectVectorGadget};

    /// Test the cond select gadget
    #[test]
    fn test_cond_select() {
        let mut rng = OsRng {};
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let a_var = a.commit_public(&mut prover);
        let b_var = b.commit_public(&mut prover);

        // Selector = 1
        let selector = Scalar::one().commit_public(&mut prover);
        let res = CondSelectGadget::select(a_var, b_var, selector, &mut prover);

        assert_eq!(a, prover.eval(&res));

        // Selector = 0
        let selector = Scalar::zero().commit_public(&mut prover);
        let res = CondSelectGadget::select(a_var, b_var, selector, &mut prover);

        assert_eq!(b, prover.eval(&res));
    }

    /// Test the cond select vector gadget
    #[test]
    fn test_cond_select_vector() {
        let n = 10;
        let mut rng = OsRng {};
        let a = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();

        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let a_var = a.iter().map(|a| a.commit_public(&mut prover)).collect_vec();
        let b_var = b.iter().map(|b| b.commit_public(&mut prover)).collect_vec();

        // Prove with selector = 1
        let selector = Scalar::one().commit_public(&mut prover);
        let res = CondSelectVectorGadget::select(&a_var, &b_var, selector, &mut prover);

        assert_eq!(a, res.into_iter().map(|lc| prover.eval(&lc)).collect_vec());

        // Prove with selector = 0
        let selector = Scalar::zero().commit_public(&mut prover);
        let res = CondSelectVectorGadget::select(&a_var, &b_var, selector, &mut prover);

        assert_eq!(b, res.into_iter().map(|lc| prover.eval(&lc)).collect_vec());
    }
}
