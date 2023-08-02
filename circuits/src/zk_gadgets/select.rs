//! Groups gadgets for conditional selection

use std::marker::PhantomData;

use circuit_types::{
    errors::ProverError,
    traits::{
        CircuitVarType, LinearCombinationLike, MpcLinearCombinationLike,
        MultiproverCircuitVariableType,
    },
};
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem},
};
use mpc_stark::{algebra::scalar::Scalar, MpcFabric};

/// Implements the control flow gate if selector { a } else { b }
pub struct CondSelectGadget;
impl CondSelectGadget {
    /// Computes the control flow statement if selector { a } else { b }
    pub fn select<L1, L2, V1, V2, CS>(a: V1, b: V1, selector: L1, cs: &mut CS) -> V2
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        V1: CircuitVarType<L2>,
        V2: CircuitVarType<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        let a_vars = a.to_vars();
        let b_vars = b.to_vars();
        assert_eq!(
            a_vars.len(),
            b_vars.len(),
            "a and b must be of equal length"
        );

        // Computes selector * a + (1 - selector) * b
        let mut res = Vec::with_capacity(a_vars.len());
        for (a_var, b_var) in a_vars.into_iter().zip(b_vars.into_iter()) {
            let (_, _, mul1_out) = cs.multiply(a_var.into(), selector.clone().into());
            let (_, _, mul2_out) = cs.multiply(b_var.into(), Variable::One() - selector.clone());

            res.push(mul1_out + mul2_out)
        }

        V2::from_vars(&mut res.into_iter())
    }
}

/// A multiprover version of the conditional select gadget
pub struct MultiproverCondSelectGadget<'a> {
    /// Phantom
    _phantom: &'a PhantomData<()>,
}

impl<'a> MultiproverCondSelectGadget<'a> {
    /// Computes the control flow statement if selector { a } else { b }
    pub fn select<L, V, CS>(
        a: V,
        b: V,
        selector: L,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<V, ProverError>
    where
        L: MpcLinearCombinationLike,
        V: MultiproverCircuitVariableType<MpcLinearCombination>,
        CS: MpcRandomizableConstraintSystem<'a>,
    {
        let a_vars = a.to_mpc_vars();
        let b_vars = b.to_mpc_vars();
        assert_eq!(
            a_vars.len(),
            b_vars.len(),
            "a and b must be of equal length"
        );

        let mut res_vals = Vec::with_capacity(a_vars.len());
        for (a_var, b_var) in a_vars.into_iter().zip(b_vars.into_iter()) {
            // Computes selector * a + (1 - selector) * b for each variable
            let (_, _, mul1_out) = cs
                .multiply(&a_var, &selector.clone().into())
                .map_err(ProverError::Collaborative)?;
            let (_, _, mul2_out) = cs
                .multiply(
                    &b_var,
                    &(MpcLinearCombination::from_scalar(Scalar::one(), fabric.clone())
                        - selector.clone().into()),
                )
                .map_err(ProverError::Collaborative)?;

            res_vals.push(mul1_out + mul2_out);
        }

        Ok(V::from_mpc_vars(&mut res_vals.into_iter()))
    }
}

/// Implements the control flow gate if selector { a } else { b }
/// where `a` and `b` are vectors of values
pub struct CondSelectVectorGadget {}
impl CondSelectVectorGadget {
    /// Implements the control flow statement if selector { a } else { b }
    pub fn select<L1, L2, V1, V2, CS>(a: &[V1], b: &[V1], selector: L1, cs: &mut CS) -> Vec<V2>
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        V1: CircuitVarType<L2>,
        V2: CircuitVarType<LinearCombination>,
        CS: RandomizableConstraintSystem,
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
pub struct MultiproverCondSelectVectorGadget<'a> {
    /// Phantom
    _phantom: &'a PhantomData<()>,
}

impl<'a> MultiproverCondSelectVectorGadget<'a> {
    /// Implements the control flow block if selector { a } else { b }
    /// where `a` and `b` are vectors
    pub fn select<L, V, CS>(
        a: &[V],
        b: &[V],
        selector: L,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<Vec<V>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a>,
        L: MpcLinearCombinationLike,
        V: MultiproverCircuitVariableType<MpcLinearCombination>,
    {
        assert_eq!(a.len(), b.len(), "a and b must be of equal length");

        let mut selected = Vec::with_capacity(a.len());
        for (a_val, b_val) in a.iter().cloned().zip(b.iter()) {
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
    use circuit_types::traits::CircuitBaseType;
    use itertools::Itertools;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, LinearCombination, Prover, Variable},
        PedersenGens,
    };
    use mpc_stark::algebra::scalar::Scalar;
    use rand::rngs::OsRng;

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
        let res = CondSelectVectorGadget::select::<_, _, Variable, LinearCombination, _>(
            &a_var,
            &b_var,
            selector,
            &mut prover,
        );

        assert_eq!(a, res.into_iter().map(|lc| prover.eval(&lc)).collect_vec());

        // Prove with selector = 0
        let selector = Scalar::zero().commit_public(&mut prover);
        let res = CondSelectVectorGadget::select::<_, _, Variable, LinearCombination, _>(
            &a_var,
            &b_var,
            selector,
            &mut prover,
        );

        assert_eq!(b, res.into_iter().map(|lc| prover.eval(&lc)).collect_vec());
    }
}
