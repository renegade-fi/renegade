//! Groups logic for adding Poseidon hash function constraints to a Bulletproof
//! constraint system

use std::marker::PhantomData;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
    r1cs_mpc::{
        MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem, MpcVariable,
        MultiproverError, R1CSError, SharedR1CSProof,
    },
    BulletproofGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use rand_core::OsRng;

use crate::{
    mpc::SharedFabric, mpc_gadgets::poseidon::PoseidonSpongeParameters, MultiProverCircuit,
    SingleProverCircuit,
};

use super::arithmetic::{ExpGadget, MultiproverExpGadget};

/**
 * Single prover gadget
 */

/// A hash gadget that applies a Poseidon hash function to the given constraint system
///
/// This version of the gadget is used for the single-prover case, i.e. no MPC
#[derive(Debug)]
pub struct PoseidonHashGadget {
    /// The parameterization of the hash function
    params: PoseidonSpongeParameters,
    /// The hash state
    state: Vec<LinearCombination>,
    /// The next index in the state to being absorbing inputs at
    next_index: usize,
    /// Whether the sponge is in squeezing mode. For simplicity, we disallow
    /// the case in which a caller wishes to squeeze values and the absorb more.
    in_squeeze_state: bool,
}

impl PoseidonHashGadget {
    /// Construct a new hash gadget with the given parameterization
    pub fn new(params: PoseidonSpongeParameters) -> Self {
        // Initialize the state as all zeros
        let state = (0..params.capacity + params.rate)
            .map(|_| LinearCombination::from(Scalar::zero()))
            .collect::<Vec<_>>();
        Self {
            params,
            state,
            next_index: 0,
            in_squeeze_state: false, // Start in absorb state
        }
    }

    /// Hashes the given input and constraints the result to equal the expected output
    pub fn hash<CS: RandomizableConstraintSystem>(
        &mut self,
        cs: &mut CS,
        hash_input: &[Variable],
        expected_output: &Variable,
    ) -> Result<(), R1CSError> {
        self.batch_absorb(cs, hash_input)?;
        self.constrained_squeeze(cs, *expected_output)
    }

    /// Absorb an input into the hasher state
    pub fn absorb<CS: RandomizableConstraintSystem>(
        &mut self,
        cs: &mut CS,
        a: Variable,
    ) -> Result<(), R1CSError> {
        assert!(
            !self.in_squeeze_state,
            "Cannot absorb from a sponge that has already been squeezed"
        );

        // Permute the digest state if we have filled up the rate sized buffer
        if self.next_index == self.params.rate {
            self.permute(cs)?;
            self.next_index = 0;
        }

        let access_index = self.next_index + self.params.capacity;
        self.state[access_index] = self.state[access_index].clone() + a;
        self.next_index += 1;
        Ok(())
    }

    /// Absorb a batch of inputs into the hasher state
    pub fn batch_absorb<CS: RandomizableConstraintSystem>(
        &mut self,
        cs: &mut CS,
        a: &[Variable],
    ) -> Result<(), R1CSError> {
        a.iter().try_for_each(|val| self.absorb(cs, *val))
    }

    /// Squeeze an output from the hasher, and constraint its value to equal the
    /// provided statement variable.
    pub fn constrained_squeeze<CS: RandomizableConstraintSystem>(
        &mut self,
        cs: &mut CS,
        expected: Variable,
    ) -> Result<(), R1CSError> {
        // Once we exit the absorb state, ensure that the digest state is permuted before squeezing
        if !self.in_squeeze_state || self.next_index == self.params.rate {
            self.permute(cs)?;
            self.next_index = 0;
            self.in_squeeze_state = true;
        }

        cs.constrain(self.state[self.params.capacity + self.next_index].clone() - expected);
        Ok(())
    }

    /// Squeeze a set of elements from the hasher, and constraint the elements to be equal
    /// to the provided statement variables
    pub fn batch_constrained_squeeze<CS: RandomizableConstraintSystem>(
        &mut self,
        cs: &mut CS,
        expected: &[Variable],
    ) -> Result<(), R1CSError> {
        expected
            .iter()
            .try_for_each(|val| self.constrained_squeeze(cs, *val))
    }

    /// Permute the digest by applying the Poseidon round function
    fn permute<CS: RandomizableConstraintSystem>(&mut self, cs: &mut CS) -> Result<(), R1CSError> {
        // Compute full_rounds / 2 rounds in which the sbox is applied to all elements
        for round in 0..self.params.full_rounds / 2 {
            self.add_round_constants(round);
            self.apply_sbox(cs, true /* full_round */)?;
            self.apply_mds()?;
        }

        // Compute partial_rounds rounds in which the sbox is applied to only the last element
        let partial_rounds_start = self.params.full_rounds / 2;
        let partial_rounds_end = partial_rounds_start + self.params.parital_rounds;
        for round in partial_rounds_start..partial_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(cs, false /* full_round */)?;
            self.apply_mds()?;
        }

        // Compute another full_rounds / 2 rounds in which we apply the sbox to all elements
        let final_full_rounds_start = partial_rounds_end;
        let final_full_rounds_end = self.params.parital_rounds + self.params.full_rounds;
        for round in final_full_rounds_start..final_full_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(cs, true /* full_round */)?;
            self.apply_mds()?;
        }

        Ok(())
    }

    /// Add the round constants for the given round to the state
    ///
    /// This is the first step in any round of the Poseidon permutation
    fn add_round_constants(&mut self, round_number: usize) {
        for (elem, round_constant) in self
            .state
            .iter_mut()
            .zip(self.params.get_round_constant(round_number))
        {
            *elem += LinearCombination::from(*round_constant)
        }
    }

    /// Apply the Poseidon s-box (i.e. x^\alpha \mod L) for given parameter \alpha
    ///
    /// This permutation is applied to every element of the state for a full round,
    /// and only to the last element of the state for a partial round
    ///
    /// This step is applied in the Poseidon permutation after the round constants
    /// are added to the state.
    fn apply_sbox<CS: RandomizableConstraintSystem>(
        &mut self,
        cs: &mut CS,
        full_round: bool,
    ) -> Result<(), R1CSError> {
        // If this is a full round, apply the sbox to each elem
        if full_round {
            self.state = self
                .state
                .iter()
                .map(|val| ExpGadget::gadget(cs, val.clone(), self.params.alpha))
                .collect_vec();
        } else {
            self.state[0] = ExpGadget::gadget(cs, self.state[0].clone(), self.params.alpha)
        }

        Ok(())
    }

    /// Multiply the state by the MDS (Maximum Distance Separable) matrix
    ///
    /// This step is applied after the sbox is applied to the state
    fn apply_mds(&mut self) -> Result<(), R1CSError> {
        let mut new_state: Vec<LinearCombination> =
            vec![LinearCombination::default(); self.state.len()];
        for (i, row) in self.params.mds_matrix.iter().enumerate() {
            for (a, b) in row.iter().zip(self.state.iter_mut()) {
                new_state[i] += *a * b.clone()
            }
        }

        self.state = new_state;

        Ok(())
    }
}

/// The witness input to a Poseidon pre-image argument of knowledge
///
/// This circuit encodes the statement that the prover knows a correct
/// Poseidon pre-image to the given hash output
#[derive(Clone, Debug)]
pub struct PoseidonGadgetWitness {
    /// Preimage
    pub preimage: Vec<Scalar>,
}

/// The statement variable (public variable) for the argument, consisting
/// of the expected hash output and the hash parameters
#[derive(Clone, Debug)]
pub struct PoseidonGadgetStatement {
    /// Expected output of applying the Poseidon hash to the preimage
    pub expected_out: Scalar,
    /// The hash parameters that parameterize the Poseidon permutation
    pub params: PoseidonSpongeParameters,
}

impl SingleProverCircuit for PoseidonHashGadget {
    type Witness = PoseidonGadgetWitness;
    type Statement = PoseidonGadgetStatement;

    const BP_GENS_CAPACITY: usize = 2048;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Vec<CompressedRistretto>, R1CSProof), R1CSError> {
        // Commit to the preimage
        let mut rng = OsRng {};
        let (preimage_commits, preimage_vars): (Vec<CompressedRistretto>, Vec<Variable>) = witness
            .preimage
            .into_iter()
            .map(|val| prover.commit(val, Scalar::random(&mut rng)))
            .unzip();

        // Commit publically to the expected result
        let (_, out_var) = prover.commit_public(statement.expected_out);

        // Apply the constraints to the proof system
        let mut hasher = PoseidonHashGadget::new(statement.params);
        hasher.hash(&mut prover, &preimage_vars, &out_var)?;

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens)?;

        Ok((preimage_commits, proof))
    }

    fn verify(
        witness_commitments: &[CompressedRistretto],
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), R1CSError> {
        // Commit to the preimage from the existing witness commitments
        let witness_vars = witness_commitments
            .iter()
            .map(|comm| verifier.commit(*comm))
            .collect_vec();

        // Commit to the public expected output
        let output_var = verifier.commit_public(statement.expected_out);

        // Build a hasher and apply the constraints
        let mut hasher = PoseidonHashGadget::new(statement.params);
        hasher.hash(&mut verifier, &witness_vars, &output_var)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier.verify(&proof, &bp_gens)
    }
}

/**
 * Multiprover Gadget
 */

/// A hash gadget that applies a Poseidon hash function to the given constraint system
///
/// This version of the gadget is used for the multi-prover case, i.e in an MPC execution
#[derive(Debug)]
pub struct MultiproverPoseidonHashGadget<
    'a,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    /// The parameterization of the hash function
    params: PoseidonSpongeParameters,
    /// The hash state
    state: Vec<MpcLinearCombination<N, S>>,
    /// The next index in the state to being absorbing inputs at
    next_index: usize,
    /// Whether the sponge is in squeezing mode. For simplicity, we disallow
    /// the case in which a caller wishes to squeeze values and the absorb more.
    in_squeeze_state: bool,
    /// A reference to the shared MPC fabric that the computation variables are allocated in
    fabric: SharedFabric<N, S>,
    /// Phantom for the lifetime parameter
    _phantom: PhantomData<&'a ()>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverPoseidonHashGadget<'a, N, S>
{
    /// Construct a new hash gadget with the given parameterization
    pub fn new(params: PoseidonSpongeParameters, fabric: SharedFabric<N, S>) -> Self {
        // Initialize the state as all zeros
        let state = (0..params.capacity + params.rate)
            .map(|_| MpcLinearCombination::from_scalar(Scalar::zero(), fabric.0.clone()))
            .collect::<Vec<_>>();
        Self {
            params,
            state,
            next_index: 0,
            in_squeeze_state: false, // Start in absorb state
            fabric,
            _phantom: PhantomData,
        }
    }

    /// Hashes the payload and then constrains the squeezed output to be the provided
    /// expected output.
    pub fn hash<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &mut self,
        cs: &mut CS,
        hash_input: &[MpcVariable<N, S>],
        expected_output: &MpcVariable<N, S>,
    ) -> Result<(), R1CSError> {
        self.batch_absorb(cs, hash_input)?;
        self.constrained_squeeze(cs, expected_output)
    }

    /// Absorb an input into the hasher state
    pub fn absorb<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &mut self,
        cs: &mut CS,
        a: &MpcVariable<N, S>,
    ) -> Result<(), R1CSError> {
        assert!(
            !self.in_squeeze_state,
            "Cannot absorb from a sponge that has already been squeezed"
        );

        // Permute the digest state if we have filled up the rate sized buffer
        if self.next_index == self.params.rate {
            self.permute(cs)?;
            self.next_index = 0;
        }

        let access_index = self.next_index + self.params.capacity;
        self.state[access_index] = &self.state[access_index] + a;
        self.next_index += 1;
        Ok(())
    }

    /// Absorb a batch of inputs into the hasher state
    pub fn batch_absorb<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &mut self,
        cs: &mut CS,
        a: &[MpcVariable<N, S>],
    ) -> Result<(), R1CSError> {
        a.iter().try_for_each(|val| self.absorb(cs, val))
    }

    /// Squeeze an output from the hasher, and constraint its value to equal the
    /// provided statement variable.
    pub fn constrained_squeeze<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &mut self,
        cs: &mut CS,
        expected: &MpcVariable<N, S>,
    ) -> Result<(), R1CSError> {
        // Once we exit the absorb state, ensure that the digest state is permuted before squeezing
        if !self.in_squeeze_state || self.next_index == self.params.rate {
            self.permute(cs)?;
            self.next_index = 0;
            self.in_squeeze_state = true;
        }

        cs.constrain(&self.state[self.params.capacity + self.next_index] - expected);
        Ok(())
    }

    /// Squeeze a set of elements from the hasher, and constraint the elements to be equal
    /// to the provided statement variables
    pub fn batch_constrained_squeeze<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &mut self,
        cs: &mut CS,
        expected: &[MpcVariable<N, S>],
    ) -> Result<(), R1CSError> {
        expected
            .iter()
            .try_for_each(|val| self.constrained_squeeze(cs, val))
    }

    /// Permute the digest by applying the Poseidon round function
    fn permute<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &mut self,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Compute full_rounds / 2 rounds in which the sbox is applied to all elements
        for round in 0..self.params.full_rounds / 2 {
            self.add_round_constants(round);
            self.apply_sbox(cs, true /* full_round */)?;
            self.apply_mds()?;
        }

        // Compute partial_rounds rounds in which the sbox is applied to only the last element
        let partial_rounds_start = self.params.full_rounds / 2;
        let partial_rounds_end = partial_rounds_start + self.params.parital_rounds;
        for round in partial_rounds_start..partial_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(cs, false /* full_round */)?;
            self.apply_mds()?;
        }

        // Compute another full_rounds / 2 rounds in which we apply the sbox to all elements
        let final_full_rounds_start = partial_rounds_end;
        let final_full_rounds_end = self.params.parital_rounds + self.params.full_rounds;
        for round in final_full_rounds_start..final_full_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(cs, true /* full_round */)?;
            self.apply_mds()?;
        }

        Ok(())
    }

    /// Add the round constants for the given round to the state
    ///
    /// This is the first step in any round of the Poseidon permutation
    fn add_round_constants(&mut self, round_number: usize) {
        for (elem, round_constant) in self
            .state
            .iter_mut()
            .zip(self.params.get_round_constant(round_number))
        {
            *elem += MpcLinearCombination::from_scalar(*round_constant, self.fabric.clone().0)
        }
    }

    /// Apply the Poseidon s-box (i.e. x^\alpha \mod L) for given parameter \alpha
    ///
    /// This permutation is applied to every element of the state for a full round,
    /// and only to the last element of the state for a partial round
    ///
    /// This step is applied in the Poseidon permutation after the round constants
    /// are added to the state.
    fn apply_sbox<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &mut self,
        cs: &mut CS,
        full_round: bool,
    ) -> Result<(), R1CSError> {
        // If this is a full round, apply the sbox to each elem
        if full_round {
            self.state = self
                .state
                .iter()
                .map(|val| {
                    MultiproverExpGadget::gadget(
                        cs,
                        val.clone(),
                        self.params.alpha,
                        self.fabric.clone(),
                    )
                })
                .collect_vec();
        } else {
            self.state[0] = MultiproverExpGadget::gadget(
                cs,
                self.state[0].clone(),
                self.params.alpha,
                self.fabric.clone(),
            )
        }

        Ok(())
    }

    /// Multiply the state by the MDS (Maximum Distance Separable) matrix
    ///
    /// This step is applied after the sbox is applied to the state
    fn apply_mds(&mut self) -> Result<(), R1CSError> {
        let mut new_state = vec![MpcLinearCombination::<N, S>::default(); self.state.len()];
        for (i, row) in self.params.mds_matrix.iter().enumerate() {
            for (a, b) in row.iter().zip(self.state.iter()) {
                new_state[i] += *a * b
            }
        }

        self.state = new_state;
        Ok(())
    }
}

/// The witness type for the multiprover Poseidon gadget
#[derive(Clone, Debug)]
pub struct MultiproverPoseidonWitness<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The preimage (input) to the hash function
    pub preimage: Vec<AuthenticatedScalar<N, S>>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>> MultiProverCircuit<'a, N, S>
    for MultiproverPoseidonHashGadget<'a, N, S>
{
    /// Witenss is as the witness in the single prover case, except for the facts that hte underlying scalar
    /// field is the authenticated and shared Ristretto scalar field.
    ///
    /// The Statement, on the other hand, is entirely public; and therefore the same type as the single prover.
    type Witness = MultiproverPoseidonWitness<N, S>;
    type Statement = PoseidonGadgetStatement;

    const BP_GENS_CAPACITY: usize = 2048;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<
        (
            Vec<AuthenticatedCompressedRistretto<N, S>>,
            SharedR1CSProof<N, S>,
        ),
        MultiproverError,
    > {
        // Commit to the hash input and expected output
        let mut rng = OsRng {};
        let blinders = (0..witness.preimage.len())
            .map(|_| {
                fabric
                    .borrow_fabric()
                    .allocate_preshared_scalar(Scalar::random(&mut rng))
            })
            .collect_vec();

        let (witness_commits, witness_vars) = prover
            .batch_commit_preshared(&witness.preimage, &blinders)
            .map_err(MultiproverError::Mpc)?;

        // TODO: If bug, public commit might be broken here
        let (_, out_var) = prover.commit_public(statement.expected_out, Scalar::one());

        // Create a hasher and apply the constraints
        let mut hasher = MultiproverPoseidonHashGadget::new(statement.params, fabric);
        hasher
            .hash(&mut prover, &witness_vars, &out_var)
            .map_err(MultiproverError::ProverError)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens)?;

        Ok((witness_commits, proof))
    }

    fn verify(
        witness_commitments: &[CompressedRistretto],
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), R1CSError> {
        // Forward to the single prover gadget
        PoseidonHashGadget::verify(witness_commitments, statement, proof, verifier)
    }
}

#[cfg(test)]
mod single_prover_test {
    use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use rand_core::{OsRng, RngCore};

    use crate::{
        mpc_gadgets::poseidon::PoseidonSpongeParameters,
        test_helpers::{bulletproof_prove_and_verify, convert_params, felt_to_scalar, TestField},
    };

    use super::{PoseidonGadgetStatement, PoseidonGadgetWitness, PoseidonHashGadget};

    #[test]
    fn test_single_prover_hash() {
        // Sample random values to hash
        let mut rng = OsRng {};
        let n = 15;
        let random_elems = (0..n).map(|_| rng.next_u64()).collect_vec();

        // Compute the hash via Arkworks for expected result
        let arkworks_params = convert_params(&PoseidonSpongeParameters::default());
        let mut arkworks_hasher = PoseidonSponge::new(&arkworks_params);

        for elem in random_elems.iter() {
            arkworks_hasher.absorb(&TestField::from(*elem as i128));
        }

        let expected_result: TestField =
            arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0];

        let expected_scalar = felt_to_scalar(&expected_result);

        bulletproof_prove_and_verify::<PoseidonHashGadget>(
            PoseidonGadgetWitness {
                preimage: random_elems.into_iter().map(Scalar::from).collect_vec(),
            },
            PoseidonGadgetStatement {
                expected_out: expected_scalar,
                params: PoseidonSpongeParameters::default(),
            },
        )
        .unwrap();
    }

    /// Tests the case in which the pre-image is not correct
    #[test]
    fn test_single_prover_hash_failure() {
        let mut rng = OsRng {};
        let n = 15;
        let random_elems = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let random_expected = Scalar::random(&mut rng);

        let res = bulletproof_prove_and_verify::<PoseidonHashGadget>(
            PoseidonGadgetWitness {
                preimage: random_elems,
            },
            PoseidonGadgetStatement {
                expected_out: random_expected,
                params: PoseidonSpongeParameters::default(),
            },
        );

        assert!(res.is_err());
    }
}
