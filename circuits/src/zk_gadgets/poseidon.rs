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
        MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem, MpcVariable, R1CSError,
        SharedR1CSProof,
    },
    BulletproofGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use rand_core::OsRng;

use crate::{
    errors::{MpcError, ProverError, VerifierError},
    mpc::SharedFabric,
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    CommitPublic, CommitWitness, MultiProverCircuit, SingleProverCircuit,
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

    /// Reset the internal state of the hasher
    pub fn reset_state(&mut self) {
        self.state = (0..self.params.capacity + self.params.rate)
            .map(|_| LinearCombination::from(Scalar::zero()))
            .collect::<Vec<_>>();
        self.in_squeeze_state = false;
    }

    /// Hashes the given input and constraints the result to equal the expected output
    pub fn hash<L, CS>(
        &mut self,
        hash_input: &[L],
        expected_output: L,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        self.batch_absorb(hash_input, cs)?;
        self.constrained_squeeze(expected_output.into(), cs)
    }

    /// Absorb an input into the hasher state
    pub fn absorb<L, CS>(&mut self, a: L, cs: &mut CS) -> Result<(), R1CSError>
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
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
    pub fn batch_absorb<L, CS>(&mut self, a: &[L], cs: &mut CS) -> Result<(), R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        a.iter()
            .try_for_each(|val| self.absorb(Into::<LinearCombination>::into(val.clone()), cs))
    }

    /// Squeeze an element from the sponge and return its representation in the constraint
    /// system
    pub fn squeeze<CS: RandomizableConstraintSystem>(
        &mut self,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Once we exit the absorb state, ensure that the digest state is permuted before squeezing
        if !self.in_squeeze_state || self.next_index == self.params.rate {
            self.permute(cs)?;
            self.next_index = 0;
            self.in_squeeze_state = true;
        }

        Ok(self.state[self.params.capacity + self.next_index].clone())
    }

    /// Squeeze a batch of elements from the sponge and return their representation in the
    /// constraint system
    pub fn batch_squeeze<CS: RandomizableConstraintSystem>(
        &mut self,
        num_elements: usize,
        cs: &mut CS,
    ) -> Result<Vec<LinearCombination>, R1CSError> {
        let mut res = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            res.push(self.squeeze(cs)?)
        }

        Ok(res)
    }

    /// Squeeze an output from the hasher, and constraint its value to equal the
    /// provided statement variable.
    pub fn constrained_squeeze<L, CS>(&mut self, expected: L, cs: &mut CS) -> Result<(), R1CSError>
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        let squeezed_elem = self.squeeze(cs)?;
        cs.constrain(squeezed_elem - expected);
        Ok(())
    }

    /// Squeeze a set of elements from the hasher, and constraint the elements to be equal
    /// to the provided statement variables
    pub fn batch_constrained_squeeze<L, CS>(
        &mut self,
        expected: &[L],
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        expected
            .iter()
            .try_for_each(|val| self.constrained_squeeze(val.clone(), cs))
    }

    /// Permute the digest by applying the Poseidon round function
    fn permute<CS: RandomizableConstraintSystem>(&mut self, cs: &mut CS) -> Result<(), R1CSError> {
        // Compute full_rounds / 2 rounds in which the sbox is applied to all elements
        for round in 0..self.params.full_rounds / 2 {
            self.add_round_constants(round);
            self.apply_sbox(true /* full_round */, cs)?;
            self.apply_mds()?;
        }

        // Compute partial_rounds rounds in which the sbox is applied to only the last element
        let partial_rounds_start = self.params.full_rounds / 2;
        let partial_rounds_end = partial_rounds_start + self.params.parital_rounds;
        for round in partial_rounds_start..partial_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(false /* full_round */, cs)?;
            self.apply_mds()?;
        }

        // Compute another full_rounds / 2 rounds in which we apply the sbox to all elements
        let final_full_rounds_start = partial_rounds_end;
        let final_full_rounds_end = self.params.parital_rounds + self.params.full_rounds;
        for round in final_full_rounds_start..final_full_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(true /* full_round */, cs)?;
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
        full_round: bool,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // If this is a full round, apply the sbox to each elem
        if full_round {
            self.state = self
                .state
                .iter()
                .map(|val| ExpGadget::exp(val.clone(), self.params.alpha, cs))
                .collect_vec();
        } else {
            self.state[0] = ExpGadget::exp(self.state[0].clone(), self.params.alpha, cs)
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

impl CommitWitness for PoseidonGadgetWitness {
    type CommitType = Vec<CompressedRistretto>;
    type VarType = Vec<Variable>;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (witness_comm, witness_var): (Vec<CompressedRistretto>, Vec<Variable>) = self
            .preimage
            .iter()
            .map(|&val| prover.commit(val, Scalar::random(rng)))
            .unzip();

        Ok((witness_var, witness_comm))
    }
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

/// A [`PoseidonHashGadget`] statement that has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct PoseidonGadgetStatementVar {
    /// Expected output of applying the Poseidon hash to the preimage
    pub expected_out: Variable,
    /// The hash parameters that parameterize the Poseidon permutation
    /// These don't actually get allocated as variables
    pub params: PoseidonSpongeParameters,
}

impl CommitPublic for PoseidonGadgetStatement {
    type VarType = PoseidonGadgetStatementVar;
    type ErrorType = ();

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        Ok(PoseidonGadgetStatementVar {
            expected_out: cs.commit_public(self.expected_out),
            params: self.params.clone(),
        })
    }
}

impl SingleProverCircuit for PoseidonHashGadget {
    type Witness = PoseidonGadgetWitness;
    type WitnessCommitment = Vec<CompressedRistretto>;
    type Statement = PoseidonGadgetStatement;

    const BP_GENS_CAPACITY: usize = 2048;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CommitWitness>::VarType,
        statement_var: <Self::Statement as CommitPublic>::VarType,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Apply the constraints over the allocated witness & statement

        // Build a hasher and apply the constraints
        let mut hasher = PoseidonHashGadget::new(statement_var.params);
        hasher.hash(&witness_var, statement_var.expected_out, cs)
    }

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Vec<CompressedRistretto>, R1CSProof), ProverError> {
        // Commit to the preimage
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();

        // Commit publicly to the expected result
        let statement_var = statement.commit_public(&mut prover).unwrap();

        Self::apply_constraints(witness_var, statement_var, &mut prover)
            .map_err(ProverError::R1CS)?;

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitments: Vec<CompressedRistretto>,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the preimage from the existing witness commitments
        let witness_var = witness_commitments
            .iter()
            .map(|comm| verifier.commit(*comm))
            .collect_vec();

        // Commit to the public expected output
        let statement_var = statement.commit_public(&mut verifier).unwrap();

        Self::apply_constraints(witness_var, statement_var, &mut verifier)
            .map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
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
    pub fn hash<L, CS>(
        &mut self,
        hash_input: &[L],
        expected_output: &L,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        self.batch_absorb(hash_input, cs)?;
        self.constrained_squeeze(expected_output.clone(), cs)
    }

    /// Absorb an input into the hasher state
    pub fn absorb<'b, L, CS>(&mut self, a: L, cs: &mut CS) -> Result<(), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
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
        self.state[access_index] = &self.state[access_index] + a.into();
        self.next_index += 1;
        Ok(())
    }

    /// Absorb a batch of inputs into the hasher state
    pub fn batch_absorb<L, CS>(&mut self, a: &[L], cs: &mut CS) -> Result<(), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        a.iter().try_for_each(|val| self.absorb(val.clone(), cs))
    }

    /// Squeeze an output from the hasher and return to the caller
    pub fn squeeze<CS>(&mut self, cs: &mut CS) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Once we exit the absorb state, ensure that the digest state is permuted before squeezing
        if !self.in_squeeze_state || self.next_index == self.params.rate {
            self.permute(cs)?;
            self.next_index = 0;
            self.in_squeeze_state = true;
        }

        Ok(self.state[self.params.capacity + self.next_index].clone())
    }

    /// Squeeze an output from the hasher, and constraint its value to equal the
    /// provided statement variable.
    pub fn constrained_squeeze<L, CS>(
        &mut self,
        expected: L,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        let squeezed = self.squeeze(cs)?;
        cs.constrain(squeezed - expected);
        Ok(())
    }

    /// Squeeze a batch of elements from the hasher
    pub fn batch_squeeze<CS>(
        &mut self,
        num_elems: usize,
        cs: &mut CS,
    ) -> Result<Vec<MpcLinearCombination<N, S>>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        (0..num_elems)
            .map(|_| self.squeeze(cs))
            .collect::<Result<Vec<_>, ProverError>>()
    }

    /// Squeeze a set of elements from the hasher, and constraint the elements to be equal
    /// to the provided statement variables
    pub fn batch_constrained_squeeze<L, CS>(
        &mut self,
        expected: &[MpcVariable<N, S>],
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        expected
            .iter()
            .try_for_each(|val| self.constrained_squeeze(val.clone(), cs))
    }

    /// Permute the digest by applying the Poseidon round function
    fn permute<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &mut self,
        cs: &mut CS,
    ) -> Result<(), ProverError> {
        // Compute full_rounds / 2 rounds in which the sbox is applied to all elements
        for round in 0..self.params.full_rounds / 2 {
            self.add_round_constants(round);
            self.apply_sbox(true /* full_round */, cs)?;
            self.apply_mds();
        }

        // Compute partial_rounds rounds in which the sbox is applied to only the last element
        let partial_rounds_start = self.params.full_rounds / 2;
        let partial_rounds_end = partial_rounds_start + self.params.parital_rounds;
        for round in partial_rounds_start..partial_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(false /* full_round */, cs)?;
            self.apply_mds();
        }

        // Compute another full_rounds / 2 rounds in which we apply the sbox to all elements
        let final_full_rounds_start = partial_rounds_end;
        let final_full_rounds_end = self.params.parital_rounds + self.params.full_rounds;
        for round in final_full_rounds_start..final_full_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(true /* full_round */, cs)?;
            self.apply_mds();
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
        full_round: bool,
        cs: &mut CS,
    ) -> Result<(), ProverError> {
        // If this is a full round, apply the sbox to each elem
        if full_round {
            self.state = self
                .state
                .iter()
                .map(|val| {
                    MultiproverExpGadget::exp(
                        val.clone(),
                        self.params.alpha,
                        self.fabric.clone(),
                        cs,
                    )
                })
                .collect::<Result<Vec<_>, ProverError>>()?;
        } else {
            self.state[0] = MultiproverExpGadget::exp(
                self.state[0].clone(),
                self.params.alpha,
                self.fabric.clone(),
                cs,
            )?
        }

        Ok(())
    }

    /// Multiply the state by the MDS (Maximum Distance Separable) matrix
    ///
    /// This step is applied after the sbox is applied to the state
    fn apply_mds(&mut self) {
        let mut new_state = vec![MpcLinearCombination::<N, S>::default(); self.state.len()];
        for (i, row) in self.params.mds_matrix.iter().enumerate() {
            for (a, b) in row.iter().zip(self.state.iter()) {
                new_state[i] += *a * b
            }
        }

        self.state = new_state;
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
    /// Witness is as the witness in the single prover case, except for the facts that hte underlying scalar
    /// field is the authenticated and shared Ristretto scalar field.
    ///
    /// The Statement, on the other hand, is entirely public; and therefore the same type as the single prover.
    type Witness = MultiproverPoseidonWitness<N, S>;
    type WitnessCommitment = Vec<AuthenticatedCompressedRistretto<N, S>>;
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
        ProverError,
    > {
        // Commit to the hash input and expected output
        let mut rng = OsRng {};
        let blinders = (0..witness.preimage.len())
            .map(|_| Scalar::random(&mut rng))
            .collect_vec();

        let (witness_commits, witness_vars) = prover
            .batch_commit_preshared(&witness.preimage, &blinders)
            .map_err(|err| ProverError::Mpc(MpcError::SharingError(err.to_string())))?;

        let (_, out_var) = prover.commit_public(statement.expected_out);

        // Create a hasher and apply the constraints
        let mut hasher = MultiproverPoseidonHashGadget::new(statement.params, fabric);
        hasher.hash(&witness_vars, &out_var, &mut prover)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::Collaborative)?;

        Ok((witness_commits, proof))
    }

    fn verify(
        witness_commitments: Vec<CompressedRistretto>,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Forward to the single prover gadget
        PoseidonHashGadget::verify(witness_commitments, statement, proof, verifier)
    }
}

#[cfg(test)]
mod single_prover_test {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{prime_field_to_scalar, DalekRistrettoField},
        hash::default_poseidon_params,
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use rand_core::{OsRng, RngCore};

    use crate::{
        mpc_gadgets::poseidon::PoseidonSpongeParameters, test_helpers::bulletproof_prove_and_verify,
    };

    use super::{PoseidonGadgetStatement, PoseidonGadgetWitness, PoseidonHashGadget};

    #[test]
    fn test_single_prover_hash() {
        // Sample random values to hash
        let mut rng = OsRng {};
        let n = 15;
        let random_elems = (0..n).map(|_| rng.next_u64()).collect_vec();

        // Compute the hash via Arkworks for expected result
        let arkworks_params = default_poseidon_params();
        let mut arkworks_hasher = PoseidonSponge::new(&arkworks_params);

        for elem in random_elems.iter() {
            arkworks_hasher.absorb(&DalekRistrettoField::from(*elem as i128));
        }

        let expected_result: DalekRistrettoField =
            arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0];

        let expected_scalar = prime_field_to_scalar(&expected_result);

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
