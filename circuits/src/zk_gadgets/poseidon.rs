//! Groups logic for adding Poseidon hash function constraints to a Bulletproof
//! constraint system

use circuit_types::{
    errors::ProverError,
    traits::{LinearCombinationLike, MpcLinearCombinationLike},
};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem, MpcVariable, R1CSError},
};
use mpc_stark::{algebra::scalar::Scalar, MpcFabric};
use renegade_crypto::hash::PoseidonParams;

use super::arithmetic::{ExpGadget, MultiproverExpGadget};

// -----------------------
// | Singleprover Gadget |
// -----------------------

/// A hash gadget that applies a Poseidon hash function to the given constraint system
///
/// This version of the gadget is used for the single-prover case, i.e. no MPC
#[derive(Debug)]
pub struct PoseidonHashGadget {
    /// The parameterization of the hash function
    params: PoseidonParams,
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
    pub fn new(params: PoseidonParams) -> Self {
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
        L: LinearCombinationLike,
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
        L: LinearCombinationLike,
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
        L: LinearCombinationLike,
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
        let partial_rounds_end = partial_rounds_start + self.params.partial_rounds;
        for round in partial_rounds_start..partial_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(false /* full_round */, cs)?;
            self.apply_mds()?;
        }

        // Compute another full_rounds / 2 rounds in which we apply the sbox to all elements
        let final_full_rounds_start = partial_rounds_end;
        let final_full_rounds_end = self.params.partial_rounds + self.params.full_rounds;
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
        for (elem, round_constant) in self.state.iter_mut().zip(
            self.params.ark[round_number]
                .iter()
                .copied()
                .map(Scalar::from),
        ) {
            *elem += LinearCombination::from(round_constant)
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
        for (i, row) in self.params.mds.iter().enumerate() {
            for (a, b) in row
                .iter()
                .copied()
                .map(Scalar::from)
                .zip(self.state.iter_mut())
            {
                new_state[i] += a * b.clone()
            }
        }

        self.state = new_state;

        Ok(())
    }
}

// ----------------------
// | Multiprover Gadget |
// ----------------------

/// A hash gadget that applies a Poseidon hash function to the given constraint system
///
/// This version of the gadget is used for the multi-prover case, i.e in an MPC execution
#[derive(Debug)]
pub struct MultiproverPoseidonHashGadget {
    /// The parameterization of the hash function
    params: PoseidonParams,
    /// The hash state
    state: Vec<MpcLinearCombination>,
    /// The next index in the state to being absorbing inputs at
    next_index: usize,
    /// Whether the sponge is in squeezing mode. For simplicity, we disallow
    /// the case in which a caller wishes to squeeze values and the absorb more.
    in_squeeze_state: bool,
    /// A reference to the shared MPC fabric that the computation variables are allocated in
    fabric: MpcFabric,
}

impl MultiproverPoseidonHashGadget {
    /// Construct a new hash gadget with the given parameterization
    pub fn new(params: PoseidonParams, fabric: MpcFabric) -> Self {
        // Initialize the state as all zeros
        let state = (0..params.capacity + params.rate)
            .map(|_| MpcLinearCombination::from_scalar(Scalar::zero(), fabric.clone()))
            .collect::<Vec<_>>();
        Self {
            params,
            state,
            next_index: 0,
            in_squeeze_state: false, // Start in absorb state
            fabric,
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
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem,
    {
        self.batch_absorb(hash_input, cs)?;
        self.constrained_squeeze(expected_output.clone(), cs)
    }

    /// Absorb an input into the hasher state
    pub fn absorb<L, CS>(&mut self, a: L, cs: &mut CS) -> Result<(), ProverError>
    where
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem,
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
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem,
    {
        a.iter().try_for_each(|val| self.absorb(val.clone(), cs))
    }

    /// Squeeze an output from the hasher and return to the caller
    pub fn squeeze<CS>(&mut self, cs: &mut CS) -> Result<MpcLinearCombination, ProverError>
    where
        CS: MpcRandomizableConstraintSystem,
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
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem,
    {
        let squeezed = self.squeeze(cs)?;
        cs.constrain(squeezed - expected.into());
        Ok(())
    }

    /// Squeeze a batch of elements from the hasher
    pub fn batch_squeeze<CS>(
        &mut self,
        num_elems: usize,
        cs: &mut CS,
    ) -> Result<Vec<MpcLinearCombination>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem,
    {
        (0..num_elems)
            .map(|_| self.squeeze(cs))
            .collect::<Result<Vec<_>, ProverError>>()
    }

    /// Squeeze a set of elements from the hasher, and constraint the elements to be equal
    /// to the provided statement variables
    pub fn batch_constrained_squeeze<L, CS>(
        &mut self,
        expected: &[MpcVariable],
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem,
    {
        expected
            .iter()
            .try_for_each(|val| self.constrained_squeeze(val.clone(), cs))
    }

    /// Permute the digest by applying the Poseidon round function
    fn permute<CS: MpcRandomizableConstraintSystem>(
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
        let partial_rounds_end = partial_rounds_start + self.params.partial_rounds;
        for round in partial_rounds_start..partial_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(false /* full_round */, cs)?;
            self.apply_mds();
        }

        // Compute another full_rounds / 2 rounds in which we apply the sbox to all elements
        let final_full_rounds_start = partial_rounds_end;
        let final_full_rounds_end = self.params.partial_rounds + self.params.full_rounds;
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
        for (elem, round_constant) in self.state.iter_mut().zip(
            self.params.ark[round_number]
                .iter()
                .copied()
                .map(Scalar::from),
        ) {
            *elem += MpcLinearCombination::from_scalar(round_constant, self.fabric.clone())
        }
    }

    /// Apply the Poseidon s-box (i.e. x^\alpha \mod L) for given parameter \alpha
    ///
    /// This permutation is applied to every element of the state for a full round,
    /// and only to the last element of the state for a partial round
    ///
    /// This step is applied in the Poseidon permutation after the round constants
    /// are added to the state.
    fn apply_sbox<CS: MpcRandomizableConstraintSystem>(
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
        let mut new_state = vec![MpcLinearCombination::default(); self.state.len()];
        for (i, row) in self.params.mds.iter().enumerate() {
            for (a, b) in row.iter().copied().map(Scalar::from).zip(self.state.iter()) {
                new_state[i] += a * b
            }
        }

        self.state = new_state;
    }
}

#[cfg(test)]
mod single_prover_test {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use circuit_types::traits::CircuitBaseType;
    use itertools::Itertools;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use mpc_stark::algebra::scalar::Scalar;
    use rand::{rngs::OsRng, RngCore};
    use renegade_crypto::hash::default_poseidon_params;

    use super::PoseidonHashGadget;

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
            arkworks_hasher.absorb(&Scalar::Field::from(*elem as i128));
        }

        let expected_result: Scalar::Field =
            arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0];

        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let preimage_vars = random_elems
            .into_iter()
            .map(|elem| elem.commit_public(&mut prover))
            .collect_vec();
        let expected_out_var = Scalar::from(expected_result).commit_public(&mut prover);

        let mut hasher = PoseidonHashGadget::new(default_poseidon_params());
        hasher
            .hash(&preimage_vars, expected_out_var, &mut prover)
            .unwrap();

        assert!(prover.constraints_satisfied());
    }

    /// Tests the case in which the pre-image is not correct
    #[test]
    fn test_single_prover_hash_failure() {
        let mut rng = OsRng {};
        let n = 15;
        let random_elems = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let random_expected = Scalar::random(&mut rng);

        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let preimage_vars = random_elems
            .into_iter()
            .map(|elem| elem.commit_public(&mut prover))
            .collect_vec();
        let expected_out_var = random_expected.commit_public(&mut prover);

        let mut hasher = PoseidonHashGadget::new(default_poseidon_params());
        hasher
            .hash(&preimage_vars, expected_out_var, &mut prover)
            .unwrap();

        assert!(!prover.constraints_satisfied());
    }
}
