//! Defines the VALID MATCH MPC circuit that proves knowledge of orders
//! which intersect to the given matches result
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.5
//! for a formal specification

// TODO: Remove this lint allowance
#![allow(unused)]

use std::marker::PhantomData;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, R1CSProof, RandomizableConstraintSystem, Verifier},
    r1cs_mpc::{
        MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem, MultiproverError,
        R1CSError, SharedR1CSProof,
    },
    BulletproofGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto, beaver::SharedValueSource,
    network::MpcNetwork,
};
use rand_core::OsRng;

use crate::{
    mpc::SharedFabric,
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{
        AuthenticatedMatch, AuthenticatedSingleMatchResult, Balance, BalanceVar, FeeVar, Order,
        OrderVar,
    },
    zk_gadgets::poseidon::{MultiproverPoseidonHashGadget, PoseidonHashGadget},
    MultiProverCircuit,
};

const ORDER_LENGTH_SCALARS: usize = 5; // mint1, mint2, direction, price, amount
const BALANCE_LENGTH_SCALARS: usize = 2; // amount, direction
const FEE_LENGTH_SCALARS: usize = 4; // settle_key, gas_addr, gas_token_amount, percentage_fee

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchMpcCircuit<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    ValidMatchMpcCircuit<'a, N, S>
{
    /// Assert that the hash of an input equals the expected public value
    ///
    /// This is used throughout the statement to assert input consistency with
    /// linked proofs
    pub fn input_consistency_check<L, CS>(
        cs: &mut CS,
        input: &[L],
        expected_out: &L,
        fabric: SharedFabric<N, S>,
    ) -> Result<(), R1CSError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Build a hasher and constrain the hash of the input to equal the expected output
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = MultiproverPoseidonHashGadget::new(hash_params, fabric);
        hasher.hash(cs, input, expected_out)
    }

    /// The single prover version of the input consistency check
    ///
    /// Used to apply constraints to a verifier or for local testing
    pub(crate) fn input_consistency_single_prover<L, CS>(
        cs: &mut CS,
        input: &[L],
        expected_out: &L,
    ) -> Result<(), R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Build a hasher and constrain the hash of the input to equal the expected output
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);
        hasher.hash(cs, input, expected_out.clone())
    }
}

/// The witness type for the circuit proving the VALID MATCH MPC statement
///
/// Note that the witness structure does not include both orders or balances.
/// This is because the witness is distributed (neither party knows both sides)
/// and is realized during the commit phase of the collaborative proof.
///
/// TODO: Add in the fee tuples from each party
#[derive(Clone, Debug)]
pub struct ValidMatchMpcWitness<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The local party's order that was matched by MPC
    pub my_order: OrderVar,
    /// A balance known by the local party that covers the position
    /// expressed in their order
    pub my_balance: BalanceVar,
    /// A fee that covers the gas and transaction fee of the local party
    pub my_fee: FeeVar,
    /// The result of running a match MPC on the given orders
    ///
    /// We do not open this value before proving so that we can avoid leaking information
    /// before the collaborative proof has finished
    pub match_res: AuthenticatedMatch<N, S>,
}

/// The parameterization for the VALID MATCH MPC statement
///
/// TODO: Add in fee tuple input consistency values
/// TODO: Add in midpoint oracle prices
/// TODO: Commitments to the randomness
#[derive(Debug, Clone)]
pub struct ValidMatchMpcStatement {
    /// The expected hash of the first order
    pub hash_order1: Scalar,
    /// The expected hash of the first balance
    pub hash_balance1: Scalar,
    /// The expected hash of the first party's fee
    pub hash_fee1: Scalar,
    /// The expected hash of the first party's randomness
    pub hash_randomness1: Scalar,
    /// The expected hash of the second order
    pub hash_order2: Scalar,
    /// The expected hash of the sceond balance
    pub hash_balance2: Scalar,
    /// The expected hash of the second party's fee
    pub hash_fee2: Scalar,
    /// The expected hash of the second party's randomness
    pub hash_randomness2: Scalar,
}

/// Prover implementation of the Valid Match circuit
impl<'a, N: 'a + MpcNetwork + Send, S: SharedValueSource<Scalar>> MultiProverCircuit<'a, N, S>
    for ValidMatchMpcCircuit<'a, N, S>
{
    type Statement = ValidMatchMpcStatement;
    type Witness = ValidMatchMpcWitness<N, S>;
    const BP_GENS_CAPACITY: usize = 16384;

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
        // Commit to party 0's inputs first, then party 1's inputs
        let mut rng = OsRng {};
        let blinders = (0..ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS + FEE_LENGTH_SCALARS)
            .map(|_| Scalar::random(&mut rng))
            .collect_vec();

        // The input values of the local party
        let my_input_values = Into::<Vec<Scalar>>::into(&witness.my_order)
            .into_iter()
            .chain(Into::<Vec<Scalar>>::into(&witness.my_balance).into_iter())
            .chain(Into::<Vec<Scalar>>::into(&witness.my_fee).into_iter())
            .collect_vec();

        let (party0_comm, party0_vars) = prover
            .batch_commit(0 /* owning_party */, &my_input_values, &blinders)
            .map_err(MultiproverError::Mpc)?;

        let (party1_comm, party1_vars) = prover
            .batch_commit(1 /* owning_party */, &my_input_values, &blinders)
            .map_err(MultiproverError::Mpc)?;

        let party0_order = party0_vars[..ORDER_LENGTH_SCALARS].to_vec();
        let party0_balance = party0_vars
            [ORDER_LENGTH_SCALARS..ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS]
            .to_vec();
        let party0_fee = party0_vars[ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS..].to_vec();
        let party1_order = party1_vars[..ORDER_LENGTH_SCALARS].to_vec();
        let party1_balance = party1_vars
            [ORDER_LENGTH_SCALARS..ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS]
            .to_vec();
        let party1_fee = party1_vars[ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS..].to_vec();

        // Commit to the public statement variables
        let (_, hash_o1_var) = prover.commit_public(statement.hash_order1);
        let (_, hash_b1_var) = prover.commit_public(statement.hash_balance1);
        let (_, hash_f1_var) = prover.commit_public(statement.hash_fee1);
        let (_, hash_o2_var) = prover.commit_public(statement.hash_order2);
        let (_, hash_b2_var) = prover.commit_public(statement.hash_balance2);
        let (_, hash_f2_var) = prover.commit_public(statement.hash_fee2);

        // Check input consistency on all orders, balances, and fees
        Self::input_consistency_check(&mut prover, &party0_order, &hash_o1_var, fabric.clone())
            .map_err(MultiproverError::ProverError)?;
        Self::input_consistency_check(&mut prover, &party0_balance, &hash_b1_var, fabric.clone())
            .map_err(MultiproverError::ProverError)?;
        Self::input_consistency_check(&mut prover, &party0_fee, &hash_f1_var, fabric.clone())
            .map_err(MultiproverError::ProverError)?;
        Self::input_consistency_check(&mut prover, &party1_order, &hash_o2_var, fabric.clone())
            .map_err(MultiproverError::ProverError)?;
        Self::input_consistency_check(&mut prover, &party1_balance, &hash_b2_var, fabric.clone())
            .map_err(MultiproverError::ProverError)?;
        Self::input_consistency_check(&mut prover, &party1_fee, &hash_f2_var, fabric)
            .map_err(MultiproverError::ProverError)?;

        // TODO: Check that the balances cover the orders

        // Prover the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens)?;

        Ok((
            party0_comm
                .into_iter()
                .chain(party1_comm.into_iter())
                .collect(),
            proof,
        ))
    }

    fn verify(
        witness_commitments: &[CompressedRistretto],
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), R1CSError> {
        // Commit to the input variables from the provers
        let witness_vars = witness_commitments
            .iter()
            .map(|comm| verifier.commit(*comm))
            .collect_vec();

        // Split witness into consituent parts
        let inputs_per_party = ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS + FEE_LENGTH_SCALARS;

        let party0_order = witness_vars[..ORDER_LENGTH_SCALARS].to_vec();
        let party0_balance = witness_vars
            [ORDER_LENGTH_SCALARS..ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS]
            .to_vec();
        let party0_fee =
            witness_vars[ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS..inputs_per_party].to_vec();
        let party1_order =
            witness_vars[inputs_per_party..inputs_per_party + ORDER_LENGTH_SCALARS].to_vec();
        let party1_balance = witness_vars[inputs_per_party + ORDER_LENGTH_SCALARS
            ..inputs_per_party + ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS]
            .to_vec();
        let party1_fee = witness_vars
            [inputs_per_party + ORDER_LENGTH_SCALARS + BALANCE_LENGTH_SCALARS..]
            .to_vec();

        // Commit to the statement variables
        let hash_o1_var = verifier.commit_public(statement.hash_order1);
        let hash_b1_var = verifier.commit_public(statement.hash_balance1);
        let hash_f1_var = verifier.commit_public(statement.hash_fee1);
        let hash_o2_var = verifier.commit_public(statement.hash_order2);
        let hash_b2_var = verifier.commit_public(statement.hash_balance2);
        let hash_f2_var = verifier.commit_public(statement.hash_fee2);

        // Apply constraints to the verifier
        Self::input_consistency_single_prover(&mut verifier, &party0_order, &hash_o1_var)?;
        Self::input_consistency_single_prover(&mut verifier, &party0_balance, &hash_b1_var)?;
        Self::input_consistency_single_prover(&mut verifier, &party0_fee, &hash_f1_var)?;
        Self::input_consistency_single_prover(&mut verifier, &party1_order, &hash_o2_var)?;
        Self::input_consistency_single_prover(&mut verifier, &party1_balance, &hash_b2_var)?;
        Self::input_consistency_single_prover(&mut verifier, &party1_fee, &hash_f2_var)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier.verify(&proof, &bp_gens)
    }
}
