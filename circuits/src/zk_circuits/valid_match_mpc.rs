//! Defines the VALID MATCH MPC circuit that proves knowledge of orders
//! which intersect to the given matches result
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.5
//! for a formal specification

use std::marker::PhantomData;

use circuit_macros::circuit_type;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::{
    r1cs::{LinearCombination, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
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
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    mpc::SharedFabric,
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
        MpcBaseType, MpcLinearCombinationLike, MpcType, MultiproverCircuitBaseType,
        MultiproverCircuitCommitmentType, MultiproverCircuitVariableType,
    },
    types::r#match::LinkableMatchResult,
    zk_gadgets::fixed_point::AuthenticatedFixedPointVar,
    zk_gadgets::select::{
        CondSelectGadget, CondSelectVectorGadget, MultiproverCondSelectGadget,
        MultiproverCondSelectVectorGadget,
    },
    MultiProverCircuit,
};
use crate::{
    types::{balance::LinkableBalance, order::LinkableOrder},
    zk_gadgets::{
        comparators::{
            GreaterThanEqGadget, GreaterThanEqZeroGadget, MultiproverGreaterThanEqGadget,
            MultiproverGreaterThanEqZeroGadget,
        },
        fixed_point::FixedPointVar,
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchMpcCircuit<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send + Clone, S: 'a + SharedValueSource<Scalar> + Clone>
    ValidMatchMpcCircuit<'a, N, S>
{
    /// The order crossing check, verifies that the matches result is valid given the orders
    /// and balances of the two parties
    pub fn matching_engine_check<CS>(
        witness: AuthenticatedValidMatchMpcWitnessVar<N, S, MpcVariable<N, S>>,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Check that both orders are for the matched asset pair
        cs.constrain(witness.order1.quote_mint - witness.match_res.quote_mint.clone());
        cs.constrain(witness.order1.base_mint - witness.match_res.base_mint.clone());
        cs.constrain(witness.order2.quote_mint - witness.match_res.quote_mint.clone());
        cs.constrain(witness.order2.base_mint - witness.match_res.base_mint.clone());

        // Check that the direction of the match is the same as the first party's direction
        cs.constrain(witness.match_res.direction.clone() - witness.order1.side.clone());

        // Check that the orders are on opposite sides of the market. It is assumed that order
        // sides are already constrained to be binary when they are submitted. More broadly it
        // is assumed that orders are well formed, checking this amounts to checking their inclusion
        // in the state tree, which is done in `input_consistency_check`
        cs.constrain(
            witness.order1.side + witness.order2.side - MpcVariable::one(fabric.0.clone()),
        );

        // Check that the prices of the orders overlap
        // 1. Mux buy/sell side based on the direction of the match
        let prices = MultiproverCondSelectVectorGadget::select(
            cs,
            &[
                witness.order2.price.repr.clone(),
                witness.order1.price.repr.clone(),
            ],
            &[
                witness.order1.price.repr.clone(),
                witness.order2.price.repr.clone(),
            ],
            witness.match_res.direction.clone(),
            fabric.clone(),
        )?;
        let buy_side_price = AuthenticatedFixedPointVar {
            repr: prices[0].to_owned(),
        };
        let sell_side_price = AuthenticatedFixedPointVar {
            repr: prices[1].to_owned(),
        };

        // 2. Enforce that the buy side price is greater than or equal to the sell side price
        MultiproverGreaterThanEqGadget::<'_, 64 /* bitlength */, N, S>::constrain_greater_than_eq(
            buy_side_price.repr,
            sell_side_price.repr,
            fabric.clone(),
            cs,
        )?;

        // Check that price is correctly computed to be the midpoint
        // i.e. price1 + price2 = 2 * execution_price
        let double_execution_price = witness
            .match_res
            .execution_price
            .mul_integer(
                MpcLinearCombination::from_scalar(Scalar::from(2u64), fabric.0.clone()),
                cs,
            )
            .map_err(ProverError::Collaborative)?;
        double_execution_price.constrain_equal(&(witness.order1.price + witness.order2.price), cs);

        // Constrain the min_amount_order_index to be binary
        // i.e. 0 === min_amount_order_index * (1 - min_amount_order_index)
        let (_, _, mul_out) = cs
            .multiply(
                &witness.match_res.min_amount_order_index.clone().into(),
                &(MpcLinearCombination::from_scalar(Scalar::one(), fabric.0.clone())
                    - &witness.match_res.min_amount_order_index),
            )
            .map_err(ProverError::Collaborative)?;
        cs.constrain(mul_out.into());

        // Check that the amount of base currency exchanged is equal to the minimum of the two
        // order's amounts

        // 1. Constraint he max_minus_min_amount to be correctly computed with respect to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = &witness.order1.amount - &witness.order2.amount;
        let max_minus_min2 = &witness.order2.amount - &witness.order1.amount;
        let max_minus_min_expected = MultiproverCondSelectGadget::select(
            max_minus_min1,
            max_minus_min2,
            witness.match_res.min_amount_order_index.into(),
            fabric.clone(),
            cs,
        )?;
        cs.constrain(&max_minus_min_expected - &witness.match_res.max_minus_min_amount);

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be computed correctly.
        // I.e. the above constraint forces `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) - min(amounts)
        MultiproverGreaterThanEqZeroGadget::<'_, 32 /* bitlength */, _, _>::constrain_greater_than_zero(
            witness.match_res.max_minus_min_amount.clone(),
            fabric.clone(),
            cs,
        )?;

        // 3. Constrain the executed base amount to be the minimum of the two order amounts
        // We use the identity
        //      min(a, b) = 1/2 * (a + b - [max(a, b) - min(a, b)])
        // Above we are given max(a, b) - min(a, b), so we can enforce the constraint
        //      2 * executed_amount = amount1 + amount2 - max_minus_min_amount
        let lhs = Scalar::from(2u64) * &witness.match_res.base_amount;
        let rhs = &witness.order1.amount + &witness.order2.amount
            - &witness.match_res.max_minus_min_amount;
        cs.constrain(lhs - rhs);

        // The quote amount should then equal the price multiplied by the base amount
        let expected_quote_amount = witness
            .match_res
            .execution_price
            .mul_integer(witness.match_res.base_amount.clone(), cs)
            .map_err(ProverError::Collaborative)?;
        expected_quote_amount.constrain_equal_integer(&witness.match_res.quote_amount, cs);

        // Ensure the balances cover the orders
        // 1. Mux between the (mint, amount) pairs that the parties are expected to cover by the
        // direction of the order

        // The selections in the case that party 0 is on the buy side of the match
        let party0_buy_side_selection = vec![
            witness.match_res.base_mint.clone(),
            witness.match_res.base_amount.clone(),
            witness.match_res.quote_mint.clone(),
            witness.match_res.quote_amount.clone(),
        ];

        let party1_buy_side_selection = vec![
            witness.match_res.quote_mint.clone(),
            witness.match_res.quote_amount.clone(),
            witness.match_res.base_mint.clone(),
            witness.match_res.base_amount.clone(),
        ];

        let selected_values = MultiproverCondSelectVectorGadget::select(
            cs,
            &party0_buy_side_selection,
            &party1_buy_side_selection,
            witness.match_res.direction,
            fabric.clone(),
        )?;

        // Destructure the conditional selection
        let party0_buy_mint = selected_values[0].to_owned();
        let party0_buy_amount = selected_values[1].to_owned();
        let party1_buy_mint = selected_values[2].to_owned();
        let party1_buy_amount = selected_values[3].to_owned();

        // Constrain the mints on the balances to be correct
        cs.constrain(&party0_buy_mint - &witness.balance1.mint);
        cs.constrain(&party1_buy_mint - &witness.balance2.mint);

        // Constrain the amounts of the balances to subsume the obligations from the match
        MultiproverGreaterThanEqGadget::<'_, 64 /* bitlength */, N, S>::constrain_greater_than_eq(
            witness.balance1.amount.into(),
            party0_buy_amount,
            fabric.clone(),
            cs,
        )?;

        MultiproverGreaterThanEqGadget::<'_, 64 /* bitlength */, N, S>::constrain_greater_than_eq(
            witness.balance2.amount.into(),
            party1_buy_amount,
            fabric,
            cs,
        )?;

        Ok(())
    }

    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    pub fn matching_engine_check_single_prover<CS>(
        witness: ValidMatchMpcWitnessVar<Variable>,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
    {
        // Check that both orders are for the matched asset pair
        cs.constrain(witness.order1.quote_mint - witness.match_res.quote_mint);
        cs.constrain(witness.order1.base_mint - witness.match_res.base_mint);
        cs.constrain(witness.order2.quote_mint - witness.match_res.quote_mint);
        cs.constrain(witness.order2.base_mint - witness.match_res.base_mint);

        // Check that the direction of the match is the same as the first party's direction
        cs.constrain(witness.match_res.direction - witness.order1.side);

        // Check that the orders are on opposite sides of the market. It is assumed that order
        // sides are already constrained to be binary when they are submitted. More broadly it
        // is assumed that orders are well formed, checking this amounts to checking their inclusion
        // in the state tree, which is done in `input_consistency_check`
        cs.constrain(witness.order1.side + witness.order2.side - Variable::One());

        // Check that the prices of the orders overlap
        // 1. Mux buy/sell side based on the direction of the match
        let prices = CondSelectVectorGadget::select::<Variable, Variable, _>(
            &[witness.order2.price.repr, witness.order1.price.repr],
            &[witness.order1.price.repr, witness.order2.price.repr],
            witness.match_res.direction,
            cs,
        );
        let buy_side_price = FixedPointVar {
            repr: prices[0].to_owned(),
        };
        let sell_side_price = FixedPointVar {
            repr: prices[1].to_owned(),
        };

        // 2. Enforce that the buy side price is greater than or equal to the sell side price
        GreaterThanEqGadget::<64 /* bitlength */>::constrain_greater_than_eq(
            buy_side_price.repr,
            sell_side_price.repr,
            cs,
        );

        // Check that price is correctly computed to be the midpoint
        // i.e. price1 + price2 = 2 * execution_price
        let double_execution_price = witness
            .match_res
            .execution_price
            .mul_integer::<LinearCombination, _>(Scalar::from(2u8).into(), cs);
        cs.constrain(double_execution_price - (witness.order1.price + witness.order2.price));

        // Constrain the min_amount_order_index to be binary
        // i.e. 0 === min_amount_order_index * (1 - min_amount_order_index)
        let (_, _, mul_out) = cs.multiply(
            witness.match_res.min_amount_order_index.into(),
            LinearCombination::from(Scalar::one()) - witness.match_res.min_amount_order_index,
        );
        cs.constrain(mul_out.into());

        // Check that the amount of base currency exchanged is equal to the minimum of the two
        // order's amounts

        // 1. Constraint he max_minus_min_amount to be correctly computed with respect to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = witness.order1.amount - witness.order2.amount;
        let max_minus_min2 = witness.order2.amount - witness.order1.amount;
        let max_minus_min_expected = CondSelectGadget::select::<LinearCombination, Variable, _>(
            max_minus_min1,
            max_minus_min2,
            witness.match_res.min_amount_order_index,
            cs,
        );
        cs.constrain(max_minus_min_expected - witness.match_res.max_minus_min_amount);

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be computed correctly.
        // I.e. the above constraint forces `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) - min(amounts)
        GreaterThanEqZeroGadget::<32 /* bitlength */>::constrain_greater_than_zero(
            witness.match_res.max_minus_min_amount,
            cs,
        );

        // 3. Constrain the executed base amount to be the minimum of the two order amounts
        // We use the identity
        //      min(a, b) = 1/2 * (a + b - [max(a, b) - min(a, b)])
        // Above we are given max(a, b) - min(a, b), so we can enforce the constraint
        //      2 * executed_amount = amount1 + amount2 - max_minus_min_amount
        let lhs = Scalar::from(2u64) * witness.match_res.base_amount;
        let rhs =
            witness.order1.amount + witness.order2.amount - witness.match_res.max_minus_min_amount;
        cs.constrain(lhs - rhs);

        // The quote amount should then equal the price multiplied by the base amount
        let expected_quote_amount = witness
            .match_res
            .execution_price
            .mul_integer(witness.match_res.base_amount, cs);
        expected_quote_amount.constraint_equal_integer(witness.match_res.quote_amount, cs);

        // Ensure the balances cover the orders
        // 1. Mux between the (mint, amount) pairs that the parties are expected to cover by the
        // direction of the order

        // The selections in the case that party 0 is on the buy side of the match
        let party0_buy_side_selection = vec![
            witness.match_res.base_mint,
            witness.match_res.base_amount,
            witness.match_res.quote_mint,
            witness.match_res.quote_amount,
        ];

        let party1_buy_side_selection = vec![
            witness.match_res.quote_mint,
            witness.match_res.quote_amount,
            witness.match_res.base_mint,
            witness.match_res.base_amount,
        ];

        let selected_values = CondSelectVectorGadget::select(
            &party0_buy_side_selection,
            &party1_buy_side_selection,
            witness.match_res.direction,
            cs,
        );

        // Destructure the conditional selection
        let party0_buy_mint = selected_values[0].to_owned();
        let party0_buy_amount = selected_values[1].to_owned();
        let party1_buy_mint = selected_values[2].to_owned();
        let party1_buy_amount = selected_values[3].to_owned();

        // Constrain the mints on the balances to be correct
        cs.constrain(party0_buy_mint - witness.balance1.mint);
        cs.constrain(party1_buy_mint - witness.balance2.mint);

        // Constrain the amounts of the balances to subsume the obligations from the match
        GreaterThanEqGadget::<64 /* bitlength */>::constrain_greater_than_eq(
            witness.balance1.amount.into(),
            party0_buy_amount,
            cs,
        );

        GreaterThanEqGadget::<64 /* bitlength */>::constrain_greater_than_eq(
            witness.balance2.amount.into(),
            party1_buy_amount,
            cs,
        );

        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The full witness, recovered by opening the witness commitment, but never realized in
/// the plaintext by either party
#[circuit_type(singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidMatchMpcWitness {
    /// The first party's order
    pub order1: LinkableOrder,
    /// The first party's balance
    pub balance1: LinkableBalance,
    /// The second party's order
    pub order2: LinkableOrder,
    /// The second party's balance
    pub balance2: LinkableBalance,
    /// The result of running a match MPC on the given orders
    ///
    /// We do not open this value before proving so that we can avoid leaking information
    /// before the collaborative proof has finished
    pub match_res: LinkableMatchResult,
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The parameterization for the VALID MATCH MPC statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidMatchMpcStatement {}

// ---------------------
// | Prove Verify Flow |
// ---------------------

/// Prover implementation of the Valid Match circuit
impl<'a, N: 'a + MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiProverCircuit<'a, N, S> for ValidMatchMpcCircuit<'a, N, S>
{
    type Statement = ();
    type Witness = AuthenticatedValidMatchMpcWitness<N, S>;

    const BP_GENS_CAPACITY: usize = 256;

    fn prove(
        witness: Self::Witness,
        _statement: Self::Statement,
        mut prover: MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<
        (
            AuthenticatedValidMatchMpcWitnessCommitment<N, S>,
            SharedR1CSProof<N, S>,
        ),
        ProverError,
    > {
        // Commit to party 0's inputs first, then party 1's inputs
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness
            .commit_shared(&mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;

        Self::matching_engine_check(witness_var, fabric, &mut prover)?;

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::Collaborative)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitment: ValidMatchMpcWitnessCommitment,
        _statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Allocate the witness in the constraint system
        let witness_vars = witness_commitment.commit_verifier(&mut verifier);

        // Check that the matches value is properly formed
        Self::matching_engine_check_single_prover(witness_vars, &mut verifier)
            .map_err(VerifierError::R1CS)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
