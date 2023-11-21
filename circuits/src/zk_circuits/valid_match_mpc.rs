//! Defines the VALID MATCH MPC circuit that proves knowledge of orders
//! which intersect to the given matches result
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.5
//! for a formal specification

use ark_ff::{One, Zero};
use circuit_types::{
    balance::{Balance, BalanceVar},
    fixed_point::{FixedPoint, FixedPointVar, DEFAULT_FP_PRECISION},
    order::{Order, OrderVar},
    r#match::{MatchResult, MatchResultVar},
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType, MultiProverCircuit,
        MultiproverCircuitBaseType, SingleProverCircuit,
    },
    Fabric, MpcPlonkCircuit, PlonkCircuit, AMOUNT_BITS, PRICE_BITS,
};
use constants::{AuthenticatedScalar, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use crate::zk_gadgets::{
    comparators::{
        EqGadget, GreaterThanEqGadget, GreaterThanEqZeroGadget, MultiproverGreaterThanEqGadget,
        MultiproverGreaterThanEqZeroGadget,
    },
    fixed_point::{FixedPointGadget, MultiproverFixedPointGadget},
    select::{CondSelectGadget, CondSelectVectorGadget},
};
use circuit_macros::circuit_type;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchMpc;
impl ValidMatchMpc {
    /// The order crossing check, verifies that the matches result is valid
    /// given the orders and balances of the two parties
    pub fn multi_prover_circuit(
        witness: &ValidMatchMpcWitnessVar,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = ScalarField::zero();
        let one = ScalarField::one();

        let zero_var = cs.zero();
        let one_var = cs.one();

        // --- Match Engine Input Validity --- //
        // Check that both orders are for the matched asset pair
        cs.enforce_equal(witness.order1.quote_mint, witness.match_res.quote_mint)?;
        cs.enforce_equal(witness.order1.base_mint, witness.match_res.base_mint)?;
        cs.enforce_equal(witness.order2.quote_mint, witness.match_res.quote_mint)?;
        cs.enforce_equal(witness.order2.base_mint, witness.match_res.base_mint)?;

        // Check that the prices supplied by the parties are equal, these should be
        // agreed upon outside of the circuit
        EqGadget::constrain_eq(&witness.price1, &witness.price2, cs)?;

        // Check that the balances supplied are for the correct mints; i.e. for the mint
        // that each party sells in the settlement
        let selected_mints = CondSelectGadget::select(
            &[witness.match_res.base_mint, witness.match_res.quote_mint],
            &[witness.match_res.quote_mint, witness.match_res.base_mint],
            witness.match_res.direction,
            cs,
        )?;

        cs.enforce_equal(witness.balance1.mint, selected_mints[0])?;
        cs.enforce_equal(witness.balance2.mint, selected_mints[1])?;

        // Check that the max amount match supplied by both parties is covered by the
        // balance no greater than the amount specified in the order
        Self::validate_volume_constraints(
            &witness.match_res,
            &witness.balance1,
            &witness.order1,
            fabric,
            cs,
        )?;

        Self::validate_volume_constraints(
            &witness.match_res,
            &witness.balance2,
            &witness.order2,
            fabric,
            cs,
        )?;

        // --- Match Engine Execution Validity --- //
        // Check that the direction of the match is the same as the first party's
        // direction
        cs.enforce_equal(
            witness.match_res.direction.into(),
            witness.order1.side.into(),
        )?;

        // Check that the orders are on opposite sides of the market. It is assumed that
        // order sides are already constrained to be binary when they are
        // submitted. More broadly it is assumed that orders are well formed,
        // checking this amounts to checking their inclusion in the state tree,
        // which is done in `input_consistency_check`
        cs.lc_gate(
            &[
                witness.order1.side.into(),
                witness.order2.side.into(),
                one_var,
                one_var,
                zero_var, // out wire
            ],
            &[one, one, -one, zero],
        )?;

        // Check that the amount of base currency exchanged is equal to the minimum of
        // the two order's amounts

        // 1. Constrain the max_minus_min_amount to be correctly computed with respect
        //    to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = cs.sub(witness.amount1, witness.amount2)?;
        let max_minus_min2 = cs.sub(witness.amount2, witness.amount1)?;
        cs.mux_gate(
            witness.match_res.min_amount_order_index,
            max_minus_min1,
            max_minus_min2,
            witness.match_res.max_minus_min_amount, // out wire
        )?;

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be
        // computed correctly. I.e. the above constraint forces
        // `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) -
        // min(amounts)
        MultiproverGreaterThanEqZeroGadget::<AMOUNT_BITS>::constrain_greater_than_zero(
            witness.match_res.max_minus_min_amount,
            fabric,
            cs,
        )?;

        // 3. Constrain the executed base amount to be the minimum of the two order
        //    amounts
        // We use the identity
        //      min(a, b) = 1/2 * (a + b - [max(a, b) - min(a, b)])
        // Above we are given max(a, b) - min(a, b), so we can enforce the constraint
        //      2 * executed_amount = amount1 + amount2 - max_minus_min_amount
        let two = ScalarField::from(2u64);
        cs.lc_gate(
            &[
                witness.match_res.base_amount,
                witness.amount1,
                witness.amount2,
                witness.match_res.max_minus_min_amount,
                zero_var, // out wire
            ],
            &[two, -one, -one, one],
        )?;

        // The quote amount should then equal the price multiplied by the base amount
        let expected_quote_amount = witness
            .price1
            .mul_integer(witness.match_res.base_amount, cs)?;

        MultiproverFixedPointGadget::constrain_equal_integer_ignore_fraction(
            expected_quote_amount,
            witness.match_res.quote_amount,
            fabric,
            cs,
        )?;

        // --- Price Protection --- //
        Self::verify_price_protection(&witness.price1, &witness.order1, fabric, cs)?;
        Self::verify_price_protection(&witness.price2, &witness.order2, fabric, cs)
    }

    /// Check that a balance covers the advertised amount at a given price, and
    /// that the amount is less than the maximum amount allowed by the order
    pub fn validate_volume_constraints(
        match_res: &MatchResultVar,
        balance: &BalanceVar,
        order: &OrderVar,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError>
    where
        [(); AMOUNT_BITS + DEFAULT_FP_PRECISION]: Sized,
    {
        // Validate that the amount is less than the maximum amount given in the order
        MultiproverGreaterThanEqGadget::<AMOUNT_BITS /* bitlength */>::constrain_greater_than_eq(
            order.amount,
            match_res.base_amount,
            fabric,
            cs,
        )?;

        // Validate that the amount matched is covered by the balance
        // If the direction of the order is 0 (buy the base) then the balance must
        // cover the amount of the quote token sold in the swap
        // If the direction of the order is 1 (sell the base) then the balance must
        // cover the amount of the base token sold in the swap
        let amount_sold = CondSelectGadget::select(
            &match_res.base_amount,
            &match_res.quote_amount,
            order.side,
            cs,
        )?;
        MultiproverGreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            balance.amount,
            amount_sold,
            fabric,
            cs,
        )
    }

    /// Verify the price protection on the orders; i.e. that the executed price
    /// is not worse than some user-defined limit
    pub fn verify_price_protection(
        price: &FixedPointVar,
        order: &OrderVar,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        // If the order is buy side, verify that the execution price is less
        // than the limit price. If the order is sell side, verify that the
        // execution price is greater than the limit price
        let mut gte_terms = CondSelectVectorGadget::select(
            &[*price, order.worst_case_price],
            &[order.worst_case_price, *price],
            order.side,
            cs,
        )?;

        MultiproverGreaterThanEqGadget::<PRICE_BITS>::constrain_greater_than_eq(
            gte_terms.remove(0).repr,
            gte_terms.remove(0).repr,
            fabric,
            cs,
        )
    }
}

impl ValidMatchMpc {
    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    pub fn single_prover_circuit(
        witness: &ValidMatchMpcWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero = ScalarField::zero();
        let one = ScalarField::one();

        let zero_var = cs.zero();
        let one_var = cs.one();

        // --- Match Engine Input Validity --- //
        // Check that both orders are for the matched asset pair
        cs.enforce_equal(witness.order1.quote_mint, witness.match_res.quote_mint)?;
        cs.enforce_equal(witness.order1.base_mint, witness.match_res.base_mint)?;
        cs.enforce_equal(witness.order2.quote_mint, witness.match_res.quote_mint)?;
        cs.enforce_equal(witness.order2.base_mint, witness.match_res.base_mint)?;

        // Check that the prices supplied by the parties are equal, these should be
        // agreed upon outside of the circuit
        EqGadget::constrain_eq(&witness.price1, &witness.price2, cs)?;

        // Check that the balances supplied are for the correct mints; i.e. for the mint
        // that each party sells in the settlement
        let mut selected_mints = CondSelectVectorGadget::select(
            &[witness.match_res.base_mint, witness.match_res.quote_mint],
            &[witness.match_res.quote_mint, witness.match_res.base_mint],
            witness.match_res.direction,
            cs,
        )?;

        cs.enforce_equal(witness.balance1.mint, selected_mints.remove(0))?;
        cs.enforce_equal(witness.balance2.mint, selected_mints.remove(0))?;

        // Check that the max amount match supplied by both parties is covered by the
        // balance no greater than the amount specified in the order
        Self::validate_volume_constraints_single_prover(
            &witness.match_res,
            &witness.balance1,
            &witness.order1,
            cs,
        )?;

        Self::validate_volume_constraints_single_prover(
            &witness.match_res,
            &witness.balance2,
            &witness.order2,
            cs,
        )?;

        // --- Match Engine Execution Validity --- //
        // Check that the direction of the match is the same as the first party's
        // direction
        cs.enforce_equal(
            witness.match_res.direction.into(),
            witness.order1.side.into(),
        )?;

        // Check that the orders are on opposite sides of the market. It is assumed that
        // order sides are already constrained to be binary when they are
        // submitted. More broadly it is assumed that orders are well formed,
        // checking this amounts to checking their inclusion in the state tree,
        // which is done in `input_consistency_check`
        cs.lc_gate(
            &[
                witness.order1.side.into(),
                witness.order2.side.into(),
                one_var,
                one_var,
                zero_var,
            ],
            &[one, one, -one, zero],
        )?;

        // Check that the amount of base currency exchanged is equal to the minimum of
        // the two order's amounts

        // 1. Constrain the max_minus_min_amount to be correctly computed with respect
        //    to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = cs.sub(witness.amount1, witness.amount2)?;
        let max_minus_min2 = cs.sub(witness.amount2, witness.amount1)?;
        cs.mux_gate(
            witness.match_res.min_amount_order_index,
            max_minus_min1,
            max_minus_min2,
            witness.match_res.max_minus_min_amount, // out wire
        )?;

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be
        // computed correctly. I.e. the above constraint forces
        // `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) -
        // min(amounts)
        GreaterThanEqZeroGadget::<AMOUNT_BITS>::constrain_greater_than_zero(
            witness.match_res.max_minus_min_amount,
            cs,
        )?;

        // 3. Constrain the executed base amount to be the minimum of the two order
        //    amounts
        // We use the identity
        //      min(a, b) = 1/2 * (a + b - [max(a, b) - min(a, b)])
        // Above we are given max(a, b) - min(a, b), so we can enforce the constraint
        //      2 * executed_amount = amount1 + amount2 - max_minus_min_amount

        let two = ScalarField::from(2u64);
        cs.lc_gate(
            &[
                witness.match_res.base_amount,
                witness.amount1,
                witness.amount2,
                witness.match_res.max_minus_min_amount,
                zero_var, // output
            ],
            &[two, -one, -one, one],
        )?;

        // The quote amount should then equal the price multiplied by the base amount
        let expected_quote_amount = witness
            .price1
            .mul_integer(witness.match_res.base_amount, cs)?;
        FixedPointGadget::constrain_equal_integer_ignore_fraction(
            expected_quote_amount,
            witness.match_res.quote_amount,
            cs,
        )?;

        // --- Price Protection --- //
        Self::verify_price_protection_single_prover(&witness.price1, &witness.order1, cs)?;
        Self::verify_price_protection_single_prover(&witness.price2, &witness.order2, cs)
    }

    /// Check that a balance covers the advertised amount at a given price, and
    /// that the amount is less than the maximum amount allowed by the order
    pub fn validate_volume_constraints_single_prover(
        match_res: &MatchResultVar,
        balance: &BalanceVar,
        order: &OrderVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError>
    where
        [(); AMOUNT_BITS + DEFAULT_FP_PRECISION]: Sized,
    {
        // Validate that the amount is less than the maximum amount given in the order
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            order.amount,
            match_res.base_amount,
            cs,
        )?;

        // Validate that the amount matched is covered by the balance
        // If the direction of the order is 0 (buy the base) then the balance must
        // cover the amount of the quote token sold in the swap
        // If the direction of the order is 1 (sell the base) then the balance must
        // cover the amount of the base token sold in the swap
        let amount_sold = CondSelectGadget::select(
            &match_res.base_amount,
            &match_res.quote_amount,
            order.side,
            cs,
        )?;

        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            balance.amount,
            amount_sold,
            cs,
        )
    }

    /// Verify the price protection on the orders; i.e. that the executed price
    /// is not worse than some user-defined limit
    #[allow(unused)]
    pub fn verify_price_protection_single_prover(
        price: &FixedPointVar,
        order: &OrderVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // If the order is buy side, verify that the execution price is less
        // than the limit price. If the order is sell side, verify that the
        // execution price is greater than the limit price
        let mut gte_terms: Vec<FixedPointVar> = CondSelectVectorGadget::select(
            &[*price, order.worst_case_price],
            &[order.worst_case_price, *price],
            order.side,
            cs,
        )?;

        GreaterThanEqGadget::<PRICE_BITS>::constrain_greater_than_eq(
            gte_terms.remove(0).repr,
            gte_terms.remove(0).repr,
            cs,
        )
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The full witness, recovered by opening the witness commitment, but never
/// realized in the plaintext by either party
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidMatchMpcWitness {
    /// The first party's order
    pub order1: Order,
    /// The first party's balance
    pub balance1: Balance,
    /// The price that the first party agreed to execute at for their asset
    pub price1: FixedPoint,
    /// The maximum amount that the first party may match
    pub amount1: Scalar,
    /// The second party's order
    pub order2: Order,
    /// The second party's balance
    pub balance2: Balance,
    /// The price that the second party agreed to execute at for their asset
    pub price2: FixedPoint,
    /// The maximum amount that the second party may match
    pub amount2: Scalar,
    /// The result of running a match MPC on the given orders
    ///
    /// We do not open this value before proving so that we can avoid leaking
    /// information before the collaborative proof has finished
    pub match_res: MatchResult,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

/// Prover implementation of the Valid Match circuit
impl MultiProverCircuit for ValidMatchMpc {
    type Statement = ();
    type Witness = AuthenticatedValidMatchMpcWitness;
    type BaseCircuit = Self;

    fn apply_constraints_multiprover(
        witness: ValidMatchMpcWitnessVar,
        _statement: (),
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::multi_prover_circuit(&witness, fabric, cs).map_err(PlonkError::CircuitError)
    }
}

impl SingleProverCircuit for ValidMatchMpc {
    type Witness = ValidMatchMpcWitness;
    type Statement = ();

    fn apply_constraints(
        witness: ValidMatchMpcWitnessVar,
        _statement_var: (),
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        ValidMatchMpc::single_prover_circuit(&witness, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use ark_mpc::algebra::Scalar;
    use circuit_types::balance::Balance;

    use crate::test_helpers::random_orders_and_match;

    use super::ValidMatchMpcWitness;

    /// Create a dummy witness to match on
    pub fn create_dummy_witness() -> ValidMatchMpcWitness {
        let (o1, o2, price, match_res) = random_orders_and_match();

        // Build mock balances around the order

        // Buy side, buys the base selling the quote
        let b1 = Balance {
            mint: match_res.quote_mint.clone(),
            amount: match_res.quote_amount + 1,
        };

        // Sell side sells the base, buying the quote
        let b2 = Balance {
            mint: match_res.base_mint.clone(),
            amount: match_res.base_amount + 1,
        };

        let amount1 = Scalar::from(o1.amount);
        let amount2 = Scalar::from(o2.amount);
        ValidMatchMpcWitness {
            order1: o1,
            balance1: b1,
            price1: price,
            amount1,
            order2: o2,
            balance2: b2,
            price2: price,
            amount2,
            match_res,
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_mpc::PARTY0;
    use circuit_types::traits::MpcBaseType;

    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        multiprover_prove_and_verify,
        zk_circuits::valid_match_mpc::{test_helpers::create_dummy_witness, ValidMatchMpc},
    };

    /// Tests proving a valid match with a valid witness
    #[tokio::test]
    async fn prove_valid_witness() {
        let witness = create_dummy_witness();
        let (res, _) = execute_mock_mpc(move |fabric| {
            let witness = witness.clone();

            async move {
                let witness = witness.allocate(PARTY0, &fabric);
                multiprover_prove_and_verify::<ValidMatchMpc>(
                    witness,
                    (), // statement
                    fabric,
                )
                .await
            }
        })
        .await;

        assert!(res.is_ok())
    }
}
