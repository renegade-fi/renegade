//! Defines the VALID MATCH MPC circuit that proves knowledge of orders
//! which intersect to the given matches result
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.5
//! for a formal specification

use circuit_types::{
    balance::{AuthenticatedBalanceVar, BalanceVar, LinkableBalance},
    errors::ProverError,
    fixed_point::{AuthenticatedFixedPointVar, FixedPoint, FixedPointVar, DEFAULT_FP_PRECISION},
    order::{AuthenticatedOrderVar, LinkableOrder, OrderVar},
    r#match::{AuthenticatedMatchResultVar, LinkableMatchResult, MatchResultVar},
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
        MpcBaseType, MpcLinearCombinationLike, MpcType, MultiProverCircuit,
        MultiproverCircuitBaseType, MultiproverCircuitCommitmentType,
        MultiproverCircuitVariableType, SingleProverCircuit,
    },
    AMOUNT_BITS, PRICE_BITS,
};
use mpc_stark::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        authenticated_stark_point::AuthenticatedStarkPointOpenResult, scalar::Scalar,
        stark_curve::StarkPoint,
    },
    MpcFabric,
};

use crate::zk_gadgets::{
    comparators::{
        EqGadget, GreaterThanEqGadget, GreaterThanEqZeroGadget, MultiproverEqGadget,
        MultiproverGreaterThanEqGadget, MultiproverGreaterThanEqZeroGadget,
    },
    fixed_point::{FixedPointGadget, MultiproverFixedPointGadget},
    select::{
        CondSelectGadget, CondSelectVectorGadget, MultiproverCondSelectGadget,
        MultiproverCondSelectVectorGadget,
    },
};
use circuit_macros::circuit_type;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem, MpcVariable, R1CSError},
};
use rand::{CryptoRng, RngCore};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchMpcCircuit;
impl ValidMatchMpcCircuit {
    /// The order crossing check, verifies that the matches result is valid given the orders
    /// and balances of the two parties
    pub fn matching_engine_check<CS>(
        witness: AuthenticatedValidMatchMpcWitnessVar<MpcVariable>,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        CS: MpcRandomizableConstraintSystem,
    {
        // --- Match Engine Input Validity --- //
        // Check that both orders are for the matched asset pair
        cs.constrain(witness.order1.quote_mint.clone() - witness.match_res.quote_mint.clone());
        cs.constrain(witness.order1.base_mint.clone() - witness.match_res.base_mint.clone());
        cs.constrain(witness.order2.quote_mint.clone() - witness.match_res.quote_mint.clone());
        cs.constrain(witness.order2.base_mint.clone() - witness.match_res.base_mint.clone());

        // Check that the prices supplied by the parties are equal, these should be
        // agreed upon outside of the circuit
        MultiproverEqGadget::constrain_eq(witness.price1.clone(), witness.price2.clone(), cs);

        // Check that the balances supplied are for the correct mints; i.e. for the mint
        // that each party sells in the settlement
        let mut selected_mints =
            MultiproverCondSelectVectorGadget::select::<_, MpcLinearCombination, _>(
                &[
                    witness.match_res.base_mint.clone().into(),
                    witness.match_res.quote_mint.clone().into(),
                ],
                &[
                    witness.match_res.quote_mint.clone().into(),
                    witness.match_res.base_mint.clone().into(),
                ],
                witness.match_res.direction.clone(),
                fabric.clone(),
                cs,
            )?;

        cs.constrain(witness.balance1.mint.clone() - selected_mints.remove(0));
        cs.constrain(witness.balance2.mint.clone() - selected_mints.remove(0));

        // Check that the max amount match supplied by both parties is covered by the
        // balance no greater than the amount specified in the order
        Self::validate_volume_constraints(
            &witness.match_res,
            &witness.balance1,
            &witness.order1,
            fabric.clone(),
            cs,
        )?;

        Self::validate_volume_constraints(
            &witness.match_res,
            &witness.balance2,
            &witness.order2,
            fabric.clone(),
            cs,
        )?;

        // --- Match Engine Execution Validity --- //
        // Check that the direction of the match is the same as the first party's direction
        cs.constrain(witness.match_res.direction.clone() - witness.order1.side.clone());

        // Check that the orders are on opposite sides of the market. It is assumed that order
        // sides are already constrained to be binary when they are submitted. More broadly it
        // is assumed that orders are well formed, checking this amounts to checking their inclusion
        // in the state tree, which is done in `input_consistency_check`
        cs.constrain(
            &witness.order1.side + &witness.order2.side - MpcVariable::one(fabric.clone()),
        );

        // Constrain the min_amount_order_index to be binary
        // i.e. 0 === min_amount_order_index * (1 - min_amount_order_index)
        let (_, _, mul_out) = cs
            .multiply(
                &witness.match_res.min_amount_order_index.clone().into(),
                &(MpcLinearCombination::from_scalar(Scalar::one(), fabric.clone())
                    - &witness.match_res.min_amount_order_index),
            )
            .map_err(ProverError::Collaborative)?;
        cs.constrain(mul_out.into());

        // Check that the amount of base currency exchanged is equal to the minimum of the two
        // order's amounts

        // 1. Constrain the max_minus_min_amount to be correctly computed with respect to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = &witness.amount1 - &witness.amount2;
        let max_minus_min2 = &witness.amount2 - &witness.amount1;
        let max_minus_min_expected =
            MultiproverCondSelectGadget::select::<_, MpcLinearCombination, _>(
                max_minus_min1,
                max_minus_min2,
                witness.match_res.min_amount_order_index,
                fabric.clone(),
                cs,
            )?;
        cs.constrain(&max_minus_min_expected - &witness.match_res.max_minus_min_amount);

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be computed correctly.
        // I.e. the above constraint forces `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) - min(amounts)
        MultiproverGreaterThanEqZeroGadget::<AMOUNT_BITS>::constrain_greater_than_zero(
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
        let rhs = &witness.amount1 + &witness.amount2 - &witness.match_res.max_minus_min_amount;
        cs.constrain(lhs - rhs);

        // The quote amount should then equal the price multiplied by the base amount
        let expected_quote_amount = witness
            .price1
            .mul_integer(witness.match_res.base_amount.clone(), cs)
            .map_err(ProverError::Collaborative)?;

        MultiproverFixedPointGadget::constrain_equal_integer_ignore_fraction(
            &expected_quote_amount,
            &witness.match_res.quote_amount,
            fabric.clone(),
            cs,
        )?;

        // --- Price Protection --- //
        Self::verify_price_protection(&witness.price1, &witness.order1, fabric.clone(), cs)?;
        Self::verify_price_protection(&witness.price2, &witness.order2, fabric, cs)?;

        Ok(())
    }

    /// Check that a balance covers the advertised amount at a given price, and
    /// that the amount is less than the maximum amount allowed by the order
    pub fn validate_volume_constraints<CS: MpcRandomizableConstraintSystem>(
        match_res: &AuthenticatedMatchResultVar<MpcVariable>,
        balance: &AuthenticatedBalanceVar<MpcVariable>,
        order: &AuthenticatedOrderVar<MpcVariable>,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        [(); AMOUNT_BITS + DEFAULT_FP_PRECISION]: Sized,
    {
        // Validate that the amount is less than the maximum amount given in the order
        MultiproverGreaterThanEqGadget::<AMOUNT_BITS /* bitlength */>::constrain_greater_than_eq(
            order.amount.clone(),
            match_res.base_amount.clone(),
            fabric.clone(),
            cs,
        )?;

        // Validate that the amount matched is covered by the balance
        // If the direction of the order is 0 (buy the base) then the balance must
        // cover the amount of the quote token sold in the swap
        // If the direction of the order is 1 (sell the base) then the balance must
        // cover the amount of the base token sold in the swap
        let amount_sold = MultiproverCondSelectGadget::select::<_, MpcLinearCombination, _>(
            match_res.base_amount.clone().into(),
            match_res.quote_amount.clone().into(),
            order.side.clone(),
            fabric.clone(),
            cs,
        )?;
        MultiproverGreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            balance.amount.clone().into(),
            amount_sold,
            fabric,
            cs,
        )
    }

    /// Verify the price protection on the orders; i.e. that the executed price is not
    /// worse than some user-defined limit
    #[allow(unused)]
    pub fn verify_price_protection<CS: MpcRandomizableConstraintSystem>(
        price: &AuthenticatedFixedPointVar<MpcVariable>,
        order: &AuthenticatedOrderVar<MpcVariable>,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<(), ProverError> {
        // If the order is buy side, verify that the execution price is less
        // than the limit price. If the order is sell side, verify that the
        // execution price is greater than the limit price
        let mut gte_terms = MultiproverCondSelectVectorGadget::select(
            &[
                price.clone().to_lc(),
                order.worst_case_price.clone().to_lc(),
            ],
            &[
                order.worst_case_price.clone().to_lc(),
                price.clone().to_lc(),
            ],
            order.side.clone(),
            fabric.clone(),
            cs,
        )?;

        MultiproverGreaterThanEqGadget::<PRICE_BITS>::constrain_greater_than_eq(
            gte_terms.remove(0).repr,
            gte_terms.remove(0).repr,
            fabric,
            cs,
        );

        Ok(())
    }
}

pub struct ValidMatchMpcSingleProver;
impl ValidMatchMpcSingleProver {
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
        // --- Match Engine Input Validity --- //
        // Check that both orders are for the matched asset pair
        cs.constrain(witness.order1.quote_mint - witness.match_res.quote_mint);
        cs.constrain(witness.order1.base_mint - witness.match_res.base_mint);
        cs.constrain(witness.order2.quote_mint - witness.match_res.quote_mint);
        cs.constrain(witness.order2.base_mint - witness.match_res.base_mint);

        // Check that the prices supplied by the parties are equal, these should be
        // agreed upon outside of the circuit
        EqGadget::constrain_eq(witness.price1.clone(), witness.price2.clone(), cs);

        // Check that the balances supplied are for the correct mints; i.e. for the mint
        // that each party sells in the settlement
        let mut selected_mints =
            CondSelectVectorGadget::select::<_, _, Variable, LinearCombination, _>(
                &[witness.match_res.base_mint, witness.match_res.quote_mint],
                &[witness.match_res.quote_mint, witness.match_res.base_mint],
                witness.match_res.direction,
                cs,
            );

        cs.constrain(witness.balance1.mint - selected_mints.remove(0));
        cs.constrain(witness.balance2.mint - selected_mints.remove(0));

        // Check that the max amount match supplied by both parties is covered by the
        // balance no greater than the amount specified in the order
        Self::validate_volume_constraints_single_prover(
            &witness.match_res,
            &witness.balance1,
            &witness.order1,
            cs,
        );

        Self::validate_volume_constraints_single_prover(
            &witness.match_res,
            &witness.balance2,
            &witness.order2,
            cs,
        );

        // --- Match Engine Execution Validity --- //
        // Check that the direction of the match is the same as the first party's direction
        cs.constrain(witness.match_res.direction - witness.order1.side);

        // Check that the orders are on opposite sides of the market. It is assumed that order
        // sides are already constrained to be binary when they are submitted. More broadly it
        // is assumed that orders are well formed, checking this amounts to checking their inclusion
        // in the state tree, which is done in `input_consistency_check`
        cs.constrain(witness.order1.side + witness.order2.side - Variable::One());

        // Constrain the min_amount_order_index to be binary
        // i.e. 0 === min_amount_order_index * (1 - min_amount_order_index)
        let (_, _, mul_out) = cs.multiply(
            witness.match_res.min_amount_order_index.into(),
            Variable::One() - witness.match_res.min_amount_order_index,
        );
        cs.constrain(mul_out.into());

        // Check that the amount of base currency exchanged is equal to the minimum of the two
        // order's amounts

        // 1. Constrain the max_minus_min_amount to be correctly computed with respect to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = witness.amount1 - witness.amount2;
        let max_minus_min2 = witness.amount2 - witness.amount1;
        let max_minus_min_expected: LinearCombination = CondSelectGadget::select(
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
        GreaterThanEqZeroGadget::<AMOUNT_BITS>::constrain_greater_than_zero(
            witness.match_res.max_minus_min_amount,
            cs,
        );

        // 3. Constrain the executed base amount to be the minimum of the two order amounts
        // We use the identity
        //      min(a, b) = 1/2 * (a + b - [max(a, b) - min(a, b)])
        // Above we are given max(a, b) - min(a, b), so we can enforce the constraint
        //      2 * executed_amount = amount1 + amount2 - max_minus_min_amount
        let lhs = Scalar::from(2u64) * witness.match_res.base_amount;
        let rhs = witness.amount1 + witness.amount2 - witness.match_res.max_minus_min_amount;
        cs.constrain(lhs - rhs);

        // The quote amount should then equal the price multiplied by the base amount
        let expected_quote_amount = witness
            .price1
            .mul_integer(witness.match_res.base_amount, cs);
        FixedPointGadget::constrain_equal_integer_ignore_fraction(
            expected_quote_amount,
            witness.match_res.quote_amount,
            cs,
        );

        // --- Price Protection --- //
        Self::verify_price_protection_single_prover(&witness.price1, &witness.order1, cs);
        Self::verify_price_protection_single_prover(&witness.price2, &witness.order2, cs);

        Ok(())
    }

    /// Check that a balance covers the advertised amount at a given price, and
    /// that the amount is less than the maximum amount allowed by the order
    pub fn validate_volume_constraints_single_prover<CS: RandomizableConstraintSystem>(
        match_res: &MatchResultVar<Variable>,
        balance: &BalanceVar<Variable>,
        order: &OrderVar<Variable>,
        cs: &mut CS,
    ) where
        [(); AMOUNT_BITS + DEFAULT_FP_PRECISION]: Sized,
    {
        // Validate that the amount is less than the maximum amount given in the order
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            order.amount,
            match_res.base_amount,
            cs,
        );

        // Validate that the amount matched is covered by the balance
        // If the direction of the order is 0 (buy the base) then the balance must
        // cover the amount of the quote token sold in the swap
        // If the direction of the order is 1 (sell the base) then the balance must
        // cover the amount of the base token sold in the swap
        let amount_sold: LinearCombination = CondSelectGadget::select(
            match_res.base_amount,
            match_res.quote_amount,
            order.side,
            cs,
        );
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            balance.amount.into(),
            amount_sold,
            cs,
        );
    }

    /// Verify the price protection on the orders; i.e. that the executed price is not
    /// worse than some user-defined limit
    #[allow(unused)]
    pub fn verify_price_protection_single_prover<CS: RandomizableConstraintSystem>(
        price: &FixedPointVar<Variable>,
        order: &OrderVar<Variable>,
        cs: &mut CS,
    ) {
        // If the order is buy side, verify that the execution price is less
        // than the limit price. If the order is sell side, verify that the
        // execution price is greater than the limit price
        let mut gte_terms: Vec<FixedPointVar<LinearCombination>> = CondSelectVectorGadget::select(
            &[
                price.clone().to_lc(),
                order.worst_case_price.clone().to_lc(),
            ],
            &[
                order.worst_case_price.clone().to_lc(),
                price.clone().to_lc(),
            ],
            order.side,
            cs,
        );

        GreaterThanEqGadget::<PRICE_BITS>::constrain_greater_than_eq(
            gte_terms.remove(0).repr,
            gte_terms.remove(0).repr,
            cs,
        );
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The full witness, recovered by opening the witness commitment, but never realized in
/// the plaintext by either party
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidMatchMpcWitness {
    /// The first party's order
    pub order1: LinkableOrder,
    /// The first party's balance
    pub balance1: LinkableBalance,
    /// The price that the first party agreed to execute at for their asset
    pub price1: FixedPoint,
    /// The maximum amount that the first party may match
    pub amount1: Scalar,
    /// The second party's order
    pub order2: LinkableOrder,
    /// The second party's balance
    pub balance2: LinkableBalance,
    /// The price that the second party agreed to execute at for their asset
    pub price2: FixedPoint,
    /// The maximum amount that the second party may match
    pub amount2: Scalar,
    /// The result of running a match MPC on the given orders
    ///
    /// We do not open this value before proving so that we can avoid leaking information
    /// before the collaborative proof has finished
    pub match_res: LinkableMatchResult,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

/// Prover implementation of the Valid Match circuit
impl MultiProverCircuit for ValidMatchMpcCircuit {
    type Statement = ();
    type Witness = AuthenticatedValidMatchMpcWitness;

    const BP_GENS_CAPACITY: usize = 512;

    fn apply_constraints_multiprover<CS: MpcRandomizableConstraintSystem>(
        witness: <Self::Witness as MultiproverCircuitBaseType>::MultiproverVarType<MpcVariable>,
        _statement: <Self::Statement as MultiproverCircuitBaseType>::MultiproverVarType<
            MpcVariable,
        >,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<(), ProverError> {
        Self::matching_engine_check(witness, fabric, cs)
    }

    fn apply_constraints_singleprover<CS: RandomizableConstraintSystem>(
        witness:
                <<<Self::Witness as MultiproverCircuitBaseType>::MultiproverCommType
                    as MultiproverCircuitCommitmentType>::BaseCommitType
                    as CircuitCommitmentType>::VarType,
        statement:
                <<Self::Statement as MultiproverCircuitBaseType>::BaseType
                    as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        ValidMatchMpcSingleProver::apply_constraints(witness, statement, cs)
    }
}

impl SingleProverCircuit for ValidMatchMpcSingleProver {
    type Witness = ValidMatchMpcWitness;
    type Statement = ();

    const BP_GENS_CAPACITY: usize = 512;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        _statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        Self::matching_engine_check_single_prover(witness_var, cs)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        balance::Balance,
        fixed_point::FixedPoint,
        order::{Order, OrderSide},
        r#match::MatchResult,
        traits::{LinkableBaseType, MpcBaseType},
    };
    use mpc_stark::{algebra::scalar::Scalar, MpcFabric, PARTY0, PARTY1};
    use renegade_crypto::fields::scalar_to_u64;

    use crate::zk_circuits::valid_match_mpc::AuthenticatedValidMatchMpcWitness;

    /// Create a dummy witness to match on
    pub fn create_dummy_witness(fabric: &MpcFabric) -> AuthenticatedValidMatchMpcWitness {
        let min_amount = 5u64;
        let max_amount = 15u64;

        // Create two orders to match
        let order1 = Order {
            quote_mint: 1u8.into(),
            base_mint: 2u8.into(),
            side: OrderSide::Buy,
            worst_case_price: FixedPoint::from(15.),
            amount: min_amount,
            timestamp: 0,
        }
        .to_linkable();
        let balance1 = Balance {
            mint: 1u8.into(),
            amount: 300,
        }
        .to_linkable();

        let order2 = Order {
            quote_mint: 1u8.into(),
            base_mint: 2u8.into(),
            side: OrderSide::Sell,
            worst_case_price: FixedPoint::from(5.),
            amount: max_amount,
            timestamp: 0,
        }
        .to_linkable();
        let balance2 = Balance {
            mint: 2u8.into(),
            amount: 300,
        }
        .to_linkable();

        let price = FixedPoint::from(9.);

        // Match the orders directly
        let match_res = MatchResult {
            quote_mint: 1u8.into(),
            base_mint: 2u8.into(),
            quote_amount: scalar_to_u64(&(price * Scalar::from(order1.amount)).floor()),
            base_amount: min_amount,
            direction: 0,
            min_amount_order_index: 0,
            max_minus_min_amount: max_amount - min_amount,
        }
        .to_linkable();

        // Create a witness
        AuthenticatedValidMatchMpcWitness {
            order1: order1.allocate(PARTY0, fabric),
            order2: order2.allocate(PARTY0, fabric),
            balance1: balance1.allocate(PARTY0, fabric),
            balance2: balance2.allocate(PARTY0, fabric),
            price1: price.allocate(PARTY0, fabric),
            price2: price.allocate(PARTY0, fabric),
            amount1: order1.amount.val.allocate(PARTY0, fabric),
            amount2: order2.amount.val.allocate(PARTY1, fabric),
            match_res: match_res.allocate(PARTY0, fabric),
        }
    }
}

#[cfg(test)]
mod tests {
    use circuit_types::traits::{MultiProverCircuit, MultiproverCircuitCommitmentType};
    use merlin::HashChainTranscript;
    use mpc_bulletproof::{r1cs::Verifier, r1cs_mpc::MpcProver, PedersenGens};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::zk_circuits::valid_match_mpc::{
        test_helpers::create_dummy_witness, ValidMatchMpcCircuit,
    };

    /// Tests proving a valid match with a valid witness
    #[tokio::test]
    async fn prove_valid_witness() {
        // Execute an MPC to prove the match
        let ((witness_commitment, proof), _) = execute_mock_mpc(|fabric| async move {
            let witness = create_dummy_witness(&fabric);

            let (witness_commitment, proof) = {
                let pc_gens = PedersenGens::default();
                let transcript = HashChainTranscript::new(b"test");
                let prover = MpcProver::new_with_fabric(fabric.clone(), transcript, pc_gens);

                ValidMatchMpcCircuit::prove(
                    witness,
                    (), /* statement */
                    fabric.clone(),
                    prover,
                )
                .unwrap()
            }; // Let `prover` go out of scope as it is not `Send`

            (
                witness_commitment.open_and_authenticate().await.unwrap(),
                proof.open().await.unwrap(),
            )
        })
        .await;

        // Verify the proof
        let pc_gens = PedersenGens::default();
        let mut transcript = HashChainTranscript::new(b"test");
        let verifier = Verifier::new(&pc_gens, &mut transcript);

        ValidMatchMpcCircuit::verify(witness_commitment, () /* statement */, proof, verifier)
            .unwrap();
    }
}
