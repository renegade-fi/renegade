//! Defines the match-settle circuit which enforces validity of the matching
//! engine on two orders, and the settlement of the subsequent match into the
//! two traders' wallets
//!
//! Single and multiprover implementations are separated out for discoverability

pub mod multi_prover;
pub mod single_prover;

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::Order,
    r#match::MatchResult,
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType, MultiProverCircuit,
        MultiproverCircuitBaseType, SingleProverCircuit,
    },
    Fabric, MpcPlonkCircuit, PlonkCircuit,
};
use constants::{AuthenticatedScalar, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use circuit_macros::circuit_type;

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchSettle;
impl ValidMatchSettle {
    /// Applies the constraints of the match-settle circuit
    pub fn multiprover_circuit(
        witness: &ValidMatchSettleWitnessVar,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply the constraints of the match engine
        Self::validate_matching_engine(witness, fabric, cs)?;

        // Apply the constraints of the match settlement
        Self::validate_settlement(witness, (), fabric, cs)
    }

    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    pub fn singleprover_circuit(
        witness: &ValidMatchSettleWitnessVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply the constraints of the match engine
        Self::validate_matching_engine_singleprover(witness, cs)?;

        // Apply the constraints of the match settlement
        Self::validate_settlement_singleprover(witness, (), cs)
    }
}
// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The full witness, recovered by opening the witness commitment, but never
/// realized in the plaintext by either party
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidMatchSettleWitness {
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
impl MultiProverCircuit for ValidMatchSettle {
    type Statement = ();
    type Witness = AuthenticatedValidMatchSettleWitness;
    type BaseCircuit = Self;

    fn apply_constraints_multiprover(
        witness: ValidMatchSettleWitnessVar,
        _statement: (),
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::multiprover_circuit(&witness, fabric, cs).map_err(PlonkError::CircuitError)
    }
}

impl SingleProverCircuit for ValidMatchSettle {
    type Witness = ValidMatchSettleWitness;
    type Statement = ();

    fn apply_constraints(
        witness: ValidMatchSettleWitnessVar,
        _statement_var: (),
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        ValidMatchSettle::singleprover_circuit(&witness, cs).map_err(PlonkError::CircuitError)
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

    use super::ValidMatchSettleWitness;

    /// Create a dummy witness to match on
    pub fn create_dummy_witness() -> ValidMatchSettleWitness {
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
        ValidMatchSettleWitness {
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
        zk_circuits::valid_match_settle::{test_helpers::create_dummy_witness, ValidMatchSettle},
    };

    /// Tests proving a valid match with a valid witness
    #[tokio::test]
    async fn prove_valid_witness() {
        let witness = create_dummy_witness();
        let (res, _) = execute_mock_mpc(move |fabric| {
            let witness = witness.clone();

            async move {
                let witness = witness.allocate(PARTY0, &fabric);
                multiprover_prove_and_verify::<ValidMatchSettle>(
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
