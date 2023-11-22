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
    wallet::WalletShare,
    Fabric, MpcPlonkCircuit, PlonkCircuit,
};
use constants::{AuthenticatedScalar, Scalar, ScalarField, MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use circuit_macros::circuit_type;
use serde::{Deserialize, Serialize};

/// A circuit with default sizing parameters
pub type SizedValidMatchSettle = ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchSettle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Applies the constraints of the match-settle circuit
    pub fn multiprover_circuit(
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
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
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply the constraints of the match engine
        Self::validate_matching_engine_singleprover(witness, cs)?;

        // Apply the constraints of the match settlement
        Self::validate_settlement_singleprover(witness, (), cs)
    }
}

// -----------------------------------------
// | Witness and Statement Type Definition |
// -----------------------------------------

/// The full witness, recovered by opening the witness commitment, but never
/// realized in the plaintext by either party
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidMatchSettleWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
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
    /// The public shares of the first party before the match is settled
    pub party0_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public shares of the second party before the match is settled
    pub party1_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// A `VALID MATCH SETTLE` witness with default const generic sizing parameters
pub type SizedValidMatchSettleWitness = ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// The statement type for `VALID MATCH SETTLE`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The modified public secret shares of the first party
    pub party0_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares of the second party
    pub party1_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The index of the balance that the first party sent in the settlement
    pub party0_send_balance_index: u64,
    /// The index of teh balance that the first party received in the settlement
    pub party0_receive_balance_index: u64,
    /// The index of the first party's order that was matched
    pub party0_order_index: u64,
    /// The index of the balance that the second party sent in the settlement
    pub party1_send_balance_index: u64,
    /// The index of teh balance that the second party received in the
    /// settlement
    pub party1_receive_balance_index: u64,
    /// The index of the second party's order that was matched
    pub party1_order_index: u64,
}

/// A `VALID MATCH SETTLE` statement with default const generic sizing
/// parameters
pub type SizedValidSettleStatement = ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

// ---------------------
// | Prove Verify Flow |
// ---------------------

/// Prover implementation of the Valid Match circuit
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> MultiProverCircuit
    for ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Statement = ();
    type Witness = AuthenticatedValidMatchSettleWitness<MAX_ORDERS, MAX_BALANCES, MAX_FEES>;
    type BaseCircuit = Self;

    fn apply_constraints_multiprover(
        witness: ValidMatchSettleWitnessVar<MAX_ORDERS, MAX_BALANCES, MAX_FEES>,
        _statement: (),
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::multiprover_circuit(&witness, fabric, cs).map_err(PlonkError::CircuitError)
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidMatchSettle<MAX_ORDERS, MAX_BALANCES, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = ValidMatchSettleWitness<MAX_ORDERS, MAX_BALANCES, MAX_FEES>;
    type Statement = ();

    fn apply_constraints(
        witness: ValidMatchSettleWitnessVar<MAX_ORDERS, MAX_BALANCES, MAX_FEES>,
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
    use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS};

    use crate::test_helpers::random_orders_and_match;

    use super::ValidMatchSettleWitness;

    /// A witness with with default sizing parameters attached
    pub type SizedValidMatchSettleWitness =
        ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    /// Create a dummy witness to match on
    pub fn create_dummy_witness() -> SizedValidMatchSettleWitness {
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
