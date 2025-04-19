//! Defines the match-settle circuit which enforces validity of the matching
//! engine on two orders, and the settlement of the subsequent match into the
//! two traders' wallets
//!
//! Single and multiprover implementations are separated out for discoverability

pub mod multi_prover;
pub mod single_prover;

use circuit_types::{
    balance::Balance,
    fees::FeeTake,
    fixed_point::FixedPoint,
    order::Order,
    r#match::{MatchResult, OrderSettlementIndices},
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType, MultiProverCircuit,
        MultiproverCircuitBaseType, SingleProverCircuit,
    },
    wallet::{WalletShare, WalletShareStateCommitment},
    Fabric, MpcPlonkCircuit, PlonkCircuit,
};
use constants::{AuthenticatedScalar, Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{
    errors::CircuitError,
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
    Variable,
};

use circuit_macros::circuit_type;
use serde::{Deserialize, Serialize};

use crate::zk_gadgets::wallet_operations::WalletGadget;

use super::{VALID_COMMITMENTS_MATCH_SETTLE_LINK0, VALID_COMMITMENTS_MATCH_SETTLE_LINK1};

/// A circuit with default sizing parameters
pub type SizedValidMatchSettle = ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>;

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchSettle<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// Applies the constraints of the match-settle circuit
    pub fn multiprover_circuit(
        statement: &ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply the constraints of the match engine
        Self::validate_matching_engine(witness, fabric, cs)?;

        // Apply the constraints of the match settlement
        Self::validate_settlement(statement, witness, fabric, cs)
    }

    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    pub fn singleprover_circuit(
        statement: &ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply the constraints of the match engine
        Self::validate_matching_engine_singleprover(witness, cs)?;

        // Apply the constraints of the match settlement
        Self::validate_settlement_singleprover(statement, witness, cs)
    }
}

/// A `VALID MATCH SETTLE` circuit in which we also compute the commitment to
/// the new wallet's shared in-circuit
///
/// This removes the need for the contract to hash the public commitment, which
/// is a significant cost
///
/// We only use this for internal matches, as the cost of computing the
/// commitment in a multiprover circuit outweighs the gains from removing this
/// computation in the contract
#[derive(Clone, Debug)]
pub struct ValidMatchSettleWithCommitment<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
    ValidMatchSettleWithCommitment<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    fn singleprover_circuit(
        statement: &ValidMatchSettleWithCommitmentStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply the constraints of the match engine
        ValidMatchSettle::validate_matching_engine_singleprover(witness, cs)?;
        // Apply the constraints of the match settlement
        let match_settle_statement = ValidMatchSettleStatementVar {
            party0_indices: statement.party0_indices.clone(),
            party1_indices: statement.party1_indices.clone(),
            party0_modified_shares: statement.party0_modified_shares.clone(),
            party1_modified_shares: statement.party1_modified_shares.clone(),
            protocol_fee: statement.protocol_fee,
        };
        ValidMatchSettle::validate_settlement_singleprover(&match_settle_statement, witness, cs)?;

        // Check the commitments to the new wallets shares are correct
        let party0_commitment = WalletGadget::compute_wallet_commitment_from_private(
            &statement.party0_modified_shares,
            statement.private_share_commitment0,
            cs,
        )?;
        cs.enforce_equal(party0_commitment, statement.new_share_commitment0)?;

        let party1_commitment = WalletGadget::compute_wallet_commitment_from_private(
            &statement.party1_modified_shares,
            statement.private_share_commitment1,
            cs,
        )?;
        cs.enforce_equal(party1_commitment, statement.new_share_commitment1)?;

        Ok(())
    }
}

// -----------------------------------------
// | Witness and Statement Type Definition |
// -----------------------------------------

/// The full witness, recovered by opening the witness commitment, but never
/// realized in the plaintext by either party
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidMatchSettleWitness<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The first party's order
    #[link_groups = "valid_commitments_match_settle0"]
    pub order0: Order,
    /// The first party's balance
    #[link_groups = "valid_commitments_match_settle0"]
    pub balance0: Balance,
    /// The first party's receive balance
    #[link_groups = "valid_commitments_match_settle0"]
    pub balance_receive0: Balance,
    /// The first party's managing relayer fee
    #[link_groups = "valid_commitments_match_settle0"]
    pub relayer_fee0: FixedPoint,
    /// The first party's fee obligations as a result of the match
    pub party0_fees: FeeTake,
    /// The price that the first party agreed to execute at for their asset
    pub price0: FixedPoint,
    /// The maximum amount that the first party may match
    pub amount0: Scalar,
    /// The second party's order
    #[link_groups = "valid_commitments_match_settle1"]
    pub order1: Order,
    /// The second party's balance
    #[link_groups = "valid_commitments_match_settle1"]
    pub balance1: Balance,
    /// The second party's receive balance
    #[link_groups = "valid_commitments_match_settle1"]
    pub balance_receive1: Balance,
    /// The second party's managing relayer fee
    #[link_groups = "valid_commitments_match_settle1"]
    pub relayer_fee1: FixedPoint,
    /// The second party's fee obligations as a result of the match
    pub party1_fees: FeeTake,
    /// The price that the second party agreed to execute at for their asset
    pub price1: FixedPoint,
    /// The maximum amount that the second party may match
    pub amount1: Scalar,
    /// The result of running a match MPC on the given orders
    ///
    /// We do not open this value before proving so that we can avoid leaking
    /// information before the collaborative proof has finished
    pub match_res: MatchResult,
    /// The public shares of the first party before the match is settled
    #[link_groups = "valid_commitments_match_settle0"]
    pub party0_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The public shares of the second party before the match is settled
    #[link_groups = "valid_commitments_match_settle1"]
    pub party1_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
}

/// A `VALID MATCH SETTLE` witness with default const generic sizing parameters
pub type SizedValidMatchSettleWitness = ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>;
/// An authenticated `VALID MATCH SETTLE` witness with default const generic
/// sizing parameters
pub type SizedAuthenticatedMatchSettleWitness =
    AuthenticatedValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>;

/// The statement type for `VALID MATCH SETTLE`
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleStatement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The modified public secret shares of the first party
    pub party0_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The modified public secret shares of the second party
    pub party1_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The indices that settlement should modify in the first party's wallet
    pub party0_indices: OrderSettlementIndices,
    /// The indices that settlement should modify in the second party's wallet
    pub party1_indices: OrderSettlementIndices,
    /// The protocol fee used in the match
    pub protocol_fee: FixedPoint,
}

/// A `VALID MATCH SETTLE` statement including the commitment to the new
/// wallet's private shares computed in `VALID REBLIND`
///
/// This is only used for the `VALID MATCH SETTLE WITH COMMITMENTS` statement
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleWithCommitmentStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The commitment to the first party's new wallet's private shares
    ///
    /// This is placed in the statement to allow a verifier to check this value
    /// against the value generated by a proof of `VALID REBLIND`
    pub private_share_commitment0: WalletShareStateCommitment,
    /// The commitment to the second party's new wallet's private shares
    ///
    /// This is placed in the statement to allow a verifier to check this value
    /// against the value generated by a proof of `VALID REBLIND`
    pub private_share_commitment1: WalletShareStateCommitment,
    /// The commitment to the first party's new wallet shares
    pub new_share_commitment0: WalletShareStateCommitment,
    /// The commitment to the second party's new wallet shares
    pub new_share_commitment1: WalletShareStateCommitment,
    /// The modified public secret shares of the first party
    pub party0_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The modified public secret shares of the second party
    pub party1_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The indices that settlement should modify in the first party's wallet
    pub party0_indices: OrderSettlementIndices,
    /// The indices that settlement should modify in the second party's wallet
    pub party1_indices: OrderSettlementIndices,
    /// The protocol fee used in the match
    pub protocol_fee: FixedPoint,
}

/// A `VALID MATCH SETTLE` statement with default const generic sizing
/// parameters
pub type SizedValidMatchSettleStatement = ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>;
/// An authenticated `VALID MATCH SETTLE` statement with default const generic
/// sizing parameters
pub type SizedAuthenticatedMatchSettleStatement =
    AuthenticatedValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>;
/// A `VALID MATCH SETTLE WITH COMMITMENTS` statement with default const
/// generic sizing parameters
pub type SizedValidMatchSettleWithCommitmentStatement =
    ValidMatchSettleWithCommitmentStatement<MAX_BALANCES, MAX_ORDERS>;

// ---------------------
// | Prove Verify Flow |
// ---------------------

/// Prover implementation of the Valid Match circuit
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> MultiProverCircuit
    for ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Witness = AuthenticatedValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>;
    type Statement = AuthenticatedValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>;
    type BaseCircuit = Self;

    fn apply_constraints_multiprover(
        witness: ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement: ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS>,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::multiprover_circuit(&statement, &witness, fabric, cs)
            .map_err(PlonkError::CircuitError)
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Witness = ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>;
    type Statement = ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("Valid Match Settle ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    /// VALID MATCH SETTLE places the two groups that it shares with VALID
    /// COMMITMENTS
    ///
    /// Note: VALID MATCH SETTLE places these groups because it has a larger
    /// statement. If VALID COMMITMENTS were to place this group, VALID MATCH
    /// SETTLE would not be able to inherit it -- it would overlap with public
    /// inputs
    ///
    /// Ideally we would fix this by exposing a `min_offset` or similar, but for
    /// now we simply have VALID MATCH SETTLE place the group
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        Ok(vec![
            (VALID_COMMITMENTS_MATCH_SETTLE_LINK0.to_string(), None),
            (VALID_COMMITMENTS_MATCH_SETTLE_LINK1.to_string(), None),
        ])
    }

    fn apply_constraints(
        witness: ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement: ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        ValidMatchSettle::singleprover_circuit(&statement, &witness, cs)
            .map_err(PlonkError::CircuitError)
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidMatchSettleWithCommitment<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Witness = ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>;
    type Statement = ValidMatchSettleWithCommitmentStatement<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("Valid Match Settle With Commitments ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    /// Same proof linking groups as `VALID MATCH SETTLE`
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        <ValidMatchSettle<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::proof_linking_groups()
    }

    fn apply_constraints(
        witness: ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement: ValidMatchSettleWithCommitmentStatementVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        ValidMatchSettleWithCommitment::singleprover_circuit(&statement, &witness, cs)
            .map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        balance::Balance,
        native_helpers::compute_wallet_commitment_from_private,
        order::{Order, OrderSide},
        r#match::{MatchResult, OrderSettlementIndices},
        wallet::Wallet,
    };
    use constants::Scalar;
    use rand::{distributions::uniform::SampleRange, thread_rng, RngCore};
    use util::{
        matching_engine::{apply_match_to_shares, compute_fee_obligation},
        on_chain::get_protocol_fee,
    };

    use crate::{
        test_helpers::random_orders_and_match,
        zk_circuits::test_helpers::{
            create_wallet_shares, INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS,
        },
    };

    use super::{
        ValidMatchSettle, ValidMatchSettleStatement, ValidMatchSettleWithCommitmentStatement,
        ValidMatchSettleWitness,
    };

    /// A match settle circuit with default sizing parameters
    pub type SizedValidMatchSettle = ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>;
    /// A witness with default sizing parameters attached
    pub type SizedValidMatchSettleWitness = ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>;
    /// A statement with default sizing parameters attached
    pub type SizedValidMatchSettleStatement = ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>;

    /// Convert a statement of `VALID MATCH SETTLE` to a statement of
    /// `VALID MATCH SETTLE WITH COMMITMENTS`
    pub fn convert_statement_to_commitments<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        statement: ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>,
    ) -> ValidMatchSettleWithCommitmentStatement<MAX_BALANCES, MAX_ORDERS>
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let mut rng = thread_rng();
        let private_comm0 = Scalar::random(&mut rng);
        let private_comm1 = Scalar::random(&mut rng);
        let public_shares0 = &statement.party0_modified_shares;
        let public_shares1 = &statement.party1_modified_shares;
        let share_comm0 = compute_wallet_commitment_from_private(public_shares0, private_comm0);
        let share_comm1 = compute_wallet_commitment_from_private(public_shares1, private_comm1);

        ValidMatchSettleWithCommitmentStatement {
            private_share_commitment0: private_comm0,
            private_share_commitment1: private_comm1,
            new_share_commitment0: share_comm0,
            new_share_commitment1: share_comm1,
            party0_modified_shares: statement.party0_modified_shares,
            party1_modified_shares: statement.party1_modified_shares,
            party0_indices: statement.party0_indices,
            party1_indices: statement.party1_indices,
            protocol_fee: statement.protocol_fee,
        }
    }

    /// Create a dummy witness and statement with commitments
    pub fn dummy_witness_and_statement_with_commitments<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >() -> (
        ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMatchSettleWithCommitmentStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let (witness, base_statement) = dummy_witness_and_statement::<MAX_BALANCES, MAX_ORDERS>();
        let statement = convert_statement_to_commitments(base_statement);
        (witness, statement)
    }

    /// Create a dummy witness to match on
    pub fn dummy_witness_and_statement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>() -> (
        ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let (o1, o2, price, match_res) = random_orders_and_match();

        // Build wallets for the crossing orders
        let (wallet1, party0_indices) = build_wallet_and_indices_from_order(&o1, &match_res);
        let (wallet2, party1_indices) = build_wallet_and_indices_from_order(&o2, &match_res);
        let (_, party0_public_shares) = create_wallet_shares(&wallet1);
        let (_, party1_public_shares) = create_wallet_shares(&wallet2);

        // Compute the fee obligations of both parties
        let party0_fees = compute_fee_obligation(wallet1.max_match_fee, o1.side, &match_res);
        let party1_fees = compute_fee_obligation(wallet2.max_match_fee, o2.side, &match_res);

        // Update the wallets
        let mut party0_modified_shares = party0_public_shares.clone();
        apply_match_to_shares(
            &mut party0_modified_shares,
            &party0_indices,
            party0_fees,
            &match_res,
            o1.side,
        );

        let mut party1_modified_shares = party1_public_shares.clone();
        apply_match_to_shares(
            &mut party1_modified_shares,
            &party1_indices,
            party1_fees,
            &match_res,
            o2.side,
        );

        let amount0 = Scalar::from(o1.amount);
        let amount1 = Scalar::from(o2.amount);

        (
            ValidMatchSettleWitness {
                order0: o1,
                balance0: wallet1.balances[party0_indices.balance_send].clone(),
                balance_receive0: wallet1.balances[party0_indices.balance_receive].clone(),
                relayer_fee0: wallet1.max_match_fee,
                price0: price,
                party0_fees,
                amount0,
                order1: o2,
                balance1: wallet2.balances[party1_indices.balance_send].clone(),
                balance_receive1: wallet2.balances[party1_indices.balance_receive].clone(),
                relayer_fee1: wallet2.max_match_fee,
                price1: price,
                party1_fees,
                amount1,
                match_res,
                party0_public_shares,
                party1_public_shares,
            },
            ValidMatchSettleStatement {
                party0_indices,
                party1_indices,
                party0_modified_shares,
                party1_modified_shares,
                protocol_fee: get_protocol_fee(),
            },
        )
    }

    // Build two wallets and sample indices for the orders and balances for the
    // match to be placed into
    pub fn build_wallet_and_indices_from_order<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        order: &Order,
        match_res: &MatchResult,
    ) -> (Wallet<MAX_BALANCES, MAX_ORDERS>, OrderSettlementIndices)
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let mut wallet = Wallet {
            keys: INITIAL_WALLET.keys.clone(),
            max_match_fee: INITIAL_WALLET.max_match_fee,
            managing_cluster: INITIAL_WALLET.managing_cluster,
            ..Default::default()
        };

        let mut rng = thread_rng();
        let send = (0..MAX_BALANCES).sample_single(&mut rng);
        let mut recv = (0..MAX_BALANCES).sample_single(&mut rng);
        while recv == send {
            recv = (0..MAX_BALANCES).sample_single(&mut rng);
        }

        let order_ind = (0..MAX_ORDERS).sample_single(&mut rng);

        // Insert the order and balances into the wallet
        wallet.orders[order_ind] = order.clone();
        wallet.balances[send] = send_balance(order, match_res);
        wallet.balances[recv] = receive_balance(order);

        (
            wallet,
            OrderSettlementIndices { balance_send: send, balance_receive: recv, order: order_ind },
        )
    }

    /// Build a send balance given an order
    ///
    /// This builds a balance that fully capitalizes the position the order
    /// represents
    fn send_balance(order: &Order, match_res: &MatchResult) -> Balance {
        let (mint, amount) = match order.side {
            // Buy the base sell the quote
            OrderSide::Buy => (order.quote_mint.clone(), match_res.quote_amount + 1),
            // Sell the base buy the quote
            OrderSide::Sell => (order.base_mint.clone(), match_res.base_amount + 1),
        };

        Balance::new_from_mint_and_amount(mint, amount)
    }

    /// Build a receive balance given an order
    ///
    /// This gives a random initial balance to the order
    fn receive_balance(order: &Order) -> Balance {
        let mut rng = thread_rng();
        let mint = match order.side {
            // Buy the base sell the quote
            OrderSide::Buy => order.base_mint.clone(),
            // Sell the base buy the quote
            OrderSide::Sell => order.quote_mint.clone(),
        };

        Balance::new_from_mint_and_amount(mint, rng.next_u32() as u128)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use ark_mpc::PARTY0;
    use circuit_types::{
        fixed_point::FixedPoint,
        traits::{MpcBaseType, SingleProverCircuit},
        AMOUNT_BITS,
    };

    use constants::Scalar;
    use rand::{thread_rng, Rng};
    use renegade_crypto::fields::scalar_to_u128;
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        multiprover_prove_and_verify, singleprover_prove_and_verify,
        zk_circuits::{
            check_constraint_satisfaction,
            test_helpers::{MAX_BALANCES, MAX_ORDERS},
            valid_match_settle::{
                test_helpers::{dummy_witness_and_statement, SizedValidMatchSettle},
                ValidMatchSettle, ValidMatchSettleWithCommitment,
            },
        },
    };

    use super::{
        test_helpers::{
            convert_statement_to_commitments, dummy_witness_and_statement_with_commitments,
        },
        ValidMatchSettleStatement, ValidMatchSettleWithCommitmentStatement,
        ValidMatchSettleWitness,
    };

    // -----------
    // | Helpers |
    // -----------

    /// A witness with test sizing parameters attached
    type TestValidMatchSettleWitness = ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS>;
    /// A statement with test sizing parameters attached
    type TestValidMatchSettleStatement = ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>;
    /// A statement with test sizing parameters attached
    type TestValidMatchSettleWithCommitmentStatement =
        ValidMatchSettleWithCommitmentStatement<MAX_BALANCES, MAX_ORDERS>;
    /// A `VALID MATCH SETTLE WITH COMMITMENTS` circuit with test sizing
    /// parameters attached
    type TestValidMatchSettleWithCommitment =
        ValidMatchSettleWithCommitment<MAX_BALANCES, MAX_ORDERS>;
    /// A `VALID MATCH SETTLE` circuit with test sizing parameters attached
    type TestValidMatchSettle = ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>;

    /// Gets a scalar representing the maximum amount of a balance
    fn max_amount_scalar() -> Scalar {
        Scalar::from(2u8).pow(AMOUNT_BITS as u64) - Scalar::one()
    }

    /// Assert that a witness and statement are valid on both `VALID MATCH
    /// SETTLE` and `VALID MATCH SETTLE WITH COMMITMENTS` circuits
    fn assert_valid_witness_statement(
        witness: &TestValidMatchSettleWitness,
        statement: &TestValidMatchSettleStatement,
    ) {
        let (res1, res2) = check_witness_statement(witness, statement);
        assert!(res1 && res2);
    }

    /// Assert that a witness and statement are valid on both `VALID MATCH
    /// SETTLE` and `VALID MATCH SETTLE WITH COMMITMENTS` circuits
    fn assert_invalid_witness_statement(
        witness: &TestValidMatchSettleWitness,
        statement: &TestValidMatchSettleStatement,
    ) {
        let (res1, res2) = check_witness_statement(witness, statement);
        assert!(!res1 && !res2);
    }

    /// Check the witness and statement on both `VALID MATCH SETTLE` and
    /// `VALID MATCH SETTLE WITH COMMITMENTS` circuits
    fn check_witness_statement(
        witness: &TestValidMatchSettleWitness,
        statement: &TestValidMatchSettleStatement,
    ) -> (bool, bool) {
        let statement_with_commitments = convert_statement_to_commitments(statement.clone());
        let valid_match_settle_res = check_witness_statement_basic(witness, statement);
        let valid_match_settle_with_commitments_res =
            check_witness_statement_with_commitments(witness, &statement_with_commitments);

        (valid_match_settle_res, valid_match_settle_with_commitments_res)
    }

    /// Check the witness and statement on the `VALID MATCH SETTLE` circuit
    fn check_witness_statement_basic(
        witness: &TestValidMatchSettleWitness,
        statement: &TestValidMatchSettleStatement,
    ) -> bool {
        check_constraint_satisfaction::<TestValidMatchSettle>(witness, statement)
    }

    /// Check the witness and statement on the `VALID MATCH SETTLE WITH
    /// COMMITMENTS` circuit
    fn check_witness_statement_with_commitments(
        witness: &TestValidMatchSettleWitness,
        statement: &TestValidMatchSettleWithCommitmentStatement,
    ) -> bool {
        check_constraint_satisfaction::<TestValidMatchSettleWithCommitment>(witness, statement)
    }

    // ------------------------
    // | Circuit Size Helpers |
    // ------------------------

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    #[ignore]
    fn test_n_constraints() {
        let layout = ValidMatchSettle::<
            { constants::MAX_BALANCES },
            { constants::MAX_ORDERS },
        >::get_circuit_layout()
        .unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// A helper to print the number of constraints in the settle with
    /// commitments circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    #[ignore]
    fn test_n_constraints_with_commitments() {
        let layout = ValidMatchSettleWithCommitment::<
            { constants::MAX_BALANCES },
            { constants::MAX_ORDERS },
        >::get_circuit_layout()
        .unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    // -----------------------
    // | Valid Witness Tests |
    // -----------------------

    /// Tests proving a valid match with a valid witness
    #[tokio::test]
    async fn prove_valid_witness() {
        let (witness, statement) = dummy_witness_and_statement();
        let (res, _) = execute_mock_mpc(move |fabric| {
            let witness = witness.clone();
            let statement = statement.clone();

            async move {
                let witness = witness.allocate(PARTY0, &fabric);
                let statement = statement.allocate(PARTY0, &fabric);

                multiprover_prove_and_verify::<SizedValidMatchSettle>(witness, statement, fabric)
                    .await
            }
        })
        .await;

        assert!(res.is_ok())
    }

    /// Tests proving a valid match on the singleprover circuit
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_valid_match__singleprover() {
        let (witness, statement) = dummy_witness_and_statement();

        singleprover_prove_and_verify::<SizedValidMatchSettle>(witness, statement)
            .expect("failed to prove and verify");
    }

    /// Tests a valid witness and statement on the `VALID MATCH SETTLE WITH
    /// COMMITMENTS` circuit
    #[test]
    fn test_valid_match__singleprover_with_commitments() {
        let (witness, statement) = dummy_witness_and_statement();
        assert_valid_witness_statement(&witness, &statement);
    }

    // ---------------
    // | Match Tests |
    // ---------------

    /// Randomly perform one of two operation
    macro_rules! rand_branch {
        ($x:expr, $y:expr) => {
            if rand::thread_rng().gen_bool(0.5) {
                $x;
            } else {
                $y;
            }
        };
    }

    /// Test the case in which the two parties attempt to match on different
    /// mints
    #[test]
    fn test_valid_match__different_mints() {
        let (original_witness, statement) = dummy_witness_and_statement();

        // One party switches the quote mint of their order
        let mut witness = original_witness.clone();
        rand_branch!(witness.order0.quote_mint += 1u8, witness.order1.quote_mint += 1u8);

        // Validate that the constraints are not satisfied
        assert_invalid_witness_statement(&witness, &statement);

        // Now test with base mint switched
        let mut witness = original_witness;
        rand_branch!(witness.order0.base_mint += 1u8, witness.order1.base_mint += 1u8);
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which the parties sit on the same side of the book
    #[test]
    fn test_valid_match__same_side() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Swap the sides of one of the orders
        rand_branch!(
            witness.order0.side = witness.order0.side.opposite(),
            witness.order1.side = witness.order1.side.opposite()
        );
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which the match direction is incorrectly set by the
    /// prover
    #[test]
    fn test_valid_match__incorrect_direction() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Invert the match direction
        witness.match_res.direction = !witness.match_res.direction;
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which parties attempt to match on different prices
    #[test]
    fn test_valid_match__different_prices() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Change the price of one of the orders
        let one = Scalar::one();
        rand_branch!(witness.price0 = witness.price0 + one, witness.price1 = witness.price1 + one);
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which a prover advertises an amount outside the valid
    /// amount range
    #[test]
    fn test_valid_match__invalid_amount() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Set the amount to be greater than the maximum
        rand_branch!(
            witness.amount0 = max_amount_scalar() + Scalar::one(),
            witness.amount1 = max_amount_scalar() + Scalar::one()
        );
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests the case in which the base amount is incorrect
    #[test]
    fn test_valid_match__incorrect_base_amount() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Modify the base amount
        witness.match_res.base_amount -= 1;
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests the case in which the quote amount is incorrect
    #[test]
    fn test_valid_match__incorrect_quote_amount() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Modify the quote amount
        witness.match_res.quote_amount -= 1;
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which the balance provided does not cover the
    /// advertised amount
    #[test]
    fn test_valid_match__insufficient_balance() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Reduce the balance to be less than the amount matched
        rand_branch!(witness.balance0.amount = 1, witness.balance1.amount = 1);
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which the matched amount exceeds the order size for a
    /// party
    #[test]
    fn test_valid_match__amount_exceeds_order() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Place one party's order amount below the min amount
        rand_branch!(
            witness.order0.amount = witness.match_res.base_amount - 1,
            witness.order1.amount = witness.match_res.base_amount - 1
        );

        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which the `min_amount_order_index` field is incorrectly
    /// computed
    #[test]
    fn test_valid_match__incorrect_min_amount_order_index() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Invert the index
        witness.match_res.min_amount_order_index = !witness.match_res.min_amount_order_index;
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which the execution price exceeds the buy side price
    /// protection
    #[test]
    fn test_valid_match__price_protection_violated_buy_side() {
        let (mut witness, statement) = dummy_witness_and_statement();
        let execution_price =
            (witness.match_res.quote_amount as f64) / (witness.match_res.base_amount as f64);

        // Move the worst case price of the buy side order down
        let new_price = FixedPoint::from_f64_round_down(execution_price - 1.);
        if witness.order0.side.is_buy() {
            witness.order0.worst_case_price = new_price;
        } else {
            witness.order1.worst_case_price = new_price;
        }

        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which the execution price falls sort of the sell
    /// side price protection
    #[test]
    fn test_valid_match__price_protection_violated_sell_side() {
        let (mut witness, statement) = dummy_witness_and_statement();
        let execution_price =
            (witness.match_res.quote_amount as f64) / (witness.match_res.base_amount as f64);

        // Move the worst case price of the sell side order up
        let new_price = FixedPoint::from_f64_round_down(execution_price + 1.);
        if witness.order0.side.is_sell() {
            witness.order0.worst_case_price = new_price;
        } else {
            witness.order1.worst_case_price = new_price;
        }

        assert_invalid_witness_statement(&witness, &statement);
    }

    // --------------------
    // | Settlement Tests |
    // --------------------

    /// Tests the case in which a settlement would push the balance over the
    /// valid range
    #[test]
    fn test_invalid_settle__balance_overflow() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Set the balance to be the maximum
        let initial_bal = scalar_to_u128(&max_amount_scalar());
        rand_branch!(
            witness.balance_receive0.amount = initial_bal,
            witness.balance_receive1.amount = initial_bal
        );
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests the case in which a settlement overflows the relayer fee balance
    #[test]
    fn test_invalid_settle__relayer_fee_overflow() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Set the relayer fee balance to be the maximum
        let initial_bal = scalar_to_u128(&max_amount_scalar());
        rand_branch!(
            witness.balance_receive0.relayer_fee_balance = initial_bal,
            witness.balance_receive1.relayer_fee_balance = initial_bal
        );
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests the case in which a settlement overflows the protocol fee balance
    #[test]
    fn test_invalid_settle__protocol_fee_overflow() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Set the protocol fee balance to be the maximum
        let initial_bal = scalar_to_u128(&max_amount_scalar());
        rand_branch!(
            witness.balance_receive0.protocol_fee_balance = initial_bal,
            witness.balance_receive1.protocol_fee_balance = initial_bal
        );
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests the case in which an incorrect balance index is given
    #[test]
    fn test_invalid_settle__invalid_balance_index() {
        let (witness, original_statement) = dummy_witness_and_statement();

        // Party 0 send balance corrupted
        let mut statement = original_statement.clone();
        statement.party0_indices.balance_send += 1;
        assert_invalid_witness_statement(&witness, &statement);

        // Party 0 receive balance corrupted
        let mut statement = original_statement.clone();
        statement.party0_indices.balance_receive += 1;
        assert_invalid_witness_statement(&witness, &statement);

        // Party 1 send balance corrupted
        let mut statement = original_statement.clone();
        statement.party1_indices.balance_send += 1;
        assert_invalid_witness_statement(&witness, &statement);

        // Party 1 receive balance corrupted
        let mut statement = original_statement;
        statement.party1_indices.balance_receive += 1;
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test the case in which the order index of a settlement is incorrect
    #[test]
    fn test_invalid_settle__invalid_order_index() {
        let (witness, original_statement) = dummy_witness_and_statement();

        // Party 0 order index corrupted
        let mut statement = original_statement.clone();
        statement.party0_indices.order += 1;
        assert_invalid_witness_statement(&witness, &statement);

        // Party 1 order index corrupted
        let mut statement = original_statement;
        statement.party1_indices.order += 1;
        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Test case in which the send balance is incorrectly updated
    #[test]
    fn test_invalid_settle__invalid_send_balance() {
        let (witness, mut statement) = dummy_witness_and_statement();

        // Modify the send balance of party 0
        statement.party0_modified_shares.balances[statement.party0_indices.balance_send].amount +=
            Scalar::one();

        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests the case in which the receive balance is incorrectly updated
    #[test]
    fn test_invalid_settle__invalid_receive_balance() {
        let (witness, mut statement) = dummy_witness_and_statement();

        // Modify the receive balance of party 1
        statement.party1_modified_shares.balances[statement.party1_indices.balance_receive]
            .amount += Scalar::one();

        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests the case in which the receive balance relayer fee is incorrectly
    /// updated
    #[test]
    fn test_invalid_settle__invalid_receive_relayer_fee() {
        let (witness, mut statement) = dummy_witness_and_statement();

        // Modify the receive balance relayer fee of party 0
        rand_branch!(
            statement.party0_modified_shares.balances[statement.party0_indices.balance_receive]
                .relayer_fee_balance += Scalar::one(),
            statement.party1_modified_shares.balances[statement.party1_indices.balance_receive]
                .relayer_fee_balance += Scalar::one()
        );

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(&witness, &statement));
    }

    /// Tests the case in which the receive balance protocol fee is incorrectly
    /// updated
    #[test]
    fn test_invalid_settle__invalid_receive_protocol_fee() {
        let (witness, mut statement) = dummy_witness_and_statement();

        // Modify the receive balance protocol fee of party 0
        rand_branch!(
            statement.party0_modified_shares.balances[statement.party0_indices.balance_receive]
                .protocol_fee_balance += Scalar::one(),
            statement.party1_modified_shares.balances[statement.party1_indices.balance_receive]
                .protocol_fee_balance += Scalar::one()
        );

        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests the case in which the order amount is incorrectly modified
    #[test]
    fn test_invalid_settle__invalid_order_update() {
        let (witness, mut statement) = dummy_witness_and_statement();

        // Modify the order of party 0
        statement.party0_modified_shares.orders[statement.party0_indices.order].amount -=
            Scalar::one();

        assert_invalid_witness_statement(&witness, &statement);
    }

    /// Tests cases in which an element is spuriously modified that should not
    /// be
    #[test]
    fn test_invalid_settle__spurious_modifications() {
        let (witness, original_statement) = dummy_witness_and_statement();

        // Modify a balance that should not be modified
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.balances[statement.party0_indices.balance_send].mint +=
            Scalar::one();
        assert_invalid_witness_statement(&witness, &statement);

        // Modify an order that should not be modified
        let mut statement = original_statement.clone();
        statement.party1_modified_shares.orders[statement.party1_indices.order].amount -=
            Scalar::one();
        assert_invalid_witness_statement(&witness, &statement);

        // Modify the match fee
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.max_match_fee.repr += Scalar::one();
        assert_invalid_witness_statement(&witness, &statement);

        // Modify the managing cluster
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.managing_cluster.x += Scalar::one();
        assert_invalid_witness_statement(&witness, &statement);

        // Modify a key
        let mut statement = original_statement.clone();
        statement.party1_modified_shares.keys.pk_match.key += Scalar::one();
        assert_invalid_witness_statement(&witness, &statement);

        // Modify the keychain nonce
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.keys.nonce += Scalar::one();
        assert_invalid_witness_statement(&witness, &statement);

        // Modify the blinder
        let mut statement = original_statement;
        statement.party0_modified_shares.blinder += Scalar::one();
        assert_invalid_witness_statement(&witness, &statement);
    }

    // ---------------------------------------------
    // | Valid Match Settle With Commitments Tests |
    // ---------------------------------------------

    /// Test the case in which a prover modifies the wallet share commitment
    #[test]
    fn test_invalid_commitment__invalid_wallet_share_comm() {
        let mut rng = thread_rng();
        let (witness, mut statement) = dummy_witness_and_statement_with_commitments();
        let modification = Scalar::random(&mut rng);
        rand_branch!(
            statement.new_share_commitment0 += modification,
            statement.new_share_commitment1 += modification
        );

        assert!(!check_witness_statement_with_commitments(&witness, &statement));
    }

    /// Test the case in which a prover modifies a private share commitment
    #[test]
    fn test_invalid_commitment__invalid_private_share_commitment() {
        let mut rng = thread_rng();
        let (witness, mut statement) = dummy_witness_and_statement_with_commitments();
        let modification = Scalar::random(&mut rng);
        rand_branch!(
            statement.private_share_commitment0 += modification,
            statement.private_share_commitment1 += modification
        );

        assert!(!check_witness_statement_with_commitments(&witness, &statement));
    }
}
