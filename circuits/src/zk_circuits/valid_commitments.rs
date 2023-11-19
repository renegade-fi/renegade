//! Defines the VALID COMMITMENTS circuit which leaks indices of balances and
//! orders that will need to be updated upon a successful match. Specifically,
//! the circuit verifies that balances, orders, etc are contained in a wallet at
//! the claimed index. These balances, orders, etc are then linked to the
//! settlement proofs upon a successful match.
//!
//! Note that the wallet's state inclusion in the global Merkle tree is proven
//! in a linked proof of `VALID REBLIND`.
//!
//! VALID COMMITMENTS is proven once per order in the wallet

use crate::{
    zk_gadgets::{comparators::EqGadget, select::CondSelectVectorGadget},
    SingleProverCircuit,
};
use circuit_macros::circuit_type;
use circuit_types::{
    balance::{Balance, BalanceVar},
    fee::{Fee, FeeVar},
    order::{Order, OrderVar},
    traits::{BaseType, CircuitBaseType, CircuitVarType, SecretShareVarType},
    wallet::{WalletShare, WalletVar},
    PlonkCircuit,
};
use constants::{Scalar, ScalarField, MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar, Variable};
use serde::{Deserialize, Serialize};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit implementation of VALID COMMITMENTS
pub struct ValidCommitments<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>;
/// `VALID COMMITMENTS` with default state element sizing
pub type SizedValidCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The circuit constraints for VALID COMMITMENTS
    pub fn circuit(
        statement: ValidCommitmentsStatementVar,
        witness: ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Reconstruct the base and augmented wallets
        let recovered_blinder = cs.add(
            witness.private_secret_shares.blinder,
            witness.public_secret_shares.blinder,
        )?;

        let unblinded_public_shares = witness
            .public_secret_shares
            .unblind_shares(recovered_blinder, cs);
        let unblinded_augmented_shares = witness
            .augmented_public_shares
            .unblind_shares(recovered_blinder, cs);

        let base_wallet = witness
            .private_secret_shares
            .add_shares(&unblinded_public_shares, cs);
        let augmented_wallet = witness
            .private_secret_shares
            .add_shares(&unblinded_augmented_shares, cs);

        // The order side should be binary
        cs.enforce_bool(witness.order.side)?;
        let side = BoolVar::new_unchecked(witness.order.side);

        // The mint that the wallet will receive if the order is matched
        let mut receive_send_mint = CondSelectVectorGadget::select(
            &[witness.order.quote_mint, witness.order.base_mint],
            &[witness.order.base_mint, witness.order.quote_mint],
            side,
            cs,
        )?;
        let receive_mint = receive_send_mint.remove(0);
        let send_mint = receive_send_mint.remove(0);

        // Verify that the wallets are the same other than a possibly augmented balance
        // of zero for the received mint of the order. This augmented balance
        // must come in place of a previous balance that was zero.
        Self::verify_wallets_equal_with_augmentation(
            statement.balance_receive_index,
            receive_mint,
            &base_wallet,
            &augmented_wallet,
            cs,
        )?;

        // Verify that the send balance is at the correct index
        Self::contains_balance_at_index(
            statement.balance_send_index,
            &witness.balance_send,
            &augmented_wallet,
            cs,
        )?;
        cs.enforce_equal(witness.balance_send.mint, send_mint)?;

        // Verify that the receive balance is at the correct index
        Self::contains_balance_at_index(
            statement.balance_receive_index,
            &witness.balance_receive,
            &augmented_wallet,
            cs,
        )?;
        cs.enforce_equal(witness.balance_receive.mint, receive_mint)?;

        // Verify that the fee balance is in the wallet
        // TODO: Implement fees properly
        Self::contains_balance(&witness.balance_fee, &augmented_wallet, cs)?;
        cs.enforce_equal(witness.balance_fee.mint, witness.fee.gas_addr)?;

        // Verify that the order is at the correct index
        Self::contains_order_at_index(
            statement.order_index,
            &witness.order,
            &augmented_wallet,
            cs,
        )?;

        // Verify that the fee is contained in the wallet
        Self::contains_fee(&witness.fee, &augmented_wallet, cs)
    }

    /// Verify that two wallets are equal except possibly with a balance
    /// augmentation
    fn verify_wallets_equal_with_augmentation(
        receive_index: Variable,
        received_mint: Variable,
        base_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        augmented_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // All balances should be the same except possibly the balance at the receive
        // index. We allow This balance to be zero'd in the base wallet, and
        // have the received mint with zero balance in the augmented wallet
        let zero_var = cs.zero();
        let one_var = cs.one();
        let mut curr_index = zero_var;

        for (base_balance, augmented_balance) in base_wallet
            .balances
            .iter()
            .zip(augmented_wallet.balances.iter())
        {
            // Non-augmented case, balances are equal
            let balances_eq = EqGadget::eq(base_balance, augmented_balance, cs)?;

            // Validate a potential augmentation
            let prev_balance_zero = EqGadget::eq(
                base_balance,
                &BalanceVar {
                    mint: zero_var,
                    amount: zero_var,
                },
                cs,
            )?;

            let augmented_balance = EqGadget::eq(
                augmented_balance,
                &BalanceVar {
                    mint: received_mint,
                    amount: zero_var,
                },
                cs,
            )?;

            let augmentation_index_mask = EqGadget::eq(&curr_index, &receive_index, cs)?;

            // Validate that the balance is either unmodified or augmented from (0, 0) to
            // (receive_mint, 0)
            let augmented_from_zero = cs.logic_and_all(&[
                prev_balance_zero,
                augmented_balance,
                augmentation_index_mask,
            ])?;
            let valid_balance = cs.logic_or(augmented_from_zero, balances_eq)?;

            cs.enforce_true(valid_balance)?;
            curr_index = cs.add(curr_index, one_var)?;
        }

        // All orders should be the same
        for (base_order, augmented_order) in base_wallet
            .orders
            .iter()
            .zip(augmented_wallet.orders.iter())
        {
            EqGadget::constrain_eq(base_order, augmented_order, cs)?;
        }

        // All fees should be the same
        for (base_fee, augmented_fee) in base_wallet.fees.iter().zip(augmented_wallet.fees.iter()) {
            EqGadget::constrain_eq(base_fee, augmented_fee, cs)?;
        }

        // Keys should be equal
        EqGadget::constrain_eq(&base_wallet.keys, &augmented_wallet.keys, cs)?;

        // Blinders should be equal
        EqGadget::constrain_eq(&base_wallet.blinder, &augmented_wallet.blinder, cs)
    }

    /// Verify that the wallet has the given balance at the specified index
    fn contains_balance_at_index(
        index: Variable,
        target_balance: &BalanceVar,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let mut curr_index = cs.zero();
        let mut balance_found = cs.false_var();

        for balance in wallet.balances.iter() {
            let index_mask = EqGadget::eq(&curr_index, &index, cs)?;
            let balances_eq = EqGadget::eq(balance, target_balance, cs)?;

            let found = cs.logic_and(index_mask, balances_eq)?;

            balance_found = cs.logic_or(balance_found, found)?;
            curr_index = cs.add(curr_index, cs.one())?;
        }

        cs.enforce_true(balance_found)
    }

    /// Verify that the wallet has the given order at the specified index
    fn contains_order_at_index(
        index: Variable,
        target_order: &OrderVar,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let mut curr_index = cs.zero();
        let mut order_found = cs.false_var();

        for order in wallet.orders.iter() {
            let index_mask = EqGadget::eq(&curr_index, &index, cs)?;
            let orders_eq = EqGadget::eq(order, target_order, cs)?;

            let found = cs.logic_and(index_mask, orders_eq)?;
            order_found = cs.logic_or(order_found, found)?;
            curr_index = cs.add(curr_index, cs.one())?;
        }

        cs.enforce_true(order_found)
    }

    /// Verify that the wallet contains the given balance at an unspecified
    /// index
    ///
    /// Note that this definition implies a balance can exist more than once,
    /// this is fine from a security perspective
    fn contains_balance(
        target_balance: &BalanceVar,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let mut balance_found = cs.false_var();
        for balance in wallet.balances.iter() {
            let balances_eq = EqGadget::eq(balance, target_balance, cs)?;

            balance_found = cs.logic_or(balance_found, balances_eq)?;
        }

        cs.enforce_true(balance_found)
    }

    /// Verify that the wallet contains the given fee at an unspecified index
    fn contains_fee(
        target_fee: &FeeVar,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let mut fee_found = cs.false_var();

        for fee in wallet.fees.iter() {
            let fees_eq = EqGadget::eq(fee, target_fee, cs)?;
            fee_found = cs.logic_or(fee_found, fees_eq)?;
        }

        cs.enforce_true(fee_found)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID COMMITMENTS`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidCommitmentsWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The private secret shares of the wallet that have been reblinded for
    /// match
    pub private_secret_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the wallet that have been reblinded for
    /// match
    pub public_secret_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares, possibly with a zero'd balance added
    /// for the mint that will be received by this party upon a successful
    /// match
    pub augmented_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The order that the prover intends to match against with this proof
    pub order: Order,
    /// The balance that the wallet will send when the order is matched
    pub balance_send: Balance,
    /// The balance that the wallet will receive into when the order is matched
    pub balance_receive: Balance,
    /// The balance that will cover the relayer's fee when matched
    pub balance_fee: Balance,
    /// The fee that the relayer will take upon a successful match
    pub fee: Fee,
}
/// A `VALID COMMITMENTS` witness with default const generic sizing parameters
pub type SizedValidCommitmentsWitness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// The statement type for `VALID COMMITMENTS`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidCommitmentsStatement {
    /// The index of the balance that holds the mint that the wallet will
    /// send if a successful match occurs
    pub balance_send_index: u64,
    /// The index of the balance that holds the mint that the wallet will
    /// receive if a successful match occurs
    pub balance_receive_index: u64,
    /// The index of the order that is to be matched
    pub order_index: u64,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Statement = ValidCommitmentsStatement;
    type Witness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    fn apply_constraints(
        witness_var: ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        statement_var: ValidCommitmentsStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(statement_var, witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        balance::Balance, native_helpers::create_wallet_shares_from_private, order::OrderSide,
        wallet::Wallet,
    };
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};

    use crate::zk_circuits::test_helpers::{
        create_wallet_shares, MAX_BALANCES, MAX_FEES, MAX_ORDERS,
    };

    use super::{ValidCommitmentsStatement, ValidCommitmentsWitness};

    /// A type alias for the VALID COMMITMENTS witness with size parameters
    /// attached
    pub type SizedWitness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    /// Construct a valid witness and statement from the given wallet
    ///
    /// Simply chooses a random order to match against from the wallet
    pub fn create_witness_and_statement<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> (
        ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        ValidCommitmentsStatement,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let mut rng = thread_rng();

        // Split the wallet into secret shares
        let (private_secret_shares, public_secret_shares) = create_wallet_shares(wallet.clone());

        // Choose an order and fee to match on
        let ind_order = 0;
        let ind_fee = rng.gen_range(0..wallet.fees.len());
        let order = wallet.orders[ind_order].clone();
        let fee = wallet.fees[ind_fee].clone();

        // Restructure the mints from the order direction
        let (received_mint, sent_mint) = if order.side == OrderSide::Buy {
            (order.base_mint.clone(), order.quote_mint.clone())
        } else {
            (order.quote_mint.clone(), order.base_mint.clone())
        };

        let mut augmented_wallet = wallet.clone();

        // Find appropriate balances in the wallet
        let (ind_receive, balance_receive) = find_balance_or_augment(
            received_mint,
            &mut augmented_wallet.balances,
            true, // augment
        );
        let (ind_send, balance_send) = find_balance_or_augment(
            sent_mint,
            &mut augmented_wallet.balances,
            false, // augment
        );
        let (_, balance_fee) = find_balance_or_augment(
            fee.gas_addr.clone(),
            &mut augmented_wallet.balances,
            false, // augment
        );

        // After augmenting, split the augmented wallet into shares, using the same
        // private secret shares as the original (un-augmented) wallet
        let (_, augmented_public_shares) = create_wallet_shares_from_private(
            &augmented_wallet,
            &private_secret_shares,
            wallet.blinder,
        );

        let witness = ValidCommitmentsWitness {
            private_secret_shares,
            public_secret_shares,
            augmented_public_shares,
            order,
            balance_send,
            balance_receive,
            balance_fee,
            fee,
        };

        let statement = ValidCommitmentsStatement {
            balance_send_index: ind_send as u64,
            balance_receive_index: ind_receive as u64,
            order_index: ind_order as u64,
        };

        (witness, statement)
    }

    /// Finds a balance for the given order returning the index and the balance
    /// itself
    ///
    /// If the balance does not exist the `augment` flag lets the method augment
    /// the wallet with a zero'd balance
    pub(super) fn find_balance_or_augment<const MAX_BALANCES: usize>(
        mint: BigUint,
        balances: &mut [Balance; MAX_BALANCES],
        augment: bool,
    ) -> (usize, Balance) {
        let balance = balances
            .iter()
            .enumerate()
            .find(|(_ind, balance)| balance.mint == mint);

        match balance {
            Some((ind, balance)) => (ind, balance.clone()),
            None => {
                if !augment {
                    panic!("balance not found in wallet");
                }

                // Find a zero'd balance
                let (zerod_index, _) = balances
                    .iter()
                    .enumerate()
                    .find(|(_ind, balance)| balance.mint == BigUint::from(0u8))
                    .expect("wallet must have zero'd balance to augment");

                balances[zerod_index] = Balance { mint, amount: 0 };
                (zerod_index, balances[zerod_index].clone())
            },
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(non_snake_case)]

    use circuit_types::{
        balance::{Balance, BalanceShare},
        fee::FeeShare,
        fixed_point::FixedPointShare,
        order::{OrderShare, OrderSide},
    };
    use constants::Scalar;
    use lazy_static::lazy_static;

    use crate::zk_circuits::{
        test_helpers::{
            check_constraint_satisfaction, SizedWallet, INITIAL_WALLET, MAX_BALANCES, MAX_FEES,
            MAX_ORDERS,
        },
        valid_commitments::test_helpers::{create_witness_and_statement, find_balance_or_augment},
    };

    use super::ValidCommitments;

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        /// A wallet needing augmentation to receive its side of an order
        static ref UNAUGMENTED_WALLET: SizedWallet = {
            // Zero the wallet balance corresponding to the received mint
            let mut wallet = INITIAL_WALLET.clone();
            let order_receive_mint = match wallet.orders[0].side {
                OrderSide::Buy => wallet.orders[0].base_mint.clone(),
                OrderSide::Sell => wallet.orders[0].quote_mint.clone(),
            };

            // Find the received mint balance
            let (balance_ind, _) = find_balance_or_augment(order_receive_mint, &mut wallet.balances, false /* augment */);
            wallet.balances[balance_ind] = Balance::default();
            wallet
        };
    }

    /// A type alias for the VALID COMMITMENTS circuit with size parameters
    pub type SizedCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // --------------
    // | Test Cases |
    // --------------

    /// Tests that the constraints may be satisfied by a valid witness
    /// and statement pair
    #[test]
    fn test_valid_commitments() {
        let wallet = INITIAL_WALLET.clone();
        let (witness, statement) = create_witness_and_statement(&wallet);

        assert!(check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ))
    }

    /// Tests the case in which an augmented balance must be added
    #[test]
    fn test_valid_commitments__valid_augmentation() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, statement) = create_witness_and_statement(&wallet);

        assert!(check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ))
    }

    /// Tests the case in which the prover attempts to add a non-zero balance to
    /// the augmented wallet
    #[test]
    fn test_invalid_commitment__augmented_nonzero_balance() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Prover attempt to augment the wallet with a non-zero balance
        let augmented_balance_index = statement.balance_receive_index;
        witness.augmented_public_shares.balances[augmented_balance_index as usize].amount +=
            Scalar::one();
        witness.balance_receive.amount += 1u64;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }

    /// Tests the case in which the prover clobbers a non-zero balance to
    /// augment the wallet
    #[test]
    fn test_invalid_commitment__augmentation_clobbers_balance() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Reset the original wallet such that the augmented balance was non-zero
        let augmentation_index = statement.balance_receive_index;
        witness.public_secret_shares.balances[augmentation_index as usize] = BalanceShare {
            amount: Scalar::one(),
            mint: Scalar::one(),
        };

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ))
    }

    /// Tests the case in which a prover attempts to modify an order in the
    /// augmented wallet
    #[test]
    fn test_invalid_commitment__augmentation_modifies_order() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify an order in the augmented wallet
        witness.augmented_public_shares.orders[1].amount += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }

    /// Test the case in which a prover attempts to modify a fee in the
    /// augmented wallet
    #[test]
    fn test_invalid_commitment__augmentation_modifies_fee() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify a fee in the wallet
        witness.augmented_public_shares.fees[0].gas_token_amount += Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }

    /// Test the case in which a prover attempts to modify wallet keys and
    /// blinders in augmentation
    #[test]
    fn test_invalid_commitment__augmentation_modifies_keys() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify a key in the wallet
        witness.augmented_public_shares.keys.pk_match.key = Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }

    /// Test the case in which a prover attempts to modify the blinder in
    /// augmentation
    #[test]
    fn test_invalid_commitment__augmentation_modifies_blinder() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the wallet blinder
        witness.augmented_public_shares.blinder += Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ))
    }

    /// Test the case in which the index of the send balance is incorrect
    #[test]
    fn test_invalid_commitment__invalid_send_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the send balance
        statement.balance_send_index += 1;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ))
    }

    /// Test the case in which the index of the receive balance is incorrect
    #[test]
    fn test_invalid_commitment__invalid_receive_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the send balance
        statement.balance_receive_index += 1;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ))
    }

    /// Test the case in which the index of the matched order is incorrect
    #[test]
    fn test_invalid_commitment__invalid_order_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the order
        statement.order_index += 1;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ))
    }

    /// Test the case in which a balance is missing from the wallet
    #[test]
    fn test_invalid_commitment__send_balance_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the send balance from the order
        witness.augmented_public_shares.balances[statement.balance_send_index as usize] =
            BalanceShare {
                mint: Scalar::zero(),
                amount: Scalar::zero(),
            };

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }

    /// Test the case in which the receive balance is missing from the wallet
    #[test]
    fn test_invalid_commitment__receive_balance_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the receive balance from the order
        witness.augmented_public_shares.balances[statement.balance_receive_index as usize] =
            BalanceShare {
                mint: Scalar::zero(),
                amount: Scalar::zero(),
            };

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }

    /// Test the case in which the fee balance is missing from the wallet
    #[test]
    fn test_invalid_commitment__fee_balance_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the fee balance from the order; clobber all balances because this
        // does not come with an index
        witness
            .augmented_public_shares
            .balances
            .iter_mut()
            .for_each(|balance| {
                *balance = BalanceShare {
                    mint: Scalar::zero(),
                    amount: Scalar::zero(),
                }
            });

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }

    /// Test the case in which the order is missing from the wallet
    #[test]
    fn test_invalid_commitment__order_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the order being proved on
        witness.augmented_public_shares.orders[statement.order_index as usize] = OrderShare {
            quote_mint: Scalar::zero(),
            base_mint: Scalar::zero(),
            side: Scalar::zero(),
            amount: Scalar::zero(),
            worst_case_price: FixedPointShare {
                repr: Scalar::zero(),
            },
            timestamp: Scalar::zero(),
        };

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }

    /// Test the case in which the fee is missing from the wallet
    #[test]
    fn test_invalid_commitment__fee_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the fees, clobber all of them because the fee does not contain an
        // index
        witness
            .augmented_public_shares
            .fees
            .iter_mut()
            .for_each(|fee| {
                *fee = FeeShare {
                    settle_key: Scalar::zero(),
                    gas_addr: Scalar::zero(),
                    gas_token_amount: Scalar::zero(),
                    percentage_fee: FixedPointShare {
                        repr: Scalar::zero(),
                    },
                }
            });

        assert!(!check_constraint_satisfaction::<SizedCommitments>(
            witness, statement
        ));
    }
}
