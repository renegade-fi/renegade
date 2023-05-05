//! Defines the VALID COMMITMENTS circuit which leaks indices of balances and orders
//! that will need to be updated upon a successful match. Specifically, the circuit
//! verifies that balances, orders, etc are contained in a wallet at the claimed
//! index. These balances, orders, etc are then linked to the settlement proofs
//! upon a successful match.
//!
//! Note that the wallet's state inclusion in the global Merkle tree is proven in
//! a linked proof of `VALID REBLIND`.
//!
//! VALID COMMITMENTS is proven once per order in the wallet

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
    BulletproofGens,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        balance::{Balance, BalanceVar, CommittedBalance, LinkableBalanceCommitment},
        fee::{CommittedFee, Fee, FeeVar},
        order::{CommittedOrder, LinkableOrderCommitment, OrderVar},
        wallet::{WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar, WalletVar},
    },
    zk_gadgets::{
        comparators::EqGadget,
        gates::{AndGate, OrGate},
        nonnative::NonNativeElementVar,
        select::CondSelectVectorGadget,
        wallet_operations::{BalanceComparatorGadget, FeeComparatorGadget, OrderComparatorGadget},
    },
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit implementation of VALID COMMITMENTS
pub struct ValidCommitments<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The circuit constraints for VALID COMMITMENTS
    pub fn circuit<CS: RandomizableConstraintSystem>(
        statement: ValidCommitmentsStatementVar,
        mut witness: ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // Reconstruct the base and augmented wallets
        let recovered_blinder = witness.private_secret_shares.blinder.clone()
            + witness.public_secret_shares.blinder.clone();
        witness
            .public_secret_shares
            .unblind(recovered_blinder.clone());
        witness.augmented_public_shares.unblind(recovered_blinder);

        let base_wallet =
            witness.private_secret_shares.clone() + witness.public_secret_shares.clone();
        let augmented_wallet =
            witness.private_secret_shares.clone() + witness.augmented_public_shares.clone();

        // The mint that the wallet will receive if the order is matched
        let mut receive_send_mint = CondSelectVectorGadget::select(
            &[witness.order.quote_mint, witness.order.base_mint],
            &[witness.order.base_mint, witness.order.quote_mint],
            witness.order.side,
            cs,
        );
        let receive_mint = receive_send_mint.remove(0);
        let send_mint = receive_send_mint.remove(0);

        // Verify that the wallets are the same other than a possibly augmented balance of
        // zero for the received mint of the order. This augmented balance must come in place of
        // a previous balance that was zero.
        Self::verify_wallets_equal_with_augmentation(
            statement.balance_receive_index,
            receive_mint.clone(),
            &base_wallet,
            &augmented_wallet,
            cs,
        );

        // Verify that the send balance is at the correct index
        Self::contains_balance_at_index(
            statement.balance_send_index,
            witness.balance_send,
            &augmented_wallet,
            cs,
        );
        cs.constrain(witness.balance_send.mint - send_mint);

        // Verify that the receive balance is at the correct index
        Self::contains_balance_at_index(
            statement.balance_receive_index,
            witness.balance_receive,
            &augmented_wallet,
            cs,
        );
        cs.constrain(witness.balance_receive.mint - receive_mint);

        // Verify that the fee balance is in the wallet
        // TODO: Implement fees properly
        Self::contains_balance(witness.balance_fee, &augmented_wallet, cs);
        cs.constrain(witness.balance_fee.mint - witness.fee.gas_addr);

        // Verify that the order is at the correct index
        Self::contains_order_at_index(statement.order_index, witness.order, &augmented_wallet, cs);

        // Verify that the fee is contained in the wallet
        Self::contains_fee(witness.fee, &augmented_wallet, cs);
    }

    /// Verify that two wallets are equal except possibly with a balance augmentation
    fn verify_wallets_equal_with_augmentation<CS: RandomizableConstraintSystem>(
        receive_index: Variable,
        received_mint: LinearCombination,
        base_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        augmented_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        cs: &mut CS,
    ) {
        // All balances should be the same except possibly the balance at the receive index. We allow
        // This balance to be zero'd in the base wallet, and have the received mint with zero
        // balance in the augmented wallet
        let mut curr_index: LinearCombination = Variable::Zero().into();
        for (base_balance, augmented_balance) in base_wallet
            .balances
            .iter()
            .zip(augmented_wallet.balances.iter())
        {
            // Non-augmented case, balances are equal
            let balances_eq = BalanceComparatorGadget::compare_eq(
                base_balance.clone(),
                augmented_balance.clone(),
                cs,
            );

            // Validate a potential augmentation
            let prev_balance_zero = BalanceComparatorGadget::compare_eq(
                base_balance.clone(),
                BalanceVar {
                    mint: Variable::Zero(),
                    amount: Variable::Zero(),
                },
                cs,
            );
            let augmented_balance = BalanceComparatorGadget::compare_eq(
                augmented_balance.clone(),
                BalanceVar {
                    mint: received_mint.clone(),
                    amount: Variable::Zero().into(),
                },
                cs,
            );
            let augmentation_index_mask =
                EqGadget::eq(curr_index.clone(), receive_index.into(), cs);

            // Validate that the balance is either unmodified or augmented from (0, 0) to (receive_mint, 0)
            let augmented_from_zero = AndGate::multi_and(
                &[
                    prev_balance_zero,
                    augmented_balance,
                    augmentation_index_mask,
                ],
                cs,
            );
            let valid_balance = OrGate::or(augmented_from_zero, balances_eq, cs);

            cs.constrain(Variable::One() - valid_balance);
            curr_index += Variable::One();
        }

        // All orders should be the same
        for (base_order, augmented_order) in base_wallet
            .orders
            .iter()
            .zip(augmented_wallet.orders.iter())
        {
            OrderComparatorGadget::constrain_eq(base_order.clone(), augmented_order.clone(), cs);
        }

        // All fees should be the same
        for (base_fee, augmented_fee) in base_wallet.fees.iter().zip(augmented_wallet.fees.iter()) {
            FeeComparatorGadget::constrain_eq(base_fee.clone(), augmented_fee.clone(), cs);
        }

        // Keys should be equal
        NonNativeElementVar::constrain_equal(
            &base_wallet.keys.pk_root,
            &augmented_wallet.keys.pk_root,
            cs,
        );
        cs.constrain(base_wallet.keys.pk_match.clone() - augmented_wallet.keys.pk_match.clone());

        // Blinders should be equal
        cs.constrain(base_wallet.blinder.clone() - augmented_wallet.blinder.clone());
    }

    /// Verify that the wallet has the given balance at the specified index
    fn contains_balance_at_index<CS: RandomizableConstraintSystem>(
        index: Variable,
        target_balance: BalanceVar<Variable>,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        cs: &mut CS,
    ) {
        let mut curr_index: LinearCombination = Variable::Zero().into();
        let mut balance_found: LinearCombination = Variable::Zero().into();
        for balance in wallet.balances.iter() {
            let index_mask = EqGadget::eq(curr_index.clone(), index.into(), cs);
            let balances_eq =
                BalanceComparatorGadget::compare_eq(balance.clone(), target_balance, cs);

            let found = AndGate::and(index_mask, balances_eq, cs);
            balance_found += found;
            curr_index += Variable::One();
        }

        cs.constrain(balance_found - Variable::One())
    }

    /// Verify that the wallet has the given order at the specified index
    fn contains_order_at_index<CS: RandomizableConstraintSystem>(
        index: Variable,
        target_order: OrderVar<Variable>,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        cs: &mut CS,
    ) {
        let mut curr_index: LinearCombination = Variable::Zero().into();
        let mut order_found: LinearCombination = Variable::Zero().into();
        for order in wallet.orders.iter() {
            let index_mask = EqGadget::eq(curr_index.clone(), index.into(), cs);
            let orders_eq =
                OrderComparatorGadget::compare_eq(order.clone(), target_order.clone(), cs);

            let found = AndGate::and(index_mask, orders_eq, cs);
            order_found += found;
            curr_index += Variable::One();
        }

        cs.constrain(order_found - Variable::One())
    }

    /// Verify that the wallet contains the given balance at an unspecified index
    fn contains_balance<CS: RandomizableConstraintSystem>(
        target_balance: BalanceVar<Variable>,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        cs: &mut CS,
    ) {
        let mut balance_found: LinearCombination = Variable::Zero().into();
        for balance in wallet.balances.iter() {
            let balances_eq =
                BalanceComparatorGadget::compare_eq(balance.clone(), target_balance, cs);
            balance_found += balances_eq;
        }

        cs.constrain(balance_found - Variable::One());
    }

    /// Verify that the wallet contains the given fee at an unspecified index
    fn contains_fee<CS: RandomizableConstraintSystem>(
        target_fee: FeeVar<Variable>,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        cs: &mut CS,
    ) {
        let mut fee_found: LinearCombination = Variable::Zero().into();
        for fee in wallet.fees.iter() {
            let fees_eq = FeeComparatorGadget::compare_eq(fee.clone(), target_fee.clone(), cs);
            fee_found += fees_eq;
        }

        cs.constrain(fee_found - Variable::One())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID COMMITMENTS`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidCommitmentsWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the wallet that have been reblinded for match
    pub private_secret_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the wallet that have been reblinded for match
    pub public_secret_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares, possibly with a zero'd balance added for
    /// the mint that will be received by this party upon a successful match
    pub augmented_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The order that the prover intends to match against with this proof
    pub order: LinkableOrderCommitment,
    /// The balance that the wallet will send when the order is matched
    pub balance_send: LinkableBalanceCommitment,
    /// The balance that the wallet will receive into when the order is matched
    pub balance_receive: Balance,
    /// The balance that will cover the relayer's fee when matched
    pub balance_fee: Balance,
    /// The fee that the relayer will take upon a successful match
    pub fee: Fee,
}

/// The witness type for `VALID COMMITMENTS`, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidCommitmentsWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the wallet that have been reblinded for match
    pub private_secret_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the wallet that have been reblinded for match
    pub public_secret_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares, possibly with a zero'd balance added for
    /// the mint that will be received by this party upon a successful match
    pub augmented_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The order that the prover intends to match against with this proof
    pub order: OrderVar<Variable>,
    /// The balance that the wallet will send when the order is matched
    pub balance_send: BalanceVar<Variable>,
    /// The balance that the wallet will receive into when the order is matched
    pub balance_receive: BalanceVar<Variable>,
    /// The balance that will cover the relayer's fee when matched
    pub balance_fee: BalanceVar<Variable>,
    /// The fee that the relayer will take upon a successful match
    pub fee: FeeVar<Variable>,
}

/// The witness type for `VALID COMMITMENTS`, allocated in a constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidCommitmentsWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the wallet that have been reblinded for match
    pub private_secret_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the wallet that have been reblinded for match
    pub public_secret_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares, possibly with a zero'd balance added for
    /// the mint that will be received by this party upon a successful match
    pub augmented_public_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The order that the prover intends to match against with this proof
    pub order: CommittedOrder,
    /// The balance that the wallet will send when the order is matched
    pub balance_send: CommittedBalance,
    /// The balance that the wallet will receive into when the order is matched
    pub balance_receive: CommittedBalance,
    /// The balance that will cover the relayer's fee when matched
    pub balance_fee: CommittedBalance,
    /// The fee that the relayer will take upon a successful match
    pub fee: CommittedFee,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidCommitmentsWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (private_share_vars, private_share_comms) = self
            .private_secret_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (public_share_vars, public_share_comms) = self
            .public_secret_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (augmented_share_vars, augmented_share_comms) = self
            .augmented_public_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (order_var, order_comm) = self.order.commit_witness(rng, prover).unwrap();
        let (balance_send_var, balance_send_comm) =
            self.balance_send.commit_witness(rng, prover).unwrap();
        let (balance_receive_var, balance_receive_comm) =
            self.balance_receive.commit_witness(rng, prover).unwrap();
        let (balance_fee_var, balance_fee_comm) =
            self.balance_fee.commit_witness(rng, prover).unwrap();
        let (fee_var, fee_comm) = self.fee.commit_witness(rng, prover).unwrap();

        Ok((
            ValidCommitmentsWitnessVar {
                private_secret_shares: private_share_vars,
                public_secret_shares: public_share_vars,
                augmented_public_shares: augmented_share_vars,
                order: order_var,
                balance_send: balance_send_var,
                balance_receive: balance_receive_var,
                balance_fee: balance_fee_var,
                fee: fee_var,
            },
            ValidCommitmentsWitnessCommitment {
                private_secret_shares: private_share_comms,
                public_secret_shares: public_share_comms,
                augmented_public_shares: augmented_share_comms,
                order: order_comm,
                balance_send: balance_send_comm,
                balance_receive: balance_receive_comm,
                balance_fee: balance_fee_comm,
                fee: fee_comm,
            },
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for ValidCommitmentsWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let private_share_vars = self
            .private_secret_shares
            .commit_verifier(verifier)
            .unwrap();
        let public_share_vars = self.public_secret_shares.commit_verifier(verifier).unwrap();
        let augmented_share_vars = self
            .augmented_public_shares
            .commit_verifier(verifier)
            .unwrap();
        let order_var = self.order.commit_verifier(verifier).unwrap();
        let balance_send_var = self.balance_send.commit_verifier(verifier).unwrap();
        let balance_receive_var = self.balance_receive.commit_verifier(verifier).unwrap();
        let balance_fee_var = self.balance_fee.commit_verifier(verifier).unwrap();
        let fee_var = self.fee.commit_verifier(verifier).unwrap();

        Ok(ValidCommitmentsWitnessVar {
            private_secret_shares: private_share_vars,
            public_secret_shares: public_share_vars,
            augmented_public_shares: augmented_share_vars,
            order: order_var,
            balance_send: balance_send_var,
            balance_receive: balance_receive_var,
            balance_fee: balance_fee_var,
            fee: fee_var,
        })
    }
}

/// The statement type for `VALID COMMITMENTS`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidCommitmentsStatement {
    /// The index of the balance that holds the mint that the wallet will
    /// send if a successful match occurs
    pub balance_send_index: usize,
    /// The index of the balance that holds the mint that the wallet will
    /// receive if a successful match occurs
    pub balance_receive_index: usize,
    /// The index of the order that is to be matched
    pub order_index: usize,
}

/// The statement type for `VALID COMMITMENTS`, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidCommitmentsStatementVar {
    /// The index of the balance that holds the mint that the wallet will
    /// send if a successful match occurs
    pub balance_send_index: Variable,
    /// The index of the balance that holds the mint that the wallet will
    /// receive if a successful match occurs
    pub balance_receive_index: Variable,
    /// The index of the order that is to be matched
    pub order_index: Variable,
}

impl CommitPublic for ValidCommitmentsStatement {
    type VarType = ValidCommitmentsStatementVar;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let send_index_var = cs.commit_public(Scalar::from(self.balance_send_index as u32));
        let receive_index_var = cs.commit_public(Scalar::from(self.balance_receive_index as u32));
        let order_index_var = cs.commit_public(Scalar::from(self.order_index as u32));

        Ok(ValidCommitmentsStatementVar {
            balance_send_index: send_index_var,
            balance_receive_index: receive_index_var,
            order_index: order_index_var,
        })
    }
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
    type WitnessCommitment = ValidCommitmentsWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 1024;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness and statement
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        // Apply the constraints
        Self::circuit(statement_var, witness_var, &mut prover);

        // Prove the relation
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness and statement
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();
        let statement_var = statement.commit_public(&mut verifier).unwrap();

        // Apply the constrains
        Self::circuit(statement_var, witness_var, &mut verifier);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    #![allow(non_snake_case)]

    use curve25519_dalek::scalar::Scalar;
    use lazy_static::lazy_static;
    use merlin::Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};
    use rand_core::OsRng;

    use crate::{
        types::{
            balance::{Balance, BalanceSecretShare},
            fee::FeeSecretShare,
            order::{OrderSecretShare, OrderSide},
        },
        zk_circuits::test_helpers::{
            create_wallet_shares, create_wallet_shares_from_private, SizedWallet, INITIAL_WALLET,
            MAX_BALANCES, MAX_FEES, MAX_ORDERS,
        },
        CommitPublic, CommitWitness,
    };

    use super::{ValidCommitments, ValidCommitmentsStatement, ValidCommitmentsWitness};

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
            let (balance_ind, _) = find_balance_or_augment(order_receive_mint, &mut wallet, false /* augment */);
            wallet.balances[balance_ind] = Balance::default();
            wallet
        };
    }

    /// A type alias for the VALID COMMITMENTS witness with size parameters attached
    type SizedWitness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // -----------
    // | Helpers |
    // -----------

    /// Construct a valid witness and statement from the given wallet
    ///
    /// Simply chooses a random order to match against from the wallet
    fn create_witness_and_statement(
        wallet: &SizedWallet,
    ) -> (SizedWitness, ValidCommitmentsStatement) {
        let mut rng = thread_rng();

        // Split the wallet into secret shares
        let (private_shares, public_shares) = create_wallet_shares(wallet);

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
            &mut augmented_wallet,
            true, /* augment */
        );
        let (ind_send, balance_send) =
            find_balance_or_augment(sent_mint, &mut augmented_wallet, false /* augment */);
        let (_, balance_fee) = find_balance_or_augment(
            fee.gas_addr.clone(),
            &mut augmented_wallet,
            false, /* augment */
        );

        // After augmenting, split the augmented wallet into shares, using the same private secret shares
        // as the original (un-augmented) wallet
        let (_, augmented_public_shares) =
            create_wallet_shares_from_private(&augmented_wallet, &private_shares, wallet.blinder);

        let witness = SizedWitness {
            private_secret_shares: private_shares,
            public_secret_shares: public_shares,
            augmented_public_shares,
            order: order.into(),
            balance_send: balance_send.into(),
            balance_receive,
            balance_fee,
            fee,
        };

        let statement = ValidCommitmentsStatement {
            balance_send_index: ind_send,
            balance_receive_index: ind_receive,
            order_index: ind_order,
        };

        (witness, statement)
    }

    /// Finds a balance for the given order returning the index and the balance itself
    ///
    /// If the balance does not exist the `augment` flag lets the method augment the wallet
    /// with a zero'd balance
    fn find_balance_or_augment(
        mint: BigUint,
        wallet: &mut SizedWallet,
        augment: bool,
    ) -> (usize, Balance) {
        let balance = wallet
            .balances
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
                let (zerod_index, _) = wallet
                    .balances
                    .iter()
                    .enumerate()
                    .find(|(_ind, balance)| balance.mint == BigUint::from(0u8))
                    .expect("wallet must have zero'd balance to augment");

                wallet.balances[zerod_index] = Balance { mint, amount: 0 };
                (zerod_index, wallet.balances[zerod_index].clone())
            }
        }
    }

    /// Returns true if the given witness and statement satisfy the relation defined by `VALID COMMITMENTS`
    fn constraints_satisfied(witness: SizedWitness, statement: ValidCommitmentsStatement) -> bool {
        let mut rng = OsRng {};

        // Create a constrain system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Commit to the witness and statement
        let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        // Apply the constraints
        ValidCommitments::circuit(statement_var, witness_var, &mut prover);
        prover.constraints_satisfied()
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests that the constraints may be satisfied by a valid witness
    /// and statement pair
    #[test]
    fn test_valid_commitments() {
        let wallet = INITIAL_WALLET.clone();
        let (witness, statement) = create_witness_and_statement(&wallet);

        assert!(constraints_satisfied(witness, statement))
    }

    /// Tests the case in which an augmented balance must be added
    #[test]
    fn test_valid_commitments__valid_augmentation() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, statement) = create_witness_and_statement(&wallet);

        assert!(constraints_satisfied(witness, statement))
    }

    /// Tests the case in which the prover attempts to add a non-zero balance to the augmented wallet
    #[test]
    fn test_invalid_commitment__augmented_nonzero_balance() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Prover attempt to augment the wallet with a non-zero balance
        let augmented_balance_index = statement.balance_receive_index;
        witness.augmented_public_shares.balances[augmented_balance_index].amount += Scalar::one();
        witness.balance_receive.amount += 1u64;

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests the case in which the prover clobbers a non-zero balance to augment the wallet
    #[test]
    fn test_invalid_commitment__augmentation_clobbers_balance() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Reset the original wallet such that the augmented balance was non-zero
        let augmentation_index = statement.balance_receive_index;
        witness.public_secret_shares.balances[augmentation_index] = BalanceSecretShare {
            amount: Scalar::one(),
            mint: Scalar::one(),
        };

        assert!(!constraints_satisfied(witness, statement))
    }

    /// Tests the case in which a prover attempts to modify an order in the augmented wallet
    #[test]
    fn test_invalid_commitment__augmentation_modifies_order() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify an order in the augmented wallet
        witness.augmented_public_shares.orders[1].amount += Scalar::one();

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test the case in which a prover attempts to modify a fee in the augmented wallet
    #[test]
    fn test_invalid_commitment__augmentation_modifies_fee() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify a fee in the wallet
        witness.augmented_public_shares.fees[0].gas_token_amount += Scalar::one();
        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test the case in which a prover attempts to modify wallet keys and blinders in augmentation
    #[test]
    fn test_invalid_commitment__augmentation_modifies_keys() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify a key in the wallet
        witness.augmented_public_shares.keys.pk_match += Scalar::one();
        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test the case in which a prover attempts to modify the blinder in augmentation
    #[test]
    fn test_invalid_commitment__augmentation_modifies_blinder() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the wallet blinder
        witness.augmented_public_shares.blinder += Scalar::one();
        assert!(!constraints_satisfied(witness, statement))
    }

    /// Test the case in which the index of the send balance is incorrect
    #[test]
    fn test_invalid_commitment__invalid_send_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the send balance
        statement.balance_send_index += 1;

        assert!(!constraints_satisfied(witness, statement))
    }

    /// Test the case in which the index of the receive balance is incorrect
    #[test]
    fn test_invalid_commitment__invalid_receive_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the send balance
        statement.balance_receive_index += 1;

        assert!(!constraints_satisfied(witness, statement))
    }

    /// Test the case in which the index of the matched order is incorrect
    #[test]
    fn test_invalid_commitment__invalid_order_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the order
        statement.order_index += 1;

        assert!(!constraints_satisfied(witness, statement))
    }

    /// Test the case in which a balance is missing from the wallet
    #[test]
    fn test_invalid_commitment__send_balance_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the send balance from the order
        witness.augmented_public_shares.balances[statement.balance_send_index] =
            BalanceSecretShare {
                mint: Scalar::zero(),
                amount: Scalar::zero(),
            };
        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test the case in which the receive balance is missing from the wallet
    #[test]
    fn test_invalid_commitment__receive_balance_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the receive balance from the order
        witness.augmented_public_shares.balances[statement.balance_receive_index] =
            BalanceSecretShare {
                mint: Scalar::zero(),
                amount: Scalar::zero(),
            };
        assert!(!constraints_satisfied(witness, statement));
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
                *balance = BalanceSecretShare {
                    mint: Scalar::zero(),
                    amount: Scalar::zero(),
                }
            });

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test the case in which the order is missing from the wallet
    #[test]
    fn test_invalid_commitment__order_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the order being proved on
        witness.augmented_public_shares.orders[statement.order_index] = OrderSecretShare {
            quote_mint: Scalar::zero(),
            base_mint: Scalar::zero(),
            side: Scalar::zero(),
            price: Scalar::zero(),
            amount: Scalar::zero(),
            timestamp: Scalar::zero(),
        };
        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test the case in which the fee is missing from the wallet
    #[test]
    fn test_invalid_commitment__fee_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the fees, clobber all of them because the fee does not contain an index
        witness
            .augmented_public_shares
            .fees
            .iter_mut()
            .for_each(|fee| {
                *fee = FeeSecretShare {
                    settle_key: Scalar::zero(),
                    gas_addr: Scalar::zero(),
                    gas_token_amount: Scalar::zero(),
                    percentage_fee: Scalar::zero(),
                }
            });
        assert!(!constraints_satisfied(witness, statement));
    }
}
