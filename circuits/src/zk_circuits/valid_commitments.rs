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
        balance::{Balance, BalanceVar, CommittedBalance},
        fee::{CommittedFee, Fee, FeeVar},
        order::{CommittedOrder, Order, OrderVar},
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
            &[witness.order.base_mint, witness.order.quote_mint],
            &[witness.order.quote_mint, witness.order.base_mint],
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
#[derive(Clone, Debug)]
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
