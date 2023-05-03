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
    r1cs::{Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
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
        wallet::{WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar},
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
        witness: ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        unimplemented!("")
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
