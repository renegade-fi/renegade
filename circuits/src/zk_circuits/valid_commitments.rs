//! Defines the VALID COMMITMENTS circuit which proves knowledge of a balance
//! order and fee inside of a wallet that can be matched against
//!
//! A node in the relayer network will prove this statement for each order and
//! use it as part of the handshake process
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.3
//! for a formal specification

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{ConstraintSystem, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        balance::{Balance, BalanceVar, CommittedBalance},
        fee::{CommittedFee, Fee, FeeVar},
        order::{CommittedOrder, Order, OrderVar},
        wallet::{CommittedWallet, Wallet, WalletVar},
    },
    CommitProver, CommitVerifier, SingleProverCircuit,
};

/// The circuitry for the VALID COMMITMENTS statement
#[derive(Clone, Debug)]
pub struct ValidCommitments<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Apply the constraints for the VALID COMMITMENTS circuitry
    pub fn circuit<CS: RandomizableConstraintSystem>(
        witness: ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        merkle_root: Variable,
        match_nullifier: Variable,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        Ok(())
    }
}

/// The witness type for VALID COMMITMENTS
#[derive(Clone, Debug)]
pub struct ValidCommitmentsWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The wallet that the committed values come from
    pub wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The selected order to commit to
    pub order: Order,
    /// The selected balance to commit to
    pub balance: Balance,
    /// The selected fee to commit to
    pub fee: Fee,
    /// The merkle proof that the wallet is valid within the state tree
    pub wallet_opening: Vec<Scalar>,
    /// The indices of the merkle proof that the wallet is valid
    pub wallet_opening_indices: Vec<Scalar>,
}

/// The witness type for VALID COMMITMENTS, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidCommitmentsWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The wallet that the committed values come from
    pub wallet: WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The selected order to commit to
    pub order: OrderVar,
    /// The selected balance to commit to
    pub balance: BalanceVar,
    /// The selected fee to commit to
    pub fee: FeeVar,
    /// The merkle proof that the wallet is valid within the state tree
    pub wallet_opening: Vec<Variable>,
    /// The indices of the merkle proof that the wallet is valid
    pub wallet_opening_indices: Vec<Variable>,
}

/// The witness type for VALID COMMITMENTS, committed to by a prover
#[derive(Clone, Debug)]
pub struct ValidCommitmentsWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The wallet that the committed values come from
    pub wallet: CommittedWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The selected order to commit to
    pub order: CommittedOrder,
    /// The selected balance to commit to
    pub balance: CommittedBalance,
    /// The selected fee to commit to
    pub fee: CommittedFee,
    /// The merkle proof that the wallet is valid within the state tree
    pub wallet_opening: Vec<CompressedRistretto>,
    /// The indices of the merkle proof that the wallet is valid
    pub wallet_opening_indices: Vec<CompressedRistretto>,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitProver
    for ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidCommitmentsWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        // Commit to the variables individually
        let (wallet_var, wallet_commit) = self.wallet.commit_prover(rng, prover).unwrap();
        let (order_var, order_commit) = self.order.commit_prover(rng, prover).unwrap();
        let (balance_var, balance_commit) = self.balance.commit_prover(rng, prover).unwrap();
        let (fee_var, fee_commit) = self.fee.commit_prover(rng, prover).unwrap();

        // Commit to the Merkle proof
        let (merkle_opening_comms, merkle_opening_vars): (Vec<CompressedRistretto>, Vec<Variable>) =
            self.wallet_opening
                .iter()
                .map(|opening_elem| prover.commit(*opening_elem, Scalar::random(rng)))
                .unzip();
        let (merkle_index_comms, merkle_index_vars): (Vec<CompressedRistretto>, Vec<Variable>) =
            self.wallet_opening_indices
                .iter()
                .map(|opening_index| prover.commit(*opening_index, Scalar::random(rng)))
                .unzip();

        Ok((
            ValidCommitmentsWitnessVar {
                wallet: wallet_var,
                order: order_var,
                balance: balance_var,
                fee: fee_var,
                wallet_opening: merkle_opening_vars,
                wallet_opening_indices: merkle_index_vars,
            },
            ValidCommitmentsWitnessCommitment {
                wallet: wallet_commit,
                order: order_commit,
                balance: balance_commit,
                fee: fee_commit,
                wallet_opening: merkle_opening_comms,
                wallet_opening_indices: merkle_index_comms,
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
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let wallet_var = self.wallet.commit_verifier(verifier).unwrap();
        let order_var = self.order.commit_verifier(verifier).unwrap();
        let balance_var = self.balance.commit_verifier(verifier).unwrap();
        let fee_var = self.fee.commit_verifier(verifier).unwrap();

        let merkle_opening_vars = self
            .wallet_opening
            .iter()
            .map(|opening_val| verifier.commit(*opening_val))
            .collect_vec();
        let merkle_index_vars = self
            .wallet_opening_indices
            .iter()
            .map(|opening_indices| verifier.commit(*opening_indices))
            .collect_vec();

        Ok(ValidCommitmentsWitnessVar {
            wallet: wallet_var,
            order: order_var,
            balance: balance_var,
            fee: fee_var,
            wallet_opening: merkle_opening_vars,
            wallet_opening_indices: merkle_index_vars,
        })
    }
}

/// The statement type for VALID COMMITMENTS
#[derive(Clone, Debug)]
pub struct ValidCommitmentsStatement {
    /// The wallet match nullifier of the wallet committed to
    pub nullifier: Scalar,
    /// The global merkle root being proved against
    pub merkle_root: Scalar,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidCommitmentsWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidCommitmentsStatement;

    const BP_GENS_CAPACITY: usize = 32768;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_var, witness_commit) = witness.commit_prover(&mut rng, &mut prover).unwrap();

        let nullifier_var = prover.commit_public(statement.nullifier);
        let merkle_root_var = prover.commit_public(statement.merkle_root);

        // Apply the constraints
        ValidCommitments::circuit(witness_var, merkle_root_var, nullifier_var, &mut prover)
            .map_err(ProverError::R1CS)?;

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_commit, proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

        let nullifier_var = verifier.commit_public(statement.nullifier);
        let merkle_root_var = verifier.commit_public(statement.merkle_root);

        // Apply the constraints
        ValidCommitments::circuit(witness_var, merkle_root_var, nullifier_var, &mut verifier)
            .map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
