//! Defines the VALID WALLET CREATE circuit that proves that a committed
//! wallet is a wallet of all zero values, i.e. empty orders, balances,
//! and fees
//!
//! The user proves this statement to bootstrap into the system with a fresh
//! wallet that may be deposited into.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.1
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
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::fee::{CommittedFee, Fee, FeeVar},
    zk_gadgets::poseidon::PoseidonHashGadget,
    CommitProver, CommitVerifier, SingleProverCircuit, MAX_BALANCES, MAX_FEES, MAX_ORDERS,
};

/// The number of zero Scalars to use when representing an empty balance
/// One for the mint, one for the amount
const BALANCE_ZEROS: usize = 2;
/// The number of zero Scalars to use when representing an empty order
/// zero'd fields are the two mints, the side, the amount, and the price
const ORDER_ZEROS: usize = 5;

/// A type alias for an instantiation of this circuit with default generics
pub type ValidWalletCreateDefault = ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// The circuitry for the valid wallet create statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreate<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {}

#[allow(unused)]
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES * BALANCE_ZEROS + MAX_ORDERS * ORDER_ZEROS]: Sized,
{
    /// Applies constraints to the constraint system specifying the statement of
    /// VALID WALLET CREATE
    fn apply_constraints<CS>(
        cs: &mut CS,
        expected_commit: Variable,
        wallet_ciphertext: Vec<Variable>,
        witness: ValidWalletCreateVar<MAX_FEES>,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
    {
        // Check that the commitment is to an empty wallet with the given randomness
        // keys, and fees
        Self::check_commitment(cs, expected_commit, witness)?;
        Ok(())
    }

    /// Validates
    fn check_commitment<CS>(
        cs: &mut CS,
        expected_commit: Variable,
        witness: ValidWalletCreateVar<MAX_FEES>,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
    {
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        // This wallet should have empty orders and balances, hash zeros into the state
        // to represent an empty orders list
        let zeros = [Scalar::zero(); MAX_BALANCES * BALANCE_ZEROS + MAX_ORDERS * ORDER_ZEROS];
        hasher.batch_absorb(cs, &zeros)?;

        // Hash the fees into the state
        for fee in witness.fees.iter() {
            hasher.batch_absorb(
                cs,
                &[
                    fee.settle_key,
                    fee.gas_addr,
                    fee.gas_token_amount,
                    fee.percentage_fee,
                ],
            )?;
        }

        // Hash the keys into the state
        hasher.batch_absorb(
            cs,
            &[
                witness.root_public_key,
                witness.match_public_key,
                witness.settle_public_key,
                witness.view_public_key,
            ],
        )?;
        hasher.absorb(cs, witness.wallet_randomness)?;

        // Enforce that the result is equal to the expected commitment
        hasher.constrained_squeeze(cs, expected_commit)?;
        Ok(())
    }
}

/// The parameterization for the VALID WALLET CREATE statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreateStatement {
    /// The expected commitment of the newly created wallet
    pub wallet_commitment: Scalar,
    /// The ElGamal encryption of the wallet under the view key
    pub wallet_ciphertext: Vec<Scalar>,
}

/// The witness for the VALID WALLET CREATE statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreateWitness<const MAX_FEES: usize> {
    /// The fees to initialize the wallet with; may be nonzero
    pub fees: [Fee; MAX_FEES],
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomness: Scalar,
    /// The root secret key, used to derive all fine-grained permissioned keys
    pub root_secret_key: Scalar,
    /// The root public key
    pub root_public_key: Scalar,
    /// The match secret key, knowing this key gives an actor permission to match orders
    pub match_secret_key: Scalar,
    /// The match public key
    pub match_public_key: Scalar,
    /// The settle secret key, knowing this key gives an actor permission to settle matches
    pub settle_secret_key: Scalar,
    /// The settle public key
    pub settle_public_key: Scalar,
    /// The view secret key, knowing this key gives an actor permission to view the wallet
    pub view_secret_key: Scalar,
    /// The view public key
    pub view_public_key: Scalar,
}

/// The committed witness for the VALID WALLET CREATE proof
#[derive(Clone, Debug)]
pub struct ValidWalletCreateCommitment<const MAX_FEES: usize> {
    /// The fees to initialize the wallet with; may be nonzero
    pub fees: [CommittedFee; MAX_FEES],
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomness: CompressedRistretto,
    /// The root secret key, used to derive all fine-grained permissioned keys
    pub root_secret_key: CompressedRistretto,
    /// The root public key
    pub root_public_key: CompressedRistretto,
    /// The match secret key, knowing this key gives an actor permission to match orders
    pub match_secret_key: CompressedRistretto,
    /// The match public key
    pub match_public_key: CompressedRistretto,
    /// The settle secret key, knowing this key gives an actor permission to settle matches
    pub settle_secret_key: CompressedRistretto,
    /// The settle public key
    pub settle_public_key: CompressedRistretto,
    /// The view secret key, knowing this key gives an actor permission to view the wallet
    pub view_secret_key: CompressedRistretto,
    /// The view public key
    pub view_public_key: CompressedRistretto,
}

/// The proof-system allocated witness for VALID WALLET CREATE
#[derive(Clone, Debug)]
pub struct ValidWalletCreateVar<const MAX_FEES: usize> {
    /// The fees to initialize the wallet with; may be nonzero
    pub fees: [FeeVar; MAX_FEES],
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomness: Variable,
    /// The root secret key, used to derive all fine-grained permissioned keys
    pub root_secret_key: Variable,
    /// The root public key
    pub root_public_key: Variable,
    /// The match secret key, knowing this key gives an actor permission to match orders
    pub match_secret_key: Variable,
    /// The match public key
    pub match_public_key: Variable,
    /// The settle secret key, knowing this key gives an actor permission to settle matches
    pub settle_secret_key: Variable,
    /// The settle public key
    pub settle_public_key: Variable,
    /// The view secret key, knowing this key gives an actor permission to view the wallet
    pub view_secret_key: Variable,
    /// The view public key
    pub view_public_key: Variable,
}

impl<const MAX_FEES: usize> CommitProver for ValidWalletCreateWitness<MAX_FEES> {
    type CommitType = ValidWalletCreateCommitment<MAX_FEES>;
    type VarType = ValidWalletCreateVar<MAX_FEES>;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (fee_vars, fee_commitments): (Vec<FeeVar>, Vec<CommittedFee>) = self
            .fees
            .iter()
            .map(|fee| fee.commit_prover(rng, prover).unwrap())
            .unzip();

        let (randomness_comm, randomness_var) =
            prover.commit(self.wallet_randomness, Scalar::random(rng));
        let (sk_root_comm, sk_root_var) = prover.commit(self.root_secret_key, Scalar::random(rng));
        let (pk_root_comm, pk_root_var) = prover.commit(self.root_public_key, Scalar::random(rng));
        let (sk_match_comm, sk_match_var) =
            prover.commit(self.match_secret_key, Scalar::random(rng));
        let (pk_match_comm, pk_match_var) =
            prover.commit(self.match_public_key, Scalar::random(rng));
        let (sk_settle_comm, sk_settle_var) =
            prover.commit(self.settle_secret_key, Scalar::random(rng));
        let (pk_settle_comm, pk_settle_var) =
            prover.commit(self.settle_public_key, Scalar::random(rng));
        let (sk_view_comm, sk_view_var) = prover.commit(self.view_secret_key, Scalar::random(rng));
        let (pk_view_comm, pk_view_var) = prover.commit(self.view_public_key, Scalar::random(rng));

        Ok((
            ValidWalletCreateVar {
                fees: fee_vars.try_into().unwrap(),
                wallet_randomness: randomness_var,
                root_secret_key: sk_root_var,
                root_public_key: pk_root_var,
                match_secret_key: sk_match_var,
                match_public_key: pk_match_var,
                settle_secret_key: sk_settle_var,
                settle_public_key: pk_settle_var,
                view_secret_key: sk_view_var,
                view_public_key: pk_view_var,
            },
            ValidWalletCreateCommitment {
                fees: fee_commitments.try_into().unwrap(),
                wallet_randomness: randomness_comm,
                root_secret_key: sk_root_comm,
                root_public_key: pk_root_comm,
                match_secret_key: sk_match_comm,
                match_public_key: pk_match_comm,
                settle_secret_key: sk_settle_comm,
                settle_public_key: pk_settle_comm,
                view_secret_key: sk_view_comm,
                view_public_key: pk_view_comm,
            },
        ))
    }
}

impl<const MAX_FEES: usize> CommitVerifier for ValidWalletCreateCommitment<MAX_FEES> {
    type VarType = ValidWalletCreateVar<MAX_FEES>;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let fee_vars = self
            .fees
            .iter()
            .map(|fee| fee.commit_verifier(verifier).unwrap())
            .collect_vec();

        let randomness_var = verifier.commit(self.wallet_randomness);
        let sk_root_var = verifier.commit(self.root_secret_key);
        let pk_root_var = verifier.commit(self.root_public_key);
        let sk_match_var = verifier.commit(self.match_secret_key);
        let pk_match_var = verifier.commit(self.match_public_key);
        let sk_settle_var = verifier.commit(self.settle_secret_key);
        let pk_settle_var = verifier.commit(self.settle_public_key);
        let sk_view_var = verifier.commit(self.view_secret_key);
        let pk_view_var = verifier.commit(self.view_public_key);

        Ok(ValidWalletCreateVar {
            fees: fee_vars.try_into().unwrap(),
            wallet_randomness: randomness_var,
            root_secret_key: sk_root_var,
            root_public_key: pk_root_var,
            match_secret_key: sk_match_var,
            match_public_key: pk_match_var,
            settle_secret_key: sk_settle_var,
            settle_public_key: pk_settle_var,
            view_secret_key: sk_view_var,
            view_public_key: pk_view_var,
        })
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES * BALANCE_ZEROS + MAX_ORDERS * ORDER_ZEROS]: Sized,
{
    type Statement = ValidWalletCreateStatement;
    type Witness = ValidWalletCreateWitness<MAX_FEES>;
    type WitnessCommitment = ValidWalletCreateCommitment<MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 10000;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

        // Commit to the statement
        let wallet_commitment_var = prover.commit_public(statement.wallet_commitment);
        let wallet_ciphertext_vars = statement
            .wallet_ciphertext
            .iter()
            .map(|felt| prover.commit_public(*felt))
            .collect_vec();

        // Apply the constraints
        Self::apply_constraints(
            &mut prover,
            wallet_commitment_var,
            wallet_ciphertext_vars,
            witness_var,
        )
        .map_err(ProverError::R1CS)?;

        // Prove the statement
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
        // Commit to the witness
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

        // Commit to the statement
        let wallet_commitment_var = verifier.commit_public(statement.wallet_commitment);
        let wallet_ciphertext_vars = statement
            .wallet_ciphertext
            .iter()
            .map(|felt| verifier.commit_public(*felt))
            .collect_vec();

        // Apply the constraints
        Self::apply_constraints(
            &mut verifier,
            wallet_commitment_var,
            wallet_ciphertext_vars,
            witness_var,
        )
        .map_err(VerifierError::R1CS)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

#[cfg(test)]
mod test_valid_wallet_create {
    use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{
            bigint_to_scalar, prime_field_to_scalar, scalar_to_prime_field, DalekRistrettoField,
        },
        hash::default_poseidon_params,
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use num_bigint::BigInt;
    use rand_core::{CryptoRng, OsRng, RngCore};

    use crate::{test_helpers::bulletproof_prove_and_verify, types::fee::Fee};

    use super::{
        ValidWalletCreate, ValidWalletCreateStatement, ValidWalletCreateWitness, BALANCE_ZEROS,
        ORDER_ZEROS,
    };

    /// Set to smaller values for testing
    /// The maximum balances allowed in a wallet
    const MAX_BALANCES: usize = 2;
    /// The maximum orders allowed in a wallet
    const MAX_ORDERS: usize = 2;
    /// The maximum fees allowed in a wallet
    const MAX_FEES: usize = 2;

    /// Generates a random fee for testing
    fn random_fee<R: RngCore + CryptoRng>(rng: &mut R) -> Fee {
        Fee {
            settle_key: BigInt::from(rng.next_u64()),
            gas_addr: BigInt::from(rng.next_u64()),
            gas_token_amount: rng.next_u64(),
            percentage_fee: rng.next_u64(),
        }
    }

    /// Compute the commitment to an empty wallet given a witness variable
    fn compute_commitment(witness: &ValidWalletCreateWitness<MAX_FEES>) -> Scalar {
        let arkworks_params = default_poseidon_params();
        let mut arkworks_hasher = PoseidonSponge::new(&arkworks_params);

        // Hash zeros into the sponge for each order and balance
        for _ in 0..(MAX_ORDERS * ORDER_ZEROS + MAX_BALANCES * BALANCE_ZEROS) {
            arkworks_hasher.absorb(&DalekRistrettoField::from(0u64));
        }

        // Absorb the fees into the hasher state
        for fee in witness.fees.iter() {
            arkworks_hasher.absorb(&scalar_to_prime_field(&bigint_to_scalar(&fee.settle_key)));
            arkworks_hasher.absorb(&scalar_to_prime_field(&bigint_to_scalar(&fee.gas_addr)));
            arkworks_hasher.absorb(&DalekRistrettoField::from(fee.gas_token_amount));
            arkworks_hasher.absorb(&DalekRistrettoField::from(fee.percentage_fee));
        }

        // Absorb the public keys into the hasher state
        arkworks_hasher.absorb(&scalar_to_prime_field(&witness.root_public_key));
        arkworks_hasher.absorb(&scalar_to_prime_field(&witness.match_public_key));
        arkworks_hasher.absorb(&scalar_to_prime_field(&witness.settle_public_key));
        arkworks_hasher.absorb(&scalar_to_prime_field(&witness.view_public_key));

        // Absorb the wallet randomness into the hasher state
        arkworks_hasher.absorb(&scalar_to_prime_field(&witness.wallet_randomness));

        prime_field_to_scalar::<DalekRistrettoField>(
            &arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0],
        )
    }

    /// Tests the VALID WALLET CREATE with a valid witness (empty wallet)
    #[test]
    fn test_valid_wallet() {
        let mut rng = OsRng {};
        let n_fees = MAX_FEES;
        let fees = (0..n_fees).map(|_| random_fee(&mut rng)).collect_vec();

        let witness = ValidWalletCreateWitness {
            fees: fees.try_into().unwrap(),
            wallet_randomness: Scalar::random(&mut rng),
            root_secret_key: Scalar::random(&mut rng),
            root_public_key: Scalar::random(&mut rng),
            match_secret_key: Scalar::random(&mut rng),
            match_public_key: Scalar::random(&mut rng),
            settle_secret_key: Scalar::random(&mut rng),
            settle_public_key: Scalar::random(&mut rng),
            view_secret_key: Scalar::random(&mut rng),
            view_public_key: Scalar::random(&mut rng),
        };
        let statement = ValidWalletCreateStatement {
            wallet_ciphertext: Vec::new(),
            wallet_commitment: compute_commitment(&witness),
        };

        // Prove and verify on a smaller (for testing speed) version of the circuit
        let res = bulletproof_prove_and_verify::<
            ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement);
        assert!(res.is_ok());
    }
}
