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
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{
        deserialize_array,
        fee::{CommittedFee, Fee, FeeVar},
        keychain::{CommittedPublicKeyChain, PublicKeyChain, PublicKeyChainVar},
        serialize_array,
    },
    zk_gadgets::poseidon::PoseidonHashGadget,
    CommitVerifier, CommitWitness, SingleProverCircuit, MAX_BALANCES, MAX_FEES, MAX_ORDERS,
};

/// The number of zero Scalars to use when representing an empty balance
/// One for the mint, one for the amount
const BALANCE_ZEROS: usize = 2;
/// The number of zero Scalars to use when representing an empty order
/// zero'd fields are the two mints, the side, the amount, and the price
const ORDER_ZEROS: usize = 5;

/// A type alias for an instantiation of this circuit with default generics
pub type ValidWalletCreateDefault = ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuitry for the valid wallet create statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreate<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES * BALANCE_ZEROS + MAX_ORDERS * ORDER_ZEROS]: Sized,
{
    /// Applies constraints to the constraint system specifying the statement of
    /// VALID WALLET CREATE
    fn circuit<CS>(
        cs: &mut CS,
        expected_commit: Variable,
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
        hasher.batch_absorb(&zeros, cs)?;

        // Hash the fees into the state
        for fee in witness.fees.iter() {
            hasher.batch_absorb(
                &[
                    fee.settle_key.into(),
                    fee.gas_addr.into(),
                    fee.gas_token_amount.into(),
                    fee.percentage_fee.repr.clone(),
                ],
                cs,
            )?;
        }

        // Hash the keys into the state
        let mut key_vars = witness.keys.pk_root.words();
        key_vars.push(witness.keys.pk_match.into());
        key_vars.push(witness.keys.pk_settle.into());
        key_vars.push(witness.keys.pk_view.into());

        hasher.batch_absorb(&key_vars, cs)?;
        hasher.absorb(witness.wallet_randomness, cs)?;

        // Enforce that the result is equal to the expected commitment
        hasher.constrained_squeeze(expected_commit, cs)?;
        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness for the VALID WALLET CREATE statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreateWitness<const MAX_FEES: usize> {
    /// The fees to initialize the wallet with; may be nonzero
    pub fees: [Fee; MAX_FEES],
    /// The keys used to authenticate operations on the wallet
    pub keys: PublicKeyChain,
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomness: Scalar,
}

/// The committed witness for the VALID WALLET CREATE proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletCreateCommitment<const MAX_FEES: usize> {
    /// The fees to initialize the wallet with; may be nonzero
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub fees: [CommittedFee; MAX_FEES],
    /// The keys used to authenticate operations on the wallet
    pub keys: CommittedPublicKeyChain,
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomness: CompressedRistretto,
}

/// The proof-system allocated witness for VALID WALLET CREATE
#[derive(Clone, Debug)]
pub struct ValidWalletCreateVar<const MAX_FEES: usize> {
    /// The fees to initialize the wallet with; may be nonzero
    pub fees: [FeeVar; MAX_FEES],
    /// The keys used to authenticate operations on the wallet
    pub keys: PublicKeyChainVar,
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomness: Variable,
}

impl<const MAX_FEES: usize> CommitWitness for ValidWalletCreateWitness<MAX_FEES> {
    type CommitType = ValidWalletCreateCommitment<MAX_FEES>;
    type VarType = ValidWalletCreateVar<MAX_FEES>;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (fee_vars, fee_commitments): (Vec<FeeVar>, Vec<CommittedFee>) = self
            .fees
            .iter()
            .map(|fee| fee.commit_witness(rng, prover).unwrap())
            .unzip();
        let (keychain_var, keychain_comm) = self.keys.commit_witness(rng, prover).unwrap();

        let (randomness_comm, randomness_var) =
            prover.commit(self.wallet_randomness, Scalar::random(rng));

        Ok((
            ValidWalletCreateVar {
                fees: fee_vars.try_into().unwrap(),
                keys: keychain_var,
                wallet_randomness: randomness_var,
            },
            ValidWalletCreateCommitment {
                fees: fee_commitments.try_into().unwrap(),
                keys: keychain_comm,
                wallet_randomness: randomness_comm,
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

        let keychain_var = self.keys.commit_verifier(verifier).unwrap();
        let randomness_var = verifier.commit(self.wallet_randomness);

        Ok(ValidWalletCreateVar {
            fees: fee_vars.try_into().unwrap(),
            keys: keychain_var,
            wallet_randomness: randomness_var,
        })
    }
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The parameterization for the VALID WALLET CREATE statement
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletCreateStatement {
    /// The expected commitment of the newly created wallet
    pub wallet_commitment: Scalar,
}

// ---------------------
// | Prove/Verify Flow |
// ---------------------

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
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();

        // Commit to the statement
        let wallet_commitment_var = prover.commit_public(statement.wallet_commitment);

        // Apply the constraints
        Self::circuit(&mut prover, wallet_commitment_var, witness_var)
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

        // Apply the constraints
        Self::circuit(&mut verifier, wallet_commitment_var, witness_var)
            .map_err(VerifierError::R1CS)?;

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
mod test_valid_wallet_create {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{
            biguint_to_scalar, prime_field_to_scalar, scalar_to_prime_field, DalekRistrettoField,
        },
        hash::default_poseidon_params,
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use num_bigint::BigUint;
    use rand_core::{CryptoRng, OsRng, RngCore};

    use crate::{
        test_helpers::bulletproof_prove_and_verify, types::fee::Fee,
        zk_circuits::test_helpers::PUBLIC_KEYS, zk_gadgets::fixed_point::FixedPoint,
    };

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
            settle_key: BigUint::from(rng.next_u64()),
            gas_addr: BigUint::from(rng.next_u64()),
            gas_token_amount: rng.next_u64(),
            percentage_fee: FixedPoint::from(0.01),
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
            arkworks_hasher.absorb(&scalar_to_prime_field(&biguint_to_scalar(&fee.settle_key)));
            arkworks_hasher.absorb(&scalar_to_prime_field(&biguint_to_scalar(&fee.gas_addr)));
            arkworks_hasher.absorb(&DalekRistrettoField::from(fee.gas_token_amount));
            arkworks_hasher.absorb(&DalekRistrettoField::from(Into::<u64>::into(
                fee.percentage_fee,
            )));
        }

        // Absorb the public keys into the hasher state
        let pk_root_words: Vec<Scalar> = witness.keys.pk_root.clone().into();
        arkworks_hasher.absorb(
            &pk_root_words
                .iter()
                .map(scalar_to_prime_field)
                .collect_vec(),
        );
        arkworks_hasher.absorb(&scalar_to_prime_field(&witness.keys.pk_match.into()));
        arkworks_hasher.absorb(&scalar_to_prime_field(&witness.keys.pk_settle.into()));
        arkworks_hasher.absorb(&scalar_to_prime_field(&witness.keys.pk_view.into()));

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
            keys: PUBLIC_KEYS.clone(),
            wallet_randomness: Scalar::random(&mut rng),
        };
        let statement = ValidWalletCreateStatement {
            wallet_commitment: compute_commitment(&witness),
        };

        // Prove and verify on a smaller (for testing speed) version of the circuit
        let res = bulletproof_prove_and_verify::<
            ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement);
        assert!(res.is_ok());
    }
}
