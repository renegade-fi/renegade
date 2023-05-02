//! Defines the `VALID REBLIND` circuit, which proves:
//!     1. State inclusion validity of the input
//!     2. CSPRNG execution integrity to sample new wallet blinders
//!     3. Re-blinding of a wallet using the sampled blinders

use curve25519_dalek::ristretto::CompressedRistretto;
use itertools::{izip, Itertools};
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{
        keychain::SecretIdentificationKey,
        wallet::{
            Nullifier, WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar,
            WalletShareCommitment,
        },
    },
    zk_gadgets::{
        commitments::{NullifierGadget, WalletShareCommitGadget},
        merkle::{
            MerkleOpening, MerkleOpeningCommitment, MerkleOpeningVar, MerkleRoot,
            PoseidonMerkleHashGadget,
        },
        poseidon::PoseidonHashGadget,
    },
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit definition for `VALID REBLIND`
pub struct ValidReblind<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidReblind<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Apply the constraints of `VALID REBLIND` to the given constraint system
    pub fn circuit<CS: RandomizableConstraintSystem>(
        statement: ValidReblindStatementVar,
        mut witness: ValidReblindWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // -- State Validity -- //

        // Verify the opening of the old wallet's private secret shares to the Merkle root
        let old_private_shares_comm = WalletShareCommitGadget::compute_commitment(
            &witness.original_wallet_private_shares,
            cs,
        )?;
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            old_private_shares_comm.clone(),
            witness.private_share_opening,
            statement.merkle_root.into(),
            cs,
        )?;

        // Verify the opening of the old wallet's public secret shares to the Merkle root
        let old_public_shares_comm = WalletShareCommitGadget::compute_commitment(
            &witness.original_wallet_private_shares,
            cs,
        )?;
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            old_public_shares_comm.clone(),
            witness.public_share_opening,
            statement.merkle_root.into(),
            cs,
        )?;

        // Verify the nullifier of the old wallet's private shares is correctly computed
        let recovered_old_blinder = witness.original_wallet_private_shares.blinder.clone()
            + witness.original_wallet_public_shares.blinder.clone();
        let old_private_nullifier = NullifierGadget::wallet_shares_nullifier(
            old_private_shares_comm,
            recovered_old_blinder.clone(),
            cs,
        )?;
        cs.constrain(old_private_nullifier - statement.original_private_share_nullifier);

        // Verify the nullifier of the old wallet's public shares is correctly computed
        let old_public_nullifier = NullifierGadget::wallet_shares_nullifier(
            old_public_shares_comm,
            recovered_old_blinder.clone(),
            cs,
        )?;
        cs.constrain(old_public_nullifier - statement.original_public_share_nullifier);

        // Verify the commitment to the new wallet's private shares
        let reblinded_private_shares_commitment = WalletShareCommitGadget::compute_commitment(
            &witness.reblinded_wallet_private_shares,
            cs,
        )?;
        cs.constrain(
            statement.reblinded_private_share_commitment - reblinded_private_shares_commitment,
        );

        // -- Authorization -- //

        // Recover the old wallet
        witness
            .original_wallet_public_shares
            .unblind(recovered_old_blinder);
        let old_wallet = witness.original_wallet_private_shares.clone()
            + witness.original_wallet_public_shares.clone();

        // Check that the hash of `sk_match` is the wallet's `pk_match`
        let poseidon_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(poseidon_params);
        hasher.hash(&[witness.sk_match.into()], old_wallet.keys.pk_match, cs)?;

        // -- Reblind Operation -- //

        // Reconstruct the new wallet from secret shares
        Self::validate_reblind(
            witness.original_wallet_private_shares,
            witness.original_wallet_public_shares,
            witness.reblinded_wallet_private_shares,
            witness.reblinded_wallet_public_shares,
            cs,
        )?;

        Ok(())
    }

    /// Validates that the given reblinded wallet is the correct reblinding of the old wallet
    ///
    /// There are two CSPRNG streams used in reblinding a wallet:
    ///     1. The `blinder` stream, from this stream we sample the new wallet blinder $r$, and its
    ///        private secret share $r_1$. The public secret share is then $r_2 = r - r_1$.
    ///     2. The `share` stream, from this stream we sample secret shares used for individual wallet
    ///        elements. That is for a given wallet element w[i], we sample $r^{share}_i$ as the private
    ///        secret share. The public secret share is then $w[i] + r - r^{share}_i$. Note that this
    ///        secret share is blinded using the blinder from step 1.
    ///
    /// These CSPRNGs are implemented as chained Poseidon hashes of a secret seed. We seed a CSPRNG
    /// with the last sampled value from the old wallet. For the `blinder` stream this is $r_1$ of the
    /// old wallet. For the secret share stream, this is the last private share in the serialized wallet
    fn validate_reblind<CS: RandomizableConstraintSystem>(
        old_private_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        old_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        reblinded_private_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        reblinded_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // The seeds to the `blinder` CSPRNG
        let old_private_blinder_share = old_private_shares.blinder.clone();
        let old_blinder = old_private_shares.blinder.clone() + old_public_shares.blinder.clone();

        let reblinded_private_blinder_share = reblinded_private_shares.blinder.clone();
        let reblinded_public_blinder_share = reblinded_public_shares.blinder.clone();

        // Serialize the shares
        let old_private_shares_ser: Vec<LinearCombination> = old_private_shares.into();
        let old_public_shares_ser: Vec<LinearCombination> = old_public_shares.into();
        let reblinded_private_shares_ser: Vec<LinearCombination> = reblinded_private_shares.into();
        let reblinded_public_shares_ser: Vec<LinearCombination> = reblinded_public_shares.into();

        // -- CSPRNG Samples -- //

        // Sample the wallet blinder and its public share from the blinder CSPRNG
        let mut blinder_samples =
            Self::sample_csprng(old_private_blinder_share, 2 /* num_vals */, cs)?;
        let new_blinder = blinder_samples.pop().unwrap();
        let new_blinder_private_share = blinder_samples.pop().unwrap();

        // Sample secret shares for individual wallet elements, we sample for n - 1 shares because
        // the wallet serialization includes the wallet blinder, which was resampled separately in
        // the previous step
        //
        // As well, we seed the CSPRNG with the second to last share in the old wallet, again because
        // the wallet blinder comes from a separate stream of randomness
        let serialized_length = old_private_shares_ser.len();
        let share_samples = Self::sample_csprng(
            old_private_shares_ser[serialized_length - 2].clone(),
            serialized_length - 1,
            cs,
        )?;

        // -- Private Shares -- //

        // Enforce that all the private shares of the reblinded wallet are exactly the sampled secret shares
        cs.constrain(reblinded_private_blinder_share - new_blinder_private_share.clone());
        for (private_share, sampled_blinder) in reblinded_private_shares_ser
            .iter()
            .take(serialized_length - 1)
            .cloned()
            .zip_eq(share_samples.iter().cloned())
        {
            cs.constrain(private_share - sampled_blinder)
        }

        // -- Public Shares -- //

        // Constrain that the public blinder share is equal to $r - r_1$
        cs.constrain(
            reblinded_public_blinder_share - (new_blinder.clone() - new_blinder_private_share),
        );
        // Enforce that each public share is the correct reblinding
        for (public_share, old_private_share, old_public_share, new_private_share) in izip!(
            reblinded_public_shares_ser.iter().cloned(),
            old_private_shares_ser.iter().cloned(),
            old_public_shares_ser.iter().cloned(),
            share_samples.iter().cloned(),
        ) {
            // Adding the two old shares gives the blinded share w[i] + r_old, we then subtract the old blinder,
            // and add the new one in to get the newly blinded value w[i] + r_new. Finally, subtract the new private
            // share to arrive at the new public share
            let old_blinded_value = old_private_share + old_public_share;
            let new_blinded_value = old_blinded_value + new_blinder.clone() - old_blinder.clone();
            let new_public_share = new_blinded_value - new_private_share;

            cs.constrain(public_share - new_public_share);
        }

        Ok(())
    }

    /// Samples values from a chained Poseidon hash CSPRNG, seeded with the given
    /// input
    fn sample_csprng<L, CS>(
        seed: L,
        num_vals: usize,
        cs: &mut CS,
    ) -> Result<Vec<LinearCombination>, R1CSError>
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        let mut seed_lc: LinearCombination = seed.into();
        let mut values = Vec::with_capacity(num_vals);

        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hasher_params);

        // Chained hash of the seed value
        for _ in 0..num_vals {
            // Absorb the seed and then squeeze the next element
            hasher.absorb(seed_lc, cs)?;
            seed_lc = hasher.squeeze(cs)?;

            values.push(seed_lc.clone());

            // Reset the hasher state; we want the CSPRNG chain to be stateless, this includes
            // the internal state of the Poseidon sponge
            hasher.reset_state();
        }

        Ok(values)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for VALID REBLIND
#[derive(Clone, Debug)]
pub struct ValidReblindWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the original wallet
    pub original_wallet_private_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the original wallet
    pub original_wallet_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The private secret shares of the reblinded wallet
    pub reblinded_wallet_private_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the reblinded wallet
    pub reblinded_wallet_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The merkle opening of the original wallet's private shares
    pub private_share_opening: MerkleOpening,
    /// The merkle opening of the original wallet's public shares
    pub public_share_opening: MerkleOpening,
    /// The secret match key corresponding to the wallet's public match key
    pub sk_match: SecretIdentificationKey,
}

/// The witness type for VALID REBLIND, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidReblindWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the original wallet
    pub original_wallet_private_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the original wallet
    pub original_wallet_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The private secret shares of the reblinded wallet
    pub reblinded_wallet_private_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the reblinded wallet
    pub reblinded_wallet_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The merkle opening of the original wallet's private shares
    pub private_share_opening: MerkleOpeningVar,
    /// The merkle opening of the original wallet's public shares
    pub public_share_opening: MerkleOpeningVar,
    /// The secret match key corresponding to the wallet's public match key
    pub sk_match: Variable,
}

/// A commitment to the witness type for VALID REBLIND,
/// allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidReblindWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the original wallet
    pub original_wallet_private_shares:
        WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the original wallet
    pub original_wallet_public_shares:
        WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The private secret shares of the reblinded wallet
    pub reblinded_wallet_private_shares:
        WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the reblinded wallet
    pub reblinded_wallet_public_shares:
        WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The merkle opening of the original wallet's private shares
    pub private_share_opening: MerkleOpeningCommitment,
    /// The merkle opening of the original wallet's public shares
    pub public_share_opening: MerkleOpeningCommitment,
    /// The secret match key corresponding to the wallet's public match key
    pub sk_match: CompressedRistretto,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidReblindWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidReblindWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut mpc_bulletproof::r1cs::Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (original_private_share_vars, original_private_share_comms) = self
            .original_wallet_private_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (original_public_share_vars, original_public_share_comms) = self
            .original_wallet_public_shares
            .commit_witness(rng, prover)
            .unwrap();

        let (reblinded_private_share_vars, reblinded_private_share_comms) = self
            .reblinded_wallet_private_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (reblinded_public_share_vars, reblinded_public_share_comms) = self
            .reblinded_wallet_public_shares
            .commit_witness(rng, prover)
            .unwrap();

        let (private_opening_var, private_opening_comm) = self
            .private_share_opening
            .commit_witness(rng, prover)
            .unwrap();
        let (public_opening_var, public_opening_comm) = self
            .public_share_opening
            .commit_witness(rng, prover)
            .unwrap();

        let (sk_match_var, sk_match_comm) = self.sk_match.commit_witness(rng, prover).unwrap();

        Ok((
            ValidReblindWitnessVar {
                original_wallet_private_shares: original_private_share_vars,
                original_wallet_public_shares: original_public_share_vars,
                reblinded_wallet_private_shares: reblinded_private_share_vars,
                reblinded_wallet_public_shares: reblinded_public_share_vars,
                private_share_opening: private_opening_var,
                public_share_opening: public_opening_var,
                sk_match: sk_match_var,
            },
            ValidReblindWitnessCommitment {
                original_wallet_private_shares: original_private_share_comms,
                original_wallet_public_shares: original_public_share_comms,
                reblinded_wallet_private_shares: reblinded_private_share_comms,
                reblinded_wallet_public_shares: reblinded_public_share_comms,
                private_share_opening: private_opening_comm,
                public_share_opening: public_opening_comm,
                sk_match: sk_match_comm,
            },
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for ValidReblindWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidReblindWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let original_private_share_vars = self
            .original_wallet_private_shares
            .commit_verifier(verifier)
            .unwrap();
        let original_public_share_vars = self
            .original_wallet_public_shares
            .commit_verifier(verifier)
            .unwrap();

        let reblinded_private_share_vars = self
            .reblinded_wallet_private_shares
            .commit_verifier(verifier)
            .unwrap();
        let reblinded_public_share_vars = self
            .reblinded_wallet_public_shares
            .commit_verifier(verifier)
            .unwrap();

        let private_opening_var = self
            .private_share_opening
            .commit_verifier(verifier)
            .unwrap();
        let public_opening_var = self.public_share_opening.commit_verifier(verifier).unwrap();

        let sk_match_var = self.sk_match.commit_verifier(verifier).unwrap();

        Ok(ValidReblindWitnessVar {
            original_wallet_private_shares: original_private_share_vars,
            original_wallet_public_shares: original_public_share_vars,
            reblinded_wallet_private_shares: reblinded_private_share_vars,
            reblinded_wallet_public_shares: reblinded_public_share_vars,
            private_share_opening: private_opening_var,
            public_share_opening: public_opening_var,
            sk_match: sk_match_var,
        })
    }
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for VALID REBLIND
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidReblindStatement {
    /// The nullifier of the original wallet's private secret shares
    pub original_private_share_nullifier: Nullifier,
    /// The nullifier of the original wallet's public secret shares
    pub original_public_share_nullifier: Nullifier,
    /// A commitment to the private secret shares of the reblinded wallet
    pub reblinded_private_share_commitment: WalletShareCommitment,
    /// The global merkle root to prove inclusion into
    pub merkle_root: MerkleRoot,
}

/// The statement type for VALID REBLIND, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidReblindStatementVar {
    /// The nullifier of the original wallet's private secret shares
    pub original_private_share_nullifier: Variable,
    /// The nullifier of the original wallet's public secret shares
    pub original_public_share_nullifier: Variable,
    /// A commitment to the private secret shares of the reblinded wallet
    pub reblinded_private_share_commitment: Variable,
    /// The global merkle root to prove inclusion into
    pub merkle_root: Variable,
}

impl CommitPublic for ValidReblindStatement {
    type VarType = ValidReblindStatementVar;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let private_share_nullifier_var = self
            .original_private_share_nullifier
            .commit_public(cs)
            .unwrap();
        let public_share_nullifier_var = self
            .original_public_share_nullifier
            .commit_public(cs)
            .unwrap();
        let private_share_commitment_var = self
            .reblinded_private_share_commitment
            .commit_public(cs)
            .unwrap();
        let merkle_root_var = self.merkle_root.commit_public(cs).unwrap();

        Ok(ValidReblindStatementVar {
            original_private_share_nullifier: private_share_nullifier_var,
            original_public_share_nullifier: public_share_nullifier_var,
            reblinded_private_share_commitment: private_share_commitment_var,
            merkle_root: merkle_root_var,
        })
    }
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidReblind<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidReblindWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidReblindStatement;

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
        Self::circuit(statement_var, witness_var, &mut prover).map_err(ProverError::R1CS)?;

        // Prove the circuit
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

        // Apply the constraints
        Self::circuit(statement_var, witness_var, &mut verifier).map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
