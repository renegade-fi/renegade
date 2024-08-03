//! Defines the `VALID REBLIND` circuit, which proves:
//!     1. State inclusion validity of the input
//!     2. CSPRNG execution integrity to sample new wallet blinders
//!     3. Re-blinding of a wallet using the sampled blinders

use ark_ff::One;
use circuit_macros::circuit_type;
use circuit_types::{
    keychain::SecretIdentificationKey,
    merkle::{MerkleOpening, MerkleRoot},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
    wallet::{Nullifier, WalletShare, WalletShareStateCommitment, WalletShareVar},
    PlonkCircuit,
};
use constants::{Scalar, ScalarField};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use itertools::izip;
use mpc_plonk::errors::PlonkError;
use mpc_relation::{
    errors::CircuitError,
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
    Variable,
};
use serde::{Deserialize, Serialize};

use crate::{
    zk_circuits::valid_commitments::ValidCommitments,
    zk_gadgets::{
        comparators::EqGadget, poseidon::PoseidonHashGadget, wallet_operations::WalletGadget,
    },
    SingleProverCircuit,
};

use super::VALID_REBLIND_COMMITMENTS_LINK;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit definition for `VALID REBLIND`
pub struct ValidReblind<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>;
/// A `VALID REBLIND` circuit with default const generic sizing parameters
pub type SizedValidReblind = ValidReblind<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    ValidReblind<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// Apply the constraints of `VALID REBLIND` to the given constraint system
    pub fn circuit(
        statement: &ValidReblindStatementVar,
        witness: &ValidReblindWitnessVar<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // -- State Validity -- //

        // Verify merkle opening and nullifier
        WalletGadget::validate_wallet_transition(
            &witness.original_wallet_public_shares,
            &witness.original_wallet_private_shares,
            &witness.original_share_opening,
            statement.merkle_root,
            statement.original_shares_nullifier,
            cs,
        )?;

        // Verify the commitment to the new wallet's private shares
        let reblinded_private_shares_commitment =
            WalletGadget::compute_private_commitment(&witness.reblinded_wallet_private_shares, cs)?;
        cs.enforce_equal(
            statement.reblinded_private_share_commitment,
            reblinded_private_shares_commitment,
        )?;

        // -- Authorization -- //

        // We don't need to recover the old wallet, but it's simple to do so and doesn't
        // currently push us over the next power of two constraint boundary
        // TODO: If we need to optimize, we can remove this
        let old_wallet = WalletGadget::wallet_from_shares(
            &witness.original_wallet_public_shares,
            &witness.original_wallet_private_shares,
            cs,
        )?;

        // Check that the hash of `sk_match` is the wallet's `pk_match`
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.hash(&witness.sk_match.to_vars(), old_wallet.keys.pk_match.key, cs)?;

        // -- Reblind Operation -- //

        // Reconstruct the new wallet from secret shares
        Self::validate_reblind(
            &witness.original_wallet_private_shares,
            &witness.original_wallet_public_shares,
            &witness.reblinded_wallet_private_shares,
            &witness.reblinded_wallet_public_shares,
            cs,
        )
    }

    /// Validates that the given reblinded wallet is the correct reblinding of
    /// the old wallet
    ///
    /// There are two CSPRNG streams used in reblinding a wallet:
    ///     1. The `blinder` stream, from this stream we sample the new wallet
    ///        blinder $r$, and its private secret share $r_1$. The public
    ///        secret share is then $r_2 = r - r_1$.
    ///     2. The `share` stream, from this stream we sample secret shares used
    ///        for individual wallet elements. That is for a given wallet
    ///        element w[i], we sample $r^{share}_i$ as the private secret
    ///        share. The public secret share is then $w[i] + r - r^{share}_i$.
    ///        Note that this secret share is blinded using the blinder from
    ///        step 1.
    ///
    /// These CSPRNGs are implemented as chained Poseidon hashes of a secret
    /// seed. We seed a CSPRNG with the last sampled value from the old
    /// wallet. For the `blinder` stream this is $r_1$ of the old wallet.
    /// For the secret share stream, this is the last private share in the
    /// serialized wallet
    fn validate_reblind(
        old_private_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        old_public_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        reblinded_private_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        reblinded_public_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let one = ScalarField::one();

        // -- Private Shares -- //
        let (private_share_samples, new_blinder) = WalletGadget::reblind(old_private_shares, cs)?;
        EqGadget::constrain_eq(reblinded_private_shares, &private_share_samples, cs)?;

        // -- Public Shares -- //

        // Constrain that the public blinder share is equal to $r - r_1$
        let reblinded_public_blinder_share = reblinded_public_shares.blinder;
        cs.lc_gate(
            &[
                reblinded_public_blinder_share,
                new_blinder,
                private_share_samples.blinder,
                cs.zero(),
                cs.zero(), // output
            ],
            &[one, -one, one, one],
        )?;

        // Serialize the shares
        let old_blinder = cs.add(old_private_shares.blinder, old_public_shares.blinder)?;
        let old_private_shares_ser = old_private_shares.to_vars();
        let old_public_shares_ser = old_public_shares.to_vars();
        let reblinded_public_shares_ser = reblinded_public_shares.to_vars();
        let reblinded_private_shares_ser = private_share_samples.to_vars();

        // Enforce that each public share is the correct reblinding
        for (old_private_share, old_public_share, new_private_share, public_share) in izip!(
            old_private_shares_ser.iter(),
            old_public_shares_ser.iter(),
            reblinded_private_shares_ser.iter(),
            reblinded_public_shares_ser.iter(),
        ) {
            // Adding the two old shares gives the blinded share w[i] + r_old,
            // we then subtract the old blinder, and add the new one
            // in to get the newly blinded value w[i] + r_new.
            // Finally, subtract the new private share to arrive at
            // the new public share

            let new_public_share = cs.lc_sum(
                &[
                    *old_private_share,
                    *old_public_share,
                    new_blinder,
                    old_blinder,
                    *new_private_share,
                ],
                &[one, one, one, -one, -one],
            )?;

            cs.enforce_equal(*public_share, new_public_share)?;
        }

        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for VALID REBLIND
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidReblindWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The private secret shares of the original wallet
    pub original_wallet_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The public secret shares of the original wallet
    pub original_wallet_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The private secret shares of the reblinded wallet
    #[link_groups = "valid_reblind_commitments"]
    pub reblinded_wallet_private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The public secret shares of the reblinded wallet
    #[link_groups = "valid_reblind_commitments"]
    pub reblinded_wallet_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The Merkle opening from the commitment to the original wallet's shares
    pub original_share_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The secret match key corresponding to the wallet's public match key
    pub sk_match: SecretIdentificationKey,
}
/// A `VALID REBLIND` witness with default const generic sizing parameters
pub type SizedValidReblindWitness = ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for VALID REBLIND
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidReblindStatement {
    /// The nullifier of the original wallet's secret shares
    pub original_shares_nullifier: Nullifier,
    /// A commitment to the private secret shares of the reblinded wallet
    pub reblinded_private_share_commitment: WalletShareStateCommitment,
    /// The global merkle root to prove inclusion into
    pub merkle_root: MerkleRoot,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MERKLE_HEIGHT: usize>
    SingleProverCircuit for ValidReblind<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Witness = ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;
    type Statement = ValidReblindStatement;

    fn name() -> String {
        format!("Valid Reblind ({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})")
    }

    // VALID REBLIND inherits the group placement from VALID COMMITMENTS for their
    // link group
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let commitments_layout =
            ValidCommitments::<MAX_BALANCES, MAX_ORDERS>::get_circuit_layout()?;
        let shared_layout = commitments_layout.get_group_layout(VALID_REBLIND_COMMITMENTS_LINK);

        Ok(vec![(VALID_REBLIND_COMMITMENTS_LINK.to_string(), Some(shared_layout))])
    }

    fn apply_constraints(
        witness_var: ValidReblindWitnessVar<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
        statement_var: ValidReblindStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        keychain::SecretIdentificationKey,
        native_helpers::{
            compute_wallet_private_share_commitment, compute_wallet_share_commitment,
            compute_wallet_share_nullifier, reblind_wallet,
        },
        wallet::Wallet,
    };

    use crate::zk_circuits::test_helpers::{
        create_multi_opening, create_wallet_shares, MAX_BALANCES, MAX_ORDERS, PRIVATE_KEYS,
    };

    use super::{ValidReblindStatement, ValidReblindWitness};

    /// The height of the Merkle tree used for testing
    const MERKLE_HEIGHT: usize = 3;

    /// A witness type with default size parameters attached
    pub type SizedWitness = ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

    /// Construct a witness and statement for `VALID REBLIND` from a given
    /// wallet
    pub fn construct_witness_statement<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MERKLE_HEIGHT: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
    ) -> (ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>, ValidReblindStatement)
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        // Build shares of the original wallet, then reblind it
        let (old_wallet_private_shares, old_wallet_public_shares) = create_wallet_shares(wallet);
        let (reblinded_private_shares, reblinded_public_shares) =
            reblind_wallet(&old_wallet_private_shares, wallet);

        // Create Merkle openings for the old shares
        let original_shares_commitment =
            compute_wallet_share_commitment(&old_wallet_public_shares, &old_wallet_private_shares);

        let (merkle_root, mut opening) =
            create_multi_opening::<MERKLE_HEIGHT>(&[original_shares_commitment]);
        let original_share_opening = opening.pop().unwrap();

        // Compute nullifiers for the old shares
        let original_shares_nullifier =
            compute_wallet_share_nullifier(original_shares_commitment, wallet.blinder);

        // Compute a commitment to the new private share
        let new_private_commitment =
            compute_wallet_private_share_commitment(&reblinded_private_shares);

        let witness = ValidReblindWitness {
            original_wallet_private_shares: old_wallet_private_shares,
            original_wallet_public_shares: old_wallet_public_shares,
            reblinded_wallet_private_shares: reblinded_private_shares,
            reblinded_wallet_public_shares: reblinded_public_shares,
            original_share_opening,
            sk_match: SecretIdentificationKey { key: PRIVATE_KEYS[1] },
        };

        let statement = ValidReblindStatement {
            original_shares_nullifier,
            reblinded_private_share_commitment: new_private_commitment,
            merkle_root,
        };

        (witness, statement)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use circuit_types::{
        native_helpers::compute_wallet_private_share_commitment,
        traits::{BaseType, SecretShareType},
    };
    use constants::{Scalar, MERKLE_HEIGHT};
    use rand::{thread_rng, Rng};

    use crate::zk_circuits::{
        check_constraint_satisfaction,
        test_helpers::{SizedWallet, SizedWalletShare, INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS},
        valid_reblind::test_helpers::construct_witness_statement,
    };

    use super::ValidReblind;

    // -----------
    // | Helpers |
    // -----------

    /// A `VALID REBLIND` circuit with test sizing parameters attached
    pub type SizedReblind = ValidReblind<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;

    /// Asserts that a set of secret shares is a valid reblinding of a wallet
    ///
    /// This is useful for testing that malicious modifications to the wallet's
    /// blinding have left the wallet unaffected, for isolating failure
    /// cases
    fn assert_valid_reblinding(
        private_shares: &SizedWalletShare,
        public_shares: &SizedWalletShare,
        wallet: &SizedWallet,
    ) {
        // This boils down to checking equality on the recovered wallet and the original
        // wallet except for the wallet blinder, so we clobber that field to be
        // trivially equal between the wallets
        let recovered_blinder = private_shares.blinder + public_shares.blinder;
        let unblinded_public_shares = public_shares.unblind_shares(recovered_blinder);
        let mut recovered_wallet = unblinded_public_shares + private_shares.clone();

        recovered_wallet.blinder = wallet.blinder;
        assert!(wallet.eq(&recovered_wallet));
    }

    // -------------------------
    // | Reblinding Test Cases |
    // -------------------------

    /// Tests a valid reblinding of the original wallet
    #[test]
    fn test_valid_reblind() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (witness, statement) = construct_witness_statement(&wallet);

        assert!(check_constraint_satisfaction::<SizedReblind>(&witness, &statement))
    }

    /// Tests an invalid reblinding, i.e. a secret share that was sampled
    /// incorrectly
    #[test]
    fn test_invalid_reblind__invalid_secret_share() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, mut statement) = construct_witness_statement(&wallet);

        // Choose a random index in the wallet and alter the secret shares such that it
        // remains a valid blinding, but an incorrectly sampled one
        let mut rng = thread_rng();
        let mut private_shares_serialized: Vec<Scalar> =
            witness.reblinded_wallet_private_shares.to_scalars();
        let mut public_shares_serialized: Vec<Scalar> =
            witness.reblinded_wallet_public_shares.to_scalars();

        let random_index = rng.gen_range(0..private_shares_serialized.len());
        private_shares_serialized[random_index] += Scalar::one();
        public_shares_serialized[random_index] -= Scalar::one();

        // Reconstruct the shares from the modified serialized values
        let reblinded_wallet_private_share =
            SizedWalletShare::from_scalars(&mut private_shares_serialized.into_iter());
        let reblinded_wallet_public_share =
            SizedWalletShare::from_scalars(&mut public_shares_serialized.into_iter());

        witness.reblinded_wallet_private_shares = reblinded_wallet_private_share.clone();
        witness.reblinded_wallet_public_shares = reblinded_wallet_public_share.clone();
        statement.reblinded_private_share_commitment =
            compute_wallet_private_share_commitment(&reblinded_wallet_private_share);

        // Verify that the reblinding is a valid secret sharing
        assert_valid_reblinding(
            &reblinded_wallet_private_share,
            &reblinded_wallet_public_share,
            &wallet,
        );

        // Verify that the constraints are not satisfied on this statement, witness pair
        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));
    }

    /// Tests an invalidly re-sampled wallet blinder
    #[test]
    fn test_invalid_reblind__invalid_wallet_blinder() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, mut statement) = construct_witness_statement(&wallet);

        // Reblind the wallet with a new, incorrect blinder
        let recovered_blinder = witness.reblinded_wallet_private_shares.blinder
            + witness.reblinded_wallet_public_shares.blinder;

        let mut rng = thread_rng();
        let new_blinder = Scalar::random(&mut rng);
        let new_blinder_private_share = Scalar::random(&mut rng);

        let wallet_public_shares = witness.reblinded_wallet_public_shares;
        let unblinded = wallet_public_shares.unblind_shares(recovered_blinder);

        let mut reblinded = unblinded.blind(new_blinder);
        reblinded.blinder = new_blinder - new_blinder_private_share;

        // Reconstruct the incorrect witness
        witness.reblinded_wallet_public_shares = reblinded;
        witness.reblinded_wallet_private_shares.blinder = new_blinder_private_share;
        statement.reblinded_private_share_commitment =
            compute_wallet_private_share_commitment(&witness.reblinded_wallet_private_shares);

        assert_valid_reblinding(
            &witness.reblinded_wallet_private_shares,
            &witness.reblinded_wallet_public_shares,
            &wallet,
        );

        // Verify that the constraints are not satisfied
        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));
    }

    /// Tests a case in which the prover tries to modify a wallet element
    /// in the reblinding by modifying a private secret share
    #[test]
    fn test_invalid_reblind__wallet_private_value_modified() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, mut statement) = construct_witness_statement(&wallet);

        // Prover attempt to change a private share
        let mut rng = thread_rng();
        let mut private_shares = witness.reblinded_wallet_private_shares.to_scalars();
        let random_index = rng.gen_range(0..private_shares.len());
        private_shares[random_index] += Scalar::one();

        witness.reblinded_wallet_private_shares =
            SizedWalletShare::from_scalars(&mut private_shares.into_iter());
        statement.reblinded_private_share_commitment =
            compute_wallet_private_share_commitment(&witness.reblinded_wallet_private_shares);

        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));
    }

    /// Tests the case in which the prover tries to modify a wallet element
    /// in the reblinding by modifying a public secret share
    #[test]
    fn test_invalid_reblind__wallet_public_value_modified() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, mut statement) = construct_witness_statement(&wallet);

        // Prover attempts to change a public share
        let mut rng = thread_rng();
        let mut public_shares = witness.reblinded_wallet_public_shares.to_scalars();
        let random_index = rng.gen_range(0..public_shares.len());
        public_shares[random_index] += Scalar::one();

        witness.reblinded_wallet_public_shares =
            SizedWalletShare::from_scalars(&mut public_shares.into_iter());
        statement.reblinded_private_share_commitment =
            compute_wallet_private_share_commitment(&witness.reblinded_wallet_private_shares);

        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));
    }

    // ----------------------------
    // | Authorization Test Cases |
    // ----------------------------

    /// Tests the case in which a prover does not know `sk_match`
    #[test]
    fn test_invalid_key() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = construct_witness_statement(&wallet);

        // Modify the key to emulate an incorrectly specified key
        witness.sk_match.key += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));
    }

    // -----------------------------
    // | State Validity Test Cases |
    // -----------------------------

    /// Tests an invalid Merkle proof
    #[test]
    fn test_invalid_merkle_opening() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (original_witness, original_statement) = construct_witness_statement(&wallet);

        let mut rng = thread_rng();

        // Invalid opening
        let mut witness = original_witness.clone();
        let statement = original_statement.clone();

        let random_index = rng.gen_range(0..witness.original_share_opening.elems.len());
        witness.original_share_opening.elems[random_index] = Scalar::random(&mut thread_rng());

        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));

        // Invalid Merkle root
        let witness = original_witness;
        let mut statement = original_statement;

        statement.merkle_root = Scalar::random(&mut thread_rng());

        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));
    }

    /// Tests an invalid nullifier given as a public variable
    #[test]
    fn test_invalid_nullifier() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (original_witness, original_statement) = construct_witness_statement(&wallet);

        let mut rng = thread_rng();

        // Invalid nullifier
        let witness = original_witness;
        let mut statement = original_statement;
        statement.original_shares_nullifier = Scalar::random(&mut rng);

        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));
    }

    /// Tests the case in which the prover uses an invalid private share
    /// commitment
    #[test]
    fn test_invalid_commitment() {
        // Construct the witness and statement
        let wallet = INITIAL_WALLET.clone();
        let (witness, mut statement) = construct_witness_statement(&wallet);

        let mut rng = thread_rng();
        statement.reblinded_private_share_commitment = Scalar::random(&mut rng);

        assert!(!check_constraint_satisfaction::<SizedReblind>(&witness, &statement));
    }
}
